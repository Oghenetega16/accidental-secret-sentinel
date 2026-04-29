import type { Finding, Suppression, StorageSync } from './types';

/**
 * Returns true if this finding should be suppressed based on the current suppression list.
 */
export function isSuppressed(finding: Finding, settings: StorageSync): boolean {
  const { suppressions, disabledDomains } = settings;

  // Check domain suppression first (cheapest check)
  try {
    const hostname = new URL(finding.url).hostname;
    if (disabledDomains.some(d => hostname === d || hostname.endsWith('.' + d))) {
      return true;
    }
  } catch {
    // Invalid URL — skip domain check
  }

  for (const s of suppressions) {
    if (s.kind === 'value-hash' && s.value === finding.valueHash) return true;
    if (s.kind === 'pattern' && s.value === finding.patternId) return true;
    // domain handled above
  }

  return false;
}

/**
 * Creates a new Suppression object from a finding.
 */
export function buildSuppression(
  kind: Suppression['kind'],
  finding: Finding
): Omit<Suppression, 'id' | 'createdAt'> {
  switch (kind) {
    case 'value-hash':
      return {
        kind,
        value: finding.valueHash,
        label: `${finding.patternName} — ${finding.redactedValue}`,
      };
    case 'pattern':
      return {
        kind,
        value: finding.patternId,
        label: `All ${finding.patternName} detections`,
      };
    case 'domain': {
      let hostname = finding.url;
      try { hostname = new URL(finding.url).hostname; } catch { /* noop */ }
      return {
        kind,
        value: hostname,
        label: `All detections on ${hostname}`,
      };
    }
  }
}