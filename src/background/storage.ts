import type { StorageLocal, StorageSync, SessionFindings, Suppression, Finding } from '../shared/types';

// ─── Defaults ─────────────────────────────────────────────────────────────────

export const DEFAULT_SYNC: StorageSync = {
  suppressions: [],
  customPatterns: [],
  disabledDomains: [],
  enabled: true,
};

// chrome.storage.sync quota constants
// https://developer.chrome.com/docs/extensions/reference/storage/#property-sync
const SYNC_QUOTA_BYTES       = 102_400; // 100 KB total
const SYNC_QUOTA_BYTES_ITEM  = 8_192;   // 8 KB per item
const MAX_SUPPRESSIONS       = 200;     // hard cap before we start evicting oldest

// ─── Settings (chrome.storage.sync) ──────────────────────────────────────────

export async function getSettings(): Promise<StorageSync> {
  const result = await chrome.storage.sync.get(DEFAULT_SYNC);
  return {
    suppressions:    Array.isArray(result['suppressions'])    ? result['suppressions']    : [],
    customPatterns:  Array.isArray(result['customPatterns'])  ? result['customPatterns']  : [],
    disabledDomains: Array.isArray(result['disabledDomains']) ? result['disabledDomains'] : [],
    enabled:         typeof result['enabled'] === 'boolean'   ? result['enabled']         : true,
  };
}

/**
 * Merges a partial update into sync storage.
 * Performs a read-merge-write to avoid overwriting unrelated keys.
 */
export async function updateSettings(partial: Partial<StorageSync>): Promise<void> {
  await chrome.storage.sync.set(partial);
}

// ─── Suppression helpers ──────────────────────────────────────────────────────

/**
 * Adds a suppression, enforcing deduplication and quota limits.
 *
 * Dedup rules:
 *  - value-hash: no two suppressions with the same hash
 *  - domain:     no two suppressions for the same hostname
 *  - pattern:    no two suppressions for the same patternId
 *
 * Quota strategy: if the list exceeds MAX_SUPPRESSIONS, evict the oldest
 * entries first (sorted by createdAt asc) until we're under the cap.
 */
export async function addSuppression(
  suppression: Omit<Suppression, 'id' | 'createdAt'>
): Promise<{ added: boolean; reason?: string }> {
  const settings = await getSettings();
  const existing = settings.suppressions;

  // Deduplication check
  const isDuplicate = existing.some(s =>
    s.kind === suppression.kind && s.value === suppression.value
  );
  if (isDuplicate) {
    return { added: false, reason: 'duplicate' };
  }

  const newSuppression: Suppression = {
    ...suppression,
    id: crypto.randomUUID(),
    createdAt: Date.now(),
  };

  let updated = [...existing, newSuppression];

  // Quota enforcement — evict oldest if over the cap
  if (updated.length > MAX_SUPPRESSIONS) {
    updated = updated
      .sort((a, b) => a.createdAt - b.createdAt)
      .slice(updated.length - MAX_SUPPRESSIONS);
  }

  // Byte-size guard — serialize and check against sync quota estimate
  const serialized = JSON.stringify(updated);
  if (serialized.length > SYNC_QUOTA_BYTES_ITEM) {
    // Trim one more entry and try again
    updated = updated.slice(1);
  }

  await chrome.storage.sync.set({ suppressions: updated });
  return { added: true };
}

/**
 * Removes a suppression by its ID.
 */
export async function removeSuppression(id: string): Promise<void> {
  const settings = await getSettings();
  await chrome.storage.sync.set({
    suppressions: settings.suppressions.filter(s => s.id !== id),
  });
}

/**
 * Returns the full suppression list.
 */
export async function getSuppressions(): Promise<Suppression[]> {
  const settings = await getSettings();
  return settings.suppressions;
}

// ─── Session findings (chrome.storage.local) ─────────────────────────────────

export async function getFindings(tabId: number): Promise<Finding[]> {
  const result = await chrome.storage.local.get('findings');
  const findings: SessionFindings = result['findings'] ?? {};
  return findings[String(tabId)] ?? [];
}

export async function addFinding(finding: Finding): Promise<void> {
  const result = await chrome.storage.local.get('findings');
  const all: SessionFindings = result['findings'] ?? {};
  const key = String(finding.tabId);
  const existing = all[key] ?? [];

  // Deduplicate by valueHash — same secret value, same tab
  if (existing.some(f => f.valueHash === finding.valueHash)) return;

  all[key] = [...existing, finding];
  await chrome.storage.local.set({ findings: all });
}

export async function clearFindings(tabId: number): Promise<void> {
  const result = await chrome.storage.local.get('findings');
  const all: SessionFindings = result['findings'] ?? {};
  delete all[String(tabId)];
  await chrome.storage.local.set({ findings: all });
}

export async function getFindingCount(tabId: number): Promise<number> {
  return (await getFindings(tabId)).length;
}

/**
 * Removes all findings matching a suppression from every tab.
 * Called after a new suppression is added so stale findings disappear
 * from the popup without a page reload.
 */
export async function purgeSuppressedFindings(
  suppression: Pick<Suppression, 'kind' | 'value'>
): Promise<void> {
  const result = await chrome.storage.local.get('findings');
  const all: SessionFindings = result['findings'] ?? {};
  let changed = false;

  for (const tabKey of Object.keys(all)) {
    const before = all[tabKey] ?? [];
    const after = before.filter(f => {
      if (suppression.kind === 'value-hash') return f.valueHash !== suppression.value;
      if (suppression.kind === 'pattern')    return f.patternId  !== suppression.value;
      if (suppression.kind === 'domain') {
        try {
          const h = new URL(f.url).hostname;
          const matched = h === suppression.value || h.endsWith('.' + suppression.value);
          return !matched;
        } catch { return true; }
      }
      return true;
    });
    if (after.length !== before.length) {
      all[tabKey] = after;
      changed = true;
    }
  }

  if (changed) await chrome.storage.local.set({ findings: all });
}
