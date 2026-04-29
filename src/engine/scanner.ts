import type { Finding, Pattern, SourceType } from '../shared/types';
import { PATTERNS } from './patterns';
import { meetsEntropyThreshold, shannonEntropy } from './entropy';

// ─── Helpers ─────────────────────────────────────────────────────────────────

/**
 * Computes a SHA-256 hash of the matched value.
 * Used as the suppression key — never store the raw value.
 */
async function hashValue(value: string): Promise<string> {
  const encoded = new TextEncoder().encode(value);
  const buffer = await crypto.subtle.digest('SHA-256', encoded);
  return Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Redacts a matched secret for display.
 * Shows first 4 chars + *** + last 4 chars.
 * For values < 12 chars, shows only first 2 + ***.
 */
function redact(value: string): string {
  if (value.length <= 8) return value.slice(0, 2) + '***';
  return value.slice(0, 4) + '***' + value.slice(-4);
}

/** Naive UUID v4 generator (crypto.randomUUID not available in all contexts) */
function generateId(): string {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
    const r = (Math.random() * 16) | 0;
    return (c === 'x' ? r : (r & 0x3) | 0x8).toString(16);
  });
}

// ─── Main scan function ───────────────────────────────────────────────────────

export interface ScanOptions {
  url: string;
  tabId: number;
  sourceType: SourceType;
  /** Optional: header name this content came from — used for contextBoost scoring */
  headerName?: string;
  /** Override pattern list — useful for tests */
  patterns?: Pattern[];
}

export interface ScanResult {
  findings: RawFinding[];
}

/** Finding before async hashing — caller must call toFinding() to get the full Finding */
export interface RawFinding {
  patternId: string;
  patternName: string;
  severity: Finding['severity'];
  sourceType: SourceType;
  url: string;
  tabId: number;
  redactedValue: string;
  rawValue: string;  // only exists until hashed — do NOT persist this
  entropy: number;
  toFinding(): Promise<Finding>;
}

/**
 * Scans a string for secret patterns.
 *
 * Pure function — no browser API calls, safe to run in any context.
 * Call toFinding() on each result to get the final Finding with value hash.
 *
 * @example
 *   const results = scan(responseBody, { url, tabId, sourceType: 'response-body' });
 *   const findings = await Promise.all(results.map(r => r.toFinding()));
 */
export function scan(input: string, opts: ScanOptions): RawFinding[] {
  const patternList = opts.patterns ?? PATTERNS;
  const results: RawFinding[] = [];
  const seenValues = new Set<string>(); // deduplicate within a single scan call

  for (const pattern of patternList) {
    // Use a fresh regex per call to avoid lastIndex drift
    const regex = new RegExp(pattern.regex.source, pattern.regex.flags.replace('g', '') + 'g');
    let match: RegExpExecArray | null;

    while ((match = regex.exec(input)) !== null) {
      // Capture group 1 if present, otherwise full match
      const rawValue = match[1] ?? match[0] ?? '';

      if (rawValue.length < 8) continue; // too short to be a real secret

      if (!meetsEntropyThreshold(rawValue, pattern.entropyMin)) continue;

      if (seenValues.has(rawValue)) continue;
      seenValues.add(rawValue);

      const entropy = shannonEntropy(rawValue);
      const redactedValue = redact(rawValue);

      // Capture these in closure for the async toFinding()
      const capturedPattern = pattern;
      const capturedOpts = opts;

      const raw: RawFinding = {
        patternId: capturedPattern.id,
        patternName: capturedPattern.name,
        severity: capturedPattern.severity,
        sourceType: capturedOpts.sourceType,
        url: capturedOpts.url,
        tabId: capturedOpts.tabId,
        redactedValue,
        rawValue,
        entropy,
        async toFinding(): Promise<Finding> {
          return {
            id: generateId(),
            patternId: capturedPattern.id,
            patternName: capturedPattern.name,
            severity: capturedPattern.severity,
            sourceType: capturedOpts.sourceType,
            url: capturedOpts.url,
            tabId: capturedOpts.tabId,
            redactedValue,
            valueHash: await hashValue(rawValue),
            timestamp: Date.now(),
            entropy,
          };
        },
      };

      results.push(raw);
    }
  }

  return results;
}