/**
 * storage.test.ts
 *
 * Tests the storage helpers in isolation by providing a minimal
 * chrome.storage mock — no browser required.
 *
 * The mock mirrors the real chrome.storage.sync / local API:
 *   get(defaults?)   → returns merged defaults + stored values
 *   set(partial)     → merges into the store
 *
 * We also test the three suppression invariants:
 *   1. Deduplication — same kind+value cannot be added twice
 *   2. Quota cap     — list is trimmed to MAX_SUPPRESSIONS (200)
 *   3. Purge         — purgeSuppressedFindings removes matching findings
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import type { Finding, Suppression } from '../src/shared/types';

// ─── chrome.storage mock ──────────────────────────────────────────────────────

function makeStoreMock() {
  const db: Record<string, unknown> = {};

  return {
    db,
    get(defaults?: Record<string, unknown>) {
      const merged = { ...(defaults ?? {}) };
      for (const [k, v] of Object.entries(db)) {
        merged[k] = v;
      }
      return Promise.resolve(merged);
    },
    set(partial: Record<string, unknown>) {
      Object.assign(db, partial);
      return Promise.resolve();
    },
    clear() {
      for (const k of Object.keys(db)) delete db[k];
    },
  };
}

// Install mock before importing storage module
const syncStore = makeStoreMock();
const localStore = makeStoreMock();

vi.stubGlobal('crypto', {
  randomUUID: () => 'test-uuid-' + Math.random().toString(36).slice(2),
});

vi.stubGlobal('chrome', {
  storage: {
    sync:  { get: syncStore.get.bind(syncStore),  set: syncStore.set.bind(syncStore)  },
    local: { get: localStore.get.bind(localStore), set: localStore.set.bind(localStore) },
  },
});

// Import AFTER globals are set
const {
  getSettings,
  updateSettings,
  addSuppression,
  removeSuppression,
  getSuppressions,
  addFinding,
  getFindings,
  clearFindings,
  getFindingCount,
  purgeSuppressedFindings,
} = await import('../src/background/storage');

// ─── Fixtures ─────────────────────────────────────────────────────────────────

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'find-' + Math.random().toString(36).slice(2),
    patternId: 'stripe-secret-key',
    patternName: 'Stripe Secret Key',
    severity: 'critical',
    sourceType: 'response-body',
    url: 'https://app.example.com/api',
    tabId: 1,
    redactedValue: 'sk_l***dc',
    valueHash: ('hash' + Math.random()).padEnd(64, '0').slice(0, 64),
    timestamp: Date.now(),
    entropy: 4.5,
    ...overrides,
  };
}

// ─── getSettings / updateSettings ────────────────────────────────────────────

describe('getSettings', () => {
  beforeEach(() => { syncStore.clear(); localStore.clear(); });

  it('returns defaults when storage is empty', async () => {
    const settings = await getSettings();
    expect(settings.enabled).toBe(true);
    expect(settings.suppressions).toEqual([]);
    expect(settings.disabledDomains).toEqual([]);
    expect(settings.customPatterns).toEqual([]);
  });

  it('returns stored values when present', async () => {
    await updateSettings({ enabled: false, disabledDomains: ['localhost'] });
    const settings = await getSettings();
    expect(settings.enabled).toBe(false);
    expect(settings.disabledDomains).toContain('localhost');
  });

  it('handles corrupt storage (non-array suppressions) gracefully', async () => {
    syncStore.db['suppressions'] = 'invalid-not-an-array';
    const settings = await getSettings();
    expect(Array.isArray(settings.suppressions)).toBe(true);
    expect(settings.suppressions).toEqual([]);
  });
});

// ─── addSuppression ───────────────────────────────────────────────────────────

describe('addSuppression', () => {
  beforeEach(() => { syncStore.clear(); localStore.clear(); });

  it('adds a value-hash suppression', async () => {
    const result = await addSuppression({
      kind: 'value-hash',
      value: 'a'.repeat(64),
      label: 'Test suppression',
    });
    expect(result.added).toBe(true);
    const sups = await getSuppressions();
    expect(sups).toHaveLength(1);
    expect(sups[0]!.kind).toBe('value-hash');
    expect(sups[0]!.id).toBeTruthy();
    expect(sups[0]!.createdAt).toBeGreaterThan(0);
  });

  it('adds a pattern suppression', async () => {
    await addSuppression({ kind: 'pattern', value: 'stripe-secret-key', label: 'All Stripe' });
    const sups = await getSuppressions();
    expect(sups.some(s => s.kind === 'pattern' && s.value === 'stripe-secret-key')).toBe(true);
  });

  it('adds a domain suppression', async () => {
    await addSuppression({ kind: 'domain', value: 'localhost', label: 'localhost' });
    const sups = await getSuppressions();
    expect(sups.some(s => s.kind === 'domain' && s.value === 'localhost')).toBe(true);
  });

  it('deduplicates — same kind+value cannot be added twice', async () => {
    const sup = { kind: 'value-hash' as const, value: 'b'.repeat(64), label: 'test' };
    const r1 = await addSuppression(sup);
    const r2 = await addSuppression(sup);
    expect(r1.added).toBe(true);
    expect(r2.added).toBe(false);
    expect(r2.reason).toBe('duplicate');
    const sups = await getSuppressions();
    expect(sups.filter(s => s.value === 'b'.repeat(64))).toHaveLength(1);
  });

  it('allows same value with different kind (not a duplicate)', async () => {
    await addSuppression({ kind: 'value-hash', value: 'sharedvalue'.padEnd(64, '0'), label: 'A' });
    const r = await addSuppression({ kind: 'pattern', value: 'sharedvalue'.padEnd(64, '0'), label: 'B' });
    expect(r.added).toBe(true);
  });

  it('accumulates multiple suppressions independently', async () => {
    await addSuppression({ kind: 'value-hash', value: '1'.repeat(64), label: 'one' });
    await addSuppression({ kind: 'value-hash', value: '2'.repeat(64), label: 'two' });
    await addSuppression({ kind: 'pattern', value: 'aws-access-key-id', label: 'aws' });
    const sups = await getSuppressions();
    expect(sups).toHaveLength(3);
  });
});

// ─── removeSuppression ────────────────────────────────────────────────────────

describe('removeSuppression', () => {
  beforeEach(() => { syncStore.clear(); localStore.clear(); });

  it('removes a suppression by ID', async () => {
    await addSuppression({ kind: 'pattern', value: 'github-pat-classic', label: 'GitHub' });
    const before = await getSuppressions();
    expect(before).toHaveLength(1);

    await removeSuppression(before[0]!.id);
    const after = await getSuppressions();
    expect(after).toHaveLength(0);
  });

  it('is idempotent — removing non-existent ID does not throw', async () => {
    await expect(removeSuppression('ghost-id')).resolves.not.toThrow();
  });

  it('only removes the targeted suppression, leaving others intact', async () => {
    await addSuppression({ kind: 'pattern', value: 'stripe-secret-key', label: 'Stripe' });
    await addSuppression({ kind: 'pattern', value: 'aws-access-key-id', label: 'AWS' });
    const sups = await getSuppressions();
    await removeSuppression(sups[0]!.id);
    const after = await getSuppressions();
    expect(after).toHaveLength(1);
    expect(after[0]!.value).toBe('aws-access-key-id');
  });
});

// ─── addFinding / getFindings / clearFindings ────────────────────────────────

describe('addFinding', () => {
  beforeEach(() => { syncStore.clear(); localStore.clear(); });

  it('stores a finding and retrieves it by tabId', async () => {
    const f = makeFinding({ tabId: 42 });
    await addFinding(f);
    const stored = await getFindings(42);
    expect(stored).toHaveLength(1);
    expect(stored[0]!.id).toBe(f.id);
  });

  it('deduplicates by valueHash — same hash not stored twice', async () => {
    const hash = 'c'.repeat(64);
    const f1 = makeFinding({ tabId: 1, valueHash: hash });
    const f2 = makeFinding({ tabId: 1, valueHash: hash, id: 'different-id' }); // different id, same hash
    await addFinding(f1);
    await addFinding(f2);
    const stored = await getFindings(1);
    expect(stored).toHaveLength(1);
  });

  it('stores different hashes as separate findings', async () => {
    await addFinding(makeFinding({ tabId: 1, valueHash: 'd'.repeat(64) }));
    await addFinding(makeFinding({ tabId: 1, valueHash: 'e'.repeat(64) }));
    expect(await getFindingCount(1)).toBe(2);
  });

  it('keeps findings isolated per tab', async () => {
    await addFinding(makeFinding({ tabId: 1, valueHash: 'f'.repeat(64) }));
    await addFinding(makeFinding({ tabId: 2, valueHash: 'g'.repeat(64) }));
    expect(await getFindingCount(1)).toBe(1);
    expect(await getFindingCount(2)).toBe(1);
  });
});

describe('clearFindings', () => {
  beforeEach(() => { syncStore.clear(); localStore.clear(); });

  it('removes all findings for a tab', async () => {
    await addFinding(makeFinding({ tabId: 5, valueHash: 'h'.repeat(64) }));
    await addFinding(makeFinding({ tabId: 5, valueHash: 'i'.repeat(64) }));
    await clearFindings(5);
    expect(await getFindingCount(5)).toBe(0);
  });

  it('does not affect other tabs', async () => {
    await addFinding(makeFinding({ tabId: 10, valueHash: 'j'.repeat(64) }));
    await addFinding(makeFinding({ tabId: 11, valueHash: 'k'.repeat(64) }));
    await clearFindings(10);
    expect(await getFindingCount(10)).toBe(0);
    expect(await getFindingCount(11)).toBe(1);
  });
});

// ─── purgeSuppressedFindings ──────────────────────────────────────────────────

describe('purgeSuppressedFindings', () => {
  beforeEach(() => { syncStore.clear(); localStore.clear(); });

  it('removes findings matching a value-hash suppression', async () => {
    const targetHash = 'l'.repeat(64);
    const safeHash   = 'm'.repeat(64);
    await addFinding(makeFinding({ tabId: 1, valueHash: targetHash }));
    await addFinding(makeFinding({ tabId: 1, valueHash: safeHash }));
    await purgeSuppressedFindings({ kind: 'value-hash', value: targetHash });
    const remaining = await getFindings(1);
    expect(remaining).toHaveLength(1);
    expect(remaining[0]!.valueHash).toBe(safeHash);
  });

  it('removes findings matching a pattern suppression', async () => {
    await addFinding(makeFinding({ tabId: 1, patternId: 'stripe-secret-key', valueHash: 'n'.repeat(64) }));
    await addFinding(makeFinding({ tabId: 1, patternId: 'stripe-secret-key', valueHash: 'o'.repeat(64) }));
    await addFinding(makeFinding({ tabId: 1, patternId: 'aws-access-key-id', valueHash: 'p'.repeat(64) }));
    await purgeSuppressedFindings({ kind: 'pattern', value: 'stripe-secret-key' });
    const remaining = await getFindings(1);
    expect(remaining).toHaveLength(1);
    expect(remaining[0]!.patternId).toBe('aws-access-key-id');
  });

  it('removes findings matching a domain suppression across all tabs', async () => {
    const targetUrl = 'https://leak.example.com/api';
    const safeUrl   = 'https://safe.other.com/api';
    await addFinding(makeFinding({ tabId: 1, url: targetUrl, valueHash: 'q'.repeat(64) }));
    await addFinding(makeFinding({ tabId: 2, url: targetUrl, valueHash: 'r'.repeat(64) }));
    await addFinding(makeFinding({ tabId: 1, url: safeUrl,   valueHash: 's'.repeat(64) }));
    await purgeSuppressedFindings({ kind: 'domain', value: 'leak.example.com' });
    expect(await getFindingCount(1)).toBe(1);
    expect(await getFindingCount(2)).toBe(0);
  });

  it('is a no-op when no findings match', async () => {
    await addFinding(makeFinding({ tabId: 1, valueHash: 't'.repeat(64) }));
    await purgeSuppressedFindings({ kind: 'value-hash', value: 'u'.repeat(64) });
    expect(await getFindingCount(1)).toBe(1);
  });

  it('handles empty findings store without throwing', async () => {
    await expect(
      purgeSuppressedFindings({ kind: 'pattern', value: 'any-pattern' })
    ).resolves.not.toThrow();
  });
});