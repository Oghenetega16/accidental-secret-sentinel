import { describe, it, expect } from 'vitest';
import { isSuppressed, buildSuppression } from '../src/shared/allowlist';
import type { Finding, Suppression, StorageSync } from '../src/shared/types';

// ─── Fixtures ─────────────────────────────────────────────────────────────────

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'find-001',
    patternId: 'stripe-secret-key',
    patternName: 'Stripe Secret Key',
    severity: 'critical',
    sourceType: 'response-body',
    url: 'https://app.example.com/api/config',
    tabId: 1,
    redactedValue: 'sk_l***dc',
    valueHash: 'abc123hash456abc123hash456abc123hash456abc123hash456abc123hash456',
    timestamp: 1714000000000,
    entropy: 4.75,
    ...overrides,
  };
}

function makeSettings(overrides: Partial<StorageSync> = {}): StorageSync {
  return {
    suppressions: [],
    customPatterns: [],
    disabledDomains: [],
    enabled: true,
    ...overrides,
  };
}

function makeSuppression(overrides: Partial<Suppression>): Suppression {
  return {
    id: 'sup-001',
    kind: 'value-hash',
    value: 'abc123hash456abc123hash456abc123hash456abc123hash456abc123hash456',
    label: 'Stripe Secret Key — sk_l***dc',
    createdAt: 1714000000000,
    ...overrides,
  };
}

// ─── isSuppressed — value-hash ────────────────────────────────────────────────

describe('isSuppressed — value-hash', () => {
  it('suppresses a finding whose valueHash matches', () => {
    const finding = makeFinding();
    const settings = makeSettings({
      suppressions: [makeSuppression({
        kind: 'value-hash',
        value: finding.valueHash,
      })],
    });
    expect(isSuppressed(finding, settings)).toBe(true);
  });

  it('does not suppress when hash does not match', () => {
    const finding = makeFinding();
    const settings = makeSettings({
      suppressions: [makeSuppression({
        kind: 'value-hash',
        value: 'differenthash' + '0'.repeat(51),
      })],
    });
    expect(isSuppressed(finding, settings)).toBe(false);
  });

  it('suppresses when one of multiple suppressions matches', () => {
    const finding = makeFinding();
    const settings = makeSettings({
      suppressions: [
        makeSuppression({ id: 'sup-1', kind: 'value-hash', value: 'nope'.padEnd(64, '0') }),
        makeSuppression({ id: 'sup-2', kind: 'value-hash', value: finding.valueHash }),
        makeSuppression({ id: 'sup-3', kind: 'value-hash', value: 'also-nope'.padEnd(64, '0') }),
      ],
    });
    expect(isSuppressed(finding, settings)).toBe(true);
  });

  it('is not suppressed when suppression list is empty', () => {
    expect(isSuppressed(makeFinding(), makeSettings())).toBe(false);
  });
});

// ─── isSuppressed — pattern ───────────────────────────────────────────────────

describe('isSuppressed — pattern', () => {
  it('suppresses all findings with a matching patternId', () => {
    const finding = makeFinding({ patternId: 'stripe-secret-key' });
    const settings = makeSettings({
      suppressions: [makeSuppression({
        kind: 'pattern',
        value: 'stripe-secret-key',
      })],
    });
    expect(isSuppressed(finding, settings)).toBe(true);
  });

  it('does not suppress findings with a different patternId', () => {
    const finding = makeFinding({ patternId: 'github-pat-classic' });
    const settings = makeSettings({
      suppressions: [makeSuppression({
        kind: 'pattern',
        value: 'stripe-secret-key',
      })],
    });
    expect(isSuppressed(finding, settings)).toBe(false);
  });

  it('suppresses any finding once the pattern is suppressed, regardless of value', () => {
    const f1 = makeFinding({ valueHash: 'hash1'.padEnd(64, '0'), patternId: 'aws-access-key-id' });
    const f2 = makeFinding({ valueHash: 'hash2'.padEnd(64, '0'), patternId: 'aws-access-key-id' });
    const settings = makeSettings({
      suppressions: [makeSuppression({ kind: 'pattern', value: 'aws-access-key-id' })],
    });
    expect(isSuppressed(f1, settings)).toBe(true);
    expect(isSuppressed(f2, settings)).toBe(true);
  });
});

// ─── isSuppressed — domain ────────────────────────────────────────────────────

describe('isSuppressed — domain (disabledDomains)', () => {
  it('suppresses all findings from an exact domain match', () => {
    const finding = makeFinding({ url: 'https://internal.example.com/api' });
    const settings = makeSettings({ disabledDomains: ['internal.example.com'] });
    expect(isSuppressed(finding, settings)).toBe(true);
  });

  it('suppresses subdomains of a disabled domain', () => {
    const finding = makeFinding({ url: 'https://api.corp.example.com/v2/data' });
    const settings = makeSettings({ disabledDomains: ['corp.example.com'] });
    expect(isSuppressed(finding, settings)).toBe(true);
  });

  it('does NOT suppress a parent domain when only a subdomain is disabled', () => {
    const finding = makeFinding({ url: 'https://example.com/page' });
    const settings = makeSettings({ disabledDomains: ['api.example.com'] });
    expect(isSuppressed(finding, settings)).toBe(false);
  });

  it('does not suppress findings from a different domain', () => {
    const finding = makeFinding({ url: 'https://evil.attacker.com/leak' });
    const settings = makeSettings({ disabledDomains: ['safe.internal.com'] });
    expect(isSuppressed(finding, settings)).toBe(false);
  });

  it('handles invalid URL gracefully — does not suppress', () => {
    const finding = makeFinding({ url: 'not-a-valid-url' });
    const settings = makeSettings({ disabledDomains: ['example.com'] });
    expect(isSuppressed(finding, settings)).toBe(false);
  });

  it('suppresses localhost when localhost is disabled', () => {
    const finding = makeFinding({ url: 'http://localhost:3000/api/keys' });
    const settings = makeSettings({ disabledDomains: ['localhost'] });
    expect(isSuppressed(finding, settings)).toBe(true);
  });
});

// ─── isSuppressed — combination ───────────────────────────────────────────────

describe('isSuppressed — combined rules', () => {
  it('suppresses if ANY rule matches (OR logic)', () => {
    const finding = makeFinding({
      patternId: 'github-pat-classic',
      url: 'https://clean.example.com/page',
      valueHash: 'uniquehash'.padEnd(64, '0'),
    });
    const settings = makeSettings({
      // Only the pattern rule matches, not value-hash or domain
      suppressions: [
        makeSuppression({ kind: 'value-hash', value: 'wronghash'.padEnd(64, '0') }),
        makeSuppression({ kind: 'pattern', value: 'github-pat-classic' }),
      ],
      disabledDomains: ['other.com'],
    });
    expect(isSuppressed(finding, settings)).toBe(true);
  });

  it('does not suppress when no rule matches', () => {
    const finding = makeFinding({
      patternId: 'stripe-secret-key',
      url: 'https://app.example.com/dashboard',
      valueHash: 'uniquehash'.padEnd(64, '0'),
    });
    const settings = makeSettings({
      suppressions: [
        makeSuppression({ kind: 'value-hash', value: 'different'.padEnd(64, '0') }),
        makeSuppression({ kind: 'pattern', value: 'aws-access-key-id' }),
      ],
      disabledDomains: ['other.com'],
    });
    expect(isSuppressed(finding, settings)).toBe(false);
  });

  it('respects global disabled check — suppressed even if no suppressions list entry', () => {
    const finding = makeFinding({ url: 'https://staging.example.com/api' });
    const settings = makeSettings({
      suppressions: [],
      disabledDomains: ['staging.example.com'],
    });
    expect(isSuppressed(finding, settings)).toBe(true);
  });
});

// ─── buildSuppression ─────────────────────────────────────────────────────────

describe('buildSuppression', () => {
  it('builds a value-hash suppression from a finding', () => {
    const finding = makeFinding();
    const result = buildSuppression('value-hash', finding);
    expect(result.kind).toBe('value-hash');
    expect(result.value).toBe(finding.valueHash);
    expect(result.label).toContain(finding.patternName);
    expect(result.label).toContain(finding.redactedValue);
  });

  it('builds a pattern suppression from a finding', () => {
    const finding = makeFinding();
    const result = buildSuppression('pattern', finding);
    expect(result.kind).toBe('pattern');
    expect(result.value).toBe(finding.patternId);
    expect(result.label).toContain(finding.patternName);
    expect(result.label).toContain('All');
  });

  it('builds a domain suppression extracting hostname from URL', () => {
    const finding = makeFinding({ url: 'https://api.example.com/v2/config' });
    const result = buildSuppression('domain', finding);
    expect(result.kind).toBe('domain');
    expect(result.value).toBe('api.example.com');
    expect(result.label).toContain('api.example.com');
  });

  it('builds a domain suppression even for invalid URL (uses full url as fallback)', () => {
    const finding = makeFinding({ url: 'not-a-valid-url' });
    const result = buildSuppression('domain', finding);
    expect(result.kind).toBe('domain');
    expect(result.value).toBeTruthy();
  });

  it('does not include id or createdAt (caller adds those)', () => {
    const finding = makeFinding();
    const result = buildSuppression('value-hash', finding);
    expect((result as any).id).toBeUndefined();
    expect((result as any).createdAt).toBeUndefined();
  });
});