import { describe, it, expect, vi, beforeEach } from 'vitest';
import { scan } from '../src/engine/scanner';
import type { Pattern } from '../src/shared/types';

// ─── Test fixture patterns ────────────────────────────────────────────────────

const MOCK_PATTERNS: Pattern[] = [
  {
    id: 'test-aws-key',
    name: 'Test AWS Key',
    regex: /AKIA[0-9A-Z]{16}/,
    severity: 'critical',
    entropyMin: 3.5,
  },
  {
    id: 'test-stripe-key',
    name: 'Test Stripe Key',
    regex: /sk_(live|test)_[A-Za-z0-9]{24,}/,
    severity: 'critical',
  },
  {
    id: 'test-generic-secret',
    name: 'Test Generic Secret',
    regex: /secret[_=:\s"']+([A-Za-z0-9+/=]{32,})/i,
    severity: 'info',
    entropyMin: 4.0,
  },
  {
    id: 'test-capture-group',
    name: 'Test Capture Group',
    regex: /token[=:\s"']+([A-Za-z0-9]{20,})/i,
    severity: 'warning',
  },
];

const OPTS = {
  url: 'https://example.com/api',
  tabId: 42,
  sourceType: 'response-body' as const,
  patterns: MOCK_PATTERNS,
};

// ─── Basic detection ──────────────────────────────────────────────────────────

describe('scan — basic detection', () => {
  it('finds an AWS key in plain text', () => {
    const results = scan('AKIAIOSFODNN7EXAMPLE1', OPTS);
    expect(results).toHaveLength(1);
    expect(results[0]!.patternId).toBe('test-aws-key');
    expect(results[0]!.severity).toBe('critical');
  });

  it('finds a Stripe key in plain text', () => {
    const results = scan('sk_live_4eC39HqLyjWDarjtT1zdp7dc', OPTS);
    expect(results).toHaveLength(1);
    expect(results[0]!.patternId).toBe('test-stripe-key');
  });

  it('finds multiple different secrets in one input', () => {
    const input = [
      'config.aws_key = "AKIAIOSFODNN7EXAMPLE1"',
      'config.stripe = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"',
    ].join('\n');
    const results = scan(input, OPTS);
    expect(results.length).toBeGreaterThanOrEqual(2);
    const ids = results.map(r => r.patternId);
    expect(ids).toContain('test-aws-key');
    expect(ids).toContain('test-stripe-key');
  });

  it('returns empty array for clean input', () => {
    const results = scan('Hello world, nothing secret here!', OPTS);
    expect(results).toHaveLength(0);
  });

  it('returns empty array for empty string', () => {
    expect(scan('', OPTS)).toHaveLength(0);
  });

  it('returns empty array for very short input', () => {
    expect(scan('abc', OPTS)).toHaveLength(0);
  });
});

// ─── Capture group extraction ─────────────────────────────────────────────────

describe('scan — capture group extraction', () => {
  it('extracts the capture group value, not the full match', () => {
    const results = scan('token="abcdefghijklmnopqrstu"', OPTS);
    expect(results).toHaveLength(1);
    // Should have captured the token value, not the full "token=..." string
    expect(results[0]!.rawValue).not.toContain('token=');
    expect(results[0]!.rawValue).toBe('abcdefghijklmnopqrstu');
  });

  it('redacts the extracted capture group value', () => {
    const results = scan('token="ABCDEFGHIJKLMNOPQRST"', OPTS);
    expect(results).toHaveLength(1);
    const r = results[0]!;
    expect(r.redactedValue).toContain('***');
    expect(r.redactedValue).not.toBe(r.rawValue);
  });
});

// ─── Redaction ────────────────────────────────────────────────────────────────

describe('scan — redaction', () => {
  it('shows first 4 and last 4 chars for values >= 8 chars', () => {
    const results = scan('AKIAIOSFODNN7EXAMPLE1', OPTS);
    const r = results[0]!;
    expect(r.redactedValue).toMatch(/^AKIA\*\*\*.+E1$/);
  });

  it('never exposes the full raw value in redactedValue', () => {
    const results = scan('AKIAIOSFODNN7EXAMPLE1', OPTS);
    expect(results[0]!.redactedValue).not.toBe('AKIAIOSFODNN7EXAMPLE1');
  });
});

// ─── Entropy filtering ────────────────────────────────────────────────────────

describe('scan — entropy filtering', () => {
  it('filters out low-entropy matches when entropyMin is set', () => {
    // 'aaaaaaaaaaaaaaaaaaaaaa' matches AWS key length but has 0 entropy
    // Use a pattern with entropyMin
    const lowEntropyInput = 'AKIAAAAAAAAAAAAAAAAAAA'; // all A's after prefix — very low entropy
    const results = scan(lowEntropyInput, OPTS);
    // Should be filtered out because entropy is too low
    expect(results).toHaveLength(0);
  });

  it('passes high-entropy matches through', () => {
    const results = scan('AKIAIOSFODNN7EXAMPLE1', OPTS);
    expect(results).toHaveLength(1);
    expect(results[0]!.entropy).toBeGreaterThan(3.5);
  });

  it('passes matches through when no entropyMin is set', () => {
    // test-stripe-key has no entropyMin — even a low-entropy value should pass
    const results = scan('sk_live_AAAAAAAAAAAAAAAAAAAAAAAAA', OPTS);
    expect(results).toHaveLength(1);
  });
});

// ─── Deduplication ───────────────────────────────────────────────────────────

describe('scan — deduplication', () => {
  it('deduplicates identical raw values within one scan call', () => {
    const input = [
      'key1=AKIAIOSFODNN7EXAMPLE1',
      'key2=AKIAIOSFODNN7EXAMPLE1', // same value
    ].join('\n');
    const results = scan(input, OPTS);
    const awsResults = results.filter(r => r.patternId === 'test-aws-key');
    expect(awsResults).toHaveLength(1);
  });

  it('reports two different secrets of the same pattern type', () => {
    const input = [
      'key1=AKIAIOSFODNN7EXAMPLE1',
      'key2=AKIAI44QH8DHBEXAMPLE2', // different value
    ].join('\n');
    const results = scan(input, OPTS);
    const awsResults = results.filter(r => r.patternId === 'test-aws-key');
    expect(awsResults).toHaveLength(2);
  });
});

// ─── toFinding() ─────────────────────────────────────────────────────────────

describe('scan — toFinding()', () => {
  it('produces a Finding with a value hash', async () => {
    const results = scan('AKIAIOSFODNN7EXAMPLE1', OPTS);
    expect(results).toHaveLength(1);
    const finding = await results[0]!.toFinding();

    expect(finding.id).toMatch(/^[0-9a-f-]{36}$/); // UUID format
    expect(finding.patternId).toBe('test-aws-key');
    expect(finding.tabId).toBe(42);
    expect(finding.url).toBe('https://example.com/api');
    expect(finding.valueHash).toHaveLength(64); // SHA-256 hex
    expect(finding.timestamp).toBeGreaterThan(0);
    expect(finding.entropy).toBeGreaterThan(0);
  });

  it('does not include rawValue on the Finding object', async () => {
    const results = scan('AKIAIOSFODNN7EXAMPLE1', OPTS);
    const finding = await results[0]!.toFinding();
    expect((finding as unknown as { rawValue?: string }).rawValue).toBeUndefined();
  });

  it('produces a consistent value hash for the same input', async () => {
    const r1 = scan('AKIAIOSFODNN7EXAMPLE1', OPTS);
    const r2 = scan('AKIAIOSFODNN7EXAMPLE1', OPTS);
    const [f1, f2] = await Promise.all([r1[0]!.toFinding(), r2[0]!.toFinding()]);
    expect(f1.valueHash).toBe(f2.valueHash);
  });

  it('produces different value hashes for different values', async () => {
    const r1 = scan('AKIAIOSFODNN7EXAMPLE1', OPTS);
    const r2 = scan('AKIAI44QH8DHBEXAMPLE2', OPTS);
    const [f1, f2] = await Promise.all([r1[0]!.toFinding(), r2[0]!.toFinding()]);
    expect(f1.valueHash).not.toBe(f2.valueHash);
  });
});

// ─── Source type passthrough ──────────────────────────────────────────────────

describe('scan — source type passthrough', () => {
  const sourceTypes = [
    'request-header',
    'request-body',
    'response-header',
    'response-body',
    'js-bundle',
    'html-source',
    'url-param',
  ] as const;

  for (const sourceType of sourceTypes) {
    it(`preserves sourceType "${sourceType}"`, () => {
      const results = scan('AKIAIOSFODNN7EXAMPLE1', { ...OPTS, sourceType });
      expect(results[0]?.sourceType).toBe(sourceType);
    });
  }
});

// ─── Edge cases ───────────────────────────────────────────────────────────────

describe('scan — edge cases', () => {
  it('handles very large inputs without throwing', () => {
    const large = 'x'.repeat(100_000) + 'AKIAIOSFODNN7EXAMPLE1' + 'y'.repeat(100_000);
    expect(() => scan(large, OPTS)).not.toThrow();
  });

  it('handles inputs with unicode without throwing', () => {
    const input = '🔑 AKIAIOSFODNN7EXAMPLE1 🚀 こんにちは';
    expect(() => scan(input, OPTS)).not.toThrow();
    expect(scan(input, OPTS)).toHaveLength(1);
  });

  it('handles JSON stringified objects', () => {
    const payload = JSON.stringify({
      config: { aws_key: 'AKIAIOSFODNN7EXAMPLE1' },
    });
    const results = scan(payload, OPTS);
    expect(results.length).toBeGreaterThanOrEqual(1);
  });

  it('handles multiline strings', () => {
    const input = `
      const config = {
        awsKey: "AKIAIOSFODNN7EXAMPLE1",
        stripeKey: "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
      };
    `;
    const results = scan(input, OPTS);
    expect(results.length).toBeGreaterThanOrEqual(2);
  });

  it('skips values shorter than 8 characters', () => {
    // Even if regex matches, values < 8 chars are skipped
    const shortPattern: Pattern = {
      id: 'short-test',
      name: 'Short Test',
      regex: /TINY([A-Z]{3})/,
      severity: 'info',
    };
    const results = scan('TINYABC', { ...OPTS, patterns: [shortPattern] });
    expect(results).toHaveLength(0);
  });
});

// ─── False positive rate measurement ─────────────────────────────────────────

describe('scan — false positive rate on benign corpus', () => {
  const BENIGN_CORPUS = [
    'const version = "1.0.0"',
    'backgroundColor: "#1a1a1a"',
    '<div class="container">Hello</div>',
    'process.env.PORT || 3000',
    'https://api.example.com/v1/users',
    '550e8400-e29b-41d4-a716-446655440000',
    'f47ac10b-58cc-4372-a567-0e02b2c3d479',
    'console.log("Hello, world!")',
    'npm install --save-dev typescript',
    '{"status":"ok","timestamp":1714000000}',
    'SELECT * FROM users WHERE id = $1',
    'function fetchData(url) { return fetch(url); }',
    'padding: 16px; margin: 0 auto;',
    'git commit -m "feat: add user auth"',
    'export default function App() {}',
    'import React from "react"',
    '<meta charset="UTF-8">',
    'Authorization: Basic dXNlcjpwYXNz', // too short after base64
    'Content-Type: application/json',
    'Host: localhost:3000',
  ];

  it('fires on fewer than 10% of benign strings using real patterns', () => {
    const { PATTERNS: REAL_PATTERNS } = require('../src/engine/patterns');
    let hits = 0;

    for (const str of BENIGN_CORPUS) {
      const results = scan(str, { ...OPTS, patterns: REAL_PATTERNS });
      if (results.length > 0) hits++;
    }

    const fpRate = hits / BENIGN_CORPUS.length;
    expect(
      fpRate,
      `False positive rate ${(fpRate * 100).toFixed(1)}% exceeds 10% threshold. ${hits}/${BENIGN_CORPUS.length} benign strings triggered.`
    ).toBeLessThan(0.10);
  });
});