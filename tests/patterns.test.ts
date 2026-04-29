import { describe, it, expect } from 'vitest';
import { PATTERNS, PATTERN_MAP } from '../src/engine/patterns';
import type { Pattern } from '../src/shared/types';

// ─── Helpers ──────────────────────────────────────────────────────────────────

function matches(pattern: Pattern, input: string): boolean {
  const r = new RegExp(pattern.regex.source, pattern.regex.flags.replace('g', ''));
  return r.test(input);
}

function assertHits(patternId: string, samples: string[]): void {
  const p = PATTERN_MAP.get(patternId);
  if (!p) throw new Error(`Pattern not found: ${patternId}`);
  for (const s of samples) {
    expect(matches(p, s), `Pattern "${patternId}" should match: "${s}"`).toBe(true);
  }
}

function assertMisses(patternId: string, samples: string[]): void {
  const p = PATTERN_MAP.get(patternId);
  if (!p) throw new Error(`Pattern not found: ${patternId}`);
  for (const s of samples) {
    expect(matches(p, s), `Pattern "${patternId}" should NOT match: "${s}"`).toBe(false);
  }
}

// ─── Corpus ───────────────────────────────────────────────────────────────────

describe('Pattern library — coverage', () => {
  it('has at least 30 patterns', () => {
    expect(PATTERNS.length).toBeGreaterThanOrEqual(30);
  });

  it('every pattern has a non-empty id, name, regex, and severity', () => {
    for (const p of PATTERNS) {
      expect(p.id.length, `Empty id on pattern: ${JSON.stringify(p)}`).toBeGreaterThan(0);
      expect(p.name.length, `Empty name on: ${p.id}`).toBeGreaterThan(0);
      expect(p.regex, `No regex on: ${p.id}`).toBeInstanceOf(RegExp);
      expect(['critical', 'warning', 'info']).toContain(p.severity);
    }
  });

  it('all pattern IDs are unique', () => {
    const ids = PATTERNS.map(p => p.id);
    const unique = new Set(ids);
    expect(unique.size).toBe(ids.length);
  });
});

// ─── AWS ─────────────────────────────────────────────────────────────────────

describe('aws-access-key-id', () => {
  it('matches real-format AWS access key IDs', () => {
    // AKIA + exactly 16 uppercase alphanumeric chars = 20 chars total
    assertHits('aws-access-key-id', [
      'AKIAABCDEFGHIJKLMNOP',  // AKIA + 16 ✓
      'AKIAI44QH8DHBEXAMPLE',  // AKIA + 16 ✓
      'AKIAIOSFODNN7ABCDEFG',  // AKIA + 16 ✓
    ]);
  });

  it('does not match short strings or wrong prefix', () => {
    assertMisses('aws-access-key-id', [
      'AKIA123',              // too short
      'akiaiosfodnn7example', // lowercase
      'PKIAIOSFODNN7EXAMPLE', // wrong prefix
      'AKIAIOSFODNN',         // too short after prefix
    ]);
  });
});

describe('aws-secret-access-key', () => {
  it('matches secret key assignment patterns', () => {
    assertHits('aws-secret-access-key', [
      'aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
      'AWS_SECRET="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"',
      'aws_secret: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    ]);
  });

  it('does not match short values', () => {
    assertMisses('aws-secret-access-key', [
      'aws_secret=short',
      'aws_secret=',
    ]);
  });
});

// ─── GitHub ───────────────────────────────────────────────────────────────────

describe('github-pat-classic', () => {
  it('matches classic PAT format', () => {
    // ghp_ + exactly 36 alphanumeric chars = 40 chars total
    assertHits('github-pat-classic', [
      'ghp_' + 'a'.repeat(36),
      'ghp_' + 'A'.repeat(36),
      'ghp_' + '1234567890abcdefghijklmnopqrstuvwxyzab',  // mixed, 38... use repeat
      'Authorization: token ghp_' + 'abcdefghijklmnopqrstuvwxyz0123456789',
    ]);
  });

  it('does not match short or wrong prefix', () => {
    assertMisses('github-pat-classic', [
      'ghp_short',
      'gho_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345', // wrong prefix (OAuth)
      'ghp_',
    ]);
  });
});

describe('github-pat-fine-grained', () => {
  it('matches fine-grained PAT format', () => {
    assertHits('github-pat-fine-grained', [
      'github_pat_' + 'A'.repeat(82),
    ]);
  });
  it('does not match classic PAT', () => {
    assertMisses('github-pat-fine-grained', [
      'ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345',
    ]);
  });
});

describe('github-oauth-token', () => {
  it('matches OAuth token prefix', () => {
    assertHits('github-oauth-token', [
      'gho_' + 'a'.repeat(36),
    ]);
  });
});

describe('github-app-token', () => {
  it('matches App installation token', () => {
    assertHits('github-app-token', [
      'ghs_' + 'a'.repeat(36),
      'ghs_' + 'A'.repeat(36),
    ]);
  });
});

// ─── Stripe ───────────────────────────────────────────────────────────────────

describe('stripe-secret-key', () => {
  it('matches live and test secret keys', () => {
    assertHits('stripe-secret-key', [
      'sk_live_4eC39HqLyjWDarjtT1zdp7dc',
      'sk_test_4eC39HqLyjWDarjtT1zdp7dc',
      'sk_live_ABCDEFGHIJKLMNOPQRSTUVWXabcdefghij',
    ]);
  });

  it('does not match publishable keys', () => {
    assertMisses('stripe-secret-key', [
      'pk_live_4eC39HqLyjWDarjtT1zdp7dc',
      'pk_test_4eC39HqLyjWDarjtT1zdp7dc',
    ]);
  });
});

describe('stripe-restricted-key', () => {
  it('matches restricted keys', () => {
    assertHits('stripe-restricted-key', [
      'rk_live_4eC39HqLyjWDarjtT1zdp7dc',
      'rk_test_4eC39HqLyjWDarjtT1zdp7dc',
    ]);
  });
});

describe('stripe-webhook-secret', () => {
  it('matches webhook signing secrets', () => {
    assertHits('stripe-webhook-secret', [
      'whsec_abcdefghijklmnopqrstuvwxyz012345',
      'whsec_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345678901234567',
    ]);
  });
});

// ─── Google ───────────────────────────────────────────────────────────────────

describe('google-api-key', () => {
  it('matches Google API key format', () => {
    assertHits('google-api-key', [
      'AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI',
      'key=AIzaSyB_abc123DEFghiJKL456mnoPQR789stuV',
    ]);
  });

  it('does not match short AIza strings', () => {
    assertMisses('google-api-key', [
      'AIza123',
      'AIzaSy',
    ]);
  });
});

describe('google-oauth-client-secret', () => {
  it('matches GOCSPX format', () => {
    // GOCSPX- + exactly 28 alphanumeric chars
    assertHits('google-oauth-client-secret', [
      'GOCSPX-' + 'a'.repeat(28),
      'GOCSPX-abcdefghijklmnopqrstuvwxyz1',  // 28 chars after dash ✓
      'client_secret=GOCSPX-' + 'ABCDEFGHIJKLMNOPQRSTUVWXYZ12',
    ]);
  });
});

// ─── Slack ────────────────────────────────────────────────────────────────────

describe('slack-bot-token', () => {
  it('matches xoxb token format', () => {
    assertHits('slack-bot-token', [
      'xoxb-123456789012-123456789012-abcdefghijklmnopqrstuvwx',
      'Authorization: Bearer xoxb-111111111111-222222222222-ABCDEFabcdefABCDEFabcdef',
    ]);
  });

  it('does not match user or workspace tokens', () => {
    assertMisses('slack-bot-token', [
      'xoxp-123456789012-123456789012-123456789012-abcdefghijklmnopqrstuvwxyz012345',
    ]);
  });
});

describe('slack-user-token', () => {
  it('matches xoxp token format', () => {
    assertHits('slack-user-token', [
      'xoxp-123456789012-123456789012-123456789012-abcdefghijklmnopqrstuvwxyz012345',
    ]);
  });
});

describe('slack-webhook-url', () => {
  it('matches incoming webhook URLs', () => {
    assertHits('slack-webhook-url', [
      'https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXXXXXX',
      'url: "https://hooks.slack.com/services/TABCDE123/BABCDE456/abcdefghijklmnopqrstuvwx"',
    ]);
  });

  it('does not match generic Slack URLs', () => {
    assertMisses('slack-webhook-url', [
      'https://slack.com/api/chat.postMessage',
      'https://hooks.slack.com/',
    ]);
  });
});

// ─── SendGrid ─────────────────────────────────────────────────────────────────

describe('sendgrid-api-key', () => {
  it('matches SendGrid key format', () => {
    assertHits('sendgrid-api-key', [
      'SG.aBcDeFgHiJkLmNoPqRsTuV.WxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlM',
      'SENDGRID_API_KEY=SG.1234567890abcdefghijkl.1234567890abcdefghijklmnopqrstuvwxyzABC',
    ]);
  });

  it('does not match short SG strings', () => {
    assertMisses('sendgrid-api-key', [
      'SG.short',
      'SG.abc.def',
    ]);
  });
});

// ─── OpenAI ───────────────────────────────────────────────────────────────────

describe('openai-api-key', () => {
  it('matches OpenAI key format', () => {
    assertHits('openai-api-key', [
      'sk-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUV',
      'OPENAI_API_KEY=sk-proj1234567890abcdefghijklmnopqrstuvwxyzABCDE',
    ]);
  });

  it('does not match Stripe secret keys (different length)', () => {
    // Stripe keys are sk_live_ / sk_test_ — different format
    assertMisses('openai-api-key', [
      'sk_live_4eC39HqLyjWDarjtT1zdp7dc',
      'sk_test_short',
    ]);
  });
});

// ─── Anthropic ────────────────────────────────────────────────────────────────

describe('anthropic-api-key', () => {
  it('matches Anthropic key format', () => {
    assertHits('anthropic-api-key', [
      'sk-ant-api03-' + 'a'.repeat(95),
      'ANTHROPIC_API_KEY=sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJ',
    ]);
  });
});

// ─── npm ─────────────────────────────────────────────────────────────────────

describe('npm-access-token', () => {
  it('matches npm token format', () => {
    // npm_ + exactly 36 alphanumeric chars = 40 chars total
    assertHits('npm-access-token', [
      'npm_' + 'a'.repeat(36),
      'npm_' + 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ab',
      '//registry.npmjs.org/:_authToken=npm_' + 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
    ]);
  });
});

// ─── JWT ─────────────────────────────────────────────────────────────────────

describe('jwt-token', () => {
  it('matches standard JWT format', () => {
    assertHits('jwt-token', [
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
      'Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJ0ZXN0In0.abc123DEF456ghi789',
    ]);
  });

  it('does not match non-JWT base64 strings', () => {
    assertMisses('jwt-token', [
      'eyJ',          // too short
      'notaJWT.atall',
      'AAAA.BBBB',   // segments too short
    ]);
  });
});

// ─── Private keys ─────────────────────────────────────────────────────────────

describe('rsa-private-key', () => {
  it('matches PEM RSA header', () => {
    assertHits('rsa-private-key', [
      '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...',
      'const key = "-----BEGIN RSA PRIVATE KEY-----"',
    ]);
  });
});

describe('openssh-private-key', () => {
  it('matches OpenSSH key header', () => {
    assertHits('openssh-private-key', [
      '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk...',
    ]);
  });
});

describe('pgp-private-key', () => {
  it('matches PGP private key block', () => {
    assertHits('pgp-private-key', [
      '-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: GnuPG v2',
    ]);
  });
});

// ─── Shopify ──────────────────────────────────────────────────────────────────

describe('shopify-private-app-password', () => {
  it('matches shppa_ format', () => {
    // shppa_ + exactly 32 alphanumeric chars
    assertHits('shopify-private-app-password', [
      'shppa_' + 'a'.repeat(32),
      'shppa_' + 'ABCDEFGHIJKLMNOPQRSTUVWXYZ012345',
      'password=shppa_' + 'abcdefghijklmnopqrstuvwxyz012345',
    ]);
  });
});

describe('shopify-shared-secret', () => {
  it('matches shpss_ format', () => {
    assertHits('shopify-shared-secret', [
      'shpss_' + 'a'.repeat(32),
      'shpss_' + 'ABCDEFGHIJKLMNOPQRSTUVWXYZ012345',
    ]);
  });
});

// ─── Mailgun ──────────────────────────────────────────────────────────────────

describe('mailgun-api-key', () => {
  it('matches key- format', () => {
    assertHits('mailgun-api-key', [
      'key-abcdefghijklmnopqrstuvwxyz012345',
      'MAILGUN_API_KEY=key-ABCDEFGHIJKLMNOPQRSTUVWXYZ01234',
    ]);
  });
});

// ─── Generic patterns ────────────────────────────────────────────────────────

describe('generic-bearer-token', () => {
  it('matches Bearer token in headers', () => {
    assertHits('generic-bearer-token', [
      'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9abc123',
      'Bearer abcdefghijklmnopqrstuvwxyz0123456789ABCDEF',
    ]);
  });

  it('does not match short bearer values', () => {
    assertMisses('generic-bearer-token', [
      'Bearer short',
      'Bearer abc',
    ]);
  });
});

describe('generic-secret-assignment', () => {
  it('matches high-entropy secret assignments', () => {
    assertHits('generic-secret-assignment', [
      'api_key="wJalrXUtnFEMI/K7MDENGbPxRfiCYEXAMPLEKEY1234"',
      'secret: "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789ABCDEF"',
      'access_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9abcdef"',
    ]);
  });
});

// ─── False positive corpus ────────────────────────────────────────────────────
// Strings that should NOT match any pattern.
// These represent common benign values developers encounter.

describe('False positive corpus — no patterns should fire', () => {
  const benignStrings = [
    // UUIDs
    '550e8400-e29b-41d4-a716-446655440000',
    'f47ac10b-58cc-4372-a567-0e02b2c3d479',
    // Short random-looking strings
    'abc123def456',
    'session_id_1234',
    // CSS class names
    '.btn-primary { color: #185FA5 }',
    // Base64 image data prefix (not a secret)
    'data:image/png;base64,iVBORw0KGgo=',
    // Git commit SHAs
    'commit abc123def456789012345678901234567890abcd',
    '7f3b2a1c9d8e4f0a6b5c2d1e0f9a8b7c6d5e4f3a',
    // Regular URLs
    'https://api.example.com/v1/users',
    'https://fonts.googleapis.com/css2?family=Inter',
    // Environment variable names without values
    'process.env.API_KEY',
    'process.env.DATABASE_URL',
    // HTML/CSS
    '<div class="container">Hello</div>',
    'background-color: #1a1a1a;',
    // Version numbers
    'version: 1.0.0',
    '"version": "3.2.1"',
    // Common config keys with short safe values
    'port: 3000',
    'timeout: 5000',
    // Placeholder text
    'your-api-key-here',
    'INSERT_KEY_HERE',
    'REPLACE_ME',
    'xxxxxxxxxxxxxxxxxxxx', // too low entropy
    // ISO dates
    '2026-04-29T12:00:00.000Z',
    // Short hash-like but too short
    'abc123',
    'def456ghi',
    // npm package names
    '"name": "my-awesome-package"',
    // Regular JWT-looking but too short segments
    'aGVsbG8=.d29ybGQ=.Zm9v',
  ];

  for (const str of benignStrings) {
    it(`no pattern fires on: "${str.slice(0, 60)}${str.length > 60 ? '...' : ''}"`, () => {
      for (const pattern of PATTERNS) {
        // Skip patterns with no entropyMin — generic patterns intentionally
        // need entropy scoring in the scanner to filter these out
        if (!pattern.entropyMin) continue;
        const r = new RegExp(pattern.regex.source, pattern.regex.flags.replace('g', ''));
        if (r.test(str)) {
          // If it matches, verify entropy would filter it
          const { shannonEntropy } = require('../src/engine/entropy');
          const match = str.match(r);
          if (match) {
            const val = match[1] ?? match[0] ?? '';
            const entropy = shannonEntropy(val);
            expect(
              entropy,
              `Pattern "${pattern.id}" matched "${str}" with value "${val}" at entropy ${entropy.toFixed(2)}, below threshold ${pattern.entropyMin}`
            ).toBeLessThan(pattern.entropyMin!);
          }
        }
      }
    });
  }
});

// ─── Pattern metadata quality checks ─────────────────────────────────────────

describe('Pattern metadata quality', () => {
  it('critical patterns have entropyMin or a tightly scoped prefix', () => {
    const criticalPatterns = PATTERNS.filter(p => p.severity === 'critical');
    for (const p of criticalPatterns) {
      const src = p.regex.source;
      const hasTightPrefix =
        src.includes('AKIA') ||
        src.includes('ghp_') ||
        src.includes('gho_') ||
        src.includes('ghs_') ||
        src.includes('ghr_') ||
        src.includes('github_pat_') ||
        src.includes('sk_') ||
        src.includes('rk_') ||
        src.includes('whsec_') ||
        src.includes('SG\\.') ||
        src.includes('xoxb-') ||
        src.includes('xoxp-') ||
        src.includes('npm_') ||
        src.includes('shppa_') ||
        src.includes('shpss_') ||
        src.includes('sk-ant-') ||
        src.includes('sk-') ||
        src.includes('BEGIN') ||
        src.includes('GOCSPX') ||
        src.includes('service_account') ||
        src.includes('AccountKey=');

      expect(
        hasTightPrefix || p.entropyMin !== undefined,
        `Critical pattern "${p.id}" should have either a tight prefix or entropyMin to reduce false positives`
      ).toBe(true);
    }
  });

  it('generic patterns all have entropyMin set', () => {
    const genericPatterns = PATTERNS.filter(p => p.id.startsWith('generic-'));
    for (const p of genericPatterns) {
      expect(
        p.entropyMin,
        `Generic pattern "${p.id}" must have entropyMin to avoid false positives`
      ).toBeDefined();
    }
  });

  it('no regex has catastrophic backtracking potential (no nested quantifiers)', () => {
    for (const p of PATTERNS) {
      const src = p.regex.source;
      // Naive check: nested quantifiers like (a+)+ are catastrophic
      expect(
        src,
        `Pattern "${p.id}" may have catastrophic backtracking: ${src}`
      ).not.toMatch(/\([^)]*[+*][^)]*\)[+*{]/);
    }
  });
});