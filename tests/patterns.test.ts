import { describe, it, expect } from 'vitest';
import { scan } from '../src/engine/scanner';

// A small sample of what your 200+ test corpus will look like
const KNOWN_SECRETS = [
  { name: 'Slack Bot Token', value: 'xoxb-123456789012-1234567890123-abcdef1234567890abcdef12' },
  { name: 'AWS Access Key', value: 'AKIAIOSFODNN7EXAMPLE' },
  { name: 'Stripe Secret Key', value: 'sk_live_1234567890abcdefGHIJKLMN' }
];

describe('Regex Pattern Corpus', () => {
  const mockContext = { url: 'http://localhost', tabId: 0, sourceType: 'html-source' as const };

  KNOWN_SECRETS.forEach(({ name, value }) => {
    it(`successfully detects: ${name}`, () => {
      // Wrap the secret in some noise to simulate realistic exposure
      const payload = `const config = { key: "${value}", debug: true };`;
      
      const findings = scan(payload, mockContext);
      expect(findings.length).toBeGreaterThan(0);
      
      // Verify the correct pattern was matched
      const matchedPattern = findings.some(f => f.patternName.includes(name.split(' ')[0]));
      expect(matchedPattern).toBe(true);
    });
  });
});