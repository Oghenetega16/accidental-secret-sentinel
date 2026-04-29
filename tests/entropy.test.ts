import { describe, it, expect } from 'vitest';
import { shannonEntropy, meetsEntropyThreshold } from '../src/engine/entropy';

describe('Shannon Entropy Scorer', () => {
  it('returns low entropy for simple or repeating strings', () => {
    expect(shannonEntropy('aaaaaaaaaaaaaaaa')).toBeLessThan(1.0);
    expect(shannonEntropy('1234567890')).toBeLessThan(3.5);
  });

  it('returns high entropy for complex, random base64 or hex strings', () => {
    // A typical high-entropy secret structure
    const mockSecret = 'v1.a_bCdEfGhIjKlMnOpQrStUvWxYz0123456789';
    expect(shannonEntropy(mockSecret)).toBeGreaterThan(4.5);
  });

  it('handles empty strings gracefully', () => {
    expect(shannonEntropy('')).toBe(0);
  });

  describe('Threshold Checking', () => {
    it('passes if no threshold is set', () => {
      expect(meetsEntropyThreshold('abc', undefined)).toBe(true);
    });

    it('passes if entropy meets or exceeds minimum', () => {
      // '1234567890' scores around ~3.32
      expect(meetsEntropyThreshold('1234567890', 3.0)).toBe(true);
    });

    it('fails if entropy is below minimum', () => {
      // 'aaaaa' scores 0
      expect(meetsEntropyThreshold('aaaaa', 3.0)).toBe(false);
    });
  });
});