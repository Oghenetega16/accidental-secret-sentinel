import { describe, it, expect } from 'vitest';
import { shannonEntropy, meetsEntropyThreshold } from '../src/engine/entropy';

describe('shannonEntropy', () => {
  it('returns 0 for empty string', () => {
    expect(shannonEntropy('')).toBe(0);
  });

  it('returns 0 for a single repeated character', () => {
    expect(shannonEntropy('aaaaaaaaaa')).toBe(0);
  });

  it('scores a simple English word low', () => {
    // "password" has repeated chars, low entropy
    expect(shannonEntropy('password')).toBeLessThan(3.0);
  });

  it('scores a UUID reasonably high', () => {
    expect(shannonEntropy('550e8400-e29b-41d4-a716-446655440000')).toBeGreaterThan(3.5);
  });

  it('scores a random base64 string high', () => {
    // Simulated 32-byte random secret base64-encoded
    expect(shannonEntropy('wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY')).toBeGreaterThan(4.0);
  });

  it('scores a real AWS access key high', () => {
    expect(shannonEntropy('AKIAIOSFODNN7EXAMPLE')).toBeGreaterThan(3.5);
  });

  it('scores a low-variety string below threshold', () => {
    expect(shannonEntropy('aabbccddaabbccdd')).toBeLessThan(2.5);
  });

  it('scores a GitHub PAT high', () => {
    expect(shannonEntropy('ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345')).toBeGreaterThan(4.0);
  });

  it('handles a single character string', () => {
    expect(shannonEntropy('x')).toBe(0);
  });

  it('scores a max-entropy string near log2(charSet)', () => {
    // All unique ASCII chars → entropy approaches log2(n)
    const unique = 'abcdefghijklmnopqrstuvwxyz0123456789';
    expect(shannonEntropy(unique)).toBeGreaterThan(5.0);
  });
});

describe('meetsEntropyThreshold', () => {
  it('always passes when no threshold given', () => {
    expect(meetsEntropyThreshold('aaa', undefined)).toBe(true);
    expect(meetsEntropyThreshold('', undefined)).toBe(true);
  });

  it('passes when entropy meets threshold', () => {
    const highEntropy = 'AKIAIOSFODNN7EXAMPLE';
    expect(meetsEntropyThreshold(highEntropy, 3.5)).toBe(true);
  });

  it('fails when entropy is below threshold', () => {
    expect(meetsEntropyThreshold('aaaaaaaaaaaaaaaa', 3.5)).toBe(false);
  });

  it('passes at exactly the threshold', () => {
    // Find a value whose entropy is exactly at the boundary
    const val = 'abcdabcdabcdabcd'; // ~2.0 entropy
    const e = shannonEntropy(val);
    expect(meetsEntropyThreshold(val, e)).toBe(true);  // exactly at threshold = pass
    expect(meetsEntropyThreshold(val, e + 0.001)).toBe(false);
  });
});