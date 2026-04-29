/**
 * Calculates the Shannon entropy of a string.
 * Range: 0 (all same character) to log2(charSetSize) (perfectly random).
 *
 * Most real secrets score above 3.5. UUIDs score ~3.9. Random base64 ~4.5+.
 * Short English words score below 3.0.
 *
 * @param value The string to score
 * @returns Shannon entropy value (bits per character)
 */
export function shannonEntropy(value: string): number {
  if (value.length === 0) return 0;

  const freq = new Map<string, number>();
  for (const char of value) {
    freq.set(char, (freq.get(char) ?? 0) + 1);
  }

  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / value.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/**
 * Returns true if the value's entropy meets or exceeds the minimum threshold.
 * Patterns without an entropyMin always pass this check.
 */
export function meetsEntropyThreshold(
  value: string,
  entropyMin: number | undefined
): boolean {
  if (entropyMin === undefined) return true;
  return shannonEntropy(value) >= entropyMin;
}