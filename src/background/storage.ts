import type { StorageLocal, StorageSync, SessionFindings } from '../shared/types';

// ─── Default values ───────────────────────────────────────────────────────────

export const DEFAULT_SYNC: StorageSync = {
  suppressions: [],
  customPatterns: [],
  disabledDomains: [],
  enabled: true,
};

export const DEFAULT_LOCAL: StorageLocal = {
  findings: {},
};

// ─── Sync storage (settings, suppressions) ───────────────────────────────────

export async function getSettings(): Promise<StorageSync> {
  const result = await chrome.storage.sync.get(DEFAULT_SYNC);
  return result as StorageSync;
}

export async function updateSettings(partial: Partial<StorageSync>): Promise<void> {
  await chrome.storage.sync.set(partial);
}

// ─── Local storage (session findings) ────────────────────────────────────────

export async function getFindings(tabId: number) {
  const result = await chrome.storage.local.get('findings');
  const findings: SessionFindings = result['findings'] ?? {};
  return findings[String(tabId)] ?? [];
}

export async function addFinding(finding: import('../shared/types').Finding): Promise<void> {
  const result = await chrome.storage.local.get('findings');
  const all: SessionFindings = result['findings'] ?? {};
  const key = String(finding.tabId);
  const existing = all[key] ?? [];

  // Deduplicate by valueHash — same secret, same tab
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
  const findings = await getFindings(tabId);
  return findings.length;
}