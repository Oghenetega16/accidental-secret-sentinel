/**
 * Content script — runs at document_start in the MAIN world.
 *
 * Execution order:
 * 1. Negotiate tab ID with the service worker
 * 2. Check global enabled flag + domain allowlist
 * 3. Patch fetch + XHR immediately (before any page JS runs)
 * 4. Start DOM scanner after DOMContentLoaded
 * 5. Listen for findings echoed back from the service worker and show toasts
 */

import { interceptFetch, interceptXHR } from './fetch-intercept';
import { DomScanner } from './dom-scanner';
import { showFindingToast } from './toast';
import type { Finding, Message } from '../shared/types';

// ─── Boot ─────────────────────────────────────────────────────────────────────

async function init(): Promise<void> {
  const tabId = await getTabId();
  if (tabId === null || tabId === -1) return;

  const settings = await getSettings();
  if (!settings.enabled) return;

  const hostname = window.location.hostname;
  const isDomainDisabled = settings.disabledDomains.some(
    (d: string) => hostname === d || hostname.endsWith('.' + d)
  );
  if (isDomainDisabled) return;

  // Patch fetch + XHR before any page script runs (document_start)
  interceptFetch(tabId);
  interceptXHR(tabId);

  // DOM scan after DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => startDomScanner(tabId), { once: true });
  } else {
    startDomScanner(tabId);
  }

  // Listen for findings echoed back from service worker → show toasts
  chrome.runtime.onMessage.addListener((message: Message) => {
    if (message.type === 'FINDING_DETECTED' && message.finding.tabId === tabId) {
      handleFinding(message.finding);
    }
  });
}

// ─── DOM scanner lifecycle ────────────────────────────────────────────────────

let domScanner: InstanceType<typeof DomScanner> | null = null;

function startDomScanner(tabId: number): void {
  domScanner = new DomScanner(tabId);
  domScanner.start();
  window.addEventListener('beforeunload', () => {
    domScanner?.stop();
    domScanner = null;
  }, { once: true });
}

// ─── Finding handler ──────────────────────────────────────────────────────────

const shownPatterns = new Set<string>();

function handleFinding(finding: Finding): void {
  if (!shownPatterns.has(finding.patternId)) {
    shownPatterns.add(finding.patternId);
    showFindingToast(finding);
  }
}

// ─── IPC helpers ─────────────────────────────────────────────────────────────

async function getTabId(): Promise<number | null> {
  return new Promise(resolve => {
    try {
      chrome.runtime.sendMessage({ type: 'GET_TAB_ID' }, response => {
        if (chrome.runtime.lastError || !response) { resolve(null); return; }
        resolve((response as { tabId: number }).tabId ?? null);
      });
    } catch { resolve(null); }
  });
}

async function getSettings(): Promise<{ enabled: boolean; disabledDomains: string[] }> {
  return new Promise(resolve => {
    const fallback = { enabled: true, disabledDomains: [] };
    try {
      chrome.runtime.sendMessage({ type: 'GET_SETTINGS' }, response => {
        if (chrome.runtime.lastError || !response) { resolve(fallback); return; }
        resolve((response as { settings: typeof fallback }).settings ?? fallback);
      });
    } catch { resolve(fallback); }
  });
}

// Boot
init().catch(err => console.warn('[Sentinel] init error:', err));