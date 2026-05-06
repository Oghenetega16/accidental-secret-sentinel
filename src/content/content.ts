/**
 * content.ts — MAIN world entry point.
 *
 * Communication architecture:
 *   MAIN world → service worker : chrome.runtime.sendMessage (works fine)
 *   service worker → MAIN world : chrome.tabs.sendMessage → relay.ts (ISOLATED)
 *                                 → window.postMessage → this file
 *
 * chrome.tabs.sendMessage cannot reach MAIN world directly — the relay
 * script bridges the gap.
 */

import { interceptFetch, interceptXHR } from './fetch-intercept';
import { DomScanner } from './dom-scanner';
import { showFindingToast } from './toast';
import type { Finding } from '../shared/types';

const SENTINEL_MSG_KEY = '__sentinel_finding__';

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

  // Patch fetch + XHR before any page script runs
  interceptFetch(tabId);
  interceptXHR(tabId);

  // DOM scan after DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => startDomScanner(tabId), { once: true });
  } else {
    startDomScanner(tabId);
  }

  // Listen for findings forwarded by relay.ts via window.postMessage
  // This is the only reliable way to receive messages in MAIN world.
  window.addEventListener('message', (event) => {
    if (
      event.source === window &&
      event.data?.[SENTINEL_MSG_KEY] === true
    ) {
      handleFinding(event.data.finding as Finding);
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

// One toast per pattern per page load — relay may fire multiple times
// for the same pattern if the popup is also open.
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

init().catch(err => console.warn('[Sentinel] init error:', err));