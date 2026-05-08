/**
 * content.ts — MAIN world.
 *
 * chrome.runtime is NOT available here (this is the page's JS context).
 * All extension API calls go through relay.ts (ISOLATED world) via postMessage.
 *
 * Protocol:
 *   MAIN → ISOLATED: window.postMessage({ __sentinel_to_bg__: true, message })
 *   ISOLATED → MAIN: window.postMessage({ __sentinel_to_page__: true, finding })
 *   MAIN asks for settings: window.postMessage({ __sentinel_get_settings__: true })
 *   ISOLATED replies:       window.postMessage({ __sentinel_settings__: true, settings })
 */

import { interceptFetch, interceptXHR } from './fetch-intercept';
import { DomScanner } from './dom-scanner';
import { showFindingToast } from './toast';
import type { Finding } from '../shared/types';

const TO_PAGE = '__sentinel_to_page__';

async function init(): Promise<void> {
  console.log('[Sentinel] MAIN world init, readyState:', document.readyState);

  // Ask coordinator (ISOLATED world) for settings
  const settings = await requestSettings();
  console.log('[Sentinel] settings received — enabled:', settings.enabled);

  if (!settings.enabled) return;

  const hostname = window.location.hostname;
  const blocked = settings.disabledDomains.some(
    (d: string) => hostname === d || hostname.endsWith('.' + d)
  );
  if (blocked) { console.log('[Sentinel] domain disabled:', hostname); return; }

  // Patch fetch + XHR (must happen before page JS runs — document_start)
  interceptFetch();
  interceptXHR();
  console.log('[Sentinel] fetch/XHR patched');

  // DOM scanner after DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', startDomScanner, { once: true });
  } else {
    startDomScanner();
  }

  // Toast trigger — coordinator posts findings back here after service worker confirms
  window.addEventListener('message', (event) => {
    if (event.source === window && event.data?.[TO_PAGE] === true) {
      console.log('[Sentinel] toast trigger received for:', event.data.finding?.patternId);
      handleFinding(event.data.finding as Finding);
    }
  });

  console.log('[Sentinel] init complete');
}

// ─── Settings request ─────────────────────────────────────────────────────────

function requestSettings(): Promise<{ enabled: boolean; disabledDomains: string[] }> {
  return new Promise(resolve => {
    const fallback = { enabled: true, disabledDomains: [] };
    const timeout = setTimeout(() => resolve(fallback), 1000);

    window.addEventListener('message', function handler(event) {
      if (event.source === window && event.data?.__sentinel_settings__ === true) {
        clearTimeout(timeout);
        window.removeEventListener('message', handler);
        resolve(event.data.settings ?? fallback);
      }
    });

    window.postMessage({ __sentinel_get_settings__: true }, '*');
  });
}

// ─── DOM scanner ──────────────────────────────────────────────────────────────

let domScanner: InstanceType<typeof DomScanner> | null = null;

function startDomScanner(): void {
  console.log('[Sentinel] starting DOM scanner');
  domScanner = new DomScanner();
  domScanner.start();
  window.addEventListener('beforeunload', () => {
    domScanner?.stop();
    domScanner = null;
  }, { once: true });
}

// ─── Toast handler ────────────────────────────────────────────────────────────

const shownPatterns = new Set<string>();

function handleFinding(finding: Finding): void {
  if (!shownPatterns.has(finding.patternId)) {
    shownPatterns.add(finding.patternId);
    showFindingToast(finding);
  }
}

init().catch(err => console.warn('[Sentinel] init error:', err));