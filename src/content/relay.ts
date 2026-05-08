/**
 * coordinator.ts — runs in ISOLATED world (default for content scripts).
 *
 * Bridges MAIN world ↔ service worker:
 *   MAIN world cannot use chrome.runtime (it's the page's JS context).
 *   ISOLATED world has full extension API access.
 *
 * MAIN → ISOLATED: window.postMessage({ __sentinel_to_bg__: true, ... })
 * ISOLATED → MAIN: window.postMessage({ __sentinel_to_page__: true, ... })
 */

const TO_BG   = '__sentinel_to_bg__';
const TO_PAGE = '__sentinel_to_page__';

// ── MAIN world → service worker ──────────────────────────────────────────────

window.addEventListener('message', (event) => {
  if (event.source !== window) return;

  const data = event.data;
  if (!data || data[TO_BG] !== true) return;

  // Forward FINDING_DETECTED to service worker.
  // The service worker will override tabId from sender.tab.id.
  chrome.runtime.sendMessage(data.message).catch(() => {});
});

// ── service worker → MAIN world ───────────────────────────────────────────────

chrome.runtime.onMessage.addListener((message) => {
  if (message.type === 'FINDING_DETECTED') {
    window.postMessage({ [TO_PAGE]: true, finding: message.finding }, '*');
  }
});

// ── Settings / tabId relay ────────────────────────────────────────────────────
// MAIN world needs settings before scanning. Request them via postMessage.

window.addEventListener('message', (event) => {
  if (event.source !== window) return;
  const data = event.data;
  if (!data) return;

  if (data.__sentinel_get_settings__) {
    chrome.runtime.sendMessage({ type: 'GET_SETTINGS' }, (response) => {
      window.postMessage({
        __sentinel_settings__: true,
        settings: response?.settings ?? { enabled: true, disabledDomains: [] },
      }, '*');
    });
  }
});