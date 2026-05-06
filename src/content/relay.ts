/**
 * relay.ts — runs in ISOLATED world (default for content scripts).
 *
 * chrome.tabs.sendMessage from the service worker reaches ISOLATED world
 * but NOT MAIN world. This relay bridges the gap by forwarding messages
 * to the MAIN world via window.postMessage.
 *
 * MAIN world (content.ts) listens for window.message events with
 * source === window and the SENTINEL_MSG_KEY prefix.
 */

export const SENTINEL_MSG_KEY = '__sentinel_finding__';

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.type === 'FINDING_DETECTED') {
    // Forward to MAIN world via postMessage
    window.postMessage(
      { [SENTINEL_MSG_KEY]: true, finding: message.finding },
      window.location.origin || '*'
    );
  }
  sendResponse(null);
});