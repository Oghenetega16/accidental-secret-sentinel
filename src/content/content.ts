import { DomScanner } from './dom-scanner';

/**
 * Content script — runs at document_start in the ISOLATED world.
 *
 * Execution order:
 * 1. Ask service worker for our tabId
 * 2. Check if scanning is enabled / domain is not blocked
 * 3. Inject the MAIN world monkey-patch script via a <script> tag
 * 4. Set up the IPC relay to listen for findings from the MAIN world
 * 5. Start DOM scanner once DOMContentLoaded fires
 */

async function init(): Promise<void> {
  // Get our tabId from the background
  const tabId = await getTabId();
  if (tabId === null) return;

  // Check if the extension is enabled and this domain isn't blocked
  const settings = await new Promise<{ enabled: boolean; disabledDomains: string[] }>(resolve => {
    chrome.runtime.sendMessage({ type: 'GET_SETTINGS' }, response => {
      resolve(response?.settings ?? { enabled: true, disabledDomains: [] });
    });
  });

  if (!settings.enabled) return;

  const hostname = window.location.hostname;
  const isDomainDisabled = settings.disabledDomains.some(
    d => hostname === d || hostname.endsWith('.' + d)
  );
  if (isDomainDisabled) return;

  // 1. Set up the message relay from the MAIN world to the Service Worker
  setupMessageRelay(tabId);

  // 2. Inject the monkey-patch into the MAIN world immediately
  injectMainWorldInterceptor();

  // 3. Start DOM scanner after DOM is available
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => startDomScanner(tabId));
  } else {
    startDomScanner(tabId);
  }
}

function injectMainWorldInterceptor(): void {
  // To run in the MAIN world, the script must be injected into the DOM.
  const script = document.createElement('script');
  script.src = chrome.runtime.getURL('dist/intercept.js');
  
  // Append to documentElement to ensure it runs as early as possible
  (document.head || document.documentElement).appendChild(script);
  
  // Remove the tag immediately to keep the DOM clean (the script has already executed in memory)
  script.remove();
}

function setupMessageRelay(tabId: number): void {
  window.addEventListener('message', (event) => {
    // Only accept messages from our own MAIN world script
    if (event.source !== window || event.data?.source !== 'ACCIDENTAL_SECRET_SENTINEL_MAIN') {
      return;
    }

    if (event.data.type === 'FINDING_DETECTED') {
      // Attach the isolated tabId here, then forward to the background service worker
      const finding = { ...event.data.finding, tabId };
      chrome.runtime.sendMessage({
        type: 'FINDING_DETECTED',
        finding
      });
    }
  });
}

function startDomScanner(tabId: number): void {
  const scanner = new DomScanner(tabId);
  scanner.start();

  // Clean up when page unloads
  window.addEventListener('beforeunload', () => scanner.stop());
}

async function getTabId(): Promise<number | null> {
  return new Promise(resolve => {
    try {
      chrome.runtime.sendMessage({ type: 'GET_TAB_ID' }, response => {
        if (chrome.runtime.lastError) {
          resolve(null);
          return;
        }
        resolve(response?.tabId ?? null);
      });
    } catch {
      resolve(null);
    }
  });
}

// Kick off
init().catch(err => console.warn('[Sentinel] Content script init failed:', err));