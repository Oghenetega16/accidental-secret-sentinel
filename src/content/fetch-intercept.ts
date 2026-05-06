import type { SourceType } from '../shared/types';
import { scan } from '../engine/scanner';

/**
 * Monkey-patches window.fetch and XMLHttpRequest.
 * Runs in MAIN world — sends findings to the service worker only.
 * Toast display is handled by content.ts via the relay postMessage bridge.
 */

export function interceptFetch(tabId: number): void {
  const originalFetch = window.fetch.bind(window);

  window.fetch = async function (input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    const url = typeof input === 'string'
      ? input
      : input instanceof URL
        ? input.href
        : (input as Request).url;

    if (init?.headers) {
      emitFindings(JSON.stringify(init.headers), url, tabId, 'request-header');
    }
    if (init?.body && typeof init.body === 'string') {
      emitFindings(init.body, url, tabId, 'request-body');
    }

    const response = await originalFetch(input, init);
    const clone = response.clone();

    clone.text()
      .then(body => {
        emitFindings(body, url, tabId, 'response-body');
        const headerStr = JSON.stringify(Object.fromEntries((response.headers as any)));
        emitFindings(headerStr, url, tabId, 'response-header');
      })
      .catch(() => {});

    return response;
  };
}

export function interceptXHR(tabId: number): void {
  const OriginalXHR = window.XMLHttpRequest;

  (window as typeof globalThis).XMLHttpRequest = class extends OriginalXHR {
    private _url = '';

    override open(method: string, url: string | URL, async?: boolean, user?: string | null, password?: string | null): void {
      this._url = url.toString();
      super.open(method, url.toString(), async ?? true, user, password);
    }

    override send(body?: Document | XMLHttpRequestBodyInit | null): void {
      if (body && typeof body === 'string') {
        emitFindings(body, this._url, tabId, 'request-body');
      }
      this.addEventListener('load', () => {
        if (typeof this.responseText === 'string') {
          emitFindings(this.responseText, this._url, tabId, 'response-body');
        }
        const headers = this.getAllResponseHeaders();
        if (headers) emitFindings(headers, this._url, tabId, 'response-header');
      });
      super.send(body);
    }
  } as typeof XMLHttpRequest;
}

// ─── Emitter — scan and send to service worker ────────────────────────────────

function emitFindings(input: string, url: string, tabId: number, sourceType: SourceType): void {
  if (!input || input.length < 8) return;

  const MAX_INLINE = 50_000;
  const chunk = input.length > MAX_INLINE ? input.slice(0, MAX_INLINE) : input;
  const rawFindings = scan(chunk, { url, tabId, sourceType });
  if (rawFindings.length === 0) return;

  Promise.all(rawFindings.map(r => r.toFinding()))
    .then(findings => {
      for (const finding of findings) {
        // Send to service worker — it stores, updates badge, and relays
        // back via chrome.tabs.sendMessage → relay.ts → window.postMessage
        // → content.ts → showFindingToast
        chrome.runtime.sendMessage({ type: 'FINDING_DETECTED', finding });
      }
    })
    .catch(err => console.warn('[Sentinel] emit error:', err));
}