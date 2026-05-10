/**
 * fetch-intercept.ts — MAIN world.
 * No chrome.runtime calls. Posts findings via window.postMessage
 * to the ISOLATED world coordinator (relay.ts).
 */

import { scan } from '../engine/scanner';
import type { SourceType } from '../shared/types';

const TO_BG = '__sentinel_to_bg__';

// tabId is unknown in MAIN world — service worker overrides from sender.tab.id
const UNKNOWN_TAB = -1;

export function interceptFetch(): void {
  const originalFetch = window.fetch.bind(window);

  window.fetch = async function (input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    const url = typeof input === 'string'
      ? input
      : input instanceof URL ? input.href : (input as Request).url;

    if (init?.headers) emitFindings(JSON.stringify(init.headers), url, 'request-header');
    if (init?.body && typeof init.body === 'string') emitFindings(init.body, url, 'request-body');

    const response = await originalFetch(input, init);
    const clone = response.clone();

    clone.text().then(body => {
      emitFindings(body, url, 'response-body');
      const headerStr = JSON.stringify(Object.fromEntries((response.headers as any)));
      emitFindings(headerStr, url, 'response-header');
    }).catch(() => {});

    return response;
  };
}

export function interceptXHR(): void {
  const OriginalXHR = window.XMLHttpRequest;

  (window as typeof globalThis).XMLHttpRequest = class extends OriginalXHR {
    private _url = '';

    override open(method: string, url: string | URL, async?: boolean, user?: string | null, password?: string | null): void {
      this._url = url.toString();
      super.open(method, url.toString(), async ?? true, user, password);
    }

    override send(body?: Document | XMLHttpRequestBodyInit | null): void {
      if (body && typeof body === 'string') emitFindings(body, this._url, 'request-body');
      this.addEventListener('load', () => {
        try {
          const body = (!this.responseType || this.responseType === 'text')
            ? this.responseText
            : this.responseType === 'json' && this.response ? JSON.stringify(this.response) : null;
          if (body) emitFindings(body, this._url, 'response-body');
        } catch { /* unsupported responseType — skip */ }
        const h = this.getAllResponseHeaders();
        if (h) emitFindings(h, this._url, 'response-header');
      });
      super.send(body);
    }
  } as typeof XMLHttpRequest;
}

function emitFindings(input: string, url: string, sourceType: SourceType): void {
  if (!input || input.length < 8) return;
  const chunk = input.length > 50_000 ? input.slice(0, 50_000) : input;
  const rawFindings = scan(chunk, { url, tabId: UNKNOWN_TAB, sourceType });
  if (!rawFindings.length) return;

  Promise.all(rawFindings.map(r => r.toFinding())).then(findings => {
    for (const finding of findings) {
      // Post to ISOLATED world coordinator via postMessage
      window.postMessage({
        [TO_BG]: true,
        message: { type: 'FINDING_DETECTED', finding },
      }, '*');
    }
  }).catch(err => console.warn('[Sentinel] emit error:', err));
}