import type { SourceType } from '../shared/types';
import { scan } from '../engine/scanner';

/**
 * Monkey-patches window.fetch and XMLHttpRequest to intercept
 * request/response data for scanning.
 *
 * IMPORTANT: Runs in MAIN world. Cannot use chrome.* APIs.
 * Communicates with the isolated content.ts via window.postMessage.
 */

const CURRENT_URL = () => window.location.href;
// tabId isn't easily known in the MAIN world, so we will let 
// the isolated content script attach the tabId when it relays the message.

// ─── fetch interception ───────────────────────────────────────────────────────

export function interceptFetch(): void {
  const originalFetch = window.fetch.bind(window);

  window.fetch = async function (input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    const url = typeof input === 'string'
      ? input
      : input instanceof URL
        ? input.href
        : (input as Request).url;

    if (init?.headers) {
      const headerStr = JSON.stringify(init.headers);
      emitFindings(headerStr, url, 'request-header');
    }

    if (init?.body && typeof init.body === 'string') {
      emitFindings(init.body, url, 'request-body');
    }

    const response = await originalFetch(input, init);
    const clone = response.clone();

    clone.text()
      .then(body => {
        emitFindings(body, url, 'response-body');
        const headerStr = JSON.stringify(Object.fromEntries(response.headers.entries()));
        emitFindings(headerStr, url, 'response-header');
      })
      .catch(() => { /* Non-text body — skip silently */ });

    return response;
  };
}

// ─── XHR interception ────────────────────────────────────────────────────────

export function interceptXHR(): void {
  const OriginalXHR = window.XMLHttpRequest;

  // Cast window to any to bypass TS read-only DOM restrictions
  (window as any).XMLHttpRequest = class extends OriginalXHR {
    private _url = '';

    // Add 'override' keyword
    override open(method: string, url: string | URL, ...args: unknown[]): void {
      this._url = url.toString();
      // @ts-ignore — rest args
      super.open(method, url, ...args);
    }

    // Add 'override' keyword
    override send(body?: Document | XMLHttpRequestBodyInit | null): void {
      if (body && typeof body === 'string') {
        emitFindings(body, this._url, 'request-body');
      }

      this.addEventListener('load', () => {
        if (typeof this.responseText === 'string') {
          emitFindings(this.responseText, this._url, 'response-body');
        }
        const headers = this.getAllResponseHeaders();
        if (headers) {
          emitFindings(headers, this._url, 'response-header');
        }
      });

      super.send(body);
    }
  };
}

// ─── Finding emitter ──────────────────────────────────────────────────────────

function emitFindings(
  input: string,
  url: string,
  sourceType: SourceType
): void {
  if (!input || input.length < 8) return;

  const MAX_INLINE_SCAN = 50_000;
  const chunk = input.length > MAX_INLINE_SCAN
    ? input.slice(0, MAX_INLINE_SCAN)
    : input;

  // Notice tabId is passed as -1 here, the isolated script will fix it
  const rawFindings = scan(chunk, { url, tabId: -1, sourceType });
  if (rawFindings.length === 0) return;

  Promise.all(rawFindings.map(r => r.toFinding()))
    .then(findings => {
      for (const finding of findings) {
        // Broadcast to the isolated content script instead of chrome.runtime
        window.postMessage({
          source: 'ACCIDENTAL_SECRET_SENTINEL_MAIN',
          type: 'FINDING_DETECTED',
          finding
        }, '*');
      }
    })
    .catch(err => console.warn('[Sentinel] Finding emit error:', err));
}

// Auto-start the monkey-patching when the script loads in the MAIN world
interceptFetch();
interceptXHR();