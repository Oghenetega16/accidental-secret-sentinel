import type { SourceType } from '../shared/types';
import { scan } from '../engine/scanner';

/**
 * Monkey-patches window.fetch and XMLHttpRequest to intercept
 * request/response data for scanning.
 *
 * IMPORTANT: This file runs in the MAIN world (page context), not the
 * extension's isolated world. It has full access to page APIs but must
 * use chrome.runtime.sendMessage to communicate findings.
 *
 * Critical pattern: always clone() response bodies before reading —
 * returning a consumed response breaks the page.
 */

const CURRENT_URL = () => window.location.href;
const CURRENT_TAB_ID = -1; // populated by content.ts after tab ID negotiation

// ─── fetch interception ───────────────────────────────────────────────────────

export function interceptFetch(tabId: number): void {
  const originalFetch = window.fetch.bind(window);

  window.fetch = async function (input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    // Scan outgoing request
    const url = typeof input === 'string'
      ? input
      : input instanceof URL
        ? input.href
        : (input as Request).url;

    // Scan request headers
    if (init?.headers) {
      const headerStr = JSON.stringify(init.headers);
      emitFindings(headerStr, url, tabId, 'request-header');
    }

    // Scan request body
    if (init?.body && typeof init.body === 'string') {
      emitFindings(init.body, url, tabId, 'request-body');
    }

    // Execute the real fetch
    const response = await originalFetch(input, init);

    // Clone BEFORE reading — original is returned to the page untouched
    const clone = response.clone();

    clone.text()
      .then(body => {
        emitFindings(body, url, tabId, 'response-body');

        // Also scan response headers
        // Headers.entries() is not in all TS DOM lib versions — cast to any to iterate
        const headerStr = JSON.stringify(Object.fromEntries((response.headers as any)));
        emitFindings(headerStr, url, tabId, 'response-header');
      })
      .catch(() => {
        // Non-text body (images, binary) — skip silently
      });

    return response; // Always return the ORIGINAL, not the clone
  };
}

// ─── XHR interception ────────────────────────────────────────────────────────

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
        // Scan response headers
        const headers = this.getAllResponseHeaders();
        if (headers) {
          emitFindings(headers, this._url, tabId, 'response-header');
        }
      });

      super.send(body);
    }
  } as typeof XMLHttpRequest;
}

// ─── Finding emitter ──────────────────────────────────────────────────────────

/**
 * Scans input and sends any findings to the service worker via IPC.
 * Runs async but does not block the calling code.
 */
function emitFindings(
  input: string,
  url: string,
  tabId: number,
  sourceType: SourceType
): void {
  if (!input || input.length < 8) return;

  // Cap input length to avoid scanning huge blobs synchronously on main thread
  // Bundle scanning happens in content.ts via a Worker
  const MAX_INLINE_SCAN = 50_000; // 50KB
  const chunk = input.length > MAX_INLINE_SCAN
    ? input.slice(0, MAX_INLINE_SCAN)
    : input;

  const rawFindings = scan(chunk, { url, tabId, sourceType });
  if (rawFindings.length === 0) return;

  Promise.all(rawFindings.map(r => r.toFinding()))
    .then(findings => {
      for (const finding of findings) {
        chrome.runtime.sendMessage({ type: 'FINDING_DETECTED', finding });
      }
    })
    .catch(err => console.warn('[Sentinel] Finding emit error:', err));
}