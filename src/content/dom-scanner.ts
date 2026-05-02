import { scan } from '../engine/scanner';
import type { SourceType } from '../shared/types';

/**
 * Scans the current page's HTML source and watches for dynamically
 * injected <script> tags using MutationObserver.
 */
export class DomScanner {
  private tabId: number;
  private observer: MutationObserver | null = null;
  private scannedUrls = new Set<string>();

  constructor(tabId: number) {
    this.tabId = tabId;
  }

  /** Scan the initial HTML and start watching for new scripts */
  start(): void {
    // Scan initial HTML source
    this.scanText(document.documentElement.outerHTML, 'html-source', window.location.href);

    // Watch for dynamically added script tags
    this.observer = new MutationObserver(mutations => {
      for (const mutation of mutations) {
        for (const node of Array.from(mutation.addedNodes)) {
          if (node instanceof HTMLScriptElement) {
            this.handleScriptTag(node);
          }
          // Also check children of added nodes (e.g. a div containing scripts)
          if (node instanceof Element) {
            node.querySelectorAll('script').forEach(s => this.handleScriptTag(s));
          }
        }
      }
    });

    this.observer.observe(document.documentElement, {
      childList: true,
      subtree: true,
    });

    // Scan all scripts already in DOM (inline + external)
    document.querySelectorAll('script').forEach(s => this.handleScriptTag(s));
  }

  stop(): void {
    this.observer?.disconnect();
    this.observer = null;
  }

  private handleScriptTag(script: HTMLScriptElement): void {
    if (script.src) {
      // External script — fetch and scan if not already done
      if (!this.scannedUrls.has(script.src)) {
        this.scannedUrls.add(script.src);
        this.fetchAndScanBundle(script.src);
      }
    } else if (script.textContent) {
      // Inline script
      this.scanText(script.textContent, 'js-bundle', window.location.href);
    }
  }

  private async fetchAndScanBundle(url: string): Promise<void> {
    try {
      // Skip browser-extension and data URLs
      if (url.startsWith('chrome-extension://') || url.startsWith('data:')) return;

      const response = await fetch(url, { credentials: 'omit' });
      if (!response.ok) return;

      const text = await response.text();

      // Scan in chunks to avoid blocking main thread
      this.scanInChunks(text, 'js-bundle', url);
    } catch {
      // Network errors are expected (CORS, offline) — skip silently
    }
  }

  /**
   * Scans large text in chunks, yielding between each to avoid
   * blocking the main thread on large bundles (2-5MB+).
   */
  private scanInChunks(
    text: string,
    sourceType: SourceType,
    url: string,
    chunkSize = 50_000
  ): void {
    let offset = 0;

    const processChunk = () => {
      const chunk = text.slice(offset, offset + chunkSize);
      if (chunk.length === 0) return;

      this.scanText(chunk, sourceType, url);
      offset += chunkSize;

      if (offset < text.length) {
        // Yield to browser before next chunk
        requestIdleCallback
          ? requestIdleCallback(processChunk, { timeout: 2000 })
          : setTimeout(processChunk, 0);
      }
    };

    processChunk();
  }

  private scanText(input: string, sourceType: SourceType, url: string): void {
    const rawFindings = scan(input, { url, tabId: this.tabId, sourceType });
    if (rawFindings.length === 0) return;

    Promise.all(rawFindings.map(r => r.toFinding()))
      .then(findings => {
        for (const finding of findings) {
          chrome.runtime.sendMessage({ type: 'FINDING_DETECTED', finding });
        }
      })
      .catch(err => console.warn('[Sentinel] DOM scan error:', err));
  }
}