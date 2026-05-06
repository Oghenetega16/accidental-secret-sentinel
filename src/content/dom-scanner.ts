import { scan } from '../engine/scanner';
import { showFindingToast } from './toast';
import type { SourceType } from '../shared/types';

/**
 * Scans the page's HTML source and watches for dynamically injected
 * <script> tags using MutationObserver.
 *
 * Toast is shown via the sendMessage response callback — the only
 * reliable way to trigger UI from a MAIN world content script.
 */
export class DomScanner {
  private tabId: number;
  private observer: MutationObserver | null = null;
  private scannedUrls = new Set<string>();
  private shownPatterns = new Set<string>();

  constructor(tabId: number) {
    this.tabId = tabId;
  }

  start(): void {
    // Scan initial HTML
    this.scanText(document.documentElement.outerHTML, 'html-source', window.location.href);

    // Watch for dynamically added script tags
    this.observer = new MutationObserver(mutations => {
      for (const mutation of mutations) {
        for (const node of Array.from(mutation.addedNodes)) {
          if (node instanceof HTMLScriptElement) {
            this.handleScriptTag(node);
          }
          if (node instanceof Element) {
            node.querySelectorAll('script').forEach(s => this.handleScriptTag(s));
          }
        }
      }
    });

    this.observer.observe(document.documentElement, { childList: true, subtree: true });

    // Scan scripts already in DOM
    document.querySelectorAll('script').forEach(s => this.handleScriptTag(s));
  }

  stop(): void {
    this.observer?.disconnect();
    this.observer = null;
  }

  private handleScriptTag(script: HTMLScriptElement): void {
    if (script.src) {
      if (!this.scannedUrls.has(script.src)) {
        this.scannedUrls.add(script.src);
        this.fetchAndScanBundle(script.src);
      }
    } else if (script.textContent) {
      this.scanText(script.textContent, 'js-bundle', window.location.href);
    }
  }

  private async fetchAndScanBundle(url: string): Promise<void> {
    try {
      if (url.startsWith('chrome-extension://') || url.startsWith('data:')) return;
      const response = await fetch(url, { credentials: 'omit' });
      if (!response.ok) return;
      const text = await response.text();
      this.scanInChunks(text, 'js-bundle', url);
    } catch { /* network errors expected — skip */ }
  }

  private scanInChunks(text: string, sourceType: SourceType, url: string, chunkSize = 50_000): void {
    let offset = 0;
    const processChunk = () => {
      const chunk = text.slice(offset, offset + chunkSize);
      if (!chunk.length) return;
      this.scanText(chunk, sourceType, url);
      offset += chunkSize;
      if (offset < text.length) {
        if (typeof requestIdleCallback !== 'undefined') {
          requestIdleCallback(processChunk, { timeout: 2000 });
        } else {
          setTimeout(processChunk, 0);
        }
      }
    };
    processChunk();
  }

  private scanText(input: string, sourceType: SourceType, url: string): void {
    const rawFindings = scan(input, { url, tabId: this.tabId, sourceType });
    if (!rawFindings.length) return;

    Promise.all(rawFindings.map(r => r.toFinding()))
      .then(findings => {
        for (const finding of findings) {
          chrome.runtime.sendMessage(
            { type: 'FINDING_DETECTED', finding },
            (response) => {
              // Show toast only if service worker stored the finding
              // (not suppressed, not a duplicate)
              if (response?.stored && !this.shownPatterns.has(finding.patternId)) {
                this.shownPatterns.add(finding.patternId);
                showFindingToast(finding);
              }
            }
          );
        }
      })
      .catch(err => console.warn('[Sentinel] scan error:', err));
  }
}