var __defProp = Object.defineProperty;
var __defNormalProp = (obj, key, value) => key in obj ? __defProp(obj, key, { enumerable: true, configurable: true, writable: true, value }) : obj[key] = value;
var __publicField = (obj, key, value) => __defNormalProp(obj, typeof key !== "symbol" ? key + "" : key, value);
import { s as scan } from "./chunks/scanner-B1JRbrCP.js";
class DomScanner {
  constructor(tabId) {
    __publicField(this, "tabId");
    __publicField(this, "observer", null);
    __publicField(this, "scannedUrls", /* @__PURE__ */ new Set());
    this.tabId = tabId;
  }
  /** Scan the initial HTML and start watching for new scripts */
  start() {
    this.scanText(document.documentElement.outerHTML, "html-source", window.location.href);
    this.observer = new MutationObserver((mutations) => {
      for (const mutation of mutations) {
        for (const node of mutation.addedNodes) {
          if (node instanceof HTMLScriptElement) {
            this.handleScriptTag(node);
          }
          if (node instanceof Element) {
            node.querySelectorAll("script").forEach((s) => this.handleScriptTag(s));
          }
        }
      }
    });
    this.observer.observe(document.documentElement, {
      childList: true,
      subtree: true
    });
    document.querySelectorAll("script").forEach((s) => this.handleScriptTag(s));
  }
  stop() {
    var _a;
    (_a = this.observer) == null ? void 0 : _a.disconnect();
    this.observer = null;
  }
  handleScriptTag(script) {
    if (script.src) {
      if (!this.scannedUrls.has(script.src)) {
        this.scannedUrls.add(script.src);
        this.fetchAndScanBundle(script.src);
      }
    } else if (script.textContent) {
      this.scanText(script.textContent, "js-bundle", window.location.href);
    }
  }
  async fetchAndScanBundle(url) {
    try {
      if (url.startsWith("chrome-extension://") || url.startsWith("data:")) return;
      const response = await fetch(url, { credentials: "omit" });
      if (!response.ok) return;
      const text = await response.text();
      this.scanInChunks(text, "js-bundle", url);
    } catch {
    }
  }
  /**
   * Scans large text in chunks, yielding between each to avoid
   * blocking the main thread on large bundles (2-5MB+).
   */
  scanInChunks(text, sourceType, url, chunkSize = 5e4) {
    let offset = 0;
    const processChunk = () => {
      const chunk = text.slice(offset, offset + chunkSize);
      if (chunk.length === 0) return;
      this.scanText(chunk, sourceType, url);
      offset += chunkSize;
      if (offset < text.length) {
        requestIdleCallback ? requestIdleCallback(processChunk, { timeout: 2e3 }) : setTimeout(processChunk, 0);
      }
    };
    processChunk();
  }
  scanText(input, sourceType, url) {
    const rawFindings = scan(input, { url, tabId: this.tabId, sourceType });
    if (rawFindings.length === 0) return;
    Promise.all(rawFindings.map((r) => r.toFinding())).then((findings) => {
      for (const finding of findings) {
        chrome.runtime.sendMessage({ type: "FINDING_DETECTED", finding });
      }
    }).catch((err) => console.warn("[Sentinel] DOM scan error:", err));
  }
}
async function init() {
  const tabId = await getTabId();
  if (tabId === null) return;
  const settings = await new Promise((resolve) => {
    chrome.runtime.sendMessage({ type: "GET_SETTINGS" }, (response) => {
      resolve((response == null ? void 0 : response.settings) ?? { enabled: true, disabledDomains: [] });
    });
  });
  if (!settings.enabled) return;
  const hostname = window.location.hostname;
  const isDomainDisabled = settings.disabledDomains.some(
    (d) => hostname === d || hostname.endsWith("." + d)
  );
  if (isDomainDisabled) return;
  setupMessageRelay(tabId);
  injectMainWorldInterceptor();
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => startDomScanner(tabId));
  } else {
    startDomScanner(tabId);
  }
}
function injectMainWorldInterceptor() {
  const script = document.createElement("script");
  script.src = chrome.runtime.getURL("dist/intercept.js");
  (document.head || document.documentElement).appendChild(script);
  script.remove();
}
function setupMessageRelay(tabId) {
  window.addEventListener("message", (event) => {
    var _a;
    if (event.source !== window || ((_a = event.data) == null ? void 0 : _a.source) !== "ACCIDENTAL_SECRET_SENTINEL_MAIN") {
      return;
    }
    if (event.data.type === "FINDING_DETECTED") {
      const finding = { ...event.data.finding, tabId };
      chrome.runtime.sendMessage({
        type: "FINDING_DETECTED",
        finding
      });
    }
  });
}
function startDomScanner(tabId) {
  const scanner = new DomScanner(tabId);
  scanner.start();
  window.addEventListener("beforeunload", () => scanner.stop());
}
async function getTabId() {
  return new Promise((resolve) => {
    try {
      chrome.runtime.sendMessage({ type: "GET_TAB_ID" }, (response) => {
        if (chrome.runtime.lastError) {
          resolve(null);
          return;
        }
        resolve((response == null ? void 0 : response.tabId) ?? null);
      });
    } catch {
      resolve(null);
    }
  });
}
init().catch((err) => console.warn("[Sentinel] Content script init failed:", err));
//# sourceMappingURL=content.js.map
