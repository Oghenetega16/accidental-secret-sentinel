var __defProp = Object.defineProperty;
var __defNormalProp = (obj, key, value) => key in obj ? __defProp(obj, key, { enumerable: true, configurable: true, writable: true, value }) : obj[key] = value;
var __publicField = (obj, key, value) => __defNormalProp(obj, typeof key !== "symbol" ? key + "" : key, value);
import { s as scan } from "./chunks/scanner-B1JRbrCP.js";
function interceptFetch() {
  const originalFetch = window.fetch.bind(window);
  window.fetch = async function(input, init) {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    if (init == null ? void 0 : init.headers) {
      const headerStr = JSON.stringify(init.headers);
      emitFindings(headerStr, url, "request-header");
    }
    if ((init == null ? void 0 : init.body) && typeof init.body === "string") {
      emitFindings(init.body, url, "request-body");
    }
    const response = await originalFetch(input, init);
    const clone = response.clone();
    clone.text().then((body) => {
      emitFindings(body, url, "response-body");
      const headerStr = JSON.stringify(Object.fromEntries(response.headers.entries()));
      emitFindings(headerStr, url, "response-header");
    }).catch(() => {
    });
    return response;
  };
}
function interceptXHR() {
  const OriginalXHR = window.XMLHttpRequest;
  window.XMLHttpRequest = class extends OriginalXHR {
    constructor() {
      super(...arguments);
      __publicField(this, "_url", "");
    }
    // Add 'override' keyword
    open(method, url, ...args) {
      this._url = url.toString();
      super.open(method, url, ...args);
    }
    // Add 'override' keyword
    send(body) {
      if (body && typeof body === "string") {
        emitFindings(body, this._url, "request-body");
      }
      this.addEventListener("load", () => {
        if (typeof this.responseText === "string") {
          emitFindings(this.responseText, this._url, "response-body");
        }
        const headers = this.getAllResponseHeaders();
        if (headers) {
          emitFindings(headers, this._url, "response-header");
        }
      });
      super.send(body);
    }
  };
}
function emitFindings(input, url, sourceType) {
  if (!input || input.length < 8) return;
  const MAX_INLINE_SCAN = 5e4;
  const chunk = input.length > MAX_INLINE_SCAN ? input.slice(0, MAX_INLINE_SCAN) : input;
  const rawFindings = scan(chunk, { url, tabId: -1, sourceType });
  if (rawFindings.length === 0) return;
  Promise.all(rawFindings.map((r) => r.toFinding())).then((findings) => {
    for (const finding of findings) {
      window.postMessage({
        source: "ACCIDENTAL_SECRET_SENTINEL_MAIN",
        type: "FINDING_DETECTED",
        finding
      }, "*");
    }
  }).catch((err) => console.warn("[Sentinel] Finding emit error:", err));
}
interceptFetch();
interceptXHR();
//# sourceMappingURL=intercept.js.map
