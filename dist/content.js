var __defProp = Object.defineProperty;
var __defNormalProp = (obj, key, value) => key in obj ? __defProp(obj, key, { enumerable: true, configurable: true, writable: true, value }) : obj[key] = value;
var __publicField = (obj, key, value) => __defNormalProp(obj, typeof key !== "symbol" ? key + "" : key, value);
const PATTERNS = [
  // ── AWS ───────────────────────────────────────────────────────────────────
  {
    id: "aws-access-key-id",
    name: "AWS Access Key ID",
    regex: /\bAKIA[0-9A-Z]{16}\b/,
    severity: "critical",
    entropyMin: 3.5,
    description: "AWS IAM access key — grants API access to AWS services."
  },
  {
    id: "aws-secret-access-key",
    name: "AWS Secret Access Key",
    regex: /(?:aws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key|aws[_\-\s]?secret)[\"'\s]*[:=][\"'\s]*([A-Za-z0-9/+=]{40})/i,
    severity: "critical",
    entropyMin: 4,
    contextBoost: ["Authorization", "X-Amz-Security-Token"],
    description: "AWS IAM secret key — used to sign API requests."
  },
  {
    id: "aws-session-token",
    name: "AWS Session Token",
    regex: /(?:aws[_\-\s]?session[_\-\s]?token)[\"'\s]*[:=][\"'\s]*([A-Za-z0-9/+=]{100,})/i,
    severity: "critical",
    entropyMin: 4,
    description: "Temporary AWS session credential."
  },
  // ── GitHub ────────────────────────────────────────────────────────────────
  {
    id: "github-pat-classic",
    name: "GitHub Personal Access Token (classic)",
    regex: /\bghp_[A-Za-z0-9]{36}\b/,
    severity: "critical",
    description: "GitHub classic PAT — grants repo/org access."
  },
  {
    id: "github-pat-fine-grained",
    name: "GitHub Fine-Grained PAT",
    regex: /\bgithub_pat_[A-Za-z0-9_]{82}\b/,
    severity: "critical",
    description: "GitHub fine-grained PAT."
  },
  {
    id: "github-oauth-token",
    name: "GitHub OAuth Token",
    regex: /\bgho_[A-Za-z0-9]{36}\b/,
    severity: "critical"
  },
  {
    id: "github-app-token",
    name: "GitHub App Token",
    regex: /\bghs_[A-Za-z0-9]{36}\b/,
    severity: "critical"
  },
  {
    id: "github-refresh-token",
    name: "GitHub Refresh Token",
    regex: /\bghr_[A-Za-z0-9]{76}\b/,
    severity: "critical"
  },
  // ── Stripe ────────────────────────────────────────────────────────────────
  {
    id: "stripe-secret-key",
    name: "Stripe Secret Key",
    regex: /\bsk_(live|test)_[A-Za-z0-9]{24,99}\b/,
    severity: "critical",
    description: "Stripe secret key — full API access including charges."
  },
  {
    id: "stripe-restricted-key",
    name: "Stripe Restricted Key",
    regex: /\brk_(live|test)_[A-Za-z0-9]{24,99}\b/,
    severity: "warning",
    description: "Stripe restricted key — limited API access."
  },
  {
    id: "stripe-webhook-secret",
    name: "Stripe Webhook Secret",
    regex: /\bwhsec_[A-Za-z0-9]{32,99}\b/,
    severity: "warning"
  },
  // ── Google / GCP ──────────────────────────────────────────────────────────
  {
    id: "google-api-key",
    name: "Google API Key",
    regex: /\bAIza[0-9A-Za-z_\-]{35}\b/,
    severity: "warning",
    description: "Google API key — scope depends on enabled APIs."
  },
  {
    id: "google-oauth-client-secret",
    name: "Google OAuth Client Secret",
    regex: /GOCSPX-[A-Za-z0-9_\-]{28}/,
    severity: "critical"
  },
  {
    id: "google-service-account-key",
    name: "Google Service Account Key",
    regex: /"type"\s*:\s*"service_account"/,
    severity: "critical",
    description: "GCP service account key — full GCP access per IAM roles."
  },
  // ── Slack ─────────────────────────────────────────────────────────────────
  {
    id: "slack-bot-token",
    name: "Slack Bot Token",
    regex: /\bxoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24}\b/,
    severity: "critical",
    description: "Slack bot token — can post messages and read channels."
  },
  {
    id: "slack-user-token",
    name: "Slack User Token",
    regex: /\bxoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{32}\b/,
    severity: "critical"
  },
  {
    id: "slack-workspace-token",
    name: "Slack Workspace Token",
    regex: /\bxoxa-2-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{64}\b/,
    severity: "critical"
  },
  {
    id: "slack-webhook-url",
    name: "Slack Webhook URL",
    regex: /https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9_]{8}\/B[A-Za-z0-9_]{8,}\/[A-Za-z0-9_]{24}/,
    severity: "warning"
  },
  // ── Twilio ────────────────────────────────────────────────────────────────
  {
    id: "twilio-account-sid",
    name: "Twilio Account SID",
    regex: /\bAC[a-z0-9]{32}\b/,
    severity: "warning",
    description: "Twilio Account SID — identifies the account."
  },
  {
    id: "twilio-auth-token",
    name: "Twilio Auth Token",
    regex: /(?:twilio[_\-\s]?auth[_\-\s]?token|TWILIO_AUTH_TOKEN)[\"'\s]*[:=][\"'\s]*([a-z0-9]{32})/i,
    severity: "critical",
    entropyMin: 3.5
  },
  // ── SendGrid ──────────────────────────────────────────────────────────────
  {
    id: "sendgrid-api-key",
    name: "SendGrid API Key",
    regex: /\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b/,
    severity: "critical"
  },
  // ── OpenAI ────────────────────────────────────────────────────────────────
  {
    id: "openai-api-key",
    name: "OpenAI API Key",
    regex: /\bsk-[A-Za-z0-9]{48}\b/,
    severity: "critical",
    description: "OpenAI API key — grants model API access and incurs billing."
  },
  {
    id: "openai-org-id",
    name: "OpenAI Organisation ID",
    regex: /\borg-[A-Za-z0-9]{24}\b/,
    severity: "info"
  },
  // ── Anthropic ─────────────────────────────────────────────────────────────
  {
    id: "anthropic-api-key",
    name: "Anthropic API Key",
    regex: /\bsk-ant-[A-Za-z0-9\-_]{95,}\b/,
    severity: "critical",
    description: "Anthropic Claude API key."
  },
  // ── Azure ─────────────────────────────────────────────────────────────────
  {
    id: "azure-storage-account-key",
    name: "Azure Storage Account Key",
    regex: /AccountKey=[A-Za-z0-9+/]{88}==/,
    severity: "critical"
  },
  {
    id: "azure-sas-token",
    name: "Azure SAS Token",
    regex: /sig=[A-Za-z0-9%]{43,}/,
    severity: "warning",
    entropyMin: 3.5
  },
  {
    id: "azure-ad-client-secret",
    name: "Azure AD Client Secret",
    regex: /(?:client[_\-\s]?secret)[\"'\s]*[:=][\"'\s]*([A-Za-z0-9~._\-]{34,40})/i,
    severity: "critical",
    entropyMin: 3.8
  },
  // ── JWT ───────────────────────────────────────────────────────────────────
  {
    id: "jwt-token",
    name: "JSON Web Token (JWT)",
    regex: /\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b/,
    severity: "warning",
    contextBoost: ["Authorization", "X-Auth-Token"],
    description: "JWT — may carry sensitive claims or auth grants."
  },
  // ── Private Keys ──────────────────────────────────────────────────────────
  {
    id: "rsa-private-key",
    name: "RSA Private Key",
    regex: /-----BEGIN RSA PRIVATE KEY-----/,
    severity: "critical"
  },
  {
    id: "openssh-private-key",
    name: "OpenSSH Private Key",
    regex: /-----BEGIN OPENSSH PRIVATE KEY-----/,
    severity: "critical"
  },
  {
    id: "ec-private-key",
    name: "EC Private Key",
    regex: /-----BEGIN EC PRIVATE KEY-----/,
    severity: "critical"
  },
  {
    id: "pgp-private-key",
    name: "PGP Private Key Block",
    regex: /-----BEGIN PGP PRIVATE KEY BLOCK-----/,
    severity: "critical"
  },
  // ── npm ───────────────────────────────────────────────────────────────────
  {
    id: "npm-access-token",
    name: "npm Access Token",
    regex: /\bnpm_[A-Za-z0-9]{36}\b/,
    severity: "critical"
  },
  // ── Mailgun ───────────────────────────────────────────────────────────────
  {
    id: "mailgun-api-key",
    name: "Mailgun API Key",
    regex: /\bkey-[A-Za-z0-9]{32}\b/,
    severity: "critical",
    entropyMin: 3.5
  },
  // ── Shopify ───────────────────────────────────────────────────────────────
  {
    id: "shopify-private-app-password",
    name: "Shopify Private App Password",
    regex: /\bshppa_[A-Za-z0-9]{32}\b/,
    severity: "critical"
  },
  {
    id: "shopify-shared-secret",
    name: "Shopify Shared Secret",
    regex: /\bshpss_[A-Za-z0-9]{32}\b/,
    severity: "critical"
  },
  // ── Okta ─────────────────────────────────────────────────────────────────
  {
    id: "okta-api-token",
    name: "Okta API Token",
    regex: /00[A-Za-z0-9\-_]{40}/,
    severity: "critical",
    contextBoost: ["Authorization", "X-Okta-User-Agent-Extended"],
    entropyMin: 4
  },
  // ── Generic high-entropy secrets ──────────────────────────────────────────
  {
    id: "generic-secret-assignment",
    name: "Generic Secret Assignment",
    regex: /(?:secret|api[_\-]?key|auth[_\-]?token|access[_\-]?token|private[_\-]?key)[\"'\s]*[:=][\"'\s]*([A-Za-z0-9+/=_\-]{32,88})/i,
    severity: "info",
    entropyMin: 4.2,
    description: "High-entropy string assigned to a secret-like variable name."
  },
  {
    id: "generic-bearer-token",
    name: "Bearer Token",
    regex: /Bearer\s+([A-Za-z0-9\-_=+/]{32,})/,
    severity: "warning",
    contextBoost: ["Authorization"],
    entropyMin: 3.8
  }
];
new Map(
  PATTERNS.map((p) => [p.id, p])
);
function shannonEntropy(value) {
  if (value.length === 0) return 0;
  const freq = /* @__PURE__ */ new Map();
  for (const char of value) {
    freq.set(char, (freq.get(char) ?? 0) + 1);
  }
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / value.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}
function meetsEntropyThreshold(value, entropyMin) {
  if (entropyMin === void 0) return true;
  return shannonEntropy(value) >= entropyMin;
}
async function hashValue(value) {
  const encoded = new TextEncoder().encode(value);
  const buffer = await crypto.subtle.digest("SHA-256", encoded);
  return Array.from(new Uint8Array(buffer)).map((b) => b.toString(16).padStart(2, "0")).join("");
}
function redact(value) {
  if (value.length <= 8) return value.slice(0, 2) + "***";
  return value.slice(0, 4) + "***" + value.slice(-4);
}
function generateId() {
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (c) => {
    const r = Math.random() * 16 | 0;
    return (c === "x" ? r : r & 3 | 8).toString(16);
  });
}
function scan(input, opts) {
  const patternList = opts.patterns ?? PATTERNS;
  const results = [];
  const seenValues = /* @__PURE__ */ new Set();
  for (const pattern of patternList) {
    const regex = new RegExp(pattern.regex.source, pattern.regex.flags.replace("g", "") + "g");
    let match;
    while ((match = regex.exec(input)) !== null) {
      const rawValue = match[1] ?? match[0] ?? "";
      if (rawValue.length < 8) continue;
      if (!meetsEntropyThreshold(rawValue, pattern.entropyMin)) continue;
      if (seenValues.has(rawValue)) continue;
      seenValues.add(rawValue);
      const entropy = shannonEntropy(rawValue);
      const redactedValue = redact(rawValue);
      const capturedPattern = pattern;
      const capturedOpts = opts;
      const raw = {
        patternId: capturedPattern.id,
        patternName: capturedPattern.name,
        severity: capturedPattern.severity,
        sourceType: capturedOpts.sourceType,
        url: capturedOpts.url,
        tabId: capturedOpts.tabId,
        redactedValue,
        rawValue,
        entropy,
        async toFinding() {
          return {
            id: generateId(),
            patternId: capturedPattern.id,
            patternName: capturedPattern.name,
            severity: capturedPattern.severity,
            sourceType: capturedOpts.sourceType,
            url: capturedOpts.url,
            tabId: capturedOpts.tabId,
            redactedValue,
            valueHash: await hashValue(rawValue),
            timestamp: Date.now(),
            entropy
          };
        }
      };
      results.push(raw);
    }
  }
  return results;
}
function interceptFetch(tabId) {
  const originalFetch = window.fetch.bind(window);
  window.fetch = async function(input, init2) {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    if (init2 == null ? void 0 : init2.headers) {
      const headerStr = JSON.stringify(init2.headers);
      emitFindings(headerStr, url, tabId, "request-header");
    }
    if ((init2 == null ? void 0 : init2.body) && typeof init2.body === "string") {
      emitFindings(init2.body, url, tabId, "request-body");
    }
    const response = await originalFetch(input, init2);
    const clone = response.clone();
    clone.text().then((body) => {
      emitFindings(body, url, tabId, "response-body");
      const headerStr = JSON.stringify(Object.fromEntries(response.headers));
      emitFindings(headerStr, url, tabId, "response-header");
    }).catch(() => {
    });
    return response;
  };
}
function interceptXHR(tabId) {
  const OriginalXHR = window.XMLHttpRequest;
  window.XMLHttpRequest = class extends OriginalXHR {
    constructor() {
      super(...arguments);
      __publicField(this, "_url", "");
    }
    open(method, url, async, user, password) {
      this._url = url.toString();
      super.open(method, url.toString(), async ?? true, user, password);
    }
    send(body) {
      if (body && typeof body === "string") {
        emitFindings(body, this._url, tabId, "request-body");
      }
      this.addEventListener("load", () => {
        if (typeof this.responseText === "string") {
          emitFindings(this.responseText, this._url, tabId, "response-body");
        }
        const headers = this.getAllResponseHeaders();
        if (headers) {
          emitFindings(headers, this._url, tabId, "response-header");
        }
      });
      super.send(body);
    }
  };
}
function emitFindings(input, url, tabId, sourceType) {
  if (!input || input.length < 8) return;
  const MAX_INLINE_SCAN = 5e4;
  const chunk = input.length > MAX_INLINE_SCAN ? input.slice(0, MAX_INLINE_SCAN) : input;
  const rawFindings = scan(chunk, { url, tabId, sourceType });
  if (rawFindings.length === 0) return;
  Promise.all(rawFindings.map((r) => r.toFinding())).then((findings) => {
    for (const finding of findings) {
      chrome.runtime.sendMessage({ type: "FINDING_DETECTED", finding });
    }
  }).catch((err) => console.warn("[Sentinel] Finding emit error:", err));
}
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
        for (const node of Array.from(mutation.addedNodes)) {
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
const TOAST_ID_PREFIX = "sentinel-toast-";
const STYLE_ID = "sentinel-toast-styles";
const MAX_TOASTS = 3;
function ensureStyles() {
  if (document.getElementById(STYLE_ID)) return;
  const style = document.createElement("style");
  style.id = STYLE_ID;
  style.textContent = `
    .sentinel-toast-wrap {
      position: fixed;
      bottom: 20px;
      right: 20px;
      z-index: 2147483647;
      display: flex;
      flex-direction: column;
      gap: 8px;
      pointer-events: none;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    }
    .sentinel-toast {
      background: #fff;
      border: 1px solid #e8e6e0;
      border-left: 3px solid #E24B4A;
      border-radius: 6px;
      padding: 10px 36px 10px 12px;
      max-width: 300px;
      min-width: 220px;
      box-shadow: 0 4px 12px rgba(0,0,0,.12);
      pointer-events: all;
      animation: sentinel-slide-in .2s ease;
      position: relative;
    }
    .sentinel-toast.warning { border-left-color: #EF9F27; }
    .sentinel-toast.info    { border-left-color: #185FA5; }
    @keyframes sentinel-slide-in {
      from { opacity: 0; transform: translateX(12px); }
      to   { opacity: 1; transform: translateX(0); }
    }
    @keyframes sentinel-slide-out {
      from { opacity: 1; transform: translateX(0); }
      to   { opacity: 0; transform: translateX(12px); }
    }
    .sentinel-toast.dismissing {
      animation: sentinel-slide-out .18s ease forwards;
    }
    .sentinel-toast-title {
      font-size: 12px;
      font-weight: 600;
      color: #1a1a18;
      margin-bottom: 2px;
    }
    .sentinel-toast-body {
      font-size: 11px;
      color: #555550;
      line-height: 1.4;
    }
    .sentinel-toast-value {
      font-family: 'SF Mono', 'Fira Code', Consolas, monospace;
      font-size: 10px;
      color: #888880;
      margin-top: 3px;
    }
    .sentinel-toast-close {
      position: absolute;
      top: 7px;
      right: 8px;
      background: none;
      border: none;
      font-size: 15px;
      cursor: pointer;
      color: #b4b2a9;
      line-height: 1;
      padding: 0 2px;
      border-radius: 3px;
    }
    .sentinel-toast-close:hover { color: #1a1a18; background: #f1efe8; }
  `;
  (document.head || document.documentElement).appendChild(style);
}
function getOrCreateContainer() {
  let wrap = document.getElementById("sentinel-toast-wrap");
  if (!wrap) {
    wrap = document.createElement("div");
    wrap.id = "sentinel-toast-wrap";
    wrap.className = "sentinel-toast-wrap";
    (document.body || document.documentElement).appendChild(wrap);
  }
  return wrap;
}
function showFindingToast(finding) {
  const toastId = `${TOAST_ID_PREFIX}${finding.patternId}`;
  if (document.getElementById(toastId)) return;
  ensureStyles();
  const container = getOrCreateContainer();
  const existing = container.querySelectorAll(".sentinel-toast");
  if (existing.length >= MAX_TOASTS) {
    dismissToast(existing[0]);
  }
  const severityClass = finding.severity === "warning" ? "warning" : finding.severity === "info" ? "info" : "";
  const toast = document.createElement("div");
  toast.id = toastId;
  toast.className = `sentinel-toast ${severityClass}`.trim();
  toast.setAttribute("role", "alert");
  toast.setAttribute("aria-live", "assertive");
  toast.innerHTML = `
    <div class="sentinel-toast-title">🔑 Secret detected</div>
    <div class="sentinel-toast-body">${escHtml(finding.patternName)}</div>
    <div class="sentinel-toast-value">${escHtml(finding.redactedValue)}</div>
    <button class="sentinel-toast-close" aria-label="Dismiss">&times;</button>
  `;
  toast.querySelector(".sentinel-toast-close").addEventListener("click", () => dismissToast(toast));
  container.appendChild(toast);
  setTimeout(() => dismissToast(toast), 8e3);
}
function dismissToast(el) {
  if (!el.parentNode) return;
  el.classList.add("dismissing");
  setTimeout(() => {
    var _a;
    return (_a = el.parentNode) == null ? void 0 : _a.removeChild(el);
  }, 200);
}
function escHtml(s) {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
async function init() {
  const tabId = await getTabId();
  if (tabId === null || tabId === -1) return;
  const settings = await getSettings();
  if (!settings.enabled) return;
  const hostname = window.location.hostname;
  const isDomainDisabled = settings.disabledDomains.some(
    (d) => hostname === d || hostname.endsWith("." + d)
  );
  if (isDomainDisabled) return;
  interceptFetch(tabId);
  interceptXHR(tabId);
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => startDomScanner(tabId), { once: true });
  } else {
    startDomScanner(tabId);
  }
  chrome.runtime.onMessage.addListener((message) => {
    if (message.type === "FINDING_DETECTED" && message.finding.tabId === tabId) {
      handleFinding(message.finding);
    }
  });
}
let domScanner = null;
function startDomScanner(tabId) {
  domScanner = new DomScanner(tabId);
  domScanner.start();
  window.addEventListener("beforeunload", () => {
    domScanner == null ? void 0 : domScanner.stop();
    domScanner = null;
  }, { once: true });
}
const shownPatterns = /* @__PURE__ */ new Set();
function handleFinding(finding) {
  if (!shownPatterns.has(finding.patternId)) {
    shownPatterns.add(finding.patternId);
    showFindingToast(finding);
  }
}
async function getTabId() {
  return new Promise((resolve) => {
    try {
      chrome.runtime.sendMessage({ type: "GET_TAB_ID" }, (response) => {
        if (chrome.runtime.lastError || !response) {
          resolve(null);
          return;
        }
        resolve(response.tabId ?? null);
      });
    } catch {
      resolve(null);
    }
  });
}
async function getSettings() {
  return new Promise((resolve) => {
    const fallback = { enabled: true, disabledDomains: [] };
    try {
      chrome.runtime.sendMessage({ type: "GET_SETTINGS" }, (response) => {
        if (chrome.runtime.lastError || !response) {
          resolve(fallback);
          return;
        }
        resolve(response.settings ?? fallback);
      });
    } catch {
      resolve(fallback);
    }
  });
}
init().catch((err) => console.warn("[Sentinel] init error:", err));
//# sourceMappingURL=content.js.map
