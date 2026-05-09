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
const TO_BG$1 = "__sentinel_to_bg__";
const UNKNOWN_TAB$1 = -1;
function interceptFetch() {
  const originalFetch = window.fetch.bind(window);
  window.fetch = async function(input, init2) {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    if (init2 == null ? void 0 : init2.headers) emitFindings(JSON.stringify(init2.headers), url, "request-header");
    if ((init2 == null ? void 0 : init2.body) && typeof init2.body === "string") emitFindings(init2.body, url, "request-body");
    const response = await originalFetch(input, init2);
    const clone = response.clone();
    clone.text().then((body) => {
      emitFindings(body, url, "response-body");
      const headerStr = JSON.stringify(Object.fromEntries(response.headers));
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
    open(method, url, async, user, password) {
      this._url = url.toString();
      super.open(method, url.toString(), async ?? true, user, password);
    }
    send(body) {
      if (body && typeof body === "string") emitFindings(body, this._url, "request-body");
      this.addEventListener("load", () => {
        if (typeof this.responseText === "string") emitFindings(this.responseText, this._url, "response-body");
        const h = this.getAllResponseHeaders();
        if (h) emitFindings(h, this._url, "response-header");
      });
      super.send(body);
    }
  };
}
function emitFindings(input, url, sourceType) {
  if (!input || input.length < 8) return;
  const chunk = input.length > 5e4 ? input.slice(0, 5e4) : input;
  const rawFindings = scan(chunk, { url, tabId: UNKNOWN_TAB$1, sourceType });
  if (!rawFindings.length) return;
  Promise.all(rawFindings.map((r) => r.toFinding())).then((findings) => {
    for (const finding of findings) {
      window.postMessage({
        [TO_BG$1]: true,
        message: { type: "FINDING_DETECTED", finding }
      }, "*");
    }
  }).catch((err) => console.warn("[Sentinel] emit error:", err));
}
const TO_BG = "__sentinel_to_bg__";
const UNKNOWN_TAB = -1;
class DomScanner {
  constructor() {
    __publicField(this, "observer", null);
    __publicField(this, "scannedUrls", /* @__PURE__ */ new Set());
  }
  start() {
    this.scanText(document.documentElement.outerHTML, "html-source", window.location.href);
    this.observer = new MutationObserver((mutations) => {
      for (const mutation of mutations) {
        for (const node of Array.from(mutation.addedNodes)) {
          if (node instanceof HTMLScriptElement) this.handleScriptTag(node);
          if (node instanceof Element) node.querySelectorAll("script").forEach((s) => this.handleScriptTag(s));
        }
      }
    });
    this.observer.observe(document.documentElement, { childList: true, subtree: true });
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
  scanInChunks(text, sourceType, url, chunkSize = 5e4) {
    let offset = 0;
    const processChunk = () => {
      const chunk = text.slice(offset, offset + chunkSize);
      if (!chunk.length) return;
      this.scanText(chunk, sourceType, url);
      offset += chunkSize;
      if (offset < text.length) {
        typeof requestIdleCallback !== "undefined" ? requestIdleCallback(processChunk, { timeout: 2e3 }) : setTimeout(processChunk, 0);
      }
    };
    processChunk();
  }
  scanText(input, sourceType, url) {
    const rawFindings = scan(input, { url, tabId: UNKNOWN_TAB, sourceType });
    if (!rawFindings.length) return;
    Promise.all(rawFindings.map((r) => r.toFinding())).then((findings) => {
      for (const finding of findings) {
        window.postMessage({
          [TO_BG]: true,
          message: { type: "FINDING_DETECTED", finding }
        }, "*");
      }
    }).catch((err) => console.warn("[Sentinel] scan error:", err));
  }
}
const TOAST_ID = "sentinel-toast-main";
const STYLE_ID = "sentinel-toast-styles";
const AUTO_CLOSE = 6e3;
let toastCount = 0;
let autoCloseTimer = null;
function ensureStyles() {
  if (document.getElementById(STYLE_ID)) return;
  const style = document.createElement("style");
  style.id = STYLE_ID;
  style.textContent = `
    #sentinel-toast-main {
      position: fixed;
      bottom: 20px;
      right: 20px;
      z-index: 2147483647;
      background: #fff;
      border: 1px solid #e8e6e0;
      border-left: 3px solid #E24B4A;
      border-radius: 6px;
      padding: 10px 36px 10px 12px;
      min-width: 220px;
      max-width: 300px;
      box-shadow: 0 4px 12px rgba(0,0,0,.14);
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      animation: sentinel-in .2s ease;
      pointer-events: all;
    }
    @keyframes sentinel-in {
      from { opacity: 0; transform: translateX(10px); }
      to   { opacity: 1; transform: translateX(0); }
    }
    @keyframes sentinel-out {
      from { opacity: 1; transform: translateX(0); }
      to   { opacity: 0; transform: translateX(10px); }
    }
    #sentinel-toast-main.closing {
      animation: sentinel-out .18s ease forwards;
    }
    #sentinel-toast-main .s-title {
      font-size: 12px; font-weight: 600; color: #1a1a18; margin-bottom: 2px;
    }
    #sentinel-toast-main .s-body {
      font-size: 11px; color: #555550; line-height: 1.4;
    }
    #sentinel-toast-main .s-close {
      position: absolute; top: 8px; right: 8px;
      background: none; border: none; font-size: 15px;
      cursor: pointer; color: #b4b2a9; line-height: 1; padding: 0 2px;
    }
    #sentinel-toast-main .s-close:hover { color: #1a1a18; }
  `;
  (document.head || document.documentElement).appendChild(style);
}
function showFindingToast(finding) {
  toastCount++;
  ensureStyles();
  const existing = document.getElementById(TOAST_ID);
  if (existing) {
    const body = existing.querySelector(".s-body");
    if (body) {
      body.textContent = toastCount === 1 ? `${finding.patternName} — click the extension badge to view.` : `${toastCount} secrets detected — click the extension badge to view all.`;
    }
    if (autoCloseTimer) clearTimeout(autoCloseTimer);
    autoCloseTimer = setTimeout(() => dismissToast(), AUTO_CLOSE);
    return;
  }
  const toast = document.createElement("div");
  toast.id = TOAST_ID;
  toast.setAttribute("role", "alert");
  toast.setAttribute("aria-live", "assertive");
  toast.innerHTML = `
    <div class="s-title">🔑 Secret detected</div>
    <div class="s-body">${escHtml(finding.patternName)} — click the extension badge to view.</div>
    <button class="s-close" aria-label="Dismiss">&times;</button>
  `;
  toast.querySelector(".s-close").addEventListener("click", dismissToast);
  (document.body || document.documentElement).appendChild(toast);
  if (autoCloseTimer) clearTimeout(autoCloseTimer);
  autoCloseTimer = setTimeout(() => dismissToast(), AUTO_CLOSE);
}
function dismissToast() {
  const toast = document.getElementById(TOAST_ID);
  if (!toast) return;
  toast.classList.add("closing");
  setTimeout(() => {
    var _a;
    return (_a = toast.parentNode) == null ? void 0 : _a.removeChild(toast);
  }, 200);
}
function escHtml(s) {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
const TO_PAGE = "__sentinel_to_page__";
async function init() {
  const settings = await requestSettings();
  if (!settings.enabled) return;
  const hostname = window.location.hostname;
  const blocked = settings.disabledDomains.some(
    (d) => hostname === d || hostname.endsWith("." + d)
  );
  if (blocked) {
    console.log("[Sentinel] domain disabled:", hostname);
    return;
  }
  interceptFetch();
  interceptXHR();
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", startDomScanner, { once: true });
  } else {
    startDomScanner();
  }
  window.addEventListener("message", (event) => {
    var _a;
    if (event.source === window && ((_a = event.data) == null ? void 0 : _a[TO_PAGE]) === true) {
      handleFinding(event.data.finding);
    }
  });
}
function requestSettings() {
  return new Promise((resolve) => {
    const fallback = { enabled: true, disabledDomains: [] };
    const timeout = setTimeout(() => resolve(fallback), 1e3);
    window.addEventListener("message", function handler(event) {
      var _a;
      if (event.source === window && ((_a = event.data) == null ? void 0 : _a.__sentinel_settings__) === true) {
        clearTimeout(timeout);
        window.removeEventListener("message", handler);
        resolve(event.data.settings ?? fallback);
      }
    });
    window.postMessage({ __sentinel_get_settings__: true }, "*");
  });
}
let domScanner = null;
function startDomScanner() {
  domScanner = new DomScanner();
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
init().catch((err) => console.warn("[Sentinel] init error:", err));
//# sourceMappingURL=content.js.map
