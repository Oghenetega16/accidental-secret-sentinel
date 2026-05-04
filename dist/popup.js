let currentTabId = -1;
let findings = [];
async function init() {
  var _a;
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!(tab == null ? void 0 : tab.id)) return;
  currentTabId = tab.id;
  const settingsRes = await sendMessage({ type: "GET_SETTINGS" });
  const enabled = ((_a = settingsRes == null ? void 0 : settingsRes.settings) == null ? void 0 : _a.enabled) ?? true;
  setToggleState(enabled);
  const findingsRes = await sendMessage({
    type: "GET_FINDINGS",
    tabId: currentTabId
  });
  findings = (findingsRes == null ? void 0 : findingsRes.findings) ?? [];
  render();
  chrome.runtime.onMessage.addListener((message) => {
    if (message.type === "FINDING_DETECTED" && message.finding.tabId === currentTabId) {
      findings = [...findings, message.finding];
      render();
    }
    if (message.type === "SUPPRESSION_ADDED") {
      sendMessage({ type: "GET_FINDINGS", tabId: currentTabId }).then((res) => {
        findings = (res == null ? void 0 : res.findings) ?? [];
        render();
      });
    }
  });
  document.getElementById("enabled-toggle").addEventListener("change", onToggle);
  document.getElementById("btn-clear").addEventListener("click", onClearAll);
  document.getElementById("btn-export").addEventListener("click", onExport);
  document.getElementById("btn-settings").addEventListener("click", () => {
    chrome.runtime.openOptionsPage();
  });
}
function render() {
  const list = document.getElementById("findings-list");
  const countText = document.getElementById("count-text");
  const btnClear = document.getElementById("btn-clear");
  if (findings.length === 0) {
    countText.textContent = "No secrets detected on this page";
    btnClear.style.display = "none";
    list.innerHTML = `
      <div class="empty" role="status">
        <span class="empty-icon" aria-hidden="true">🛡️</span>
        <div class="empty-title">All clear</div>
        <div class="empty-sub">No exposed secrets detected.<br>Sentinel is watching.</div>
      </div>`;
    return;
  }
  const critCount = findings.filter((f) => f.severity === "critical").length;
  const label = `${findings.length} finding${findings.length !== 1 ? "s" : ""}${critCount > 0 ? ` (${critCount} critical)` : ""}`;
  countText.textContent = label;
  btnClear.style.display = "block";
  const sorted = findings.slice().sort((a, b) => {
    const order = { critical: 0, warning: 1, info: 2 };
    return (order[a.severity] ?? 3) - (order[b.severity] ?? 3);
  });
  list.innerHTML = sorted.map((f) => findingHtml(f)).join("");
  list.querySelectorAll(".finding").forEach((el) => {
    el.addEventListener("click", (e) => {
      if (e.target.closest(".btn-suppress")) return;
      toggleExpand(el);
    });
    el.addEventListener("keydown", (e) => {
      const ke = e;
      if (ke.key === "Enter" || ke.key === " ") {
        if (e.target.closest(".btn-suppress")) return;
        e.preventDefault();
        toggleExpand(el);
      }
    });
  });
  list.querySelectorAll(".btn-suppress").forEach((btn) => {
    btn.addEventListener("click", async (e) => {
      e.stopPropagation();
      const kind = btn.dataset["kind"];
      const fid = btn.dataset["findingId"];
      const finding = findings.find((f) => f.id === fid);
      if (!finding) return;
      let value;
      if (kind === "value-hash") value = finding.valueHash;
      else if (kind === "pattern") value = finding.patternId;
      else {
        try {
          value = new URL(finding.url).hostname;
        } catch {
          value = finding.url;
        }
      }
      await sendMessage({
        type: "SUPPRESS",
        suppression: {
          kind,
          value,
          label: `${finding.patternName} — ${finding.redactedValue}`
        }
      });
      findings = findings.filter((f) => f.id !== fid);
      render();
    });
  });
}
function toggleExpand(el) {
  const expanded = el.classList.toggle("expanded");
  el.setAttribute("aria-expanded", String(expanded));
}
function findingHtml(f) {
  const time = new Date(f.timestamp).toLocaleTimeString();
  let hostname = f.url;
  try {
    hostname = new URL(f.url).hostname;
  } catch {
  }
  const chevron = `<span class="chevron" aria-hidden="true">
    <svg viewBox="0 0 10 10"><polyline points="2,3 5,7 8,3"/></svg>
  </span>`;
  return `
    <div class="finding"
         data-id="${esc(f.id)}"
         role="button"
         tabindex="0"
         aria-expanded="false"
         aria-label="${esc(f.patternName)}, ${esc(f.severity)}, detected on ${esc(hostname)}">
      <div class="finding-header">
        <div class="finding-left">
          <div class="finding-name">${esc(f.patternName)}</div>
          <div class="finding-value" aria-label="Detected value: ${esc(f.redactedValue)}">${esc(f.redactedValue)}</div>
          <div class="finding-meta">${esc(sourceLabel(f.sourceType))} · ${esc(hostname)}</div>
        </div>
        <div class="finding-right">
          <span class="severity severity-${esc(f.severity)}" aria-label="Severity: ${esc(f.severity)}">${esc(f.severity.toUpperCase())}</span>
          ${chevron}
        </div>
      </div>
      <div class="finding-detail" role="region" aria-label="Details for ${esc(f.patternName)}">
        <div class="detail-grid">
          <span class="detail-label">Source</span>
          <span class="detail-value">${esc(sourceLabel(f.sourceType))}</span>
          <span class="detail-label">URL</span>
          <span class="detail-value">${esc(f.url)}</span>
          <span class="detail-label">Entropy</span>
          <span class="detail-value">${f.entropy.toFixed(2)} bits</span>
          <span class="detail-label">Time</span>
          <span class="detail-value">${esc(time)}</span>
        </div>
        <div class="suppress-row" role="group" aria-label="Suppress options">
          <span class="suppress-label">Suppress</span>
          <button class="btn-suppress"
                  data-kind="value-hash" data-finding-id="${esc(f.id)}"
                  aria-label="Suppress this specific value of ${esc(f.patternName)}">
            This value
          </button>
          <button class="btn-suppress"
                  data-kind="domain" data-finding-id="${esc(f.id)}"
                  aria-label="Suppress all findings on ${esc(hostname)}">
            This domain
          </button>
          <button class="btn-suppress"
                  data-kind="pattern" data-finding-id="${esc(f.id)}"
                  aria-label="Suppress all ${esc(f.patternName)} findings">
            All ${esc(f.patternName)}
          </button>
        </div>
      </div>
    </div>`;
}
async function onToggle(e) {
  const enabled = e.target.checked;
  setToggleState(enabled);
  await sendMessage({ type: "UPDATE_SETTINGS", settings: { enabled } });
}
async function onClearAll() {
  await sendMessage({ type: "CLEAR_FINDINGS", tabId: currentTabId });
  findings = [];
  render();
}
function onExport() {
  const blob = new Blob([JSON.stringify(findings, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `sentinel-findings-${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(url);
}
function setToggleState(enabled) {
  const toggle = document.getElementById("enabled-toggle");
  const label = document.getElementById("toggle-label");
  const banner = document.getElementById("disabled-banner");
  toggle.checked = enabled;
  toggle.setAttribute("aria-checked", String(enabled));
  if (label) label.textContent = enabled ? "On" : "Off";
  if (banner) banner.classList.toggle("visible", !enabled);
}
function sourceLabel(s) {
  const map = {
    "request-header": "Request header",
    "request-body": "Request body",
    "response-header": "Response header",
    "response-body": "Response body",
    "js-bundle": "JS bundle",
    "html-source": "HTML source",
    "url-param": "URL parameter"
  };
  return map[s] ?? s;
}
function esc(str) {
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
function sendMessage(message) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage(message, (response) => {
      if (chrome.runtime.lastError) {
        resolve(null);
        return;
      }
      resolve(response ?? null);
    });
  });
}
init().catch(console.error);
//# sourceMappingURL=popup.js.map
