let currentTabId = -1;
let findings = [];
async function init() {
  var _a;
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!(tab == null ? void 0 : tab.id)) return;
  currentTabId = tab.id;
  const settingsRes = await sendMessage({ type: "GET_SETTINGS" });
  const enabled = ((_a = settingsRes == null ? void 0 : settingsRes.settings) == null ? void 0 : _a.enabled) ?? true;
  document.getElementById("enabled-toggle").checked = enabled;
  updateToggleLabel(enabled);
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
      <div class="empty">
        <div class="empty-icon">🛡️</div>
        <div class="empty-title">All clear</div>
        <div class="empty-sub">No exposed secrets detected.<br>Browse normally — Sentinel is watching.</div>
      </div>`;
    return;
  }
  const critCount = findings.filter((f) => f.severity === "critical").length;
  countText.textContent = `${findings.length} finding${findings.length !== 1 ? "s" : ""}${critCount > 0 ? ` (${critCount} critical)` : ""}`;
  btnClear.style.display = "block";
  list.innerHTML = findings.sort((a, b) => {
    const order = { critical: 0, warning: 1, info: 2 };
    return (order[a.severity] ?? 3) - (order[b.severity] ?? 3);
  }).map((f) => findingHtml(f)).join("");
  list.querySelectorAll(".finding").forEach((el) => {
    el.addEventListener("click", (e) => {
      const target = e.currentTarget;
      target.classList.toggle("expanded");
    });
  });
  list.querySelectorAll(".btn-suppress").forEach((btn) => {
    btn.addEventListener("click", async (e) => {
      e.stopPropagation();
      const kind = btn.dataset["kind"];
      const findingId = btn.dataset["findingId"];
      const finding = findings.find((f) => f.id === findingId);
      if (!finding) return;
      await sendMessage({
        type: "SUPPRESS",
        suppression: {
          kind,
          value: kind === "value-hash" ? finding.valueHash : kind === "pattern" ? finding.patternId : new URL(finding.url).hostname,
          label: `${finding.patternName} — ${finding.redactedValue}`
        }
      });
      findings = findings.filter((f) => f.id !== findingId);
      render();
    });
  });
}
function findingHtml(f) {
  const time = new Date(f.timestamp).toLocaleTimeString();
  let hostname = f.url;
  try {
    hostname = new URL(f.url).hostname;
  } catch {
  }
  return `
    <div class="finding" data-id="${f.id}">
      <div class="finding-header">
        <span class="finding-name">${escape(f.patternName)}</span>
        <span class="severity severity-${f.severity}">${f.severity.toUpperCase()}</span>
      </div>
      <div class="finding-value">${escape(f.redactedValue)}</div>
      <div class="finding-meta">${escape(sourceLabel(f.sourceType))} · ${escape(hostname)}</div>
      <div class="finding-detail">
        <div class="detail-row"><span class="detail-label">Source</span><span>${escape(sourceLabel(f.sourceType))}</span></div>
        <div class="detail-row"><span class="detail-label">URL</span><span style="word-break:break-all">${escape(f.url)}</span></div>
        <div class="detail-row"><span class="detail-label">Entropy</span><span>${f.entropy.toFixed(2)}</span></div>
        <div class="detail-row"><span class="detail-label">Detected</span><span>${time}</span></div>
        <div class="suppress-row">
          <button class="btn-suppress" data-kind="value-hash" data-finding-id="${f.id}">Suppress this value</button>
          <button class="btn-suppress" data-kind="domain" data-finding-id="${f.id}">Suppress domain</button>
          <button class="btn-suppress" data-kind="pattern" data-finding-id="${f.id}">Suppress all ${escape(f.patternName)}</button>
        </div>
      </div>
    </div>`;
}
async function onToggle(e) {
  const enabled = e.target.checked;
  updateToggleLabel(enabled);
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
function updateToggleLabel(enabled) {
  const label = document.getElementById("toggle-label");
  if (label) label.textContent = enabled ? "On" : "Off";
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
function escape(str) {
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
