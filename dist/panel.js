const MSG = {
  FINDING_DETECTED: "FINDING_DETECTED",
  GET_FINDINGS: "GET_FINDINGS",
  GET_FINDINGS_RESPONSE: "GET_FINDINGS_RESPONSE",
  SUPPRESS: "SUPPRESS",
  CLEAR_FINDINGS: "CLEAR_FINDINGS",
  GET_SETTINGS: "GET_SETTINGS",
  GET_SETTINGS_RESPONSE: "GET_SETTINGS_RESPONSE",
  UPDATE_SETTINGS: "UPDATE_SETTINGS"
};
const createMessage = {
  findingDetected: (finding) => ({
    type: MSG.FINDING_DETECTED,
    finding
  }),
  getFindings: (tabId2) => ({
    type: MSG.GET_FINDINGS,
    tabId: tabId2
  }),
  getFindingsResponse: (findings) => ({
    type: MSG.GET_FINDINGS_RESPONSE,
    findings
  }),
  suppress: (suppression) => ({
    type: MSG.SUPPRESS,
    suppression
  }),
  clearFindings: (tabId2) => ({
    type: MSG.CLEAR_FINDINGS,
    tabId: tabId2
  }),
  getSettings: () => ({
    type: MSG.GET_SETTINGS
  }),
  getSettingsResponse: (settings) => ({
    type: MSG.GET_SETTINGS_RESPONSE,
    settings
  }),
  updateSettings: (settings) => ({
    type: MSG.UPDATE_SETTINGS,
    settings
  })
};
function sendMessage(message) {
  return new Promise((resolve) => {
    try {
      chrome.runtime.sendMessage(message, (response) => {
        if (chrome.runtime.lastError) {
          resolve(null);
          return;
        }
        resolve(response ?? null);
      });
    } catch {
      resolve(null);
    }
  });
}
let allFindings = [];
let activeFilter = "all";
let searchQuery = "";
let suppressionCount = 0;
let tabId = chrome.devtools.inspectedWindow.tabId;
async function init() {
  updateStatusBar();
  await loadFindings();
  wireToolbar();
  wireSearch();
  listenForLiveFindings();
}
async function loadFindings() {
  var _a;
  const res = await sendMessage(
    createMessage.getFindings(tabId)
  );
  allFindings = (res == null ? void 0 : res.findings) ?? [];
  const settingsRes = await sendMessage(
    createMessage.getSettings()
  );
  suppressionCount = ((_a = settingsRes == null ? void 0 : settingsRes.settings) == null ? void 0 : _a.suppressions.length) ?? 0;
  renderTable();
  updateStatusBar();
}
function listenForLiveFindings() {
  chrome.runtime.onMessage.addListener((message) => {
    if (message.type === "FINDING_DETECTED" && message.finding.tabId === tabId) {
      allFindings = [...allFindings, message.finding];
      renderTable();
      updateStatusBar();
    }
  });
}
window.__sentinelOnShown = () => {
  loadFindings();
};
function filteredFindings() {
  return allFindings.filter((f) => {
    if (activeFilter !== "all" && f.severity !== activeFilter) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      return f.patternName.toLowerCase().includes(q) || f.redactedValue.toLowerCase().includes(q) || f.url.toLowerCase().includes(q) || f.sourceType.toLowerCase().includes(q);
    }
    return true;
  });
}
function renderTable() {
  const body = document.getElementById("table-body");
  const empty = document.getElementById("empty-state");
  const countPill = document.getElementById("total-count");
  const visible = filteredFindings();
  countPill.textContent = String(allFindings.length);
  if (visible.length === 0) {
    body.innerHTML = "";
    empty.style.display = "block";
    body.appendChild(empty);
    return;
  }
  empty.style.display = "none";
  body.innerHTML = visible.slice().sort((a, b) => {
    const order = { critical: 0, warning: 1, info: 2 };
    const sevDiff = (order[a.severity] ?? 3) - (order[b.severity] ?? 3);
    return sevDiff !== 0 ? sevDiff : b.timestamp - a.timestamp;
  }).map((f) => rowHtml(f)).join("");
  body.querySelectorAll(".row").forEach((el) => {
    el.addEventListener("click", () => {
      const id = el.dataset["id"];
      const finding = allFindings.find((f) => f.id === id) ?? null;
      selectFinding(finding);
      body.querySelectorAll(".row").forEach((r) => r.classList.remove("selected"));
      el.classList.add("selected");
    });
  });
  updateStatusBar();
}
function rowHtml(f) {
  const time = new Date(f.timestamp).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit"
  });
  let hostname = f.url;
  try {
    hostname = new URL(f.url).hostname;
  } catch {
  }
  return `
    <div class="row" data-id="${esc(f.id)}" role="row" tabindex="0">
      <div class="cell cell-sev">
        <span class="sev-dot sev-dot-${esc(f.severity)}" title="${esc(f.severity)}"></span>
      </div>
      <div class="cell cell-pattern" title="${esc(f.patternName)}">${esc(f.patternName)}</div>
      <div class="cell cell-value">${esc(f.redactedValue)}</div>
      <div class="cell cell-source">${esc(sourceLabel(f.sourceType))}</div>
      <div class="cell cell-url" title="${esc(f.url)}">${esc(hostname)}</div>
      <div class="cell cell-time">${esc(time)}</div>
    </div>`;
}
function selectFinding(f) {
  const empty = document.getElementById("detail-empty");
  const content = document.getElementById("detail-content");
  if (!f) {
    empty.style.display = "flex";
    content.style.display = "none";
    return;
  }
  empty.style.display = "none";
  content.style.display = "flex";
  setText("d-pattern-name", f.patternName);
  const sevEl = document.getElementById("d-severity");
  sevEl.textContent = f.severity.toUpperCase();
  sevEl.className = `sev-badge sev-badge-${f.severity}`;
  setText("d-value", f.redactedValue);
  setText("d-source", sourceLabel(f.sourceType));
  setText("d-url", f.url);
  setText("d-time", new Date(f.timestamp).toLocaleString());
  setText("d-hash", f.valueHash);
  setText("d-entropy-num", `(${f.entropy.toFixed(2)} bits)`);
  const pct = Math.min(f.entropy / 6 * 100, 100);
  const bar = document.getElementById("d-entropy-bar");
  bar.style.width = `${pct}%`;
  bar.style.background = f.entropy >= 4 ? "#4e9fe5" : f.entropy >= 3 ? "#e8a94c" : "#888";
  wireSuppressButtons(f);
}
function wireSuppressButtons(f) {
  const btn = (id, kind, label) => {
    const el = document.getElementById(id);
    if (!el) return;
    el.onclick = async () => {
      let value;
      if (kind === "value-hash") value = f.valueHash;
      else if (kind === "pattern") value = f.patternId;
      else {
        try {
          value = new URL(f.url).hostname;
        } catch {
          value = f.url;
        }
      }
      await sendMessage(createMessage.suppress({ kind, value, label }));
      allFindings = allFindings.filter((x) => {
        if (kind === "value-hash") return x.valueHash !== f.valueHash;
        if (kind === "pattern") return x.patternId !== f.patternId;
        try {
          return new URL(x.url).hostname !== new URL(f.url).hostname;
        } catch {
          return true;
        }
      });
      suppressionCount++;
      selectFinding(null);
      renderTable();
      updateStatusBar();
    };
  };
  btn("d-sup-value", "value-hash", `${f.patternName} — ${f.redactedValue}`);
  btn("d-sup-domain", "domain", `All on ${(() => {
    try {
      return new URL(f.url).hostname;
    } catch {
      return f.url;
    }
  })()}`);
  btn("d-sup-pattern", "pattern", `All ${f.patternName} detections`);
}
function wireToolbar() {
  document.querySelectorAll(".chip").forEach((chip) => {
    chip.addEventListener("click", () => {
      const filter = chip.dataset["filter"];
      activeFilter = filter;
      document.querySelectorAll(".chip").forEach((c) => {
        c.className = "chip";
      });
      chip.classList.add(`active-${filter}`);
      renderTable();
    });
  });
  document.getElementById("btn-clear").addEventListener("click", async () => {
    await sendMessage(createMessage.clearFindings(tabId));
    allFindings = [];
    selectFinding(null);
    renderTable();
    updateStatusBar();
  });
  document.getElementById("btn-export").addEventListener("click", () => {
    const blob = new Blob(
      [JSON.stringify(filteredFindings(), null, 2)],
      { type: "application/json" }
    );
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `sentinel-findings-tab${tabId}-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  });
  document.getElementById("btn-refresh").addEventListener("click", loadFindings);
}
function wireSearch() {
  const input = document.getElementById("search-input");
  input.addEventListener("input", () => {
    searchQuery = input.value.trim();
    renderTable();
  });
}
function updateStatusBar() {
  setText("status-tab", `Tab: ${tabId}`);
  setText("status-filtered", `Showing: ${filteredFindings().length} / ${allFindings.length}`);
  setText("status-suppressed", `Suppressions active: ${suppressionCount}`);
}
function setText(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value;
}
function esc(str) {
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
function sourceLabel(s) {
  const map = {
    "request-header": "Req header",
    "request-body": "Req body",
    "response-header": "Res header",
    "response-body": "Res body",
    "js-bundle": "JS bundle",
    "html-source": "HTML",
    "url-param": "URL param"
  };
  return map[s] ?? s;
}
init().catch(console.error);
//# sourceMappingURL=panel.js.map
