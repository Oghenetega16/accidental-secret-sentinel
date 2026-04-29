import type { Finding, Message } from '../shared/types';

let currentTabId = -1;
let findings: Finding[] = [];

// ─── Init ─────────────────────────────────────────────────────────────────────

async function init(): Promise<void> {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) return;
  currentTabId = tab.id;

  // Load settings
  const settingsRes = await sendMessage<{ settings: { enabled: boolean } }>({ type: 'GET_SETTINGS' });
  const enabled = settingsRes?.settings?.enabled ?? true;
  (document.getElementById('enabled-toggle') as HTMLInputElement).checked = enabled;
  updateToggleLabel(enabled);

  // Load findings
  const findingsRes = await sendMessage<{ findings: Finding[] }>({
    type: 'GET_FINDINGS',
    tabId: currentTabId,
  });
  findings = findingsRes?.findings ?? [];
  render();

  // Listen for new findings while popup is open
  chrome.runtime.onMessage.addListener((message: Message) => {
    if (message.type === 'FINDING_DETECTED' && message.finding.tabId === currentTabId) {
      findings = [...findings, message.finding];
      render();
    }
  });

  // Wire controls
  document.getElementById('enabled-toggle')!.addEventListener('change', onToggle);
  document.getElementById('btn-clear')!.addEventListener('click', onClearAll);
  document.getElementById('btn-export')!.addEventListener('click', onExport);
  document.getElementById('btn-settings')!.addEventListener('click', () => {
    chrome.runtime.openOptionsPage();
  });
}

// ─── Render ───────────────────────────────────────────────────────────────────

function render(): void {
  const list = document.getElementById('findings-list')!;
  const countText = document.getElementById('count-text')!;
  const btnClear = document.getElementById('btn-clear') as HTMLButtonElement;

  if (findings.length === 0) {
    countText.textContent = 'No secrets detected on this page';
    btnClear.style.display = 'none';
    list.innerHTML = `
      <div class="empty">
        <div class="empty-icon">🛡️</div>
        <div class="empty-title">All clear</div>
        <div class="empty-sub">No exposed secrets detected.<br>Browse normally — Sentinel is watching.</div>
      </div>`;
    return;
  }

  const critCount = findings.filter(f => f.severity === 'critical').length;
  countText.textContent = `${findings.length} finding${findings.length !== 1 ? 's' : ''}${critCount > 0 ? ` (${critCount} critical)` : ''}`;
  btnClear.style.display = 'block';

  list.innerHTML = findings
    .sort((a, b) => {
      const order = { critical: 0, warning: 1, info: 2 };
      return (order[a.severity] ?? 3) - (order[b.severity] ?? 3);
    })
    .map(f => findingHtml(f))
    .join('');

  // Wire expand toggles
  list.querySelectorAll('.finding').forEach(el => {
    el.addEventListener('click', e => {
      const target = e.currentTarget as HTMLElement;
      target.classList.toggle('expanded');
    });
  });

  // Wire suppress buttons (stop propagation to avoid toggling expand)
  list.querySelectorAll('.btn-suppress').forEach(btn => {
    btn.addEventListener('click', async e => {
      e.stopPropagation();
      const kind = (btn as HTMLElement).dataset['kind'] as 'value-hash' | 'domain' | 'pattern';
      const findingId = (btn as HTMLElement).dataset['findingId']!;
      const finding = findings.find(f => f.id === findingId);
      if (!finding) return;

      await sendMessage({
        type: 'SUPPRESS',
        suppression: {
          kind,
          value: kind === 'value-hash' ? finding.valueHash
            : kind === 'pattern' ? finding.patternId
            : new URL(finding.url).hostname,
          label: `${finding.patternName} — ${finding.redactedValue}`,
        },
      });

      // Remove suppressed finding from local list
      findings = findings.filter(f => f.id !== findingId);
      render();
    });
  });
}

function findingHtml(f: Finding): string {
  const time = new Date(f.timestamp).toLocaleTimeString();
  let hostname = f.url;
  try { hostname = new URL(f.url).hostname; } catch { /* noop */ }

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

// ─── Event handlers ───────────────────────────────────────────────────────────

async function onToggle(e: Event): Promise<void> {
  const enabled = (e.target as HTMLInputElement).checked;
  updateToggleLabel(enabled);
  await sendMessage({ type: 'UPDATE_SETTINGS', settings: { enabled } });
}

async function onClearAll(): Promise<void> {
  await sendMessage({ type: 'CLEAR_FINDINGS', tabId: currentTabId });
  findings = [];
  render();
}

function onExport(): void {
  const blob = new Blob([JSON.stringify(findings, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `sentinel-findings-${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function updateToggleLabel(enabled: boolean): void {
  const label = document.getElementById('toggle-label');
  if (label) label.textContent = enabled ? 'On' : 'Off';
}

function sourceLabel(s: Finding['sourceType']): string {
  const map: Record<string, string> = {
    'request-header': 'Request header',
    'request-body': 'Request body',
    'response-header': 'Response header',
    'response-body': 'Response body',
    'js-bundle': 'JS bundle',
    'html-source': 'HTML source',
    'url-param': 'URL parameter',
  };
  return map[s] ?? s;
}

function escape(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function sendMessage<T>(message: Message): Promise<T | null> {
  return new Promise(resolve => {
    chrome.runtime.sendMessage(message, response => {
      if (chrome.runtime.lastError) { resolve(null); return; }
      resolve(response ?? null);
    });
  });
}

// Boot
init().catch(console.error);