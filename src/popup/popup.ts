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
  setToggleState(enabled);

  // Load findings
  const findingsRes = await sendMessage<{ findings: Finding[] }>({
    type: 'GET_FINDINGS',
    tabId: currentTabId,
  });
  findings = findingsRes?.findings ?? [];
  render();

  // Live updates while popup is open
  chrome.runtime.onMessage.addListener((message: Message) => {
    if (message.type === 'FINDING_DETECTED' && message.finding.tabId === currentTabId) {
      findings = [...findings, message.finding];
      render();
    }
    if ((message as any).type === 'SUPPRESSION_ADDED') {
      sendMessage<{ findings: Finding[] }>({ type: 'GET_FINDINGS', tabId: currentTabId })
        .then(res => { findings = res?.findings ?? []; render(); });
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
  const list      = document.getElementById('findings-list')!;
  const countText = document.getElementById('count-text')!;
  const btnClear  = document.getElementById('btn-clear') as HTMLButtonElement;

  if (findings.length === 0) {
    countText.textContent = 'No secrets detected on this page';
    btnClear.style.display = 'none';
    list.innerHTML = `
      <div class="empty" role="status">
        <span class="empty-icon" aria-hidden="true">🛡️</span>
        <div class="empty-title">All clear</div>
        <div class="empty-sub">No exposed secrets detected.<br>Sentinel is watching.</div>
      </div>`;
    return;
  }

  const critCount = findings.filter(f => f.severity === 'critical').length;
  const label = `${findings.length} finding${findings.length !== 1 ? 's' : ''}${critCount > 0 ? ` (${critCount} critical)` : ''}`;
  countText.textContent = label;
  btnClear.style.display = 'block';

  const sorted = findings.slice().sort((a, b) => {
    const order = { critical: 0, warning: 1, info: 2 } as const;
    return (order[a.severity] ?? 3) - (order[b.severity] ?? 3);
  });

  list.innerHTML = sorted.map(f => findingHtml(f)).join('');

  // ── Keyboard + click for expand/collapse ──
  list.querySelectorAll('.finding').forEach(el => {
    // Click
    el.addEventListener('click', e => {
      if ((e.target as HTMLElement).closest('.btn-suppress')) return;
      toggleExpand(el as HTMLElement);
    });
    // Enter / Space to expand
    el.addEventListener('keydown', e => {
      const ke = e as KeyboardEvent;
      if (ke.key === 'Enter' || ke.key === ' ') {
        if ((e.target as HTMLElement).closest('.btn-suppress')) return;
        e.preventDefault();
        toggleExpand(el as HTMLElement);
      }
    });
  });

  // ── Suppress buttons ──
  list.querySelectorAll('.btn-suppress').forEach(btn => {
    btn.addEventListener('click', async e => {
      e.stopPropagation();
      const kind   = (btn as HTMLElement).dataset['kind'] as 'value-hash' | 'domain' | 'pattern';
      const fid    = (btn as HTMLElement).dataset['findingId']!;
      const finding = findings.find(f => f.id === fid);
      if (!finding) return;

      let value: string;
      if (kind === 'value-hash') value = finding.valueHash;
      else if (kind === 'pattern') value = finding.patternId;
      else { try { value = new URL(finding.url).hostname; } catch { value = finding.url; } }

      await sendMessage({
        type: 'SUPPRESS',
        suppression: {
          kind,
          value,
          label: `${finding.patternName} — ${finding.redactedValue}`,
        },
      });

      findings = findings.filter(f => f.id !== fid);
      render();
    });
  });
}

function toggleExpand(el: HTMLElement): void {
  const expanded = el.classList.toggle('expanded');
  el.setAttribute('aria-expanded', String(expanded));
}

function findingHtml(f: Finding): string {
  const time = new Date(f.timestamp).toLocaleTimeString();
  let hostname = f.url;
  try { hostname = new URL(f.url).hostname; } catch { /* noop */ }

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

// ─── Event handlers ───────────────────────────────────────────────────────────

async function onToggle(e: Event): Promise<void> {
  const enabled = (e.target as HTMLInputElement).checked;
  setToggleState(enabled);
  await sendMessage({ type: 'UPDATE_SETTINGS', settings: { enabled } });
}

async function onClearAll(): Promise<void> {
  await sendMessage({ type: 'CLEAR_FINDINGS', tabId: currentTabId });
  findings = [];
  render();
}

function onExport(): void {
  const blob = new Blob([JSON.stringify(findings, null, 2)], { type: 'application/json' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href     = url;
  a.download = `sentinel-findings-${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function setToggleState(enabled: boolean): void {
  const toggle  = document.getElementById('enabled-toggle') as HTMLInputElement;
  const label   = document.getElementById('toggle-label');
  const banner  = document.getElementById('disabled-banner');
  toggle.checked = enabled;
  toggle.setAttribute('aria-checked', String(enabled));
  if (label)  label.textContent = enabled ? 'On' : 'Off';
  if (banner) banner.classList.toggle('visible', !enabled);
}

function sourceLabel(s: Finding['sourceType']): string {
  const map: Record<string, string> = {
    'request-header':  'Request header',
    'request-body':    'Request body',
    'response-header': 'Response header',
    'response-body':   'Response body',
    'js-bundle':       'JS bundle',
    'html-source':     'HTML source',
    'url-param':       'URL parameter',
  };
  return map[s] ?? s;
}

function esc(str: string): string {
  return str
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function sendMessage<T>(message: Message): Promise<T | null> {
  return new Promise(resolve => {
    chrome.runtime.sendMessage(message, response => {
      if (chrome.runtime.lastError) { resolve(null); return; }
      resolve(response ?? null);
    });
  });
}

init().catch(console.error);