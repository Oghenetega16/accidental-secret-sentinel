import type { Finding, Message, StorageSync } from '../shared/types';
import { createMessage, sendMessage } from '../shared/messages';

// ─── State ────────────────────────────────────────────────────────────────────

let allFindings: Finding[] = [];
let selectedFinding: Finding | null = null;
let activeFilter: 'all' | 'critical' | 'warning' | 'info' = 'all';
let searchQuery = '';
let suppressionCount = 0;
let tabId = chrome.devtools.inspectedWindow.tabId;

// ─── Boot ─────────────────────────────────────────────────────────────────────

async function init(): Promise<void> {
  updateStatusBar();
  await loadFindings();
  wireToolbar();
  wireSearch();
  listenForLiveFindings();
}

// ─── Data loading ─────────────────────────────────────────────────────────────

async function loadFindings(): Promise<void> {
  const res = await sendMessage<{ findings: Finding[] }>(
    createMessage.getFindings(tabId)
  );
  allFindings = res?.findings ?? [];

  const settingsRes = await sendMessage<{ settings: StorageSync }>(
    createMessage.getSettings()
  );
  suppressionCount = settingsRes?.settings?.suppressions.length ?? 0;

  renderTable();
  updateStatusBar();
}

// ─── Live updates ─────────────────────────────────────────────────────────────

function listenForLiveFindings(): void {
  chrome.runtime.onMessage.addListener((message: Message) => {
    if (
      message.type === 'FINDING_DETECTED' &&
      message.finding.tabId === tabId
    ) {
      allFindings = [...allFindings, message.finding];
      renderTable();
      updateStatusBar();
    }
  });
}

// Expose hook for devtools.html panel.onShown callback
(window as Window & { __sentinelOnShown?: () => void }).__sentinelOnShown = () => {
  loadFindings();
};

// ─── Filtered view ────────────────────────────────────────────────────────────

function filteredFindings(): Finding[] {
  return allFindings.filter(f => {
    if (activeFilter !== 'all' && f.severity !== activeFilter) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      return (
        f.patternName.toLowerCase().includes(q) ||
        f.redactedValue.toLowerCase().includes(q) ||
        f.url.toLowerCase().includes(q) ||
        f.sourceType.toLowerCase().includes(q)
      );
    }
    return true;
  });
}

// ─── Table render ─────────────────────────────────────────────────────────────

function renderTable(): void {
  const body = document.getElementById('table-body')!;
  const empty = document.getElementById('empty-state')!;
  const countPill = document.getElementById('total-count')!;

  const visible = filteredFindings();
  countPill.textContent = String(allFindings.length);

  if (visible.length === 0) {
    body.innerHTML = '';
    empty.style.display = 'block';
    body.appendChild(empty);
    return;
  }

  empty.style.display = 'none';

  body.innerHTML = visible
    .slice()
    .sort((a, b) => {
      const order = { critical: 0, warning: 1, info: 2 } as const;
      const sevDiff = (order[a.severity] ?? 3) - (order[b.severity] ?? 3);
      return sevDiff !== 0 ? sevDiff : b.timestamp - a.timestamp;
    })
    .map(f => rowHtml(f))
    .join('');

  // Wire row click
  body.querySelectorAll('.row').forEach(el => {
    el.addEventListener('click', () => {
      const id = (el as HTMLElement).dataset['id'];
      const finding = allFindings.find(f => f.id === id) ?? null;
      selectFinding(finding);
      body.querySelectorAll('.row').forEach(r => r.classList.remove('selected'));
      el.classList.add('selected');
    });
  });

  updateStatusBar();
}

function rowHtml(f: Finding): string {
  const time = new Date(f.timestamp).toLocaleTimeString([], {
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  });

  let hostname = f.url;
  try { hostname = new URL(f.url).hostname; } catch { /* noop */ }

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

// ─── Detail pane ──────────────────────────────────────────────────────────────

function selectFinding(f: Finding | null): void {
  selectedFinding = f;

  const empty   = document.getElementById('detail-empty')!;
  const content = document.getElementById('detail-content')!;

  if (!f) {
    empty.style.display = 'flex';
    content.style.display = 'none';
    return;
  }

  empty.style.display = 'none';
  content.style.display = 'flex';

  setText('d-pattern-name', f.patternName);

  const sevEl = document.getElementById('d-severity')!;
  sevEl.textContent = f.severity.toUpperCase();
  sevEl.className = `sev-badge sev-badge-${f.severity}`;

  setText('d-value', f.redactedValue);
  setText('d-source', sourceLabel(f.sourceType));
  setText('d-url', f.url);
  setText('d-time', new Date(f.timestamp).toLocaleString());
  setText('d-hash', f.valueHash);
  setText('d-entropy-num', `(${f.entropy.toFixed(2)} bits)`);

  // Entropy bar — max realistic is ~6, show as % of 6
  const pct = Math.min((f.entropy / 6) * 100, 100);
  const bar = document.getElementById('d-entropy-bar')!;
  bar.style.width = `${pct}%`;
  bar.style.background = f.entropy >= 4 ? '#4e9fe5' : f.entropy >= 3 ? '#e8a94c' : '#888';

  wireSuppressButtons(f);
}

function wireSuppressButtons(f: Finding): void {
  const btn = (id: string, kind: 'value-hash' | 'domain' | 'pattern', label: string) => {
    const el = document.getElementById(id);
    if (!el) return;
    el.onclick = async () => {
      let value: string;
      if (kind === 'value-hash') value = f.valueHash;
      else if (kind === 'pattern') value = f.patternId;
      else {
        try { value = new URL(f.url).hostname; }
        catch { value = f.url; }
      }

      await sendMessage(createMessage.suppress({ kind, value, label }));

      // Remove from local list and refresh
      allFindings = allFindings.filter(x => {
        if (kind === 'value-hash') return x.valueHash !== f.valueHash;
        if (kind === 'pattern')    return x.patternId !== f.patternId;
        try {
          return new URL(x.url).hostname !== new URL(f.url).hostname;
        } catch { return true; }
      });

      suppressionCount++;
      selectedFinding = null;
      selectFinding(null);
      renderTable();
      updateStatusBar();
    };
  };

  btn('d-sup-value',   'value-hash', `${f.patternName} — ${f.redactedValue}`);
  btn('d-sup-domain',  'domain',     `All on ${(() => { try { return new URL(f.url).hostname; } catch { return f.url; } })()}`);
  btn('d-sup-pattern', 'pattern',   `All ${f.patternName} detections`);
}

// ─── Toolbar wiring ───────────────────────────────────────────────────────────

function wireToolbar(): void {
  // Filter chips
  document.querySelectorAll('.chip').forEach(chip => {
    chip.addEventListener('click', () => {
      const filter = (chip as HTMLElement).dataset['filter'] as typeof activeFilter;
      activeFilter = filter;

      // Reset all chips
      document.querySelectorAll('.chip').forEach(c => {
        c.className = 'chip';
      });
      chip.classList.add(`active-${filter}`);
      renderTable();
    });
  });

  // Clear
  document.getElementById('btn-clear')!.addEventListener('click', async () => {
    await sendMessage(createMessage.clearFindings(tabId));
    allFindings = [];
    selectedFinding = null;
    selectFinding(null);
    renderTable();
    updateStatusBar();
  });

  // Export
  document.getElementById('btn-export')!.addEventListener('click', () => {
    const blob = new Blob(
      [JSON.stringify(filteredFindings(), null, 2)],
      { type: 'application/json' }
    );
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sentinel-findings-tab${tabId}-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  });

  // Refresh
  document.getElementById('btn-refresh')!.addEventListener('click', loadFindings);
}

// ─── Search ───────────────────────────────────────────────────────────────────

function wireSearch(): void {
  const input = document.getElementById('search-input') as HTMLInputElement;
  input.addEventListener('input', () => {
    searchQuery = input.value.trim();
    renderTable();
  });
}

// ─── Status bar ───────────────────────────────────────────────────────────────

function updateStatusBar(): void {
  setText('status-tab',        `Tab: ${tabId}`);
  setText('status-filtered',   `Showing: ${filteredFindings().length} / ${allFindings.length}`);
  setText('status-suppressed', `Suppressions active: ${suppressionCount}`);
}

// ─── Utilities ────────────────────────────────────────────────────────────────

function setText(id: string, value: string): void {
  const el = document.getElementById(id);
  if (el) el.textContent = value;
}

function esc(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function sourceLabel(s: Finding['sourceType']): string {
  const map: Record<string, string> = {
    'request-header':  'Req header',
    'request-body':    'Req body',
    'response-header': 'Res header',
    'response-body':   'Res body',
    'js-bundle':       'JS bundle',
    'html-source':     'HTML',
    'url-param':       'URL param',
  };
  return map[s] ?? s;
}

// Boot
init().catch(console.error);