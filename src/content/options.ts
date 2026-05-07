import type { StorageSync, Suppression } from '../shared/types';
import { sendMessage } from '../shared/messages';

let settings: StorageSync = {
  suppressions: [],
  customPatterns: [],
  disabledDomains: [],
  enabled: true,
};

// ─── Boot ─────────────────────────────────────────────────────────────────────

async function init(): Promise<void> {
  const res = await sendMessage<{ settings: StorageSync }>({ type: 'GET_SETTINGS' });
  if (res?.settings) settings = res.settings;

  renderAll();
  wireControls();
}

// ─── Render ───────────────────────────────────────────────────────────────────

function renderAll(): void {
  (document.getElementById('toggle-enabled') as HTMLInputElement).checked = settings.enabled;
  renderSuppressions();
  renderDomains();
}

function renderSuppressions(): void {
  const list = document.getElementById('suppressions-list')!;
  if (settings.suppressions.length === 0) {
    list.innerHTML = `<div class="empty-suppressions">No suppressions yet. Suppress findings from the popup or DevTools panel.</div>`;
    return;
  }

  list.innerHTML = settings.suppressions
    .slice()
    .sort((a, b) => b.createdAt - a.createdAt)
    .map(s => suppressionHtml(s))
    .join('');

  list.querySelectorAll('.btn-remove').forEach(btn => {
    btn.addEventListener('click', async () => {
      const id = (btn as HTMLElement).dataset['id']!;
      settings = {
        ...settings,
        suppressions: settings.suppressions.filter(s => s.id !== id),
      };
      await save();
      renderSuppressions();
    });
  });
}

function suppressionHtml(s: Suppression): string {
  const time = new Date(s.createdAt).toLocaleDateString();
  return `
    <div class="suppression-item">
      <div class="suppression-info">
        <div class="suppression-label">${esc(s.label)}</div>
        <div class="suppression-meta">Added ${time}</div>
      </div>
      <span class="kind-chip">${esc(s.kind)}</span>
      <button class="btn-remove" data-id="${esc(s.id)}">Remove</button>
    </div>`;
}

function renderDomains(): void {
  const list = document.getElementById('domains-list')!;
  list.innerHTML = settings.disabledDomains
    .map(d => `
      <div class="domain-item">
        <span>${esc(d)}</span>
        <button class="btn-remove" data-domain="${esc(d)}">Remove</button>
      </div>`)
    .join('');

  list.querySelectorAll('.btn-remove').forEach(btn => {
    btn.addEventListener('click', async () => {
      const domain = (btn as HTMLElement).dataset['domain']!;
      settings = {
        ...settings,
        disabledDomains: settings.disabledDomains.filter(d => d !== domain),
      };
      await save();
      renderDomains();
    });
  });
}

// ─── Controls ─────────────────────────────────────────────────────────────────

function wireControls(): void {
  // Enabled toggle
  document.getElementById('toggle-enabled')!.addEventListener('change', async e => {
    settings = { ...settings, enabled: (e.target as HTMLInputElement).checked };
    await save();
  });

  // Add domain
  const domainInput = document.getElementById('domain-input') as HTMLInputElement;
  document.getElementById('btn-add-domain')!.addEventListener('click', async () => {
    const domain = domainInput.value.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    if (!domain || settings.disabledDomains.includes(domain)) return;
    settings = { ...settings, disabledDomains: [...settings.disabledDomains, domain] };
    domainInput.value = '';
    await save();
    renderDomains();
  });

  domainInput.addEventListener('keydown', e => {
    if (e.key === 'Enter') document.getElementById('btn-add-domain')!.click();
  });

  // Export
  document.getElementById('btn-export')!.addEventListener('click', () => {
    const blob = new Blob([JSON.stringify(settings, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sentinel-settings-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  });

  // Import
  document.getElementById('file-import')!.addEventListener('change', async e => {
    const file = (e.target as HTMLInputElement).files?.[0];
    if (!file) return;
    try {
      const text = await file.text();
      const imported = JSON.parse(text) as Partial<StorageSync>;
      settings = {
        suppressions: imported.suppressions ?? [],
        customPatterns: imported.customPatterns ?? [],
        disabledDomains: imported.disabledDomains ?? [],
        enabled: imported.enabled ?? true,
      };
      await save();
      renderAll();
    } catch {
      alert('Invalid settings file.');
    }
  });
}

// ─── Save ─────────────────────────────────────────────────────────────────────

async function save(): Promise<void> {
  await sendMessage({ type: 'UPDATE_SETTINGS', settings });
  const flash = document.getElementById('saved-flash')!;
  flash.classList.add('visible');
  setTimeout(() => flash.classList.remove('visible'), 1800);
}

function esc(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

init().catch(console.error);