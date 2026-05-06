import type { Finding } from '../shared/types';

const TOAST_ID   = 'sentinel-toast-main';
const STYLE_ID   = 'sentinel-toast-styles';
const AUTO_CLOSE = 6000;

let toastCount   = 0;
let autoCloseTimer: ReturnType<typeof setTimeout> | null = null;

// ─── Style injection ──────────────────────────────────────────────────────────

function ensureStyles(): void {
  if (document.getElementById(STYLE_ID)) return;
  const style = document.createElement('style');
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

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Shows or updates a single summary toast.
 * Only one toast exists at a time — subsequent findings update the count.
 * This prevents flooding the page when multiple secrets are detected at once.
 */
export function showFindingToast(finding: Finding): void {
  toastCount++;

  ensureStyles();

  const existing = document.getElementById(TOAST_ID);

  if (existing) {
    // Update the existing toast with the new count
    const body = existing.querySelector('.s-body');
    if (body) {
      body.textContent = toastCount === 1
        ? `${finding.patternName} — click the extension badge to view.`
        : `${toastCount} secrets detected — click the extension badge to view all.`;
    }
    // Reset auto-close timer
    if (autoCloseTimer) clearTimeout(autoCloseTimer);
    autoCloseTimer = setTimeout(() => dismissToast(), AUTO_CLOSE);
    return;
  }

  // Create fresh toast
  const toast = document.createElement('div');
  toast.id = TOAST_ID;
  toast.setAttribute('role', 'alert');
  toast.setAttribute('aria-live', 'assertive');
  toast.innerHTML = `
    <div class="s-title">🔑 Secret detected</div>
    <div class="s-body">${escHtml(finding.patternName)} — click the extension badge to view.</div>
    <button class="s-close" aria-label="Dismiss">&times;</button>
  `;

  toast.querySelector('.s-close')!.addEventListener('click', dismissToast);
  (document.body || document.documentElement).appendChild(toast);

  if (autoCloseTimer) clearTimeout(autoCloseTimer);
  autoCloseTimer = setTimeout(() => dismissToast(), AUTO_CLOSE);
}

function dismissToast(): void {
  const toast = document.getElementById(TOAST_ID);
  if (!toast) return;
  toast.classList.add('closing');
  setTimeout(() => toast.parentNode?.removeChild(toast), 200);
}

function escHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}