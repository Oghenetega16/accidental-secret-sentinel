import type { Finding } from '../shared/types';

const TOAST_ID_PREFIX = 'sentinel-toast-';
const STYLE_ID = 'sentinel-toast-styles';
const MAX_TOASTS = 3;

// ─── Style injection ──────────────────────────────────────────────────────────

function ensureStyles(): void {
  if (document.getElementById(STYLE_ID)) return;
  const style = document.createElement('style');
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

// ─── Toast container ──────────────────────────────────────────────────────────

function getOrCreateContainer(): HTMLElement {
  let wrap = document.getElementById('sentinel-toast-wrap');
  if (!wrap) {
    wrap = document.createElement('div');
    wrap.id = 'sentinel-toast-wrap';
    wrap.className = 'sentinel-toast-wrap';
    (document.body || document.documentElement).appendChild(wrap);
  }
  return wrap;
}

// ─── Show a toast ─────────────────────────────────────────────────────────────

/**
 * Shows a dismissible toast notification for a finding.
 * Only shows one toast per unique patternId per page load to avoid flooding.
 * Auto-dismisses after 8 seconds.
 */
export function showFindingToast(finding: Finding): void {
  // Only one toast per pattern per page to avoid flooding
  const toastId = `${TOAST_ID_PREFIX}${finding.patternId}`;
  if (document.getElementById(toastId)) return;

  ensureStyles();
  const container = getOrCreateContainer();

  // Enforce max concurrent toasts
  const existing = container.querySelectorAll('.sentinel-toast');
  if (existing.length >= MAX_TOASTS) {
    // Dismiss the oldest one
    dismissToast(existing[0] as HTMLElement);
  }

  const severityClass = finding.severity === 'warning' ? 'warning'
    : finding.severity === 'info' ? 'info' : '';

  const toast = document.createElement('div');
  toast.id = toastId;
  toast.className = `sentinel-toast ${severityClass}`.trim();
  toast.setAttribute('role', 'alert');
  toast.setAttribute('aria-live', 'assertive');

  toast.innerHTML = `
    <div class="sentinel-toast-title">🔑 Secret detected</div>
    <div class="sentinel-toast-body">${escHtml(finding.patternName)}</div>
    <div class="sentinel-toast-value">${escHtml(finding.redactedValue)}</div>
    <button class="sentinel-toast-close" aria-label="Dismiss">&times;</button>
  `;

  toast.querySelector('.sentinel-toast-close')!
    .addEventListener('click', () => dismissToast(toast));

  container.appendChild(toast);

  // Auto-dismiss after 8 seconds
  setTimeout(() => dismissToast(toast), 8000);
}

function dismissToast(el: HTMLElement): void {
  if (!el.parentNode) return;
  el.classList.add('dismissing');
  setTimeout(() => el.parentNode?.removeChild(el), 200);
}

function escHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}