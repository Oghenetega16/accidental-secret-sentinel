import type { Finding } from '../shared/types';

// DevTools specific API to get the ID of the page we are inspecting
const inspectedTabId = chrome.devtools.inspectedWindow.tabId;
let findings: Finding[] = [];

// UI Elements
let tbody: HTMLTableSectionElement;
let emptyState: HTMLDivElement;
let clearBtn: HTMLButtonElement;

async function init(): Promise<void> {
    tbody = document.getElementById('findings-body') as HTMLTableSectionElement;
    emptyState = document.getElementById('empty-state') as HTMLDivElement;
    clearBtn = document.getElementById('btn-clear') as HTMLButtonElement;

    // 1. Initial load
    await loadFindings();
    render();

    // 2. Listen for real-time findings while DevTools is open
    chrome.runtime.onMessage.addListener((message) => {
        if (message.type === 'FINDING_DETECTED' && message.finding.tabId === inspectedTabId) {
            findings.push(message.finding);
            render();
        }
    });

    // 3. Clear session
    clearBtn.addEventListener('click', () => {
        chrome.runtime.sendMessage({ type: 'CLEAR_FINDINGS', tabId: inspectedTabId }, () => {
            findings = [];
            render();
        });
    });

    // 4. Hook from devtools.html to refresh when tab is switched to
    (window as any).__sentinelOnShown = () => {
        loadFindings().then(render);
    };
}

async function loadFindings(): Promise<void> {
    return new Promise((resolve) => {
        chrome.runtime.sendMessage({ type: 'GET_FINDINGS', tabId: inspectedTabId }, (response) => {
            findings = response?.findings || [];
            resolve();
        });
    });
}

function render(): void {
    if (findings.length === 0) {
        emptyState.style.display = 'flex';
        tbody.parentElement!.style.display = 'none';
        clearBtn.disabled = true;
        return;
    }

    emptyState.style.display = 'none';
    tbody.parentElement!.style.display = 'table';
    clearBtn.disabled = false;
    tbody.innerHTML = '';

    // Show newest findings at the top
    const displayFindings = [...findings].reverse();

    for (const f of displayFindings) {
        const tr = document.createElement('tr');
        
        tr.innerHTML = `
            <td>
                <span class="badge badge-${f.severity?.toLowerCase() || 'warning'}">
                    ${escapeHtml(f.severity || 'WARN')}
                </span>
            </td>
            <td class="font-bold">${escapeHtml(f.patternName)}</td>
            <td class="font-mono text-red">${escapeHtml(f.redactedValue)}</td>
            <td><span class="source-tag">${escapeHtml(f.sourceType)}</span></td>
            <td class="truncate" title="${escapeHtml(f.url)}">${escapeHtml(new URL(f.url).pathname)}</td>
        `;
        tbody.appendChild(tr);
    }
}

// Security: Always escape strings before injecting into innerHTML
function escapeHtml(str: string): string {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

document.addEventListener('DOMContentLoaded', init);