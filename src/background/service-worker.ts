import type { Message, Finding, Suppression } from '../shared/types';
import {
  getSettings,
  updateSettings,
  getFindings,
  addFinding,
  clearFindings,
  getFindingCount,
} from './storage';
import { isSuppressed } from '../shared/allowlist';

// ─── Service worker lifecycle ─────────────────────────────────────────────────
// MV3 service workers terminate after ~30s of inactivity.
// All state lives in chrome.storage — never rely on in-memory variables.

chrome.runtime.onInstalled.addListener(async () => {
  console.log('[Sentinel] Extension installed / updated.');
  // Initialise storage with defaults if not already set
  const settings = await getSettings();
  await updateSettings(settings); // write defaults back if keys were missing
});

// ─── Message handler ──────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener(
  (message: Message, sender, sendResponse) => {
    // Must return true to keep the message channel open for async responses
    handleMessage(message, sender).then(sendResponse).catch(err => {
      console.error('[Sentinel] Message handler error:', err);
      sendResponse(null);
    });
    return true;
  }
);

async function handleMessage(
  message: Message,
  sender: chrome.runtime.MessageSender
): Promise<unknown> {
  switch (message.type) {

    case 'GET_TAB_ID': {
      return { type: 'GET_TAB_ID_RESPONSE', tabId: sender.tab?.id ?? -1 };
    }

    case 'FINDING_DETECTED': {
      const finding: Finding = message.finding;
      const settings = await getSettings();

      if (!settings.enabled) return null;
      if (isSuppressed(finding, settings)) return null;

      await addFinding(finding);
      await updateBadge(finding.tabId);

      // Notify the popup if it's open
      chrome.runtime.sendMessage({
        type: 'FINDING_DETECTED',
        finding,
      }).catch(() => { /* popup not open — ignore */ });

      return null;
    }

    case 'GET_FINDINGS': {
      const findings = await getFindings(message.tabId);
      return { type: 'GET_FINDINGS_RESPONSE', findings };
    }

    case 'SUPPRESS': {
      const settings = await getSettings();
      const suppression: Suppression = {
        ...message.suppression,
        id: crypto.randomUUID(),
        createdAt: Date.now(),
      };
      await updateSettings({
        suppressions: [...settings.suppressions, suppression],
      });
      return null;
    }

    case 'CLEAR_FINDINGS': {
      await clearFindings(message.tabId);
      await updateBadge(message.tabId);
      return null;
    }

    case 'GET_SETTINGS': {
      const settings = await getSettings();
      return { type: 'GET_SETTINGS_RESPONSE', settings };
    }

    case 'UPDATE_SETTINGS': {
      await updateSettings(message.settings);
      return null;
    }

    default:
      return null;
  }
}

// ─── Badge management ─────────────────────────────────────────────────────────

async function updateBadge(tabId: number): Promise<void> {
  const count = await getFindingCount(tabId);

  if (count === 0) {
    await chrome.action.setBadgeText({ text: '', tabId });
  } else {
    await chrome.action.setBadgeText({
      text: count > 99 ? '99+' : String(count),
      tabId,
    });
    await chrome.action.setBadgeBackgroundColor({
      color: count > 0 ? '#E24B4A' : '#888780',
      tabId,
    });
  }
}

// ─── Tab lifecycle — clear findings when tab navigates ────────────────────────

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo) => {
  if (changeInfo.status === 'loading' && changeInfo.url) {
    // New navigation — clear previous findings for this tab
    await clearFindings(tabId);
    await updateBadge(tabId);
  }
});

chrome.tabs.onRemoved.addListener(async (tabId) => {
  await clearFindings(tabId);
});