import type { Message, Finding, Suppression } from '../shared/types';
import {
  getSettings,
  updateSettings,
  getFindings,
  addFinding,
  clearFindings,
  getFindingCount,
  addSuppression,
  removeSuppression,
  purgeSuppressedFindings,
} from './storage';
import { isSuppressed } from '../shared/allowlist';

// MV3 service workers terminate after ~30s of inactivity.
// All state lives in chrome.storage — never rely on in-memory variables.

chrome.runtime.onInstalled.addListener(async () => {
  console.log('[Sentinel] Extension installed / updated.');
  const settings = await getSettings();
  await updateSettings(settings);
});

// ─── Message handler ──────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener(
  (message: Message, sender, sendResponse) => {
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
      return { tabId: sender.tab?.id ?? -1 };
    }

    case 'FINDING_DETECTED': {
      const finding: Finding = message.finding;
      const settings = await getSettings();

      if (!settings.enabled) return { stored: false };
      if (isSuppressed(finding, settings)) return { stored: false };

      await addFinding(finding);
      await updateBadge(finding.tabId);

      // Notify popup if open
      chrome.runtime.sendMessage({
        type: 'FINDING_DETECTED',
        finding,
      }).catch(() => {});

      // Forward to the tab's relay.ts (ISOLATED world) which bridges
      // to MAIN world via window.postMessage so the toast can fire.
      if (finding.tabId > 0) {
        chrome.tabs.sendMessage(finding.tabId, {
          type: 'FINDING_DETECTED',
          finding,
        }).catch(() => {});
      }

      return null;
    }

    case 'GET_FINDINGS': {
      const findings = await getFindings(message.tabId);
      return { type: 'GET_FINDINGS_RESPONSE', findings };
    }

    case 'SUPPRESS': {
      const sup = message.suppression;
      const result = await addSuppression(sup);

      if (result.added) {
        await purgeSuppressedFindings(sup);
        chrome.runtime.sendMessage({
          type: 'SUPPRESSION_ADDED',
          suppression: sup,
        } as any).catch(() => {});
        const tabs = await chrome.tabs.query({});
        for (const tab of tabs) {
          if (tab.id) await updateBadge(tab.id);
        }
      }

      return { added: result.added, reason: result.reason };
    }

    case 'REMOVE_SUPPRESSION': {
      await removeSuppression((message as any).suppressionId);
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
    await chrome.action.setBadgeBackgroundColor({ color: '#E24B4A', tabId });
  }
}

// ─── Tab lifecycle ─────────────────────────────────────────────────────────────

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo) => {
  // Clear on any loading event — including same-page refresh where
  // changeInfo.url is undefined because the URL did not change.
  if (changeInfo.status === 'loading') {
    await clearFindings(tabId);
    await updateBadge(tabId);
  }
});

chrome.tabs.onRemoved.addListener(async (tabId) => {
  await clearFindings(tabId);
});