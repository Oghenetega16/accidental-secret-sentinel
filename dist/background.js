const DEFAULT_SYNC = {
  suppressions: [],
  customPatterns: [],
  disabledDomains: [],
  enabled: true
};
const SYNC_QUOTA_BYTES_ITEM = 8192;
const MAX_SUPPRESSIONS = 200;
async function getSettings() {
  const result = await chrome.storage.sync.get(DEFAULT_SYNC);
  return {
    suppressions: Array.isArray(result["suppressions"]) ? result["suppressions"] : [],
    customPatterns: Array.isArray(result["customPatterns"]) ? result["customPatterns"] : [],
    disabledDomains: Array.isArray(result["disabledDomains"]) ? result["disabledDomains"] : [],
    enabled: typeof result["enabled"] === "boolean" ? result["enabled"] : true
  };
}
async function updateSettings(partial) {
  await chrome.storage.sync.set(partial);
}
async function addSuppression(suppression) {
  const settings = await getSettings();
  const existing = settings.suppressions;
  const isDuplicate = existing.some(
    (s) => s.kind === suppression.kind && s.value === suppression.value
  );
  if (isDuplicate) {
    return { added: false, reason: "duplicate" };
  }
  const newSuppression = {
    ...suppression,
    id: crypto.randomUUID(),
    createdAt: Date.now()
  };
  let updated = [...existing, newSuppression];
  if (updated.length > MAX_SUPPRESSIONS) {
    updated = updated.sort((a, b) => a.createdAt - b.createdAt).slice(updated.length - MAX_SUPPRESSIONS);
  }
  const serialized = JSON.stringify(updated);
  if (serialized.length > SYNC_QUOTA_BYTES_ITEM) {
    updated = updated.slice(1);
  }
  await chrome.storage.sync.set({ suppressions: updated });
  return { added: true };
}
async function removeSuppression(id) {
  const settings = await getSettings();
  await chrome.storage.sync.set({
    suppressions: settings.suppressions.filter((s) => s.id !== id)
  });
}
async function getFindings(tabId) {
  const result = await chrome.storage.local.get("findings");
  const findings = result["findings"] ?? {};
  return findings[String(tabId)] ?? [];
}
async function addFinding(finding) {
  const result = await chrome.storage.local.get("findings");
  const all = result["findings"] ?? {};
  const key = String(finding.tabId);
  const existing = all[key] ?? [];
  if (existing.some((f) => f.valueHash === finding.valueHash)) return;
  all[key] = [...existing, finding];
  await chrome.storage.local.set({ findings: all });
}
async function clearFindings(tabId) {
  const result = await chrome.storage.local.get("findings");
  const all = result["findings"] ?? {};
  delete all[String(tabId)];
  await chrome.storage.local.set({ findings: all });
}
async function getFindingCount(tabId) {
  return (await getFindings(tabId)).length;
}
async function purgeSuppressedFindings(suppression) {
  const result = await chrome.storage.local.get("findings");
  const all = result["findings"] ?? {};
  let changed = false;
  for (const tabKey of Object.keys(all)) {
    const before = all[tabKey] ?? [];
    const after = before.filter((f) => {
      if (suppression.kind === "value-hash") return f.valueHash !== suppression.value;
      if (suppression.kind === "pattern") return f.patternId !== suppression.value;
      if (suppression.kind === "domain") {
        try {
          const h = new URL(f.url).hostname;
          const matched = h === suppression.value || h.endsWith("." + suppression.value);
          return !matched;
        } catch {
          return true;
        }
      }
      return true;
    });
    if (after.length !== before.length) {
      all[tabKey] = after;
      changed = true;
    }
  }
  if (changed) await chrome.storage.local.set({ findings: all });
}
function isSuppressed(finding, settings) {
  const { suppressions, disabledDomains } = settings;
  try {
    const hostname = new URL(finding.url).hostname;
    if (disabledDomains.some((d) => hostname === d || hostname.endsWith("." + d))) {
      return true;
    }
  } catch {
  }
  for (const s of suppressions) {
    if (s.kind === "value-hash" && s.value === finding.valueHash) return true;
    if (s.kind === "pattern" && s.value === finding.patternId) return true;
  }
  return false;
}
chrome.runtime.onInstalled.addListener(async () => {
  console.log("[Sentinel] Extension installed / updated.");
  const settings = await getSettings();
  await updateSettings(settings);
});
chrome.runtime.onMessage.addListener(
  (message, sender, sendResponse) => {
    handleMessage(message, sender).then(sendResponse).catch((err) => {
      console.error("[Sentinel] Message handler error:", err);
      sendResponse(null);
    });
    return true;
  }
);
async function handleMessage(message, sender) {
  var _a;
  switch (message.type) {
    case "GET_TAB_ID": {
      return { tabId: ((_a = sender.tab) == null ? void 0 : _a.id) ?? -1 };
    }
    case "FINDING_DETECTED": {
      const finding = message.finding;
      const settings = await getSettings();
      if (!settings.enabled) return { stored: false };
      if (isSuppressed(finding, settings)) return { stored: false };
      await addFinding(finding);
      await updateBadge(finding.tabId);
      chrome.runtime.sendMessage({
        type: "FINDING_DETECTED",
        finding
      }).catch(() => {
      });
      if (finding.tabId > 0) {
        chrome.tabs.sendMessage(finding.tabId, {
          type: "FINDING_DETECTED",
          finding
        }).catch(() => {
        });
      }
      return null;
    }
    case "GET_FINDINGS": {
      const findings = await getFindings(message.tabId);
      return { type: "GET_FINDINGS_RESPONSE", findings };
    }
    case "SUPPRESS": {
      const sup = message.suppression;
      const result = await addSuppression(sup);
      if (result.added) {
        await purgeSuppressedFindings(sup);
        chrome.runtime.sendMessage({
          type: "SUPPRESSION_ADDED",
          suppression: sup
        }).catch(() => {
        });
        const tabs = await chrome.tabs.query({});
        for (const tab of tabs) {
          if (tab.id) await updateBadge(tab.id);
        }
      }
      return { added: result.added, reason: result.reason };
    }
    case "REMOVE_SUPPRESSION": {
      await removeSuppression(message.suppressionId);
      return null;
    }
    case "CLEAR_FINDINGS": {
      await clearFindings(message.tabId);
      await updateBadge(message.tabId);
      return null;
    }
    case "GET_SETTINGS": {
      const settings = await getSettings();
      return { type: "GET_SETTINGS_RESPONSE", settings };
    }
    case "UPDATE_SETTINGS": {
      await updateSettings(message.settings);
      return null;
    }
    default:
      return null;
  }
}
async function updateBadge(tabId) {
  const count = await getFindingCount(tabId);
  if (count === 0) {
    await chrome.action.setBadgeText({ text: "", tabId });
  } else {
    await chrome.action.setBadgeText({
      text: count > 99 ? "99+" : String(count),
      tabId
    });
    await chrome.action.setBadgeBackgroundColor({ color: "#E24B4A", tabId });
  }
}
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo) => {
  if (changeInfo.status === "loading") {
    await clearFindings(tabId);
    await updateBadge(tabId);
  }
});
chrome.tabs.onRemoved.addListener(async (tabId) => {
  await clearFindings(tabId);
});
//# sourceMappingURL=background.js.map
