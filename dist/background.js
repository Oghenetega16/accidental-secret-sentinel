const DEFAULT_SYNC = {
  suppressions: [],
  customPatterns: [],
  disabledDomains: [],
  enabled: true
};
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
      return { type: "GET_TAB_ID_RESPONSE", tabId: ((_a = sender.tab) == null ? void 0 : _a.id) ?? -1 };
    }
    case "FINDING_DETECTED": {
      const finding = message.finding;
      const settings = await getSettings();
      if (!settings.enabled) return null;
      if (isSuppressed(finding, settings)) return null;
      await addFinding(finding);
      await updateBadge(finding.tabId);
      chrome.runtime.sendMessage({
        type: "FINDING_DETECTED",
        finding
      }).catch(() => {
      });
      return null;
    }
    case "GET_FINDINGS": {
      const findings = await getFindings(message.tabId);
      return { type: "GET_FINDINGS_RESPONSE", findings };
    }
    case "SUPPRESS": {
      const settings = await getSettings();
      const suppression = {
        ...message.suppression,
        id: crypto.randomUUID(),
        createdAt: Date.now()
      };
      await updateSettings({
        suppressions: [...settings.suppressions, suppression]
      });
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
    await chrome.action.setBadgeBackgroundColor({
      color: count > 0 ? "#E24B4A" : "#888780",
      tabId
    });
  }
}
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo) => {
  if (changeInfo.status === "loading" && changeInfo.url) {
    await clearFindings(tabId);
    await updateBadge(tabId);
  }
});
chrome.tabs.onRemoved.addListener(async (tabId) => {
  await clearFindings(tabId);
});
//# sourceMappingURL=background.js.map
