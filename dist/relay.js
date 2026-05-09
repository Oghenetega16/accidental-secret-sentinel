const TO_BG = "__sentinel_to_bg__";
const TO_PAGE = "__sentinel_to_page__";
window.addEventListener("message", (event) => {
  if (event.source !== window) return;
  const data = event.data;
  if (!data || data[TO_BG] !== true) return;
  chrome.runtime.sendMessage(data.message, () => {
    void chrome.runtime.lastError;
  });
});
chrome.runtime.onMessage.addListener((message) => {
  if (message.type === "FINDING_DETECTED") {
    window.postMessage({ [TO_PAGE]: true, finding: message.finding }, "*");
  }
});
window.addEventListener("message", (event) => {
  if (event.source !== window) return;
  const data = event.data;
  if (!data) return;
  if (data.__sentinel_get_settings__) {
    chrome.runtime.sendMessage({ type: "GET_SETTINGS" }, (response) => {
      window.postMessage({
        __sentinel_settings__: true,
        settings: (response == null ? void 0 : response.settings) ?? { enabled: true, disabledDomains: [] }
      }, "*");
    });
  }
});
//# sourceMappingURL=relay.js.map
