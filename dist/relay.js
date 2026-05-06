const SENTINEL_MSG_KEY = "__sentinel_finding__";
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.type === "FINDING_DETECTED") {
    window.postMessage(
      { [SENTINEL_MSG_KEY]: true, finding: message.finding },
      window.location.origin || "*"
    );
  }
  sendResponse(null);
});
//# sourceMappingURL=relay.js.map
