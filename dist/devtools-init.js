chrome.devtools.panels.create(
  "Sentinel",
  // Panel tab label
  "icons/icon16.png",
  // Panel tab icon
  "panel.html",
  // Panel UI page
  function(panel) {
    panel.onShown.addListener(function(panelWindow) {
      if (panelWindow.__sentinelOnShown) {
        panelWindow.__sentinelOnShown();
      }
    });
    panel.onHidden.addListener(function() {
    });
  }
);
//# sourceMappingURL=devtools-init.js.map
