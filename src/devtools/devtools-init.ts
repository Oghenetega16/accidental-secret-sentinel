/**
 * devtools-init.ts
 *
 * Registers the Sentinel panel inside Chrome DevTools.
 * Must be an external script — MV3 CSP forbids inline scripts
 * in extension pages (devtools.html, popup.html, etc.)
 */
chrome.devtools.panels.create(
  'Sentinel',         // Panel tab label
  'icons/icon16.png', // Panel tab icon
  'panel.html',       // Panel UI page
  function (panel) {
    panel.onShown.addListener(function (panelWindow: Window & { __sentinelOnShown?: () => void }) {
      if (panelWindow.__sentinelOnShown) {
        panelWindow.__sentinelOnShown();
      }
    });

    panel.onHidden.addListener(function () {
      // Reserved for future cleanup
    });
  }
);