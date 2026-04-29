chrome.devtools.panels.create(
    'Sentinel',
    'icons/icon16.png',
    'panel.html',
    function (panel) {
        panel.onShown.addListener(function (panelWindow) {
            if (panelWindow.__sentinelOnShown) {
                panelWindow.__sentinelOnShown();
            }
        });
    }
);