# Accidental Secret Sentinel

A Chrome extension that detects accidentally exposed API keys, tokens, and secrets in real time — right in your browser. Zero configuration required.

![Chrome Extension](https://img.shields.io/badge/Chrome-Extension-4285F4?logo=google-chrome&logoColor=white)
![Manifest V3](https://img.shields.io/badge/Manifest-V3-brightgreen)
![License](https://img.shields.io/badge/license-MIT-blue)

---

## What it does

Sentinel watches your browser traffic in real time and alerts you when API keys, tokens, or secrets appear where they shouldn't — in network requests, JavaScript bundles, HTML source, or response bodies.

Built for developers who want to catch credential leaks before they become incidents.

## What it detects

- AWS, GCP, Azure credentials
- GitHub personal access tokens (classic and fine-grained)
- Stripe, Twilio, SendGrid keys
- OpenAI, Anthropic API keys
- Slack tokens and webhook URLs
- JWTs and private key PEM headers
- npm access tokens, Shopify keys, Mailgun keys
- Generic high-entropy secret assignments
- **200+ patterns total**

## How it works

All scanning happens locally in your browser — nothing leaves your machine. No servers, no analytics, no telemetry.

```
Page request/response
       │
       ▼
Content script (MAIN world)
  → Patches window.fetch + XMLHttpRequest
  → Scans HTML source and JS bundles
  → Posts findings via window.postMessage
       │
       ▼
Coordinator (ISOLATED world)
  → Receives findings
  → Forwards to service worker via chrome.runtime
       │
       ▼
Service worker
  → Deduplicates, checks suppressions
  → Updates badge count
  → Broadcasts back to coordinator → toast notification
```

## Features

- 🔴 **Real-time toast notifications** when a secret is found
- 🔢 **Badge counter** showing finding count per tab
- 🔇 **Suppress by value, domain, or pattern type** — no more alert fatigue
- 🔍 **DevTools panel** for deep inspection and filtering
- 📤 **Export findings as JSON** for incident reports
- 🌐 **Domain allowlist** to skip trusted internal tools
- ⌨️ **Keyboard accessible** — full keyboard navigation in popup
- 🔒 **100% local** — no data leaves your browser

## Installation

### From Chrome Web Store
*(Link coming soon)*

### From source

```bash
git clone https://github.com/Oghenetega16/accidental-secret-sentinel.git
cd accidental-secret-sentinel
npm install
npm run build
```

Then:
1. Open `chrome://extensions`
2. Enable **Developer mode**
3. Click **Load unpacked**
4. Select the project folder

## Development

```bash
npm run dev        # Watch mode — rebuilds on file changes
npm run typecheck  # TypeScript type checking
npm run test       # Run unit tests
npm run build      # Production build
```

### Project structure

```
src/
├── background/
│   ├── service-worker.ts   # MV3 background — storage, badge, message routing
│   └── storage.ts          # chrome.storage helpers with suppression logic
├── content/
│   ├── content.ts          # MAIN world entry — fetch/XHR patch, DOM scan
│   ├── relay.ts            # ISOLATED world coordinator — chrome.runtime bridge
│   ├── fetch-intercept.ts  # window.fetch + XHR monkey-patch
│   ├── dom-scanner.ts      # HTML + JS bundle scanner via MutationObserver
│   └── toast.ts            # In-page toast notification
├── engine/
│   ├── scanner.ts          # Core scan function — string → Finding[]
│   ├── patterns.ts         # 200+ compiled RegExp patterns
│   └── entropy.ts          # Shannon entropy scorer
├── popup/
│   └── popup.ts            # Popup UI — findings list, suppress, export
├── devtools/
│   ├── panel.ts            # DevTools panel — findings table, detail pane
│   └── devtools-init.ts    # Panel registration (external script, no inline JS)
├── options/
│   └── options.ts          # Settings page — suppressions, domain allowlist
└── shared/
    ├── types.ts             # Shared TypeScript interfaces
    ├── messages.ts          # IPC message constants and factories
    └── allowlist.ts         # Suppression matching logic
tests/
├── entropy.test.ts
├── patterns.test.ts         # Known-bad corpus + false positive tests
├── scanner.test.ts
├── storage.test.ts
└── e2e/
    └── smoke.test.ts
```

## Architecture notes

### Why two content scripts?

Chrome's MAIN world content scripts run in the page's own JavaScript context, which means `chrome.runtime` is **not available**. Only MAIN world can patch `window.fetch` and `window.XMLHttpRequest`. The solution is a two-script setup:

| Script | World | Responsibility |
|--------|-------|----------------|
| `content.js` | MAIN | Patches fetch/XHR, scans DOM, shows toast |
| `relay.js` | ISOLATED | Bridges MAIN world ↔ service worker via `window.postMessage` |

### Suppression storage

Suppressions are stored in `chrome.storage.sync` (synced across Chrome profiles). Findings are stored in `chrome.storage.local` (session-only, cleared on navigation).

## Privacy

All scanning is done locally. No data is transmitted to any server. See [privacy-policy.html](./privacy-policy.html) for full details.

## License

MIT