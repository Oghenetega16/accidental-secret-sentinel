# Chrome Web Store — Submission Checklist

## Before you submit

### Build & typecheck
- [ ] `npm run typecheck` passes with zero errors
- [ ] `npm run build` completes cleanly
- [ ] Extension loads in Chrome via `chrome://extensions` (developer mode)
- [ ] Extension loads from the **dist/** folder, not source

### Manual smoke test (use `test-page/index.html`)
- [ ] HTML source scan fires toast on page load (AWS key in comment)
- [ ] Inline script scan fires toast (OpenAI key in `<script>` tag)
- [ ] Fetch request header scan fires (click "Leak in request header")
- [ ] Fetch request body scan fires (click "Leak in request body")
- [ ] XHR body scan fires (click "Leak in XHR body")
- [ ] Dynamic script injection scan fires (click "Inject script with leaked key")
- [ ] Clean requests do NOT trigger (Surface 5 buttons — all should be silent)
- [ ] Badge count increments correctly per finding
- [ ] Popup shows findings with correct severity, source, and redacted value
- [ ] Suppress by value → finding disappears immediately from popup
- [ ] Suppress by domain → domain added to settings, findings purged
- [ ] Suppress by pattern → all findings of that type purged
- [ ] Export JSON → valid JSON file downloads, no `rawValue` field present
- [ ] Settings page opens from popup footer
- [ ] Settings page shows suppressions, allows removal
- [ ] Domain allowlist can be added and removed
- [ ] Global toggle disables scanning — banner shows in popup, no new findings
- [ ] DevTools panel opens (F12 → Sentinel tab)
- [ ] DevTools panel shows findings, filter chips work, detail pane shows on click

### Accessibility
- [ ] All popup interactive elements reachable via Tab key
- [ ] Finding cards expand/collapse via Enter and Space
- [ ] Suppress buttons reachable via Tab within expanded card
- [ ] Toggle switch operates via keyboard
- [ ] No Lighthouse accessibility score below 90

### Icons (required by Store)
- [ ] `icons/icon16.png`  — 16×16px
- [ ] `icons/icon32.png`  — 32×32px
- [ ] `icons/icon48.png`  — 48×48px (used on extensions page)
- [ ] `icons/icon128.png` — 128×128px (used in Store listing)
- All icons must be PNG, transparent background recommended

### Store listing assets
- [ ] At least 1 screenshot (1280×800 or 640×400)
  - Screenshot 1: Popup with findings visible
  - Screenshot 2: DevTools panel with findings table
  - Screenshot 3: Options / suppression management page
- [ ] Small promo tile: 440×280px (optional but recommended)
- [ ] Store icon: 128×128px (same as icon128.png)

### Store listing copy
**Name:** Accidental Secret Sentinel

**Short description (132 chars max):**
Detects accidentally exposed API keys, tokens, and secrets in real time — right in your browser. Zero config.

**Detailed description:**
Accidental Secret Sentinel watches your browser traffic in real time and alerts you when API keys, tokens, or secrets appear where they shouldn't — in network requests, JavaScript bundles, HTML source, or response bodies.

Built for developers who want to catch credential leaks before they become incidents.

**What it detects:**
• AWS, GCP, Azure credentials
• GitHub personal access tokens
• Stripe, Twilio, SendGrid keys
• OpenAI, Anthropic API keys
• Slack tokens and webhook URLs
• JWTs and private key PEM headers
• npm access tokens, Shopify keys
• 200+ patterns total

**How it works:**
All scanning happens locally in your browser — nothing leaves your machine. No servers, no analytics, no telemetry.

**Key features:**
• Real-time toast notifications when a secret is found
• Badge counter shows finding count per tab
• Suppress by value, domain, or pattern type
• DevTools panel for deep inspection and filtering
• Export findings as JSON for incident reports
• Domain allowlist to skip trusted internal tools

**Privacy:** 100% local. See the full privacy policy at [your GitHub Pages URL].

### Pre-submission
- [ ] Developer account created at https://chrome.google.com/webstore/devconsole ($5 one-time fee)
- [ ] Privacy policy hosted publicly (upload `privacy-policy.html` to GitHub Pages or Netlify)
- [ ] Privacy policy URL added to Store listing
- [ ] Category set to: **Developer Tools**
- [ ] Language set to: English
- [ ] Single purpose description written (Store requires this for `<all_urls>` permission):
  > "This extension scans browser traffic and page content for accidentally exposed API keys and secrets, alerting the developer in real time."

### Package for submission
```bash
# Zip only what the Store needs — exclude source, tests, node_modules
zip -r sentinel-v1.0.0.zip \
  manifest.json \
  popup.html panel.html devtools.html options.html \
  privacy-policy.html \
  dist/ \
  icons/
```

**Do NOT include:** `src/`, `tests/`, `node_modules/`, `*.map` files (optional — source maps help debugging but add size), `test-page/`

## After submission
- Review typically takes 1–3 business days
- If rejected for permission justification, respond explaining `<all_urls>` is needed to scan requests across all developer tools and staging environments
- Once approved, tag the release: `git tag v1.0.0 && git push --tags`