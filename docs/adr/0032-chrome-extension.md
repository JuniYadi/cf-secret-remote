# 32. Chrome extension

Status: accepted (not implemented yet)

## Decision
- **Scope.** Manifest V3, `apps/extension`, built with the same toolchain as the web app. Chrome first (Edge and Brave work with the same build). Firefox later; no Safari or mobile in v1.
- **Login.** The device-code flow of ADR 11 with `device_type: extension`. The extension shows a code, the person approves it in the web app (behind Access), and receives a `cfs_` token valid 8 hours. The Worker host is entered at setup and requested through `optional_host_permissions`. The API sends no CORS headers (ADR 27) and none are needed because the extension has host permission.
- **Keys.** The unlocked key and token live in `chrome.storage.session` and are gone when the browser closes. Auto-lock after 1 hour by default, like `cfs unlock`. Nothing secret is stored in `storage.local`; only the encrypted Login list (for fast start) and the host.
- **Permissions.** `activeTab`, `scripting`, `storage`, and optional host access to the Worker. **No** `<all_urls>` and no always-on content script. The content script is injected only when the person clicks the icon, uses the shortcut, or picks the context menu.
- **Autofill rules.**
  - Match the **exact origin** (scheme, host, port). `staging.shop.com` does not match `shop.com`; `localhost:3000` does not match `localhost:5173`. No parent-domain matching in v1. A per-item wildcard may be added later as an explicit, warned option.
  - HTTPS required, except `localhost` and `127.0.0.1`.
  - Fill only after a user action. No fill on page load and no auto-submit.
  - No fill into cross-origin iframes or hidden fields.
  - The secret is never put in a DOM attribute, and every fill is audited (ADR 29).
- **Sync.** One `GET /api/v1/logins` with `ETag` on unlock and on manual refresh. No polling.
- **Release.** See ADR 34 for build and signing. The Store listing links to the release hash.

## Consequences
New app and CI job; a content-script test page for origin matching, iframes, and hidden fields; a Chrome Web Store developer account (one-time fee) under a publisher name the owner chooses.
