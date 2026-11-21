# 24. Web app: stack, keys, and screens

Status: accepted (not implemented yet)

## Context
`apps/web` has no framework. The UI is designed (50 boards). Keys must live only in browser memory.

## Decision
- **Stack.** Vite + Preact + TypeScript, `wouter` for routing, plain CSS with the design tokens (no CSS framework), built to `apps/web/dist` and served by the Worker (ADR 9). Tests: Vitest for logic, plus a browser smoke test with Playwright against `wrangler dev`.
- **Crypto.** Only `@cfs/core` in a main-thread module. The unlocked private key lives in a module-scope variable, never in storage. Lock or sign-out drops it; auto-lock after 15 minutes idle (warning at 14).
- **Session.** The browser relies on the Access cookie; the Worker takes the JWT from `Cf-Access-Jwt-Assertion`. Sign out goes to `/cdn-cgi/access/logout` and drops keys.
- **Language.** English default with ID toggle: a `t(en, id)` helper like the design's `d()`; choice kept in `localStorage`. Every new string needs both.
- **Titles.** Page title, breadcrumb and `<title>` follow the rules in DESIGN.md.
- **Security headers** set by the Worker for assets: strict CSP (`default-src 'self'`, no inline scripts, `connect-src 'self'`), `Referrer-Policy: no-referrer`, `X-Content-Type-Options`, `frame-ancestors 'none'`. Values are shown only on "Show" and hidden again after 30 seconds; copy clears the clipboard after 30 seconds where the browser allows.
- **Screens** map one to one to the 50 boards. Build order: sign-in/setup/unlock, secrets (list, detail, edit, JSON, import, versions, history), groups, permissions, apps, activity, requests, agent rules, alerts, devices and CLI authorize, settings, recovery, offboarding, backup, quota.
- **Accessibility.** Keyboard operable, labelled controls, contrast checked against the tokens, no information by colour alone.

## Consequences
Source of truth for visuals stays `design/project`. The web app is built last (ADR order) because it depends on every API above.
