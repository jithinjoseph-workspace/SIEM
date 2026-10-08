# SECURITY NOTES (frontend)

This file documents remaining security items that require backend or ops changes.

## 1) Move JWTs out of localStorage
- Problem: UI stores JWT in `localStorage` (`src/services/auth/auth.ts`). XSS can expose tokens.
- Required backend change: Return auth token via `Set-Cookie` with `HttpOnly; Secure; SameSite=Strict` instead of returning raw token in JSON. Provide a refresh endpoint and short-lived JWTs.

## 2) WebSocket authentication
- Problem: WS currently sends token from `localStorage` on open (`src/services/websocket/websocket.ts`). If cookies are used, WS auth can rely on cookies and server session.
- Required backend change: Accept cookie-based session for WS or implement an ephemeral WS token endpoint that returns a short-lived token tied to the authenticated session.

## 3) SSRF / proxy validations
- Problem: UI constructs proxied favicon URLs (e.g. `/favicon-proxy?url=http://...`). Backend that fetches external URLs must validate and whitelist hostnames, block internal IP ranges, and limit redirects/timeouts.

## 4) Dependency scanning and patching
- Action: Run `npm audit` / Snyk on `ndr-ui/` and review advisories. Apply fixes via `npm audit fix` where safe and open PRs for manual changes.

## 5) SRI verification for driver.js
- The UI adds `integrity` attributes for driver.js and its CSS. Verify the SRI locally using:

```bash
curl -s https://cdn.jsdelivr.net/npm/driver.js@1.0.1/dist/driver.js.iife.js | openssl dgst -sha384 -binary | openssl base64 -A
curl -s https://cdn.jsdelivr.net/npm/driver.js@1.0.1/dist/driver.css | openssl dgst -sha384 -binary | openssl base64 -A
```

Update the `integrity` values in `src/services/tour/tour.service.ts` if they differ.

---

If you want, I can open a PR with these notes and the frontend changes, and (optionally) run `npm audit` and paste the results here for review.
