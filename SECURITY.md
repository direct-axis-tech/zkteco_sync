# Security

ZKTeco Sync moved from a LAN appliance to a single origin reachable from the
public internet, terminated by Apache in front of it. This document is the
threat model an operator needs before deploying it that way: what is
exposed, what protects it, what is deliberately *not* protected, and what to
do if something goes wrong.

If you are setting up the reverse proxy, read
[`deploy/apache/zkteco-sync.conf.example`](deploy/apache/zkteco-sync.conf.example)
alongside this file — it documents the `X-Forwarded-For`/`TRUSTED_PROXIES`
relationship in detail, which this document only summarizes.

## What is exposed

Everything is on one origin, behind Apache:

- The admin web UI and its JSON API (`/devices`, `/employees`, `/attendance`,
  `/users`, `/audit`, `/hrm-sync`, `/auth`, …) — cookie-session authenticated.
- The ADMS device-push endpoints (`/iclock/cdata`, `/iclock/ping`,
  `/iclock/getrequest`, `/iclock/devicecmd`) — **unauthenticated by design**,
  because device firmware cannot present a credential on these routes. Trust
  here comes from the serial-number allowlist and, optionally, a per-device
  source-IP allowlist (below).

Nothing else should be reachable. The app itself binds to `127.0.0.1` only
(`install.py`'s default, and `run.py`'s default if `APP_HOST` is unset) —
Apache is the only process meant to hold a public socket. `run.py` also
never turns on uvicorn's own `proxy_headers` handling; see
[Why `proxy_headers=False` stays off](#why-proxy_headersfalse-stays-off)
below.

## Admin authentication

- Accounts are DB-backed (`users` table), passwords hashed with Argon2id.
  There is no shared static credential.
- `API_USERNAME`/`API_PASSWORD` in `.env` are **first-boot bootstrap only**:
  they seed exactly one admin account the moment the `users` table is empty,
  with `must_change_password` forced on. Every boot after that ignores both
  values completely — they never resurrect a deleted account and never
  overwrite a password an operator has since changed. Delete them from
  `.env` once you've logged in and changed the password.
- Sessions are an opaque, server-generated token in an `HttpOnly`,
  `SameSite=Strict` cookie (`Secure` too, whenever `COOKIE_SECURE` is on,
  which is the production default). The token itself is never stored — only
  its SHA-256 hash — so a stolen database row cannot be replayed as a
  session. Sessions expire after `SESSION_IDLE_MINUTES` of inactivity or
  `SESSION_ABSOLUTE_HOURS` regardless of activity, whichever comes first.
- State-changing requests (`POST`/`PUT`/`PATCH`/`DELETE`) require an
  `X-CSRF-Token` header matching the session's own CSRF token — the classic
  double-submit pattern, which a cross-site request cannot forge because it
  cannot read the cookie to copy the token out of it.
- Repeated failed logins lock the account for `LOGIN_LOCKOUT_MINUTES` after
  `LOGIN_MAX_ATTEMPTS`. The failure message is generic either way ("Invalid
  username or password") so a prober can't distinguish "wrong password" from
  "account doesn't exist" — though a locked-out account does surface a
  distinct 423 with a wait time, which is a deliberate trade: an operator
  needs to *see* why they're locked out, at the cost of five guesses telling
  an attacker a username is real. Roles are `admin` and `viewer`; only admins
  reach privileged endpoints (device control, user management, HRM
  configuration, template push).
- No credential is ever in `localStorage` or `sessionStorage` — an XSS bug
  can't lift a bearer token that was never stored client-side to begin with.

## Device onboarding: serial allowlist and pairing mode

A device is not trusted just because it knows the server's address. Every
`/iclock/*` request is checked in this order:

1. **Known serial number.** An unrecognized serial is refused outright —
   *unless* an admin has opened a time-boxed pairing window (Devices → open
   pairing, default `ADMS_PAIRING_MINUTES` long), in which case the unknown
   serial is filed into a `pending` queue instead of being dropped.
2. **Approved status.** A `pending` or `rejected` device is refused even
   though its serial is known. An admin has to explicitly approve it from
   the queue.
3. **Optional per-device source-IP allowlist** (below), only if the device
   has it turned on.

Refusals return a deliberately bland `401 Unauthorized` with body
`Unauthorized` and no further detail — a prober gets nothing back that tells
them whether a serial is unknown, pending, rejected, or IP-blocked. The real
reason is logged server-side (serial + resolved source IP) and written to
the audit trail as an `adms_refused` row attributable to that serial and IP.

**Onboard a new device:** open the pairing window in Devices, power on (or
reboot) the device so it re-registers, approve it from the pending queue
once it appears, then close the window. Leaving pairing open indefinitely
defeats the point of the allowlist — anyone who can reach `/iclock/*` during
that window can plant a serial into the pending queue, though it still needs
an admin's explicit approval before it can push anything.

## Per-device IP allowlisting

Each approved device can optionally be pinned to a CIDR allowlist
(`ip_check_enabled` + `allowed_cidrs`), checked against the resolved client
IP — never the raw socket peer, which behind Apache is always `127.0.0.1`.
See `deploy/apache/zkteco-sync.conf.example` for exactly how that resolution
depends on `TRUSTED_PROXIES` matching Apache's real source address; if that
relationship is wrong, this allowlist either refuses every device (fails
closed) or can be walked through with a forged header (fails open) — the
symptom won't look like an IP-allowlist bug, so check that relationship
first.

It's off by default because some sites have dynamic IPs and would lock
themselves out. **Recommendation: turn it on for every site with a static
IP** — it is the only control that closes the residual risk below.

## Accepted residual risk: attendance forgery for a known serial

**Rate limiting on `/iclock/*` is deliberately not implemented.** This was
an explicit operator decision (roster decision D5), not an oversight — the
endpoint has to accept a burst of legitimate traffic (a device catching up
after being offline, several devices in sync near shift-change) and a global
or per-serial rate limit risked dropping real attendance data for a benefit
that a smarter attacker route around anyway.

The consequence: **the serial allowlist stops device *registration*, not
device *forgery*.** A serial number is not a secret — it's stamped on the
device and visible to anyone who can see it, and it travels in plaintext on
every push. Anyone who learns an approved serial (a compromised device on
the same LAN, a leaked device inventory, a `?SN=` query parameter left in a
proxy log) can forge unlimited attendance pushes for that serial from
anywhere, indistinguishable from the real device, for as long as no other
control stops them.

**The per-device CIDR allowlist above is the only control that closes this
gap.** With it enabled and correctly matched to the device's real egress IP,
a forged push from anywhere else is refused regardless of how correct the
serial number is. Enable it on every device at a site with a static IP; for
sites without one, there is currently no equivalent protection and this risk
is accepted as-is.

## The comm key (device SDK credential)

Separately from ADMS push, the server can *pull* from a device over the SDK
protocol (TCP 4370) — employee sync, attendance backfill, template pull,
door unlock, clock set. Authentication on that channel is a single
communication key configured on the device's keypad and mirrored on its
`Device` row here (`comm_key`).

- The key is **write-only** through the API and the UI: it can be set or
  cleared, but is never returned in a response body, never logged, and never
  appears in an error detail (`grep -rn "comm_key" app/` shows no path that
  echoes the value — the response schema simply has no field for it; only
  `comm_key_set: true|false` is exposed).
- A wrong key on a pull surfaces as a distinct error naming the comm key as
  the likely cause, rather than a generic connection failure, so an operator
  doesn't chase a network fault that isn't there.
- This key is the *only* authentication on TCP 4370. See
  [Known-imperfect realities](#known-imperfect-realities) below — SDK pull
  cannot traverse NAT — for why that port should never be exposed to the
  internet directly.

## Security headers, hosts, and body limits

- `Content-Security-Policy: default-src 'self'; object-src 'none';
  base-uri 'self'; frame-ancestors 'none'` on every browser-facing response —
  no `unsafe-inline`, no `unsafe-eval`. `X-Content-Type-Options: nosniff`,
  `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, and a
  `Permissions-Policy` disabling camera/mic/geolocation are also always set.
  `Strict-Transport-Security` is added only when `APP_ENV=production`. None
  of this is sent on `/iclock/*` — devices aren't browsers and don't benefit
  from it.
- `TrustedHostMiddleware` rejects any request whose `Host` header isn't in
  `ALLOWED_HOSTS` before it reaches a route.
- Request bodies over `MAX_REQUEST_BYTES` (default ~2 MiB) get a `413`,
  checked both from `Content-Length` up front and by counting bytes as a
  streamed body arrives, so a client that lies about or omits
  `Content-Length` is still caught.
- The interactive API docs (`/docs`, `/redoc`, `/openapi.json`) are off
  unless `ENABLE_DOCS=true` — leave them off on a public deployment; they
  hand out a complete map of every endpoint.
- There is no CORS middleware at all. The SPA is always same-origin (FastAPI
  serves `frontend/dist` directly in production; in development the browser
  only ever talks to the Vite dev server, which proxies `/api` to the
  backend server-to-server), and the session cookie is `SameSite=Strict`
  regardless, so cross-origin requests can't carry it even if CORS allowed
  them through. Adding a CORS allowlist here would only create a path for
  some other origin to be permitted by mistake, for no offsetting benefit.

## Web UI and REST API share the same paths

`/devices`, `/employees`, `/attendance` and `/users` are simultaneously
client-side routes of the SPA and real API endpoints. Which one you get is
decided by `SpaNavigationMiddleware` (`app/middleware.py`), on intent rather
than on path:

- **Default is the page.** A `GET`/`HEAD` that looks like a top-level browser
  navigation (`Sec-Fetch-Mode: navigate`, or — for browsers old enough not to
  send `Sec-Fetch-*` — an `Accept` header explicitly preferring `text/html`
  over `application/json`) is answered with the SPA shell, and React Router
  resolves the path. That is what makes a hard reload, a bookmark or a pasted
  deep link work on every route.
- **With the XHR flag you get JSON.** Every call the app makes carries
  `X-Requested-With: XMLHttpRequest`, and any request carrying it is passed
  straight to the API.
- **Non-browser clients are untouched.** `curl`, cron scripts and any other
  consumer of the REST API send `Accept: */*` (or no `Accept` at all) and no
  `Sec-Fetch-*`, none of which reads as a navigation, so they keep getting
  JSON exactly as before. An explicit `Accept: application/json` always wins,
  even on a request that otherwise looks like a navigation.
- **`/iclock/*` is exempt by path, before any header is examined.** Devices
  are embedded ADMS clients that send no flag and no `Accept` worth the name;
  handing one of them an HTML page would stop attendance collection silently.
  Nothing about the ADMS wire protocol changes.
- Static assets are excluded too (`/assets/*` and anything with a file
  extension), so `StaticFiles` still serves the real files out of
  `frontend/dist`.

The shell is served from inside `SecurityHeadersMiddleware`, so it carries
the same CSP and other headers as any other document response, and from
inside `TrustedHostMiddleware`, so an unrecognised `Host` is still rejected
before the shell is ever considered.

## HRM integration secret

The HRM push integration's API key (`hrm_integration.secret`) is
write-only through the API: `GET /hrm-sync` returns `secret_set: true|false`,
never the value. Writes work as before — leave the field blank in the
Settings UI to keep the currently stored secret unchanged, or fill it in to
replace it.

## Known-imperfect realities

These are documented deliberately rather than hidden — read them before
relying on behavior they touch.

- **SDK pull cannot traverse NAT from a public server.** `SDK pull`
  (server → device, TCP 4370: employee sync, attendance backfill, template
  pull, door unlock, clock set) is a server-initiated *outbound* connection
  to the device. If a device sits behind NAT at a branch site with no
  inbound path back to it, none of those actions work from a server on the
  public internet — only ADMS push (device → server) reaches it. The
  options are a VPN between the server and the branch site, or accepting
  that branch as push-only. **Do not port-forward 4370 to the internet** to
  work around this: the comm key above is the *only* authentication on that
  port, and exposing it turns every device behind that forward into a
  target for anyone who can guess or brute-force the key.

### Why `proxy_headers=False` stays off

`run.py` deliberately never sets uvicorn's `proxy_headers=True` (or
`forwarded_allow_ips`). It would seem natural to turn it on — uvicorn has
its own `X-Forwarded-For` handling — but it would *rewrite* `scope["client"]`
for any peer in uvicorn's own `forwarded_allow_ips` (which defaults to
`127.0.0.1`, i.e. every request that comes through Apache), before
`app/net.py:client_ip` ever sees the request. That hands `app/net.py` an
already-substituted address and turns the app's own `TRUSTED_PROXIES` check
into a rubber stamp on a second, differently configured trust list uvicorn
owns instead. Exactly one layer must own the "who do we trust to tell us the
real client address" decision, and it is `app/net.py:client_ip` — re-enabling
uvicorn's own handling silently defeats the per-device CIDR allowlist above
without changing anything visible in the UI. **Do not turn this on.**

## Incident response

**Suspected compromised session or account:**
1. As an admin, deactivate the affected user (Users page) or reset their
   password (Users → reset password) — either action revokes their live
   sessions immediately.
2. Rotate `SECRET_KEY` in `.env` and restart the app. This invalidates every
   session token still holding a cookie for this app (they're opaque
   references verified against the DB, not signed with `SECRET_KEY`
   themselves — but rotating it as part of an incident response is still
   good hygiene, since other parts of the app may depend on it going
   forward, and a fresh key rules out any assumption about what may have
   leaked alongside it).
3. Review the audit trail (Settings → Audit, or `GET /audit`) filtered by
   the affected actor and a date range around the incident — every
   privileged action (login, password change, user/device
   create/modify/delete, pairing window changes, door unlock, restart,
   attendance wipe, template push/delete, HRM config change) is attributed
   to an actor and source IP there.

**Suspected forged/compromised device serial:**
1. Reject the device (Devices → reject) — this immediately stops it from
   pushing further, regardless of what its serial claims.
2. Check the audit trail for `adms_refused` and successful push rows
   against that serial to see what has already gone through and from what
   IP.
3. If the site has a static IP and doesn't already have the CIDR allowlist
   on, turn it on once you've re-approved the legitimate device — see
   [Accepted residual risk](#accepted-residual-risk-attendance-forgery-for-a-known-serial)
   above.

**Suspected leaked comm key:**
1. Clear the comm key for the affected device (Devices → device → comm key
   → clear) and set a new one on the device keypad and here to match. Until
   a wrong key can talk to nothing, an attacker who has the old one can
   still open the door, pull data, or wipe attendance on that device over
   TCP 4370 if they can reach it.
2. Confirm TCP 4370 for that device is not, and has never needed to be,
   reachable from the public internet — see
   [Known-imperfect realities](#known-imperfect-realities) above.

**General `.env` hygiene after any incident:** confirm `.env` is still mode
`600` (`ls -l .env`), confirm `API_USERNAME`/`API_PASSWORD` have been
deleted if the first login already happened, and confirm `ALLOWED_HOSTS`
still lists only hostnames you control.
