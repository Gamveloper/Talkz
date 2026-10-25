# Talkz Cloud — Render deployment

Talkz Cloud is a real server-backed chat MVP with:
- User registration and sign-in (passwords hashed with bcrypt)
- Email verification and password reset by email, with optional TOTP two-factor auth (Phase 2)
- Uploads in Postgres, or in an S3-compatible bucket (Cloudflare R2 / AWS S3) with signed-URL downloads (Phase 2)
- PostgreSQL persistence for users, servers, channels, memberships, and messages
- Session-based authentication with HTTP-only cookies
- Real-time channel message updates through Socket.IO
- Membership checks on server/channel/message routes
- Rate limits on authentication and message sending
- Render Blueprint configuration for a web service and PostgreSQL database

## Deploy to Render

1. Create a GitHub repository and upload the contents of this folder to its root.
2. In Render, choose **New + → Blueprint** and connect that repository.
3. Render reads `render.yaml` and proposes the `talkz-cloud` web service plus `talkz-db` PostgreSQL database. Review the plan and deploy.
4. Wait for the web service to finish deploying. Open its `onrender.com` URL.
5. Create an account in Talkz and test with two separate browsers/accounts.

The Blueprint generates `SESSION_SECRET` and wires the database connection string into the service. Do not put secrets in GitHub or browser code.

## Local development

Requires Node.js 20+ and PostgreSQL.

1. Create a database named `talkz`.
2. Copy `.env.example` to `.env` and set `DATABASE_URL` and a long random `SESSION_SECRET`.
3. Install dependencies with `npm install`.
4. Run `npm start`, then visit `http://localhost:3000`. (The server loads `.env` automatically.)

The app creates its required tables on startup. `connect-pg-simple` also creates its session table.

## Current scope / important limitations

Phase 1 (Part 1 fixes) is implemented — see `ARCHITECTURE.md` for the full model:

- CSRF protection (`X-Requested-With: fetch` required on all state-changing API calls), per-IP **and** per-user rate limits, `trust proxy` on in production.
- Hidden channels via per-channel `view_role`, with live socket-room eviction when access is lost, and `voice:participants` sent only to members who can view the channel.
- File uploads (8 MB, MIME allowlist) with strict download access control and hourly orphan cleanup.
- Webhooks with bot profiles (hidden from DM lookup; deleting a webhook keeps its messages, re-attributed to "Deleted Bot").
- Compound `(created_at, id)` cursor pagination, channel-name dedupe + unique index at startup.
- Account basics: change username, delete account (owned servers transfer to the highest-ranked longest-standing member, or are deleted if empty), log out of all devices.
- Voice: TURN via `TURN_URL`/`TURN_USERNAME`/`TURN_CREDENTIAL` (+ `/api/ice`), speaking indicator, shared mute/deafen state, mic device-loss recovery, reconnect resync.
- Optional email is collected at registration and used for verification/password-reset mail; threads, unread tracking, custom roles, moderation tooling and presence statuses are **later phases** (see ARCHITECTURE.md and the phase plan).
- Free Render services/databases can have limits or sleep/expiry policies that change over time. Check the current Render dashboard/pricing before relying on a free deployment.
- PostgreSQL SSL uses `rejectUnauthorized: false` in production for compatibility with hosted database certificates. For stricter deployments, configure certificate verification according to your database provider.

## Environment variables

Required: `DATABASE_URL`, `SESSION_SECRET` (production).
Set by the Blueprint: `NODE_ENV=production`, `TRUST_PROXY=true`, `STUN_URL`.
Optional (sync: false secrets): `TURN_URL`, `TURN_USERNAME`, `TURN_CREDENTIAL` — when all three are set, `/api/ice` includes the TURN server; otherwise voice falls back to STUN only.
Tuning: `AUTH_RATE_LIMIT` (default 30 per 15 min), `ACCOUNT_RATE_LIMIT` (default 60 per hour, verification/reset token endpoints).

### Email — verification & password reset (Phase 2)

Accounts work fully without email. To actually SEND mail, set `MAIL_FROM` plus ONE provider:

- **Resend:** `RESEND_API_KEY` (sent via the Resend HTTPS API — no extra setup).
- **SMTP:** `SMTP_HOST`, `SMTP_PORT` (default 587; 465 implies TLS, or set `SMTP_SECURE=true`), `SMTP_USER`, `SMTP_PASS` (via nodemailer).

`APP_BASE_URL` (e.g. `https://your-app.onrender.com`) is used for the links in those emails; when unset, links are built from the request's host. With NO provider configured the app still runs: signup/reset flows report "email isn't configured on this server" and the action link is written to the server log instead — mail is never silently faked.

How it behaves:

- Registering with an email (or changing your email under **Profile → email & security**) sends a verification link, valid 24 hours. Until clicked, the profile shows the address as unverified; a "Resend verification email" button lives in the same settings section.
- **Forgot password** (link on the sign-in form) always answers with the same generic message whether or not the address has an account. Reset links are valid 1 hour, work once, and signing in everywhere else is ended when a reset completes.
- All token links are single-use and only their SHA-256 hash is stored.

### Two-factor authentication (Phase 2)

Optional per user, under **Profile → email & security → Enable 2FA**: confirm your password, then the app shows a one-time secret as text — a manual key plus the full `otpauth://` URI to paste/type into any authenticator app (no QR dependency). Enter a code from the app to switch 2FA on; you'll get **10 recovery codes, shown once** — save them. Signing in then needs your password AND a 6-digit code (or one recovery code; each works once). Disabling 2FA needs your password plus a valid code. Codes are standard TOTP (RFC 6238), so any authenticator app works.

### Object storage for uploads (Phase 2)

Set all four to store new uploads in an S3-compatible bucket instead of Postgres: `S3_BUCKET`, `S3_ACCESS_KEY_ID`, `S3_SECRET_ACCESS_KEY`, plus `S3_ENDPOINT` for non-AWS stores (Cloudflare R2: `https://<accountid>.r2.cloudflarestorage.com`; `S3_REGION` defaults to `auto`). The bucket must NOT be public: downloads are checked against Talkz permissions first, then the browser is redirected to a signed URL that expires after 5 minutes. Files uploaded earlier stay readable in both modes (each row remembers its backend). The hourly cleanup sweep also deletes bucket objects — both when an orphan row is removed and when an object lost its row some other way (`S3_SWEEP_MIN_AGE_MS` controls how old an unreferenced object must be, default 1 hour). Image uploads have their metadata stripped at upload (JPEG metadata segments and PNG text/EXIF chunks) in both storage modes; GIF/WebP are stored as-is.

## Tests

Requires a **separate** test database (it is wiped):

```
TEST_DATABASE_URL=postgres://user:pass@localhost:5432/talkz_test npm test
```

The suites: `tests/api.test.js` (Phase 1 behaviour), `tests/accounts.test.js`
(Phase 2 accounts: verification, reset, mailer, 2FA incl. the RFC 6238 TOTP
vectors) and `tests/storage.test.js` (Phase 2 storage against a local stub
S3 server, plus the Postgres fallback). The Phase 2 suites each use their
own sibling database (`talkz_test_accounts`, `talkz_test_storage`) so all
files can run in parallel; they create those databases if missing.

## Project files

- `server.js` — Express API, PostgreSQL schema setup, sessions, Socket.IO
- `lib/mailer.js` — pluggable email (Resend API or SMTP via nodemailer; logs links when unconfigured)
- `lib/totp.js` — TOTP two-factor codes (RFC 6238, Node crypto only)
- `lib/storage.js` — S3-compatible object storage + signed URLs (AWS SDK v3)
- `lib/exif.js` — JPEG/PNG metadata stripping at upload
- `public/index.html` — Talkz login and app layout
- `public/style.css` — Talkz UI styling
- `public/app.js` — client application
- `render.yaml` — Render Blueprint
