# Talkz Cloud — Architecture (Phases 1–2.1)

Single-process Node 20 app: Express 4 REST API + Socket.IO 4 realtime on one HTTP
server, PostgreSQL via `pg` (parameterised queries only), sessions in Postgres
(`express-session` + `connect-pg-simple`), vanilla-JS client in `public/` with no
build step. Deployed on Render (web service + Postgres, free tier).

## Tables

| Table | Purpose / notes |
|---|---|
| `profiles` | Users. `username` unique, `password_hash` (bcrypt), `display_name`, `status_text`, `is_bot` — bot profiles (webhooks, tombstone) are hidden from DM/friend lookup and cannot log in. Phase 2 adds `totp_secret` (base32, only while 2FA is set up/enabled), `totp_enabled`. 2FA state is exposed only on self-scoped responses (`userPrivate`), never on public profiles. Phase 2.1 removed email: fresh installs have no `email`/`email_verified` columns (older databases keep theirs, unused, never dropped). |
| `servers` | `owner_id` → profiles (cascade). |
| `server_members` | PK (server_id, user_id); `role` in owner/admin/moderator/member (Phase 1 keeps the fixed 4-role scheme; bitfield roles are a later phase). |
| `channels` | `kind` text/voice/announcement, `position`, `view_role` — minimum rank that can view the channel. Unique index on (server_id, lower(name)) after automatic dedupe at startup. |
| `messages` | Channel messages; `reply_to` self-FK (SET NULL), `edited_at`. Indexed (channel_id, created_at DESC, id DESC) for cursor pagination. |
| `message_reactions` | PK (message_id, user_id, emoji). |
| `invites` | `code` PK, `max_uses`, `expires_at`, `uses`. |
| `dm_conversations` / `dm_members` / `dm_messages` | 1-to-1 DMs (group DMs are a later phase). dm_messages has the same compound-cursor index. |
| `files` | Uploads: metadata + `data BYTEA` (Postgres storage) or bucket object (`storage` = `postgres`/`s3`, `storage_key` set in S3 mode — Phase 2), `uploader_id`, nullable `message_id` / `dm_message_id`, both ON DELETE CASCADE. Unattached rows older than 1 h are swept every 15 min; in S3 mode the sweep also deletes the bucket object and reconciles objects whose row vanished another way (once older than `S3_SWEEP_MIN_AGE_MS`). |
| `account_tokens` | Removed in Phase 2.1 with the email features: not created on fresh installs; on older databases the table is left in place, unused. |
| `recovery_codes` | Phase 2: TOTP recovery codes — SHA-256 hashes only, `used_at` for single-use. Replaced wholesale when 2FA is enabled; deleted when disabled. |
| `webhooks` | `channel_id`, `bot_user_id` → profiles (SET NULL), `token_hash` (SHA-256; plaintext shown once). |
| `user_sessions` | Managed by connect-pg-simple. |

All schema changes run at startup, idempotently (`IF NOT EXISTS`), without data loss.

## Permission model

- Rank: owner 3 > admin 2 > moderator 1 > member 0. `isMod` = rank ≥ 1.
- Every REST route and socket event re-checks membership server-side.
- `channelAccess(channelId, userId)` is the single choke point: membership **and**
  `RANK[role] >= RANK[channel.view_role]`, else the channel does not exist for you
  (403 on REST, ignored on sockets, omitted from server lists and voice snapshots).
- Role changes and `view_role` changes evict losing sockets from `channel:`/`voice:`
  rooms and tear down their live voice sessions (`voice:removed`).
- Files: downloadable only by the uploader, by members who pass `channelAccess`
  for the attached message's channel, or by members of the DM. Others get 404.
- Kicks require moderator+ and a strictly higher rank than the target. Only the
  owner changes roles. Only owner/admin rename; only the owner deletes a server.
- Bots: webhook ingest is token-authenticated (timing-safe hash comparison), is
  not session/CSRF based, and bot profiles cannot be DM'd or log in.

## REST routes

Auth/account: `POST /api/auth/register|login|logout|logout-all`,
`GET /api/me`, `PATCH /api/me`, `PATCH /api/me/username`, `DELETE /api/me`,
`GET /api/ice` (STUN always; TURN when `TURN_URL/USERNAME/CREDENTIAL` are set),
`GET /api/health`.

Phase 2 accounts: `POST /api/auth/login/2fa` (completes a
sign-in that returned `twoFactorRequired`), `POST /api/me/2fa/setup|enable|disable`,
`POST /api/me/password` (change password, current password required — Phase 2.1).
Login for a 2FA account stores a short-lived `pending2fa` marker in the
session (5 min, max 5 attempts) instead of `userId`. Phase 2.1 removed every
email route (`verify-email`, `resend-verification`, `forgot-password`,
`reset-password` — now JSON 404) and deleted `lib/mailer.js`.

Servers/channels: `GET|POST /api/servers`, `PATCH|DELETE /api/servers/:serverId`,
`POST /api/servers/:serverId/leave`, `GET /api/servers/:serverId/members`,
`PATCH|DELETE /api/servers/:serverId/members/:userId`,
`POST /api/servers/:serverId/channels`, `PATCH|DELETE /api/channels/:channelId`,
`GET /api/servers/:serverId/voice`.

Invites: `POST|GET /api/servers/:serverId/invites`,
`DELETE /api/servers/:serverId/invites/:code`, `POST /api/invites/:code/join`.

Messages: `GET|POST /api/channels/:channelId/messages` (cursor pagination:
`?cursor=` returns `nextCursor`; legacy `?before=` still accepted),
`PATCH|DELETE /api/messages/:messageId`, `PUT /api/messages/:messageId/reactions`.

Files: `POST /api/files` (multipart, 8 MB, MIME allowlist, per-user limit;
image metadata stripped at upload), `GET /api/files/:fileId` (permission
check first; Postgres rows stream from the DB, S3 rows 302 to a 5-minute
signed URL).

Webhooks: `POST|GET /api/channels/:channelId/webhooks`,
`DELETE /api/webhooks/:webhookId`, `POST /api/webhooks/:webhookId/:token` (ingest).

DMs: `GET|POST /api/dms`, `GET|POST /api/dms/:conversationId/messages`.

Unknown `/api/*` returns a JSON 404 (never the SPA page).

## Socket events

Client → server: `channel:join`, `channel:leave`, `typing`, `dm:typing`,
`voice:join`, `voice:leave`, `voice:signal` (WebRTC SDP/ICE relay, same voice
room only), `voice:state` {muted, deafened}, `voice:speaking` {speaking}.

Server → client: `message:new|update|delete`, `dm:new`, `dm:typing`, `typing`,
`presence`, `server:changed`, `server:removed`, `voice:participants`
(**only to members who can view that channel**), `voice:peers`, `voice:signal`,
`voice:peer-left`, `voice:state`, `voice:speaking`, `voice:removed`,
`voice:ended`, `voice:full`.

Rooms: `user:<id>`, `server:<id>`, `channel:<id>`, `voice:<id>`. Voice membership
is tracked in a server-side roster (socketId → state) so mute/deafen/speaking
survive re-broadcasts and eviction works on remote sockets.

## Cross-cutting

- **CSRF:** every state-changing `/api` call must send `X-Requested-With: fetch`
  (webhook ingest exempt — token auth, no session). The client sends it centrally.
- **Pagination:** compound `(created_at, id)` cursors (base64url JSON), newest-first
  pages of 50. Identical timestamps can no longer drop/repeat rows.
- **Rate limits:** per-IP (auth 30/15 min — `AUTH_RATE_LIMIT` override; messages
  60/min; webhook ingest 30/min) plus per-user (messages 60/min, uploads 20/10 min,
  invites 10/10 min, DM starts 20/10 min). `trust proxy` is on in production so
  per-IP limits key on the real client behind Render.
- **No email (Phase 2.1):** no email addresses, verification or emailed
  reset links anywhere. Password changes happen signed-in via
  `POST /api/me/password` (current password required, new password 10–72
  chars, must differ) and end every other session for the account.
- **2FA (Phase 2):** TOTP per RFC 6238 (SHA-1, 6 digits, ±1 step window),
  implemented with Node crypto in `lib/totp.js` and verified against the RFC
  Appendix B vectors in tests. Secrets are generated per user (shown once as
  text/otpauth URI — no QR dependency); recovery codes are 10 single-use
  values, hashed at rest, shown once.
- **Upload storage (Phase 2):** `lib/storage.js` — when `S3_BUCKET` +
  `S3_ACCESS_KEY_ID` + `S3_SECRET_ACCESS_KEY` are set, new uploads go to the
  bucket under `files/<uuid>` keys (path-style when `S3_ENDPOINT` is set,
  plain non-chunked PUTs); otherwise Postgres BYTEA exactly as Phase 1.
  Downloads always run the file-access permission check first; the bucket is
  never public. JPEG APPn/COM segments and PNG text/EXIF chunks are stripped
  at upload in both modes (`lib/exif.js`); GIF/WebP pass through.
- **Voice:** WebRTC mesh (max 8), ICE from `/api/ice`, speaking indicator via
  WebAudio RMS on the client, mute/deafen state broadcast, mic device-loss and
  permission-revocation recovery via track `ended` + `devicechange`.
- **Reconnect:** the client re-syncs servers/messages/members/voice/DMs on
  reconnect and re-joins voice only if the mic track is still live.
