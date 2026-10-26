/* Talkz Cloud — server.js (Phase 1: Part 1 fixes; Phase 2: accounts + storage;
 * Phase 2.1: ALL email features removed at Rodrigo's request + scrollbar fixes)
 * See ARCHITECTURE.md for tables, routes, socket events and the permission model.
 * Phase 1 notes:
 *  - The supplied codebase had NO file-upload, webhook, friend or view_role code at all.
 *    Files and webhooks are implemented here in minimal, secure form so the Part 1
 *    access-control fixes are real and testable rather than theoretical.
 * Phase 2 notes:
 *  - Accounts: username + password only — no email anywhere (no address
 *    collected, no verification mail, no emailed password reset; lib/mailer.js
 *    is deleted). Optional TOTP two-factor auth with recovery codes
 *    (lib/totp.js, RFC 6238, Node crypto). Signed-in users change their
 *    password via POST /api/me/password (current password required).
 *  - Storage: uploads go to S3-compatible object storage when S3_* env vars are
 *    set (lib/storage.js), Postgres BYTEA otherwise; image metadata is stripped
 *    at upload in both modes (lib/exif.js). Downloads stay permission-gated.
 */
const path = require("path");
const http = require("http");
const crypto = require("crypto");
try { process.loadEnvFile && process.loadEnvFile(); } catch { /* no .env file: env comes from the host (Render) */ }
const express = require("express");
const helmet = require("helmet");
const session = require("express-session");
const pgSession = require("connect-pg-simple")(session);
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const { Server } = require("socket.io");
const rateLimit = require("express-rate-limit");
const { ipKeyGenerator } = require("express-rate-limit");
const multer = require("multer");
const totp = require("./lib/totp");
const storage = require("./lib/storage");
const { stripImageMetadata } = require("./lib/exif");

const app = express();
const server = http.createServer(app);
const io = new Server(server);
const PORT = process.env.PORT || 3000;
const isProduction = process.env.NODE_ENV === "production";

if (!process.env.DATABASE_URL) {
  console.error("DATABASE_URL is required. Configure it in Render or your local .env.");
  process.exit(1);
}
if (isProduction && !process.env.SESSION_SECRET) {
  console.error("SESSION_SECRET is required in production.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: isProduction ? { rejectUnauthorized: false } : undefined,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

/* Part 1 #11 — trust proxy. Render always sits behind a proxy; without this every
 * user shares the proxy IP and per-IP rate limits collapse into one bucket.
 * Default: on in production, or when TRUST_PROXY=true. TRUST_PROXY=false forces off. */
const trustProxy = process.env.TRUST_PROXY === "false" ? false
  : (process.env.TRUST_PROXY === "true" || isProduction) ? 1 : false;
app.set("trust proxy", trustProxy);
if (isProduction && !trustProxy) console.warn("WARNING: production without trust proxy - per-IP rate limits will be inaccurate behind Render.");

app.disable("x-powered-by");
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "https://cdn.socket.io"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com", "data:"],
      imgSrc: ["'self'", "data:", "https:", "blob:"],
      connectSrc: ["'self'", "ws:", "wss:"],
      mediaSrc: ["'self'", "blob:"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"]
    }
  }
}));
app.use(express.json({ limit: "30kb" }));

const sessionMiddleware = session({
  store: new pgSession({ pool, tableName: "user_sessions", createTableIfMissing: true }),
  name: "talkz.sid",
  secret: process.env.SESSION_SECRET || "local-development-only-change-me",
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: { httpOnly: true, secure: isProduction, sameSite: "lax", maxAge: 1000 * 60 * 60 * 24 * 14 }
});
app.use(sessionMiddleware);
io.engine.use(sessionMiddleware);

/* Part 1 #4 — CSRF. Same-origin JSON API: every state-changing /api request must
 * carry the custom header X-Requested-With: fetch. Cross-site requests cannot set
 * custom headers without a CORS preflight, which we never grant, so they cannot
 * forge it. Exempt: webhook ingest (token-authenticated, no session involved).
 * Login/register are NOT exempt — the bundled client always sends the header. */
function csrfGuard(req, res, next) {
  if (!["POST", "PATCH", "PUT", "DELETE"].includes(req.method)) return next();
  // Only the token-authenticated ingest (POST /webhooks/:uuid/:token) is exempt;
  // the session-authenticated DELETE /webhooks/:uuid must stay CSRF-protected.
  if (req.method === "POST" && /^\/webhooks\/[0-9a-f-]{36}\/[^/]+$/i.test(req.path)) return next();
  if (req.get("X-Requested-With") === "fetch") return next();
  return res.status(403).json({ error: "Missing required X-Requested-With header." });
}
app.use("/api", csrfGuard);

/* ---------- rate limits (Part 1 #11: per-IP + per-user) ---------- */
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, limit: parseInt(process.env.AUTH_RATE_LIMIT, 10) || 30, standardHeaders: "draft-7", legacyHeaders: false,
  message: { error: "Too many attempts. Please wait a little and try again." }
});
const messageLimiter = rateLimit({
  windowMs: 60 * 1000, limit: 60, standardHeaders: true, legacyHeaders: false,
  message: { error: "You're doing that too fast. Slow down a little." }
});
const webhookLimiter = rateLimit({
  windowMs: 60 * 1000, limit: 30, standardHeaders: true, legacyHeaders: false,
  message: { error: "Webhook rate limit exceeded." }
});
function userLimiter(windowMs, limit, message) {
  return rateLimit({
    windowMs, limit, standardHeaders: true, legacyHeaders: false,
    keyGenerator: (req, res) => (req.session && req.session.userId) ? `u:${req.session.userId}` : ipKeyGenerator(req, res),
    message: { error: message }
  });
}
const uploadLimiter = userLimiter(10 * 60 * 1000, 20, "Too many uploads. Please wait a little.");
/* The 2FA login-challenge endpoint is per-IP limited on top of the auth
 * limiter; ACCOUNT_RATE_LIMIT overrides the count like AUTH_RATE_LIMIT does. */
const tokenRequestLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, limit: parseInt(process.env.ACCOUNT_RATE_LIMIT, 10) || 60, standardHeaders: "draft-7", legacyHeaders: false,
  message: { error: "Too many attempts. Please wait a little and try again." }
});
const inviteLimiter = userLimiter(10 * 60 * 1000, 10, "Too many invites created. Please wait a little.");
const dmStartLimiter = userLimiter(10 * 60 * 1000, 20, "You're starting conversations too fast. Please wait a little."); // doubles as the friend-request budget when friends land in a later phase
const userMessageLimiter = userLimiter(60 * 1000, 60, "You're sending messages too fast. Slow down a little.");

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
for (const name of ["serverId", "channelId", "messageId", "conversationId", "userId", "fileId", "webhookId"]) {
  app.param(name, (_req, res, next, val) => UUID_RE.test(val) ? next() : res.status(404).json({ error: "Not found." }));
}

const asyncRoute = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const clean = (value, max = 100) => String(value ?? "").replace(/\u0000/g, "").trim().slice(0, max);
const userPublic = row => ({ id: row.id, username: row.username, displayName: row.display_name, statusText: row.status_text || "", bio: row.bio || "", presence: row.presence || "online", accentColor: row.accent_color || "#8b5cf6", avatarUrl: row.avatar_url || "", bannerUrl: row.banner_url || "", socialLinks: row.social_links || {}, privacy: row.privacy || {}, createdAt: row.created_at, isBot: !!row.is_bot });
/* The account owner's own view (auth responses + /api/me only; never used
 * for other users, so 2FA state can't leak into member lists). */
const userPrivate = row => ({ ...userPublic(row), totpEnabled: !!row.totp_enabled });
const RANK = { owner: 3, admin: 2, moderator: 1, member: 0 };
const isMod = role => (RANK[role] ?? -1) >= 1;
const canView = (role, viewRole) => role != null && (RANK[role] ?? -1) >= (RANK[viewRole || "member"] ?? 0);

function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: "Sign in to continue." });
  next();
}
async function getRole(serverId, userId) {
  const r = await pool.query("SELECT role FROM server_members WHERE server_id=$1 AND user_id=$2", [serverId, userId]);
  return r.rows[0]?.role || null;
}
const DEFAULT_ROLE_PERMISSIONS = { manageServer:false, manageRoles:false, manageChannels:false, manageMessages:false, kickMembers:false, inviteMembers:true, sendMessages:true, attachFiles:true, viewChannels:true };
async function getMemberPermissions(serverId, userId) {
  const result = await pool.query(`SELECT sm.role, cr.permissions FROM server_members sm LEFT JOIN server_custom_roles cr ON cr.id=sm.custom_role_id WHERE sm.server_id=$1 AND sm.user_id=$2`, [serverId,userId]);
  const row=result.rows[0]; if(!row) return null;
  if(row.role==="owner") return Object.fromEntries(Object.keys(DEFAULT_ROLE_PERMISSIONS).map(k=>[k,true]));
  const legacy={...DEFAULT_ROLE_PERMISSIONS};
  if(row.role==="admin") Object.assign(legacy,Object.fromEntries(Object.keys(legacy).map(k=>[k,true])));
  if(row.role==="moderator") Object.assign(legacy,{manageMessages:true,kickMembers:true});
  return {...legacy,...(row.permissions||{})};
}
async function requireServerPermission(serverId,userId,permission) { const perms=await getMemberPermissions(serverId,userId); return !!perms && !!perms[permission]; }
/* Part 1 #3 — channelAccess enforces view_role: a member ranked below the
 * channel's view_role gets the same "no access" result as a non-member. */
async function channelAccess(channelId, userId) {
  const r = await pool.query(`
    SELECT c.id,c.server_id,c.kind,c.view_role,sm.role FROM channels c
    JOIN server_members sm ON sm.server_id=c.server_id
    WHERE c.id=$1 AND sm.user_id=$2`, [channelId, userId]);
  const row = r.rows[0] || null;
  if (!row || !canView(row.role, row.view_role)) return null;
  return row;
}
async function dmAccess(conversationId, userId) {
  const r = await pool.query(`SELECT 1 FROM dm_members me JOIN dm_members other ON other.conversation_id=me.conversation_id AND other.user_id<>me.user_id
    WHERE me.conversation_id=$1 AND me.user_id=$2 AND NOT EXISTS (SELECT 1 FROM user_blocks b WHERE (b.user_id=$2 AND b.blocked_user_id=other.user_id) OR (b.user_id=other.user_id AND b.blocked_user_id=$2))`, [conversationId, userId]);
  return r.rowCount > 0;
}
async function createStarterServer(client, userId, displayName) {
  const s = await client.query("INSERT INTO servers(name, owner_id) VALUES($1,$2) RETURNING id,name,owner_id,created_at", [`${displayName}'s space`.slice(0, 80), userId]);
  const srv = s.rows[0];
  await client.query("INSERT INTO server_members(server_id,user_id,role) VALUES($1,$2,'owner')", [srv.id, userId]);
  await client.query("INSERT INTO channels(server_id,name,kind,topic,position) VALUES($1,'general','text','The place for everything.',0)", [srv.id]);
  await client.query("INSERT INTO channels(server_id,name,kind,topic,position) VALUES($1,'Lounge','voice','Hang out and talk.',1)", [srv.id]);
  return srv;
}

/* Part 1 #7 — compound (created_at, id) cursor. A bare timestamp cursor silently
 * drops/repeats rows sharing a millisecond (Postgres stores microseconds, JS
 * Dates only carry milliseconds, so ties were common under bursts). */
function encodeCursor(row) {
  return Buffer.from(JSON.stringify({ t: new Date(row.created_at).toISOString(), id: row.id })).toString("base64url");
}
function decodeCursor(raw) {
  if (!raw) return null;
  try {
    const o = JSON.parse(Buffer.from(String(raw), "base64url").toString("utf8"));
    if (o && typeof o.t === "string" && UUID_RE.test(String(o.id)) && !isNaN(new Date(o.t))) return { t: new Date(o.t).toISOString(), id: o.id };
  } catch { /* not a cursor — fall through to legacy handling */ }
  const d = new Date(String(raw));
  if (!isNaN(d)) return { t: d.toISOString(), id: "ffffffff-ffff-ffff-ffff-ffffffffffff", legacy: true };
  return null;
}

const MSG_SELECT = `
  SELECT m.id,m.channel_id,m.content,m.created_at,m.edited_at,m.reply_to,
    p.id AS user_id,p.username,p.display_name,p.is_bot,
    rm.content AS reply_content, rp.display_name AS reply_name,
    COALESCE((SELECT json_agg(json_build_object('id',f.id,'filename',f.filename,'mime',f.mime,'size',f.size) ORDER BY f.created_at)
      FROM files f WHERE f.message_id=m.id),'[]') AS attachments,
    COALESCE((SELECT json_agg(json_build_object('emoji',r.emoji,'count',r.cnt,'users',r.users))
      FROM (SELECT emoji,COUNT(*)::int AS cnt,json_agg(user_id) AS users
            FROM message_reactions WHERE message_id=m.id GROUP BY emoji ORDER BY MIN(created_at)) r),'[]') AS reactions
  FROM messages m
  JOIN profiles p ON p.id=m.author_id
  LEFT JOIN messages rm ON rm.id=m.reply_to
  LEFT JOIN profiles rp ON rp.id=rm.author_id`;
async function fetchMessage(id) {
  const r = await pool.query(`${MSG_SELECT} WHERE m.id=$1`, [id]);
  return r.rows[0] || null;
}
async function emitServerChanged(serverId) {
  io.to(`server:${serverId}`).emit("server:changed", { serverId });
}
async function removeUserFromServerRooms(serverId, userId) {
  const ch = await pool.query("SELECT id FROM channels WHERE server_id=$1", [serverId]);
  const sockets = io.in(`user:${userId}`);
  sockets.socketsLeave(`server:${serverId}`);
  for (const c of ch.rows) { sockets.socketsLeave(`channel:${c.id}`); sockets.socketsLeave(`voice:${c.id}`); }
  io.to(`user:${userId}`).emit("server:removed", { serverId });
}

/* Part 1 #3 — when a role drops or a channel's view_role rises, sockets that lost
 * view access leave channel:/voice: rooms, and a live voice session there is torn
 * down server-side (peers are notified). */
async function evictUserFromChannel(userId, channelId) {
  const socks = await io.in(`user:${userId}`).fetchSockets();
  for (const s of socks) {
    const v = voiceRoster.get(s.id);
    if (v && v.channelId === channelId) {
      voiceRoster.delete(s.id);
      s.leave(`voice:${channelId}`);
      s.to(`voice:${channelId}`).emit("voice:peer-left", s.id);
      s.emit("voice:removed", { channelId });
      try { await broadcastVoice(channelId, v.serverId); } catch { /* room may already be gone */ }
    }
    s.leave(`channel:${channelId}`);
    s.leave(`voice:${channelId}`);
  }
}
async function evictLosingViewers(serverId) {
  const chs = await pool.query("SELECT id,view_role FROM channels WHERE server_id=$1", [serverId]);
  const members = await pool.query("SELECT user_id,role FROM server_members WHERE server_id=$1", [serverId]);
  for (const c of chs.rows) {
    for (const m of members.rows) {
      if (!canView(m.role, c.view_role)) await evictUserFromChannel(m.user_id, c.id);
    }
  }
}

/* Tombstone account that inherits a deleted bot's messages (Part 1 #8), so history
 * survives webhook deletion, attributed to "Deleted Bot". */
async function tombstoneBotId() {
  const r = await pool.query(
    `INSERT INTO profiles(username,display_name,password_hash,is_bot) VALUES('deleted-bot','Deleted Bot',$1,true)
     ON CONFLICT (username) DO UPDATE SET display_name=EXCLUDED.display_name RETURNING id`,
    [await bcrypt.hash(crypto.randomBytes(32).toString("hex"), 12)]);
  return r.rows[0].id;
}

async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS profiles (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      username TEXT NOT NULL UNIQUE,
      display_name TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    ALTER TABLE profiles ADD COLUMN IF NOT EXISTS status_text TEXT NOT NULL DEFAULT '';
    ALTER TABLE profiles ADD COLUMN IF NOT EXISTS bio TEXT NOT NULL DEFAULT '';
    ALTER TABLE profiles ADD COLUMN IF NOT EXISTS presence TEXT NOT NULL DEFAULT 'online';
    ALTER TABLE profiles ADD COLUMN IF NOT EXISTS accent_color TEXT NOT NULL DEFAULT '#8b5cf6';
    ALTER TABLE profiles ADD COLUMN IF NOT EXISTS avatar_url TEXT NOT NULL DEFAULT '';
    ALTER TABLE profiles ADD COLUMN IF NOT EXISTS banner_url TEXT NOT NULL DEFAULT '';
    ALTER TABLE profiles ADD COLUMN IF NOT EXISTS social_links JSONB NOT NULL DEFAULT '{}'::jsonb;
    ALTER TABLE profiles ADD COLUMN IF NOT EXISTS privacy JSONB NOT NULL DEFAULT '{"friendRequests":"everyone","dm":"everyone","showActivity":true}'::jsonb;
    CREATE TABLE IF NOT EXISTS friend_requests (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(), requester_id UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
      recipient_id UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
      status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','accepted','rejected')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), UNIQUE(requester_id,recipient_id), CHECK(requester_id<>recipient_id)
    );
    CREATE INDEX IF NOT EXISTS friend_requests_recipient_idx ON friend_requests(recipient_id,status,created_at DESC);
    CREATE TABLE IF NOT EXISTS user_blocks (user_id UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
      blocked_user_id UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY(user_id,blocked_user_id), CHECK(user_id<>blocked_user_id));
    CREATE TABLE IF NOT EXISTS user_preferences (user_id UUID PRIMARY KEY REFERENCES profiles(id) ON DELETE CASCADE,
      settings JSONB NOT NULL DEFAULT '{}'::jsonb, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
    ALTER TABLE profiles ADD COLUMN IF NOT EXISTS is_bot BOOLEAN NOT NULL DEFAULT false;
    /* Phase 2.1: no email columns on fresh installs. Older databases keep
     * their (now unused) email/email_verified columns and account_tokens
     * table — deliberately NOT dropped, so the migration loses no data. */
    ALTER TABLE profiles ADD COLUMN IF NOT EXISTS totp_secret TEXT;
    ALTER TABLE profiles ADD COLUMN IF NOT EXISTS totp_enabled BOOLEAN NOT NULL DEFAULT false;
    CREATE TABLE IF NOT EXISTS servers (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      name TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 80),
      owner_id UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    ALTER TABLE servers ADD COLUMN IF NOT EXISTS description TEXT NOT NULL DEFAULT '';
    ALTER TABLE servers ADD COLUMN IF NOT EXISTS welcome_message TEXT NOT NULL DEFAULT '';
    ALTER TABLE servers ADD COLUMN IF NOT EXISTS accent_color TEXT NOT NULL DEFAULT '#8b5cf6';
    ALTER TABLE servers ADD COLUMN IF NOT EXISTS visibility TEXT NOT NULL DEFAULT 'private';
    ALTER TABLE servers ADD COLUMN IF NOT EXISTS icon_url TEXT NOT NULL DEFAULT '';
    ALTER TABLE servers ADD COLUMN IF NOT EXISTS banner_url TEXT NOT NULL DEFAULT '';
    CREATE TABLE IF NOT EXISTS server_custom_roles (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(), server_id UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
      name TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 40),
      color TEXT NOT NULL DEFAULT '#8b5cf6' CHECK (color ~ '^#[0-9a-fA-F]{6}$'), position INTEGER NOT NULL DEFAULT 0,
      permissions JSONB NOT NULL DEFAULT '{"viewChannels":true,"sendMessages":true,"attachFiles":true,"inviteMembers":false,"manageMessages":false,"kickMembers":false,"manageChannels":false,"manageRoles":false,"manageServer":false}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), UNIQUE(server_id,name));
    CREATE INDEX IF NOT EXISTS server_custom_roles_server_idx ON server_custom_roles(server_id,position DESC);
    CREATE TABLE IF NOT EXISTS server_custom_emojis (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(), server_id UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
      name TEXT NOT NULL CHECK (name ~ '^[a-zA-Z0-9_]{2,32}$'), mime TEXT NOT NULL CHECK (mime IN ('image/png','image/jpeg','image/gif','image/webp')),
      data BYTEA NOT NULL, uploader_id UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), UNIQUE(server_id,name));
    CREATE INDEX IF NOT EXISTS server_custom_emojis_server_idx ON server_custom_emojis(server_id,name);
    CREATE TABLE IF NOT EXISTS server_members (
      server_id UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
      user_id UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
      role TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('owner','admin','moderator','member')),
      joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      custom_role_id UUID REFERENCES server_custom_roles(id) ON DELETE SET NULL,
      PRIMARY KEY(server_id,user_id)
    );
    ALTER TABLE server_members ADD COLUMN IF NOT EXISTS custom_role_id UUID REFERENCES server_custom_roles(id) ON DELETE SET NULL;
    CREATE TABLE IF NOT EXISTS channels (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      server_id UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
      name TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100),
      kind TEXT NOT NULL DEFAULT 'text' CHECK (kind IN ('text','voice','announcement')),
      topic TEXT NOT NULL DEFAULT '',
      position INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    ALTER TABLE channels ADD COLUMN IF NOT EXISTS view_role TEXT NOT NULL DEFAULT 'member';
    DO $$ BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='channels_view_role_check') THEN
        ALTER TABLE channels ADD CONSTRAINT channels_view_role_check CHECK (view_role IN ('owner','admin','moderator','member'));
      END IF;
    END $$;
    CREATE TABLE IF NOT EXISTS messages (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      channel_id UUID NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
      author_id UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
      content TEXT NOT NULL CHECK (char_length(content) BETWEEN 1 AND 2000),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    ALTER TABLE messages ADD COLUMN IF NOT EXISTS edited_at TIMESTAMPTZ;
    ALTER TABLE messages ADD COLUMN IF NOT EXISTS reply_to UUID REFERENCES messages(id) ON DELETE SET NULL;
    CREATE INDEX IF NOT EXISTS messages_channel_created_idx ON messages(channel_id,created_at DESC);
    CREATE INDEX IF NOT EXISTS messages_channel_cursor_idx ON messages(channel_id,created_at DESC,id DESC);
    CREATE TABLE IF NOT EXISTS saved_messages (user_id UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
      message_id UUID NOT NULL REFERENCES messages(id) ON DELETE CASCADE, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), PRIMARY KEY(user_id,message_id));
    CREATE TABLE IF NOT EXISTS message_pins (message_id UUID PRIMARY KEY REFERENCES messages(id) ON DELETE CASCADE,
      pinned_by UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
    CREATE TABLE IF NOT EXISTS message_reactions (
      message_id UUID NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
      user_id UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
      emoji TEXT NOT NULL CHECK (char_length(emoji) BETWEEN 1 AND 16),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY(message_id,user_id,emoji)
    );
    CREATE TABLE IF NOT EXISTS invites (
      code TEXT PRIMARY KEY,
      server_id UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
      created_by UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
      uses INTEGER NOT NULL DEFAULT 0,
      max_uses INTEGER,
      expires_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS dm_conversations (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS dm_members (
      conversation_id UUID NOT NULL REFERENCES dm_conversations(id) ON DELETE CASCADE,
      user_id UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
      PRIMARY KEY(conversation_id,user_id)
    );
    CREATE TABLE IF NOT EXISTS dm_messages (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      conversation_id UUID NOT NULL REFERENCES dm_conversations(id) ON DELETE CASCADE,
      author_id UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
      content TEXT NOT NULL CHECK (char_length(content) BETWEEN 1 AND 2000),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS dm_messages_conversation_created_idx ON dm_messages(conversation_id,created_at DESC);
    CREATE INDEX IF NOT EXISTS dm_messages_conversation_cursor_idx ON dm_messages(conversation_id,created_at DESC,id DESC);
    CREATE TABLE IF NOT EXISTS dm_message_pins (message_id UUID PRIMARY KEY REFERENCES dm_messages(id) ON DELETE CASCADE, conversation_id UUID NOT NULL REFERENCES dm_conversations(id) ON DELETE CASCADE, pinned_by UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
    CREATE TABLE IF NOT EXISTS files (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      uploader_id UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
      message_id UUID REFERENCES messages(id) ON DELETE CASCADE,
      dm_message_id UUID REFERENCES dm_messages(id) ON DELETE CASCADE,
      filename TEXT NOT NULL,
      mime TEXT NOT NULL,
      size INTEGER NOT NULL,
      data BYTEA,
      storage TEXT NOT NULL DEFAULT 'postgres',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS files_unattached_idx ON files(created_at) WHERE message_id IS NULL AND dm_message_id IS NULL;
    ALTER TABLE files ADD COLUMN IF NOT EXISTS storage_key TEXT;
    CREATE TABLE IF NOT EXISTS recovery_codes (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
      code_hash TEXT NOT NULL,
      used_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS recovery_codes_user_idx ON recovery_codes(user_id);
    CREATE TABLE IF NOT EXISTS webhooks (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      channel_id UUID NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      bot_user_id UUID REFERENCES profiles(id) ON DELETE SET NULL,
      token_hash TEXT NOT NULL,
      created_by UUID REFERENCES profiles(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
  /* Part 1 #9 — the old code swallowed the unique-index error when duplicate channel
   * names existed, leaving the DB without the index forever. Now: deduplicate first
   * (oldest channel keeps the name; later ones get -2, -3, ... skipping names that
   * are already taken), then create the index, and log loudly if it still fails. */
  try {
    const dupes = await pool.query(`
      SELECT server_id, lower(name) AS lname FROM channels
      GROUP BY server_id, lower(name) HAVING COUNT(*) > 1`);
    for (const d of dupes.rows) {
      const rows = await pool.query(
        "SELECT id,name FROM channels WHERE server_id=$1 AND lower(name)=$2 ORDER BY created_at,id", [d.server_id, d.lname]);
      const taken = new Set((await pool.query("SELECT lower(name) AS n FROM channels WHERE server_id=$1", [d.server_id])).rows.map(r => r.n));
      for (let i = 1; i < rows.rows.length; i++) {
        let n = i + 1, candidate;
        do { candidate = `${rows.rows[i].name.slice(0, 96)}-${n}`; n++; } while (taken.has(candidate.toLowerCase()));
        taken.add(candidate.toLowerCase());
        await pool.query("UPDATE channels SET name=$2 WHERE id=$1", [rows.rows[i].id, candidate]);
        console.log(`Deduped channel name in server ${d.server_id}: "${rows.rows[i].name}" -> "${candidate}"`);
      }
    }
    await pool.query("CREATE UNIQUE INDEX IF NOT EXISTS channels_server_name_idx ON channels(server_id,lower(name))");
  } catch (e) {
    console.error("Could not create unique channel-name index even after dedupe:", e.message);
  }
  console.log("Talkz database is ready.");
}

/* Part 1 #2 — orphan cleanup: unattached uploads older than 1 hour are deleted.
 * Attached files die with their message/channel/server/DM via ON DELETE CASCADE.
 * Phase 2 — in S3 mode the sweep also deletes the bucket objects of removed
 * orphan rows, and reconciles the bucket: objects no files row points at any
 * more (their row was cascade-deleted) are removed once they are older than
 * S3_SWEEP_MIN_AGE_MS (default 1 h) so a just-landed upload can never be
 * swept mid-flight. */
async function cleanupOrphanFiles() {
  try {
    const orphans = await pool.query(
      "SELECT f.id,f.storage,f.storage_key FROM files f WHERE f.message_id IS NULL AND f.dm_message_id IS NULL AND f.created_at < NOW() - INTERVAL '1 hour' AND NOT EXISTS (SELECT 1 FROM profiles p WHERE p.avatar_url LIKE '%' || f.id::text OR p.banner_url LIKE '%' || f.id::text)");
    if (orphans.rowCount) {
      await pool.query("DELETE FROM files WHERE id = ANY($1::uuid[])", [orphans.rows.map(r => r.id)]);
      console.log(`Cleaned up ${orphans.rowCount} orphaned upload(s).`);
      if (storage.storageMode() === "s3") {
        for (const f of orphans.rows) {
          if (f.storage === "s3" && f.storage_key) {
            try { await storage.deleteObject(f.storage_key); } catch (e) { console.error("S3 orphan delete failed:", e.message); }
          }
        }
      }
    }
    if (storage.storageMode() === "s3") {
      try {
        const known = await pool.query("SELECT storage_key FROM files WHERE storage='s3' AND storage_key IS NOT NULL");
        const knownKeys = new Set(known.rows.map(r => r.storage_key));
        const parsedAge = parseInt(process.env.S3_SWEEP_MIN_AGE_MS, 10);
        const cutoff = Date.now() - (Number.isNaN(parsedAge) ? 60 * 60 * 1000 : parsedAge);
        for (const obj of await storage.listObjects("files/")) {
          if (!knownKeys.has(obj.key) && (!obj.lastModified || new Date(obj.lastModified).getTime() < cutoff)) {
            try { await storage.deleteObject(obj.key); console.log(`Swept unreferenced bucket object ${obj.key}.`); }
            catch (e) { console.error("S3 sweep delete failed:", e.message); }
          }
        }
      } catch (e) { console.error("S3 bucket reconciliation failed:", e.message); }
    }
  } catch (e) { console.error("Orphan file cleanup failed:", e.message); }
}

/* ---------- Phase 2: recovery codes (2FA) ---------- */
const sha256Hex = s => crypto.createHash("sha256").update(String(s)).digest("hex");

/* Recovery codes: 10 codes like "a1b2c-3d4e5", shown once at enable time.
 * Only SHA-256 hashes of the normalised code (lowercase, no dash) are stored. */
function generateRecoveryCodes() {
  const codes = [];
  for (let i = 0; i < 10; i++) {
    const hex = crypto.randomBytes(5).toString("hex");
    codes.push(`${hex.slice(0, 5)}-${hex.slice(5)}`);
  }
  return codes;
}
const recoveryCodeHash = code => sha256Hex(String(code || "").toLowerCase().replace(/[^a-z0-9]/g, ""));
async function consumeRecoveryCode(userId, code) {
  const r = await pool.query(
    "UPDATE recovery_codes SET used_at=NOW() WHERE user_id=$1 AND code_hash=$2 AND used_at IS NULL RETURNING id",
    [userId, recoveryCodeHash(code)]);
  return r.rowCount > 0;
}

/* ---------- health, ICE, auth ---------- */
app.get("/api/health", asyncRoute(async (_req, res) => {
  await pool.query("SELECT 1");
  res.json({ ok: true, app: "Talkz Cloud", database: "connected" });
}));

/* Part 1 #6 — ICE config, authenticated. STUN always; TURN only when configured. */
app.get("/api/ice", requireAuth, (_req, res) => {
  const iceServers = [{ urls: process.env.STUN_URL || "stun:stun.l.google.com:19302" }];
  if (process.env.TURN_URL && process.env.TURN_USERNAME && process.env.TURN_CREDENTIAL) {
    iceServers.push({ urls: process.env.TURN_URL, username: process.env.TURN_USERNAME, credential: process.env.TURN_CREDENTIAL });
  }
  res.json({ iceServers, turnConfigured: iceServers.length > 1 });
});

app.post("/api/auth/register", authLimiter, asyncRoute(async (req, res) => {
  const username = clean(req.body.username, 24).toLowerCase();
  const displayName = clean(req.body.displayName || req.body.username, 32);
  const password = String(req.body.password || "");
  if (!/^[a-z0-9_]{3,24}$/.test(username)) return res.status(400).json({ error: "Username must be 3-24 characters using letters, numbers, or underscores." });
  if (username === "deleted-bot" || username === "deleted-user") return res.status(400).json({ error: "That username is reserved." });
  if (password.length < 10 || password.length > 72) return res.status(400).json({ error: "Password must be between 10 and 72 characters." });
  if (displayName.length < 1) return res.status(400).json({ error: "Enter a display name." });
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const passwordHash = await bcrypt.hash(password, 12);
    const inserted = await client.query(
      "INSERT INTO profiles(username,display_name,password_hash) VALUES($1,$2,$3) RETURNING id,username,display_name,status_text,created_at,is_bot,totp_enabled",
      [username, displayName, passwordHash]);
    const user = inserted.rows[0];
    const starter = await createStarterServer(client, user.id, displayName);
    await client.query("COMMIT");
    req.session.userId = user.id;
    req.session.save(err => {
      if (err) return res.status(500).json({ error: "Account created, but session could not be saved. Please sign in." });
      res.status(201).json({ user: userPrivate(user), starterServerId: starter.id });
    });
  } catch (err) {
    await client.query("ROLLBACK");
    if (err.code === "23505") return res.status(409).json({ error: "That username is already taken." });
    throw err;
  } finally { client.release(); }
}));

app.post("/api/auth/login", authLimiter, asyncRoute(async (req, res) => {
  const username = clean(req.body.username, 24).toLowerCase();
  const password = String(req.body.password || "");
  const result = await pool.query("SELECT * FROM profiles WHERE username=$1 AND is_bot=false", [username]);
  const user = result.rows[0];
  if (!user || !(await bcrypt.compare(password, user.password_hash))) return res.status(401).json({ error: "Incorrect username or password." });
  /* Phase 2 — two-factor gate: a correct password alone does not sign in a
   * 2FA account. The session only remembers a short-lived pending challenge;
   * /api/auth/login/2fa completes the sign-in. */
  if (user.totp_enabled && user.totp_secret) {
    req.session.pending2fa = { userId: user.id, attempts: 0, exp: Date.now() + 5 * 60 * 1000 };
    return req.session.save(err => {
      if (err) return res.status(500).json({ error: "Could not start the two-factor challenge." });
      res.json({ twoFactorRequired: true });
    });
  }
  req.session.regenerate(err => {
    if (err) return res.status(500).json({ error: "Could not start your session." });
    req.session.userId = user.id;
    req.session.save(saveErr => {
      if (saveErr) return res.status(500).json({ error: "Could not save your session." });
      res.json({ user: userPrivate(user) });
    });
  });
}));

/* Phase 2 — second factor: an authenticator TOTP code, or one of the
 * single-use recovery codes shown when 2FA was enabled. */
app.post("/api/auth/login/2fa", authLimiter, tokenRequestLimiter, asyncRoute(async (req, res) => {
  const pending = req.session.pending2fa;
  if (!pending || Date.now() > pending.exp) {
    delete req.session.pending2fa;
    return res.status(401).json({ error: "That sign-in challenge has expired. Sign in again." });
  }
  const code = String(req.body.code || req.body.recoveryCode || "").trim();
  const result = await pool.query("SELECT * FROM profiles WHERE id=$1 AND is_bot=false", [pending.userId]);
  const user = result.rows[0];
  if (!user || !user.totp_enabled || !user.totp_secret) {
    delete req.session.pending2fa;
    return res.status(401).json({ error: "That sign-in challenge has expired. Sign in again." });
  }
  let ok = totp.verifyTotp(user.totp_secret, code);
  if (!ok && code) ok = await consumeRecoveryCode(user.id, code);
  if (!ok) {
    pending.attempts = (pending.attempts || 0) + 1;
    if (pending.attempts >= 5) delete req.session.pending2fa;
    return req.session.save(() => res.status(401).json({
      error: pending.attempts >= 5
        ? "Too many incorrect codes. Sign in again."
        : "That code didn't check out. Try again."
    }));
  }
  req.session.regenerate(err => {
    if (err) return res.status(500).json({ error: "Could not start your session." });
    req.session.userId = user.id;
    req.session.save(saveErr => {
      if (saveErr) return res.status(500).json({ error: "Could not save your session." });
      res.json({ user: userPrivate(user) });
    });
  });
}));

/* Email routes (verify-email, resend-verification, forgot-password,
 * reset-password) were removed in Phase 2.1 with the rest of the email
 * features — they now fall through to the JSON 404 for unknown /api routes. */

app.post("/api/auth/logout", requireAuth, (req, res, next) => {
  req.session.destroy(err => {
    if (err) return next(err);
    res.clearCookie("talkz.sid", { httpOnly: true, sameSite: "lax", secure: isProduction });
    res.json({ ok: true });
  });
});

/* Part 1 #12 — log out of all devices: delete every stored session for this user
 * except the current one. connect-pg-simple keeps sessions in user_sessions with
 * the session JSON in `sess`, so this is a single parameterised delete. */
app.post("/api/auth/logout-all", requireAuth, asyncRoute(async (req, res) => {
  const r = await pool.query(
    "DELETE FROM user_sessions WHERE sess->>'userId'=$1 AND sid<>$2", [req.session.userId, req.sessionID]);
  io.in(`user:${req.session.userId}`).disconnectSockets(false);
  // The current socket was disconnected too; the client reconnects with its still-valid session cookie.
  res.json({ ok: true, sessionsEnded: r.rowCount });
}));

app.get("/api/me", asyncRoute(async (req, res) => {
  if (!req.session.userId) return res.json({ user: null });
  const result = await pool.query("SELECT id,username,display_name,status_text,bio,presence,accent_color,avatar_url,banner_url,social_links,privacy,created_at,is_bot,totp_enabled FROM profiles WHERE id=$1", [req.session.userId]);
  res.json({ user: result.rows[0] ? userPrivate(result.rows[0]) : null });
}));

app.patch("/api/me", requireAuth, messageLimiter, asyncRoute(async (req, res) => {
  const displayName = clean(req.body.displayName, 32);
  const statusText = clean(req.body.statusText, 60);
  const bio = clean(req.body.bio, 300);
  const presence = ["online","idle","dnd","invisible"].includes(req.body.presence) ? req.body.presence : "online";
  const accentColor = /^#[0-9a-f]{6}$/i.test(String(req.body.accentColor || "")) ? req.body.accentColor : "#8b5cf6";
  const socialLinks = {};
  for (const key of ["website","youtube","twitch","github","x"]) {
    const value = clean(req.body.socialLinks?.[key], 200);
    if (value && !/^https:\/\//i.test(value)) return res.status(400).json({ error: `The ${key} link must start with https://` });
    if (value) socialLinks[key] = value;
  }
  const privacy = {
    friendRequests: ["everyone","none"].includes(req.body.privacy?.friendRequests) ? req.body.privacy.friendRequests : "everyone",
    dm: ["everyone","friends","none"].includes(req.body.privacy?.dm) ? req.body.privacy.dm : "everyone",
    showActivity: req.body.privacy?.showActivity !== false
  };
  if (!displayName) return res.status(400).json({ error: "Display name can't be empty." });
  const r = await pool.query("UPDATE profiles SET display_name=$2,status_text=$3,bio=$4,presence=$5,accent_color=$6,social_links=$7::jsonb,privacy=$8::jsonb WHERE id=$1 RETURNING id,username,display_name,status_text,bio,presence,accent_color,avatar_url,banner_url,social_links,privacy,created_at,is_bot,totp_enabled", [req.session.userId, displayName, statusText, bio, presence, accentColor, JSON.stringify(socialLinks), JSON.stringify(privacy)]);
  const rooms = await pool.query("SELECT server_id FROM server_members WHERE user_id=$1", [req.session.userId]);
  rooms.rows.forEach(x => emitServerChanged(x.server_id));
  res.json({ user: userPrivate(r.rows[0]) });
}));

/* Profile image and banner uploads reuse the existing secure storage pipeline. */
async function storeProfileImage(req, res, kind) {
  console.info(`[image-upload] profile ${kind} request user=${req.session.userId} file=${req.file ? `${req.file.originalname} (${req.file.mimetype}, ${req.file.size} bytes)` : "missing"}`);
  if (!req.file) return res.status(400).json({ error: "Choose an image to upload." });
  if (!String(req.file.mimetype).startsWith("image/")) return res.status(400).json({ error: "Only image files are allowed." });
  const buffer = stripImageMetadata(req.file.buffer, req.file.mimetype);
  let fileId;
  if (storage.storageMode() === "s3") {
    const key = storage.newObjectKey();
    await storage.putObject(key, buffer, req.file.mimetype);
    try {
      const r = await pool.query("INSERT INTO files(uploader_id,filename,mime,size,storage,storage_key) VALUES($1,$2,$3,$4,'s3',$5) RETURNING id", [req.session.userId, kind + "." + (req.file.mimetype.split("/")[1] || "img"), req.file.mimetype, buffer.length, key]);
      fileId = r.rows[0].id;
    } catch (e) { try { await storage.deleteObject(key); } catch {} throw e; }
  } else {
    const r = await pool.query("INSERT INTO files(uploader_id,filename,mime,size,data) VALUES($1,$2,$3,$4,$5) RETURNING id", [req.session.userId, kind + "." + (req.file.mimetype.split("/")[1] || "img"), req.file.mimetype, buffer.length, buffer]);
    fileId = r.rows[0].id;
  }
  const url = `/api/files/${fileId}`;
  const col = kind === "avatar" ? "avatar_url" : "banner_url";
  const r = await pool.query(`UPDATE profiles SET ${col}=$2 WHERE id=$1 RETURNING id,username,display_name,status_text,bio,presence,accent_color,avatar_url,banner_url,social_links,privacy,created_at,is_bot,totp_enabled`, [req.session.userId, url]);
  console.info(`[image-upload] profile ${kind} saved user=${req.session.userId} fileId=${fileId} url=${url} storage=${storage.storageMode()}`);
  res.status(201).json({ user: userPrivate(r.rows[0]), url });
}
const profileImageUpload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 5 * 1024 * 1024, files: 1 }, fileFilter: (_req, file, cb) => String(file.mimetype).startsWith("image/") ? cb(null, true) : cb(new Error("Choose a PNG, JPEG, GIF, or WebP image.")) });
for (const kind of ["avatar", "banner"]) {
  app.post(`/api/me/${kind}`, requireAuth, uploadLimiter, (req,res,next)=>profileImageUpload.single("file")(req,res,err=>err?res.status(400).json({error:err.code === "LIMIT_FILE_SIZE" ? "Images are limited to 5 MB." : err.message}):next()), asyncRoute(async(req,res)=>storeProfileImage(req,res,kind)));
  app.delete(`/api/me/${kind}`, requireAuth, asyncRoute(async(req,res)=>{
    const col = kind === "avatar" ? "avatar_url" : "banner_url";
    await pool.query(`UPDATE profiles SET ${col}='' WHERE id=$1`, [req.session.userId]);
    const r = await pool.query("SELECT id,username,display_name,status_text,bio,presence,accent_color,avatar_url,banner_url,social_links,privacy,created_at,is_bot,totp_enabled FROM profiles WHERE id=$1", [req.session.userId]);
    res.json({user:userPrivate(r.rows[0])});
  }));
}

/* ---------- friends, blocks, saved messages, pins, preferences ---------- */
app.get("/api/friends", requireAuth, asyncRoute(async (req,res)=>{
  const uid=req.session.userId;
  const [friends,incoming,outgoing,blocked]=await Promise.all([
    pool.query(`SELECT p.id,p.username,p.display_name,p.status_text,p.presence FROM friend_requests f JOIN profiles p ON p.id=CASE WHEN f.requester_id=$1 THEN f.recipient_id ELSE f.requester_id END WHERE (f.requester_id=$1 OR f.recipient_id=$1) AND f.status='accepted' ORDER BY p.username`,[uid]),
    pool.query(`SELECT f.id,p.id AS user_id,p.username,p.display_name,f.created_at FROM friend_requests f JOIN profiles p ON p.id=f.requester_id WHERE f.recipient_id=$1 AND f.status='pending' ORDER BY f.created_at DESC`,[uid]),
    pool.query(`SELECT f.id,p.id AS user_id,p.username,p.display_name,f.created_at FROM friend_requests f JOIN profiles p ON p.id=f.recipient_id WHERE f.requester_id=$1 AND f.status='pending' ORDER BY f.created_at DESC`,[uid]),
    pool.query(`SELECT p.id,p.username,p.display_name FROM user_blocks b JOIN profiles p ON p.id=b.blocked_user_id WHERE b.user_id=$1 ORDER BY p.username`,[uid])
  ]);
  res.json({friends:friends.rows.map(x=>({...x,online:x.presence!=='invisible'&&online.has(x.id)})),incoming:incoming.rows,outgoing:outgoing.rows,blocked:blocked.rows});
}));
app.post("/api/friends/requests", requireAuth, dmStartLimiter, asyncRoute(async(req,res)=>{
  const username=clean(req.body.username,24).toLowerCase().replace(/^@/,"");
  const target=(await pool.query("SELECT id,username,privacy FROM profiles WHERE username=$1 AND is_bot=false",[username])).rows[0];
  if(!target)return res.status(404).json({error:"No user with that username."});
  if(target.id===req.session.userId)return res.status(400).json({error:"You cannot add yourself."});
  if(target.privacy?.friendRequests==="none")return res.status(403).json({error:"This user is not accepting friend requests."});
  const blocked=await pool.query("SELECT 1 FROM user_blocks WHERE (user_id=$1 AND blocked_user_id=$2) OR (user_id=$2 AND blocked_user_id=$1)",[req.session.userId,target.id]);
  if(blocked.rowCount)return res.status(403).json({error:"Friend requests are unavailable for this pair of users."});
  const existing=await pool.query("SELECT id,status,requester_id FROM friend_requests WHERE (requester_id=$1 AND recipient_id=$2) OR (requester_id=$2 AND recipient_id=$1) ORDER BY created_at DESC LIMIT 1",[req.session.userId,target.id]);
  if(existing.rows[0]?.status==='accepted')return res.status(409).json({error:"You are already friends."});
  if(existing.rows[0]?.status==='pending')return res.status(409).json({error:existing.rows[0].requester_id===req.session.userId?"Request already sent.":"This user has already requested you; accept the incoming request."});
  const r=await pool.query("INSERT INTO friend_requests(requester_id,recipient_id) VALUES($1,$2) RETURNING id",[req.session.userId,target.id]);
  io.to(`user:${target.id}`).emit("friends:changed",{});res.status(201).json({ok:true,id:r.rows[0].id});
}));
app.post("/api/friends/requests/:requestId/respond", requireAuth, asyncRoute(async(req,res)=>{
  if(!UUID_RE.test(req.params.requestId))return res.status(404).json({error:"Not found."});
  const accept=req.body.accept===true;
  const r=await pool.query("UPDATE friend_requests SET status=$3 WHERE id=$1 AND recipient_id=$2 AND status='pending' RETURNING requester_id",[req.params.requestId,req.session.userId,accept?'accepted':'rejected']);
  if(!r.rowCount)return res.status(404).json({error:"Request not found."});
  io.to(`user:${r.rows[0].requester_id}`).emit("friends:changed",{});res.json({ok:true});
}));
app.delete("/api/friends/:userId", requireAuth, asyncRoute(async(req,res)=>{
  await pool.query("DELETE FROM friend_requests WHERE status='accepted' AND ((requester_id=$1 AND recipient_id=$2) OR (requester_id=$2 AND recipient_id=$1))",[req.session.userId,req.params.userId]);res.json({ok:true});
}));
app.post("/api/blocks/:userId", requireAuth, asyncRoute(async(req,res)=>{
  if(req.params.userId===req.session.userId)return res.status(400).json({error:"You cannot block yourself."});
  const exists=await pool.query("SELECT 1 FROM profiles WHERE id=$1 AND is_bot=false",[req.params.userId]);if(!exists.rowCount)return res.status(404).json({error:"User not found."});
  await pool.query("INSERT INTO user_blocks(user_id,blocked_user_id) VALUES($1,$2) ON CONFLICT DO NOTHING",[req.session.userId,req.params.userId]);
  await pool.query("DELETE FROM friend_requests WHERE (requester_id=$1 AND recipient_id=$2) OR (requester_id=$2 AND recipient_id=$1)",[req.session.userId,req.params.userId]);res.json({ok:true});
}));
app.delete("/api/blocks/:userId", requireAuth, asyncRoute(async(req,res)=>{await pool.query("DELETE FROM user_blocks WHERE user_id=$1 AND blocked_user_id=$2",[req.session.userId,req.params.userId]);res.json({ok:true});}));
app.get("/api/me/saved-messages", requireAuth, asyncRoute(async(req,res)=>{
 const r=await pool.query(`SELECT m.id,m.content,m.created_at,c.name AS channel_name,s.name AS server_name FROM saved_messages b JOIN messages m ON m.id=b.message_id JOIN channels c ON c.id=m.channel_id JOIN servers s ON s.id=c.server_id JOIN server_members sm ON sm.server_id=s.id AND sm.user_id=b.user_id WHERE b.user_id=$1 ORDER BY b.created_at DESC LIMIT 200`,[req.session.userId]);res.json({messages:r.rows});
}));
app.put("/api/messages/:messageId/save", requireAuth, asyncRoute(async(req,res)=>{
 const m=await pool.query("SELECT m.id,c.server_id FROM messages m JOIN channels c ON c.id=m.channel_id JOIN server_members sm ON sm.server_id=c.server_id AND sm.user_id=$2 WHERE m.id=$1",[req.params.messageId,req.session.userId]);if(!m.rowCount)return res.status(404).json({error:"Message not found."});
 if(req.body.saved===false)await pool.query("DELETE FROM saved_messages WHERE user_id=$1 AND message_id=$2",[req.session.userId,req.params.messageId]);else await pool.query("INSERT INTO saved_messages(user_id,message_id) VALUES($1,$2) ON CONFLICT DO NOTHING",[req.session.userId,req.params.messageId]);res.json({ok:true,saved:req.body.saved!==false});
}));
app.get("/api/channels/:channelId/pins", requireAuth, asyncRoute(async(req,res)=>{
 const a=await channelAccess(req.params.channelId,req.session.userId);if(!a)return res.status(403).json({error:"No access to this channel."});const r=await pool.query(`${MSG_SELECT} JOIN message_pins pin ON pin.message_id=m.id WHERE m.channel_id=$1 ORDER BY pin.created_at DESC LIMIT 100`,[req.params.channelId]);res.json({messages:r.rows});
}));
app.put("/api/messages/:messageId/pin", requireAuth, asyncRoute(async(req,res)=>{
 const m=await pool.query("SELECT m.id,c.server_id,c.id AS channel_id FROM messages m JOIN channels c ON c.id=m.channel_id WHERE m.id=$1",[req.params.messageId]);if(!m.rowCount)return res.status(404).json({error:"Message not found."});const role=await getRole(m.rows[0].server_id,req.session.userId);if(!isMod(role))return res.status(403).json({error:"Moderator permission required."});
 if(req.body.pinned===false)await pool.query("DELETE FROM message_pins WHERE message_id=$1",[req.params.messageId]);else await pool.query("INSERT INTO message_pins(message_id,pinned_by) VALUES($1,$2) ON CONFLICT(message_id) DO NOTHING",[req.params.messageId,req.session.userId]);io.to(`channel:${m.rows[0].channel_id}`).emit("pins:changed",{});res.json({ok:true,pinned:req.body.pinned!==false});
}));
app.get("/api/me/preferences", requireAuth, asyncRoute(async(req,res)=>{const r=await pool.query("SELECT settings FROM user_preferences WHERE user_id=$1",[req.session.userId]);res.json({settings:r.rows[0]?.settings||{}});}));
app.put("/api/me/preferences", requireAuth, asyncRoute(async(req,res)=>{const settings=req.body.settings;if(!settings||typeof settings!=="object"||Array.isArray(settings)||JSON.stringify(settings).length>8000)return res.status(400).json({error:"Invalid preferences."});const r=await pool.query("INSERT INTO user_preferences(user_id,settings) VALUES($1,$2::jsonb) ON CONFLICT(user_id) DO UPDATE SET settings=EXCLUDED.settings,updated_at=NOW() RETURNING settings",[req.session.userId,JSON.stringify(settings)]);res.json({settings:r.rows[0].settings});}));

/* Change password (Phase 2.1) — signed-in, current-password confirmed. With
 * email gone there is no emailed reset link, so this is the way a password
 * is rotated; a forgotten password can only be reset by the server operator
 * directly in the database. A successful change ends every OTHER session
 * for the account (the hygiene the old email reset flow had). */
app.post("/api/me/password", requireAuth, authLimiter, asyncRoute(async (req, res) => {
  const current = String(req.body.currentPassword || "");
  const next = String(req.body.newPassword || "");
  if (next.length < 10 || next.length > 72) return res.status(400).json({ error: "New password must be between 10 and 72 characters." });
  const me = await pool.query("SELECT password_hash FROM profiles WHERE id=$1", [req.session.userId]);
  if (!me.rowCount || !(await bcrypt.compare(current, me.rows[0].password_hash))) return res.status(401).json({ error: "Current password is incorrect." });
  if (await bcrypt.compare(next, me.rows[0].password_hash)) return res.status(400).json({ error: "That's already your password — pick a different one." });
  const passwordHash = await bcrypt.hash(next, 12);
  await pool.query("UPDATE profiles SET password_hash=$2 WHERE id=$1", [req.session.userId, passwordHash]);
  const r = await pool.query("DELETE FROM user_sessions WHERE sess->>'userId'=$1 AND sid<>$2", [req.session.userId, req.sessionID]);
  io.in(`user:${req.session.userId}`).disconnectSockets(false);
  // The current socket was disconnected too; the client reconnects with its still-valid session cookie.
  res.json({ ok: true, sessionsEnded: r.rowCount });
}));

/* ---------- Phase 2: two-factor management ---------- */
app.post("/api/me/2fa/setup", requireAuth, authLimiter, asyncRoute(async (req, res) => {
  const password = String(req.body.password || "");
  const me = await pool.query("SELECT id,username,password_hash,totp_enabled FROM profiles WHERE id=$1", [req.session.userId]);
  const user = me.rows[0];
  if (!user || !(await bcrypt.compare(password, user.password_hash))) return res.status(401).json({ error: "Current password is incorrect." });
  if (user.totp_enabled) return res.status(400).json({ error: "Two-factor is already on. Disable it first if you want a fresh secret." });
  const secret = totp.generateSecret();
  await pool.query("UPDATE profiles SET totp_secret=$2 WHERE id=$1", [user.id, secret]);
  // The secret is staged, not active, until a code confirms the user saved it.
  res.json({ secret, otpauthUrl: totp.otpauthUrl(secret, user.username) });
}));

app.post("/api/me/2fa/enable", requireAuth, authLimiter, asyncRoute(async (req, res) => {
  const me = await pool.query("SELECT id,totp_secret,totp_enabled FROM profiles WHERE id=$1", [req.session.userId]);
  const user = me.rows[0];
  if (!user || user.totp_enabled) return res.status(400).json({ error: "Two-factor is already on." });
  if (!user.totp_secret) return res.status(400).json({ error: "Start setup first so we can generate your secret." });
  if (!totp.verifyTotp(user.totp_secret, String(req.body.code || ""))) return res.status(401).json({ error: "That code didn't check out. Make sure your authenticator's clock is right and try again." });
  const codes = generateRecoveryCodes();
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("UPDATE profiles SET totp_enabled=true WHERE id=$1", [user.id]);
    await client.query("DELETE FROM recovery_codes WHERE user_id=$1", [user.id]);
    for (const code of codes) {
      await client.query("INSERT INTO recovery_codes(user_id,code_hash) VALUES($1,$2)", [user.id, recoveryCodeHash(code)]);
    }
    await client.query("COMMIT");
  } catch (e) { await client.query("ROLLBACK"); throw e; } finally { client.release(); }
  // Recovery codes are shown exactly once — only their hashes were stored.
  res.json({ ok: true, recoveryCodes: codes });
}));

app.post("/api/me/2fa/disable", requireAuth, authLimiter, asyncRoute(async (req, res) => {
  const password = String(req.body.password || "");
  const code = String(req.body.code || "").trim();
  const me = await pool.query("SELECT id,password_hash,totp_secret,totp_enabled FROM profiles WHERE id=$1", [req.session.userId]);
  const user = me.rows[0];
  if (!user || !(await bcrypt.compare(password, user.password_hash))) return res.status(401).json({ error: "Current password is incorrect." });
  if (!user.totp_enabled) return res.status(400).json({ error: "Two-factor isn't on for this account." });
  let ok = user.totp_secret ? totp.verifyTotp(user.totp_secret, code) : false;
  if (!ok && code) ok = await consumeRecoveryCode(user.id, code);
  if (!ok) return res.status(401).json({ error: "That code didn't check out." });
  await pool.query("UPDATE profiles SET totp_enabled=false, totp_secret=NULL WHERE id=$1", [user.id]);
  await pool.query("DELETE FROM recovery_codes WHERE user_id=$1", [user.id]);
  res.json({ ok: true });
}));

/* Part 1 #12 — change username (password-confirmed). */
app.patch("/api/me/username", requireAuth, authLimiter, asyncRoute(async (req, res) => {
  const username = clean(req.body.username, 24).toLowerCase();
  const password = String(req.body.password || "");
  if (!/^[a-z0-9_]{3,24}$/.test(username)) return res.status(400).json({ error: "Username must be 3-24 characters using letters, numbers, or underscores." });
  if (username === "deleted-bot" || username === "deleted-user") return res.status(400).json({ error: "That username is reserved." });
  const me = await pool.query("SELECT password_hash FROM profiles WHERE id=$1", [req.session.userId]);
  if (!me.rowCount || !(await bcrypt.compare(password, me.rows[0].password_hash))) return res.status(401).json({ error: "Current password is incorrect." });
  try {
    const r = await pool.query("UPDATE profiles SET username=$2 WHERE id=$1 RETURNING id,username,display_name,status_text,created_at,is_bot", [req.session.userId, username]);
    res.json({ user: userPublic(r.rows[0]) });
  } catch (e) {
    if (e.code === "23505") return res.status(409).json({ error: "That username is already taken." });
    throw e;
  }
}));

/* Part 1 #12 — delete account (password-confirmed). Owned servers are transferred
 * to the highest-ranked, longest-standing remaining member; a server with no other
 * members is deleted. The profile delete then cascades memberships and messages. */
app.delete("/api/me", requireAuth, authLimiter, asyncRoute(async (req, res) => {
  const password = String(req.body.password || "");
  const me = await pool.query("SELECT password_hash FROM profiles WHERE id=$1", [req.session.userId]);
  if (!me.rowCount || !(await bcrypt.compare(password, me.rows[0].password_hash))) return res.status(401).json({ error: "Current password is incorrect." });
  const uid = req.session.userId;
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const owned = await client.query("SELECT id FROM servers WHERE owner_id=$1", [uid]);
    for (const s of owned.rows) {
      const heir = await client.query(
        `SELECT user_id FROM server_members WHERE server_id=$1 AND user_id<>$2
         ORDER BY CASE role WHEN 'admin' THEN 0 WHEN 'moderator' THEN 1 ELSE 2 END, joined_at LIMIT 1`, [s.id, uid]);
      if (heir.rowCount) {
        await client.query("UPDATE servers SET owner_id=$2 WHERE id=$1", [s.id, heir.rows[0].user_id]);
        await client.query("UPDATE server_members SET role='owner' WHERE server_id=$1 AND user_id=$2", [s.id, heir.rows[0].user_id]);
      } else {
        await client.query("DELETE FROM servers WHERE id=$1", [s.id]);
        io.to(`server:${s.id}`).emit("server:removed", { serverId: s.id });
      }
    }
    await client.query("DELETE FROM profiles WHERE id=$1", [uid]);
    await client.query("COMMIT");
  } catch (e) { await client.query("ROLLBACK"); throw e; } finally { client.release(); }
  io.in(`user:${uid}`).disconnectSockets(true);
  req.session.destroy(() => {
    res.clearCookie("talkz.sid", { httpOnly: true, sameSite: "lax", secure: isProduction });
    res.json({ ok: true });
  });
}));

/* ---------- servers ---------- */
app.get("/api/servers", requireAuth, asyncRoute(async (req, res) => {
  const result = await pool.query(`
    SELECT s.id,s.name,s.description,s.welcome_message,s.accent_color,s.visibility,s.icon_url,s.banner_url,s.owner_id,s.created_at,sm.role,
      COALESCE(json_agg(json_build_object('id',c.id,'name',c.name,'kind',c.kind,'topic',c.topic,'position',c.position,'view_role',c.view_role)
        ORDER BY c.position,c.created_at) FILTER (WHERE c.id IS NOT NULL),'[]') AS channels
    FROM server_members sm JOIN servers s ON s.id=sm.server_id
    LEFT JOIN channels c ON c.server_id=s.id
    WHERE sm.user_id=$1
    GROUP BY s.id,s.name,s.description,s.welcome_message,s.accent_color,s.visibility,s.icon_url,s.banner_url,s.owner_id,s.created_at,sm.role
    ORDER BY s.created_at`, [req.session.userId]);
  // Part 1 #3 — hidden channels are not even listed for members who can't view them.
  for (const srv of result.rows) srv.channels = srv.channels.filter(c => canView(srv.role, c.view_role));
  res.json({ servers: result.rows });
}));

app.post("/api/servers", requireAuth, messageLimiter, asyncRoute(async (req, res) => {
  const name = clean(req.body.name, 80);
  if (!name) return res.status(400).json({ error: "Server name is required." });
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const s = await client.query("INSERT INTO servers(name,owner_id) VALUES($1,$2) RETURNING id,name,owner_id,created_at", [name, req.session.userId]);
    const srv = s.rows[0];
    await client.query("INSERT INTO server_members(server_id,user_id,role) VALUES($1,$2,'owner')", [srv.id, req.session.userId]);
    const c = await client.query("INSERT INTO channels(server_id,name,topic,position) VALUES($1,'general','The place for everything.',0) RETURNING id,name,kind,topic,position,view_role", [srv.id]);
    const v = await client.query("INSERT INTO channels(server_id,name,kind,topic,position) VALUES($1,'Lounge','voice','Hang out and talk.',1) RETURNING id,name,kind,topic,position,view_role", [srv.id]);
    await client.query("COMMIT");
    srv.channels = [c.rows[0], v.rows[0]];
    io.in(`user:${req.session.userId}`).socketsJoin(`server:${srv.id}`);
    res.status(201).json({ server: srv });
  } catch (e) { await client.query("ROLLBACK"); throw e; } finally { client.release(); }
}));

app.patch("/api/servers/:serverId", requireAuth, asyncRoute(async (req, res) => {
  const role = await getRole(req.params.serverId, req.session.userId);
  if (role !== "owner" && role !== "admin") return res.status(403).json({ error: "Only admins can rename the server." });
  const name = clean(req.body.name, 80);
  if (!name) return res.status(400).json({ error: "Server name is required." });
  const description = clean(req.body.description, 500);
  const welcomeMessage = clean(req.body.welcomeMessage, 1000);
  const accentColor = /^#[0-9a-f]{6}$/i.test(String(req.body.accentColor || "")) ? req.body.accentColor : "#8b5cf6";
  const visibility = ["private","public"].includes(req.body.visibility) ? req.body.visibility : "private";
  const iconUrl = typeof req.body.iconUrl === "string" ? req.body.iconUrl.slice(0,500) : undefined;
  const bannerUrl = typeof req.body.bannerUrl === "string" ? req.body.bannerUrl.slice(0,500) : undefined;
  await pool.query(`UPDATE servers SET name=$2,description=$3,welcome_message=$4,accent_color=$5,visibility=$6,icon_url=COALESCE($7,icon_url),banner_url=COALESCE($8,banner_url) WHERE id=$1`, [req.params.serverId,name,description,welcomeMessage,accentColor,visibility,iconUrl,bannerUrl]);
  emitServerChanged(req.params.serverId);
  res.json({ ok: true });
}));

/* Server icon/banner uploads use the same database/S3 storage pipeline as profile images. GIF bytes are preserved so animation remains intact. */
const serverImageUpload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 8 * 1024 * 1024, files: 1 }, fileFilter: (_req,file,cb) => new Set(["image/png","image/jpeg","image/gif","image/webp"]).has(file.mimetype) ? cb(null,true) : cb(new Error("Choose a PNG, JPEG, GIF, or WebP image.")) });
async function storeServerImage(req,res,kind){
  console.info(`[image-upload] server ${kind} request server=${req.params.serverId} user=${req.session.userId} file=${req.file ? `${req.file.originalname} (${req.file.mimetype}, ${req.file.size} bytes)` : "missing"}`);
  const role=await getRole(req.params.serverId,req.session.userId);
  if(role!=="owner"&&role!=="admin")return res.status(403).json({error:"Manage Server permission required."});
  if(!req.file)return res.status(400).json({error:"Choose an image to upload."});
  const buffer=stripImageMetadata(req.file.buffer,req.file.mimetype); let fileId;
  if(storage.storageMode()==="s3"){
    const key=storage.newObjectKey(); await storage.putObject(key,buffer,req.file.mimetype);
    try{const r=await pool.query("INSERT INTO files(uploader_id,filename,mime,size,storage,storage_key) VALUES($1,$2,$3,$4,'s3',$5) RETURNING id",[req.session.userId,"server-"+kind+"."+(req.file.mimetype.split("/")[1]||"img"),req.file.mimetype,buffer.length,key]);fileId=r.rows[0].id}
    catch(e){try{await storage.deleteObject(key)}catch{}throw e}
  }else{const r=await pool.query("INSERT INTO files(uploader_id,filename,mime,size,data) VALUES($1,$2,$3,$4,$5) RETURNING id",[req.session.userId,"server-"+kind+"."+(req.file.mimetype.split("/")[1]||"img"),req.file.mimetype,buffer.length,buffer]);fileId=r.rows[0].id}
  const url=`/api/files/${fileId}`,col=kind==="icon"?"icon_url":"banner_url";
  await pool.query(`UPDATE servers SET ${col}=$2 WHERE id=$1`,[req.params.serverId,url]);
  emitServerChanged(req.params.serverId);
  console.info(`[image-upload] server ${kind} saved server=${req.params.serverId} user=${req.session.userId} fileId=${fileId} url=${url} storage=${storage.storageMode()}`);
  res.status(201).json({url,kind});
}
for(const kind of ["icon","banner"]){
  app.post(`/api/servers/:serverId/${kind}`,requireAuth,uploadLimiter,(req,res,next)=>serverImageUpload.single("file")(req,res,err=>err?res.status(400).json({error:err.code==="LIMIT_FILE_SIZE"?"Server images are limited to 8 MB.":err.message}):next()),asyncRoute(async(req,res)=>storeServerImage(req,res,kind)));
  app.delete(`/api/servers/:serverId/${kind}`,requireAuth,asyncRoute(async(req,res)=>{const role=await getRole(req.params.serverId,req.session.userId);if(role!=="owner"&&role!=="admin")return res.status(403).json({error:"Manage Server permission required."});const col=kind==="icon"?"icon_url":"banner_url";await pool.query(`UPDATE servers SET ${col}='' WHERE id=$1`,[req.params.serverId]);emitServerChanged(req.params.serverId);res.json({ok:true})}));
}

app.delete("/api/servers/:serverId", requireAuth, asyncRoute(async (req, res) => {
  const role = await getRole(req.params.serverId, req.session.userId);
  if (role !== "owner") return res.status(403).json({ error: "Only the owner can delete the server." });
  const id = req.params.serverId;
  await pool.query("DELETE FROM servers WHERE id=$1", [id]); // cascades channels, messages, files, webhooks
  io.to(`server:${id}`).emit("server:removed", { serverId: id });
  io.in(`server:${id}`).socketsLeave(`server:${id}`);
  res.json({ ok: true });
}));

app.post("/api/servers/:serverId/leave", requireAuth, asyncRoute(async (req, res) => {
  const role = await getRole(req.params.serverId, req.session.userId);
  if (!role) return res.status(403).json({ error: "You are not a member of this server." });
  if (role === "owner") return res.status(400).json({ error: "Owners can't leave. Transfer ownership or delete the server instead." });
  await pool.query("DELETE FROM server_members WHERE server_id=$1 AND user_id=$2", [req.params.serverId, req.session.userId]);
  await removeUserFromServerRooms(req.params.serverId, req.session.userId);
  emitServerChanged(req.params.serverId);
  res.json({ ok: true });
}));

app.get("/api/servers/:serverId/members", requireAuth, asyncRoute(async (req, res) => {
  if (!(await getRole(req.params.serverId, req.session.userId))) return res.status(403).json({ error: "You are not a member of this server." });
  const result = await pool.query(`
    SELECT p.id,p.username,p.display_name,p.status_text,p.is_bot,p.avatar_url,p.banner_url,sm.role
    FROM server_members sm JOIN profiles p ON p.id=sm.user_id
    WHERE sm.server_id=$1 ORDER BY p.display_name LIMIT 500`, [req.params.serverId]);
  res.json({ members: result.rows.map(m => ({ ...m, online: online.has(m.id) })) });
}));

app.patch("/api/servers/:serverId/members/:userId", requireAuth, asyncRoute(async (req, res) => {
  const actor = await getRole(req.params.serverId, req.session.userId);
  if (actor !== "owner") return res.status(403).json({ error: "Only the owner can change roles." });
  const role = String(req.body.role || "");
  if (!["admin", "moderator", "member"].includes(role)) return res.status(400).json({ error: "Invalid role." });
  const target = await getRole(req.params.serverId, req.params.userId);
  if (!target) return res.status(404).json({ error: "Member not found." });
  if (target === "owner") return res.status(400).json({ error: "The owner's role can't be changed." });
  await pool.query("UPDATE server_members SET role=$3 WHERE server_id=$1 AND user_id=$2", [req.params.serverId, req.params.userId, role]);
  // Part 1 #3 — a demotion may revoke view access to hidden channels: evict those rooms.
  const chs = await pool.query("SELECT id,view_role FROM channels WHERE server_id=$1", [req.params.serverId]);
  for (const c of chs.rows) if (!canView(role, c.view_role)) await evictUserFromChannel(req.params.userId, c.id);
  emitServerChanged(req.params.serverId);
  res.json({ ok: true });
}));

app.delete("/api/servers/:serverId/members/:userId", requireAuth, asyncRoute(async (req, res) => {
  const actor = await getRole(req.params.serverId, req.session.userId);
  const target = await getRole(req.params.serverId, req.params.userId);
  if (!isMod(actor)) return res.status(403).json({ error: "Only moderators can remove members." });
  if (!target) return res.status(404).json({ error: "Member not found." });
  if (req.params.userId === req.session.userId) return res.status(400).json({ error: "Use Leave server instead." });
  if (RANK[actor] <= RANK[target]) return res.status(403).json({ error: "You can only remove members ranked below you." });
  await pool.query("DELETE FROM server_members WHERE server_id=$1 AND user_id=$2", [req.params.serverId, req.params.userId]);
  await removeUserFromServerRooms(req.params.serverId, req.params.userId);
  emitServerChanged(req.params.serverId);
  res.json({ ok: true });
}));

/* ---------- custom server emojis ---------- */
const emojiUpload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 256 * 1024, files: 1 }, fileFilter: (_req,file,cb) => new Set(["image/png","image/jpeg","image/gif","image/webp"]).has(file.mimetype) ? cb(null,true) : cb(new Error("Custom emojis must be PNG, JPEG, GIF, or WebP images.")) });
app.get("/api/servers/:serverId/emojis", requireAuth, asyncRoute(async(req,res)=>{
  if(!(await getRole(req.params.serverId,req.session.userId))) return res.status(403).json({error:"Server membership required."});
  const result=await pool.query("SELECT id,name,mime,created_at FROM server_custom_emojis WHERE server_id=$1 ORDER BY name",[req.params.serverId]);
  res.json({emojis:result.rows.map(e=>({...e,url:`/api/servers/${req.params.serverId}/emojis/${e.id}/image`}))});
}));
app.post("/api/servers/:serverId/emojis", requireAuth, uploadLimiter, (req,res,next)=>emojiUpload.single("file")(req,res,err=>err?res.status(400).json({error:err.code==="LIMIT_FILE_SIZE"?"Custom emojis are limited to 256 KB.":err.message}):next()), asyncRoute(async(req,res)=>{
  if(!(await requireServerPermission(req.params.serverId,req.session.userId,"manageServer"))) return res.status(403).json({error:"Manage Server permission required."});
  if(!req.file) return res.status(400).json({error:"Choose an emoji image."});
  const name=String(req.body.name||"").trim();
  if(!/^[a-zA-Z0-9_]{2,32}$/.test(name)) return res.status(400).json({error:"Emoji names must be 2–32 letters, numbers, or underscores."});
  const buffer=stripImageMetadata(req.file.buffer,req.file.mimetype);
  try {
    const result=await pool.query("INSERT INTO server_custom_emojis(server_id,name,mime,data,uploader_id) VALUES($1,$2,$3,$4,$5) RETURNING id,name,mime,created_at",[req.params.serverId,name,req.file.mimetype,buffer,req.session.userId]);
    const e=result.rows[0]; res.status(201).json({emoji:{...e,url:`/api/servers/${req.params.serverId}/emojis/${e.id}/image`}});
  } catch(err) { if(err.code==="23505") return res.status(409).json({error:"That emoji name is already in use on this server."}); throw err; }
}));
app.delete("/api/servers/:serverId/emojis/:emojiId", requireAuth, asyncRoute(async(req,res)=>{
  if(!(await requireServerPermission(req.params.serverId,req.session.userId,"manageServer"))) return res.status(403).json({error:"Manage Server permission required."});
  const result=await pool.query("DELETE FROM server_custom_emojis WHERE server_id=$1 AND id=$2 RETURNING id",[req.params.serverId,req.params.emojiId]);
  if(!result.rowCount) return res.status(404).json({error:"Custom emoji not found."}); res.json({ok:true});
}));
app.get("/api/servers/:serverId/emojis/:emojiId/image", requireAuth, asyncRoute(async(req,res)=>{
  if(!(await getRole(req.params.serverId,req.session.userId))) return res.status(404).end();
  const result=await pool.query("SELECT mime,data FROM server_custom_emojis WHERE server_id=$1 AND id=$2",[req.params.serverId,req.params.emojiId]);
  if(!result.rowCount) return res.status(404).end();
  res.set({"Content-Type":result.rows[0].mime,"Cache-Control":"private, max-age=300","X-Content-Type-Options":"nosniff"});res.send(result.rows[0].data);
}));

/* ---------- custom server roles and granular permissions ---------- */
const ROLE_PERMISSION_KEYS = Object.keys(DEFAULT_ROLE_PERMISSIONS);
function normalizePermissions(input) { const out={}; for(const key of ROLE_PERMISSION_KEYS) out[key]=input && typeof input[key]==="boolean" ? input[key] : DEFAULT_ROLE_PERMISSIONS[key]; return out; }
app.get("/api/servers/:serverId/roles", requireAuth, asyncRoute(async(req,res)=>{
  if(!(await getRole(req.params.serverId,req.session.userId))) return res.status(403).json({error:"Server membership required."});
  const result=await pool.query("SELECT id,name,color,position,permissions,created_at FROM server_custom_roles WHERE server_id=$1 ORDER BY position DESC,created_at",[req.params.serverId]);
  res.json({roles:result.rows,permissionKeys:ROLE_PERMISSION_KEYS});
}));
app.post("/api/servers/:serverId/roles", requireAuth, asyncRoute(async(req,res)=>{
  if(!(await requireServerPermission(req.params.serverId,req.session.userId,"manageRoles"))) return res.status(403).json({error:"Manage Roles permission required."});
  const name=clean(req.body.name,40), color=/^#[0-9a-f]{6}$/i.test(String(req.body.color||""))?req.body.color:"#8b5cf6";
  if(!name) return res.status(400).json({error:"Role name is required."});
  const result=await pool.query("INSERT INTO server_custom_roles(server_id,name,color,position,permissions) VALUES($1,$2,$3,COALESCE((SELECT MAX(position)+1 FROM server_custom_roles WHERE server_id=$1),1),$4::jsonb) RETURNING id,name,color,position,permissions",[req.params.serverId,name,color,JSON.stringify(normalizePermissions(req.body.permissions))]);
  emitServerChanged(req.params.serverId); res.status(201).json({role:result.rows[0]});
}));
app.patch("/api/servers/:serverId/roles/:roleId", requireAuth, asyncRoute(async(req,res)=>{
  if(!(await requireServerPermission(req.params.serverId,req.session.userId,"manageRoles"))) return res.status(403).json({error:"Manage Roles permission required."});
  const name=clean(req.body.name,40), color=/^#[0-9a-f]{6}$/i.test(String(req.body.color||""))?req.body.color:"#8b5cf6";
  if(!name) return res.status(400).json({error:"Role name is required."});
  const result=await pool.query("UPDATE server_custom_roles SET name=$3,color=$4,permissions=$5::jsonb WHERE server_id=$1 AND id=$2 RETURNING id,name,color,position,permissions",[req.params.serverId,req.params.roleId,name,color,JSON.stringify(normalizePermissions(req.body.permissions))]);
  if(!result.rowCount) return res.status(404).json({error:"Role not found."}); emitServerChanged(req.params.serverId); res.json({role:result.rows[0]});
}));
app.delete("/api/servers/:serverId/roles/:roleId", requireAuth, asyncRoute(async(req,res)=>{
  if(!(await requireServerPermission(req.params.serverId,req.session.userId,"manageRoles"))) return res.status(403).json({error:"Manage Roles permission required."});
  const result=await pool.query("DELETE FROM server_custom_roles WHERE server_id=$1 AND id=$2 RETURNING id",[req.params.serverId,req.params.roleId]);
  if(!result.rowCount) return res.status(404).json({error:"Role not found."}); emitServerChanged(req.params.serverId); res.json({ok:true});
}));
app.patch("/api/servers/:serverId/members/:userId/custom-role", requireAuth, asyncRoute(async(req,res)=>{
  if(!(await requireServerPermission(req.params.serverId,req.session.userId,"manageRoles"))) return res.status(403).json({error:"Manage Roles permission required."});
  const target=await getRole(req.params.serverId,req.params.userId); if(!target) return res.status(404).json({error:"Member not found."});
  if(target==="owner" || req.params.userId===req.session.userId) return res.status(403).json({error:"You cannot change this member's custom role."});
  const roleId=req.body.roleId||null;
  if(roleId){const r=await pool.query("SELECT id FROM server_custom_roles WHERE id=$1 AND server_id=$2",[roleId,req.params.serverId]);if(!r.rowCount)return res.status(400).json({error:"Role does not belong to this server."});}
  await pool.query("UPDATE server_members SET custom_role_id=$3 WHERE server_id=$1 AND user_id=$2",[req.params.serverId,req.params.userId,roleId]); emitServerChanged(req.params.serverId); res.json({ok:true});
}));

/* ---------- invites ---------- */
app.post("/api/servers/:serverId/invites", requireAuth, inviteLimiter, asyncRoute(async (req, res) => {
  const role = await getRole(req.params.serverId, req.session.userId);
  if (!isMod(role)) return res.status(403).json({ error: "Only moderators can create invites." });
  const maxUses = Math.max(0, Math.min(1000, parseInt(req.body.maxUses, 10) || 0)) || null;
  const hours = Math.max(0, Math.min(24 * 90, parseInt(req.body.expiresHours, 10) || 0));
  const code = crypto.randomBytes(6).toString("base64url");
  await pool.query(
    "INSERT INTO invites(code,server_id,created_by,max_uses,expires_at) VALUES($1,$2,$3,$4,CASE WHEN $5::int>0 THEN NOW()+make_interval(hours=>$5::int) END)",
    [code, req.params.serverId, req.session.userId, maxUses, hours]);
  res.status(201).json({ code });
}));

app.get("/api/servers/:serverId/invites", requireAuth, asyncRoute(async (req, res) => {
  const role = await getRole(req.params.serverId, req.session.userId);
  if (!isMod(role)) return res.status(403).json({ error: "Only moderators can view invites." });
  const r = await pool.query(
    "SELECT code,uses,max_uses,expires_at,created_at FROM invites WHERE server_id=$1 ORDER BY created_at DESC LIMIT 100", [req.params.serverId]);
  res.json({ invites: r.rows });
}));

app.delete("/api/servers/:serverId/invites/:code", requireAuth, asyncRoute(async (req, res) => {
  const role = await getRole(req.params.serverId, req.session.userId);
  if (!isMod(role)) return res.status(403).json({ error: "Only moderators can revoke invites." });
  const r = await pool.query("DELETE FROM invites WHERE server_id=$1 AND code=$2", [req.params.serverId, clean(req.params.code, 40)]);
  if (!r.rowCount) return res.status(404).json({ error: "Invite not found." });
  res.json({ ok: true });
}));

app.post("/api/invites/:code/join", requireAuth, authLimiter, asyncRoute(async (req, res) => {
  const code = clean(req.params.code, 40);
  const inv = await pool.query(`
    SELECT i.code,i.server_id FROM invites i
    WHERE i.code=$1 AND (i.expires_at IS NULL OR i.expires_at>NOW()) AND (i.max_uses IS NULL OR i.uses<i.max_uses)`, [code]);
  if (!inv.rowCount) return res.status(404).json({ error: "That invite is invalid or has expired." });
  const serverId = inv.rows[0].server_id;
  const ins = await pool.query("INSERT INTO server_members(server_id,user_id) VALUES($1,$2) ON CONFLICT DO NOTHING", [serverId, req.session.userId]);
  if (ins.rowCount) await pool.query("UPDATE invites SET uses=uses+1 WHERE code=$1", [code]);
  io.in(`user:${req.session.userId}`).socketsJoin(`server:${serverId}`);
  emitServerChanged(serverId);
  res.json({ ok: true, serverId });
}));

/* ---------- channels ---------- */
function normalizeChannelName(raw, kind) {
  let name = clean(raw, 100);
  return kind === "voice" ? name.replace(/\s+/g, " ") : name.toLowerCase().replace(/\s+/g, "-").replace(/[^a-z0-9_-]/g, "");
}

app.post("/api/servers/:serverId/channels", requireAuth, messageLimiter, asyncRoute(async (req, res) => {
  const kind = ["text", "voice", "announcement"].includes(req.body.kind) ? req.body.kind : "text";
  const name = normalizeChannelName(req.body.name, kind);
  const topic = clean(req.body.topic, 180);
  const viewRole = ["owner", "admin", "moderator", "member"].includes(req.body.viewRole) ? req.body.viewRole : "member";
  if (!name) return res.status(400).json({ error: "Enter a valid channel name." });
  const role = await getRole(req.params.serverId, req.session.userId);
  if (!role) return res.status(403).json({ error: "You are not a member of this server." });
  if (!isMod(role)) return res.status(403).json({ error: "Only server moderators can create channels." });
  try {
    const result = await pool.query(
      "INSERT INTO channels(server_id,name,kind,topic,view_role,position) VALUES($1,$2,$3,$4,$5,(SELECT COALESCE(MAX(position),-1)+1 FROM channels WHERE server_id=$1)) RETURNING id,name,kind,topic,position,view_role",
      [req.params.serverId, name, kind, topic, viewRole]);
    emitServerChanged(req.params.serverId);
    res.status(201).json({ channel: result.rows[0] });
  } catch (e) {
    if (e.code === "23505") return res.status(409).json({ error: "A channel with that name already exists." });
    throw e;
  }
}));

app.patch("/api/channels/:channelId", requireAuth, asyncRoute(async (req, res) => {
  const a = await channelAccess(req.params.channelId, req.session.userId);
  if (!a || !isMod(a.role)) return res.status(403).json({ error: "Only moderators can edit channels." });
  const name = normalizeChannelName(req.body.name, a.kind);
  if (!name) return res.status(400).json({ error: "Enter a valid channel name." });
  const viewRole = ["owner", "admin", "moderator", "member"].includes(req.body.viewRole) ? req.body.viewRole : a.view_role;
  try {
    await pool.query("UPDATE channels SET name=$2,topic=$3,view_role=$4 WHERE id=$1", [a.id, name, clean(req.body.topic, 180), viewRole]);
  } catch (e) {
    if (e.code === "23505") return res.status(409).json({ error: "A channel with that name already exists." });
    throw e;
  }
  // Part 1 #3 — raising view_role evicts members who can no longer view the channel.
  if (viewRole !== a.view_role) await evictLosingViewers(a.server_id);
  emitServerChanged(a.server_id);
  res.json({ ok: true });
}));

app.delete("/api/channels/:channelId", requireAuth, asyncRoute(async (req, res) => {
  const a = await channelAccess(req.params.channelId, req.session.userId);
  if (!a || !isMod(a.role)) return res.status(403).json({ error: "Only moderators can delete channels." });
  const count = await pool.query("SELECT COUNT(*)::int AS n FROM channels WHERE server_id=$1", [a.server_id]);
  if (count.rows[0].n <= 1) return res.status(400).json({ error: "A server needs at least one channel." });
  await pool.query("DELETE FROM channels WHERE id=$1", [a.id]); // cascades messages, files, webhooks
  io.in(`voice:${a.id}`).emit("voice:ended");
  io.in(`voice:${a.id}`).socketsLeave(`voice:${a.id}`);
  io.in(`channel:${a.id}`).socketsLeave(`channel:${a.id}`);
  emitServerChanged(a.server_id);
  res.json({ ok: true });
}));

/* ---------- files (Part 1 #2) ---------- */
const ALLOWED_MIME = new Set([
  "image/png", "image/jpeg", "image/gif", "image/webp",
  "application/pdf", "text/plain", "text/markdown", "text/csv",
  "application/zip", "audio/mpeg", "audio/ogg", "audio/wav", "video/mp4", "video/webm"
]);
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 8 * 1024 * 1024, files: 1 },
  fileFilter: (_req, file, cb) => ALLOWED_MIME.has(file.mimetype) ? cb(null, true) : cb(new Error("That file type isn't allowed."))
});

app.post("/api/files", requireAuth, uploadLimiter, (req, res, next) => {
  upload.single("file")(req, res, err => {
    if (err) return res.status(400).json({ error: err.code === "LIMIT_FILE_SIZE" ? "Files are limited to 8 MB." : err.message });
    next();
  });
}, asyncRoute(async (req, res) => {
  if (!req.file) return res.status(400).json({ error: "Choose a file to upload." });
  const filename = clean(req.file.originalname, 120) || "file";
  /* Phase 2 — image metadata (EXIF etc.) is stripped at upload, in both
   * storage modes, before the bytes go anywhere (see lib/exif.js). */
  const buffer = stripImageMetadata(req.file.buffer, req.file.mimetype);
  if (storage.storageMode() === "s3") {
    const key = storage.newObjectKey();
    try {
      await storage.putObject(key, buffer, req.file.mimetype);
    } catch (e) {
      console.error("Object-storage upload failed:", e.message);
      return res.status(502).json({ error: "Upload to object storage failed. Please try again." });
    }
    try {
      const r = await pool.query(
        "INSERT INTO files(uploader_id,filename,mime,size,storage,storage_key) VALUES($1,$2,$3,$4,'s3',$5) RETURNING id,filename,mime,size,created_at",
        [req.session.userId, filename, req.file.mimetype, buffer.length, key]);
      return res.status(201).json({ file: r.rows[0] });
    } catch (e) {
      // The object landed but the row didn't — remove it again rather than leak it.
      try { await storage.deleteObject(key); } catch { /* the sweep reconciles leftovers */ }
      throw e;
    }
  }
  const r = await pool.query(
    "INSERT INTO files(uploader_id,filename,mime,size,data) VALUES($1,$2,$3,$4,$5) RETURNING id,filename,mime,size,created_at",
    [req.session.userId, filename, req.file.mimetype, buffer.length, buffer]);
  res.status(201).json({ file: r.rows[0] });
}));

/* Attach helper: only the uploader can attach, only while unattached, max 4. */
async function claimAttachments(ids, userId, client) {
  if (ids == null) return [];
  if (!Array.isArray(ids)) throw Object.assign(new Error("attachmentIds must be an array."), { status: 400 });
  if (ids.length > 4) throw Object.assign(new Error("At most 4 attachments per message."), { status: 400 });
  const q = client || pool;
  const out = [];
  for (const id of ids) {
    if (!UUID_RE.test(String(id))) throw Object.assign(new Error("Invalid attachment id."), { status: 400 });
    const r = await q.query("SELECT id FROM files WHERE id=$1 AND uploader_id=$2 AND message_id IS NULL AND dm_message_id IS NULL", [id, userId]);
    if (!r.rowCount) throw Object.assign(new Error("An attachment is missing, already used, or isn't yours."), { status: 400 });
    out.push(id);
  }
  return out;
}

app.get("/api/files/:fileId", requireAuth, asyncRoute(async (req, res) => {
  console.info(`[image-file] request fileId=${req.params.fileId} user=${req.session.userId}`);
  const r = await pool.query("SELECT * FROM files WHERE id=$1", [req.params.fileId]);
  const f = r.rows[0];
  if (!f) { console.warn(`[image-file] missing fileId=${req.params.fileId}`); return res.status(404).json({ error: "Not found." }); }
  /* Access: the uploader; members who can view the channel the message is in
   * (view_role enforced by channelAccess); or members of the DM it was sent in.
   * Everyone else gets 404 so the endpoint doesn't confirm a file exists. */
  let allowed = f.uploader_id === req.session.userId;
  if (!allowed) { const profileAsset = await pool.query("SELECT 1 FROM profiles WHERE (avatar_url=$1 OR banner_url=$1) LIMIT 1", [`/api/files/${f.id}`]); allowed = profileAsset.rowCount > 0; }
  if (!allowed) { const serverAsset = await pool.query("SELECT s.id FROM servers s JOIN server_members sm ON sm.server_id=s.id WHERE (s.icon_url=$1 OR s.banner_url=$1) AND sm.user_id=$2 LIMIT 1", [`/api/files/${f.id}`, req.session.userId]); allowed = serverAsset.rowCount > 0; }
  if (!allowed && f.message_id) {
    const m = await pool.query("SELECT channel_id FROM messages WHERE id=$1", [f.message_id]);
    if (m.rowCount) allowed = !!(await channelAccess(m.rows[0].channel_id, req.session.userId));
  }
  if (!allowed && f.dm_message_id) {
    const m = await pool.query("SELECT conversation_id FROM dm_messages WHERE id=$1", [f.dm_message_id]);
    if (m.rowCount) allowed = await dmAccess(m.rows[0].conversation_id, req.session.userId);
  }
  if (!allowed) { console.warn(`[image-file] denied fileId=${f.id} user=${req.session.userId} uploader=${f.uploader_id}`); return res.status(404).json({ error: "Not found." }); }
  /* Phase 2 — S3-backed files: the permission check above always runs first;
   * only then do we hand out a short-lived signed URL (the bucket itself is
   * never public). If the row says S3 but this server has no S3 configured,
   * say so plainly instead of pretending the file is gone. */
  if (f.storage === "s3") {
    if (!f.storage_key || storage.storageMode() !== "s3") {
      return res.status(503).json({ error: "This file lives in object storage, which isn't configured on this server right now." });
    }
    const url = await storage.signedDownloadUrl(f.storage_key, 300);
    res.set({ "Cache-Control": "private, no-store" });
    return res.redirect(302, url);
  }
  if (!f.data) { console.error(`[image-file] no database data fileId=${f.id} storage=${f.storage}`); return res.status(410).json({ error: "File data is not available." }); }
  const inline = f.mime.startsWith("image/") || f.mime === "application/pdf";
  res.set({
    "Content-Type": f.mime,
    "Content-Length": f.size,
    "Content-Disposition": `${inline ? "inline" : "attachment"}; filename="${f.filename.replace(/["\r\n]/g, "")}"`,
    "Content-Security-Policy": "sandbox",
    "X-Content-Type-Options": "nosniff",
    "Cache-Control": "private, no-store"
  });
  console.info(`[image-file] served fileId=${f.id} mime=${f.mime} bytes=${f.size}`);
  res.send(f.data);
}));

/* ---------- messages ---------- */
app.get("/api/channels/:channelId/messages", requireAuth, asyncRoute(async (req, res) => {
  const a = await channelAccess(req.params.channelId, req.session.userId);
  if (!a) return res.status(403).json({ error: "You do not have access to this channel." });
  const params = [req.params.channelId];
  let where = "m.channel_id=$1";
  const cursor = decodeCursor(req.query.cursor || req.query.before);
  if (cursor) { params.push(cursor.t, cursor.id); where += ` AND (m.created_at, m.id) < ($${params.length - 1}, $${params.length})`; }
  const q = clean(req.query.q, 100);
  if (q) { params.push(`%${q.replace(/[\\%_]/g, "\\$&")}%`); where += ` AND m.content ILIKE $${params.length}`; }
  const result = await pool.query(`${MSG_SELECT} WHERE ${where} ORDER BY m.created_at DESC, m.id DESC LIMIT 50`, params);
  const rows = result.rows.reverse();
  res.json({ messages: rows, hasMore: result.rowCount === 50, nextCursor: rows.length ? encodeCursor(rows[0]) : null });
}));

app.post("/api/channels/:channelId/messages", requireAuth, messageLimiter, userMessageLimiter, asyncRoute(async (req, res) => {
  const content = clean(req.body.content, 2000);
  const a = await channelAccess(req.params.channelId, req.session.userId);
  if (!a || a.kind === "voice") return res.status(403).json({ error: "You do not have access to this text channel." });
  if (a.kind === "announcement" && !isMod(a.role)) return res.status(403).json({ error: "Only moderators can post in announcement channels." });
  let attachments;
  try { attachments = await claimAttachments(req.body.attachmentIds, req.session.userId); }
  catch (e) { return res.status(e.status || 400).json({ error: e.message }); }
  if (!content && !attachments.length) return res.status(400).json({ error: "Message cannot be empty." });
  let replyTo = null;
  if (req.body.replyTo && UUID_RE.test(String(req.body.replyTo))) {
    const r = await pool.query("SELECT id FROM messages WHERE id=$1 AND channel_id=$2", [req.body.replyTo, a.id]);
    if (r.rowCount) replyTo = r.rows[0].id;
  }
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const ins = await client.query(
      "INSERT INTO messages(channel_id,author_id,content,reply_to) VALUES($1,$2,$3,$4) RETURNING id",
      [a.id, req.session.userId, content || "(attachment)", replyTo]);
    if (attachments.length) await client.query("UPDATE files SET message_id=$1 WHERE id=ANY($2::uuid[])", [ins.rows[0].id, attachments]);
    await client.query("COMMIT");
    const message = await fetchMessage(ins.rows[0].id);
    io.to(`channel:${a.id}`).emit("message:new", message);
    res.status(201).json({ message });
  } catch (e) { await client.query("ROLLBACK"); throw e; } finally { client.release(); }
}));

async function messageContext(messageId, userId) {
  const r = await pool.query(`
    SELECT m.id,m.author_id,m.channel_id,c.server_id,c.kind,sm.role
    FROM messages m JOIN channels c ON c.id=m.channel_id
    JOIN server_members sm ON sm.server_id=c.server_id AND sm.user_id=$2
    WHERE m.id=$1`, [messageId, userId]);
  const row = r.rows[0] || null;
  if (row) {
    const ch = await pool.query("SELECT view_role FROM channels WHERE id=$1", [row.channel_id]);
    if (!canView(row.role, ch.rows[0]?.view_role)) return null;
  }
  return row;
}

app.patch("/api/messages/:messageId", requireAuth, messageLimiter, asyncRoute(async (req, res) => {
  const ctx = await messageContext(req.params.messageId, req.session.userId);
  if (!ctx) return res.status(404).json({ error: "Message not found." });
  if (ctx.author_id !== req.session.userId) return res.status(403).json({ error: "You can only edit your own messages." });
  const content = clean(req.body.content, 2000);
  if (!content) return res.status(400).json({ error: "Message cannot be empty." });
  await pool.query("UPDATE messages SET content=$2,edited_at=NOW() WHERE id=$1", [ctx.id, content]);
  const message = await fetchMessage(ctx.id);
  io.to(`channel:${ctx.channel_id}`).emit("message:update", message);
  res.json({ message });
}));

app.delete("/api/messages/:messageId", requireAuth, messageLimiter, asyncRoute(async (req, res) => {
  const ctx = await messageContext(req.params.messageId, req.session.userId);
  if (!ctx) return res.status(404).json({ error: "Message not found." });
  if (ctx.author_id !== req.session.userId && !isMod(ctx.role)) return res.status(403).json({ error: "You can't delete this message." });
  await pool.query("DELETE FROM messages WHERE id=$1", [ctx.id]); // attached files cascade-delete with the message
  io.to(`channel:${ctx.channel_id}`).emit("message:delete", { id: ctx.id, channel_id: ctx.channel_id });
  res.json({ ok: true });
}));

app.put("/api/messages/:messageId/reactions", requireAuth, messageLimiter, asyncRoute(async (req, res) => {
  const ctx = await messageContext(req.params.messageId, req.session.userId);
  if (!ctx) return res.status(404).json({ error: "Message not found." });
  const emoji = clean(req.body.emoji, 16);
  if (!emoji) return res.status(400).json({ error: "Pick an emoji." });
  const del = await pool.query("DELETE FROM message_reactions WHERE message_id=$1 AND user_id=$2 AND emoji=$3", [ctx.id, req.session.userId, emoji]);
  if (!del.rowCount) {
    const n = await pool.query("SELECT COUNT(DISTINCT emoji)::int AS n FROM message_reactions WHERE message_id=$1", [ctx.id]);
    if (n.rows[0].n >= 20) return res.status(400).json({ error: "That message has too many different reactions." });
    await pool.query("INSERT INTO message_reactions(message_id,user_id,emoji) VALUES($1,$2,$3) ON CONFLICT DO NOTHING", [ctx.id, req.session.userId, emoji]);
  }
  const message = await fetchMessage(ctx.id);
  io.to(`channel:${ctx.channel_id}`).emit("message:update", message);
  res.json({ message });
}));

/* ---------- webhooks & bot profiles (Part 1 #8) ---------- */
app.post("/api/channels/:channelId/webhooks", requireAuth, messageLimiter, asyncRoute(async (req, res) => {
  const a = await channelAccess(req.params.channelId, req.session.userId);
  if (!a || !isMod(a.role)) return res.status(403).json({ error: "Only moderators can create webhooks." });
  const name = clean(req.body.name, 32) || "Talkz Webhook";
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    let bot = null;
    for (let attempt = 0; attempt < 5 && !bot; attempt++) {
      const uname = `bot_${crypto.randomBytes(4).toString("hex")}`;
      try {
        bot = (await client.query(
          "INSERT INTO profiles(username,display_name,password_hash,is_bot) VALUES($1,$2,$3,true) RETURNING id,username",
          [uname, name, await bcrypt.hash(crypto.randomBytes(32).toString("hex"), 12)])).rows[0];
      } catch (e) { if (e.code !== "23505") throw e; }
    }
    if (!bot) throw new Error("Could not allocate a bot username.");
    const token = crypto.randomBytes(32).toString("base64url");
    const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
    const wh = await client.query(
      "INSERT INTO webhooks(channel_id,name,bot_user_id,token_hash,created_by) VALUES($1,$2,$3,$4,$5) RETURNING id,channel_id,name,created_at",
      [a.id, name, bot.id, tokenHash, req.session.userId]);
    await client.query("COMMIT");
    res.status(201).json({ webhook: wh.rows[0], token, url: `/api/webhooks/${wh.rows[0].id}/${token}`, note: "The token is shown once. Store it now." });
  } catch (e) { await client.query("ROLLBACK"); throw e; } finally { client.release(); }
}));

app.get("/api/channels/:channelId/webhooks", requireAuth, asyncRoute(async (req, res) => {
  const a = await channelAccess(req.params.channelId, req.session.userId);
  if (!a || !isMod(a.role)) return res.status(403).json({ error: "Only moderators can view webhooks." });
  const r = await pool.query("SELECT id,channel_id,name,created_at FROM webhooks WHERE channel_id=$1 ORDER BY created_at", [a.id]);
  res.json({ webhooks: r.rows });
}));

app.delete("/api/webhooks/:webhookId", requireAuth, asyncRoute(async (req, res) => {
  const wh = await pool.query("SELECT w.*,c.server_id FROM webhooks w JOIN channels c ON c.id=w.channel_id WHERE w.id=$1", [req.params.webhookId]);
  if (!wh.rowCount) return res.status(404).json({ error: "Webhook not found." });
  const role = await getRole(wh.rows[0].server_id, req.session.userId);
  if (!isMod(role)) return res.status(403).json({ error: "Only moderators can delete webhooks." });
  const botId = wh.rows[0].bot_user_id;
  const tomb = botId ? await tombstoneBotId() : null; // outside the tx below: tombstone creation is idempotent and harmless if the tx rolls back
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    if (botId) {
      // Keep the messages, re-attributed to "Deleted Bot", then remove the bot profile.
      await client.query("UPDATE messages SET author_id=$2 WHERE author_id=$1", [botId, tomb]);
      await client.query("DELETE FROM profiles WHERE id=$1", [botId]);
    }
    await client.query("DELETE FROM webhooks WHERE id=$1", [req.params.webhookId]);
    await client.query("COMMIT");
  } catch (e) { await client.query("ROLLBACK"); throw e; } finally { client.release(); }
  res.json({ ok: true });
}));

app.post("/api/webhooks/:webhookId/:token", webhookLimiter, asyncRoute(async (req, res) => {
  const wh = await pool.query("SELECT * FROM webhooks WHERE id=$1", [req.params.webhookId]);
  if (!wh.rowCount || !wh.rows[0].bot_user_id) return res.status(404).json({ error: "Webhook not found." });
  const given = crypto.createHash("sha256").update(String(req.params.token)).digest();
  const stored = Buffer.from(wh.rows[0].token_hash, "hex");
  if (given.length !== stored.length || !crypto.timingSafeEqual(given, stored)) return res.status(401).json({ error: "Invalid webhook token." });
  const content = clean(req.body.content, 2000);
  if (!content) return res.status(400).json({ error: "Message cannot be empty." });
  const ins = await pool.query("INSERT INTO messages(channel_id,author_id,content) VALUES($1,$2,$3) RETURNING id", [wh.rows[0].channel_id, wh.rows[0].bot_user_id, content]);
  const message = await fetchMessage(ins.rows[0].id);
  io.to(`channel:${wh.rows[0].channel_id}`).emit("message:new", message);
  res.status(201).json({ message });
}));

/* ---------- voice state (REST snapshot, view-filtered) ---------- */
app.get("/api/servers/:serverId/voice", requireAuth, asyncRoute(async (req, res) => {
  const role = await getRole(req.params.serverId, req.session.userId);
  if (!role) return res.status(403).json({ error: "You are not a member of this server." });
  const ch = await pool.query("SELECT id,view_role FROM channels WHERE server_id=$1 AND kind='voice'", [req.params.serverId]);
  const voice = {};
  for (const c of ch.rows) if (canView(role, c.view_role)) voice[c.id] = await voiceUsers(c.id);
  res.json({ voice });
}));

/* Public discovery exposes only servers explicitly marked public, never private channels. */
app.get("/api/discovery/servers", requireAuth, asyncRoute(async(req,res)=>{
 const q=clean(req.query.q,80).toLowerCase();
 const r=await pool.query(`SELECT s.id,s.name,s.description,s.accent_color,COUNT(sm.user_id)::int AS member_count
   FROM servers s LEFT JOIN server_members sm ON sm.server_id=s.id
   WHERE s.visibility='public' AND ($1='' OR lower(s.name) LIKE '%'||$1||'%' OR lower(s.description) LIKE '%'||$1||'%')
   GROUP BY s.id ORDER BY member_count DESC,s.name LIMIT 50`,[q]);res.json({servers:r.rows});
}));
app.get("/api/search", requireAuth, asyncRoute(async(req,res)=>{
 const q=clean(req.query.q,120);if(q.length<2)return res.json({messages:[],users:[]});
 const pattern=`%${q.replace(/[\%_]/g,"\\$&")}%`;
 const [messages,users]=await Promise.all([
  pool.query(`SELECT m.id,m.content,m.created_at,c.id AS channel_id,c.name AS channel_name,s.id AS server_id,s.name AS server_name,p.username,p.display_name
   FROM messages m JOIN channels c ON c.id=m.channel_id JOIN servers s ON s.id=c.server_id
   JOIN server_members sm ON sm.server_id=s.id AND sm.user_id=$1 JOIN profiles p ON p.id=m.author_id
   WHERE m.content ILIKE $2 AND (sm.role IS NOT NULL) ORDER BY m.created_at DESC LIMIT 50`,[req.session.userId,pattern]),
  pool.query(`SELECT id,username,display_name,status_text,bio,accent_color FROM profiles WHERE is_bot=false AND id<>$1 AND (username ILIKE $2 OR display_name ILIKE $2) AND NOT EXISTS(SELECT 1 FROM user_blocks b WHERE (b.user_id=$1 AND b.blocked_user_id=profiles.id) OR (b.user_id=profiles.id AND b.blocked_user_id=$1)) ORDER BY username LIMIT 20`,[req.session.userId,pattern])
 ]);res.json({messages:messages.rows,users:users.rows});
}));
app.get("/api/servers/:serverId/stats", requireAuth, asyncRoute(async(req,res)=>{
 const role=await getRole(req.params.serverId,req.session.userId);if(!isMod(role))return res.status(403).json({error:"Moderator permission required."});
 const r=await pool.query(`SELECT (SELECT COUNT(*)::int FROM server_members WHERE server_id=$1) AS members,
 (SELECT COUNT(*)::int FROM channels WHERE server_id=$1) AS channels,
 (SELECT COUNT(*)::int FROM messages m JOIN channels c ON c.id=m.channel_id WHERE c.server_id=$1) AS messages,
 (SELECT COUNT(*)::int FROM server_members WHERE server_id=$1 AND joined_at>NOW()-INTERVAL '7 days') AS new_members`,[req.params.serverId]);res.json({stats:r.rows[0]});
}));

/* ---------- direct messages ---------- */
const DM_MSG_SELECT = `
  SELECT m.id,m.conversation_id,m.content,m.created_at,p.id AS user_id,p.username,p.display_name,p.is_bot,
    COALESCE((SELECT json_agg(json_build_object('id',f.id,'filename',f.filename,'mime',f.mime,'size',f.size) ORDER BY f.created_at)
      FROM files f WHERE f.dm_message_id=m.id),'[]') AS attachments
  FROM dm_messages m JOIN profiles p ON p.id=m.author_id`;

app.get("/api/dms", requireAuth, asyncRoute(async (req, res) => {
  const r = await pool.query(`
    SELECT c.id,p.id AS user_id,p.username,p.display_name,
      (SELECT content FROM dm_messages WHERE conversation_id=c.id ORDER BY created_at DESC LIMIT 1) AS last_content,
      COALESCE((SELECT created_at FROM dm_messages WHERE conversation_id=c.id ORDER BY created_at DESC LIMIT 1),c.created_at) AS last_at
    FROM dm_members me
    JOIN dm_conversations c ON c.id=me.conversation_id
    JOIN dm_members other ON other.conversation_id=c.id AND other.user_id<>me.user_id
    JOIN profiles p ON p.id=other.user_id
    WHERE me.user_id=$1 ORDER BY last_at DESC LIMIT 100`, [req.session.userId]);
  res.json({ conversations: r.rows.map(x => ({ ...x, online: online.has(x.user_id) })) });
}));

app.post("/api/dms", requireAuth, dmStartLimiter, asyncRoute(async (req, res) => {
  const username = clean(req.body.username, 24).toLowerCase().replace(/^@/, "");
  // Part 1 #8 — bot profiles (webhooks, the Deleted Bot tombstone) can never be DM'd or found here.
  const u = await pool.query("SELECT id,username,display_name FROM profiles WHERE username=$1 AND is_bot=false", [username]);
  if (!u.rowCount) return res.status(404).json({ error: "No user with that username." });
  const other = u.rows[0];
  if (other.id === req.session.userId) return res.status(400).json({ error: "You can't message yourself." });
  const block = await pool.query("SELECT 1 FROM user_blocks WHERE (user_id=$1 AND blocked_user_id=$2) OR (user_id=$2 AND blocked_user_id=$1)", [req.session.userId, other.id]);
  if (block.rowCount) return res.status(403).json({ error: "You cannot start a conversation with this user." });
  const privacy = await pool.query("SELECT privacy FROM profiles WHERE id=$1", [other.id]);
  const dmPolicy = privacy.rows[0]?.privacy?.dm || "everyone";
  if (dmPolicy === "none") return res.status(403).json({ error: "This user is not accepting direct messages." });
  if (dmPolicy === "friends") {
    const friend = await pool.query("SELECT 1 FROM friend_requests WHERE status='accepted' AND ((requester_id=$1 AND recipient_id=$2) OR (requester_id=$2 AND recipient_id=$1))", [req.session.userId, other.id]);
    if (!friend.rowCount) return res.status(403).json({ error: "This user only accepts direct messages from friends." });
  }
  const existing = await pool.query(`
    SELECT a.conversation_id AS id FROM dm_members a JOIN dm_members b ON a.conversation_id=b.conversation_id
    WHERE a.user_id=$1 AND b.user_id=$2 LIMIT 1`, [req.session.userId, other.id]);
  let id = existing.rows[0]?.id;
  if (!id) {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      id = (await client.query("INSERT INTO dm_conversations DEFAULT VALUES RETURNING id")).rows[0].id;
      await client.query("INSERT INTO dm_members(conversation_id,user_id) VALUES($1,$2),($1,$3)", [id, req.session.userId, other.id]);
      await client.query("COMMIT");
    } catch (e) { await client.query("ROLLBACK"); throw e; } finally { client.release(); }
  }
  res.json({ conversation: { id, user_id: other.id, username: other.username, display_name: other.display_name } });
}));

app.get("/api/dms/:conversationId/messages", requireAuth, asyncRoute(async (req, res) => {
  if (!(await dmAccess(req.params.conversationId, req.session.userId))) return res.status(403).json({ error: "You do not have access to this conversation." });
  const params = [req.params.conversationId];
  let where = "m.conversation_id=$1";
  const cursor = decodeCursor(req.query.cursor || req.query.before);
  if (cursor) { params.push(cursor.t, cursor.id); where += ` AND (m.created_at, m.id) < ($${params.length - 1}, $${params.length})`; }
  const r = await pool.query(`${DM_MSG_SELECT} WHERE ${where} ORDER BY m.created_at DESC, m.id DESC LIMIT 50`, params);
  const rows = r.rows.reverse();
  res.json({ messages: rows, hasMore: r.rowCount === 50, nextCursor: rows.length ? encodeCursor(rows[0]) : null });
}));

app.post("/api/dms/:conversationId/messages", requireAuth, messageLimiter, userMessageLimiter, asyncRoute(async (req, res) => {
  const content = clean(req.body.content, 2000);
  if (!(await dmAccess(req.params.conversationId, req.session.userId))) return res.status(403).json({ error: "You do not have access to this conversation." });
  let attachments;
  try { attachments = await claimAttachments(req.body.attachmentIds, req.session.userId); }
  catch (e) { return res.status(e.status || 400).json({ error: e.message }); }
  if (!content && !attachments.length) return res.status(400).json({ error: "Message cannot be empty." });
  const client = await pool.connect();
  let message;
  try {
    await client.query("BEGIN");
    const ins = await client.query("INSERT INTO dm_messages(conversation_id,author_id,content) VALUES($1,$2,$3) RETURNING id", [req.params.conversationId, req.session.userId, content || "(attachment)"]);
    if (attachments.length) await client.query("UPDATE files SET dm_message_id=$1 WHERE id=ANY($2::uuid[])", [ins.rows[0].id, attachments]);
    await client.query("COMMIT");
    message = (await pool.query(`${DM_MSG_SELECT} WHERE m.id=$1`, [ins.rows[0].id])).rows[0];
  } catch (e) { await client.query("ROLLBACK"); throw e; } finally { client.release(); }
  const members = await pool.query("SELECT user_id FROM dm_members WHERE conversation_id=$1", [req.params.conversationId]);
  members.rows.forEach(m => io.to(`user:${m.user_id}`).emit("dm:new", message));
  res.status(201).json({ message });
}));

/* DM message deletion and pins. Only the author may delete their own DM; all conversation members may pin/unpin. */
app.delete("/api/dms/:conversationId/messages/:messageId", requireAuth, asyncRoute(async(req,res)=>{
  if (!(await dmAccess(req.params.conversationId, req.session.userId))) return res.status(403).json({error:"You do not have access to this conversation."});
  const r=await pool.query("DELETE FROM dm_messages WHERE id=$1 AND conversation_id=$2 AND author_id=$3 RETURNING id",[req.params.messageId,req.params.conversationId,req.session.userId]);
  if(!r.rowCount)return res.status(404).json({error:"Message not found or you cannot delete it."});
  const members=await pool.query("SELECT user_id FROM dm_members WHERE conversation_id=$1",[req.params.conversationId]);
  members.rows.forEach(m=>io.to(`user:${m.user_id}`).emit("dm:delete",{conversationId:req.params.conversationId,id:req.params.messageId}));
  res.json({ok:true});
}));
app.get("/api/dms/:conversationId/pins", requireAuth, asyncRoute(async(req,res)=>{
  if (!(await dmAccess(req.params.conversationId, req.session.userId))) return res.status(403).json({error:"You do not have access to this conversation."});
  const r=await pool.query(`${DM_MSG_SELECT} JOIN dm_message_pins pin ON pin.message_id=m.id WHERE m.conversation_id=$1 ORDER BY pin.created_at DESC LIMIT 100`,[req.params.conversationId]);
  res.json({messages:r.rows});
}));
app.put("/api/dms/:conversationId/messages/:messageId/pin", requireAuth, asyncRoute(async(req,res)=>{
  if (!(await dmAccess(req.params.conversationId, req.session.userId))) return res.status(403).json({error:"You do not have access to this conversation."});
  const m=await pool.query("SELECT id FROM dm_messages WHERE id=$1 AND conversation_id=$2",[req.params.messageId,req.params.conversationId]);
  if(!m.rowCount)return res.status(404).json({error:"Message not found."});
  if(req.body.pinned===false) await pool.query("DELETE FROM dm_message_pins WHERE message_id=$1 AND conversation_id=$2",[req.params.messageId,req.params.conversationId]);
  else await pool.query("INSERT INTO dm_message_pins(message_id,conversation_id,pinned_by) VALUES($1,$2,$3) ON CONFLICT(message_id) DO NOTHING",[req.params.messageId,req.params.conversationId,req.session.userId]);
  const members=await pool.query("SELECT user_id FROM dm_members WHERE conversation_id=$1",[req.params.conversationId]);
  members.rows.forEach(m=>io.to(`user:${m.user_id}`).emit("dm:pins:changed",{conversationId:req.params.conversationId}));
  res.json({ok:true,pinned:req.body.pinned!==false});
}));

/* ---------- realtime: presence, typing, voice signalling ---------- */
const online = new Map(); // userId -> open socket count
const voiceRoster = new Map(); // socketId -> { channelId, serverId, userId, displayName, muted, deafened, speaking }

async function voiceUsers(channelId) {
  const ids = io.sockets.adapter.rooms.get(`voice:${channelId}`) || new Set();
  return [...ids].map(id => voiceRoster.get(id) ? { socketId: id, ...voiceRoster.get(id) } : null).filter(Boolean)
    .map(e => ({ socketId: e.socketId, userId: e.userId, displayName: e.displayName, muted: e.muted, deafened: e.deafened, speaking: e.speaking }));
}
/* Part 1 #3 — voice:participants goes ONLY to server members who can view that
 * channel (previously broadcast to the whole server room, leaking hidden channels). */
async function broadcastVoice(channelId, serverId) {
  const ch = await pool.query("SELECT view_role FROM channels WHERE id=$1", [channelId]);
  if (!ch.rowCount) return;
  const roles = new Map((await pool.query("SELECT user_id,role FROM server_members WHERE server_id=$1", [serverId])).rows.map(r => [r.user_id, r.role]));
  const users = await voiceUsers(channelId);
  const socks = await io.in(`server:${serverId}`).fetchSockets();
  for (const s of socks) {
    if (canView(roles.get(s.data.userId), ch.rows[0].view_role)) s.emit("voice:participants", { channelId, users });
  }
}
async function leaveVoice(socket) {
  const v = voiceRoster.get(socket.id);
  if (!v) return;
  voiceRoster.delete(socket.id);
  socket.leave(`voice:${v.channelId}`);
  socket.to(`voice:${v.channelId}`).emit("voice:peer-left", socket.id);
  try { await broadcastVoice(v.channelId, v.serverId); } catch (e) { console.error("Voice broadcast failed:", e.message); }
}

io.use(async (socket, next) => {
  try {
    const sess = socket.request.session;
    if (!sess || !sess.userId) return next(new Error("Sign in required"));
    socket.userId = sess.userId;
    const u = await pool.query("SELECT display_name FROM profiles WHERE id=$1", [socket.userId]);
    if (!u.rowCount) return next(new Error("Sign in required"));
    socket.displayName = u.rows[0].display_name;
    socket.data.userId = socket.userId;
    socket.data.displayName = socket.displayName;
    const s = await pool.query("SELECT server_id FROM server_members WHERE user_id=$1", [socket.userId]);
    socket.serverIds = s.rows.map(r => r.server_id);
    next();
  } catch (e) { next(new Error("Connection failed")); }
});

io.on("connection", socket => {
  const uid = socket.userId;
  socket.join(`user:${uid}`);
  socket.serverIds.forEach(id => socket.join(`server:${id}`));
  const n = (online.get(uid) || 0) + 1;
  online.set(uid, n);
  if (n === 1) socket.serverIds.forEach(id => io.to(`server:${id}`).emit("presence", { userId: uid, online: true }));

  socket.on("channel:join", async channelId => {
    try {
      if (typeof channelId !== "string" || !UUID_RE.test(channelId)) return;
      const a = await channelAccess(channelId, uid);
      if (a) {
        for (const room of socket.rooms) if (room.startsWith("channel:")) socket.leave(room);
        socket.join(`channel:${channelId}`);
      }
    } catch (e) { console.error("Socket channel join failed:", e.message); }
  });

  /* Part 1 #5 — leaving the server view leaves the channel room, so a client in
   * DM view stops receiving (and rendering against) server-channel traffic. */
  socket.on("channel:leave", () => {
    for (const room of socket.rooms) if (room.startsWith("channel:")) socket.leave(room);
  });

  socket.on("typing", channelId => {
    if (typeof channelId !== "string" || !socket.rooms.has(`channel:${channelId}`)) return;
    socket.to(`channel:${channelId}`).emit("typing", { channelId, userId: uid, name: socket.displayName });
  });

  socket.on("dm:typing", conversationId => {
    if (typeof conversationId !== "string" || !UUID_RE.test(conversationId)) return;
    dmAccess(conversationId, uid).then(ok => {
      if (!ok) return;
      pool.query("SELECT user_id FROM dm_members WHERE conversation_id=$1 AND user_id<>$2", [conversationId, uid])
        .then(r => r.rows.forEach(m => io.to(`user:${m.user_id}`).emit("dm:typing", { conversationId, userId: uid, name: socket.displayName })))
        .catch(() => {});
    }).catch(() => {});
  });

  socket.on("voice:join", async channelId => {
    try {
      if (typeof channelId !== "string" || !UUID_RE.test(channelId)) return;
      const a = await channelAccess(channelId, uid);
      if (!a || a.kind !== "voice") return;
      const current = voiceRoster.get(socket.id);
      if (current && current.channelId === channelId) { // idempotent re-join after reconnect
        socket.emit("voice:peers", (await voiceUsers(channelId)).filter(p => p.socketId !== socket.id));
        return;
      }
      await leaveVoice(socket);
      const peers = await voiceUsers(channelId);
      if (peers.length >= 8) return socket.emit("voice:full");
      voiceRoster.set(socket.id, { channelId, serverId: a.server_id, userId: uid, displayName: socket.displayName, muted: false, deafened: false, speaking: false });
      socket.join(`voice:${channelId}`);
      socket.emit("voice:peers", peers);
      await broadcastVoice(channelId, a.server_id);
    } catch (e) { console.error("Voice join failed:", e.message); }
  });
  socket.on("voice:leave", () => { leaveVoice(socket); });

  /* Part 1 #6 — mute/deafen and speaking state are shared with other participants. */
  socket.on("voice:state", state => {
    const v = voiceRoster.get(socket.id);
    if (!v || !state || typeof state !== "object") return;
    if (typeof state.muted === "boolean") v.muted = state.muted;
    if (typeof state.deafened === "boolean") v.deafened = state.deafened;
    socket.to(`voice:${v.channelId}`).emit("voice:state", { socketId: socket.id, userId: uid, muted: v.muted, deafened: v.deafened });
    broadcastVoice(v.channelId, v.serverId).catch(() => {});
  });
  socket.on("voice:speaking", payload => {
    const v = voiceRoster.get(socket.id);
    if (!v) return;
    const speaking = !!(payload && payload.speaking);
    if (v.speaking === speaking) return;
    v.speaking = speaking;
    socket.to(`voice:${v.channelId}`).emit("voice:speaking", { socketId: socket.id, userId: uid, speaking });
  });

  socket.on("voice:signal", payload => {
    const { to, data } = payload || {};
    const v = voiceRoster.get(socket.id);
    if (!v || typeof to !== "string" || !data || typeof data !== "object") return;
    if (!io.sockets.adapter.rooms.get(`voice:${v.channelId}`)?.has(to)) return;
    io.to(to).emit("voice:signal", { from: socket.id, userId: uid, displayName: socket.displayName, data });
  });

  socket.on("disconnecting", () => {
    leaveVoice(socket);
    const rooms = [...socket.rooms].filter(r => r.startsWith("server:"));
    const left = (online.get(uid) || 1) - 1;
    if (left <= 0) {
      online.delete(uid);
      rooms.forEach(r => io.to(r).emit("presence", { userId: uid, online: false }));
    } else online.set(uid, left);
  });
});

/* Unknown /api routes must 404 as JSON — the SPA fallback below otherwise masks
 * them with a 200 HTML page (found in smoke-testing: /api/ice "existed" as HTML). */
app.use("/api", (_req, res) => res.status(404).json({ error: "Not found." }));
app.use(express.static(path.join(__dirname, "public"), { extensions: ["html"] }));
app.get("*", (_req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));
app.use((err, _req, res, _next) => {
  console.error(err);
  if (res.headersSent) return;
  res.status(err.status || 500).json({ error: err.status ? err.message : "Something went wrong. Please try again." });
});

if (require.main === module) {
  initializeDatabase().then(() => {
    cleanupOrphanFiles();
    const timer = setInterval(cleanupOrphanFiles, 15 * 60 * 1000);
    timer.unref();
    server.listen(PORT, "0.0.0.0", () => console.log(`Talkz Cloud listening on ${PORT}`));
  }).catch(err => {
    console.error("Database initialization failed:", err);
    process.exit(1);
  });
  process.on("SIGTERM", async () => { server.close(); await pool.end(); });
}

module.exports = { app, server, io, pool, initializeDatabase, cleanupOrphanFiles, encodeCursor, decodeCursor, canView, RANK, totp, storage };
