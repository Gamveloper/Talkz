const path = require("path");
const http = require("http");
const crypto = require("crypto");
const express = require("express");
const helmet = require("helmet");
const session = require("express-session");
const pgSession = require("connect-pg-simple")(session);
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const { Server } = require("socket.io");
const rateLimit = require("express-rate-limit");

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

app.set("trust proxy", process.env.TRUST_PROXY === "true" ? 1 : false);
app.disable("x-powered-by");
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "https://cdn.socket.io"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com", "data:"],
      imgSrc: ["'self'", "data:", "https:"],
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

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, limit: 30, standardHeaders: "draft-7", legacyHeaders: false,
  message: { error: "Too many attempts. Please wait a little and try again." }
});
const messageLimiter = rateLimit({
  windowMs: 60 * 1000, limit: 60, standardHeaders: true, legacyHeaders: false,
  message: { error: "You're doing that too fast. Slow down a little." }
});

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
for (const name of ["serverId", "channelId", "messageId", "conversationId", "userId"]) {
  app.param(name, (_req, res, next, val) => UUID_RE.test(val) ? next() : res.status(404).json({ error: "Not found." }));
}

const asyncRoute = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const clean = (value, max = 100) => String(value ?? "").replace(/\u0000/g, "").trim().slice(0, max);
const userPublic = row => ({ id: row.id, username: row.username, displayName: row.display_name, statusText: row.status_text || "", createdAt: row.created_at });
const RANK = { owner: 3, admin: 2, moderator: 1, member: 0 };
const isMod = role => (RANK[role] ?? -1) >= 1;

function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: "Sign in to continue." });
  next();
}
async function getRole(serverId, userId) {
  const r = await pool.query("SELECT role FROM server_members WHERE server_id=$1 AND user_id=$2", [serverId, userId]);
  return r.rows[0]?.role || null;
}
async function channelAccess(channelId, userId) {
  const r = await pool.query(`
    SELECT c.id,c.server_id,c.kind,sm.role FROM channels c
    JOIN server_members sm ON sm.server_id=c.server_id
    WHERE c.id=$1 AND sm.user_id=$2`, [channelId, userId]);
  return r.rows[0] || null;
}
async function dmAccess(conversationId, userId) {
  const r = await pool.query("SELECT 1 FROM dm_members WHERE conversation_id=$1 AND user_id=$2", [conversationId, userId]);
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

const MSG_SELECT = `
  SELECT m.id,m.channel_id,m.content,m.created_at,m.edited_at,m.reply_to,
    p.id AS user_id,p.username,p.display_name,
    rm.content AS reply_content, rp.display_name AS reply_name,
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
    CREATE TABLE IF NOT EXISTS servers (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      name TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 80),
      owner_id UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS server_members (
      server_id UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
      user_id UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
      role TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('owner','admin','moderator','member')),
      joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY(server_id,user_id)
    );
    CREATE TABLE IF NOT EXISTS channels (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      server_id UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
      name TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100),
      kind TEXT NOT NULL DEFAULT 'text' CHECK (kind IN ('text','voice','announcement')),
      topic TEXT NOT NULL DEFAULT '',
      position INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
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
  `);
  try {
    await pool.query("CREATE UNIQUE INDEX IF NOT EXISTS channels_server_name_idx ON channels(server_id,lower(name))");
  } catch (e) { console.warn("Could not add unique channel-name index (duplicates exist?):", e.message); }
  console.log("Talkz database is ready.");
}

/* ---------- health & auth ---------- */
app.get("/api/health", asyncRoute(async (_req, res) => {
  await pool.query("SELECT 1");
  res.json({ ok: true, app: "Talkz Cloud", database: "connected" });
}));

app.post("/api/auth/register", authLimiter, asyncRoute(async (req, res) => {
  const username = clean(req.body.username, 24).toLowerCase();
  const displayName = clean(req.body.displayName || req.body.username, 32);
  const password = String(req.body.password || "");
  if (!/^[a-z0-9_]{3,24}$/.test(username)) return res.status(400).json({ error: "Username must be 3–24 characters using letters, numbers, or underscores." });
  if (password.length < 10 || password.length > 72) return res.status(400).json({ error: "Password must be between 10 and 72 characters." });
  if (displayName.length < 1) return res.status(400).json({ error: "Enter a display name." });
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const passwordHash = await bcrypt.hash(password, 12);
    const inserted = await client.query(
      "INSERT INTO profiles(username,display_name,password_hash) VALUES($1,$2,$3) RETURNING id,username,display_name,status_text,created_at",
      [username, displayName, passwordHash]);
    const user = inserted.rows[0];
    const starter = await createStarterServer(client, user.id, displayName);
    await client.query("COMMIT");
    req.session.userId = user.id;
    req.session.save(err => {
      if (err) return res.status(500).json({ error: "Account created, but session could not be saved. Please sign in." });
      res.status(201).json({ user: userPublic(user), starterServerId: starter.id });
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
  const result = await pool.query("SELECT * FROM profiles WHERE username=$1", [username]);
  const user = result.rows[0];
  if (!user || !(await bcrypt.compare(password, user.password_hash))) return res.status(401).json({ error: "Incorrect username or password." });
  req.session.regenerate(err => {
    if (err) return res.status(500).json({ error: "Could not start your session." });
    req.session.userId = user.id;
    req.session.save(saveErr => {
      if (saveErr) return res.status(500).json({ error: "Could not save your session." });
      res.json({ user: userPublic(user) });
    });
  });
}));

app.post("/api/auth/logout", requireAuth, (req, res, next) => {
  req.session.destroy(err => {
    if (err) return next(err);
    res.clearCookie("talkz.sid", { httpOnly: true, sameSite: "lax", secure: isProduction });
    res.json({ ok: true });
  });
});

app.get("/api/me", asyncRoute(async (req, res) => {
  if (!req.session.userId) return res.json({ user: null });
  const result = await pool.query("SELECT id,username,display_name,status_text,created_at FROM profiles WHERE id=$1", [req.session.userId]);
  res.json({ user: result.rows[0] ? userPublic(result.rows[0]) : null });
}));

app.patch("/api/me", requireAuth, messageLimiter, asyncRoute(async (req, res) => {
  const displayName = clean(req.body.displayName, 32);
  const statusText = clean(req.body.statusText, 60);
  if (!displayName) return res.status(400).json({ error: "Display name can't be empty." });
  const r = await pool.query("UPDATE profiles SET display_name=$2,status_text=$3 WHERE id=$1 RETURNING id,username,display_name,status_text,created_at", [req.session.userId, displayName, statusText]);
  const rooms = await pool.query("SELECT server_id FROM server_members WHERE user_id=$1", [req.session.userId]);
  rooms.rows.forEach(x => emitServerChanged(x.server_id));
  res.json({ user: userPublic(r.rows[0]) });
}));

/* ---------- servers ---------- */
app.get("/api/servers", requireAuth, asyncRoute(async (req, res) => {
  const result = await pool.query(`
    SELECT s.id,s.name,s.owner_id,s.created_at,sm.role,
      COALESCE(json_agg(json_build_object('id',c.id,'name',c.name,'kind',c.kind,'topic',c.topic,'position',c.position)
        ORDER BY c.position,c.created_at) FILTER (WHERE c.id IS NOT NULL),'[]') AS channels
    FROM server_members sm JOIN servers s ON s.id=sm.server_id
    LEFT JOIN channels c ON c.server_id=s.id
    WHERE sm.user_id=$1
    GROUP BY s.id,s.name,s.owner_id,s.created_at,sm.role
    ORDER BY s.created_at`, [req.session.userId]);
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
    const c = await client.query("INSERT INTO channels(server_id,name,topic,position) VALUES($1,'general','The place for everything.',0) RETURNING id,name,kind,topic,position", [srv.id]);
    const v = await client.query("INSERT INTO channels(server_id,name,kind,topic,position) VALUES($1,'Lounge','voice','Hang out and talk.',1) RETURNING id,name,kind,topic,position", [srv.id]);
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
  await pool.query("UPDATE servers SET name=$2 WHERE id=$1", [req.params.serverId, name]);
  emitServerChanged(req.params.serverId);
  res.json({ ok: true });
}));

app.delete("/api/servers/:serverId", requireAuth, asyncRoute(async (req, res) => {
  const role = await getRole(req.params.serverId, req.session.userId);
  if (role !== "owner") return res.status(403).json({ error: "Only the owner can delete the server." });
  const id = req.params.serverId;
  await pool.query("DELETE FROM servers WHERE id=$1", [id]);
  io.to(`server:${id}`).emit("server:removed", { serverId: id });
  io.in(`server:${id}`).socketsLeave(`server:${id}`);
  res.json({ ok: true });
}));

app.post("/api/servers/:serverId/leave", requireAuth, asyncRoute(async (req, res) => {
  const role = await getRole(req.params.serverId, req.session.userId);
  if (!role) return res.status(403).json({ error: "You are not a member of this server." });
  if (role === "owner") return res.status(400).json({ error: "Owners can't leave. Delete the server instead." });
  await pool.query("DELETE FROM server_members WHERE server_id=$1 AND user_id=$2", [req.params.serverId, req.session.userId]);
  await removeUserFromServerRooms(req.params.serverId, req.session.userId);
  emitServerChanged(req.params.serverId);
  res.json({ ok: true });
}));

app.get("/api/servers/:serverId/members", requireAuth, asyncRoute(async (req, res) => {
  if (!(await getRole(req.params.serverId, req.session.userId))) return res.status(403).json({ error: "You are not a member of this server." });
  const result = await pool.query(`
    SELECT p.id,p.username,p.display_name,p.status_text,sm.role
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

/* ---------- invites (replaces the old open /join endpoint) ---------- */
app.post("/api/servers/:serverId/invites", requireAuth, messageLimiter, asyncRoute(async (req, res) => {
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
app.post("/api/servers/:serverId/channels", requireAuth, messageLimiter, asyncRoute(async (req, res) => {
  const kind = ["text", "voice", "announcement"].includes(req.body.kind) ? req.body.kind : "text";
  let name = clean(req.body.name, 100);
  name = kind === "voice" ? name.replace(/\s+/g, " ") : name.toLowerCase().replace(/\s+/g, "-").replace(/[^a-z0-9_-]/g, "");
  const topic = clean(req.body.topic, 180);
  if (!name) return res.status(400).json({ error: "Enter a valid channel name." });
  const role = await getRole(req.params.serverId, req.session.userId);
  if (!role) return res.status(403).json({ error: "You are not a member of this server." });
  if (!isMod(role)) return res.status(403).json({ error: "Only server moderators can create channels." });
  try {
    const result = await pool.query(
      "INSERT INTO channels(server_id,name,kind,topic,position) VALUES($1,$2,$3,$4,(SELECT COALESCE(MAX(position),-1)+1 FROM channels WHERE server_id=$1)) RETURNING id,name,kind,topic,position",
      [req.params.serverId, name, kind, topic]);
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
  let name = clean(req.body.name, 100);
  name = a.kind === "voice" ? name.replace(/\s+/g, " ") : name.toLowerCase().replace(/\s+/g, "-").replace(/[^a-z0-9_-]/g, "");
  if (!name) return res.status(400).json({ error: "Enter a valid channel name." });
  try {
    await pool.query("UPDATE channels SET name=$2,topic=$3 WHERE id=$1", [a.id, name, clean(req.body.topic, 180)]);
  } catch (e) {
    if (e.code === "23505") return res.status(409).json({ error: "A channel with that name already exists." });
    throw e;
  }
  emitServerChanged(a.server_id);
  res.json({ ok: true });
}));

app.delete("/api/channels/:channelId", requireAuth, asyncRoute(async (req, res) => {
  const a = await channelAccess(req.params.channelId, req.session.userId);
  if (!a || !isMod(a.role)) return res.status(403).json({ error: "Only moderators can delete channels." });
  const count = await pool.query("SELECT COUNT(*)::int AS n FROM channels WHERE server_id=$1", [a.server_id]);
  if (count.rows[0].n <= 1) return res.status(400).json({ error: "A server needs at least one channel." });
  await pool.query("DELETE FROM channels WHERE id=$1", [a.id]);
  io.in(`voice:${a.id}`).emit("voice:ended");
  io.in(`voice:${a.id}`).socketsLeave(`voice:${a.id}`);
  io.in(`channel:${a.id}`).socketsLeave(`channel:${a.id}`);
  emitServerChanged(a.server_id);
  res.json({ ok: true });
}));

/* ---------- messages ---------- */
app.get("/api/channels/:channelId/messages", requireAuth, asyncRoute(async (req, res) => {
  const a = await channelAccess(req.params.channelId, req.session.userId);
  if (!a) return res.status(403).json({ error: "You do not have access to this channel." });
  const params = [req.params.channelId];
  let where = "m.channel_id=$1";
  if (req.query.before) {
    const d = new Date(String(req.query.before));
    if (!isNaN(d)) { params.push(d.toISOString()); where += ` AND m.created_at < $${params.length}`; }
  }
  const q = clean(req.query.q, 100);
  if (q) { params.push(`%${q.replace(/[\\%_]/g, "\\$&")}%`); where += ` AND m.content ILIKE $${params.length}`; }
  const result = await pool.query(`${MSG_SELECT} WHERE ${where} ORDER BY m.created_at DESC LIMIT 50`, params);
  res.json({ messages: result.rows.reverse(), hasMore: result.rowCount === 50 });
}));

app.post("/api/channels/:channelId/messages", requireAuth, messageLimiter, asyncRoute(async (req, res) => {
  const content = clean(req.body.content, 2000);
  if (!content) return res.status(400).json({ error: "Message cannot be empty." });
  const a = await channelAccess(req.params.channelId, req.session.userId);
  if (!a || a.kind === "voice") return res.status(403).json({ error: "You do not have access to this text channel." });
  if (a.kind === "announcement" && !isMod(a.role)) return res.status(403).json({ error: "Only moderators can post in announcement channels." });
  let replyTo = null;
  if (req.body.replyTo && UUID_RE.test(String(req.body.replyTo))) {
    const r = await pool.query("SELECT id FROM messages WHERE id=$1 AND channel_id=$2", [req.body.replyTo, a.id]);
    if (r.rowCount) replyTo = r.rows[0].id;
  }
  const ins = await pool.query("INSERT INTO messages(channel_id,author_id,content,reply_to) VALUES($1,$2,$3,$4) RETURNING id", [a.id, req.session.userId, content, replyTo]);
  const message = await fetchMessage(ins.rows[0].id);
  io.to(`channel:${a.id}`).emit("message:new", message);
  res.status(201).json({ message });
}));

async function messageContext(messageId, userId) {
  const r = await pool.query(`
    SELECT m.id,m.author_id,m.channel_id,c.server_id,c.kind,sm.role
    FROM messages m JOIN channels c ON c.id=m.channel_id
    JOIN server_members sm ON sm.server_id=c.server_id AND sm.user_id=$2
    WHERE m.id=$1`, [messageId, userId]);
  return r.rows[0] || null;
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
  await pool.query("DELETE FROM messages WHERE id=$1", [ctx.id]);
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

/* ---------- voice state ---------- */
app.get("/api/servers/:serverId/voice", requireAuth, asyncRoute(async (req, res) => {
  if (!(await getRole(req.params.serverId, req.session.userId))) return res.status(403).json({ error: "You are not a member of this server." });
  const ch = await pool.query("SELECT id FROM channels WHERE server_id=$1 AND kind='voice'", [req.params.serverId]);
  const voice = {};
  for (const c of ch.rows) voice[c.id] = await voiceUsers(c.id);
  res.json({ voice });
}));

/* ---------- direct messages ---------- */
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

app.post("/api/dms", requireAuth, messageLimiter, asyncRoute(async (req, res) => {
  const username = clean(req.body.username, 24).toLowerCase().replace(/^@/, "");
  const u = await pool.query("SELECT id,username,display_name FROM profiles WHERE username=$1", [username]);
  if (!u.rowCount) return res.status(404).json({ error: "No user with that username." });
  const other = u.rows[0];
  if (other.id === req.session.userId) return res.status(400).json({ error: "You can't message yourself." });
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
  if (req.query.before) {
    const d = new Date(String(req.query.before));
    if (!isNaN(d)) { params.push(d.toISOString()); where += ` AND m.created_at < $${params.length}`; }
  }
  const r = await pool.query(`
    SELECT m.id,m.conversation_id,m.content,m.created_at,p.id AS user_id,p.username,p.display_name
    FROM dm_messages m JOIN profiles p ON p.id=m.author_id
    WHERE ${where} ORDER BY m.created_at DESC LIMIT 50`, params);
  res.json({ messages: r.rows.reverse(), hasMore: r.rowCount === 50 });
}));

app.post("/api/dms/:conversationId/messages", requireAuth, messageLimiter, asyncRoute(async (req, res) => {
  const content = clean(req.body.content, 2000);
  if (!content) return res.status(400).json({ error: "Message cannot be empty." });
  if (!(await dmAccess(req.params.conversationId, req.session.userId))) return res.status(403).json({ error: "You do not have access to this conversation." });
  const ins = await pool.query("INSERT INTO dm_messages(conversation_id,author_id,content) VALUES($1,$2,$3) RETURNING id,conversation_id,content,created_at", [req.params.conversationId, req.session.userId, content]);
  const me = await pool.query("SELECT id,username,display_name FROM profiles WHERE id=$1", [req.session.userId]);
  const message = { ...ins.rows[0], user_id: me.rows[0].id, username: me.rows[0].username, display_name: me.rows[0].display_name };
  const members = await pool.query("SELECT user_id FROM dm_members WHERE conversation_id=$1", [req.params.conversationId]);
  members.rows.forEach(m => io.to(`user:${m.user_id}`).emit("dm:new", message));
  res.status(201).json({ message });
}));

/* ---------- realtime: presence, typing, voice signalling ---------- */
const online = new Map(); // userId -> open socket count

async function voiceUsers(channelId) {
  const socks = await io.in(`voice:${channelId}`).fetchSockets();
  return socks.map(s => ({ socketId: s.id, userId: s.userId, displayName: s.displayName }));
}
async function broadcastVoice(channelId, serverId) {
  io.to(`server:${serverId}`).emit("voice:participants", { channelId, users: await voiceUsers(channelId) });
}
async function leaveVoice(socket) {
  const v = socket.voice;
  if (!v) return;
  socket.voice = null;
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

  socket.on("typing", channelId => {
    if (typeof channelId !== "string" || !socket.rooms.has(`channel:${channelId}`)) return;
    socket.to(`channel:${channelId}`).emit("typing", { channelId, userId: uid, name: socket.displayName });
  });

  socket.on("voice:join", async channelId => {
    try {
      if (typeof channelId !== "string" || !UUID_RE.test(channelId)) return;
      const a = await channelAccess(channelId, uid);
      if (!a || a.kind !== "voice") return;
      await leaveVoice(socket);
      const peers = await voiceUsers(channelId);
      if (peers.length >= 8) return socket.emit("voice:full");
      socket.voice = { channelId, serverId: a.server_id };
      socket.join(`voice:${channelId}`);
      socket.emit("voice:peers", peers);
      await broadcastVoice(channelId, a.server_id);
    } catch (e) { console.error("Voice join failed:", e.message); }
  });
  socket.on("voice:leave", () => { leaveVoice(socket); });
  socket.on("voice:signal", payload => {
    const { to, data } = payload || {};
    if (!socket.voice || typeof to !== "string" || !data || typeof data !== "object") return;
    if (!io.sockets.adapter.rooms.get(`voice:${socket.voice.channelId}`)?.has(to)) return;
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

app.use(express.static(path.join(__dirname, "public"), { extensions: ["html"] }));
app.get("*", (_req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));
app.use((err, _req, res, _next) => {
  console.error(err);
  if (res.headersSent) return;
  res.status(500).json({ error: "Something went wrong. Please try again." });
});

initializeDatabase().then(() => {
  server.listen(PORT, "0.0.0.0", () => console.log(`Talkz Cloud listening on ${PORT}`));
}).catch(err => {
  console.error("Database initialization failed:", err);
  process.exit(1);
});

process.on("SIGTERM", async () => {
  server.close();
  await pool.end();
});
