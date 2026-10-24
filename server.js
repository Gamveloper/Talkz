const path = require("path");
const http = require("http");
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
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"]
    }
  }
}));
app.use(express.json({ limit: "30kb" }));

const sessionMiddleware = session({
  store: new pgSession({
    pool,
    tableName: "user_sessions",
    createTableIfMissing: true
  }),
  name: "talkz.sid",
  secret: process.env.SESSION_SECRET || "local-development-only-change-me",
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: {
    httpOnly: true,
    secure: isProduction,
    sameSite: "lax",
    maxAge: 1000 * 60 * 60 * 24 * 14
  }
});
app.use(sessionMiddleware);
io.engine.use(sessionMiddleware);

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { error: "Too many attempts. Please wait a little and try again." }
});
const messageLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 45,
  standardHeaders: true,
  legacyHeaders: false
});

const asyncRoute = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const clean = (value, max = 100) => String(value ?? "").trim().slice(0, max);
const userPublic = row => ({ id: row.id, username: row.username, displayName: row.display_name, createdAt: row.created_at });
function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: "Sign in to continue." });
  next();
}
async function isMember(serverId, userId) {
  const result = await pool.query("SELECT 1 FROM server_members WHERE server_id=$1 AND user_id=$2", [serverId, userId]);
  return result.rowCount > 0;
}
async function createStarterServer(client, userId, displayName) {
  const serverName = `${displayName}'s space`.slice(0, 80);
  const s = await client.query(
    "INSERT INTO servers(name, owner_id) VALUES($1,$2) RETURNING id,name,owner_id,created_at",
    [serverName, userId]
  );
  const srv = s.rows[0];
  await client.query("INSERT INTO server_members(server_id,user_id,role) VALUES($1,$2,'owner')", [srv.id, userId]);
  await client.query("INSERT INTO channels(server_id,name,kind,topic,position) VALUES($1,'general','text','The place for everything.',0)", [srv.id]);
  return srv;
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
    CREATE INDEX IF NOT EXISTS messages_channel_created_idx ON messages(channel_id,created_at DESC);
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
  console.log("Talkz database is ready.");
}

app.get("/api/health", asyncRoute(async (_req, res) => {
  await pool.query("SELECT 1");
  res.json({ ok: true, app: "Talkz Cloud", database: "connected" });
}));

app.post("/api/auth/register", authLimiter, asyncRoute(async (req, res) => {
  const username = clean(req.body.username, 24).toLowerCase();
  const displayName = clean(req.body.displayName || req.body.username, 32);
  const password = String(req.body.password || "");
  if (!/^[a-z0-9_]{3,24}$/.test(username)) {
    return res.status(400).json({ error: "Username must be 3–24 characters using letters, numbers, or underscores." });
  }
  if (password.length < 10 || password.length > 72) {
    return res.status(400).json({ error: "Password must be between 10 and 72 characters." });
  }
  if (displayName.length < 1) return res.status(400).json({ error: "Enter a display name." });
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const passwordHash = await bcrypt.hash(password, 12);
    const inserted = await client.query(
      "INSERT INTO profiles(username,display_name,password_hash) VALUES($1,$2,$3) RETURNING id,username,display_name,created_at",
      [username, displayName, passwordHash]
    );
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
  } finally {
    client.release();
  }
}));

app.post("/api/auth/login", authLimiter, asyncRoute(async (req, res) => {
  const username = clean(req.body.username, 24).toLowerCase();
  const password = String(req.body.password || "");
  const result = await pool.query("SELECT * FROM profiles WHERE username=$1", [username]);
  const user = result.rows[0];
  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    return res.status(401).json({ error: "Incorrect username or password." });
  }
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
  const result = await pool.query("SELECT id,username,display_name,created_at FROM profiles WHERE id=$1", [req.session.userId]);
  res.json({ user: result.rows[0] ? userPublic(result.rows[0]) : null });
}));

app.get("/api/servers", requireAuth, asyncRoute(async (req, res) => {
  const result = await pool.query(`
    SELECT s.id,s.name,s.owner_id,s.created_at,sm.role,
      COALESCE(json_agg(json_build_object('id',c.id,'name',c.name,'kind',c.kind,'topic',c.topic,'position',c.position)
        ORDER BY c.position,c.created_at) FILTER (WHERE c.id IS NOT NULL),'[]') AS channels
    FROM server_members sm JOIN servers s ON s.id=sm.server_id
    LEFT JOIN channels c ON c.server_id=s.id
    WHERE sm.user_id=$1
    GROUP BY s.id,s.name,s.owner_id,s.created_at,sm.role
    ORDER BY s.created_at
  `, [req.session.userId]);
  res.json({ servers: result.rows });
}));

app.post("/api/servers", requireAuth, asyncRoute(async (req, res) => {
  const name = clean(req.body.name, 80);
  if (!name) return res.status(400).json({ error: "Server name is required." });
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const s = await client.query("INSERT INTO servers(name,owner_id) VALUES($1,$2) RETURNING id,name,owner_id,created_at", [name, req.session.userId]);
    const srv = s.rows[0];
    await client.query("INSERT INTO server_members(server_id,user_id,role) VALUES($1,$2,'owner')", [srv.id, req.session.userId]);
    const c = await client.query("INSERT INTO channels(server_id,name,topic,position) VALUES($1,'general','The place for everything.',0) RETURNING id,name,kind,topic,position", [srv.id]);
    await client.query("COMMIT");
    srv.channels = [c.rows[0]];
    res.status(201).json({ server: srv });
  } catch (e) {
    await client.query("ROLLBACK");
    throw e;
  } finally { client.release(); }
}));

app.post("/api/servers/:serverId/join", requireAuth, asyncRoute(async (req, res) => {
  const exists = await pool.query("SELECT id FROM servers WHERE id=$1", [req.params.serverId]);
  if (!exists.rowCount) return res.status(404).json({ error: "Server not found." });
  await pool.query("INSERT INTO server_members(server_id,user_id) VALUES($1,$2) ON CONFLICT DO NOTHING", [req.params.serverId, req.session.userId]);
  res.json({ ok: true });
}));

app.post("/api/servers/:serverId/channels", requireAuth, asyncRoute(async (req, res) => {
  const name = clean(req.body.name, 100).toLowerCase().replace(/\s+/g, "-").replace(/[^a-z0-9_-]/g, "");
  const topic = clean(req.body.topic, 180);
  if (!name) return res.status(400).json({ error: "Enter a valid channel name." });
  const membership = await pool.query("SELECT role FROM server_members WHERE server_id=$1 AND user_id=$2", [req.params.serverId, req.session.userId]);
  if (!membership.rowCount) return res.status(403).json({ error: "You are not a member of this server." });
  if (!["owner","admin","moderator"].includes(membership.rows[0].role)) return res.status(403).json({ error: "Only server moderators can create channels." });
  try {
    const result = await pool.query("INSERT INTO channels(server_id,name,topic,position) VALUES($1,$2,$3,(SELECT COALESCE(MAX(position),-1)+1 FROM channels WHERE server_id=$1)) RETURNING id,name,kind,topic,position", [req.params.serverId, name, topic]);
    res.status(201).json({ channel: result.rows[0] });
  } catch (e) {
    if (e.code === "23505") return res.status(409).json({ error: "A channel with that name already exists." });
    throw e;
  }
}));

app.get("/api/channels/:channelId/messages", requireAuth, asyncRoute(async (req, res) => {
  const access = await pool.query(`
    SELECT c.id FROM channels c JOIN server_members sm ON sm.server_id=c.server_id
    WHERE c.id=$1 AND sm.user_id=$2
  `, [req.params.channelId, req.session.userId]);
  if (!access.rowCount) return res.status(403).json({ error: "You do not have access to this channel." });
  const result = await pool.query(`
    SELECT m.id,m.channel_id,m.content,m.created_at,p.id AS user_id,p.username,p.display_name
    FROM messages m JOIN profiles p ON p.id=m.author_id
    WHERE m.channel_id=$1 ORDER BY m.created_at DESC LIMIT 100
  `, [req.params.channelId]);
  res.json({ messages: result.rows.reverse() });
}));

app.post("/api/channels/:channelId/messages", requireAuth, messageLimiter, asyncRoute(async (req, res) => {
  const content = clean(req.body.content, 2000);
  if (!content) return res.status(400).json({ error: "Message cannot be empty." });
  const access = await pool.query(`
    SELECT c.id,c.server_id FROM channels c JOIN server_members sm ON sm.server_id=c.server_id
    WHERE c.id=$1 AND sm.user_id=$2 AND c.kind <> 'voice'
  `, [req.params.channelId, req.session.userId]);
  if (!access.rowCount) return res.status(403).json({ error: "You do not have access to this text channel." });
  const result = await pool.query(`
    INSERT INTO messages(channel_id,author_id,content) VALUES($1,$2,$3)
    RETURNING id,channel_id,content,created_at
  `, [req.params.channelId, req.session.userId, content]);
  const row = result.rows[0];
  const userResult = await pool.query("SELECT id,username,display_name FROM profiles WHERE id=$1", [req.session.userId]);
  const message = { ...row, user_id: userResult.rows[0].id, username: userResult.rows[0].username, display_name: userResult.rows[0].display_name };
  io.to(`channel:${req.params.channelId}`).emit("message:new", message);
  res.status(201).json({ message });
}));

app.get("/api/servers/:serverId/members", requireAuth, asyncRoute(async (req, res) => {
  if (!(await isMember(req.params.serverId, req.session.userId))) return res.status(403).json({ error: "You are not a member of this server." });
  const result = await pool.query(`
    SELECT p.id,p.username,p.display_name,sm.role
    FROM server_members sm JOIN profiles p ON p.id=sm.user_id
    WHERE sm.server_id=$1 ORDER BY p.display_name LIMIT 200
  `, [req.params.serverId]);
  res.json({ members: result.rows });
}));

io.use((socket, next) => {
  const sess = socket.request.session;
  if (!sess || !sess.userId) return next(new Error("Sign in required"));
  socket.userId = sess.userId;
  next();
});
io.on("connection", socket => {
  socket.on("channel:join", async channelId => {
    try {
      if (typeof channelId !== "string" || channelId.length > 80) return;
      const result = await pool.query(`
        SELECT c.id FROM channels c JOIN server_members sm ON sm.server_id=c.server_id
        WHERE c.id=$1 AND sm.user_id=$2
      `, [channelId, socket.userId]);
      if (result.rowCount) {
        for (const room of socket.rooms) if (room.startsWith("channel:")) socket.leave(room);
        socket.join(`channel:${channelId}`);
      }
    } catch (e) { console.error("Socket channel join failed:", e.message); }
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
