/* Talkz Cloud — Phase 1 integration tests.
 * Run: TEST_DATABASE_URL=postgres://user:pass@localhost:5432/talkz_test npm test
 * The test database is WIPED at start. Never point this at a real database.
 * Covers: permissions, hidden channels, invites, member removal ("kick"; a ban
 * feature does not exist yet — it arrives with the moderation phase), file
 * access control + orphan cleanup, compound-cursor pagination, CSRF, webhooks/
 * bots, voice-participant leaks, and account basics.
 */
process.env.DATABASE_URL = process.env.TEST_DATABASE_URL || "postgres://postgres:talkz@localhost:5432/talkz_test";
process.env.SESSION_SECRET = process.env.SESSION_SECRET || "test-secret";
process.env.NODE_ENV = "test";
process.env.TRUST_PROXY = "false";
process.env.AUTH_RATE_LIMIT = "1000"; // the suite registers many throwaway users from one IP

const { test, before, after } = require("node:test");
const assert = require("node:assert");
const { io: ioClient } = require("socket.io-client");
const { server, pool, initializeDatabase, cleanupOrphanFiles } = require("../server.js");

let base;
function client() {
  let cookie = "";
  async function req(method, path, body, opts = {}) {
    const headers = { ...(cookie ? { Cookie: cookie } : {}), ...(opts.headers || {}) };
    if (!opts.noCsrf && method !== "GET") headers["X-Requested-With"] = "fetch";
    let payload;
    if (opts.form) payload = opts.form;
    else if (body !== undefined) { headers["Content-Type"] = "application/json"; payload = JSON.stringify(body); }
    const res = await fetch(base + path, { method, headers, body: payload });
    const sc = res.headers.get("set-cookie");
    if (sc) cookie = sc.split(";")[0];
    let data = {};
    const text = await res.text();
    try { data = JSON.parse(text); } catch { data = { raw: text }; }
    return { status: res.status, data, text };
  }
  return { req, cookie: () => cookie };
}
const uniq = p => `${p}_${Date.now().toString(36)}${Math.floor(Math.random() * 1e4)}`;
async function makeUser(prefix) {
  const c = client();
  const username = uniq(prefix);
  const r = await c.req("POST", "/api/auth/register", { username, displayName: prefix, password: "password1234" });
  assert.equal(r.status, 201, JSON.stringify(r.data));
  return { c, user: r.data.user, starterServerId: r.data.starterServerId, username };
}
async function getServer(c, id) {
  const r = await c.req("GET", "/api/servers");
  assert.equal(r.status, 200);
  return r.data.servers.find(s => s.id === id);
}

before(async () => {
  await pool.query("DROP SCHEMA public CASCADE; CREATE SCHEMA public;");
  await initializeDatabase();
  // connect-pg-simple creates this at process start (before the drop above), so recreate it here:
  await pool.query(`CREATE TABLE IF NOT EXISTS user_sessions (sid varchar NOT NULL PRIMARY KEY, sess json NOT NULL, expire timestamp(6) NOT NULL);
                    CREATE INDEX IF NOT EXISTS IDX_session_expire ON user_sessions(expire);`);
  await new Promise(r => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${server.address().port}`;
});
after(async () => { server.close(); await pool.end(); });

test("CSRF: state-changing requests without the custom header are rejected", async () => {
  const c = client();
  const r = await c.req("POST", "/api/auth/register", { username: uniq("csrf"), displayName: "X", password: "password1234" }, { noCsrf: true });
  assert.equal(r.status, 403);
});

test("permissions: non-members cannot read a channel; members can", async () => {
  const owner = await makeUser("owner");
  const outsider = await makeUser("outsider");
  const srv = await getServer(owner.c, owner.starterServerId);
  const chan = srv.channels.find(x => x.kind === "text");
  let r = await outsider.c.req("GET", `/api/channels/${chan.id}/messages`);
  assert.equal(r.status, 403);
  r = await owner.c.req("POST", `/api/channels/${chan.id}/messages`, { content: "hello" });
  assert.equal(r.status, 201);
  r = await owner.c.req("GET", `/api/channels/${chan.id}/messages`);
  assert.equal(r.status, 200);
  assert.equal(r.data.messages.length, 1);
});

test("hidden channels: view_role hides the channel, its messages and its voice list", async () => {
  const owner = await makeUser("howner");
  const member = await makeUser("hmember");
  let r = await owner.c.req("POST", `/api/servers/${owner.starterServerId}/invites`, { expiresHours: 24, maxUses: 0 });
  await member.c.req("POST", `/api/invites/${r.data.code}/join`, {});
  r = await owner.c.req("POST", `/api/servers/${owner.starterServerId}/channels`, { name: "ops-only", kind: "text", viewRole: "admin" });
  assert.equal(r.status, 201, JSON.stringify(r.data));
  const hidden = r.data.channel;
  assert.equal(hidden.view_role, "admin");
  r = await member.c.req("GET", `/api/channels/${hidden.id}/messages`);
  assert.equal(r.status, 403);
  const memberView = await getServer(member.c, owner.starterServerId);
  assert.ok(!memberView.channels.some(c => c.id === hidden.id), "hidden channel must not appear in the member's server list");
  r = await owner.c.req("GET", `/api/channels/${hidden.id}/messages`);
  assert.equal(r.status, 200);
});

test("invites: usage counts, max-uses enforcement, revoke", async () => {
  const owner = await makeUser("iowner");
  const guest = await makeUser("iguest");
  const guest2 = await makeUser("iguest2");
  let r = await owner.c.req("POST", `/api/servers/${owner.starterServerId}/invites`, { expiresHours: 24, maxUses: 1 });
  assert.equal(r.status, 201);
  const code = r.data.code;
  r = await guest.c.req("POST", `/api/invites/${code}/join`, {});
  assert.equal(r.status, 200);
  r = await guest2.c.req("POST", `/api/invites/${code}/join`, {});
  assert.equal(r.status, 404, "second join must fail once max_uses is reached");
  r = await owner.c.req("GET", `/api/servers/${owner.starterServerId}/invites`);
  assert.equal(r.status, 200);
  assert.equal(r.data.invites.find(i => i.code === code).uses, 1);
  // revoke a fresh invite
  r = await owner.c.req("POST", `/api/servers/${owner.starterServerId}/invites`, { expiresHours: 24, maxUses: 0 });
  const code2 = r.data.code;
  r = await owner.c.req("DELETE", `/api/servers/${owner.starterServerId}/invites/${code2}`);
  assert.equal(r.status, 200);
  r = await guest2.c.req("POST", `/api/invites/${code2}/join`, {});
  assert.equal(r.status, 404);
});

test("member removal (kick): rank rules and immediate loss of access", async () => {
  const owner = await makeUser("kowner");
  const mod = await makeUser("kmod");
  const pleb = await makeUser("kpleb");
  let r = await owner.c.req("POST", `/api/servers/${owner.starterServerId}/invites`, { expiresHours: 24, maxUses: 0 });
  const code = r.data.code;
  await mod.c.req("POST", `/api/invites/${code}/join`, {});
  await pleb.c.req("POST", `/api/invites/${code}/join`, {});
  await owner.c.req("PATCH", `/api/servers/${owner.starterServerId}/members/${mod.user.id}`, { role: "moderator" });
  // a moderator cannot remove the owner-ranked... here: cannot remove someone of equal/higher rank
  r = await mod.c.req("DELETE", `/api/servers/${owner.starterServerId}/members/${owner.user.id}`);
  assert.equal(r.status, 403);
  // moderator removes a member: works, and access ends immediately
  const srv = await getServer(owner.c, owner.starterServerId);
  const chan = srv.channels.find(x => x.kind === "text");
  r = await mod.c.req("DELETE", `/api/servers/${owner.starterServerId}/members/${pleb.user.id}`);
  assert.equal(r.status, 200);
  r = await pleb.c.req("GET", `/api/channels/${chan.id}/messages`);
  assert.equal(r.status, 403);
});

test("file access: only the uploader, channel viewers and DM members can download", async () => {
  const owner = await makeUser("fowner");
  const member = await makeUser("fmember");
  const outsider = await makeUser("foutsider");
  let r = await owner.c.req("POST", `/api/servers/${owner.starterServerId}/invites`, { expiresHours: 24, maxUses: 0 });
  await member.c.req("POST", `/api/invites/${r.data.code}/join`, {});
  const srv = await getServer(owner.c, owner.starterServerId);
  const chan = srv.channels.find(x => x.kind === "text");

  const fd = new FormData();
  fd.append("file", new Blob(["hello file"], { type: "text/plain" }), "note.txt");
  r = await owner.c.req("POST", "/api/files", undefined, { form: fd });
  assert.equal(r.status, 201, JSON.stringify(r.data));
  const fileId = r.data.file.id;

  // unattached: only the uploader
  r = await member.c.req("GET", `/api/files/${fileId}`);
  assert.equal(r.status, 404);
  const raw = await fetch(`${base}/api/files/${fileId}`, { headers: { Cookie: owner.c.cookie() } });
  assert.equal(raw.status, 200);
  assert.equal(await raw.text(), "hello file");

  // attach to a channel message: channel viewers gain access, outsiders don't
  r = await owner.c.req("POST", `/api/channels/${chan.id}/messages`, { content: "", attachmentIds: [fileId] });
  assert.equal(r.status, 201, JSON.stringify(r.data));
  assert.equal(r.data.message.attachments.length, 1);
  r = await member.c.req("GET", `/api/files/${fileId}`);
  assert.equal(r.status, 200);
  r = await outsider.c.req("GET", `/api/files/${fileId}`);
  assert.equal(r.status, 404);
  r = await client().req("GET", `/api/files/${fileId}`);
  assert.equal(r.status, 401);

  // deleting the message deletes the file
  const msgId = (await owner.c.req("GET", `/api/channels/${chan.id}/messages`)).data.messages.at(-1).id;
  await owner.c.req("DELETE", `/api/messages/${msgId}`);
  r = await owner.c.req("GET", `/api/files/${fileId}`);
  assert.equal(r.status, 404);
});

test("file cleanup: unattached uploads older than 1 hour are deleted", async () => {
  const owner = await makeUser("cowner");
  const fd = new FormData();
  fd.append("file", new Blob(["stale"], { type: "text/plain" }), "stale.txt");
  const r = await owner.c.req("POST", "/api/files", undefined, { form: fd });
  const fileId = r.data.file.id;
  await pool.query("UPDATE files SET created_at = NOW() - INTERVAL '2 hours' WHERE id=$1", [fileId]);
  await cleanupOrphanFiles();
  const after = await owner.c.req("GET", `/api/files/${fileId}`);
  assert.equal(after.status, 404);
});

test("pagination: (created_at, id) cursor never drops or repeats rows with identical timestamps", async () => {
  const owner = await makeUser("powner");
  let r = await owner.c.req("POST", `/api/servers/${owner.starterServerId}/channels`, { name: "paging", kind: "text" });
  const chan = r.data.channel;
  // 55 messages, ALL with the exact same microsecond timestamp — the case a
  // millisecond timestamp cursor silently corrupts.
  const stamp = new Date().toISOString();
  for (let i = 0; i < 55; i++) {
    await pool.query("INSERT INTO messages(channel_id,author_id,content,created_at) VALUES($1,$2,$3,$4)",
      [chan.id, owner.user.id, `m${i}`, stamp]);
  }
  const page1 = await owner.c.req("GET", `/api/channels/${chan.id}/messages`);
  assert.equal(page1.data.messages.length, 50);
  assert.equal(page1.data.hasMore, true);
  assert.ok(page1.data.nextCursor, "server must return a compound cursor");
  const page2 = await owner.c.req("GET", `/api/channels/${chan.id}/messages?cursor=${encodeURIComponent(page1.data.nextCursor)}`);
  assert.equal(page2.data.messages.length, 5);
  const ids = new Set([...page1.data.messages, ...page2.data.messages].map(m => m.id));
  assert.equal(ids.size, 55, "no duplicates, no drops across pages");
});

test("channel name dedupe: startup renames duplicates and creates the unique index", async () => {
  await pool.query("DROP INDEX IF EXISTS channels_server_name_idx");
  const owner = await makeUser("downer");
  await pool.query("INSERT INTO channels(server_id,name,kind) VALUES($1,'dup-name','text'),($1,'dup-name','text'),($1,'DUP-NAME','text')",
    [owner.starterServerId]);
  await initializeDatabase(); // startup path re-runs: dedupe + index
  const names = (await pool.query("SELECT name FROM channels WHERE server_id=$1 AND lower(name) LIKE 'dup-name%' ORDER BY created_at", [owner.starterServerId])).rows.map(r => r.name);
  assert.deepEqual(names.map(n => n.toLowerCase()).sort(), ["dup-name", "dup-name-2", "dup-name-3"].sort());
  const idx = await pool.query("SELECT 1 FROM pg_indexes WHERE indexname='channels_server_name_idx'");
  assert.equal(idx.rowCount, 1);
});

test("webhooks: bot posts, bots can't be DM'd, deleting the webhook keeps messages as 'Deleted Bot'", async () => {
  const owner = await makeUser("wowner");
  const srv = await getServer(owner.c, owner.starterServerId);
  const chan = srv.channels.find(x => x.kind === "text");
  let r = await owner.c.req("POST", `/api/channels/${chan.id}/webhooks`, { name: "Announcer" });
  assert.equal(r.status, 201, JSON.stringify(r.data));
  const { webhook, token } = r.data;
  // ingest needs no session and no CSRF header (token-authenticated)
  const anon = client();
  r = await anon.req("POST", `/api/webhooks/${webhook.id}/${token}`, { content: "beep boop" }, { noCsrf: true });
  assert.equal(r.status, 201, JSON.stringify(r.data));
  const botUsername = r.data.message.username;
  assert.ok(botUsername.startsWith("bot_"));
  r = await anon.req("POST", `/api/webhooks/${webhook.id}/wrong-token`, { content: "x" }, { noCsrf: true });
  assert.equal(r.status, 401);
  // bots are hidden from DM lookup
  r = await owner.c.req("POST", "/api/dms", { username: botUsername });
  assert.equal(r.status, 404);
  // delete webhook: message survives, re-attributed
  r = await owner.c.req("DELETE", `/api/webhooks/${webhook.id}`);
  assert.equal(r.status, 200);
  r = await owner.c.req("GET", `/api/channels/${chan.id}/messages`);
  const msg = r.data.messages.find(m => m.content === "beep boop");
  assert.ok(msg, "webhook message must survive webhook deletion");
  assert.equal(msg.display_name, "Deleted Bot");
  const botGone = await pool.query("SELECT 1 FROM profiles WHERE username=$1", [botUsername]);
  assert.equal(botGone.rowCount, 0);
});

test("voice:participants is not leaked to members who cannot view the voice channel", async () => {
  const owner = await makeUser("vowner");
  const member = await makeUser("vmember");
  let r = await owner.c.req("POST", `/api/servers/${owner.starterServerId}/invites`, { expiresHours: 24, maxUses: 0 });
  await member.c.req("POST", `/api/invites/${r.data.code}/join`, {});
  r = await owner.c.req("POST", `/api/servers/${owner.starterServerId}/channels`, { name: "Stage", kind: "voice", viewRole: "admin" });
  const stage = r.data.channel;

  const connect = cookie => new Promise((resolve, reject) => {
    const s = ioClient(base, { extraHeaders: { Cookie: cookie }, transports: ["websocket"] });
    s.on("connect", () => resolve(s));
    s.on("connect_error", reject);
  });
  const ownerSock = await connect(owner.c.cookie());
  const memberSock = await connect(member.c.cookie());
  const memberGot = [];
  memberSock.on("voice:participants", p => memberGot.push(p));
  const ownerGot = [];
  ownerSock.on("voice:participants", p => ownerGot.push(p));
  ownerSock.emit("voice:join", stage.id);
  await new Promise(r2 => setTimeout(r2, 800));
  assert.ok(ownerGot.some(p => p.channelId === stage.id && p.users.length === 1), "owner should see the participant list");
  assert.ok(!memberGot.some(p => p.channelId === stage.id), "member without view access must NOT receive voice:participants");
  ownerSock.close(); memberSock.close();
});

test("room eviction: raising a channel's view_role removes members who lost access, live", async () => {
  const owner = await makeUser("eowner");
  const member = await makeUser("emember");
  let r = await owner.c.req("POST", `/api/servers/${owner.starterServerId}/invites`, { expiresHours: 24, maxUses: 0 });
  await member.c.req("POST", `/api/invites/${r.data.code}/join`, {});
  r = await owner.c.req("POST", `/api/servers/${owner.starterServerId}/channels`, { name: "Radio", kind: "voice" });
  const radio = r.data.channel;
  const sock = await new Promise((resolve, reject) => {
    const s = ioClient(base, { extraHeaders: { Cookie: member.c.cookie() }, transports: ["websocket"] });
    s.on("connect", () => resolve(s));
    s.on("connect_error", reject);
  });
  const removed = new Promise(res => sock.on("voice:removed", res));
  sock.emit("voice:join", radio.id);
  await new Promise(r2 => setTimeout(r2, 400));
  r = await owner.c.req("PATCH", `/api/channels/${radio.id}`, { name: "Radio", topic: "", viewRole: "admin" });
  assert.equal(r.status, 200);
  const ev = await Promise.race([removed, new Promise((_, rej) => setTimeout(() => rej(new Error("no voice:removed received")), 2000))]);
  assert.equal(ev.channelId, radio.id);
  r = await member.c.req("GET", `/api/servers/${owner.starterServerId}/voice`);
  assert.ok(!(radio.id in r.data.voice), "evicted member must not see the channel in the voice snapshot");
  sock.close();
});

test("account basics: change username, log out everywhere, ICE config", async () => {
  const u = await makeUser("acct");
  let r = await u.c.req("GET", "/api/ice");
  assert.equal(r.status, 200);
  assert.equal(r.data.turnConfigured, false); // no TURN_* env in tests
  r = await u.c.req("PATCH", "/api/me/username", { username: uniq("renamed"), password: "wrong-password" });
  assert.equal(r.status, 401);
  const newName = uniq("renamed");
  r = await u.c.req("PATCH", "/api/me/username", { username: newName, password: "password1234" });
  assert.equal(r.status, 200, JSON.stringify(r.data));
  r = await u.c.req("GET", "/api/me");
  assert.equal(r.data.user.username, newName);
  r = await u.c.req("POST", "/api/auth/logout-all", {});
  assert.equal(r.status, 200);
});

test("delete account: ownership transfers to the longest-standing ranked member", async () => {
  const owner = await makeUser("delowner");
  const heir = await makeUser("delheir");
  let r = await owner.c.req("POST", `/api/servers/${owner.starterServerId}/invites`, { expiresHours: 24, maxUses: 0 });
  await heir.c.req("POST", `/api/invites/${r.data.code}/join`, {});
  r = await owner.c.req("DELETE", "/api/me", { password: "wrong-password" });
  assert.equal(r.status, 401);
  r = await owner.c.req("DELETE", "/api/me", { password: "password1234" });
  assert.equal(r.status, 200);
  const heirView = await getServer(heir.c, owner.starterServerId);
  assert.equal(heirView.role, "owner");
  assert.equal(heirView.owner_id, heir.user.id);
  const gone = await pool.query("SELECT 1 FROM profiles WHERE id=$1", [owner.user.id]);
  assert.equal(gone.rowCount, 0);
});
