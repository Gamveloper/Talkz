/* Talkz Cloud — Phase 2 storage tests: S3-compatible object storage against
 * a local stub S3 HTTP server (PUT/GET/DELETE/List + presigned URLs), the
 * permission gate in front of signed downloads, bucket cleanup in the orphan
 * sweep, EXIF stripping at upload, and the Postgres fallback with S3 unset.
 * Run: TEST_DATABASE_URL=postgres://user:pass@localhost:5432/talkz_test npm test
 * Uses its own database (talkz_test_storage) via tests/helpers.js. */
process.env.SESSION_SECRET = "test-secret";
process.env.NODE_ENV = "test";
process.env.TRUST_PROXY = "false";
process.env.AUTH_RATE_LIMIT = "1000";
process.env.ACCOUNT_RATE_LIMIT = "1000";
process.env.S3_SWEEP_MIN_AGE_MS = "0"; // the sweep may delete unreferenced objects immediately in tests

const { databaseUrlFor, ensureDatabase } = require("./helpers");
const DB_URL = databaseUrlFor("storage");

const { test, before, after } = require("node:test");
const assert = require("node:assert");
const http = require("http");
const { server, pool, initializeDatabase, cleanupOrphanFiles, storage } = require("../server.js");

/* ---------- a tiny in-memory stub S3 (path-style, signatures ignored) ---------- */
const stubObjects = new Map(); // key -> { body, mime, lastModified }
let stubBase;
function startStubS3() {
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, "http://stub");
    const parts = u.pathname.split("/").filter(Boolean).map(decodeURIComponent);
    const key = parts.slice(1).join("/");
    if (req.method === "PUT") {
      const chunks = [];
      req.on("data", ch => chunks.push(ch));
      req.on("end", () => {
        stubObjects.set(key, { body: Buffer.concat(chunks), mime: req.headers["content-type"], lastModified: new Date() });
        res.writeHead(200, { ETag: '"stub-etag"' });
        res.end();
      });
      return;
    }
    if (req.method === "GET" && !key) { // ListObjectsV2
      const prefix = u.searchParams.get("prefix") || "";
      const contents = [...stubObjects.entries()]
        .filter(([k]) => k.startsWith(prefix))
        .map(([k, v]) => `<Contents><Key>${k}</Key><LastModified>${v.lastModified.toISOString()}</LastModified><ETag>"stub-etag"</ETag><Size>${v.body.length}</Size><StorageClass>STANDARD</StorageClass></Contents>`)
        .join("");
      res.writeHead(200, { "Content-Type": "application/xml" });
      res.end(`<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>test-bucket</Name><Prefix>${prefix}</Prefix><KeyCount>${stubObjects.size}</KeyCount><IsTruncated>false</IsTruncated>${contents}</ListBucketResult>`);
      return;
    }
    if (req.method === "GET") {
      const obj = stubObjects.get(key);
      if (!obj) { res.writeHead(404, { "Content-Type": "application/xml" }); return res.end("<Error><Code>NoSuchKey</Code></Error>"); }
      res.writeHead(200, { "Content-Type": obj.mime, "Content-Length": obj.body.length });
      return res.end(obj.body);
    }
    if (req.method === "DELETE") {
      stubObjects.delete(key);
      res.writeHead(204);
      return res.end();
    }
    res.writeHead(400);
    res.end();
  });
  return new Promise(resolve => srv.listen(0, "127.0.0.1", () => resolve(srv)));
}

/* ---------- the Phase 1-style cookie client ---------- */
let base;
function client() {
  let cookie = "";
  async function req(method, path, body, opts = {}) {
    const headers = { ...(cookie ? { Cookie: cookie } : {}), ...(opts.headers || {}) };
    if (!opts.noCsrf && method !== "GET") headers["X-Requested-With"] = "fetch";
    let payload;
    if (opts.form) payload = opts.form;
    else if (body !== undefined) { headers["Content-Type"] = "application/json"; payload = JSON.stringify(body); }
    const res = await fetch(base + path, { method, headers, body: payload, redirect: opts.redirect || "follow" });
    const sc = res.headers.get("set-cookie");
    if (sc) cookie = sc.split(";")[0];
    let data = {};
    const text = await res.text();
    try { data = JSON.parse(text); } catch { data = { raw: text }; }
    return { status: res.status, data, text, headers: res.headers };
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
  return r.data.servers.find(s => s.id === id);
}
async function upload(c, bytes, type, name) {
  const fd = new FormData();
  fd.append("file", new Blob([bytes], { type }), name);
  const r = await c.req("POST", "/api/files", undefined, { form: fd });
  assert.equal(r.status, 201, JSON.stringify(r.data));
  return r.data.file;
}

let stubSrv;
before(async () => {
  await ensureDatabase(DB_URL);
  stubSrv = await startStubS3();
  stubBase = `http://127.0.0.1:${stubSrv.address().port}`;
  process.env.S3_ENDPOINT = stubBase;
  process.env.S3_REGION = "test-1";
  process.env.S3_BUCKET = "test-bucket";
  process.env.S3_ACCESS_KEY_ID = "test-key";
  process.env.S3_SECRET_ACCESS_KEY = "test-secret";
  assert.equal(storage.storageMode(), "s3");
  await pool.query("DROP SCHEMA public CASCADE; CREATE SCHEMA public;");
  await initializeDatabase();
  await pool.query(`CREATE TABLE IF NOT EXISTS user_sessions (sid varchar NOT NULL PRIMARY KEY, sess json NOT NULL, expire timestamp(6) NOT NULL);
                    CREATE INDEX IF NOT EXISTS IDX_session_expire ON user_sessions(expire);`);
  await new Promise(r => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${server.address().port}`;
});
after(async () => { server.close(); stubSrv.close(); await pool.end(); });

test("S3 mode: upload stores the bytes in the bucket and records backend + key on the row", async () => {
  const owner = await makeUser("sowner");
  const file = await upload(owner.c, "hello s3 world", "text/plain", "note.txt");
  const row = (await pool.query("SELECT storage, storage_key, data, size FROM files WHERE id=$1", [file.id])).rows[0];
  assert.equal(row.storage, "s3");
  assert.ok(row.storage_key.startsWith("files/"));
  assert.equal(row.data, null, "no BYTEA copy is kept in S3 mode");
  assert.equal(row.size, 14);
  const obj = stubObjects.get(row.storage_key);
  assert.ok(obj, "the object exists in the bucket");
  assert.equal(obj.body.toString(), "hello s3 world");
});

test("S3 mode: downloads stay permission-gated, then redirect to a short-lived signed URL", async () => {
  const owner = await makeUser("downer");
  const member = await makeUser("dmember");
  const outsider = await makeUser("doutsider");
  let r = await owner.c.req("POST", `/api/servers/${owner.starterServerId}/invites`, { expiresHours: 24, maxUses: 0 });
  await member.c.req("POST", `/api/invites/${r.data.code}/join`, {});
  const srv = await getServer(owner.c, owner.starterServerId);
  const chan = srv.channels.find(x => x.kind === "text");

  const file = await upload(owner.c, "secret contents", "text/plain", "secret.txt");
  r = await owner.c.req("POST", `/api/channels/${chan.id}/messages`, { content: "", attachmentIds: [file.id] });
  assert.equal(r.status, 201);

  // outsiders and anonymous callers never reach the redirect
  r = await outsider.c.req("GET", `/api/files/${file.id}`, undefined, { redirect: "manual" });
  assert.equal(r.status, 404);
  const anon = await fetch(`${base}/api/files/${file.id}`, { redirect: "manual" });
  assert.equal(anon.status, 401);

  // a channel member gets a 302 to a presigned URL, and the URL serves the bytes
  r = await member.c.req("GET", `/api/files/${file.id}`, undefined, { redirect: "manual" });
  assert.equal(r.status, 302, JSON.stringify(r.data));
  const location = r.headers.get("location");
  assert.ok(location.startsWith(stubBase), "redirect points at the bucket endpoint");
  assert.ok(location.includes("X-Amz-Signature="), "the URL is signed");
  assert.ok(location.includes("X-Amz-Expires=300"), "the URL is short-lived (300 s)");
  const served = await fetch(location);
  assert.equal(served.status, 200);
  assert.equal(await served.text(), "secret contents");
});

test("S3 mode: the orphan sweep deletes bucket objects of removed rows", async () => {
  const owner = await makeUser("oowner");
  const file = await upload(owner.c, "stale s3", "text/plain", "stale.txt");
  const row = (await pool.query("SELECT storage_key FROM files WHERE id=$1", [file.id])).rows[0];
  assert.ok(stubObjects.has(row.storage_key));
  await pool.query("UPDATE files SET created_at = NOW() - INTERVAL '2 hours' WHERE id=$1", [file.id]);
  await cleanupOrphanFiles();
  assert.equal(stubObjects.has(row.storage_key), false, "the bucket object is deleted with the row");
  const r = await owner.c.req("GET", `/api/files/${file.id}`);
  assert.equal(r.status, 404);
});

test("S3 mode: objects orphaned by a cascade delete are reconciled by the sweep", async () => {
  const owner = await makeUser("cowner2");
  const srv = await getServer(owner.c, owner.starterServerId);
  const chan = srv.channels.find(x => x.kind === "text");
  const file = await upload(owner.c, "attached then deleted", "text/plain", "gone.txt");
  const key = (await pool.query("SELECT storage_key FROM files WHERE id=$1", [file.id])).rows[0].storage_key;
  const posted = await owner.c.req("POST", `/api/channels/${chan.id}/messages`, { content: "", attachmentIds: [file.id] });
  assert.equal(posted.status, 201);
  await owner.c.req("DELETE", `/api/messages/${posted.data.message.id}`);
  const row = await pool.query("SELECT 1 FROM files WHERE id=$1", [file.id]);
  assert.equal(row.rowCount, 0, "the row cascade-deleted with the message");
  assert.ok(stubObjects.has(key), "the object is left behind by the cascade…");
  await cleanupOrphanFiles();
  assert.equal(stubObjects.has(key), false, "…and the reconciliation sweep removes it");
});

function jpegWithExif() {
  const app1Payload = Buffer.concat([Buffer.from("Exif\0\0", "latin1"), Buffer.alloc(8, 0x41)]);
  const app1 = Buffer.concat([Buffer.from([0xff, 0xe1, 0x00, app1Payload.length + 2]), app1Payload]);
  const app0Payload = Buffer.from("JFIF\0\1\1", "latin1");
  const app0 = Buffer.concat([Buffer.from([0xff, 0xe0, 0x00, app0Payload.length + 2]), app0Payload]);
  const sos = Buffer.concat([
    Buffer.from([0xff, 0xda, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3f, 0x00]),
    Buffer.from([0x11, 0x22, 0x33]), Buffer.from([0xff, 0xd9])
  ]);
  return Buffer.concat([Buffer.from([0xff, 0xd8]), app1, app0, sos]);
}
function pngChunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  return Buffer.concat([len, Buffer.from(type, "latin1"), data, Buffer.alloc(4, 0x42)]);
}
function pngWithExif() {
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    pngChunk("IHDR", Buffer.alloc(13, 1)),
    pngChunk("eXIf", Buffer.from("II*\0secret-exif-data", "latin1")),
    pngChunk("IDAT", Buffer.from("fake-image-data", "latin1")),
    pngChunk("IEND", Buffer.alloc(0))
  ]);
}

test("EXIF: JPEG and PNG metadata are stripped at upload; image bytes survive", async () => {
  const owner = await makeUser("eowner");
  const jpg = jpegWithExif();
  const jpgFile = await upload(owner.c, jpg, "image/jpeg", "photo.jpg");
  const jpgKey = (await pool.query("SELECT storage_key FROM files WHERE id=$1", [jpgFile.id])).rows[0].storage_key;
  const storedJpg = stubObjects.get(jpgKey).body;
  assert.ok(!storedJpg.includes(Buffer.from("Exif")), "the EXIF segment is gone");
  assert.ok(storedJpg.includes(Buffer.from("JFIF")), "the JFIF header is kept");
  assert.ok(storedJpg.length < jpg.length);

  const png = pngWithExif();
  const pngFile = await upload(owner.c, png, "image/png", "shot.png");
  const pngKey = (await pool.query("SELECT storage_key FROM files WHERE id=$1", [pngFile.id])).rows[0].storage_key;
  const storedPng = stubObjects.get(pngKey).body;
  assert.ok(!storedPng.includes(Buffer.from("secret-exif-data")), "the PNG eXIf chunk is gone");
  assert.ok(storedPng.includes(Buffer.from("fake-image-data")), "the image data chunk is kept");
});

test("fallback: with S3 env unset, uploads use Postgres exactly like Phase 1", async () => {
  const saved = { ...process.env };
  delete process.env.S3_BUCKET;
  delete process.env.S3_ACCESS_KEY_ID;
  delete process.env.S3_SECRET_ACCESS_KEY;
  try {
    assert.equal(storage.storageMode(), "postgres");
    const owner = await makeUser("fowner2");
    const file = await upload(owner.c, "postgres bytes", "text/plain", "pg.txt");
    const row = (await pool.query("SELECT storage, storage_key, data FROM files WHERE id=$1", [file.id])).rows[0];
    assert.equal(row.storage, "postgres");
    assert.equal(row.storage_key, null);
    assert.equal(row.data.toString(), "postgres bytes");
    const raw = await fetch(`${base}/api/files/${file.id}`, { headers: { Cookie: owner.c.cookie() } });
    assert.equal(raw.status, 200);
    assert.equal(await raw.text(), "postgres bytes");
  } finally {
    process.env.S3_BUCKET = saved.S3_BUCKET;
    process.env.S3_ACCESS_KEY_ID = saved.S3_ACCESS_KEY_ID;
    process.env.S3_SECRET_ACCESS_KEY = saved.S3_SECRET_ACCESS_KEY;
    assert.equal(storage.storageMode(), "s3");
  }
});
