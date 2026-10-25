/* Talkz Cloud — accounts tests (Phase 2 as amended by 2.1): TOTP two-factor
 * auth (incl. RFC 6238 vectors) and change-password. There are NO email
 * features any more — a dedicated test below pins that down (register
 * ignores an email field, user JSON carries no email fields, and the old
 * verify/forgot/reset routes answer 404).
 * Run: TEST_DATABASE_URL=<redacted>
 * Uses its own database (talkz_test_accounts) via tests/helpers.js. */
process.env.SESSION_SECRET = "test-secret";
process.env.NODE_ENV = "test";
process.env.TRUST_PROXY = "false";
process.env.AUTH_RATE_LIMIT = "1000"; // the suite registers many throwaway users from one IP
process.env.ACCOUNT_RATE_LIMIT = "1000";

const { databaseUrlFor, ensureDatabase } = require("./helpers");
const DB_URL = databaseUrlFor("accounts");

const { test, before, after } = require("node:test");
const assert = require("node:assert");
const crypto = require("crypto");
const { server, pool, initializeDatabase, totp } = require("../server.js");

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
async function makeUser(prefix, extra = {}) {
  const c = client();
  const username = uniq(prefix);
  const r = await c.req("POST", "/api/auth/register", { username, displayName: prefix, password: "password1234", ...extra });
  assert.equal(r.status, 201, JSON.stringify(r.data));
  return { c, user: r.data.user, username, registerResponse: r.data };
}
const sha256 = s => crypto.createHash("sha256").update(s).digest("hex");
before(async () => {
  await ensureDatabase(DB_URL);
  await pool.query("DROP SCHEMA public CASCADE; CREATE SCHEMA public;");
  await initializeDatabase();
  await pool.query(`CREATE TABLE IF NOT EXISTS user_sessions (sid varchar NOT NULL PRIMARY KEY, sess json NOT NULL, expire timestamp(6) NOT NULL);
                    CREATE INDEX IF NOT EXISTS IDX_session_expire ON user_sessions(expire);`);
  await new Promise(r => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${server.address().port}`;
});
after(async () => { server.close(); await pool.end(); });

test("TOTP: RFC 6238 Appendix B SHA-1 test vectors", () => {
  // Seed is the ASCII string "12345678901234567890" (the RFC's SHA-1 seed).
  const secret = totp.base32Encode(Buffer.from("12345678901234567890", "ascii")).replace(/=+$/, "");
  const vectors = [
    [59, "94287082"], [1111111109, "07081804"], [1111111111, "14050471"],
    [1234567890, "89005924"], [2000000000, "69279037"], [20000000000, "65353130"]
  ];
  for (const [sec, expected] of vectors) {
    assert.equal(totp.totp(secret, { time: sec * 1000, digits: 8 }), expected, `T=${sec}`);
  }
  // base32 round-trip and the ±1-step verify window
  assert.equal(totp.base32Decode(secret).toString("ascii"), "12345678901234567890");
  const now = 1700000000000;
  const code = totp.totp(secret, { time: now });
  assert.equal(totp.verifyTotp(secret, code, { time: now + 30000 }), true, "one step of skew is accepted");
  assert.equal(totp.verifyTotp(secret, code, { time: now + 120000 }), false, "four steps of skew are rejected");
  assert.equal(totp.verifyTotp(secret, "abcdef"), false);
});

test("no email anywhere: register ignores an email field, user JSON has no email, old email routes are 404", async () => {
  const { c, user } = await makeUser("nouser", { email: "someone@example.com" });
  assert.equal("email" in user, false);
  assert.equal("emailVerified" in user, false);
  const me = await c.req("GET", "/api/me");
  assert.equal("email" in me.data.user, false);
  const patched = await c.req("PATCH", "/api/me", { displayName: "No Mail", statusText: "", email: "x@example.com" });
  assert.equal(patched.status, 200);
  assert.equal("email" in patched.data.user, false);
  for (const [method, path] of [["POST", "/api/auth/verify-email"], ["GET", "/api/auth/verify-email"], ["POST", "/api/auth/resend-verification"], ["POST", "/api/auth/forgot-password"], ["POST", "/api/auth/reset-password"]]) {
    const r = await client().req(method, path, method === "GET" ? undefined : {});
    assert.equal(r.status, 404, `${method} ${path} must be gone`);
  }
});

test("change password: current password required, other sessions ended, old password dies", async () => {
  const { c, username } = await makeUser("pwuser");
  const other = client();
  let r = await other.req("POST", "/api/auth/login", { username, password: "password1234" });
  assert.equal(r.status, 200, "second session signed in");
  r = await c.req("POST", "/api/me/password", { currentPassword: "wrong-password", newPassword: "newpassword99" });
  assert.equal(r.status, 401);
  r = await c.req("POST", "/api/me/password", { currentPassword: "password1234", newPassword: "short" });
  assert.equal(r.status, 400);
  r = await c.req("POST", "/api/me/password", { currentPassword: "password1234", newPassword: "password1234" });
  assert.equal(r.status, 400, "new password must differ from the current one");
  r = await c.req("POST", "/api/me/password", { currentPassword: "password1234", newPassword: "newpassword99" });
  assert.equal(r.status, 200);
  assert.ok(r.data.sessionsEnded >= 1, "the other session is ended");
  const meOther = await other.req("GET", "/api/me");
  assert.equal(meOther.data.user, null, "the other session no longer authenticates");
  const meMine = await c.req("GET", "/api/me");
  assert.ok(meMine.data.user, "the session that changed the password stays signed in");
  const anon = client();
  r = await anon.req("POST", "/api/auth/login", { username, password: "password1234" });
  assert.equal(r.status, 401, "old password no longer works");
  r = await anon.req("POST", "/api/auth/login", { username, password: "newpassword99" });
  assert.equal(r.status, 200, "new password works");
});

test("2FA: enable, login challenge, TOTP sign-in, recovery codes are single-use, disable", async () => {
  const { c, user, username } = await makeUser("tuser");
  let r = await c.req("POST", "/api/me/2fa/enable", { code: "123456" });
  assert.equal(r.status, 400, "enable before setup is rejected");
  r = await c.req("POST", "/api/me/2fa/setup", { password: "wrong-password" });
  assert.equal(r.status, 401);
  r = await c.req("POST", "/api/me/2fa/setup", { password: "password1234" });
  assert.equal(r.status, 200);
  const secret = r.data.secret;
  assert.ok(r.data.otpauthUrl.startsWith("otpauth://totp/"));
  const wrongCode = totp.totp(secret) === "000000" ? "000001" : "000000";
  r = await c.req("POST", "/api/me/2fa/enable", { code: wrongCode });
  assert.equal(r.status, 401);
  r = await c.req("POST", "/api/me/2fa/enable", { code: totp.totp(secret) });
  assert.equal(r.status, 200);
  const codes = r.data.recoveryCodes;
  assert.equal(codes.length, 10);
  const storedCodes = await pool.query("SELECT code_hash FROM recovery_codes WHERE user_id=$1", [user.id]);
  assert.equal(storedCodes.rowCount, 10);
  assert.ok(!storedCodes.rows.some(row => codes.includes(row.code_hash)), "recovery codes are hashed at rest");
  let me = await c.req("GET", "/api/me");
  assert.equal(me.data.user.totpEnabled, true);

  // Sign-in now stops at the challenge: a correct password alone is not a session.
  await c.req("POST", "/api/auth/logout", {});
  r = await c.req("POST", "/api/auth/login", { username, password: "password1234" });
  assert.equal(r.status, 200);
  assert.equal(r.data.twoFactorRequired, true);
  me = await c.req("GET", "/api/me");
  assert.equal(me.data.user, null);
  r = await c.req("POST", "/api/auth/login/2fa", { code: wrongCode });
  assert.equal(r.status, 401);
  r = await c.req("POST", "/api/auth/login/2fa", { code: totp.totp(secret) });
  assert.equal(r.status, 200);
  assert.equal(r.data.user.id, user.id);

  // Recovery codes sign in — once each.
  await c.req("POST", "/api/auth/logout", {});
  await c.req("POST", "/api/auth/login", { username, password: "password1234" });
  r = await c.req("POST", "/api/auth/login/2fa", { code: codes[0] });
  assert.equal(r.status, 200, "a recovery code signs in");
  await c.req("POST", "/api/auth/logout", {});
  await c.req("POST", "/api/auth/login", { username, password: "password1234" });
  r = await c.req("POST", "/api/auth/login/2fa", { code: codes[0] });
  assert.equal(r.status, 401, "a recovery code cannot be reused");
  r = await c.req("POST", "/api/auth/login/2fa", { code: codes[1] });
  assert.equal(r.status, 200, "the next recovery code still works");

  // Disable requires password + a valid code; afterwards login is direct again.
  r = await c.req("POST", "/api/me/2fa/disable", { password: "password1234", code: wrongCode });
  assert.equal(r.status, 401);
  r = await c.req("POST", "/api/me/2fa/disable", { password: "password1234", code: totp.totp(secret) });
  assert.equal(r.status, 200);
  await c.req("POST", "/api/auth/logout", {});
  r = await c.req("POST", "/api/auth/login", { username, password: "password1234" });
  assert.equal(r.status, 200);
  assert.equal(r.data.user.id, user.id);
  assert.equal(r.data.twoFactorRequired, undefined);
});
