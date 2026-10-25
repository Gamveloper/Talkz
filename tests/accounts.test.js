/* Talkz Cloud — Phase 2 accounts tests: email verification, password reset,
 * pluggable mailer behaviour, TOTP two-factor auth (incl. RFC 6238 vectors).
 * Run: TEST_DATABASE_URL=postgres://user:pass@localhost:5432/talkz_test npm test
 * Uses its own database (talkz_test_accounts) via tests/helpers.js.
 * Mail is captured in-process through the mailer's test hook — no real
 * email service is involved, and links are taken from the captured bodies,
 * exactly as a user's mail client would receive them. */
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
const { server, pool, initializeDatabase, mailer, totp } = require("../server.js");

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
function mailTo(email) {
  return mailer._test.sent.filter(m => m.to === email).at(-1);
}
function tokenFrom(mail, kind) {
  const m = mail && mail.text.match(new RegExp(`\\?${kind}=([A-Za-z0-9_-]+)`));
  assert.ok(m, `expected a ?${kind}= link in the captured email`);
  return m[1];
}

before(async () => {
  await ensureDatabase(DB_URL);
  await pool.query("DROP SCHEMA public CASCADE; CREATE SCHEMA public;");
  await initializeDatabase();
  await pool.query(`CREATE TABLE IF NOT EXISTS user_sessions (sid varchar NOT NULL PRIMARY KEY, sess json NOT NULL, expire timestamp(6) NOT NULL);
                    CREATE INDEX IF NOT EXISTS IDX_session_expire ON user_sessions(expire);`);
  mailer._test.setSender(async () => {}); // capture mode: bodies land in mailer._test.sent
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

test("email verification: link verifies once, token is hashed at rest, resend after verify is a no-op", async () => {
  const email = `${uniq("verify")}@example.com`;
  const { c, user, registerResponse } = await makeUser("vuser", { email });
  assert.deepEqual(registerResponse.emailVerification, { sent: true, configured: true });
  let me = await c.req("GET", "/api/me");
  assert.equal(me.data.user.email, email);
  assert.equal(me.data.user.emailVerified, false);

  const token = tokenFrom(mailTo(email), "verify");
  const stored = await pool.query("SELECT token_hash, used_at FROM account_tokens WHERE user_id=$1 AND purpose='verify_email'", [user.id]);
  assert.equal(stored.rowCount, 1);
  assert.equal(stored.rows[0].token_hash, sha256(token), "only the SHA-256 hash is stored");
  assert.notEqual(stored.rows[0].token_hash, token);
  assert.equal(stored.rows[0].used_at, null);

  let r = await c.req("POST", "/api/auth/verify-email", { token: "not-the-token" });
  assert.equal(r.status, 400);
  r = await c.req("POST", "/api/auth/verify-email", { token });
  assert.equal(r.status, 200);
  me = await c.req("GET", "/api/me");
  assert.equal(me.data.user.emailVerified, true);
  r = await c.req("POST", "/api/auth/verify-email", { token });
  assert.equal(r.status, 400, "verification tokens are single-use");

  r = await c.req("POST", "/api/auth/resend-verification", {});
  assert.equal(r.status, 200);
  assert.equal(r.data.alreadyVerified, true);
});

test("email verification: expired token is rejected", async () => {
  const email = `${uniq("exp")}@example.com`;
  const { user } = await makeUser("euser", { email });
  const token = tokenFrom(mailTo(email), "verify");
  await pool.query("UPDATE account_tokens SET expires_at = NOW() - INTERVAL '1 minute' WHERE user_id=$1", [user.id]);
  const r = await client().req("POST", "/api/auth/verify-email", { token });
  assert.equal(r.status, 400);
});

test("email change: marks the address unverified, burns the old link, verifies via the new link", async () => {
  const first = `${uniq("first")}@example.com`;
  const second = `${uniq("second")}@example.com`;
  const { c, user } = await makeUser("chuser", { email: first });
  const oldToken = tokenFrom(mailTo(first), "verify");
  const r = await c.req("PATCH", "/api/me", { displayName: user.displayName, statusText: "", email: second });
  assert.equal(r.status, 200, JSON.stringify(r.data));
  assert.equal(r.data.user.email, second);
  assert.equal(r.data.user.emailVerified, false);
  assert.deepEqual(r.data.emailVerification, { sent: true, configured: true });
  const stale = await c.req("POST", "/api/auth/verify-email", { token: oldToken });
  assert.equal(stale.status, 400, "the link for the old address must not verify the new one");
  const fresh = await c.req("POST", "/api/auth/verify-email", { token: tokenFrom(mailTo(second), "verify") });
  assert.equal(fresh.status, 200);
});

test("password reset: happy path, sessions invalidated, token single-use", async () => {
  const email = `${uniq("reset")}@example.com`;
  const { c, username } = await makeUser("ruser", { email });
  const anon = client();
  let r = await anon.req("POST", "/api/auth/forgot-password", { email });
  assert.equal(r.status, 200);
  const token = tokenFrom(mailTo(email), "reset");

  r = await anon.req("POST", "/api/auth/reset-password", { token, password: "short" });
  assert.equal(r.status, 400, "a too-short password is rejected BEFORE the token is burned");
  r = await anon.req("POST", "/api/auth/reset-password", { token, password: "newpassword99" });
  assert.equal(r.status, 200);

  const meAfter = await c.req("GET", "/api/me");
  assert.equal(meAfter.data.user, null, "the reset must end the account's other sessions");

  const fresh = client();
  r = await fresh.req("POST", "/api/auth/login", { username, password: "password1234" });
  assert.equal(r.status, 401, "the old password no longer works");
  r = await fresh.req("POST", "/api/auth/login", { username, password: "newpassword99" });
  assert.equal(r.status, 200, "the new password works");

  r = await anon.req("POST", "/api/auth/reset-password", { token, password: "anotherpassword1" });
  assert.equal(r.status, 400, "reset tokens are single-use");
});

test("password reset: unknown email gets the identical generic response and no mail", async () => {
  const anon = client();
  const before = mailer._test.sent.length;
  const unknown = await anon.req("POST", "/api/auth/forgot-password", { email: `${uniq("ghost")}@example.com` });
  assert.equal(unknown.status, 200);
  const real = await anon.req("POST", "/api/auth/forgot-password", { email: `${uniq("nobody")}@example.com` });
  assert.deepEqual(unknown.data, real.data);
  assert.deepEqual(unknown.data, { ok: true, message: "If an account uses that email, a password reset link is on its way." });
  assert.equal(mailer._test.sent.length, before, "no mail is captured for unknown addresses");
});

test("password reset: expired token is rejected", async () => {
  const email = `${uniq("rexp")}@example.com`;
  const { user } = await makeUser("rxuser", { email });
  await client().req("POST", "/api/auth/forgot-password", { email });
  const token = tokenFrom(mailTo(email), "reset");
  await pool.query("UPDATE account_tokens SET expires_at = NOW() - INTERVAL '1 minute' WHERE user_id=$1 AND purpose='password_reset'", [user.id]);
  const r = await client().req("POST", "/api/auth/reset-password", { token, password: "newpassword99" });
  assert.equal(r.status, 400);
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

test("mailer unconfigured: signup still works and honestly reports that no email was sent", async () => {
  mailer._test.reset(); // no capture sender, no RESEND/SMTP env in the test process
  try {
    const email = `${uniq("nomail")}@example.com`;
    const { registerResponse } = await makeUser("nuser", { email });
    assert.deepEqual(registerResponse.emailVerification, { sent: false, configured: false });
  } finally {
    mailer._test.setSender(async () => {});
  }
});
