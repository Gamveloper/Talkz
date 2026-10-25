/* Talkz Cloud — pluggable transactional mailer (Phase 2).
 *
 * Exactly one transport is used, chosen from env vars at send time:
 *   1. Resend  — RESEND_API_KEY + MAIL_FROM set: POST https://api.resend.com/emails
 *                via fetch (no extra package).
 *   2. SMTP    — SMTP_HOST + MAIL_FROM set (SMTP_PORT defaults to 587;
 *                SMTP_USER/SMTP_PASS optional for unauthenticated relays):
 *                sent with nodemailer.
 *   3. Neither — mail is NOT configured. sendMail returns
 *                { delivered:false, reason:"not-configured" } and the caller
 *                logs the action link server-side and tells the user plainly.
 *                Nothing ever pretends an email was sent when it wasn't.
 *
 * Tests can install a capture sender via mailer._test.setSender(fn); fn receives
 * { to, subject, text } and every captured message is also kept in _test.sent.
 */
let nodemailer = null; // required lazily, only when SMTP is configured

const testHooks = {
  sender: null,
  sent: [],
  setSender(fn) { this.sender = fn || null; },
  reset() { this.sender = null; this.sent = []; }
};

function mailerMode(env = process.env) {
  if (testHooks.sender) return "capture";
  if (env.RESEND_API_KEY && env.MAIL_FROM) return "resend";
  if (env.SMTP_HOST && env.MAIL_FROM) return "smtp";
  return null;
}
const mailConfigured = (env = process.env) => mailerMode(env) !== null;

async function sendViaResend(env, { to, subject, text }) {
  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, "Content-Type": "application/json" },
    body: JSON.stringify({ from: env.MAIL_FROM, to: [to], subject, text })
  });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`Resend rejected the email (${res.status}): ${body.slice(0, 200)}`);
  }
  return { delivered: true, mode: "resend" };
}

async function sendViaSmtp(env, { to, subject, text }) {
  if (!nodemailer) nodemailer = require("nodemailer");
  const port = parseInt(env.SMTP_PORT, 10) || 587;
  const transport = nodemailer.createTransport({
    host: env.SMTP_HOST,
    port,
    secure: env.SMTP_SECURE ? env.SMTP_SECURE === "true" : port === 465,
    auth: env.SMTP_USER ? { user: env.SMTP_USER, pass: env.SMTP_PASS || "" } : undefined
  });
  await transport.sendMail({ from: env.MAIL_FROM, to, subject, text });
  return { delivered: true, mode: "smtp" };
}

async function sendMail(message, env = process.env) {
  const mode = mailerMode(env);
  if (mode === "capture") {
    testHooks.sent.push(message);
    await testHooks.sender(message);
    return { delivered: true, mode };
  }
  if (mode === "resend") return sendViaResend(env, message);
  if (mode === "smtp") return sendViaSmtp(env, message);
  return { delivered: false, reason: "not-configured" };
}

module.exports = { sendMail, mailerMode, mailConfigured, _test: testHooks };
