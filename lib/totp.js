/* Talkz Cloud — TOTP two-factor authentication (RFC 4226 / RFC 6238).
 * Implemented with Node's built-in crypto only — no dependency. Verified
 * against the RFC 6238 Appendix B test vectors in tests/accounts.test.js.
 * Secrets are base32 (RFC 4648) strings, the format authenticator apps expect.
 */
const crypto = require("crypto");

const B32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32Encode(buf) {
  let bits = 0, value = 0, out = "";
  for (const byte of buf) {
    value = (value << 8) | byte; bits += 8;
    while (bits >= 5) { out += B32_ALPHABET[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += B32_ALPHABET[(value << (5 - bits)) & 31];
  while (out.length % 8) out += "=";
  return out;
}

function base32Decode(str) {
  const clean = String(str || "").toUpperCase().replace(/[\s=-]/g, "");
  let bits = 0, value = 0;
  const bytes = [];
  for (const ch of clean) {
    const idx = B32_ALPHABET.indexOf(ch);
    if (idx === -1) throw new Error("Invalid base32 character.");
    value = (value << 5) | idx; bits += 5;
    if (bits >= 8) { bytes.push((value >>> (bits - 8)) & 0xff); bits -= 8; }
  }
  return Buffer.from(bytes);
}

/* 20 random bytes → a 32-character base32 secret (160 bits, RFC 4226 size). */
function generateSecret() {
  return base32Encode(crypto.randomBytes(20)).replace(/=+$/, "");
}

function hotp(secretBase32, counter, digits = 6) {
  const key = base32Decode(secretBase32);
  const msg = Buffer.alloc(8);
  msg.writeBigInt64BE(BigInt(counter));
  const mac = crypto.createHmac("sha1", key).update(msg).digest();
  const offset = mac[mac.length - 1] & 0x0f;
  const binary = ((mac[offset] & 0x7f) << 24) | ((mac[offset + 1] & 0xff) << 16)
    | ((mac[offset + 2] & 0xff) << 8) | (mac[offset + 3] & 0xff);
  return String(binary % 10 ** digits).padStart(digits, "0");
}

function totp(secretBase32, { time = Date.now(), step = 30, digits = 6 } = {}) {
  return hotp(secretBase32, Math.floor(time / 1000 / step), digits);
}

/* Accept the current code plus one step either side (clock skew between the
 * user's phone and the server is normal). Constant-time comparison. */
function verifyTotp(secretBase32, code, { time = Date.now(), step = 30, digits = 6, window = 1 } = {}) {
  const given = String(code ?? "").replace(/\s/g, "");
  if (!new RegExp(`^\\d{${digits}}$`).test(given)) return false;
  const counter = Math.floor(time / 1000 / step);
  for (let w = -window; w <= window; w++) {
    const expected = hotp(secretBase32, counter + w, digits);
    if (crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(given))) return true;
  }
  return false;
}

function otpauthUrl(secretBase32, account, issuer = "Talkz") {
  const label = encodeURIComponent(`${issuer}:${account}`);
  const params = new URLSearchParams({ secret: secretBase32, issuer, algorithm: "SHA1", digits: "6", period: "30" });
  return `otpauth://totp/${label}?${params.toString()}`;
}

module.exports = { base32Encode, base32Decode, generateSecret, hotp, totp, verifyTotp, otpauthUrl };
