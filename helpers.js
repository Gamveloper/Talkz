/* Shared harness for the Phase 2 suites. node --test runs each test FILE in
 * its own process, but the files would all share TEST_DATABASE_URL's
 * database and wipe each other — so each suite gets a sibling database
 * (<name>_<suffix>), created on demand in its before() hook.
 * databaseUrlFor() must run BEFORE ../server.js is required (the pool is
 * created from DATABASE_URL at load time). */
const { Client } = require("pg");

function databaseUrlFor(suffix) {
  const base = process.env.TEST_DATABASE_URL;
  if (!base) throw new Error("Set TEST_DATABASE_URL to a disposable test database URL (see README).");
  const u = new URL(base);
  const baseName = decodeURIComponent(u.pathname.replace(/^\//, "")) || "talkz_test";
  u.pathname = `/${baseName}_${suffix}`;
  const url = u.toString();
  process.env.DATABASE_URL = url;
  return url;
}

async function ensureDatabase(url) {
  const u = new URL(url);
  const name = decodeURIComponent(u.pathname.replace(/^\//, ""));
  const adminUrl = new URL(url);
  adminUrl.pathname = "/postgres";
  const admin = new Client({ connectionString: adminUrl.toString() });
  await admin.connect();
  try {
    const exists = await admin.query("SELECT 1 FROM pg_database WHERE datname=$1", [name]);
    if (!exists.rowCount) await admin.query(`CREATE DATABASE "${name.replace(/"/g, '""')}"`);
  } finally { await admin.end(); }
}

module.exports = { databaseUrlFor, ensureDatabase };
