/* Talkz Cloud — S3-compatible object storage (Phase 2, storage item 5).
 *
 * Active only when S3_BUCKET, S3_ACCESS_KEY_ID and S3_SECRET_ACCESS_KEY are
 * set (S3_ENDPOINT for R2 / MinIO / other S3-compatible stores — leave unset
 * for AWS S3; S3_REGION defaults to "auto"). When inactive, uploads use the
 * Phase 1 Postgres BYTEA storage and this module is never touched.
 *
 * The bucket is never made public: downloads are authorised by the app's
 * file-access check first, then served via a short-lived (5 min) presigned
 * GET URL redirect. Config is read from env on every call so tests (and
 * operators rotating credentials) don't need a code change.
 */
let sdk = null; // { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand, ListObjectsV2Command, getSignedUrl }
let clientCache = { sig: null, client: null };

function storageConfig(env = process.env) {
  if (!env.S3_BUCKET || !env.S3_ACCESS_KEY_ID || !env.S3_SECRET_ACCESS_KEY) return null;
  return {
    endpoint: env.S3_ENDPOINT || undefined,
    region: env.S3_REGION || "auto",
    bucket: env.S3_BUCKET,
    accessKeyId: env.S3_ACCESS_KEY_ID,
    secretAccessKey: env.S3_SECRET_ACCESS_KEY
  };
}
const storageMode = (env = process.env) => (storageConfig(env) ? "s3" : "postgres");

function loadSdk() {
  if (!sdk) {
    const clientS3 = require("@aws-sdk/client-s3");
    const presigner = require("@aws-sdk/s3-request-presigner");
    sdk = { ...clientS3, getSignedUrl: presigner.getSignedUrl };
  }
  return sdk;
}

function getClient(cfg) {
  const sig = JSON.stringify(cfg);
  if (clientCache.sig !== sig) {
    const { S3Client } = loadSdk();
    clientCache = {
      sig,
      client: new S3Client({
        endpoint: cfg.endpoint,
        region: cfg.region,
        forcePathStyle: !!cfg.endpoint, // required by MinIO/most stub servers; harmless for R2
        // Plain (non-chunked) uploads: no SDK-computed trailer checksums, so
        // every S3-compatible store accepts the PUT as-is.
        requestChecksumCalculation: "WHEN_REQUIRED",
        responseChecksumValidation: "WHEN_REQUIRED",
        credentials: { accessKeyId: cfg.accessKeyId, secretAccessKey: cfg.secretAccessKey }
      })
    };
  }
  return clientCache.client;
}

function newObjectKey() {
  return `files/${require("crypto").randomUUID()}`;
}

async function putObject(key, buffer, mime, env = process.env) {
  const cfg = storageConfig(env);
  if (!cfg) throw new Error("Object storage is not configured.");
  const { PutObjectCommand } = loadSdk();
  await getClient(cfg).send(new PutObjectCommand({ Bucket: cfg.bucket, Key: key, Body: buffer, ContentType: mime }));
}

async function deleteObject(key, env = process.env) {
  const cfg = storageConfig(env);
  if (!cfg) throw new Error("Object storage is not configured.");
  const { DeleteObjectCommand } = loadSdk();
  await getClient(cfg).send(new DeleteObjectCommand({ Bucket: cfg.bucket, Key: key }));
}

async function listObjects(prefix = "files/", env = process.env) {
  const cfg = storageConfig(env);
  if (!cfg) throw new Error("Object storage is not configured.");
  const { ListObjectsV2Command } = loadSdk();
  const out = [];
  let token;
  do {
    const page = await getClient(cfg).send(new ListObjectsV2Command({ Bucket: cfg.bucket, Prefix: prefix, ContinuationToken: token }));
    for (const obj of page.Contents || []) out.push({ key: obj.Key, lastModified: obj.LastModified });
    token = page.IsTruncated ? page.NextContinuationToken : undefined;
  } while (token);
  return out;
}

/* Short-lived presigned GET URL — the only way file bytes leave the bucket. */
async function signedDownloadUrl(key, expiresInSec = 300, env = process.env) {
  const cfg = storageConfig(env);
  if (!cfg) throw new Error("Object storage is not configured.");
  const { GetObjectCommand, getSignedUrl } = loadSdk();
  return getSignedUrl(getClient(cfg), new GetObjectCommand({ Bucket: cfg.bucket, Key: key }), { expiresIn: expiresInSec });
}

module.exports = { storageConfig, storageMode, newObjectKey, putObject, deleteObject, listObjects, signedDownloadUrl };
