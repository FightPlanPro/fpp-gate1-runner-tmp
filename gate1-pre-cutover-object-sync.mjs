import { createHash } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";

const EMPTY_MD5 = "d41d8cd98f00b204e9800998ecf8427e";

function isProvenEmptyMarker(key, meta) {
  return !!meta && typeof key === "string" && key.endsWith("/") && Number(meta.size) === 0 && meta.md5 === EMPTY_MD5;
}

function stageError(stage) {
  const err = new Error(stage);
  err.stage = stage;
  return err;
}

function markerBody(downloadFailed, downloaded) {
  if (downloadFailed) return Buffer.alloc(0);
  return downloaded;
}

function assertEmptyMarkerBody(body, expected) {
  const md5 = createHash("md5").update(body).digest("hex");
  if (Number(expected.size) !== 0 || expected.md5 !== EMPTY_MD5 || body.length !== 0 || md5 !== EMPTY_MD5) {
    throw stageError("NON_EMPTY_SLASH");
  }
  return md5;
}

function copyRoute(key, meta) {
  if (!meta || !meta.md5) return "NO_MD5";
  if (key.endsWith("/") && !isProvenEmptyMarker(key, meta)) return "NON_EMPTY_SLASH";
  if (isProvenEmptyMarker(key, meta)) return "EMPTY_MARKER";
  return "NORMAL";
}

if (process.argv.includes("--self-test")) {
  let failed = 0;
  const check = (name, cond) => {
    if (!cond) {
      console.log("SELF_TEST_FAIL=" + name);
      failed++;
    }
  };
  const empty = { size: 0, md5: EMPTY_MD5 };
  check("public-marker", isProvenEmptyMarker("public/", empty));
  check("nested-marker", isProvenEmptyMarker("public/a/", empty));
  check("file-not-marker", !isProvenEmptyMarker("public/file.txt", empty));
  check("nonzero-size", !isProvenEmptyMarker("public/", { size: 1, md5: EMPTY_MD5 }));
  check("wrong-md5", !isProvenEmptyMarker("public/", { size: 0, md5: "ab".repeat(16) }));
  check("missing-md5", !isProvenEmptyMarker("public/", { size: 0, md5: "" }));
  const fallback = markerBody(true, null);
  check("fallback-empty", fallback.length === 0 && createHash("md5").update(fallback).digest("hex") === EMPTY_MD5);
  let rejectedBody = false;
  try { assertEmptyMarkerBody(Buffer.from("x"), empty); } catch (err) { rejectedBody = err.stage === "NON_EMPTY_SLASH"; }
  check("nonempty-body-fails", rejectedBody);
  let rejectedMeta = false;
  try { assertEmptyMarkerBody(Buffer.alloc(0), { size: 4, md5: EMPTY_MD5 }); } catch (err) { rejectedMeta = err.stage === "NON_EMPTY_SLASH"; }
  check("nonzero-meta-fails", rejectedMeta);
  check("empty-body-ok", assertEmptyMarkerBody(Buffer.alloc(0), empty) === EMPTY_MD5);
  check("content-md5", Buffer.from(EMPTY_MD5, "hex").toString("base64") === "1B2M2Y8AsgTpgAmY7PhCfg==");
  check("route-public", copyRoute("public/", empty) === "EMPTY_MARKER");
  check("route-nonempty-slash", copyRoute("public/file/", { size: 5, md5: EMPTY_MD5 }) === "NON_EMPTY_SLASH");
  check("route-zero-wrong-md5", copyRoute("public/", { size: 0, md5: "ab".repeat(16) }) === "NON_EMPTY_SLASH");
  check("route-normal", copyRoute("meal.jpg", { size: 5, md5: "ab".repeat(16) }) === "NORMAL");
  check("route-no-md5", copyRoute("x", { size: 0, md5: "" }) === "NO_MD5");
  check("stages", ["DOWNLOAD", "PUT", "VERIFY", "NO_MD5", "SOURCE_MISMATCH"].every((stage) => stageError(stage).stage === stage));
  if (failed) process.exit(1);
  console.log("SELF_TEST_PASS=YES");
  process.exit(0);
}

const dir = "/tmp/fpp-gate1";
const secretPaths = ["payload.json", "password.raw", "password.bin", "wrap.bin", "cipher.bin"].map((name) => `${dir}/${name}`);
function wipeSecrets() {
  for (const path of secretPaths) {
    try { rmSync(path, { force: true }); } catch {}
  }
}
function wipeKey() {
  for (const name of ["priv.pem", "sealed.bin"]) {
    try { rmSync(`${dir}/${name}`, { force: true }); } catch {}
  }
}
function fail(message) {
  wipeSecrets();
  wipeKey();
  console.log(message);
  process.exit(1);
}
process.on("uncaughtException", () => fail("GATE_1_FAILED"));
process.on("unhandledRejection", () => fail("GATE_1_FAILED"));

const acceptedKeys = [
  "meal-scans/cau_2bc240b111df44498ae99566b4bfae27/f0cd95ad-08c5-40c4-bff9-db343a665387.jpg",
  "meal-scans/cau_a3a4b98a0b5c4a2e9346f3ee4f8473d3/b3f54b4c-7ea8-4d19-aca5-ab95f2f666cc.jpg",
  "meal-scans/user_39Uz5RMNZmdnlHSfrYzoxKRMrS3/df80c3eb-d90b-4c1d-aae4-74908620a16a.jpg",
  "fitness-photos/user_39Uz5RMNZmdnlHSfrYzoxKRMrS3/front-1790540343224.jpg",
  "fitness-photos/user_39Uz5RMNZmdnlHSfrYzoxKRMrS3/side-1790540354971.jpg",
  "fitness-photos/user_39Uz5RMNZmdnlHSfrYzoxKRMrS3/back-1790540381961.jpg",
];
const accepted = new Set(acceptedKeys.map((key) => createHash("sha256").update(key).digest("hex")));
mkdirSync(dir, { recursive: true });
writeFileSync(`${dir}/accepted-unavailable.sha256`, [...accepted].join("\n") + "\n", { mode: 0o600 });
chmodSync(`${dir}/accepted-unavailable.sha256`, 0o600);

const blob = readFileSync(`${dir}/sealed.bin`);
if (!blob.subarray(0, 6).equals(Buffer.from("FPPG1\n")) || blob.length < 8) fail("SEALED_FORMAT_REJECTED");
const wrapLen = blob.readUInt16BE(6);
const wrapped = blob.subarray(8, 8 + wrapLen);
const cipher = blob.subarray(8 + wrapLen);
if (wrapLen < 256 || cipher.length < 16 || !cipher.subarray(0, 8).equals(Buffer.from("Salted__"))) fail("SEALED_FORMAT_REJECTED");
writeFileSync(`${dir}/wrap.bin`, wrapped, { mode: 0o600 });
writeFileSync(`${dir}/cipher.bin`, cipher, { mode: 0o600 });
const decrypted = spawnSync("openssl", [
  "pkeyutl", "-decrypt", "-inkey", `${dir}/priv.pem`,
  "-pkeyopt", "rsa_padding_mode:oaep",
  "-pkeyopt", "rsa_oaep_md:sha256",
  "-pkeyopt", "rsa_mgf1_md:sha256",
  "-in", `${dir}/wrap.bin`,
  "-out", `${dir}/password.raw`,
], { encoding: "utf8" });
if (decrypted.status !== 0) fail("SEALED_DECRYPT_FAILED");
const password = readFileSync(`${dir}/password.raw`);
if (password.length !== 64 || !/^[0-9a-f]+$/.test(password.toString("ascii"))) fail("SEALED_DECRYPT_FAILED");
writeFileSync(`${dir}/password.bin`, Buffer.concat([password, Buffer.from("\n")]), { mode: 0o600 });
const opened = spawnSync("openssl", [
  "enc", "-d", "-aes-256-cbc", "-pbkdf2",
  "-pass", `file:${dir}/password.bin`,
  "-in", `${dir}/cipher.bin`,
  "-out", `${dir}/payload.json`,
], { encoding: "utf8" });
if (opened.status !== 0) fail("SEALED_DECRYPT_FAILED");
chmodSync(`${dir}/payload.json`, 0o600);
let payload;
try { payload = JSON.parse(readFileSync(`${dir}/payload.json`, "utf8")); } catch { fail("SEALED_DECRYPT_FAILED"); }
wipeSecrets();
const accessKeyId = String(payload.R2_PRODUCTION_ACCESS_KEY_ID || "");
const secretAccessKey = String(payload.R2_PRODUCTION_SECRET_ACCESS_KEY || "");
const endpoint = String(payload.R2_PRODUCTION_ENDPOINT || "").replace(/\/+$/, "");
payload.R2_PRODUCTION_ACCESS_KEY_ID = "";
payload.R2_PRODUCTION_SECRET_ACCESS_KEY = "";
payload.R2_PRODUCTION_ENDPOINT = "";
if (!accessKeyId || !secretAccessKey || !endpoint.startsWith("https://")) fail("SEALED_PAYLOAD_REJECTED");
const sourceBucket = String(process.env.DEFAULT_OBJECT_STORAGE_BUCKET_ID || "");
if (!sourceBucket) fail("SOURCE_BUCKET_MISSING");
const destBucket = "fight-plan-r2-production";

const { Storage } = await import("@google-cloud/storage");
const { S3Client, ListObjectsV2Command, HeadObjectCommand, GetObjectCommand, PutObjectCommand } = await import("@aws-sdk/client-s3");

const gcs = new Storage({
  credentials: {
    audience: "replit",
    subject_token_type: "access_token",
    token_url: "http://127.0.0.1:1106/token",
    type: "external_account",
    credential_source: { url: "http://127.0.0.1:1106/credential", format: { type: "json", subject_token_field_name: "access_token" } },
    universe_domain: "googleapis.com",
  },
  projectId: "",
});
const r2 = new S3Client({
  region: "auto",
  endpoint,
  forcePathStyle: true,
  credentials: { accessKeyId, secretAccessKey },
});

async function sourceList() {
  const [files] = await gcs.bucket(sourceBucket).getFiles({ autoPaginate: true });
  const out = new Map();
  let bytes = 0;
  for (const file of files) {
    const meta = file.metadata || {};
    const size = Number(meta.size || 0);
    const md5 = meta.md5Hash ? Buffer.from(meta.md5Hash, "base64").toString("hex") : "";
    out.set(file.name, { size, md5 });
    bytes += size;
  }
  return { out, bytes };
}
function etagMd5(etag) {
  const value = String(etag || "").replaceAll('"', "").toLowerCase();
  return /^[0-9a-f]{32}$/.test(value) ? value : "";
}
async function r2List() {
  const out = new Map();
  let token, bytes = 0;
  do {
    const page = await r2.send(new ListObjectsV2Command({ Bucket: destBucket, ContinuationToken: token }));
    for (const item of page.Contents || []) {
      const size = Number(item.Size || 0);
      out.set(item.Key, { size, etag: item.ETag || "" });
      bytes += size;
    }
    token = page.IsTruncated ? page.NextContinuationToken : undefined;
  } while (token);
  return { out, bytes };
}
async function sameObject(key, meta, dest) {
  if (!dest || dest.size !== meta.size || !meta.md5) return false;
  const listed = etagMd5(dest.etag);
  if (listed) return listed === meta.md5;
  const head = await r2.send(new HeadObjectCommand({ Bucket: destBucket, Key: key }));
  const headed = etagMd5(head.ETag);
  if (headed) return headed === meta.md5 && Number(head.ContentLength) === meta.size;
  const got = await r2.send(new GetObjectCommand({ Bucket: destBucket, Key: key }));
  const chunks = [];
  for await (const chunk of got.Body) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  const body = Buffer.concat(chunks);
  return body.length === meta.size && createHash("md5").update(body).digest("hex") === meta.md5;
}
async function putAndVerify(key, body, expected) {
  const md5 = createHash("md5").update(body).digest("hex");
  if (md5 !== expected.md5 || body.length !== expected.size) throw stageError("SOURCE_MISMATCH");
  try {
    await r2.send(new PutObjectCommand({
      Bucket: destBucket,
      Key: key,
      Body: body,
      ContentLength: body.length,
      ContentMD5: Buffer.from(md5, "hex").toString("base64"),
    }));
  } catch (err) {
    err.stage = "PUT";
    throw err;
  }
  let head;
  try {
    head = await r2.send(new HeadObjectCommand({ Bucket: destBucket, Key: key }));
  } catch (err) {
    err.stage = "VERIFY";
    throw err;
  }
  if (Number(head.ContentLength) !== expected.size || etagMd5(head.ETag) !== expected.md5) throw stageError("VERIFY");
}
async function copyOne(key, expected) {
  let body;
  try {
    [body] = await gcs.bucket(sourceBucket).file(key).download();
  } catch (err) {
    err.stage = "DOWNLOAD";
    throw err;
  }
  if (key.endsWith("/") && !isProvenEmptyMarker(key, expected)) throw stageError("NON_EMPTY_SLASH");
  await putAndVerify(key, body, expected);
}
async function copyEmptyMarker(key, expected) {
  if (!isProvenEmptyMarker(key, expected)) throw stageError("NON_EMPTY_SLASH");
  let body;
  try {
    const [downloaded] = await gcs.bucket(sourceBucket).file(key).download();
    body = markerBody(false, downloaded);
  } catch {
    body = markerBody(true, null);
  }
  assertEmptyMarkerBody(body, expected);
  await putAndVerify(key, body, expected);
}

let firstSource = await sourceList();
const beforeR2 = await r2List();
let exact = 0, sourceOnly = 0, different = 0, destOnly = 0;
const work = [];
for (const [key, meta] of firstSource.out) {
  const dest = beforeR2.out.get(key);
  if (!dest) { sourceOnly++; work.push(key); continue; }
  if (await sameObject(key, meta, dest)) exact++;
  else { different++; work.push(key); }
}
for (const key of beforeR2.out.keys()) if (!firstSource.out.has(key)) destOnly++;

let copied = 0, replaced = 0, bytesCopied = 0, acceptedUnreadable = 0;
const seenAccepted = new Set();
for (const key of work) {
  const meta = firstSource.out.get(key);
  const route = copyRoute(key, meta);
  if (route === "NO_MD5") {
    if (accepted.has(createHash("sha256").update(key).digest("hex"))) { acceptedUnreadable++; continue; }
    fail("COPY_FAILURE_STAGE=NO_MD5 KEY=" + key);
  }
  if (route === "NON_EMPTY_SLASH") fail("COPY_FAILURE_STAGE=NON_EMPTY_SLASH KEY=" + key);
  const existed = beforeR2.out.has(key);
  let ok = false;
  let stage = "UNKNOWN";
  for (let attempt = 1; attempt <= 2 && !ok; attempt++) {
    try {
      if (route === "EMPTY_MARKER") await copyEmptyMarker(key, meta);
      else await copyOne(key, meta);
      ok = true;
    } catch (err) {
      stage = err.stage || "UNKNOWN";
    }
  }
  const keyHash = createHash("sha256").update(key).digest("hex");
  if (!ok) {
    if (accepted.has(keyHash)) { acceptedUnreadable++; seenAccepted.add(keyHash); continue; }
    fail("COPY_FAILURE_STAGE=" + stage + " KEY=" + key);
  }
  if (accepted.has(keyHash)) seenAccepted.add(keyHash);
  copied++;
  if (existed) replaced++;
  bytesCopied += meta.size;
}

const source = await sourceList();
const afterR2 = await r2List();
let sourceOnlyAfter = 0, differentAfter = 0, absentAccepted = 0, presentAccepted = 0;
for (const key of acceptedKeys) {
  if (source.out.has(key)) presentAccepted++;
  else absentAccepted++;
}
for (const [key, meta] of source.out) {
  const hash = createHash("sha256").update(key).digest("hex");
  const dest = afterR2.out.get(key);
  let matches = false;
  try { matches = await sameObject(key, meta, dest); } catch { matches = false; }
  if (matches) continue;
  if (accepted.has(hash)) {
    try { await gcs.bucket(sourceBucket).file(key).download(); }
    catch { continue; }
  }
  if (!dest) sourceOnlyAfter++;
  else differentAfter++;
}
wipeSecrets();
wipeKey();
const present = sourceOnlyAfter === 0 && differentAfter === 0;
console.log("SOURCE_INVENTORY_OBJECT_COUNT=" + firstSource.out.size);
console.log("SOURCE_INVENTORY_TOTAL_BYTES=" + firstSource.bytes);
console.log("R2_BEFORE_OBJECT_COUNT=" + beforeR2.out.size);
console.log("R2_BEFORE_TOTAL_BYTES=" + beforeR2.bytes);
console.log("EXACT_MATCHES_BEFORE=" + exact);
console.log("SOURCE_ONLY_BEFORE=" + sourceOnly);
console.log("CHECKSUM_DIFFERENT_BEFORE=" + different);
console.log("DESTINATION_ONLY_BEFORE=" + destOnly);
console.log("OBJECTS_COPIED=" + copied);
console.log("OBJECTS_REPLACED_IN_R2=" + replaced);
console.log("COPY_FAILURES=0");
console.log("BYTES_COPIED=" + bytesCopied);
console.log("POST_COPY_SOURCE_INVENTORY_OBJECT_COUNT=" + source.out.size);
console.log("POST_COPY_SOURCE_INVENTORY_TOTAL_BYTES=" + source.bytes);
console.log("R2_AFTER_OBJECT_COUNT=" + afterR2.out.size);
console.log("R2_AFTER_TOTAL_BYTES=" + afterR2.bytes);
console.log("RECOVERABLE_SOURCE_ONLY_AFTER=" + sourceOnlyAfter);
console.log("RECOVERABLE_CHECKSUM_DIFFERENT_AFTER=" + differentAfter);
console.log("SIX_ACCEPTED_UNAVAILABLE_OBJECTS_STATUS=UNREADABLE:" + acceptedUnreadable + ",ABSENT:" + absentAccepted + ",PRESENT:" + presentAccepted);
console.log("ALL_CURRENT_RECOVERABLE_SOURCE_OBJECTS_PRESENT_IN_R2=" + (present ? "YES" : "NO"));
console.log("GATE_1_COMPLETE=" + (present ? "YES" : "NO"));
if (!present) process.exit(1);
