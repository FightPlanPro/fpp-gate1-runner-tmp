import { spawnSync } from "node:child_process";
import { chmodSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { S3Client, ListObjectsV2Command } from "@aws-sdk/client-s3";

const dir = "/tmp/fpp-gate1";
const secretPaths = ["payload.json", "password.raw", "password.bin", "wrap.bin", "cipher.bin"].map((name) => `${dir}/${name}`);
function wipeSecrets() {
  for (const path of secretPaths) {
    try { rmSync(path, { force: true }); } catch {}
  }
}
function fail(code) {
  wipeSecrets();
  console.log("R2_LIST_SUCCESS=NO");
  console.log("R2_LIST_ERROR=" + code);
  process.exit(1);
}
process.on("uncaughtException", () => fail("UNCAUGHT"));
process.on("unhandledRejection", () => fail("UNCAUGHT"));
process.stderr.write = () => true;

const blob = readFileSync(`${dir}/sealed.bin`);
if (!blob.subarray(0, 6).equals(Buffer.from("FPPG1\n")) || blob.length < 8) fail("SEALED_FORMAT_REJECTED");
const wrapLen = blob.readUInt16BE(6);
const wrapped = blob.subarray(8, 8 + wrapLen);
const cipher = blob.subarray(8 + wrapLen);
if (wrapLen < 256 || cipher.length < 16 || !cipher.subarray(0, 8).equals(Buffer.from("Salted__"))) fail("SEALED_FORMAT_REJECTED");
writeFileSync(`${dir}/wrap.bin`, wrapped, { mode: 0o600 });
writeFileSync(`${dir}/cipher.bin`, cipher, { mode: 0o600 });
const decrypted = spawnSync("openssl", ["pkeyutl", "-decrypt", "-inkey", `${dir}/priv.pem`, "-pkeyopt", "rsa_padding_mode:oaep", "-pkeyopt", "rsa_oaep_md:sha256", "-pkeyopt", "rsa_mgf1_md:sha256", "-in", `${dir}/wrap.bin`, "-out", `${dir}/password.raw`], { encoding: "utf8" });
if (decrypted.status !== 0) fail("SEALED_DECRYPT_FAILED");
const password = readFileSync(`${dir}/password.raw`);
if (password.length !== 64 || !/^[0-9a-f]+$/.test(password.toString("ascii"))) fail("SEALED_DECRYPT_FAILED");
writeFileSync(`${dir}/password.bin`, Buffer.concat([password, Buffer.from("\n")]), { mode: 0o600 });
const opened = spawnSync("openssl", ["enc", "-d", "-aes-256-cbc", "-pbkdf2", "-pass", `file:${dir}/password.bin`, "-in", `${dir}/cipher.bin`, "-out", `${dir}/payload.json`], { encoding: "utf8" });
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

const r2 = new S3Client({ region: "auto", endpoint, forcePathStyle: true, credentials: { accessKeyId, secretAccessKey } });
let token, count = 0, bytes = 0;
try {
  do {
    const page = await r2.send(new ListObjectsV2Command({ Bucket: "fight-plan-r2-production", ContinuationToken: token }));
    for (const item of page.Contents || []) {
      count++;
      bytes += Number(item.Size || 0);
    }
    token = page.IsTruncated ? page.NextContinuationToken : undefined;
  } while (token);
} catch (err) {
  const status = Number(err && err.$metadata && err.$metadata.httpStatusCode);
  const statusOk = Number.isInteger(status) && status >= 100 && status <= 599 ? "STATUS=" + status : "";
  const name = err && typeof err.name === "string" && /^[A-Za-z][A-Za-z0-9]*$/.test(err.name) ? "NAME=" + err.name : "";
  fail([statusOk, name].filter(Boolean).join(" ") || "UNCLASSIFIED");
}
console.log("R2_LIST_SUCCESS=YES");
console.log("R2_OBJECT_COUNT=" + count);
console.log("R2_TOTAL_BYTES=" + bytes);
const child = spawnSync(process.execPath, [`${dir}/gate1.mjs`], { stdio: "inherit", env: process.env });
process.exit(child.status === null ? 1 : child.status);
