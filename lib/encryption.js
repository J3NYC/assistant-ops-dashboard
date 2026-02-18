const crypto = require("crypto");
const bcrypt = require("bcryptjs");

const KEY_ENV = process.env.DATA_ENCRYPTION_KEY || "";

function resolveKey() {
  if (!KEY_ENV) throw new Error("DATA_ENCRYPTION_KEY is required");

  // Accept 32-byte raw, base64, or hex.
  const asBase64 = Buffer.from(KEY_ENV, "base64");
  if (asBase64.length === 32) return asBase64;

  const asHex = Buffer.from(KEY_ENV, "hex");
  if (asHex.length === 32) return asHex;

  const raw = Buffer.from(KEY_ENV, "utf8");
  if (raw.length === 32) return raw;

  throw new Error("DATA_ENCRYPTION_KEY must decode to 32 bytes for AES-256-GCM");
}

function encrypt(plaintext) {
  const key = resolveKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(String(plaintext), "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.from(JSON.stringify({
    alg: "aes-256-gcm",
    iv: iv.toString("base64"),
    tag: tag.toString("base64"),
    data: encrypted.toString("base64"),
  })).toString("base64");
}

function decrypt(ciphertextB64) {
  const key = resolveKey();
  const payload = JSON.parse(Buffer.from(String(ciphertextB64), "base64").toString("utf8"));
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(payload.iv, "base64"));
  decipher.setAuthTag(Buffer.from(payload.tag, "base64"));
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(payload.data, "base64")),
    decipher.final(),
  ]);
  return decrypted.toString("utf8");
}

async function hashSecret(secret) {
  return bcrypt.hash(String(secret), 12);
}

async function verifySecret(secret, hash) {
  return bcrypt.compare(String(secret), String(hash));
}

module.exports = { encrypt, decrypt, hashSecret, verifySecret };
