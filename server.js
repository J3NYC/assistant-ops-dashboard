const express = require("express");
const { exec } = require("child_process");
const path = require("path");
const crypto = require("crypto");
const fs = require("fs");
const http = require("http");
const https = require("https");
const tls = require("tls");
const net = require("net");
const jwt = require("jsonwebtoken");

let createRedisClient = null;
try {
  ({ createClient: createRedisClient } = require("redis"));
} catch {
  createRedisClient = null;
}

const app = express();
const HTTPS_PORT = Number(process.env.HTTPS_PORT || process.env.PORT || 443);
const HTTP_PORT = Number(process.env.HTTP_PORT || 80);
const CERT_FILE = process.env.TLS_CERT_PATH || path.join(__dirname, "certs", "fullchain.pem");
const KEY_FILE = process.env.TLS_KEY_PATH || path.join(__dirname, "certs", "privkey.pem");
const TLS_MIN_VERSION = "TLSv1.2";
const TLS_CIPHERS = [
  "ECDHE-ECDSA-AES128-GCM-SHA256",
  "ECDHE-RSA-AES128-GCM-SHA256",
  "ECDHE-ECDSA-AES256-GCM-SHA384",
  "ECDHE-RSA-AES256-GCM-SHA384",
].join(":");

const ALLOWED_ORIGINS = String(process.env.ALLOWED_ORIGINS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);
const ALLOWED_METHODS = String(process.env.ALLOWED_METHODS || "GET,POST,OPTIONS");
const ALLOWED_HEADERS = String(process.env.ALLOWED_HEADERS || "Authorization,Content-Type");
const CORS_MAX_AGE_SECONDS = 86400;

const ADMIN_ALLOWED_IPS = String(process.env.ADMIN_ALLOWED_IPS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);
const WEBHOOK_ALLOWED_IPS = String(process.env.WEBHOOK_ALLOWED_IPS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);
const WEBHOOK_HMAC_SECRET = String(process.env.WEBHOOK_HMAC_SECRET || "");
const IS_PRODUCTION = process.env.NODE_ENV === "production";

const REDIS_URL = process.env.REDIS_URL || "redis://127.0.0.1:6379";
const REDIS_KEY_PREFIX = process.env.RATE_LIMIT_REDIS_PREFIX || "aod:rl:";
const INTERNAL_MONITORING_IPS = String(process.env.INTERNAL_MONITORING_IPS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);
const INTERNAL_MONITORING_HEADER = process.env.INTERNAL_MONITORING_HEADER || "x-internal-monitoring";
const INTERNAL_MONITORING_HEADER_VALUE = process.env.INTERNAL_MONITORING_HEADER_VALUE || "allow";

const CIRCUIT_BREAKER_WEBHOOK = process.env.CIRCUIT_BREAKER_WEBHOOK || "";
const CIRCUIT_BREAKER_EMAIL = process.env.CIRCUIT_BREAKER_EMAIL || "";
const DEFAULT_COST_LIMITS = {
  warning: Number(process.env.CIRCUIT_BREAKER_WARNING || 100),
  soft: Number(process.env.CIRCUIT_BREAKER_SOFT || 250),
  hard: Number(process.env.CIRCUIT_BREAKER_HARD || 500),
  emergency: Number(process.env.CIRCUIT_BREAKER_EMERGENCY || 1000),
};

const MODEL_COSTS_PER_MILLION = {
  haiku: { input: 0.25, output: 1.25 },
  sonnet: { input: 3, output: 15 },
  opus: { input: 15, output: 75 },
};

const ACCESS_TOKEN_TTL_SECONDS = 15 * 60; // 15 minutes
const REFRESH_TOKEN_TTL_SECONDS = 7 * 24 * 60 * 60; // 7 days
const SESSION_ABSOLUTE_TIMEOUT_MS = 24 * 60 * 60 * 1000; // 24h
const SESSION_SLIDING_WINDOW_MS = 15 * 60 * 1000; // 15m
const MAX_CONCURRENT_SESSIONS = 3;

const JWT_ISSUER = process.env.JWT_ISSUER || "assistant-ops-dashboard";
const JWT_AUDIENCE = process.env.JWT_AUDIENCE || "assistant-ops-dashboard-api";
const COOKIE_DOMAIN = process.env.AUTH_COOKIE_DOMAIN || undefined;

const JWT_KEY_DIR = path.join(__dirname, "keys");
const PRIVATE_KEY_PATH = path.join(JWT_KEY_DIR, "jwtRS256.key");
const PUBLIC_KEY_PATH = path.join(JWT_KEY_DIR, "jwtRS256.key.pub");

const ACCESS_COOKIE = "ops_access_token";
const REFRESH_COOKIE = "ops_refresh_token";
const SESSION_COOKIE = "ops_session_id";

https.globalAgent.options.rejectUnauthorized = true;

const CERT_PIN_MAP = (() => {
  const raw = process.env.TLS_PINNED_SPKI_SHA256 || "";
  // Format: host=sha256/base64,host2=sha256/base64
  const out = new Map();
  for (const part of raw.split(",").map((s) => s.trim()).filter(Boolean)) {
    const [host, pin] = part.split("=");
    if (host && pin) out.set(host.trim().toLowerCase(), pin.trim());
  }
  return out;
})();

function pinnedCheckServerIdentity(hostname, cert) {
  const defaultErr = tls.checkServerIdentity(hostname, cert);
  if (defaultErr) return defaultErr;

  const pin = CERT_PIN_MAP.get(String(hostname || "").toLowerCase());
  if (!pin) return undefined;

  const expected = pin.replace(/^sha256\//, "");
  const pubkey = cert?.pubkey;
  if (!pubkey) return new Error(`Pinning failed for ${hostname}: no pubkey available`);

  const actual = crypto.createHash("sha256").update(pubkey).digest("base64");
  if (actual !== expected) {
    return new Error(`Pinning failed for ${hostname}: SPKI mismatch`);
  }
  return undefined;
}

const ROLES = {
  owner: {
    permissions: ["*"],
    models: ["*"],
    rateLimitPerMin: 100,
    dailyCostCap: null,
  },
  admin: {
    permissions: [
      "dashboard:read",
      "gateway:restart",
      "config:read",
      "models:all",
      "keys:rotate",
    ],
    models: ["*"],
    rateLimitPerMin: 60,
    dailyCostCap: 500,
  },
  developer: {
    permissions: ["dashboard:read", "config:read", "keys:own:rotate", "models:limited"],
    models: ["claude-3-5-sonnet", "claude-3-5-haiku", "sonnet", "haiku"],
    rateLimitPerMin: 30,
    dailyCostCap: 100,
  },
  api_consumer: {
    permissions: ["models:key-assigned"],
    models: [],
    rateLimitPerMin: 20,
    dailyCostCap: 50,
  },
  viewer: {
    permissions: ["dashboard:read"],
    models: [],
    rateLimitPerMin: 10,
    dailyCostCap: 0,
  },
};

const API_KEY_LIMITS = (() => {
  try {
    const raw = process.env.API_KEY_RBAC_CONFIG;
    return raw ? JSON.parse(raw) : {};
  } catch {
    return {};
  }
})();

const usersById = new Map([
  [
    "u_owner",
    {
      id: "u_owner",
      username: "owner",
      password: process.env.DASHBOARD_OWNER_PASSWORD || "change-me-now",
      role: "owner",
      disabled: false,
      assignedModels: ["*"],
    },
  ],
  [
    "u_admin",
    {
      id: "u_admin",
      username: "ops-admin",
      password: process.env.DASHBOARD_ADMIN_PASSWORD || "change-me-now",
      role: "admin",
      disabled: false,
      assignedModels: ["*"],
    },
  ],
  [
    "u_developer",
    {
      id: "u_developer",
      username: "ops-dev",
      password: process.env.DASHBOARD_DEVELOPER_PASSWORD || "change-me-now",
      role: "developer",
      disabled: false,
      assignedModels: ["sonnet", "haiku"],
    },
  ],
  [
    "u_api_consumer",
    {
      id: "u_api_consumer",
      username: "ops-api",
      password: process.env.DASHBOARD_API_PASSWORD || "change-me-now",
      role: "api_consumer",
      apiKeyId: "ak_ops_default",
      disabled: false,
      assignedModels: ["claude-3-5-haiku"],
    },
  ],
  [
    "u_viewer",
    {
      id: "u_viewer",
      username: "ops-viewer",
      password: process.env.DASHBOARD_VIEWER_PASSWORD || "change-me-now",
      role: "viewer",
      disabled: false,
      assignedModels: [],
    },
  ],
]);
const usersByUsername = new Map(Array.from(usersById.values()).map((u) => [u.username, u]));

const sessionsById = new Map();
const refreshTokenStore = new Map(); // hash(token) -> { userId, sessionId, expiresAtMs }
const rateWindowStore = new Map();
const dailyCostStore = new Map();

let redisClient = null;
let redisReady = false;

async function initRedis() {
  if (!createRedisClient) {
    console.warn("[rate-limit] redis package not installed; fail-open mode enabled");
    return;
  }
  try {
    redisClient = createRedisClient({ url: REDIS_URL });
    redisClient.on("error", (err) => {
      redisReady = false;
      console.warn(`[rate-limit] redis error: ${err.message}`);
    });
    redisClient.on("ready", () => {
      redisReady = true;
      console.log("[rate-limit] redis connected");
    });
    await redisClient.connect();
    redisReady = true;
  } catch (err) {
    redisReady = false;
    console.warn(`[rate-limit] redis unavailable, fail-open mode: ${err.message}`);
  }
}

function rlKey(name) {
  return `${REDIS_KEY_PREFIX}${name}`;
}

function maskApiKey(key) {
  const s = String(key || "");
  return s ? `***${s.slice(-4)}` : "none";
}

function isInternalMonitoringRequest(req) {
  const protectedAdminPath = req.path.startsWith("/admin/") || req.path.startsWith("/api/v1/admin/");
  if (protectedAdminPath) return false;
  const ipAllowed = INTERNAL_MONITORING_IPS.length && ipMatchesAny(getClientIp(req), INTERNAL_MONITORING_IPS);
  const headerAllowed = String(req.headers[INTERNAL_MONITORING_HEADER] || "") === INTERNAL_MONITORING_HEADER_VALUE;
  return Boolean(ipAllowed || headerAllowed);
}

function shouldBypassIpRateLimit(req) {
  if (req.path === "/health") return true;
  if (isInternalMonitoringRequest(req)) return true;
  return false;
}

async function redisFailOpen(action, fallback) {
  if (!redisReady || !redisClient) {
    return { ok: true, failOpen: true, value: fallback };
  }
  try {
    const value = await action();
    return { ok: true, failOpen: false, value };
  } catch (err) {
    console.warn(`[rate-limit] redis action failed (fail-open): ${err.message}`);
    return { ok: true, failOpen: true, value: fallback };
  }
}

async function ipSlidingWindowCheck(ip, limit = 100, windowMs = 60_000) {
  const now = Date.now();
  const key = rlKey(`ip:${ip}:events`);
  const result = await redisFailOpen(async () => {
    const minTs = now - windowMs;
    await redisClient.zRemRangeByScore(key, 0, minTs);
    await redisClient.zAdd(key, [{ score: now, value: `${now}-${Math.random()}` }]);
    const count = await redisClient.zCard(key);
    await redisClient.pExpire(key, windowMs);
    return Number(count);
  }, 0);

  if (result.failOpen) return { allowed: true, count: 0, retryAfterSec: 0 };
  const count = result.value;
  const allowed = count <= limit;
  return {
    allowed,
    count,
    retryAfterSec: allowed ? 0 : Math.ceil(windowMs / 1000),
  };
}

async function tokenBucketCheck(bucketId, capacity = 60, refillPerSec = 1) {
  const nowSec = Date.now() / 1000;
  const key = rlKey(`bucket:${bucketId}`);

  const result = await redisFailOpen(async () => {
    const arr = await redisClient.hmGet(key, ["tokens", "last"]);
    let tokens = arr[0] ? Number(arr[0]) : capacity;
    let last = arr[1] ? Number(arr[1]) : nowSec;
    const elapsed = Math.max(0, nowSec - last);
    tokens = Math.min(capacity, tokens + elapsed * refillPerSec);

    if (tokens < 1) {
      await redisClient.hSet(key, { tokens: String(tokens), last: String(nowSec) });
      await redisClient.expire(key, 120);
      return { allowed: false, remaining: Math.floor(tokens), resetSec: Math.ceil((1 - tokens) / refillPerSec) };
    }

    tokens -= 1;
    await redisClient.hSet(key, { tokens: String(tokens), last: String(nowSec) });
    await redisClient.expire(key, 120);
    return { allowed: true, remaining: Math.floor(tokens), resetSec: Math.ceil((capacity - tokens) / refillPerSec) };
  }, { allowed: true, remaining: capacity - 1, resetSec: 60 });

  return result.value;
}

function modelLimitFor(modelName) {
  const m = String(modelName || "").toLowerCase();
  if (m.includes("haiku")) return { reqPerMin: 60, tokPerMin: 100_000, name: "haiku" };
  if (m.includes("sonnet")) return { reqPerMin: 30, tokPerMin: 50_000, name: "sonnet" };
  if (m.includes("opus")) return { reqPerMin: 10, tokPerMin: 20_000, name: "opus" };
  return null;
}

async function modelRateLimitCheck(identity, modelName, estimatedTokens = 0) {
  const limit = modelLimitFor(modelName);
  if (!limit) return { allowed: true };
  const nowMinute = Math.floor(Date.now() / 60000);
  const reqKey = rlKey(`model:${identity}:${limit.name}:req:${nowMinute}`);
  const tokKey = rlKey(`model:${identity}:${limit.name}:tok:${nowMinute}`);

  const result = await redisFailOpen(async () => {
    const reqCount = Number(await redisClient.incr(reqKey));
    if (reqCount === 1) await redisClient.expire(reqKey, 70);

    const tokCount = Number(await redisClient.incrBy(tokKey, Math.max(0, Number(estimatedTokens || 0))));
    if (tokCount === Number(estimatedTokens || 0)) await redisClient.expire(tokKey, 70);

    return {
      allowed: reqCount <= limit.reqPerMin && tokCount <= limit.tokPerMin,
      reqCount,
      tokCount,
      limit,
    };
  }, { allowed: true, reqCount: 0, tokCount: 0, limit });

  return result.value;
}

async function registerRateLimitViolation(ip) {
  const now = Date.now();
  const key5 = rlKey(`viol:${ip}:5m`);
  const key15 = rlKey(`viol:${ip}:15m`);
  const blockKey = rlKey(`block:${ip}`);

  const result = await redisFailOpen(async () => {
    await redisClient.zAdd(key5, [{ score: now, value: `${now}-${Math.random()}` }]);
    await redisClient.zRemRangeByScore(key5, 0, now - 5 * 60_000);
    await redisClient.pExpire(key5, 5 * 60_000);
    const hits5 = Number(await redisClient.zCard(key5));

    await redisClient.zAdd(key15, [{ score: now, value: `${now}-${Math.random()}` }]);
    await redisClient.zRemRangeByScore(key15, 0, now - 15 * 60_000);
    await redisClient.pExpire(key15, 15 * 60_000);
    const hits15 = Number(await redisClient.zCard(key15));

    let blockSec = 0;
    if (hits15 >= 50) {
      blockSec = 3600;
      await redisClient.setEx(blockKey, blockSec, "1");
      console.error(`[rate-limit-alert] ip=${ip} hits15=${hits15} action=block_1h ts=${new Date().toISOString()}`);
    } else if (hits5 >= 10) {
      blockSec = 300;
      await redisClient.setEx(blockKey, blockSec, "1");
    }

    return { hits5, hits15, blockSec };
  }, { hits5: 0, hits15: 0, blockSec: 0 });

  return result.value;
}

async function getIpBlockTtlSec(ip) {
  const key = rlKey(`block:${ip}`);
  const result = await redisFailOpen(async () => {
    const ttl = Number(await redisClient.ttl(key));
    return ttl > 0 ? ttl : 0;
  }, 0);
  return result.value;
}

function dailyCostDateKey() {
  return new Date().toISOString().slice(0, 10);
}

function modelTier(modelName) {
  const m = String(modelName || "").toLowerCase();
  if (m.includes("haiku")) return "haiku";
  if (m.includes("sonnet")) return "sonnet";
  if (m.includes("opus")) return "opus";
  return "haiku";
}

function calculateRequestCost(modelName, inputTokens = 0, outputTokens = 0) {
  const tier = modelTier(modelName);
  const rates = MODEL_COSTS_PER_MILLION[tier] || MODEL_COSTS_PER_MILLION.haiku;
  const inputCost = (Math.max(0, Number(inputTokens || 0)) / 1_000_000) * rates.input;
  const outputCost = (Math.max(0, Number(outputTokens || 0)) / 1_000_000) * rates.output;
  return { tier, inputCost, outputCost, totalCost: inputCost + outputCost };
}

async function getCircuitBreakerLimits() {
  const key = rlKey("cost:limits");
  const result = await redisFailOpen(async () => {
    const raw = await redisClient.get(key);
    return raw ? JSON.parse(raw) : DEFAULT_COST_LIMITS;
  }, DEFAULT_COST_LIMITS);
  return result.value || DEFAULT_COST_LIMITS;
}

async function setCircuitBreakerLimits(limits) {
  const key = rlKey("cost:limits");
  return redisFailOpen(async () => {
    await redisClient.set(key, JSON.stringify(limits));
    return true;
  }, false);
}

async function isEmergencyManualResetRequired() {
  const key = rlKey("cost:manual_reset_required");
  const result = await redisFailOpen(async () => (await redisClient.get(key)) === "1", false);
  return Boolean(result.value);
}

async function setEmergencyManualResetRequired(required) {
  const key = rlKey("cost:manual_reset_required");
  return redisFailOpen(async () => {
    if (required) await redisClient.set(key, "1");
    else await redisClient.del(key);
    return true;
  }, false);
}

async function sendCircuitBreakerAlert(level, message, details = {}) {
  console.warn(`[circuit-breaker] level=${level} message=${message} details=${JSON.stringify(details)}`);
  if (!CIRCUIT_BREAKER_WEBHOOK) return;
  try {
    const body = JSON.stringify({
      text: `[${level.toUpperCase()}] ${message}`,
      details,
      emailTarget: CIRCUIT_BREAKER_EMAIL || undefined,
    });
    await secureHttpsRequest(CIRCUIT_BREAKER_WEBHOOK, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(body),
      },
    });
  } catch (err) {
    console.warn(`[circuit-breaker] alert send failed: ${err.message}`);
  }
}

async function getCostSnapshot() {
  const day = dailyCostDateKey();
  const globalKey = rlKey(`cost:day:${day}:global`);
  const modelKey = rlKey(`cost:day:${day}:model`);

  const result = await redisFailOpen(async () => {
    const global = Number(await redisClient.get(globalKey) || 0);
    const byModel = await redisClient.hGetAll(modelKey);

    const userKeys = await redisClient.keys(rlKey(`cost:day:${day}:user:*`));
    const keyKeys = await redisClient.keys(rlKey(`cost:day:${day}:key:*`));

    const byUser = {};
    for (const k of userKeys) byUser[k.split(":").at(-1)] = Number(await redisClient.get(k) || 0);
    const byKey = {};
    for (const k of keyKeys) byKey[k.split(":").at(-1)] = Number(await redisClient.get(k) || 0);

    return {
      day,
      global,
      byModel: Object.fromEntries(Object.entries(byModel).map(([k, v]) => [k, Number(v)])),
      byUser,
      byKey,
    };
  }, { day, global: 0, byModel: {}, byUser: {}, byKey: {} });

  return result.value;
}

async function addCostUsage({ modelName, inputTokens, outputTokens, apiKeyId, userId }) {
  const day = dailyCostDateKey();
  const { tier, totalCost } = calculateRequestCost(modelName, inputTokens, outputTokens);
  const ttl = 24 * 60 * 60;

  const globalKey = rlKey(`cost:day:${day}:global`);
  const modelKey = rlKey(`cost:day:${day}:model`);
  const userKey = rlKey(`cost:day:${day}:user:${userId || "unknown"}`);
  const keyKey = rlKey(`cost:day:${day}:key:${apiKeyId || "none"}`);

  await redisFailOpen(async () => {
    await redisClient.incrByFloat(globalKey, totalCost);
    await redisClient.expire(globalKey, ttl);
    await redisClient.hIncrByFloat(modelKey, tier, totalCost);
    await redisClient.expire(modelKey, ttl);
    await redisClient.incrByFloat(userKey, totalCost);
    await redisClient.expire(userKey, ttl);
    await redisClient.incrByFloat(keyKey, totalCost);
    await redisClient.expire(keyKey, ttl);
    return true;
  }, false);

  return { tier, totalCost };
}

async function evaluateCircuitBreaker(modelName) {
  const limits = await getCircuitBreakerLimits();
  const snapshot = await getCostSnapshot();
  const spend = Number(snapshot.global || 0);
  const manualResetRequired = await isEmergencyManualResetRequired();

  if (manualResetRequired) {
    return { action: "suspend_all", limits, snapshot, reason: "manual_reset_required" };
  }

  if (spend >= limits.emergency) {
    await setEmergencyManualResetRequired(true);
    await sendCircuitBreakerAlert("emergency", "Emergency cost shutoff triggered", { spend, limits, snapshot });
    return { action: "suspend_all", limits, snapshot, reason: "emergency" };
  }
  if (spend >= limits.hard) {
    await sendCircuitBreakerAlert("critical", "Hard cost limit reached", { spend, limits, snapshot });
    if (modelTier(modelName) !== "haiku") return { action: "block_non_haiku", limits, snapshot, reason: "hard" };
  } else if (spend >= limits.soft) {
    await sendCircuitBreakerAlert("urgent", "Soft cost limit reached", { spend, limits, snapshot });
    if (modelTier(modelName) === "opus") return { action: "downgrade_to_sonnet", limits, snapshot, reason: "soft" };
  } else if (spend >= limits.warning) {
    await sendCircuitBreakerAlert("warning", "Warning cost threshold reached", { spend, limits, snapshot });
  }

  return { action: "allow", limits, snapshot, reason: "normal" };
}

app.use((req, res, next) => {
  if (req.path.startsWith("/webhooks/")) return next();
  return express.json()(req, res, next);
});

app.use((req, res, next) => {
  const proto = req.headers["x-forwarded-proto"] || (req.socket.encrypted ? "https" : "http");
  if (String(proto).includes("https")) {
    res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload");
  }

  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-XSS-Protection", "0");
  res.setHeader("Content-Security-Policy", "default-src 'self'");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");

  next();
});

app.use((req, res, next) => {
  const origin = String(req.headers.origin || "").trim();
  if (!origin) {
    if (req.method === "OPTIONS") return res.status(204).end();
    return next();
  }

  const matchedOrigin = ALLOWED_ORIGINS.find((o) => o === origin);
  if (!matchedOrigin) {
    console.warn(
      `[cors-rejected] origin=${origin} method=${req.method} path=${req.path} ts=${new Date().toISOString()}`
    );
    if (req.method === "OPTIONS") return res.status(204).end();
    return next();
  }

  res.setHeader("Access-Control-Allow-Origin", matchedOrigin);
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Methods", ALLOWED_METHODS);
  res.setHeader("Access-Control-Allow-Headers", ALLOWED_HEADERS);
  res.setHeader("Access-Control-Max-Age", String(CORS_MAX_AGE_SECONDS));

  if (req.method === "OPTIONS") {
    return res.status(204).end();
  }

  return next();
});

app.use(async (req, res, next) => {
  if (shouldBypassIpRateLimit(req)) return next();

  const clientIp = getClientIp(req);
  const blockTtl = await getIpBlockTtlSec(clientIp);
  if (blockTtl > 0) {
    res.setHeader("Retry-After", String(blockTtl));
    return res.status(429).json({ error: { message: "Too Many Requests", type: "rate_limited" } });
  }

  const check = await ipSlidingWindowCheck(clientIp, 100, 60_000);
  if (check.allowed) return next();

  const escalation = await registerRateLimitViolation(clientIp);
  const retryAfter = Math.max(check.retryAfterSec, escalation.blockSec || 0, 1);
  console.warn(
    `[rate-limit] layer=ip ip=${clientIp} endpoint=${req.path} count=${check.count} limit=100 ts=${new Date().toISOString()}`
  );
  res.setHeader("Retry-After", String(retryAfter));
  return res.status(429).json({ error: { message: "Too Many Requests", type: "rate_limited" } });
});

app.use((req, res, next) => {
  if (!IS_PRODUCTION) return next();
  const blockedPrefixes = ["/docs", "/swagger", "/api-docs", "/debug", "/test"];
  if (blockedPrefixes.some((p) => req.path === p || req.path.startsWith(`${p}/`))) {
    return res.status(404).json({ error: { message: "Not found", type: "not_found" } });
  }
  return next();
});

app.use((req, res, next) => {
  const protectedAdminPath = req.path.startsWith("/admin/") || req.path.startsWith("/api/v1/admin/");
  if (!protectedAdminPath) return next();

  const clientIp = getClientIp(req);
  if (!ADMIN_ALLOWED_IPS.length || ipMatchesAny(clientIp, ADMIN_ALLOWED_IPS)) return next();

  console.warn(
    `[ip-blocked] ip=${clientIp} path=${req.path} ts=${new Date().toISOString()}`
  );
  return res.status(403).json({ error: { message: "Forbidden", type: "forbidden" } });
});

function run(cmd) {
  return new Promise((resolve) => {
    exec(cmd, { timeout: 8000 }, (err, stdout, stderr) => {
      resolve({ ok: !err, output: (stdout || stderr || "").trim() });
    });
  });
}

async function runJson(cmd) {
  const result = await run(cmd);
  if (!result.ok) return { ok: false, error: result.output };
  try {
    return { ok: true, data: JSON.parse(result.output || "null") };
  } catch {
    return { ok: false, error: `Invalid JSON from command: ${cmd}` };
  }
}

function isValidRepoName(repo) {
  return /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(String(repo || ""));
}

function secureHttpsRequest(url, options = {}) {
  return new Promise((resolve, reject) => {
    const req = https.request(url, {
      ...options,
      minVersion: TLS_MIN_VERSION,
      ciphers: TLS_CIPHERS,
      honorCipherOrder: false,
      rejectUnauthorized: true,
      checkServerIdentity: pinnedCheckServerIdentity,
    }, (res) => {
      const chunks = [];
      res.on("data", (d) => chunks.push(d));
      res.on("end", () => resolve({
        statusCode: res.statusCode,
        headers: res.headers,
        body: Buffer.concat(chunks).toString("utf8"),
      }));
    });
    req.on("error", reject);
    req.end();
  });
}

function summarizeFailedJobs(runView) {
  const jobs = Array.isArray(runView?.jobs) ? runView.jobs : [];
  const failedJobs = jobs.filter((j) => ["failure", "timed_out", "cancelled", "startup_failure", "action_required"].includes(String(j?.conclusion || "").toLowerCase()));

  const failedSteps = [];
  for (const job of failedJobs) {
    const steps = Array.isArray(job?.steps) ? job.steps : [];
    const jobFailedSteps = steps.filter((s) => ["failure", "timed_out", "cancelled"].includes(String(s?.conclusion || "").toLowerCase()));
    for (const step of jobFailedSteps) {
      failedSteps.push({
        job: job?.name || "Unknown job",
        step: step?.name || "Unknown step",
        conclusion: step?.conclusion || "failure",
        number: step?.number,
      });
    }
  }

  const topFailures = failedSteps.slice(0, 3);

  let reason = "Failure reason unavailable from run metadata.";
  if (topFailures.length > 0) {
    reason = topFailures.map((f) => `${f.job} → ${f.step} (${f.conclusion})`).join("; ");
  } else if (failedJobs.length > 0) {
    reason = failedJobs.slice(0, 2).map((j) => `${j?.name || "Unknown job"} (${j?.conclusion || "failure"})`).join("; ");
  }

  return {
    failedJobsCount: failedJobs.length,
    failedStepsCount: failedSteps.length,
    topFailures,
    reason,
  };
}

function classifyFailureFromLog(logText = "") {
  const log = String(logText || "").toLowerCase();

  const categories = [
    {
      category: "test_failure",
      hint: "A test appears to be failing. Re-run locally, inspect the failing test output, and fix assertions or setup.",
      patterns: ["failing test", "test failed", "jest", "mocha", "vitest", "rspec", "pytest", "assertionerror", "expected", "received"],
    },
    {
      category: "lint_or_typecheck",
      hint: "Lint/type errors detected. Run lint/typecheck locally and fix violations before pushing.",
      patterns: ["eslint", "tsc", "type error", "typescript", "prettier", "lint", "flake8", "mypy"],
    },
    {
      category: "dependency_or_build",
      hint: "Dependency/build issue detected. Verify lockfiles, package versions, and build config.",
      patterns: ["npm err", "yarn err", "pnpm", "could not resolve", "module not found", "cannot find module", "build failed", "compilation failed"],
    },
    {
      category: "infra_or_flaky",
      hint: "Likely CI environment/network flake. Retry run and inspect external service health/timeouts.",
      patterns: ["timed out", "timeout", "econnreset", "502 bad gateway", "503 service unavailable", "network error", "rate limit exceeded", "runner lost communication"],
    },
    {
      category: "auth_or_secrets",
      hint: "Authentication/secrets issue. Check token scopes, secret names, and expiry/rotation status.",
      patterns: ["unauthorized", "forbidden", "permission denied", "access denied", "invalid token", "expired token", "secret", "authentication failed", "not authorized"],
    },
  ];

  let best = null;
  for (const c of categories) {
    const matches = c.patterns.filter((p) => log.includes(p));
    if (!matches.length) continue;
    if (!best || matches.length > best.matches.length) {
      best = { ...c, matches };
    }
  }

  if (best) {
    const confidence = Math.min(0.95, 0.4 + best.matches.length * 0.12);
    return {
      category: best.category,
      hint: best.hint,
      matchedPattern: best.matches[0],
      confidence,
      severity: confidence >= 0.75 ? "high" : confidence >= 0.55 ? "medium" : "low",
    };
  }

  return {
    category: "unknown",
    hint: "No strong signal found. Open failed logs and inspect first error stack trace.",
    matchedPattern: null,
    confidence: 0.25,
    severity: "low",
  };
}

function extractLogSnippet(logText = "", maxChars = 500) {
  const clean = String(logText || "").replace(/\r/g, "").trim();
  if (!clean) return "";
  return clean.slice(0, maxChars);
}

function getClientIp(req) {
  return (
    req.headers["x-forwarded-for"]?.toString().split(",")[0].trim() ||
    req.socket.remoteAddress ||
    "unknown"
  );
}

function getUserAgent(req) {
  return req.headers["user-agent"] || "unknown";
}

function normalizeIp(ip) {
  const raw = String(ip || "").trim();
  if (!raw) return "";
  if (raw.startsWith("::ffff:")) return raw.slice(7);
  return raw;
}

function parseIPv4ToInt(ip) {
  const parts = ip.split(".").map((p) => Number(p));
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
  return ((parts[0] * 256 + parts[1]) * 256 + parts[2]) * 256 + parts[3];
}

function expandIPv6(ip) {
  let v = ip.toLowerCase();
  if (v === "::") return Array(8).fill(0);
  const hasDouble = v.includes("::");
  const [leftRaw, rightRaw] = v.split("::");
  const left = leftRaw ? leftRaw.split(":").filter(Boolean) : [];
  const right = rightRaw ? rightRaw.split(":").filter(Boolean) : [];
  if (left.some((x) => x.length > 4) || right.some((x) => x.length > 4)) return null;
  if (!hasDouble && left.length !== 8) return null;
  const fillCount = hasDouble ? 8 - (left.length + right.length) : 0;
  if (fillCount < 0) return null;
  const full = [...left, ...Array(fillCount).fill("0"), ...right];
  if (full.length !== 8) return null;
  const nums = full.map((h) => parseInt(h || "0", 16));
  if (nums.some((n) => Number.isNaN(n) || n < 0 || n > 0xffff)) return null;
  return nums;
}

function parseIPv6ToBigInt(ip) {
  const parts = expandIPv6(ip);
  if (!parts) return null;
  return parts.reduce((acc, part) => (acc << 16n) + BigInt(part), 0n);
}

function ipInCidr(clientIp, cidr) {
  const [rangeIpRaw, prefixRaw] = String(cidr || "").split("/");
  const rangeIp = normalizeIp(rangeIpRaw);
  const client = normalizeIp(clientIp);
  const prefix = Number(prefixRaw);

  const rangeType = net.isIP(rangeIp);
  const clientType = net.isIP(client);
  if (!rangeType || rangeType !== clientType) return false;

  if (rangeType === 4) {
    if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) return false;
    const ipInt = parseIPv4ToInt(client);
    const rangeInt = parseIPv4ToInt(rangeIp);
    if (ipInt === null || rangeInt === null) return false;
    const mask = prefix === 0 ? 0 : (~((1 << (32 - prefix)) - 1)) >>> 0;
    return (ipInt & mask) === (rangeInt & mask);
  }

  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 128) return false;
  const ipBig = parseIPv6ToBigInt(client);
  const rangeBig = parseIPv6ToBigInt(rangeIp);
  if (ipBig === null || rangeBig === null) return false;
  const hostBits = 128n - BigInt(prefix);
  const mask = prefix === 0 ? 0n : ((~0n) << hostBits) & ((1n << 128n) - 1n);
  return (ipBig & mask) === (rangeBig & mask);
}

function ipMatchesAny(clientIp, rules = []) {
  const ip = normalizeIp(clientIp);
  const ipType = net.isIP(ip);
  if (!ipType) return false;

  return rules.some((rule) => {
    const r = String(rule || "").trim();
    if (!r) return false;
    if (r.includes("/")) return ipInCidr(ip, r);
    const normalized = normalizeIp(r);
    if (!net.isIP(normalized)) return false;
    return normalized === ip;
  });
}

function countryBucketFromIp(ip) {
  const m = String(ip || "").match(/(\d+)\.(\d+)\.(\d+)\.(\d+)/);
  if (!m) return "unknown";
  const first = Number(m[1]);
  if (first <= 49) return "bucket-a";
  if (first <= 99) return "bucket-b";
  if (first <= 149) return "bucket-c";
  if (first <= 199) return "bucket-d";
  return "bucket-e";
}

function parseCookies(req) {
  const raw = req.headers.cookie || "";
  const out = {};
  for (const part of raw.split(";")) {
    const idx = part.indexOf("=");
    if (idx === -1) continue;
    const k = part.slice(0, idx).trim();
    const v = part.slice(idx + 1).trim();
    if (!k) continue;
    out[k] = decodeURIComponent(v);
  }
  return out;
}

function setAuthCookie(res, name, value, maxAgeSeconds) {
  res.cookie(name, value, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    path: "/",
    domain: COOKIE_DOMAIN,
    maxAge: maxAgeSeconds * 1000,
  });
}

function clearAuthCookies(res) {
  const opts = {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    path: "/",
    domain: COOKIE_DOMAIN,
  };
  res.clearCookie(ACCESS_COOKIE, opts);
  res.clearCookie(REFRESH_COOKIE, opts);
  res.clearCookie(SESSION_COOKIE, opts);
}

function logAuthFailure(req, reason) {
  console.warn(
    `[auth-failed] ip=${getClientIp(req)} ts=${new Date().toISOString()} reason=${reason}`
  );
}

function logAuthzFailure(req, action, reason) {
  const userId = req.auth?.userId || "unknown";
  const role = req.auth?.role || "unknown";
  console.warn(
    `[authz-failed] userId=${userId} role=${role} action=${action} reason=${reason} ts=${new Date().toISOString()}`
  );
}

function ensureRsaKeys() {
  const privateFromEnv = process.env.JWT_PRIVATE_KEY;
  const publicFromEnv = process.env.JWT_PUBLIC_KEY;

  if (privateFromEnv && publicFromEnv) {
    return { privateKey: privateFromEnv, publicKey: publicFromEnv, source: "env" };
  }

  if (fs.existsSync(PRIVATE_KEY_PATH) && fs.existsSync(PUBLIC_KEY_PATH)) {
    return {
      privateKey: fs.readFileSync(PRIVATE_KEY_PATH, "utf8"),
      publicKey: fs.readFileSync(PUBLIC_KEY_PATH, "utf8"),
      source: "file",
    };
  }

  fs.mkdirSync(JWT_KEY_DIR, { recursive: true });
  const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });

  fs.writeFileSync(PRIVATE_KEY_PATH, privateKey, { mode: 0o600 });
  fs.writeFileSync(PUBLIC_KEY_PATH, publicKey, { mode: 0o644 });

  return { privateKey, publicKey, source: "generated" };
}

let keyMaterial = ensureRsaKeys();

function roleExists(role) {
  return Object.prototype.hasOwnProperty.call(ROLES, role);
}

function getPermissionsForRole(role) {
  return roleExists(role) ? ROLES[role].permissions : [];
}

function getEffectiveRoleConfig(user) {
  const base = ROLES[user.role] || ROLES.viewer;
  if (user.role !== "api_consumer") return base;
  const keyCfg = user.apiKeyId ? API_KEY_LIMITS[user.apiKeyId] || {} : {};
  return {
    ...base,
    rateLimitPerMin:
      typeof keyCfg.rateLimitPerMin === "number" ? keyCfg.rateLimitPerMin : base.rateLimitPerMin,
    dailyCostCap:
      typeof keyCfg.dailyCostCap === "number" ? keyCfg.dailyCostCap : base.dailyCostCap,
    models: Array.isArray(keyCfg.models)
      ? keyCfg.models
      : Array.isArray(user.assignedModels)
      ? user.assignedModels
      : base.models,
  };
}

function buildAccessToken(user, sessionId) {
  return jwt.sign(
    {
      sub: user.id,
      sid: sessionId,
      role: user.role,
      permissions: getPermissionsForRole(user.role),
      type: "access",
      apiKeyId: user.apiKeyId || undefined,
    },
    keyMaterial.privateKey,
    {
      algorithm: "RS256",
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE,
      expiresIn: ACCESS_TOKEN_TTL_SECONDS,
    }
  );
}

function buildRefreshToken(user, sessionId) {
  return jwt.sign(
    {
      sub: user.id,
      sid: sessionId,
      role: user.role,
      permissions: getPermissionsForRole(user.role),
      type: "refresh",
      jti: crypto.randomUUID(),
      apiKeyId: user.apiKeyId || undefined,
    },
    keyMaterial.privateKey,
    {
      algorithm: "RS256",
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE,
      expiresIn: REFRESH_TOKEN_TTL_SECONDS,
    }
  );
}

function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

function invalidateSession(sessionId) {
  sessionsById.delete(sessionId);
  for (const [k, v] of refreshTokenStore.entries()) {
    if (v.sessionId === sessionId) refreshTokenStore.delete(k);
  }
}

function invalidateAllSessionsForUser(userId) {
  for (const [sid, s] of sessionsById.entries()) {
    if (s.userId === userId) invalidateSession(sid);
  }
}

function invalidateAllSessionsGlobal() {
  sessionsById.clear();
  refreshTokenStore.clear();
}

function pruneUserSessionsToLimit(userId) {
  const userSessions = Array.from(sessionsById.values())
    .filter((s) => s.userId === userId)
    .sort((a, b) => a.createdAt - b.createdAt);
  while (userSessions.length > MAX_CONCURRENT_SESSIONS) {
    const oldest = userSessions.shift();
    invalidateSession(oldest.id);
  }
}

function createSession(req, user) {
  const id = crypto.randomUUID();
  const now = Date.now();
  const session = {
    id,
    userId: user.id,
    createdAt: now,
    lastActivityAt: now,
    ipAtCreation: getClientIp(req),
    userAgentAtCreation: getUserAgent(req),
    countryBucketAtCreation: countryBucketFromIp(getClientIp(req)),
  };
  sessionsById.set(id, session);
  pruneUserSessionsToLimit(user.id);
  return session;
}

function purgeExpiredRefreshTokens() {
  const now = Date.now();
  for (const [key, rec] of refreshTokenStore.entries()) {
    if (rec.expiresAtMs <= now) refreshTokenStore.delete(key);
  }
}

function isSessionExpired(session) {
  const now = Date.now();
  if (now - session.createdAt > SESSION_ABSOLUTE_TIMEOUT_MS) return true;
  if (now - session.lastActivityAt > SESSION_SLIDING_WINDOW_MS) return true;
  return false;
}

function send401(req, res, reason) {
  logAuthFailure(req, reason);
  clearAuthCookies(res);

  const isApiPath = String(req.path || "").startsWith("/api/");
  const isAuthPath = String(req.path || "").startsWith("/auth/");

  if (req.method === "GET" && !isApiPath && !isAuthPath) {
    return res.redirect(302, "/login");
  }

  const accept = String(req.headers.accept || "");
  const wantsHtml = accept.includes("text/html");
  if (req.method === "GET" && wantsHtml && !isApiPath) {
    return res.redirect(302, "/login");
  }

  return res.status(401).json({ error: { message: "Unauthorized", type: "unauthorized" } });
}

function authMiddleware(req, res, next) {
  if (req.method === "GET" && (req.path === "/health" || req.path === "/login")) return next();
  if (req.method === "POST" && (req.path === "/auth/login" || req.path === "/auth/refresh" || req.path.startsWith("/webhooks/"))) {
    return next();
  }

  const cookies = parseCookies(req);
  const token = cookies[ACCESS_COOKIE];
  const sessionIdCookie = cookies[SESSION_COOKIE];
  if (!token || !sessionIdCookie) return send401(req, res, "missing_session_cookie");

  try {
    const payload = jwt.verify(token, keyMaterial.publicKey, {
      algorithms: ["RS256"],
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE,
    });

    if (payload.type !== "access") return send401(req, res, "invalid_token_type");
    if (!payload.sid || payload.sid !== sessionIdCookie) return send401(req, res, "session_mismatch");

    const user = usersById.get(payload.sub);
    if (!user || user.disabled) return send401(req, res, "account_disabled_or_missing");

    const session = sessionsById.get(payload.sid);
    if (!session || session.userId !== user.id) return send401(req, res, "session_not_found");
    if (isSessionExpired(session)) {
      invalidateSession(session.id);
      return send401(req, res, "session_expired");
    }

    const currentCountryBucket = countryBucketFromIp(getClientIp(req));
    if (
      currentCountryBucket !== "unknown" &&
      session.countryBucketAtCreation !== "unknown" &&
      currentCountryBucket !== session.countryBucketAtCreation
    ) {
      console.warn(
        `[session-ip-alert] userId=${user.id} sessionId=${session.id} createdBucket=${session.countryBucketAtCreation} currentBucket=${currentCountryBucket} createdIp=${session.ipAtCreation} currentIp=${getClientIp(req)} ts=${new Date().toISOString()}`
      );
    }

    session.lastActivityAt = Date.now();

    req.auth = {
      userId: user.id,
      role: payload.role,
      permissions: Array.isArray(payload.permissions) ? payload.permissions : [],
      apiKeyId: payload.apiKeyId,
      sessionId: session.id,
    };
    req.user = user;
    req.session = session;
    return next();
  } catch (err) {
    if (err?.name === "TokenExpiredError") return send401(req, res, "token_expired");
    return send401(req, res, "invalid_token");
  }
}

function requirePermission(action) {
  return (req, res, next) => {
    const role = req.auth?.role;
    const perms = (ROLES[role] || ROLES.viewer).permissions || [];
    if (perms.includes("*") || perms.includes(action)) return next();
    logAuthzFailure(req, action, "permission_denied");
    return res.status(403).json({ error: { message: "Forbidden", type: "forbidden" } });
  };
}

function requireAnyPermission(actions) {
  return (req, res, next) => {
    const role = req.auth?.role;
    const perms = (ROLES[role] || ROLES.viewer).permissions || [];
    if (perms.includes("*") || actions.some((a) => perms.includes(a))) return next();
    logAuthzFailure(req, actions.join("|"), "permission_denied");
    return res.status(403).json({ error: { message: "Forbidden", type: "forbidden" } });
  };
}

function requireOwner(req, res, next) {
  if (req.auth?.role === "owner") return next();
  logAuthzFailure(req, "owner_only", "owner_required");
  return res.status(403).json({ error: { message: "Forbidden", type: "forbidden" } });
}

function enforceRateAndCostLimits(action, resolveEstimatedCost = () => 0) {
  return (req, res, next) => {
    const user = req.user;
    const cfg = getEffectiveRoleConfig(user);

    const minuteBucket = Math.floor(Date.now() / 60000);
    const rateKey = `${user.id}:${minuteBucket}`;
    const currentCount = rateWindowStore.get(rateKey) || 0;
    if (currentCount >= cfg.rateLimitPerMin) {
      logAuthzFailure(req, action, "rate_limit_exceeded");
      return res.status(429).json({ error: { message: "Rate limit exceeded", type: "rate_limited" } });
    }
    rateWindowStore.set(rateKey, currentCount + 1);

    const dayKey = new Date().toISOString().slice(0, 10);
    const costKey = `${user.id}:${dayKey}`;
    const currentCost = dailyCostStore.get(costKey) || 0;
    const estimatedCost = Number(resolveEstimatedCost(req) || 0);

    if (cfg.dailyCostCap !== null && currentCost + estimatedCost > cfg.dailyCostCap) {
      logAuthzFailure(req, action, "daily_cost_cap_exceeded");
      return res.status(429).json({ error: { message: "Daily cost cap exceeded", type: "cost_capped" } });
    }

    dailyCostStore.set(costKey, currentCost + Math.max(0, estimatedCost));
    return next();
  };
}

function enforceModelAccess(req, res, next) {
  const model = req.body?.model;
  const cfg = getEffectiveRoleConfig(req.user);
  const role = req.auth?.role;

  if (!model || typeof model !== "string") {
    logAuthzFailure(req, "models:invoke", "model_missing");
    return res.status(400).json({ error: { message: "Model is required", type: "invalid_request" } });
  }

  const allowed = cfg.models.includes("*") || cfg.models.includes(model);
  console.info(
    `[model-access] userId=${req.auth.userId} role=${role} model=${model} allowed=${allowed} ts=${new Date().toISOString()}`
  );

  if (!allowed) {
    logAuthzFailure(req, "models:invoke", `model_denied:${model}`);
    return res
      .status(403)
      .json({ error: { message: "Your role does not have access to this model", type: "forbidden" } });
  }

  return next();
}

async function enforceModelRateLimits(req, res, next) {
  const model = req.body?.model;
  const estimatedTokens = Number(req.body?.estimatedTokens || req.body?.tokens || 0);
  const identity = req.auth?.apiKeyId || req.auth?.userId || "anonymous";

  const check = await modelRateLimitCheck(identity, model, estimatedTokens);
  if (check.allowed) return next();

  const ip = getClientIp(req);
  const escalation = await registerRateLimitViolation(ip);
  console.warn(
    `[rate-limit] layer=model ip=${ip} apiKey=${maskApiKey(req.auth?.apiKeyId)} endpoint=${req.path} count=${check.reqCount}/${check.tokCount} limit=${check.limit.reqPerMin}req/${check.limit.tokPerMin}tok ts=${new Date().toISOString()}`
  );
  res.setHeader("Retry-After", String(Math.max(60, escalation.blockSec || 0)));
  return res.status(429).json({
    error: { message: "Too Many Requests", type: "rate_limited" },
    detail: {
      model: check.limit.name,
      requestLimitPerMin: check.limit.reqPerMin,
      tokenLimitPerMin: check.limit.tokPerMin,
      requestCount: check.reqCount,
      tokenCount: check.tokCount,
    },
  });
}

app.get("/login", (_req, res) => {
  res.type("html").send(`<!doctype html>
<html>
<head>
  <meta charset="UTF-8" />
  <title>Assistant Ops Dashboard Login</title>
  <style>
    body { font-family: system-ui, sans-serif; margin: 2rem; }
    .card { max-width: 420px; padding: 1rem; border: 1px solid #ddd; border-radius: 8px; }
    label { display: block; margin-top: 0.75rem; }
    input, button { width: 100%; box-sizing: border-box; padding: 0.6rem; margin-top: 0.3rem; }
    button { margin-top: 1rem; }
    #msg { margin-top: 0.75rem; color: #b00020; }
  </style>
</head>
<body>
  <h1>Assistant Ops Dashboard</h1>
  <div class="card">
    <h2>Login</h2>
    <label>Username
      <input id="username" type="text" autocomplete="username" />
    </label>
    <label>Password
      <input id="password" type="password" autocomplete="current-password" />
    </label>
    <button id="loginBtn">Sign in</button>
    <div id="msg"></div>
  </div>

  <script>
    const usernameEl = document.getElementById('username');
    const passwordEl = document.getElementById('password');
    const loginBtn = document.getElementById('loginBtn');
    const msgEl = document.getElementById('msg');

    async function login() {
      msgEl.textContent = '';
      const username = usernameEl.value.trim();
      const password = passwordEl.value;
      if (!username || !password) {
        msgEl.textContent = 'Enter username and password.';
        return;
      }

      try {
        const res = await fetch('/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, password }),
        });
        const data = await res.json();
        if (!res.ok) {
          msgEl.textContent = data?.error?.message || 'Login failed';
          return;
        }
        window.location.href = '/';
      } catch {
        msgEl.textContent = 'Request failed. Is the server running?';
      }
    }

    loginBtn.addEventListener('click', login);
    passwordEl.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') login();
    });
  </script>
</body>
</html>`);
});

app.use(authMiddleware);

app.use(async (req, res, next) => {
  if (!req.auth) return next();

  const apiKeyId = req.auth.apiKeyId || req.headers["x-api-key-id"] || req.auth.userId;
  const bucket = await tokenBucketCheck(`api:${apiKeyId}`, 60, 1);

  res.setHeader("X-RateLimit-Limit", "60");
  res.setHeader("X-RateLimit-Remaining", String(Math.max(0, bucket.remaining)));
  res.setHeader("X-RateLimit-Reset", String(Math.max(1, bucket.resetSec || 60)));

  if (bucket.allowed) return next();

  const ip = getClientIp(req);
  const escalation = await registerRateLimitViolation(ip);
  const retryAfter = Math.max(1, bucket.resetSec || 60, escalation.blockSec || 0);
  console.warn(
    `[rate-limit] layer=api_key ip=${ip} apiKey=${maskApiKey(apiKeyId)} endpoint=${req.path} count=${60 - Number(bucket.remaining || 0)} limit=60 ts=${new Date().toISOString()}`
  );
  res.setHeader("Retry-After", String(retryAfter));
  return res.status(429).json({ error: { message: "Too Many Requests", type: "rate_limited" } });
});

app.use(express.static(path.join(__dirname, "public"), { index: false }));

app.get("/health", (_req, res) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() });
});

app.post("/webhooks/:source", express.raw({ type: "*/*" }), (req, res) => {
  const source = req.params.source;
  const clientIp = getClientIp(req);

  if (WEBHOOK_ALLOWED_IPS.length && !ipMatchesAny(clientIp, WEBHOOK_ALLOWED_IPS)) {
    console.warn(`[webhook-blocked-ip] source=${source} ip=${clientIp} ts=${new Date().toISOString()}`);
    return res.status(403).json({ error: { message: "Forbidden", type: "forbidden" } });
  }

  if (!WEBHOOK_HMAC_SECRET) {
    console.warn(`[webhook-rejected] source=${source} reason=missing_secret ts=${new Date().toISOString()}`);
    return res.status(401).json({ error: { message: "Unauthorized", type: "unauthorized" } });
  }

  const sigHeader = String(req.headers["x-webhook-signature"] || "");
  const expected = "sha256=" + crypto.createHmac("sha256", WEBHOOK_HMAC_SECRET).update(req.body || Buffer.alloc(0)).digest("hex");

  const sigBuf = Buffer.from(sigHeader);
  const expBuf = Buffer.from(expected);
  const valid = sigHeader && sigBuf.length === expBuf.length && crypto.timingSafeEqual(sigBuf, expBuf);
  if (!valid) {
    console.warn(`[webhook-rejected] source=${source} reason=bad_signature ip=${clientIp} ts=${new Date().toISOString()}`);
    return res.status(401).json({ error: { message: "Unauthorized", type: "unauthorized" } });
  }

  return res.json({ ok: true });
});

app.post("/auth/login", (req, res) => {
  purgeExpiredRefreshTokens();
  const { username, password } = req.body || {};
  const user = usersByUsername.get(username);

  if (!user || user.password !== password || user.disabled) {
    return res.status(401).json({ error: { message: "Unauthorized", type: "unauthorized" } });
  }

  const session = createSession(req, user);
  const accessToken = buildAccessToken(user, session.id);
  const refreshToken = buildRefreshToken(user, session.id);
  refreshTokenStore.set(hashToken(refreshToken), {
    userId: user.id,
    sessionId: session.id,
    expiresAtMs: Date.now() + REFRESH_TOKEN_TTL_SECONDS * 1000,
  });

  setAuthCookie(res, ACCESS_COOKIE, accessToken, ACCESS_TOKEN_TTL_SECONDS);
  setAuthCookie(res, REFRESH_COOKIE, refreshToken, REFRESH_TOKEN_TTL_SECONDS);
  setAuthCookie(res, SESSION_COOKIE, session.id, REFRESH_TOKEN_TTL_SECONDS);

  return res.json({
    ok: true,
    message: "Login successful",
    sessionId: session.id,
    role: user.role,
    expiresIn: ACCESS_TOKEN_TTL_SECONDS,
  });
});

app.post("/auth/refresh", (req, res) => {
  purgeExpiredRefreshTokens();
  const cookies = parseCookies(req);
  const refreshToken = cookies[REFRESH_COOKIE];
  const sessionId = cookies[SESSION_COOKIE];
  if (!refreshToken || !sessionId) {
    clearAuthCookies(res);
    return res.status(401).json({ error: { message: "Unauthorized", type: "unauthorized" } });
  }

  const tokenHash = hashToken(refreshToken);
  const rec = refreshTokenStore.get(tokenHash);
  if (!rec || rec.sessionId !== sessionId) {
    clearAuthCookies(res);
    return res.status(401).json({ error: { message: "Unauthorized", type: "unauthorized" } });
  }

  try {
    const payload = jwt.verify(refreshToken, keyMaterial.publicKey, {
      algorithms: ["RS256"],
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE,
    });

    if (payload.type !== "refresh" || payload.sid !== sessionId) {
      refreshTokenStore.delete(tokenHash);
      clearAuthCookies(res);
      return res.status(401).json({ error: { message: "Unauthorized", type: "unauthorized" } });
    }

    const user = usersById.get(payload.sub);
    const session = sessionsById.get(sessionId);
    if (!user || user.disabled || !session || session.userId !== user.id || isSessionExpired(session)) {
      refreshTokenStore.delete(tokenHash);
      if (session) invalidateSession(session.id);
      clearAuthCookies(res);
      return res.status(401).json({ error: { message: "Unauthorized", type: "unauthorized" } });
    }

    refreshTokenStore.delete(tokenHash); // one-time-use rotation

    const newAccess = buildAccessToken(user, session.id);
    const newRefresh = buildRefreshToken(user, session.id);
    refreshTokenStore.set(hashToken(newRefresh), {
      userId: user.id,
      sessionId: session.id,
      expiresAtMs: Date.now() + REFRESH_TOKEN_TTL_SECONDS * 1000,
    });

    session.lastActivityAt = Date.now();

    setAuthCookie(res, ACCESS_COOKIE, newAccess, ACCESS_TOKEN_TTL_SECONDS);
    setAuthCookie(res, REFRESH_COOKIE, newRefresh, REFRESH_TOKEN_TTL_SECONDS);
    setAuthCookie(res, SESSION_COOKIE, session.id, REFRESH_TOKEN_TTL_SECONDS);

    return res.json({ ok: true, message: "Token refreshed" });
  } catch {
    refreshTokenStore.delete(tokenHash);
    clearAuthCookies(res);
    return res.status(401).json({ error: { message: "Unauthorized", type: "unauthorized" } });
  }
});

app.get("/auth/sessions", (req, res) => {
  const out = Array.from(sessionsById.values())
    .filter((s) => s.userId === req.auth.userId)
    .map((s) => ({
      id: s.id,
      userId: s.userId,
      createdAt: new Date(s.createdAt).toISOString(),
      lastActivityAt: new Date(s.lastActivityAt).toISOString(),
      ipAtCreation: s.ipAtCreation,
      userAgentAtCreation: s.userAgentAtCreation,
    }));
  res.json({ sessions: out });
});

app.delete("/auth/sessions/:id", (req, res) => {
  const sid = req.params.id;
  const target = sessionsById.get(sid);
  if (!target || target.userId !== req.auth.userId) {
    return res.status(404).json({ error: { message: "Session not found", type: "not_found" } });
  }
  invalidateSession(sid);
  if (req.auth.sessionId === sid) clearAuthCookies(res);
  return res.json({ ok: true, revokedSessionId: sid });
});

app.delete("/auth/sessions", (req, res) => {
  invalidateAllSessionsForUser(req.auth.userId);
  clearAuthCookies(res);
  return res.json({ ok: true, message: "All sessions revoked" });
});

app.post("/auth/password", (req, res) => {
  const { currentPassword, newPassword } = req.body || {};
  const user = req.user;
  if (!currentPassword || user.password !== currentPassword) {
    return res.status(403).json({ error: { message: "Forbidden", type: "forbidden" } });
  }
  if (!newPassword || String(newPassword).length < 8) {
    return res.status(400).json({ error: { message: "Invalid password", type: "invalid_request" } });
  }
  user.password = String(newPassword);
  invalidateAllSessionsForUser(user.id);
  clearAuthCookies(res);
  return res.json({ ok: true, message: "Password changed. All sessions invalidated." });
});

app.get(
  "/",
  requirePermission("dashboard:read"),
  enforceRateAndCostLimits("dashboard:read"),
  (_req, res) => {
    const indexPath = path.join(__dirname, "public", "index.html");
    try {
      const html = fs.readFileSync(indexPath, "utf8");
      return res.type("html").send(html);
    } catch {
      return res.status(500).type("text").send(`Dashboard UI not found at ${indexPath}`);
    }
  }
);

app.get(
  "/api/health",
  requirePermission("dashboard:read"),
  enforceRateAndCostLimits("dashboard:read"),
  async (req, res) => {
    if (IS_PRODUCTION && !["owner", "admin"].includes(String(req.auth?.role || ""))) {
      return res.status(403).json({ error: { message: "Forbidden", type: "forbidden" } });
    }
    const status = await run("openclaw status");
    res.json({ timestamp: new Date().toISOString(), openclaw: status.ok ? "up" : "down", raw: status.output });
  }
);

app.get(
  "/api/ci/failures",
  requirePermission("dashboard:read"),
  enforceRateAndCostLimits("dashboard:read"),
  async (req, res) => {
    const repo = String(req.query.repo || "").trim();
    const limit = Math.min(Math.max(Number(req.query.limit || 5), 1), 10);

    if (!isValidRepoName(repo)) {
      return res.status(400).json({
        error: {
          message: "Invalid repo. Use owner/repo format.",
          type: "invalid_request",
        },
      });
    }

    const list = await runJson(
      `gh run list --repo ${repo} --status failure --limit ${limit} --json databaseId,workflowName,displayTitle,headBranch,event,startedAt,updatedAt,url,headSha`
    );

    if (!list.ok) {
      return res.status(502).json({
        error: {
          message: "Failed to fetch CI runs via GitHub CLI",
          type: "upstream_error",
          detail: list.error,
        },
      });
    }

    const failures = Array.isArray(list.data) ? list.data : [];

    const summaries = [];
    for (const run of failures) {
      const runId = Number(run.databaseId);
      const base = {
        runId,
        workflow: run.workflowName,
        title: run.displayTitle,
        branch: run.headBranch,
        event: run.event,
        sha: run.headSha,
        startedAt: run.startedAt,
        updatedAt: run.updatedAt,
        url: run.url,
      };

      const detail = await runJson(
        `gh run view ${runId} --repo ${repo} --json jobs,url,displayTitle,workflowName,conclusion,status`
      );

      if (!detail.ok) {
        summaries.push({
          ...base,
          summary: `${run.workflowName || "Workflow"} failed on ${run.headBranch || "unknown-branch"} (${(run.headSha || "").slice(0, 7) || "unknown-sha"})`,
          failureReason: "Could not fetch job/step details",
          detailError: detail.error,
          failedJobsCount: null,
          failedStepsCount: null,
          topFailures: [],
        });
        continue;
      }

      const failureDetail = summarizeFailedJobs(detail.data || {});

      const failedLog = await run(`gh run view ${runId} --repo ${repo} --log-failed`);
      const logText = failedLog.ok ? failedLog.output : "";
      const classification = classifyFailureFromLog(logText);
      const logSnippet = extractLogSnippet(logText, 600);

      summaries.push({
        ...base,
        summary: `${run.workflowName || "Workflow"} failed on ${run.headBranch || "unknown-branch"} (${(run.headSha || "").slice(0, 7) || "unknown-sha"})`,
        failureReason: failureDetail.reason,
        failedJobsCount: failureDetail.failedJobsCount,
        failedStepsCount: failureDetail.failedStepsCount,
        topFailures: failureDetail.topFailures,
        failureCategory: classification.category,
        fixHint: classification.hint,
        matchedPattern: classification.matchedPattern,
        confidence: classification.confidence,
        severity: classification.severity,
        logSnippet,
      });
    }

    return res.json({
      repo,
      count: summaries.length,
      generatedAt: new Date().toISOString(),
      failures: summaries,
    });
  }
);

app.post(
  "/api/restart",
  requirePermission("gateway:restart"),
  enforceRateAndCostLimits("gateway:restart"),
  async (_req, res) => {
    const restart = await run("openclaw gateway restart");
    res.json({ success: restart.ok, message: restart.ok ? "Gateway restarted" : "Restart failed", raw: restart.output });
  }
);

app.post(
  "/api/models/invoke",
  requireAnyPermission(["models:all", "models:limited", "models:key-assigned"]),
  enforceRateAndCostLimits("models:invoke", (req) => req.body?.estimatedCost || 0),
  enforceModelAccess,
  enforceModelRateLimits,
  async (req, res) => {
    const requestedModel = String(req.body?.model || "haiku");
    const breaker = await evaluateCircuitBreaker(requestedModel);

    if (breaker.action === "suspend_all") {
      return res.status(503).json({
        error: { message: "Service temporarily suspended", type: "service_unavailable" },
        circuitBreaker: { reason: breaker.reason, spend: breaker.snapshot.global, limits: breaker.limits },
      });
    }

    if (breaker.action === "block_non_haiku") {
      return res.status(503).json({
        error: { message: "Cost limit reached, only economy model available", type: "service_unavailable" },
        circuitBreaker: { reason: breaker.reason, spend: breaker.snapshot.global, limits: breaker.limits },
      });
    }

    let effectiveModel = requestedModel;
    let downgraded = false;
    if (breaker.action === "downgrade_to_sonnet") {
      effectiveModel = "sonnet";
      downgraded = true;
      console.warn(
        `[circuit-breaker] downgraded request user=${req.auth?.userId} apiKey=${maskApiKey(req.auth?.apiKeyId)} from=${requestedModel} to=sonnet ts=${new Date().toISOString()}`
      );
    }

    const inputTokens = Number(req.body?.inputTokens || req.body?.estimatedInputTokens || req.body?.tokens || 0);
    const outputTokens = Number(req.body?.outputTokens || req.body?.estimatedOutputTokens || 0);
    const usage = await addCostUsage({
      modelName: effectiveModel,
      inputTokens,
      outputTokens,
      apiKeyId: req.auth?.apiKeyId || req.headers["x-api-key-id"] || "none",
      userId: req.auth?.userId || "unknown",
    });

    return res.json({
      ok: true,
      requestedModel,
      effectiveModel,
      downgraded,
      estimatedCostUsd: usage.totalCost,
      message: "Model call permitted and would execute now.",
    });
  }
);

app.get(
  "/admin/costs",
  requirePermission("dashboard:read"),
  enforceRateAndCostLimits("dashboard:read"),
  async (_req, res) => {
    const snapshot = await getCostSnapshot();
    const limits = await getCircuitBreakerLimits();
    const state = await evaluateCircuitBreaker("haiku");
    return res.json({
      day: snapshot.day,
      spend: snapshot,
      limits,
      breakerState: state.action,
      reason: state.reason,
    });
  }
);

app.post(
  "/admin/costs/reset",
  requireOwner,
  enforceRateAndCostLimits("users:manage"),
  async (_req, res) => {
    const day = dailyCostDateKey();
    await redisFailOpen(async () => {
      const keys = await redisClient.keys(rlKey(`cost:day:${day}:*`));
      if (keys.length) await redisClient.del(keys);
      await redisClient.del(rlKey("cost:manual_reset_required"));
      return true;
    }, false);
    return res.json({ ok: true, message: "Cost circuit breaker state reset" });
  }
);

app.put(
  "/admin/costs/limits",
  requireOwner,
  enforceRateAndCostLimits("users:manage"),
  async (req, res) => {
    const nextLimits = {
      warning: Number(req.body?.warning ?? DEFAULT_COST_LIMITS.warning),
      soft: Number(req.body?.soft ?? DEFAULT_COST_LIMITS.soft),
      hard: Number(req.body?.hard ?? DEFAULT_COST_LIMITS.hard),
      emergency: Number(req.body?.emergency ?? DEFAULT_COST_LIMITS.emergency),
    };
    if (!(nextLimits.warning < nextLimits.soft && nextLimits.soft < nextLimits.hard && nextLimits.hard < nextLimits.emergency)) {
      return res.status(400).json({ error: { message: "Invalid limit ordering", type: "invalid_request" } });
    }
    await setCircuitBreakerLimits(nextLimits);
    return res.json({ ok: true, limits: nextLimits });
  }
);

app.get(
  "/admin/users",
  requirePermission("users:manage"),
  enforceRateAndCostLimits("users:manage"),
  (_req, res) => {
    const list = Array.from(usersById.values()).map((u) => ({
      id: u.id,
      username: u.username,
      role: u.role,
      disabled: !!u.disabled,
      apiKeyId: u.apiKeyId || null,
    }));
    res.json({ users: list });
  }
);

app.post(
  "/admin/users/:id/role",
  requirePermission("users:manage"),
  enforceRateAndCostLimits("users:manage"),
  (req, res) => {
    const { id } = req.params;
    const { role } = req.body || {};
    if (!roleExists(role)) {
      return res.status(400).json({ error: { message: "Invalid role", type: "invalid_request" } });
    }
    const user = usersById.get(id);
    if (!user) {
      return res.status(404).json({ error: { message: "User not found", type: "not_found" } });
    }
    user.role = role;
    return res.json({ ok: true, user: { id: user.id, username: user.username, role: user.role } });
  }
);

app.post(
  "/admin/keys/rotate",
  requirePermission("keys:rotate"),
  enforceRateAndCostLimits("keys:rotate"),
  (_req, res) => {
    fs.mkdirSync(JWT_KEY_DIR, { recursive: true });
    const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
      modulusLength: 2048,
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    fs.writeFileSync(PRIVATE_KEY_PATH, privateKey, { mode: 0o600 });
    fs.writeFileSync(PUBLIC_KEY_PATH, publicKey, { mode: 0o644 });
    keyMaterial = { privateKey, publicKey, source: "rotated" };
    invalidateAllSessionsGlobal();
    return res.json({ ok: true, message: "Keys rotated. All sessions invalidated." });
  }
);

app.get(
  "/auth/public-key",
  requirePermission("keys:rotate"),
  enforceRateAndCostLimits("keys:rotate"),
  (_req, res) => {
    res.type("text/plain").send(keyMaterial.publicKey);
  }
);

function loadTlsMaterial() {
  if (!fs.existsSync(CERT_FILE) || !fs.existsSync(KEY_FILE)) {
    throw new Error(`TLS certificate files missing. Expected cert=${CERT_FILE} key=${KEY_FILE}`);
  }
  return {
    cert: fs.readFileSync(CERT_FILE, "utf8"),
    key: fs.readFileSync(KEY_FILE, "utf8"),
  };
}

function startServers() {
  const tlsMaterial = loadTlsMaterial();

  const httpsServer = https.createServer({
    key: tlsMaterial.key,
    cert: tlsMaterial.cert,
    minVersion: TLS_MIN_VERSION,
    ciphers: TLS_CIPHERS,
    honorCipherOrder: false,
    requestCert: false,
  }, app);

  httpsServer.listen(HTTPS_PORT, () => {
    console.log(`Dashboard running on https://localhost:${HTTPS_PORT}`);
    console.log(`TLS minVersion=${TLS_MIN_VERSION}`);
    console.log(`JWT key source: ${keyMaterial.source}`);
    console.log("Public key for verifiers:\n" + keyMaterial.publicKey);
    if (!CERT_PIN_MAP.size) {
      console.log("TLS pinning map empty (set TLS_PINNED_SPKI_SHA256 to enable host pinning)");
    }
  });

  const redirectServer = http.createServer((req, res) => {
    const host = String(req.headers.host || "localhost").replace(/:\d+$/, "");
    const portSuffix = HTTPS_PORT === 443 ? "" : `:${HTTPS_PORT}`;
    const location = `https://${host}${portSuffix}${req.url || "/"}`;
    res.writeHead(301, { Location: location });
    res.end();
  });

  redirectServer.listen(HTTP_PORT, () => {
    console.log(`HTTP redirect server on http://localhost:${HTTP_PORT} -> https://localhost:${HTTPS_PORT}`);
  });
}

(async () => {
  try {
    await initRedis();
    startServers();
  } catch (err) {
    console.error("Failed to start TLS servers:", err.message);
    process.exit(1);
  }
})();
