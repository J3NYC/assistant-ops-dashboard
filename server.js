const express = require("express");
const { exec } = require("child_process");
const path = require("path");
const crypto = require("crypto");
const fs = require("fs");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = process.env.PORT || 3000;

const ACCESS_TOKEN_TTL_SECONDS = 15 * 60; // 15 minutes
const REFRESH_TOKEN_TTL_SECONDS = 7 * 24 * 60 * 60; // 7 days
const JWT_ISSUER = process.env.JWT_ISSUER || "assistant-ops-dashboard";
const JWT_AUDIENCE = process.env.JWT_AUDIENCE || "assistant-ops-dashboard-api";
const JWT_KEY_DIR = path.join(__dirname, "keys");
const PRIVATE_KEY_PATH = path.join(JWT_KEY_DIR, "jwtRS256.key");
const PUBLIC_KEY_PATH = path.join(JWT_KEY_DIR, "jwtRS256.key.pub");

// Demo user store (replace with real DB in production)
const users = new Map([
  [
    "ops-admin",
    {
      id: "u_ops_admin",
      username: "ops-admin",
      password: process.env.DASHBOARD_ADMIN_PASSWORD || "change-me-now",
      role: "admin",
      permissions: ["dashboard:read", "gateway:restart"],
      disabled: false,
    },
  ],
  [
    "ops-viewer",
    {
      id: "u_ops_viewer",
      username: "ops-viewer",
      password: process.env.DASHBOARD_VIEWER_PASSWORD || "change-me-now",
      role: "viewer",
      permissions: ["dashboard:read"],
      disabled: false,
    },
  ],
]);

// one-time-use refresh token store
// key = sha256(token), value = { userId, expiresAtMs, revoked }
const refreshTokenStore = new Map();

app.use(express.json());

function logAuthFailure(req, reason) {
  const ip =
    req.headers["x-forwarded-for"]?.toString().split(",")[0].trim() ||
    req.socket.remoteAddress ||
    "unknown";
  console.warn(
    `[auth-failed] ip=${ip} timestamp=${new Date().toISOString()} reason=${reason}`
  );
}

function run(cmd) {
  return new Promise((resolve) => {
    exec(cmd, { timeout: 8000 }, (err, stdout, stderr) => {
      resolve({
        ok: !err,
        output: (stdout || stderr || "").trim(),
      });
    });
  });
}

function ensureRsaKeys() {
  const privateFromEnv = process.env.JWT_PRIVATE_KEY;
  const publicFromEnv = process.env.JWT_PUBLIC_KEY;

  if (privateFromEnv && publicFromEnv) {
    return {
      privateKey: privateFromEnv,
      publicKey: publicFromEnv,
      source: "env",
    };
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

const keyMaterial = ensureRsaKeys();

function buildAccessToken(user) {
  // No email/name/sensitive fields in payload
  return jwt.sign(
    {
      sub: user.id,
      role: user.role,
      permissions: user.permissions,
      type: "access",
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

function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

function buildRefreshToken(user) {
  const tokenId = crypto.randomUUID();
  const token = jwt.sign(
    {
      sub: user.id,
      role: user.role,
      permissions: user.permissions,
      type: "refresh",
      jti: tokenId,
    },
    keyMaterial.privateKey,
    {
      algorithm: "RS256",
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE,
      expiresIn: REFRESH_TOKEN_TTL_SECONDS,
    }
  );

  refreshTokenStore.set(hashToken(token), {
    userId: user.id,
    expiresAtMs: Date.now() + REFRESH_TOKEN_TTL_SECONDS * 1000,
    revoked: false,
  });

  return token;
}

function purgeExpiredRefreshTokens() {
  const now = Date.now();
  for (const [key, record] of refreshTokenStore.entries()) {
    if (record.expiresAtMs <= now || record.revoked) {
      refreshTokenStore.delete(key);
    }
  }
}

function send401(req, res, reason) {
  logAuthFailure(req, reason);
  return res.status(401).json({ error: { message: "Unauthorized", type: "unauthorized" } });
}

function authMiddleware(req, res, next) {
  if (req.method === "GET" && req.path === "/health") return next();
  if (req.method === "POST" && (req.path === "/auth/login" || req.path === "/auth/refresh")) return next();

  const authHeader = req.headers.authorization || "";
  const [scheme, token] = authHeader.split(" ");
  if (scheme !== "Bearer" || !token) {
    return send401(req, res, "missing_or_malformed_token");
  }

  try {
    const payload = jwt.verify(token, keyMaterial.publicKey, {
      algorithms: ["RS256"],
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE,
    });

    if (payload.type !== "access") {
      return send401(req, res, "invalid_token_type");
    }

    const user = Array.from(users.values()).find((u) => u.id === payload.sub);
    if (!user || user.disabled) {
      return send401(req, res, "account_disabled_or_missing");
    }

    req.auth = {
      userId: payload.sub,
      role: payload.role,
      permissions: Array.isArray(payload.permissions) ? payload.permissions : [],
    };

    return next();
  } catch (err) {
    if (err?.name === "TokenExpiredError") return send401(req, res, "token_expired");
    return send401(req, res, "invalid_token");
  }
}

app.use(authMiddleware);
app.use(express.static(path.join(__dirname, "public"), { index: false }));

app.get("/health", (_req, res) => {
  res.json({ status: "ok" });
});

app.get("/", (_req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.post("/auth/login", (req, res) => {
  purgeExpiredRefreshTokens();
  const { username, password } = req.body || {};
  const user = users.get(username);

  if (!user || user.password !== password || user.disabled) {
    return res.status(401).json({ error: { message: "Unauthorized", type: "unauthorized" } });
  }

  const accessToken = buildAccessToken(user);
  const refreshToken = buildRefreshToken(user);

  return res.json({
    accessToken,
    accessTokenExpiresIn: ACCESS_TOKEN_TTL_SECONDS,
    refreshToken,
    refreshTokenExpiresIn: REFRESH_TOKEN_TTL_SECONDS,
    tokenType: "Bearer",
  });
});

app.post("/auth/refresh", (req, res) => {
  purgeExpiredRefreshTokens();
  const { refreshToken } = req.body || {};
  if (!refreshToken || typeof refreshToken !== "string") {
    return res.status(401).json({ error: { message: "Unauthorized", type: "unauthorized" } });
  }

  const oldTokenHash = hashToken(refreshToken);
  const record = refreshTokenStore.get(oldTokenHash);
  if (!record || record.revoked) {
    return res.status(401).json({ error: { message: "Unauthorized", type: "unauthorized" } });
  }

  try {
    const payload = jwt.verify(refreshToken, keyMaterial.publicKey, {
      algorithms: ["RS256"],
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE,
    });

    if (payload.type !== "refresh") {
      refreshTokenStore.delete(oldTokenHash);
      return res.status(401).json({ error: { message: "Unauthorized", type: "unauthorized" } });
    }

    const user = Array.from(users.values()).find((u) => u.id === payload.sub);
    if (!user || user.disabled) {
      refreshTokenStore.delete(oldTokenHash);
      return res.status(401).json({ error: { message: "Unauthorized", type: "unauthorized" } });
    }

    // rotate one-time-use refresh token: invalidate old immediately
    refreshTokenStore.delete(oldTokenHash);

    const accessToken = buildAccessToken(user);
    const newRefreshToken = buildRefreshToken(user);

    return res.json({
      accessToken,
      accessTokenExpiresIn: ACCESS_TOKEN_TTL_SECONDS,
      refreshToken: newRefreshToken,
      refreshTokenExpiresIn: REFRESH_TOKEN_TTL_SECONDS,
      tokenType: "Bearer",
    });
  } catch {
    refreshTokenStore.delete(oldTokenHash);
    return res.status(401).json({ error: { message: "Unauthorized", type: "unauthorized" } });
  }
});

app.get("/api/health", async (_req, res) => {
  const status = await run("openclaw status");
  res.json({
    timestamp: new Date().toISOString(),
    openclaw: status.ok ? "up" : "down",
    raw: status.output,
  });
});

app.post("/api/restart", async (_req, res) => {
  const restart = await run("openclaw gateway restart");
  res.json({
    success: restart.ok,
    message: restart.ok ? "Gateway restarted" : "Restart failed",
    raw: restart.output,
  });
});

app.get("/auth/public-key", (_req, res) => {
  // Public key can be shared with token verification services.
  res.type("text/plain").send(keyMaterial.publicKey);
});

app.listen(PORT, () => {
  console.log(`Dashboard running on http://localhost:${PORT}`);
  console.log(`JWT key source: ${keyMaterial.source}`);
  console.log("Public key for verifiers:\n" + keyMaterial.publicKey);
});
