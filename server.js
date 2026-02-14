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
      "users:read",
    ],
    models: ["*"],
    rateLimitPerMin: 60,
    dailyCostCap: 500,
  },
  developer: {
    permissions: [
      "dashboard:read",
      "config:read",
      "keys:own:rotate",
      "models:limited",
    ],
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
    // Example:
    // {"ak_ops_default":{"models":["claude-3-5-haiku"],"rateLimitPerMin":25,"dailyCostCap":75}}
    const raw = process.env.API_KEY_RBAC_CONFIG;
    return raw ? JSON.parse(raw) : {};
  } catch {
    return {};
  }
})();

// Demo users (replace with real DB)
const usersById = new Map([
  [
    "u_owner",
    {
      id: "u_owner",
      username: "owner",
      password: process.env.DASHBOARD_OWNER_PASSWORD || "change-me-now",
      role: "owner",
      disabled: false,
      permissions: [],
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
      permissions: [],
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
      permissions: [],
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
      assignedModels: ["claude-3-5-haiku"],
      disabled: false,
      permissions: [],
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
      permissions: [],
    },
  ],
]);
const usersByUsername = new Map(Array.from(usersById.values()).map((u) => [u.username, u]));

const refreshTokenStore = new Map(); // hash(token) -> { userId, expiresAtMs }
const rateWindowStore = new Map(); // `${userId}:${minuteBucket}` -> count
const dailyCostStore = new Map(); // `${userId}:${YYYY-MM-DD}` -> cost

app.use(express.json());

function run(cmd) {
  return new Promise((resolve) => {
    exec(cmd, { timeout: 8000 }, (err, stdout, stderr) => {
      resolve({ ok: !err, output: (stdout || stderr || "").trim() });
    });
  });
}

function getClientIp(req) {
  return (
    req.headers["x-forwarded-for"]?.toString().split(",")[0].trim() ||
    req.socket.remoteAddress ||
    "unknown"
  );
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
const keyMaterial = ensureRsaKeys();

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

function buildAccessToken(user) {
  return jwt.sign(
    {
      sub: user.id,
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

function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

function buildRefreshToken(user) {
  const token = jwt.sign(
    {
      sub: user.id,
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

  refreshTokenStore.set(hashToken(token), {
    userId: user.id,
    expiresAtMs: Date.now() + REFRESH_TOKEN_TTL_SECONDS * 1000,
  });

  return token;
}

function purgeExpiredRefreshTokens() {
  const now = Date.now();
  for (const [key, rec] of refreshTokenStore.entries()) {
    if (rec.expiresAtMs <= now) refreshTokenStore.delete(key);
  }
}

function send401(req, res, reason) {
  logAuthFailure(req, reason);
  return res.status(401).json({ error: { message: "Unauthorized", type: "unauthorized" } });
}

function authMiddleware(req, res, next) {
  if (req.method === "GET" && req.path === "/health") return next();
  if (req.method === "POST" && (req.path === "/auth/login" || req.path === "/auth/refresh")) {
    return next();
  }

  const authHeader = req.headers.authorization || "";
  const [scheme, token] = authHeader.split(" ");
  if (scheme !== "Bearer" || !token) return send401(req, res, "missing_or_malformed_token");

  try {
    const payload = jwt.verify(token, keyMaterial.publicKey, {
      algorithms: ["RS256"],
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE,
    });

    if (payload.type !== "access") return send401(req, res, "invalid_token_type");
    const user = usersById.get(payload.sub);
    if (!user || user.disabled) return send401(req, res, "account_disabled_or_missing");

    req.auth = {
      userId: user.id,
      role: payload.role,
      permissions: Array.isArray(payload.permissions) ? payload.permissions : [],
      apiKeyId: payload.apiKeyId,
    };
    req.user = user;
    return next();
  } catch (err) {
    if (err?.name === "TokenExpiredError") return send401(req, res, "token_expired");
    return send401(req, res, "invalid_token");
  }
}

function requirePermission(action) {
  return (req, res, next) => {
    const role = req.auth?.role;
    const roleCfg = ROLES[role] || ROLES.viewer;
    const perms = roleCfg.permissions || [];

    if (perms.includes("*") || perms.includes(action)) {
      req.action = action;
      return next();
    }

    logAuthzFailure(req, action, "permission_denied");
    return res.status(403).json({ error: { message: "Forbidden", type: "forbidden" } });
  };
}

function requireAnyPermission(actions) {
  return (req, res, next) => {
    const role = req.auth?.role;
    const roleCfg = ROLES[role] || ROLES.viewer;
    const perms = roleCfg.permissions || [];

    if (perms.includes("*") || actions.some((a) => perms.includes(a))) return next();

    logAuthzFailure(req, actions.join("|"), "permission_denied");
    return res.status(403).json({ error: { message: "Forbidden", type: "forbidden" } });
  };
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
  const action = "models:invoke";
  const role = req.auth?.role;
  const cfg = getEffectiveRoleConfig(req.user);

  if (!model || typeof model !== "string") {
    logAuthzFailure(req, action, "model_missing");
    return res.status(400).json({ error: { message: "Model is required", type: "invalid_request" } });
  }

  const allowed = cfg.models.includes("*") || cfg.models.includes(model);
  console.info(
    `[model-access] userId=${req.auth.userId} role=${role} model=${model} allowed=${allowed} ts=${new Date().toISOString()}`
  );

  if (!allowed) {
    logAuthzFailure(req, action, `model_denied:${model}`);
    return res
      .status(403)
      .json({ error: { message: "Your role does not have access to this model", type: "forbidden" } });
  }

  return next();
}

app.use(authMiddleware); // auth first for protected routes
app.use(express.static(path.join(__dirname, "public"), { index: false }));

app.get("/health", (_req, res) => {
  res.json({ status: "ok" });
});

app.post("/auth/login", (req, res) => {
  purgeExpiredRefreshTokens();
  const { username, password } = req.body || {};
  const user = usersByUsername.get(username);

  if (!user || user.password !== password || user.disabled) {
    return res.status(401).json({ error: { message: "Unauthorized", type: "unauthorized" } });
  }

  return res.json({
    accessToken: buildAccessToken(user),
    accessTokenExpiresIn: ACCESS_TOKEN_TTL_SECONDS,
    refreshToken: buildRefreshToken(user),
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

  const tokenHash = hashToken(refreshToken);
  if (!refreshTokenStore.has(tokenHash)) {
    return res.status(401).json({ error: { message: "Unauthorized", type: "unauthorized" } });
  }

  try {
    const payload = jwt.verify(refreshToken, keyMaterial.publicKey, {
      algorithms: ["RS256"],
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE,
    });

    if (payload.type !== "refresh") {
      refreshTokenStore.delete(tokenHash);
      return res.status(401).json({ error: { message: "Unauthorized", type: "unauthorized" } });
    }

    const user = usersById.get(payload.sub);
    if (!user || user.disabled) {
      refreshTokenStore.delete(tokenHash);
      return res.status(401).json({ error: { message: "Unauthorized", type: "unauthorized" } });
    }

    refreshTokenStore.delete(tokenHash); // rotate one-time use immediately

    return res.json({
      accessToken: buildAccessToken(user),
      accessTokenExpiresIn: ACCESS_TOKEN_TTL_SECONDS,
      refreshToken: buildRefreshToken(user),
      refreshTokenExpiresIn: REFRESH_TOKEN_TTL_SECONDS,
      tokenType: "Bearer",
    });
  } catch {
    refreshTokenStore.delete(tokenHash);
    return res.status(401).json({ error: { message: "Unauthorized", type: "unauthorized" } });
  }
});

app.get(
  "/",
  requirePermission("dashboard:read"),
  enforceRateAndCostLimits("dashboard:read"),
  (_req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
  }
);

app.get(
  "/api/health",
  requirePermission("dashboard:read"),
  enforceRateAndCostLimits("dashboard:read"),
  async (_req, res) => {
    const status = await run("openclaw status");
    res.json({
      timestamp: new Date().toISOString(),
      openclaw: status.ok ? "up" : "down",
      raw: status.output,
    });
  }
);

app.post(
  "/api/restart",
  requirePermission("gateway:restart"),
  enforceRateAndCostLimits("gateway:restart"),
  async (_req, res) => {
    const restart = await run("openclaw gateway restart");
    res.json({
      success: restart.ok,
      message: restart.ok ? "Gateway restarted" : "Restart failed",
      raw: restart.output,
    });
  }
);

// Example model invocation endpoint to enforce model-tier RBAC before external call
app.post(
  "/api/models/invoke",
  requireAnyPermission(["models:all", "models:limited", "models:key-assigned"]),
  enforceRateAndCostLimits("models:invoke", (req) => req.body?.estimatedCost || 0),
  enforceModelAccess,
  async (req, res) => {
    // RBAC + model checks are complete at this point.
    // Business logic / external provider call would happen here.
    return res.json({
      ok: true,
      model: req.body.model,
      message: "Model call permitted and would execute now.",
    });
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
    user.permissions = getPermissionsForRole(role);

    return res.json({ ok: true, user: { id: user.id, username: user.username, role: user.role } });
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

app.listen(PORT, () => {
  console.log(`Dashboard running on http://localhost:${PORT}`);
  console.log(`JWT key source: ${keyMaterial.source}`);
  console.log("Public key for verifiers:\n" + keyMaterial.publicKey);
});
