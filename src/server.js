const express = require("express");
const crypto = require("crypto");
const { Readable } = require("stream");
const requestLog = require("./request-log.cjs");

const app = express();
app.set("trust proxy", true);
app.use(requestLog);

const PORT = Number(process.env.PORT || 10000);
const MCD_MCP_URL = process.env.MCD_MCP_URL || "https://mcp.mcd.cn";
const MCD_MCP_TOKEN = process.env.MCD_MCP_TOKEN || "";
const ADAPTER_OWNER_PASSWORD = process.env.ADAPTER_OWNER_PASSWORD || "";
const ALLOW_ORDER_CREATION =
  String(process.env.ALLOW_ORDER_CREATION || "false").toLowerCase() === "true";

const ACCESS_TTL = positiveInt(process.env.OAUTH_ACCESS_TOKEN_TTL_SECONDS, 900);
const REFRESH_TTL = positiveInt(process.env.OAUTH_REFRESH_TOKEN_TTL_SECONDS, 2592000);
const CODE_TTL = positiveInt(process.env.OAUTH_AUTHORIZATION_CODE_TTL_SECONDS, 300);

const clients = new Map();
const authCodes = new Map();
const accessTokens = new Map();
const refreshTokens = new Map();

function positiveInt(value, fallback) {
  const n = Number(value);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : fallback;
}

function nowSeconds() {
  return Math.floor(Date.now() / 1000);
}

function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString("base64url");
}

function sha256Base64Url(value) {
  return crypto.createHash("sha256").update(value).digest("base64url");
}

function publicBase(req) {
  const configured = String(process.env.PUBLIC_BASE_URL || "").trim();
  if (configured) return configured.replace(/\/$/, "");
  const proto = req.get("x-forwarded-proto") || req.protocol || "https";
  const host = req.get("x-forwarded-host") || req.get("host");
  return `${proto}://${host}`;
}

function safeEqual(a, b) {
  const aa = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (aa.length !== bb.length) return false;
  return crypto.timingSafeEqual(aa, bb);
}

function isAllowedRedirect(uri) {
  try {
    const u = new URL(uri);
    if (u.protocol !== "https:") return false;
    const h = u.hostname.toLowerCase();
    return (
      h === "chatgpt.com" ||
      h.endsWith(".chatgpt.com") ||
      h === "openai.com" ||
      h.endsWith(".openai.com")
    );
  } catch {
    return false;
  }
}

function cleanExpired() {
  const now = Date.now();
  for (const [k, v] of authCodes) if (v.expiresAt <= now) authCodes.delete(k);
  for (const [k, v] of accessTokens) if (v.expiresAt <= now) accessTokens.delete(k);
  for (const [k, v] of refreshTokens) if (v.expiresAt <= now) refreshTokens.delete(k);
}

setInterval(cleanExpired, 60_000).unref();

function htmlPage({ error = "", fields = {} } = {}) {
  const hidden = Object.entries(fields)
    .map(
      ([k, v]) =>
        `<input type="hidden" name="${escapeHtml(k)}" value="${escapeHtml(v || "")}">`
    )
    .join("\n");

  return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>授权麦当劳 MCP</title>
<style>
body{font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#f6f7f8;color:#202124;margin:0;padding:32px}
main{max-width:520px;margin:7vh auto;background:#fff;border:1px solid #ddd;border-radius:18px;padding:28px;box-shadow:0 8px 30px #0000000d}
h1{font-size:24px;margin:0 0 10px}
p{line-height:1.55}
label{display:block;font-weight:650;margin:22px 0 8px}
input[type=password]{box-sizing:border-box;width:100%;padding:13px;border:1px solid #aaa;border-radius:10px;font-size:16px}
button{margin-top:16px;width:100%;padding:13px;border:0;border-radius:10px;background:#111;color:#fff;font-size:16px;font-weight:700;cursor:pointer}
.error{background:#fff1f0;color:#b42318;padding:10px 12px;border-radius:10px}
.note{font-size:13px;color:#666}
</style>
</head>
<body>
<main>
<h1>授权麦当劳 MCP</h1>
<p>请输入你为这个私人适配器单独设置的授权密码。</p>
${error ? `<p class="error">${escapeHtml(error)}</p>` : ""}
<form method="post" action="/authorize">
${hidden}
<label for="password">ADAPTER_OWNER_PASSWORD</label>
<input id="password" name="password" type="password" autocomplete="current-password" required autofocus>
<button type="submit">允许 ChatGPT 访问</button>
</form>
<p class="note">这里不要填写麦当劳 MCD_MCP_TOKEN。麦当劳 Token 只应保存在 Render 环境变量中。</p>
</main>
</body>
</html>`;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function authPageHeaders(res) {
  res.set(
    "Content-Security-Policy",
    "default-src 'none'; style-src 'unsafe-inline'; form-action 'self' https://chatgpt.com https://*.chatgpt.com https://openai.com https://*.openai.com; base-uri 'none'; frame-ancestors 'none'"
  );
  res.set("Referrer-Policy", "no-referrer");
  res.set("Cache-Control", "no-store");
}

function oauthError(res, status, error, description) {
  return res.status(status).json({
    error,
    ...(description ? { error_description: description } : {}),
  });
}

function issueTokens(clientId, scope = "mcp") {
  const now = Date.now();
  const accessToken = randomToken(32);
  const refreshToken = randomToken(40);
  accessTokens.set(accessToken, {
    clientId,
    scope,
    expiresAt: now + ACCESS_TTL * 1000,
  });
  refreshTokens.set(refreshToken, {
    clientId,
    scope,
    expiresAt: now + REFRESH_TTL * 1000,
  });
  return {
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: ACCESS_TTL,
    refresh_token: refreshToken,
    scope,
  };
}

function validateClientAndRedirect(clientId, redirectUri) {
  let client = clients.get(clientId);
  // Render free services can restart/redeploy, which clears the in-memory DCR
  // registry. ChatGPT may then reuse its previously issued public client_id.
  // Recover that registration only when the redirect URI still passes our
  // strict ChatGPT/OpenAI allow-list. This keeps reconnects working without
  // storing OAuth client registrations on disk.
  if (!client && clientId && redirectUri && isAllowedRedirect(redirectUri)) {
    client = {
      client_id: String(clientId),
      client_name: "ChatGPT (recovered)",
      redirect_uris: [String(redirectUri)],
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
      created_at: nowSeconds(),
    };
    clients.set(String(clientId), client);
  }
  if (!client) return { error: "unknown client_id" };
  if (!client.redirect_uris.includes(redirectUri)) {
    return { error: "redirect_uri is not registered for this client" };
  }
  return { client };
}

function validateBearer(req) {
  const header = req.get("authorization") || "";
  const match = /^Bearer\s+(.+)$/i.exec(header);
  if (!match) return null;
  const token = accessTokens.get(match[1]);
  if (!token || token.expiresAt <= Date.now()) return null;
  return token;
}

function sendMcpUnauthorized(req, res) {
  const metadata = `${publicBase(req)}/.well-known/oauth-protected-resource/mcp`;
  res.set("WWW-Authenticate", `Bearer resource_metadata="${metadata}", scope="mcp"`);
  return res.status(401).json({ error: "unauthorized" });
}

function blockedToolName(name) {
  if (ALLOW_ORDER_CREATION) return false;
  const n = String(name || "").toLowerCase();
  return /(create|submit|place|confirm|pay|payment|checkout|redeem|exchange).*(order|purchase|cart|points?|coupon)|(?:order|purchase|cart|points?|coupon).*(create|submit|place|confirm|pay|payment|checkout|redeem|exchange)|下单|创建订单|提交订单|支付|付款|结算|兑换/.test(
    n
  );
}

function findBlockedTool(payload) {
  const items = Array.isArray(payload) ? payload : [payload];
  for (const item of items) {
    if (item && item.method === "tools/call") {
      const name = item.params && item.params.name;
      if (blockedToolName(name)) return { id: item.id ?? null, name };
    }
  }
  return null;
}

app.all(
  "/mcp",
  express.raw({ type: () => true, limit: "5mb" }),
  async (req, res) => {
    if (!validateBearer(req)) return sendMcpUnauthorized(req, res);

    if (!MCD_MCP_TOKEN) {
      return res.status(503).json({ error: "server_not_configured" });
    }

    let rawBody = null;
    if (!["GET", "HEAD"].includes(req.method) && Buffer.isBuffer(req.body)) {
      rawBody = req.body;
    }

    if (req.method === "POST" && rawBody && rawBody.length) {
      const contentType = (req.get("content-type") || "").toLowerCase();
      if (contentType.includes("application/json")) {
        try {
          const parsed = JSON.parse(rawBody.toString("utf8"));
          const blocked = findBlockedTool(parsed);
          if (blocked) {
            return res.status(403).json({
              jsonrpc: "2.0",
              id: blocked.id,
              error: {
                code: -32003,
                message:
                  "Order/payment/points-redemption tool calls are blocked by ALLOW_ORDER_CREATION=false",
                data: { tool: blocked.name },
              },
            });
          }
        } catch {
          // Leave protocol validation to the upstream MCP server.
        }
      }
    }

    const upstreamHeaders = {
      Authorization: `Bearer ${MCD_MCP_TOKEN}`,
    };

    for (const name of [
      "accept",
      "content-type",
      "mcp-session-id",
      "mcp-protocol-version",
      "last-event-id",
    ]) {
      const value = req.get(name);
      if (value) upstreamHeaders[name] = value;
    }

    let upstream;
    try {
      upstream = await fetch(MCD_MCP_URL, {
        method: req.method,
        headers: upstreamHeaders,
        body: rawBody && rawBody.length ? rawBody : undefined,
        redirect: "manual",
      });
    } catch {
      return res.status(502).json({ error: "upstream_unreachable" });
    }

    if (upstream.status === 401 || upstream.status === 403) {
      try {
        await upstream.body?.cancel();
      } catch {}
      return res.status(502).json({ error: "upstream_auth_failed" });
    }

    res.status(upstream.status);
    for (const name of [
      "content-type",
      "cache-control",
      "mcp-session-id",
      "mcp-protocol-version",
      "retry-after",
    ]) {
      const value = upstream.headers.get(name);
      if (value) res.set(name, value);
    }

    if (!upstream.body || req.method === "HEAD" || upstream.status === 204) {
      return res.end();
    }

    Readable.fromWeb(upstream.body).pipe(res);
  }
);

app.use(express.urlencoded({ extended: false, limit: "64kb" }));
app.use(express.json({ limit: "256kb" }));

app.get("/healthz", (req, res) => {
  res.set("Cache-Control", "no-store");
  res.json({
    status: "ok",
    service: "mcd-chatgpt-oauth-adapter",
    oauth: "ready",
    upstream: "not-contacted",
    orderCreation: ALLOW_ORDER_CREATION ? "enabled" : "blocked",
  });
});

app.get("/.well-known/oauth-authorization-server", (req, res) => {
  const base = publicBase(req);
  res.set("Cache-Control", "no-store");
  res.json({
    issuer: base,
    authorization_endpoint: `${base}/authorize`,
    token_endpoint: `${base}/token`,
    registration_endpoint: `${base}/register`,
    scopes_supported: ["mcp"],
    response_types_supported: ["code"],
    response_modes_supported: ["query"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    token_endpoint_auth_methods_supported: ["none"],
    code_challenge_methods_supported: ["S256"],
    authorization_response_iss_parameter_supported: true,
  });
});

function protectedResourceMetadata(req, res) {
  const base = publicBase(req);
  res.set("Cache-Control", "no-store");
  res.json({
    resource: `${base}/mcp`,
    authorization_servers: [base],
    bearer_methods_supported: ["header"],
    scopes_supported: ["mcp"],
  });
}

app.get("/.well-known/oauth-protected-resource/mcp", protectedResourceMetadata);
app.get("/.well-known/oauth-protected-resource", protectedResourceMetadata);

app.post("/register", (req, res) => {
  const redirectUris = Array.isArray(req.body?.redirect_uris)
    ? req.body.redirect_uris
    : [];

  if (!redirectUris.length || !redirectUris.every(isAllowedRedirect)) {
    return oauthError(
      res,
      400,
      "invalid_redirect_uri",
      "Only HTTPS ChatGPT/OpenAI redirect URIs are accepted"
    );
  }

  const clientId = randomToken(24);
  const client = {
    client_id: clientId,
    client_name: String(req.body?.client_name || "ChatGPT"),
    redirect_uris: redirectUris,
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
    token_endpoint_auth_method: "none",
    created_at: nowSeconds(),
  };
  clients.set(clientId, client);

  res.status(201).json({
    client_id: clientId,
    client_id_issued_at: client.created_at,
    client_name: client.client_name,
    redirect_uris: client.redirect_uris,
    grant_types: client.grant_types,
    response_types: client.response_types,
    token_endpoint_auth_method: "none",
  });
});

app.get("/authorize", (req, res) => {
  const {
    client_id,
    redirect_uri,
    response_type,
    scope = "mcp",
    state = "",
    code_challenge,
    code_challenge_method,
  } = req.query;

  const checked = validateClientAndRedirect(client_id, redirect_uri);
  if (checked.error) return res.status(400).send("Invalid OAuth client or redirect URI.");
  if (response_type !== "code") return res.status(400).send("Unsupported response_type.");
  if (!String(scope).split(/\s+/).includes("mcp")) return res.status(400).send("Scope mcp is required.");
  if (!code_challenge || code_challenge_method !== "S256") {
    return res.status(400).send("PKCE S256 is required.");
  }

  authPageHeaders(res);
  res.type("html").send(
    htmlPage({
      fields: {
        client_id,
        redirect_uri,
        response_type,
        scope,
        state,
        code_challenge,
        code_challenge_method,
      },
    })
  );
});

app.post("/authorize", (req, res) => {
  const {
    password = "",
    client_id,
    redirect_uri,
    response_type,
    scope = "mcp",
    state = "",
    code_challenge,
    code_challenge_method,
  } = req.body || {};

  const fields = {
    client_id,
    redirect_uri,
    response_type,
    scope,
    state,
    code_challenge,
    code_challenge_method,
  };

  const checked = validateClientAndRedirect(client_id, redirect_uri);
  if (checked.error || response_type !== "code") {
    return res.status(400).send("Invalid OAuth request.");
  }
  if (!code_challenge || code_challenge_method !== "S256") {
    return res.status(400).send("PKCE S256 is required.");
  }

  if (!ADAPTER_OWNER_PASSWORD || !safeEqual(password, ADAPTER_OWNER_PASSWORD)) {
    authPageHeaders(res);
    return res
      .status(401)
      .type("html")
      .send(htmlPage({ error: "授权密码不正确。", fields }));
  }

  const code = randomToken(32);
  authCodes.set(code, {
    clientId: client_id,
    redirectUri: redirect_uri,
    scope,
    codeChallenge: code_challenge,
    expiresAt: Date.now() + CODE_TTL * 1000,
  });

  const callback = new URL(redirect_uri);
  callback.searchParams.set("code", code);
  if (state) callback.searchParams.set("state", state);
  callback.searchParams.set("iss", publicBase(req));

  authPageHeaders(res);
  return res.redirect(302, callback.toString());
});

app.post("/token", (req, res) => {
  res.set("Cache-Control", "no-store");
  const grantType = req.body?.grant_type;

  if (grantType === "authorization_code") {
    const code = req.body?.code;
    const clientId = req.body?.client_id;
    const redirectUri = req.body?.redirect_uri;
    const verifier = req.body?.code_verifier;

    const record = authCodes.get(code);
    if (!record || record.expiresAt <= Date.now()) {
      authCodes.delete(code);
      return oauthError(res, 400, "invalid_grant", "Authorization code is invalid or expired");
    }

    if (record.clientId !== clientId || record.redirectUri !== redirectUri) {
      return oauthError(res, 400, "invalid_grant", "Client or redirect URI mismatch");
    }
    if (!verifier || sha256Base64Url(verifier) !== record.codeChallenge) {
      return oauthError(res, 400, "invalid_grant", "PKCE verification failed");
    }

    authCodes.delete(code);
    return res.json(issueTokens(clientId, record.scope || "mcp"));
  }

  if (grantType === "refresh_token") {
    const refresh = req.body?.refresh_token;
    const clientId = req.body?.client_id;
    const record = refreshTokens.get(refresh);
    if (!record || record.expiresAt <= Date.now() || record.clientId !== clientId) {
      refreshTokens.delete(refresh);
      return oauthError(res, 400, "invalid_grant", "Refresh token is invalid or expired");
    }
    refreshTokens.delete(refresh);
    return res.json(issueTokens(clientId, record.scope || "mcp"));
  }

  return oauthError(res, 400, "unsupported_grant_type");
});

app.get("/", (req, res) => {
  res.type("text").send("mcd-chatgpt-oauth-adapter");
});

app.use((err, req, res, next) => {
  console.error("request_error", err && err.message ? err.message : "unknown");
  if (res.headersSent) return next(err);
  res.status(500).json({ error: "internal_server_error" });
});

app.listen(PORT, () => {
  console.log(`mcd-chatgpt-oauth-adapter listening on port ${PORT}`);
});
