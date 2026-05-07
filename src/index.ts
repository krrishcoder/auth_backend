import "dotenv/config";
import cors from "cors";
import express from "express";
import { randomBytes, randomUUID, createHash, timingSafeEqual } from "node:crypto";
import { SignJWT, jwtVerify } from "jose";
import { z } from "zod";

const CONFIG = {
  host: process.env.HOST || "localhost",
  port: Number(process.env.PORT || 8080),
  publicUrl: process.env.PUBLIC_URL || `http://${process.env.HOST || "localhost"}:${process.env.PORT || 8080}`,
  google: {
    clientId: process.env.GOOGLE_CLIENT_ID || "",
    clientSecret: process.env.GOOGLE_CLIENT_SECRET || "",
    redirectUri:
      process.env.GOOGLE_REDIRECT_URI ||
      `http://${process.env.HOST || "localhost"}:${process.env.PORT || 8080}/oauth/google/callback`,
  },
  jwtSecret: process.env.AUTH_JWT_SECRET || "dev-change-me-to-a-long-random-string",
  mcpResource: process.env.MCP_RESOURCE || "http://localhost:3000",
  allowedRedirectUris: (
    process.env.ALLOWED_REDIRECT_URIS ||
    "https://claude.ai/api/mcp/auth_callback,https://claude.com/api/mcp/auth_callback"
  )
    .split(",")
    .map((uri) => uri.trim())
    .filter(Boolean),
};

type RegisteredClient = {
  clientId: string;
  clientName: string;
  redirectUris: string[];
  grantTypes: string[];
  responseTypes: string[];
  createdAt: number;
};

type PendingAuthorization = {
  clientId: string;
  redirectUri: string;
  scope: string;
  state?: string;
  resource: string;
  codeChallenge?: string;
  codeChallengeMethod?: string;
};

type AuthorizationCode = PendingAuthorization & {
  code: string;
  googleSub: string;
  email?: string;
  name?: string;
  expiresAt: number;
};

const app = express();
app.use(cors({ origin: true }));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

const clients = new Map<string, RegisteredClient>();
const pendingAuthorizations = new Map<string, PendingAuthorization>();
const authorizationCodes = new Map<string, AuthorizationCode>();

const issuer = CONFIG.publicUrl;
const tokenIssuer = new TextEncoder().encode(CONFIG.jwtSecret);

function normalizeResource(value: string) {
  return value.replace(/\/+$/, "");
}

function assertGoogleConfigured() {
  if (!CONFIG.google.clientId || !CONFIG.google.clientSecret) {
    throw new Error("Missing GOOGLE_CLIENT_ID or GOOGLE_CLIENT_SECRET");
  }
}

function isAllowedRedirectUri(uri: string) {
  try {
    const parsed = new URL(uri);
    if (CONFIG.allowedRedirectUris.includes(parsed.toString())) {
      return true;
    }

    return parsed.protocol === "http:" && ["localhost", "127.0.0.1", "::1"].includes(parsed.hostname);
  } catch {
    return false;
  }
}

function base64UrlSha256(value: string) {
  return createHash("sha256").update(value).digest("base64url");
}

function safeEqual(a: string, b: string) {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}

function verifyPkce(codeVerifier: string, challenge?: string, method?: string) {
  if (!challenge) {
    return true;
  }

  if (method === "S256") {
    return safeEqual(base64UrlSha256(codeVerifier), challenge);
  }

  if (!method || method === "plain") {
    return safeEqual(codeVerifier, challenge);
  }

  return false;
}

function buildGoogleAuthorizationUrl(state: string) {
  const url = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  url.searchParams.set("client_id", CONFIG.google.clientId);
  url.searchParams.set("redirect_uri", CONFIG.google.redirectUri);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("scope", "openid email profile");
  url.searchParams.set("state", state);
  url.searchParams.set("access_type", "offline");
  url.searchParams.set("prompt", "consent");
  return url;
}

async function exchangeGoogleCode(code: string) {
  const response = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      code,
      client_id: CONFIG.google.clientId,
      client_secret: CONFIG.google.clientSecret,
      redirect_uri: CONFIG.google.redirectUri,
      grant_type: "authorization_code",
    }),
  });

  const tokenBody = await response.json();
  if (!response.ok) {
    throw new Error(`Google token exchange failed: ${JSON.stringify(tokenBody)}`);
  }

  const userInfoResponse = await fetch("https://openidconnect.googleapis.com/v1/userinfo", {
    headers: { Authorization: `Bearer ${tokenBody.access_token}` },
  });
  const userInfo = await userInfoResponse.json();
  if (!userInfoResponse.ok) {
    throw new Error(`Google userinfo failed: ${JSON.stringify(userInfo)}`);
  }

  return userInfo as { sub: string; email?: string; name?: string };
}

async function issueAccessToken(codeRecord: AuthorizationCode) {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({
    aud: codeRecord.resource,
    scope: codeRecord.scope,
    client_id: codeRecord.clientId,
    sub: codeRecord.googleSub,
    email: codeRecord.email,
    name: codeRecord.name,
  })
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setIssuer(issuer)
    .setIssuedAt(now)
    .setExpirationTime(now + 3600)
    .setJti(randomUUID())
    .sign(tokenIssuer);
}

const metadata = {
  issuer,
  authorization_endpoint: `${issuer}/authorize`,
  token_endpoint: `${issuer}/token`,
  introspection_endpoint: `${issuer}/introspect`,
  registration_endpoint: `${issuer}/register`,
  response_types_supported: ["code"],
  grant_types_supported: ["authorization_code"],
  code_challenge_methods_supported: ["S256", "plain"],
  scopes_supported: ["openid", "email", "profile", "mcp:tools"],
};

app.get(["/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"], (_req, res) => {
  res.json(metadata);
});

app.post("/register", (req, res) => {
  const registrationSchema = z.object({
    client_name: z.string().default("MCP Client"),
    redirect_uris: z.array(z.string().url()).min(1),
    grant_types: z.array(z.string()).default(["authorization_code"]),
    response_types: z.array(z.string()).default(["code"]),
  });

  const parsed = registrationSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "invalid_client_metadata", error_description: parsed.error.message });
    return;
  }

  if (!parsed.data.redirect_uris.every(isAllowedRedirectUri)) {
    res.status(400).json({
      error: "invalid_redirect_uri",
      error_description: "Only localhost redirect URIs are allowed by this development server.",
    });
    return;
  }

  const clientId = randomUUID();
  const client: RegisteredClient = {
    clientId,
    clientName: parsed.data.client_name,
    redirectUris: parsed.data.redirect_uris,
    grantTypes: parsed.data.grant_types,
    responseTypes: parsed.data.response_types,
    createdAt: Date.now(),
  };
  clients.set(clientId, client);

  res.status(201).json({
    client_id: clientId,
    client_name: client.clientName,
    redirect_uris: client.redirectUris,
    grant_types: client.grantTypes,
    response_types: client.responseTypes,
    token_endpoint_auth_method: "none",
  });
});

app.get("/authorize", (req, res) => {
  try {
    assertGoogleConfigured();
  } catch (error) {
    res.status(500).send(error instanceof Error ? error.message : "Google OAuth is not configured");
    return;
  }

  const clientId = String(req.query.client_id || "");
  const redirectUri = String(req.query.redirect_uri || "");
  const responseType = String(req.query.response_type || "");
  const resource = String(req.query.resource || CONFIG.mcpResource);
  const scope = String(req.query.scope || "mcp:tools");
  const state = req.query.state ? String(req.query.state) : undefined;
  const codeChallenge = req.query.code_challenge ? String(req.query.code_challenge) : undefined;
  const codeChallengeMethod = req.query.code_challenge_method ? String(req.query.code_challenge_method) : undefined;

  const client = clients.get(clientId);
  if (!client || !client.redirectUris.includes(redirectUri) || responseType !== "code") {
    res.status(400).send("Invalid authorization request");
    return;
  }

  if (normalizeResource(resource) !== normalizeResource(CONFIG.mcpResource)) {
    res.status(400).send(`Unsupported resource: ${resource}`);
    return;
  }

  const requestId = randomBytes(24).toString("base64url");
  pendingAuthorizations.set(requestId, {
    clientId,
    redirectUri,
    scope,
    state,
    resource,
    codeChallenge,
    codeChallengeMethod,
  });

  res.redirect(buildGoogleAuthorizationUrl(requestId).toString());
});

app.get("/oauth/google/callback", async (req, res) => {
  const requestId = String(req.query.state || "");
  const googleCode = String(req.query.code || "");
  const pending = pendingAuthorizations.get(requestId);

  if (!pending || !googleCode) {
    res.status(400).send("Invalid Google callback");
    return;
  }

  pendingAuthorizations.delete(requestId);

  try {
    const googleUser = await exchangeGoogleCode(googleCode);
    const code = randomBytes(32).toString("base64url");
    authorizationCodes.set(code, {
      ...pending,
      code,
      googleSub: googleUser.sub,
      email: googleUser.email,
      name: googleUser.name,
      expiresAt: Date.now() + 5 * 60 * 1000,
    });

    const redirectUrl = new URL(pending.redirectUri);
    redirectUrl.searchParams.set("code", code);
    if (pending.state) {
      redirectUrl.searchParams.set("state", pending.state);
    }
    res.redirect(redirectUrl.toString());
  } catch (error) {
    console.error("[google-callback]", error);
    res.status(502).send("Google login failed");
  }
});

app.post("/token", async (req, res) => {
  const grantType = String(req.body.grant_type || "");
  const code = String(req.body.code || "");
  const clientId = String(req.body.client_id || "");
  const redirectUri = String(req.body.redirect_uri || "");
  const codeVerifier = String(req.body.code_verifier || "");

  if (grantType !== "authorization_code") {
    res.status(400).json({ error: "unsupported_grant_type" });
    return;
  }

  const record = authorizationCodes.get(code);
  authorizationCodes.delete(code);

  if (!record || record.expiresAt < Date.now()) {
    res.status(400).json({ error: "invalid_grant" });
    return;
  }

  if (record.clientId !== clientId || record.redirectUri !== redirectUri) {
    res.status(400).json({ error: "invalid_grant" });
    return;
  }

  if (!verifyPkce(codeVerifier, record.codeChallenge, record.codeChallengeMethod)) {
    res.status(400).json({ error: "invalid_grant", error_description: "PKCE verification failed" });
    return;
  }

  const accessToken = await issueAccessToken(record);
  res.json({
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: 3600,
    scope: record.scope,
  });
});

app.post("/introspect", async (req, res) => {
  const token = String(req.body.token || "");
  if (!token) {
    res.json({ active: false });
    return;
  }

  try {
    const { payload } = await jwtVerify(token, tokenIssuer, {
      issuer,
    });

    const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    const hasAllowedAudience = audiences.some(
      (audience) =>
        typeof audience === "string" &&
        normalizeResource(audience) === normalizeResource(CONFIG.mcpResource),
    );
    if (!hasAllowedAudience) {
      res.json({ active: false });
      return;
    }

    res.json({
      active: true,
      iss: payload.iss,
      aud: payload.aud,
      sub: payload.sub,
      exp: payload.exp,
      iat: payload.iat,
      scope: payload.scope,
      client_id: payload.client_id,
      email: payload.email,
      name: payload.name,
    });
  } catch {
    res.json({ active: false });
  }
});

app.get("/health", (_req, res) => {
  res.json({ ok: true, issuer, mcpResource: CONFIG.mcpResource });
});

app.listen(CONFIG.port, CONFIG.host, () => {
  console.log(`Auth backend listening on ${issuer}`);
  console.log(`Google callback: ${CONFIG.google.redirectUri}`);
});
