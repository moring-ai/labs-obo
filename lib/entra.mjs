/**
 * labsOBO | shared identity plumbing for the calling app (APP) and the local A1 runtime.
 *
 * Everything here is about making each hop VISIBLE: a request is performed and,
 * at the same time, described (method, URL, headers, body, an equivalent curl,
 * the response, and any token it carried, decoded and checked).
 */
import { readFileSync, existsSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { SignJWT, importPKCS8, createRemoteJWKSet, jwtVerify, decodeJwt, decodeProtectedHeader } from "jose";

export const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const execFileP = promisify(execFile);

// ---------------------------------------------------------------- config
export function loadEnv(path = resolve(ROOT, ".lab/labsOBO.env")) {
  const out = {};
  if (!existsSync(path)) throw new Error(`Missing ${path}. Run scripts/10-entra-provision.sh first.`);
  for (const line of readFileSync(path, "utf8").split("\n")) {
    const m = line.match(/^([A-Z0-9_]+)="?([^"]*)"?\s*$/);
    if (m) out[m[1]] = m[2];
  }
  return out;
}
export const env = loadEnv();
export const state = JSON.parse(readFileSync(resolve(ROOT, ".lab/lab-state.json"), "utf8"));
const optFile = (p) => (existsSync(resolve(ROOT, p)) ? readFileSync(resolve(ROOT, p), "utf8").trim() : null);

const tenantId = env.LABSOBO_TENANT_ID;
const authority = `https://login.microsoftonline.com/${tenantId}`;
export const cfg = {
  tenantId, authority,
  authorizeEndpoint: `${authority}/oauth2/v2.0/authorize`,
  tokenEndpoint: `${authority}/oauth2/v2.0/token`,
  issuer: `${authority}/v2.0`,
  jwksUri: `${authority}/discovery/v2.0/keys`,
  discoveryUrl: `${authority}/v2.0/.well-known/openid-configuration`,
  bp: {
    name: env.LABSOBO_BP_A1_NAME, clientId: env.LABSOBO_BP_A1_CLIENT_ID, objectId: env.LABSOBO_BP_A1_OBJECT_ID,
    principalId: env.LABSOBO_BP_A1_PRINCIPAL_ID, uri: `api://${env.LABSOBO_BP_A1_CLIENT_ID}`,
    scope: env.LABSOBO_ACCESS_SCOPE_VALUE, scopeId: env.LABSOBO_ACCESS_SCOPE_ID,
    fullScope: `api://${env.LABSOBO_BP_A1_CLIENT_ID}/${env.LABSOBO_ACCESS_SCOPE_VALUE}`,
    roleValue: env.LABSOBO_AGENT_INVOKER_ROLE_VALUE, roleId: env.LABSOBO_AGENT_INVOKER_ROLE_ID,
  },
  app: {
    name: env.LABSOBO_CALLING_APP_NAME, clientId: env.LABSOBO_CALLING_APP_CLIENT_ID,
    principalId: env.LABSOBO_CALLING_APP_PRINCIPAL_ID, redirectUri: env.LABSOBO_REDIRECT_URI,
    keyPath: resolve(ROOT, `infra/entra/certs/${env.LABSOBO_CALLING_APP_NAME}.key.pem`),
    certPath: resolve(ROOT, `infra/entra/certs/${env.LABSOBO_CALLING_APP_NAME}.cert.pem`),
  },
  direct: {
    name: "labsOBO-direct-client", clientId: env.LABSOBO_DIRECT_CLIENT_ID,
    redirectUri: "http://localhost:3100/auth/callback/direct",
  },
  agent: {
    name: env.LABSOBO_AGENT_A1_NAME, clientId: env.LABSOBO_AGENT_A1_CLIENT_ID, objectId: env.LABSOBO_AGENT_A1_OBJECT_ID,
    bpKeyPath: resolve(ROOT, `infra/entra/certs/${env.LABSOBO_BP_A1_NAME}.key.pem`),
    bpCertPath: resolve(ROOT, `infra/entra/certs/${env.LABSOBO_BP_A1_NAME}.cert.pem`),
    downstreamScope: "https://graph.microsoft.com/User.Read",
  },
  users: {
    alex: { key: "alex", upn: env.LABSOBO_ALEX_UPN, objectId: env.LABSOBO_ALEX_USER_ID, displayName: state.users?.alex?.displayName ?? "Alex" },
    sam:  { key: "sam",  upn: env.LABSOBO_SAM_UPN,  objectId: env.LABSOBO_SAM_USER_ID,  displayName: state.users?.sam?.displayName ?? "Sam" },
  },
  azureCliAppId: "04b07795-8ddb-461a-bbee-02f9e1bf7b46",
  graphAppId: "00000003-0000-0000-c000-000000000000",
  graphSpId: "c5d922ee-be5f-42bd-ac6f-1a2681d7eb60",
  tokenExchangeAppId: "fb60f99c-7a34-4190-8149-302f77469936",
  ports: { app: 3100, agent: 3101 },
  aws: { region: "us-east-1", runtimeArn: optFile(".lab/a1_runtime_arn.txt") },
};

/** Friendly labels for every GUID the lab touches, so the UI can name things. */
export const LABELS = {
  [cfg.bp.clientId]: "BP-A1 (labsOBO-agent1-blueprint)",
  [cfg.bp.principalId]: "BP-A1 service principal",
  [cfg.app.clientId]: "APP (labsOBO-calling-app)",
  [cfg.direct.clientId]: "DIRECT (labsOBO-direct-client)",
  [cfg.agent.clientId]: "AGENT-A1 (labsOBO-agent1)",
  [cfg.users.alex.objectId]: `ALEX (${cfg.users.alex.displayName})`,
  [cfg.users.sam.objectId]: `SAM (${cfg.users.sam.displayName})`,
  [cfg.azureCliAppId]: "Azure CLI (public client)",
  [cfg.graphAppId]: "Microsoft Graph",
  [cfg.tokenExchangeAppId]: "AzureADTokenExchange",
  [cfg.bp.roleId]: cfg.bp.roleValue,
  [cfg.bp.scopeId]: cfg.bp.scope,
  "https://api.security.microsoft.com": "Microsoft Defender (Advanced Hunting API)",
  "8ee8fdad-f234-4243-8f3b-15c294843740": "Microsoft Defender (Microsoft Threat Protection)",
  ...(env.LABSOBO_JIRA_BROKER_CLIENT_ID ? { [env.LABSOBO_JIRA_BROKER_CLIENT_ID]: "JIRA-BROKER (labsOBO-jira-broker)" } : {}),
};
export const label = (v) => (typeof v === "string" && LABELS[v]) ? LABELS[v] : null;

// ---------------------------------------------------------------- tokens
export const ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
export const JWT_RE = /^[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}$/;

export function decode(token) {
  try { return { header: decodeProtectedHeader(token), claims: decodeJwt(token) }; } catch { return null; }
}

const jwks = createRemoteJWKSet(new URL(cfg.jwksUri));
/** Real verification against the tenant JWKS: signature, issuer, audience, expiry. */
export async function verify(token, { audience, issuer = cfg.issuer } = {}) {
  try {
    const { payload, protectedHeader } = await jwtVerify(token, jwks, { issuer, audience });
    return { ok: true, claims: payload, header: protectedHeader };
  } catch (e) {
    return { ok: false, reason: e?.code ? `${e.code}: ${e.message}` : String(e?.message ?? e) };
  }
}

export function x5t(certPem) {
  const der = Buffer.from(certPem.replace(/-----[A-Z ]+-----/g, "").replace(/\s+/g, ""), "base64");
  return createHash("sha1").update(der).digest("base64url");
}

/** A private_key_jwt client assertion, audience = the token endpoint. */
export async function clientAssertion({ clientId, keyPath, certPath, alg = "RS256", lifetime = 300 }) {
  const key = await importPKCS8(readFileSync(keyPath, "utf8"), alg);
  const now = Math.floor(Date.now() / 1000);
  const jti = randomUUID();
  const thumb = x5t(readFileSync(certPath, "utf8"));
  const assertion = await new SignJWT({})
    .setProtectedHeader({ alg, typ: "JWT", x5t: thumb })
    .setIssuer(clientId).setSubject(clientId).setAudience(cfg.tokenEndpoint)
    .setJti(jti).setNotBefore(now).setIssuedAt(now).setExpirationTime(now + lifetime)
    .sign(key);
  return { assertion, info: { alg, x5t: thumb, iss: clientId, sub: clientId, aud: cfg.tokenEndpoint, jti, exp: now + lifetime } };
}

export function pkce() {
  const verifier = randomBytes(48).toString("base64url");
  return { verifier, challenge: createHash("sha256").update(verifier).digest("base64url"), method: "S256" };
}
export const randomState = () => randomBytes(18).toString("base64url");

// ---------------------------------------------------------------- claim checks
/**
 * The five claims the lab report is built on, each with the question it answers.
 * `expect` is what a correct token for this situation must contain.
 */
export function tokenChecks(claims, expect = {}) {
  const roles = Array.isArray(claims.roles) ? claims.roles : (claims.roles ? [claims.roles] : []);
  const scp = typeof claims.scp === "string" ? claims.scp.split(" ") : [];
  const rows = [];
  const add = (claim, value, want, ok, meaning) => rows.push({ claim, value, expect: want, ok, meaning, label: label(value) });
  add("oid", claims.oid, expect.oid ?? null, expect.oid ? claims.oid === expect.oid : null, "Which human? (the user object id)");
  // v1 access tokens (e.g. the Defender API's) name the acting client in appid instead of azp.
  const actor = claims.azp ?? claims.appid;
  add("azp", actor, expect.azp ?? null, expect.azp ? actor === expect.azp : null, claims.azp ? "Which OAuth client asked for this token?" : "Which client is acting? (appid: this is a v1 token)");
  add("aud", claims.aud, expect.aud ?? null, expect.aud ? claims.aud === expect.aud : null, "Which agent API boundary is it for?");
  add("scp", claims.scp ?? "(absent)", expect.scp ?? null, expect.scp ? scp.includes(expect.scp) : null, "What delegated operation was consented?");
  add("roles", roles.length ? roles : "(absent)", expect.role ?? null, expect.role ? roles.includes(expect.role) : null,
      "Is this human actually entitled to invoke this agent? (app-role assignment)");
  if (claims.idtyp !== undefined) add("idtyp", claims.idtyp, null, null, "Token type hint (app-only tokens carry idtyp=app)");
  return rows;
}

export function summarizeToken(name, token, expect, extra = {}) {
  const d = decode(token);
  if (!d) return { name, error: "not a JWT", raw: token, ...extra };
  return { name, header: d.header, claims: d.claims, checks: tokenChecks(d.claims, expect), raw: token, ...extra };
}

// ---------------------------------------------------------------- HTTP with a record of itself
const SECRET_KEYS = new Set(["client_assertion", "code", "refresh_token", "access_token", "id_token", "assertion", "client_secret", "code_verifier"]);
const PLACEHOLDER = {
  client_assertion: "${LABSOBO_CLIENT_ASSERTION}", code: "${LABSOBO_AUTH_CODE}", refresh_token: "${LABSOBO_REFRESH_TOKEN}",
  assertion: "${LABSOBO_USER_ASSERTION}", code_verifier: "${LABSOBO_PKCE_VERIFIER}", access_token: "${LABSOBO_ACCESS_TOKEN}",
};

/** curl equivalent of a request, with secrets as ${ENV} placeholders (the plan's style). */
export function curlFor({ method = "GET", url, headers = {}, form, json, secretNames = {} }) {
  const lines = [];
  const u = new URL(url);
  if (method === "GET" && u.search) {
    lines.push(`curl -G "${u.origin}${u.pathname}"`);
    for (const [k, v] of u.searchParams) lines.push(`  --data-urlencode "${k}=${v}"`);
  } else {
    lines.push(`curl${method !== "GET" ? ` -X ${method}` : ""} "${url}"`);
  }
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === "authorization") lines.push(`  -H "Authorization: Bearer \${${secretNames.bearer ?? "LABSOBO_TOKEN"}}"`);
    else lines.push(`  -H "${k}: ${v}"`);
  }
  if (form) for (const [k, v] of Object.entries(form)) {
    const shown = SECRET_KEYS.has(k) ? (secretNames[k] ? `\${${secretNames[k]}}` : PLACEHOLDER[k] ?? "${SECRET}") : v;
    lines.push(`  --data-urlencode "${k}=${shown}"`);
  }
  if (json !== undefined) lines.push(`  -d '${JSON.stringify(json, null, 2).replace(/'/g, "'\\''")}'`);
  return lines.join(" \\\n");
}

/** Perform a request and return { request, response } in the hop format. */
export async function doHttp({ method = "GET", url, headers = {}, form, json, secretNames, timeoutMs = 30000 }) {
  const h = { ...headers };
  let body;
  if (form) { h["Content-Type"] = "application/x-www-form-urlencoded"; body = new URLSearchParams(form).toString(); }
  else if (json !== undefined) { h["Content-Type"] = "application/json"; body = JSON.stringify(json); }
  const req = { method, url, headers: h, body: form ?? json ?? null, bodyType: form ? "form" : json !== undefined ? "json" : "none",
                curl: curlFor({ method, url, headers: h, form, json, secretNames }) };
  const t0 = Date.now();
  let res, text;
  try {
    res = await fetch(url, { method, headers: h, body, signal: AbortSignal.timeout(timeoutMs) });
    text = await res.text();
  } catch (e) {
    return { request: req, response: { status: 0, statusText: "network error", durationMs: Date.now() - t0, body: String(e?.message ?? e) }, ok: false };
  }
  let parsed = text;
  try { parsed = JSON.parse(text); } catch { /* keep text */ }
  const rh = {};
  for (const k of ["content-type", "x-ms-request-id", "x-ms-ests-server", "request-id", "client-request-id", "x-amzn-errortype", "x-amzn-requestid", "www-authenticate", "date"]) {
    const v = res.headers.get(k); if (v) rh[k] = v;
  }
  return { request: req, response: { status: res.status, statusText: res.statusText, durationMs: Date.now() - t0, headers: rh, body: parsed }, ok: res.ok };
}

/** POST to the Entra token endpoint; returns the hop pieces plus decoded tokens. */
export async function tokenRequest(form, { secretNames } = {}) {
  const r = await doHttp({ method: "POST", url: cfg.tokenEndpoint, form, secretNames });
  const out = { ...r, tokens: null, error: null };
  if (r.ok && r.response.body?.access_token) {
    out.tokens = r.response.body;
  } else if (r.response.body && typeof r.response.body === "object") {
    const desc = String(r.response.body.error_description ?? "");
    out.error = { error: r.response.body.error, code: desc.match(/AADSTS\d+/)?.[0] ?? null, description: desc.split("\n")[0] };
  }
  return out;
}

// ---------------------------------------------------------------- redaction for display
export function redactDeep(v, reveal = false) {
  if (reveal) return v;
  if (typeof v === "string") {
    if (JWT_RE.test(v)) return `«JWT ${v.slice(0, 12)}… ${v.length} chars — toggle 'reveal tokens' to see it»`;
    if (v.startsWith("Bearer ") && JWT_RE.test(v.slice(7))) return `Bearer «JWT ${v.slice(7, 19)}… ${v.length - 7} chars»`;
    if (v.length > 60 && /^[A-Za-z0-9_.-]+$/.test(v) && !/^[0-9a-f-]{36}$/.test(v)) return `«secret ${v.slice(0, 8)}… ${v.length} chars»`;
    return v;
  }
  if (Array.isArray(v)) return v.map((x) => redactDeep(x, reveal));
  if (v && typeof v === "object") {
    const o = {};
    for (const [k, x] of Object.entries(v)) {
      if (k === "raw") continue;                        // token raw values are only sent when revealed
      o[k] = redactDeep(x, reveal);
    }
    return o;
  }
  return v;
}

// ---------------------------------------------------------------- az CLI (the operator's SSO session)
/** Graph token for admin operations, borrowed from the signed-in Azure CLI session. Never persisted. */
export async function azAccessToken(args) {
  const t0 = Date.now();
  const { stdout } = await execFileP("az", ["account", "get-access-token", ...args, "-o", "json"], { maxBuffer: 1 << 20 });
  const j = JSON.parse(stdout);
  return { token: j.accessToken, expiresOn: j.expiresOn, durationMs: Date.now() - t0, command: `az account get-access-token ${args.join(" ")} -o json` };
}
