/**
 * labsOBO | steps 12-16 of the flow: Atlassian OAuth 2.0 (3LO), the Jira broker's vault, and Jira REST.
 *
 * Two callers, never A1:
 *   calling app  steps 12-13  builds the Atlassian /authorize URL, receives the code on its callback,
 *                             exchanges it, and stores the user's binding in the vault.
 *   Jira broker  steps 15-16  reads the binding for (tid, oid), refreshes the Atlassian token (Atlassian
 *                             rotates refresh tokens, so the new one is written back), and creates the
 *                             issue with that user's own grant.
 * Vault: AWS Secrets Manager, one secret per user, labsobo/jira/vault/<tid>/<oid>.
 * The client secret, the authorization code and every Atlassian token are kept out of the recorded hops.
 */
import { SecretsManagerClient, GetSecretValueCommand, PutSecretValueCommand, CreateSecretCommand } from "@aws-sdk/client-secrets-manager";
import { randomUUID } from "node:crypto";
import { decode } from "./entra.mjs";

export const JIRA = {
  site: process.env.JIRA_SITE ?? "moring-ai",
  project: process.env.JIRA_PROJECT ?? "SEC",
  scopes: ["read:jira-work", "write:jira-work", "read:jira-user", "offline_access"],
  redirectUri: process.env.JIRA_REDIRECT_URI ?? "http://localhost:3100/jira/callback",
  clientSecretName: "labsobo/jira/oauth-client",
  vaultPrefix: "labsobo/jira/vault/",
  region: process.env.AWS_REGION ?? "us-east-1",
};
const sm = new SecretsManagerClient({ region: JIRA.region });
const hop = (p) => ({ id: randomUUID(), ts: new Date().toISOString(), ...p });
const API = "https://api.atlassian.com";

/** fetch that describes itself with secrets replaced by ${PLACEHOLDERS}. */
async function call({ method = "GET", url, token, tokenName = "T_JIRA_USER", json, shown }) {
  const headers = { Accept: "application/json", ...(json ? { "Content-Type": "application/json" } : {}), ...(token ? { Authorization: `Bearer ${token}` } : {}) };
  const t0 = Date.now();
  let status = 0, body = null;
  try {
    const r = await fetch(url, { method, headers, body: json ? JSON.stringify(json) : undefined, signal: AbortSignal.timeout(30000) });
    status = r.status; const text = await r.text();
    try { body = JSON.parse(text); } catch { body = text; }
  } catch (e) { body = String(e?.message ?? e); }
  const shownHeaders = { ...headers, ...(token ? { Authorization: `Bearer \${${tokenName}}` } : {}) };
  const shownBody = shown ?? json ?? null;
  const curl = [`curl${method !== "GET" ? ` -X ${method}` : ""} "${url}"`, ...Object.entries(shownHeaders).map(([k, v]) => `  -H "${k}: ${v}"`),
                ...(shownBody ? [`  -d '${JSON.stringify(shownBody)}'`] : [])].join(" \\\n");
  return { ok: status >= 200 && status < 300, status, body, ms: Date.now() - t0,
           request: { method, url, headers: shownHeaders, body: shownBody, bodyType: shownBody ? "json" : "none", curl } };
}
const scrubbed = (b) => (b && typeof b === "object" ? { ...b,
  ...(b.access_token ? { access_token: "«T_JIRA_USER: not recorded»" } : {}),
  ...(b.refresh_token ? { refresh_token: "«refresh token: kept in the vault, not recorded»" } : {}) } : b);
const errText = (r) => (typeof r.body === "object" ? (r.body?.error_description ?? r.body?.errorMessages?.join("; ") ?? JSON.stringify(r.body?.errors ?? r.body)) : String(r.body)).slice(0, 300);

/** The Atlassian token as a token card: who (Atlassian account), for what (aud), with which scopes. The raw token is never kept. */
function jiraTokenCard(accessToken, user) {
  const c = decode(accessToken)?.claims ?? {};
  const scopes = String(c.scope ?? "");
  return { name: "T_JIRA_USER", claims: { sub: c.sub, aud: c.aud, scope: scopes, exp: c.exp, iss: c.iss },
    checks: [{ claim: "oid", value: `${user.name} (Atlassian account ${c.sub ?? "?"})`, expect: null, ok: null, meaning: "Whose Atlassian grant this is" },
             { claim: "azp", value: "labsOBO Jira broker (3LO app)", expect: null, ok: null, meaning: "The Atlassian app the user consented to" },
             { claim: "aud", value: Array.isArray(c.aud) ? c.aud.join(" ") : c.aud ?? "api.atlassian.com", expect: null, ok: null, meaning: "Atlassian API" },
             { claim: "scp", value: scopes || JIRA.scopes.join(" "), expect: null, ok: null, meaning: "What the user granted" }] };
}

// ---------------------------------------------------------------- the 3LO app's credentials (in Secrets Manager)
let clientCache = null;
export async function oauthClient() {
  if (clientCache && Date.now() - clientCache.at < 300000) return clientCache.v;
  let v;
  try { v = JSON.parse((await sm.send(new GetSecretValueCommand({ SecretId: JIRA.clientSecretName }))).SecretString); }
  catch (e) {
    if (e?.name === "ResourceNotFoundException") throw new Error(`The Atlassian app is not configured yet: run scripts/52-store-jira-client.sh (${JIRA.clientSecretName} is missing)`);
    throw e;
  }
  if (!v?.clientId || !v?.clientSecret) throw new Error(`${JIRA.clientSecretName} must hold {"clientId","clientSecret"}`);
  clientCache = { at: Date.now(), v };
  return v;
}

// ---------------------------------------------------------------- the vault: (tid, oid) -> Atlassian binding
export const vaultName = (tid, oid) => `${JIRA.vaultPrefix}${tid}/${oid}`;
export async function vaultGet(tid, oid) {
  try { return JSON.parse((await sm.send(new GetSecretValueCommand({ SecretId: vaultName(tid, oid) }))).SecretString); }
  catch (e) { if (e?.name === "ResourceNotFoundException") return null; throw e; }
}
export async function vaultPut(tid, oid, record) {
  const SecretString = JSON.stringify(record);
  try { await sm.send(new PutSecretValueCommand({ SecretId: vaultName(tid, oid), SecretString })); return "updated"; }
  catch (e) {
    if (e?.name !== "ResourceNotFoundException") throw e;
    await sm.send(new CreateSecretCommand({ Name: vaultName(tid, oid), SecretString, Description: `labsOBO Jira broker vault: Atlassian binding for ${tid}/${oid}`,
                                            Tags: [{ Key: "lab", Value: "labsOBO" }] }));
    return "created";
  }
}
const vaultHop = (p) => hop({ kind: "sdk", actor: p.from, ...p,
  request: { method: p.method, url: `secretsmanager:${p.method} ${p.secretId}`, headers: {}, body: p.shownBody ?? null, bodyType: p.shownBody ? "json" : "none",
             curl: `aws secretsmanager ${p.method === "GetSecretValue" ? "get-secret-value" : p.method === "CreateSecret" ? "create-secret --name" : "put-secret-value"} --secret-id "${p.secretId}"` } });

// ---------------------------------------------------------------- step 12: the calling app runs the consent
export async function authorizeUrl(state) {
  const { clientId } = await oauthClient();
  const u = new URL("https://auth.atlassian.com/authorize");
  for (const [k, v] of Object.entries({ audience: "api.atlassian.com", client_id: clientId, scope: JIRA.scopes.join(" "), redirect_uri: JIRA.redirectUri,
                                        state, response_type: "code", prompt: "consent" })) u.searchParams.set(k, v);
  return u.toString();
}

/** Steps 12-13 on the callback: exchange the code, find the Jira site, and bind (tid, oid) -> Atlassian account in the vault. */
export async function linkUser({ code, user }) {
  const hops = [];
  const { clientId, clientSecret } = await oauthClient();
  const x = await call({ method: "POST", url: "https://auth.atlassian.com/oauth/token",
    json: { grant_type: "authorization_code", client_id: clientId, client_secret: clientSecret, code, redirect_uri: JIRA.redirectUri },
    shown: { grant_type: "authorization_code", client_id: clientId, client_secret: "${ATLASSIAN_CLIENT_SECRET}", code: "${ATLASSIAN_AUTH_CODE}", redirect_uri: JIRA.redirectUri } });
  const tokens = x.ok ? x.body : null;
  hops.push(hop({ from: "APP", to: "ATLASSIAN", step: "12", kind: "http", actor: "APP", label: "Exchange the code at Atlassian for an access + refresh token",
    title: "POST auth.atlassian.com/oauth/token (authorization_code)", request: x.request, response: { status: x.status, durationMs: x.ms, body: scrubbed(x.body) },
    tokens: tokens?.access_token ? [jiraTokenCard(tokens.access_token, user)] : [], verdict: tokens?.access_token ? "allow" : "deny",
    summary: tokens?.access_token ? `Atlassian issued tokens for scopes: ${tokens.scope}. ${tokens.refresh_token ? "A refresh token came back (offline_access)." : "NO refresh token: offline_access was not granted."}` : `Refused: ${errText(x)}` }));
  if (!tokens?.access_token) return { ok: false, error: errText(x), hops };

  const ar = await call({ url: `${API}/oauth/token/accessible-resources`, token: tokens.access_token });
  const sites = Array.isArray(ar.body) ? ar.body : [];
  const site = sites.find((s) => s.name === JIRA.site || String(s.url).includes(`//${JIRA.site}.atlassian.net`)) ?? sites[0];
  hops.push(hop({ from: "APP", to: "ATLASSIAN", step: "12", kind: "http", actor: "APP", label: `Find the Jira site the grant covers (${site?.url ?? "none"})`,
    title: "GET api.atlassian.com/oauth/token/accessible-resources", request: ar.request, response: { status: ar.status, durationMs: ar.ms, body: ar.body },
    verdict: site ? "info" : "deny", summary: site ? `cloudId ${site.id} = ${site.url}` : "The grant covers no Jira site: is Jira added to the site?" }));
  if (!site) return { ok: false, error: "the Atlassian grant covers no site with Jira", hops };

  const me = await call({ url: `${API}/ex/jira/${site.id}/rest/api/3/myself`, token: tokens.access_token });
  hops.push(hop({ from: "APP", to: "JIRA", step: "12", kind: "http", actor: "APP", label: `Confirm the Atlassian account: ${me.body?.displayName ?? "?"}`,
    title: "GET /rest/api/3/myself", request: me.request, response: { status: me.status, durationMs: me.ms, body: me.ok ? { accountId: me.body.accountId, displayName: me.body.displayName, emailAddress: me.body.emailAddress } : me.body },
    verdict: me.ok ? "info" : "error", summary: me.ok ? `Atlassian account ${me.body.accountId} (${me.body.displayName})` : errText(me) }));

  const binding = { tid: user.tid, oid: user.oid, upn: user.upn, name: user.name, atlassianAccountId: me.body?.accountId ?? null, atlassianName: me.body?.displayName ?? null,
                    cloudId: site.id, siteUrl: site.url, scopes: String(tokens.scope ?? "").split(" "), refreshToken: tokens.refresh_token ?? null,
                    linkedAt: new Date().toISOString(), rotatedAt: null };
  const how = await vaultPut(user.tid, user.oid, binding);
  hops.push(vaultHop({ from: "APP", to: "VAULT", step: "13", method: how === "created" ? "CreateSecret" : "PutSecretValue", secretId: vaultName(user.tid, user.oid),
    shownBody: { ...binding, refreshToken: binding.refreshToken ? "«refresh token»" : null }, label: "Store the binding (tid, oid) → Atlassian account in the vault",
    title: `Vault ${how}: ${vaultName(user.tid, user.oid)}`, response: { status: 200, body: { stored: true, key: `(${user.tid}, ${user.oid})` } }, verdict: "allow",
    summary: `(${user.name}) → Atlassian ${binding.atlassianName ?? binding.atlassianAccountId} on ${site.url}. The refresh token stays in the vault; A1 never sees it.` }));
  return { ok: true, binding: { siteUrl: site.url, cloudId: site.id, atlassianName: binding.atlassianName, scopes: binding.scopes }, hops };
}

// ---------------------------------------------------------------- steps 15-16: the broker
/** Step 15: binding for (tid, oid) -> refresh -> T_JIRA_USER, rotated refresh token written back. */
export async function userToken({ user }) {
  const hops = [];
  const binding = await vaultGet(user.tid, user.oid);
  hops.push(vaultHop({ from: "BROKER", to: "VAULT", step: "15", method: "GetSecretValue", secretId: vaultName(user.tid, user.oid),
    label: binding ? `Find ${user.name}'s Atlassian binding in the vault` : `No Atlassian binding for ${user.name}`, title: `Vault lookup by (tid, oid)`,
    response: { status: binding ? 200 : 404, body: binding ? { atlassianAccount: binding.atlassianName ?? binding.atlassianAccountId, site: binding.siteUrl, scopes: binding.scopes, linkedAt: binding.linkedAt, rotatedAt: binding.rotatedAt } : { found: false } },
    verdict: "info", summary: binding ? `Bound to Atlassian ${binding.atlassianName ?? binding.atlassianAccountId} on ${binding.siteUrl}` : "First use: the user has not linked Atlassian yet → authorization_required (step 12)" }));
  if (!binding?.refreshToken) return { status: "authorization_required", hops };

  const { clientId, clientSecret } = await oauthClient();
  const r = await call({ method: "POST", url: "https://auth.atlassian.com/oauth/token",
    json: { grant_type: "refresh_token", client_id: clientId, client_secret: clientSecret, refresh_token: binding.refreshToken },
    shown: { grant_type: "refresh_token", client_id: clientId, client_secret: "${ATLASSIAN_CLIENT_SECRET}", refresh_token: "${VAULT_REFRESH_TOKEN}" } });
  const ok = r.ok && r.body?.access_token;
  hops.push(hop({ from: "BROKER", to: "ATLASSIAN", step: "15", kind: "http", actor: "BROKER", label: ok ? "Refresh the Atlassian token → T_JIRA_USER" : "Atlassian refused the refresh token",
    title: "POST auth.atlassian.com/oauth/token (refresh_token)", request: r.request, response: { status: r.status, durationMs: r.ms, body: scrubbed(r.body) },
    tokens: ok ? [jiraTokenCard(r.body.access_token, user)] : [], verdict: ok ? "allow" : "deny",
    summary: ok ? "Fresh T_JIRA_USER for this user. Atlassian rotated the refresh token." : `Refused: ${errText(r)}. The user has to consent again.` }));
  if (!ok) return { status: "authorization_required", hops };

  if (r.body.refresh_token && r.body.refresh_token !== binding.refreshToken) {
    await vaultPut(user.tid, user.oid, { ...binding, refreshToken: r.body.refresh_token, rotatedAt: new Date().toISOString() });
    hops.push(vaultHop({ from: "BROKER", to: "VAULT", step: "15", method: "PutSecretValue", secretId: vaultName(user.tid, user.oid), label: "Write the rotated refresh token back to the vault",
      title: "Vault update (rotating refresh token)", response: { status: 200, body: { rotated: true } }, verdict: "info",
      summary: "The old refresh token is now invalid; only the vault holds the new one." }));
  }
  return { status: "ok", accessToken: r.body.access_token, binding, hops };
}

/** Atlassian Document Format from plain lines: "- " bullets, ``` code fences, everything else a paragraph. */
function adf(lines) {
  const content = []; let bullets = null, code = null;
  for (const line of lines) {
    if (code) {
      if (line.startsWith("```")) { content.push({ type: "codeBlock", attrs: { language: "kusto" }, content: [{ type: "text", text: code.join("\n") || " " }] }); code = null; }
      else code.push(line);
      continue;
    }
    if (line.startsWith("```")) { bullets = null; code = []; continue; }
    if (line.startsWith("- ")) {
      if (!bullets) { bullets = { type: "bulletList", content: [] }; content.push(bullets); }
      bullets.content.push({ type: "listItem", content: [{ type: "paragraph", content: [{ type: "text", text: line.slice(2) || " " }] }] });
      continue;
    }
    bullets = null;
    if (line.trim()) content.push({ type: "paragraph", content: [{ type: "text", text: line }] });
  }
  return { type: "doc", version: 1, content };
}

/** Step 16: create the issue with T_JIRA_USER, then record the provenance on it as an issue property. */
export async function createIssue({ accessToken, binding, issue, provenance }) {
  const hops = [];
  const base = `${API}/ex/jira/${binding.cloudId}/rest/api/3`;
  const meta = await call({ url: `${base}/issue/createmeta/${JIRA.project}/issuetypes`, token: accessToken });
  const types = meta.body?.issueTypes ?? meta.body?.values ?? [];
  const type = types.find((t) => /^task$/i.test(t.name)) ?? types.find((t) => !t.subtask);
  hops.push(hop({ from: "BROKER", to: "JIRA", step: "16", kind: "http", actor: "BROKER", label: `Look up issue types in ${JIRA.project}`,
    title: `GET /issue/createmeta/${JIRA.project}/issuetypes`, request: meta.request, response: { status: meta.status, durationMs: meta.ms, body: meta.ok ? { issueTypes: types.map((t) => t.name) } : meta.body },
    verdict: type ? "info" : "deny", summary: type ? `Using "${type.name}"` : `No usable issue type in project ${JIRA.project}: ${errText(meta)}` }));
  if (!type) return { ok: false, error: meta.ok ? `project ${JIRA.project} has no issue types` : `Jira: ${errText(meta)}`, hops };

  const who = `${provenance.requestedBy.name} (${provenance.requestedBy.upn})`;
  const lines = [...issue.description, "", "Provenance:", `- Requested by: ${who}, oid ${provenance.requestedBy.oid}`,
                 `- Executed by: ${provenance.executedBy.name} (agent identity ${provenance.executedBy.clientId})`, `- Via: ${provenance.via}`,
                 `- Source: ${provenance.source}`, `- labsOBO run: ${provenance.runId}`];
  const fields = { project: { key: JIRA.project }, issuetype: { id: type.id }, summary: issue.summary.slice(0, 250), labels: issue.labels, description: adf(lines) };
  const c = await call({ method: "POST", url: `${base}/issue`, token: accessToken, json: { fields } });
  hops.push(hop({ from: "BROKER", to: "JIRA", step: "16", kind: "http", actor: "BROKER", label: c.ok ? `Create ${c.body.key} as ${provenance.requestedBy.name}` : "Jira refused the issue",
    title: "POST /ex/jira/{cloudId}/rest/api/3/issue", request: c.request, response: { status: c.status, durationMs: c.ms, body: c.body }, verdict: c.ok ? "allow" : "deny",
    summary: c.ok ? `${c.body.key} created. Jira records the reporter from T_JIRA_USER: ${binding.atlassianName ?? "the user"}.` : errText(c) }));
  if (!c.ok) return { ok: false, error: `Jira: ${errText(c)}`, hops };

  const p = await call({ method: "PUT", url: `${base}/issue/${c.body.key}/properties/labsobo.provenance`, token: accessToken, json: provenance });
  hops.push(hop({ from: "BROKER", to: "JIRA", step: "16", kind: "http", actor: "BROKER", label: "Attach the provenance (user, agent, source) to the issue",
    title: `PUT /issue/${c.body.key}/properties/labsobo.provenance`, request: p.request, response: { status: p.status, durationMs: p.ms, body: p.body || null },
    verdict: p.ok ? "info" : "error", summary: p.ok ? "Initiating user, executing agent and source kept on the issue as a property." : errText(p) }));
  return { ok: true, issue: { key: c.body.key, id: c.body.id, url: `${binding.siteUrl}/browse/${c.body.key}`, summary: fields.summary, project: JIRA.project, type: type.name,
                              reporter: binding.atlassianName ?? provenance.requestedBy.name, createdAt: new Date().toISOString(), provenance }, hops };
}
