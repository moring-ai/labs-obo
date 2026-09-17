/**
 * labsOBO | the calling application (APP), http://localhost:3100
 *
 * One process, three jobs:
 *   1. OAuth client for the user leg (authorization code + PKCE; confidential
 *      client with a certificate for APP, public client for DIRECT).
 *   2. Hop recorder: every request it makes (to Entra, Graph, A1, AgentCore, the
 *      az CLI) is stored with method/URL/headers/body, an equivalent curl, the
 *      response, and any token decoded + checked. That record is the lab evidence.
 *   3. Admin operations for Phases 13/14 (remove/add assignments) through Graph,
 *      using the operator's signed-in Azure CLI session for the admin token.
 */
import { createServer } from "node:http";
import { readFileSync, writeFileSync, mkdirSync, existsSync, readdirSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { randomUUID } from "node:crypto";
import { cfg, ROOT, LABELS, label, decode, verify, summarizeToken, tokenRequest, doHttp, clientAssertion, ASSERTION_TYPE,
         pkce, randomState, redactDeep, azAccessToken } from "../../lib/entra.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT ?? cfg.ports.app);
const A1_LOCAL = process.env.A1_LOCAL_URL ?? `http://localhost:${cfg.ports.agent}`;
import { state as labState } from "../../lib/entra.mjs";
/** CONTROL: an ordinary API registration with the same assignment-required setup, to compare Entra's behaviour with the agent blueprint. */
const CONTROL = labState.controlApi ? { clientId: labState.controlApi.clientId, principalId: labState.controlApi.principalId, scope: "labsOBO_control_access",
  fullScope: `api://${labState.controlApi.clientId}/labsOBO_control_access`, roleValue: "labsOBO.ControlInvoker", roleId: labState.controlApi.roleId, name: "labsOBO-control-api (ordinary API)" } : null;
if (CONTROL) { LABELS[CONTROL.clientId] = "CONTROL (labsOBO-control-api, ordinary API)"; LABELS[CONTROL.principalId] = "CONTROL service principal"; }
const resourceOf = (key) => key === "control" && CONTROL ? CONTROL : cfg.bp;
const TRACE_DIR = resolve(ROOT, ".lab/traces");
const TOKEN_DIR = resolve(ROOT, ".lab/tokens");
mkdirSync(TRACE_DIR, { recursive: true }); mkdirSync(TOKEN_DIR, { recursive: true });

// ---------------------------------------------------------------- runs (traces)
const runs = new Map();
for (const f of existsSync(TRACE_DIR) ? readdirSync(TRACE_DIR).filter((x) => x.endsWith(".json")).sort() : []) {
  try { const r = JSON.parse(readFileSync(resolve(TRACE_DIR, f), "utf8")); runs.set(r.id, r); } catch { /* skip */ }
}
let seq = Math.max(0, ...[...runs.values()].map((r) => r.seq ?? 0));
const persist = (run) => writeFileSync(resolve(TRACE_DIR, `${run.id}.json`), JSON.stringify(run, null, 2));

function newRun({ kind, title, user = null, client = null, scopeMode = null }) {
  seq += 1;
  const id = `${String(seq).padStart(3, "0")}-${randomUUID().slice(0, 8)}`;
  const run = { id, seq, kind, title, user, client, scopeMode, startedAt: new Date().toISOString(), status: "running",
                directoryAtStart: directory.snapshot(), hops: [], evidence: [] };
  runs.set(id, run); persist(run); return run;
}
function addHop(run, h) {
  const hop = { id: randomUUID(), ts: new Date().toISOString(), n: run.hops.length + 1, actor: "APP", ...h };
  run.hops.push(hop); persist(run); return hop;
}
function spliceHops(run, hops) { for (const h of hops) addHop(run, { ...h, spliced: true }); }
function evidence(run, test, result, detail) { run.evidence.push({ test, result, detail, ts: new Date().toISOString() }); persist(run); }
function finish(run, status = "done") { run.status = status; run.endedAt = new Date().toISOString(); persist(run); }

// ---------------------------------------------------------------- sessions (server side; browser holds an opaque id)
const SESSION_FILE = resolve(ROOT, ".lab/sessions.json");
const sessions = new Map(existsSync(SESSION_FILE) ? Object.entries(JSON.parse(readFileSync(SESSION_FILE, "utf8"))) : []);
const saveSessions = () => writeFileSync(SESSION_FILE, JSON.stringify(Object.fromEntries(sessions), null, 2));
const pending = new Map();
const cookieOf = (req) => Object.fromEntries((req.headers.cookie ?? "").split(";").map((c) => c.trim().split("=")).filter((p) => p[0]));
const sessionOf = (req) => sessions.get(cookieOf(req).labsobo_sid);
const userKeyFor = (oid) => oid === cfg.users.alex.objectId ? "alex" : oid === cfg.users.sam.objectId ? "sam" : "other";
const clientOf = (key) => key === "direct" ? cfg.direct : key === "azcli" ? { name: "Azure CLI", clientId: cfg.azureCliAppId } : cfg.app;

// ---------------------------------------------------------------- directory (Graph via the operator's az session)
const directory = {
  state: { checkedAt: null, assignmentRequired: null, alex: null, sam: null, alexAssignmentId: null, samAssignmentId: null, error: null },
  snapshot() { const s = this.state; return { checkedAt: s.checkedAt, assignmentRequired: s.assignmentRequired, alexAssigned: s.alex, samAssigned: s.sam }; },
};

async function adminToken(run) {
  const t = await azAccessToken(["--resource-type", "ms-graph"]);
  if (run) addHop(run, {
    actor: "ADMIN", from: "APP", to: "AZ-CLI", kind: "local", phase: "admin",
    title: "Borrow a Microsoft Graph token from the operator's Azure CLI session (tenant admin)",
    request: { method: "exec", url: t.command, headers: {}, body: null, bodyType: "none", curl: t.command },
    response: { status: 200, durationMs: t.durationMs, body: { expiresOn: t.expiresOn, accessToken: t.token } },
    verdict: "info", summary: `Graph admin token obtained from az (expires ${t.expiresOn}). Used only for directory reads/writes below; never sent to A1.`,
  });
  return t.token;
}
async function graph(run, { method = "GET", path, json, title, phase = "Phase 6", expectStatus = 200, note }, token) {
  const r = await doHttp({ method, url: `https://graph.microsoft.com/${path}`, headers: { Authorization: `Bearer ${token}`, ...(json ? {} : { Accept: "application/json" }) }, json,
                           secretNames: { bearer: "LABSOBO_GRAPH_ADMIN_TOKEN" } });
  const ok = r.response.status === expectStatus || (expectStatus === 200 && r.ok);
  if (run) addHop(run, { actor: "ADMIN", from: "APP", to: "GRAPH", kind: "http", phase, title, request: r.request, response: r.response,
                         verdict: ok ? "info" : "error", summary: ok ? `HTTP ${r.response.status}` : `HTTP ${r.response.status}: ${JSON.stringify(r.response.body).slice(0, 200)}`, note });
  return r;
}
async function refreshDirectory(run) {
  try {
    const tok = await adminToken(run);
    const sp = await graph(run, { path: `v1.0/servicePrincipals/${cfg.bp.principalId}?$select=id,appId,displayName,appRoleAssignmentRequired`,
      title: "Phase 4 check — is assignment required on the BP-A1 principal?" }, tok);
    const alex = await graph(run, { path: `v1.0/users/${cfg.users.alex.objectId}/appRoleAssignments?$filter=resourceId eq ${cfg.bp.principalId}`,
      title: `Phase 6 — Alex's app-role assignments on BP-A1 (${cfg.users.alex.displayName})` }, tok);
    const sam = await graph(run, { path: `v1.0/users/${cfg.users.sam.objectId}/appRoleAssignments?$filter=resourceId eq ${cfg.bp.principalId}`,
      title: `Phase 6 — Sam's app-role assignments on BP-A1 (${cfg.users.sam.displayName})` }, tok);
    const pick = (r) => (r.response.body?.value ?? []).find((a) => a.appRoleId === cfg.bp.roleId);
    const a = pick(alex), s = pick(sam);
    directory.state = { checkedAt: new Date().toISOString(), assignmentRequired: sp.response.body?.appRoleAssignmentRequired ?? null,
                        alex: !!a, sam: !!s, alexAssignmentId: a?.id ?? null, samAssignmentId: s?.id ?? null, error: null };
    if (run) addHop(run, { actor: "ADMIN", from: "APP", to: "APP", kind: "note", phase: "Phase 6", title: "Directory state",
      request: null, response: { status: 200, body: directory.state }, verdict: "info",
      summary: `assignmentRequired=${directory.state.assignmentRequired} · Alex → ${cfg.bp.roleValue} → BP-A1: ${a ? "ASSIGNED" : "NOT assigned"} · Sam: ${s ? "ASSIGNED" : "NOT assigned"}` });
  } catch (e) {
    directory.state.error = String(e?.message ?? e);
    if (run) addHop(run, { actor: "ADMIN", from: "APP", to: "AZ-CLI", kind: "note", title: "Directory refresh failed", request: null, response: { status: 0, body: directory.state.error }, verdict: "error", summary: directory.state.error });
  }
  return directory.state;
}

// ---------------------------------------------------------------- the user leg
function loginRedirect(req, res, q) {
  const userKey = q.get("as") ?? "alex";
  const clientKey = q.get("client") ?? "app";
  const scopeMode = q.get("scopeMode") ?? "twostep";        // twostep | single
  const prompt = q.get("prompt") ?? "select_account";
  const user = cfg.users[userKey]; const client = clientOf(clientKey);
  const resourceKey = q.get("resource") === "control" && CONTROL ? "control" : "bp"; const R = resourceOf(resourceKey);
  const run = newRun({ kind: "signin", title: `Sign in as ${userKey.toUpperCase()} via ${clientKey === "direct" ? "DIRECT client" : "APP"} (${scopeMode === "single" ? "agent scope in /authorize" : "OIDC first, agent token second"})${resourceKey === "control" ? " — CONTROL resource (ordinary API)" : ""}`, user: userKey, client: clientKey, scopeMode });
  run.resource = resourceKey;
  const p = pkce(); const state = randomState(); const nonce = randomUUID();
  const scopes = ["openid", "profile", "offline_access", ...(scopeMode === "single" ? [R.fullScope] : ["User.Read"])];
  const u = new URL(cfg.authorizeEndpoint);
  for (const [k, v] of Object.entries({ client_id: client.clientId, response_type: "code", redirect_uri: client.redirectUri, response_mode: "query",
      scope: scopes.join(" "), state, nonce, code_challenge: p.challenge, code_challenge_method: "S256", login_hint: user.upn, prompt })) u.searchParams.set(k, v);
  pending.set(state, { runId: run.id, verifier: p.verifier, nonce, userKey, clientKey, scopeMode, resourceKey, createdAt: Date.now() });
  addHop(run, { from: "APP", to: "BROWSER", kind: "redirect", phase: "Phase 8",
    title: `302 → Entra /authorize as ${client.name} (login_hint=${user.upn})`,
    request: { method: "GET", url: u.toString(), headers: {}, body: Object.fromEntries(u.searchParams), bodyType: "query",
               curl: `# the BROWSER navigates here; shown as curl -G for the parameter list\n` + [`curl -G "${cfg.authorizeEndpoint}"`, ...[...u.searchParams].map(([k, v]) => `  --data-urlencode "${k}=${v}"`)].join(" \\\n") },
    response: { status: 302, body: { Location: u.toString() } }, verdict: "info",
    summary: `Entra now authenticates ${user.displayName}. ${scopeMode === "single" ? "The agent scope is requested here, so the code redemption returns the BP-A1 token directly. Watch whether Entra stops an unassigned user on its page (AADSTS50105) or issues a token without the roles claim." : "Only OIDC scopes are requested here, so any tenant user can sign in; the BP-A1 token is requested in a separate, fully recorded hop."}` });
  res.writeHead(302, { Location: u.toString(), "Set-Cookie": `labsobo_run=${run.id}; Path=/; HttpOnly` }); res.end();
}

async function callback(req, res, url, clientKey) {
  const q = url.searchParams; const state = q.get("state");
  const pend = pending.get(state); pending.delete(state);
  if (!pend) { res.writeHead(400, { "Content-Type": "text/plain" }); return res.end("Unknown or expired state; start again from http://localhost:3100"); }
  const run = runs.get(pend.runId); const user = cfg.users[pend.userKey]; const client = clientOf(pend.clientKey);
  const cbHop = addHop(run, { actor: "BROWSER", from: "BROWSER", to: "APP", kind: "callback", phase: "Phase 9",
    title: q.get("error") ? `Callback carried an ERROR: ${q.get("error")}` : "Callback with an authorization code",
    request: { method: "GET", url: url.toString(), headers: { host: req.headers.host, "user-agent": req.headers["user-agent"] }, body: Object.fromEntries(q), bodyType: "query",
               curl: `# what the browser requested\ncurl "${client.redirectUri}?code=\${LABSOBO_AUTH_CODE}&state=${state}"` },
    response: { status: 302, body: { Location: `/?run=${run.id}` } }, verdict: q.get("error") ? "deny" : "info",
    summary: q.get("error") ? `${q.get("error")}: ${q.get("error_description")}` : `Entra sent a one-time code for state ${state}; the app now redeems it server-side.` });
  if (q.get("error")) { if (pend.resourceKey === "control") evidence(run, "CTRL", "denied", `${q.get("error")}: ${q.get("error_description")}`); else if (q.get("error") === "consent_required" || q.get("error") === "access_denied") evidence(run, "CONSENT", `${q.get("error")} (${(q.get("error_description") ?? "").match(/AADSTS\d+/)?.[0] ?? ""})`, (q.get("error_description") ?? "").split(" Trace ID")[0]); else evidenceForTokenOutcome(run, pend, { denied: true, code: (q.get("error_description") ?? "").match(/AADSTS\d+/)?.[0] ?? q.get("error"), flow: "authorize redirect error" }); finish(run, "denied"); return redirectHome(res, run); }

  // Redeem the code. APP proves itself with a certificate assertion; DIRECT has no credential (PKCE only).
  const R = resourceOf(pend.resourceKey);
  const form = { grant_type: "authorization_code", client_id: client.clientId, code: q.get("code"), redirect_uri: client.redirectUri, code_verifier: pend.verifier,
                 scope: ["openid", "profile", "offline_access", ...(pend.scopeMode === "single" ? [R.fullScope] : ["User.Read"])].join(" ") };
  let assertionInfo = null;
  if (pend.clientKey === "app") { const a = await clientAssertion({ clientId: cfg.app.clientId, keyPath: cfg.app.keyPath, certPath: cfg.app.certPath });
    form.client_assertion_type = ASSERTION_TYPE; form.client_assertion = a.assertion; assertionInfo = a.info; }
  const t = await tokenRequest(form, { secretNames: { client_assertion: "LABSOBO_CALLING_APP_ASSERTION", code: `LABSOBO_${pend.userKey.toUpperCase()}_AUTH_CODE` } });
  const idc = t.tokens?.id_token ? decode(t.tokens.id_token)?.claims : null;
  const nonceOk = idc ? idc.nonce === pend.nonce : null;
  const tokens = [];
  if (t.tokens?.id_token) tokens.push(summarizeToken("id_token", t.tokens.id_token, { oid: user.objectId, aud: client.clientId }, { kind: "id" }));
  if (t.tokens?.access_token) {
    const ac = decode(t.tokens.access_token)?.claims ?? {};
    const isBp = ac.aud === R.clientId;
    tokens.push(summarizeToken(isBp ? (pend.resourceKey === "control" ? "T_APP_CONTROL" : "LABSOBO_T_APP_A1") : "access_token (Microsoft Graph)", t.tokens.access_token,
      isBp ? { oid: user.objectId, azp: client.clientId, aud: R.clientId, scp: R.scope, role: R.roleValue } : { oid: user.objectId, azp: client.clientId, aud: cfg.graphAppId }, { kind: "access" }));
  }
  addHop(run, { from: "APP", to: "ENTRA", kind: "http", phase: "Phase 9",
    title: `Redeem the code at /token (${pend.clientKey === "app" ? "client_assertion = certificate JWT" : "public client, PKCE only"})`,
    request: t.request, response: t.response, tokens, verdict: t.ok ? "allow" : "deny",
    summary: t.ok ? `Entra issued an id_token for ${idc?.name} <${idc?.preferred_username}> (oid ${idc?.oid}${label(idc?.oid) ? " = " + label(idc?.oid) : ""})${nonceOk === false ? " — NONCE MISMATCH" : ""}, plus an access token for ${label(tokens[1]?.claims?.aud) ?? tokens[1]?.claims?.aud}${pend.resourceKey === "control" && tokens[1]?.claims?.aud === R.clientId ? ` — roles=${JSON.stringify(tokens[1]?.claims?.roles ?? null)} (Balaji is NOT assigned on the control API)` : ""}.`
                  : `Token request refused: ${t.error?.code ?? ""} ${t.error?.description ?? ""}`,
    note: assertionInfo ? `client assertion: ${assertionInfo.alg} x5t=${assertionInfo.x5t} iss=sub=APP aud=${assertionInfo.aud} jti=${assertionInfo.jti}` : "no client credential: labsOBO-direct-client is a public client" });
  if (!t.ok) { if (pend.resourceKey === "control") evidence(run, "CTRL", "denied", `${t.error?.code}: ${t.error?.description}`); else evidenceForTokenOutcome(run, pend, { denied: true, code: t.error?.code, flow: "authorization_code" }); finish(run, "denied"); return redirectHome(res, run); }

  const sid = randomUUID();
  const sess = { id: sid, userKey: userKeyFor(idc?.oid), clientKey: pend.clientKey, user: { oid: idc?.oid, name: idc?.name, upn: idc?.preferred_username },
                 refreshToken: t.tokens.refresh_token ?? null, graphToken: null, bpToken: null, bpTokenClaims: null, createdAt: new Date().toISOString(), runId: run.id };
  const ac = decode(t.tokens.access_token)?.claims ?? {};
  if (ac.aud === cfg.bp.clientId) { sess.bpToken = t.tokens.access_token; sess.bpTokenClaims = ac; saveToken(sess.userKey, pend.clientKey, t.tokens.access_token); }
  else if (CONTROL && ac.aud === CONTROL.clientId) { evidence(run, "CTRL", (ac.roles ?? []).includes(CONTROL.roleValue) ? "issued-with-role" : "issued-without-role", `ordinary API, assignmentRequired=true, user NOT assigned: token issued, roles=${JSON.stringify(ac.roles ?? null)} via authorization_code`); }
  else sess.graphToken = t.tokens.access_token;
  sessions.set(sid, sess); saveSessions();
  run.session = { user: sess.user, userKey: sess.userKey, clientKey: sess.clientKey };

  if (!sess.graphToken && sess.refreshToken) {
    const g = await tokenRequest({ grant_type: "refresh_token", client_id: client.clientId, refresh_token: sess.refreshToken, scope: "User.Read",
      ...(pend.clientKey === "app" ? { client_assertion_type: ASSERTION_TYPE, client_assertion: (await clientAssertion({ clientId: cfg.app.clientId, keyPath: cfg.app.keyPath, certPath: cfg.app.certPath })).assertion } : {}) },
      { secretNames: { client_assertion: "LABSOBO_CALLING_APP_ASSERTION", refresh_token: `LABSOBO_${pend.userKey.toUpperCase()}_REFRESH_TOKEN` } });
    addHop(run, { from: "APP", to: "ENTRA", kind: "http", phase: "TEST 1", title: "Get a Microsoft Graph token for the user (refresh_token → User.Read) to ask Graph who they are",
      request: g.request, response: g.response, tokens: g.tokens ? [summarizeToken("access_token (Microsoft Graph)", g.tokens.access_token, { oid: user.objectId, azp: client.clientId, aud: cfg.graphAppId }, { kind: "access" })] : [],
      verdict: g.ok ? "info" : "error", summary: g.ok ? "A second, separate token for a different resource (Graph); v2 issues one resource per request." : `refused: ${g.error?.code ?? ""} ${g.error?.description ?? ""}` });
    if (g.ok) { sess.graphToken = g.tokens.access_token; if (g.tokens.refresh_token) sess.refreshToken = g.tokens.refresh_token; }
  }
  // TEST 1 — who is the user? Ask a resource, not just the id_token.
  if (sess.graphToken) {
    const me = await doHttp({ method: "GET", url: "https://graph.microsoft.com/v1.0/me?$select=id,displayName,userPrincipalName", headers: { Authorization: `Bearer ${sess.graphToken}` }, secretNames: { bearer: "LABSOBO_GRAPH_USER_TOKEN" } });
    addHop(run, { from: "APP", to: "GRAPH", kind: "http", phase: "TEST 1", title: "TEST 1 — who is the user? GET /me with the user's Graph token",
      request: me.request, response: me.response, verdict: me.ok ? "info" : "error",
      summary: me.ok ? `Microsoft Graph says the signed-in user is ${me.response.body?.displayName} <${me.response.body?.userPrincipalName}> — oid ${me.response.body?.id} = ${label(me.response.body?.id) ?? "not Alex or Sam"}.` : `Graph /me failed HTTP ${me.response.status}` });
  }
  if (ac.aud === cfg.bp.clientId) {
    evidenceForTokenOutcome(run, pend, { denied: false, claims: ac, flow: "authorization_code (resource scope at /authorize)" });
  } else if (pend.resourceKey !== "control") {
    await requestBpToken(run, sess, "Phase 9 (step 2)");
  }
  finish(run, run.hops.some((h) => h.verdict === "deny") ? "denied" : "done"); saveSessions();
  res.writeHead(302, { Location: `/?run=${run.id}`, "Set-Cookie": `labsobo_sid=${sid}; Path=/; HttpOnly` }); res.end();
}
const redirectHome = (res, run) => { res.writeHead(302, { Location: `/?run=${run.id}` }); res.end(); };
function saveToken(userKey, clientKey, token) { writeFileSync(resolve(TOKEN_DIR, `T_APP_A1.${userKey}.${clientKey}.json`), JSON.stringify({ savedAt: new Date().toISOString(), access_token: token, claims: decode(token)?.claims }, null, 2)); }

/** TEST 2/3: ask Entra for a BP-A1 token for the signed-in user (refresh_token grant; assignment is enforced at issuance). */
async function requestBpToken(run, sess, phase = "Phase 13/14") {
  const client = clientOf(sess.clientKey); const user = cfg.users[sess.userKey] ?? { objectId: sess.user.oid };
  const form = { grant_type: "refresh_token", client_id: client.clientId, refresh_token: sess.refreshToken, scope: cfg.bp.fullScope };
  if (sess.clientKey === "app") { const a = await clientAssertion({ clientId: cfg.app.clientId, keyPath: cfg.app.keyPath, certPath: cfg.app.certPath }); form.client_assertion_type = ASSERTION_TYPE; form.client_assertion = a.assertion; }
  const t = await tokenRequest(form, { secretNames: { client_assertion: "LABSOBO_CALLING_APP_ASSERTION", refresh_token: `LABSOBO_${sess.userKey.toUpperCase()}_REFRESH_TOKEN` } });
  const ac = t.tokens ? decode(t.tokens.access_token)?.claims : null;
  const assigned = directory.state[sess.userKey];
  addHop(run, { from: "APP", to: "ENTRA", kind: "http", phase,
    title: `Request a BP-A1 token for ${sess.user.name}: scope=${cfg.bp.fullScope}`,
    request: t.request, response: t.response,
    tokens: t.tokens ? [summarizeToken("LABSOBO_T_APP_A1", t.tokens.access_token, { oid: user.objectId, azp: client.clientId, aud: cfg.bp.clientId, scp: cfg.bp.scope, role: cfg.bp.roleValue }, { kind: "access" })] : [],
    verdict: t.ok ? "allow" : "deny",
    summary: t.ok ? `Entra ISSUED a token for BP-A1: oid=${label(ac.oid) ?? ac.oid}, azp=${label(ac.azp) ?? ac.azp}, aud=${label(ac.aud) ?? ac.aud}, scp=${ac.scp}, roles=${JSON.stringify(ac.roles ?? null)}.`
                  : `Entra REFUSED: ${t.error?.code ?? t.error?.error}: ${t.error?.description}`,
    note: `Directory at request time: assignmentRequired=${directory.state.assignmentRequired}, ${sess.userKey} assigned=${assigned}` });
  if (t.ok) { sess.bpToken = t.tokens.access_token; sess.bpTokenClaims = ac; if (t.tokens.refresh_token) sess.refreshToken = t.tokens.refresh_token; saveToken(sess.userKey, sess.clientKey, t.tokens.access_token); saveSessions(); }
  evidenceForTokenOutcome(run, { userKey: sess.userKey, clientKey: sess.clientKey }, { denied: !t.ok, code: t.error?.code, claims: ac, flow: "refresh_token" });
  return t;
}

/** Map a token outcome onto the lab's test matrix, using the directory state at the time. */
function evidenceForTokenOutcome(run, { userKey, clientKey }, { denied, code, claims, flow }) {
  const assigned = directory.state[userKey];
  const hasRole = !!claims?.roles?.includes(cfg.bp.roleValue);
  const expectIssued = assigned === true;
  const outcomeOk = denied ? (!expectIssued && code === "AADSTS50105") : (expectIssued && hasRole);
  const detail = (denied ? `${code ?? "denied"} (assigned=${assigned})` : `issued; roles=${JSON.stringify(claims?.roles ?? null)} azp=${label(claims?.azp) ?? claims?.azp} (assigned=${assigned})`) + (flow ? ` via ${flow}` : "");
  // "issued-without-role": Entra issued the token but the roles claim is absent — the runtime's roles check is what denies. Measured, not a bug in the lab.
  const result = outcomeOk ? "pass" : (!denied && !assigned && !hasRole) ? "issued-without-role" : "unexpected";
  if (userKey === "alex" && clientKey === "app" && assigned) evidence(run, "T01", result, detail);
  if (userKey === "sam" && clientKey === "app" && !assigned) evidence(run, "T02", result, detail);
  if (userKey === "alex" && !assigned) evidence(run, "T03", result, detail);
  if (userKey === "sam" && assigned) evidence(run, "T04", result, detail);
  if (userKey === "alex" && clientKey !== "app" && assigned) evidence(run, "T07", result, detail);
}

// ---------------------------------------------------------------- invoking A1
async function invokeA1(run, sess, { target = "local", mode = "echo", tokenKind = "bp" }) {
  const token = tokenKind === "graph" ? sess.graphToken : sess.bpToken;
  const tokenName = tokenKind === "graph" ? "Graph access token (WRONG audience on purpose)" : "LABSOBO_T_APP_A1";
  if (!token) { addHop(run, { from: "APP", to: "APP", kind: "note", title: `No ${tokenName} in this session`, request: null, response: { status: 0, body: null }, verdict: "error", summary: "Sign in and obtain a BP-A1 token first." }); return; }
  const payload = { lab: "labsOBO", message: "run labsOBO Agent A1", mode, trace_id: run.id };
  let r, url, toLabel, headers;
  if (target === "agentcore") {
    const arn = existsSync(resolve(ROOT, ".lab/a1_runtime_arn.txt")) ? readFileSync(resolve(ROOT, ".lab/a1_runtime_arn.txt"), "utf8").trim() : null;
    if (!arn) { addHop(run, { from: "APP", to: "AGENTCORE", kind: "note", title: "No AgentCore runtime configured", request: null, response: { status: 0, body: null }, verdict: "error", summary: "Run scripts/40-create-runtime.sh first." }); return; }
    url = `https://bedrock-agentcore.${cfg.aws.region}.amazonaws.com/runtimes/${encodeURIComponent(arn)}/invocations?qualifier=DEFAULT`;
    headers = { Accept: "application/json", "X-Amzn-Bedrock-AgentCore-Runtime-Session-Id": `labsOBO-${randomUUID()}-${randomUUID().slice(0, 8)}`, Authorization: `Bearer ${token}` };
    toLabel = "AGENTCORE";
  } else {
    url = `${A1_LOCAL}/invocations`; headers = { Authorization: `Bearer ${token}` }; toLabel = "A1";
  }
  r = await doHttp({ method: "POST", url, headers, json: payload, secretNames: { bearer: tokenKind === "graph" ? "LABSOBO_GRAPH_USER_TOKEN" : "LABSOBO_T_APP_A1" }, timeoutMs: 90000 });
  const claims = decode(token)?.claims ?? {};
  const bodyObj = r.response.body && typeof r.response.body === "object" ? r.response.body : {};
  const reason = bodyObj.reason ?? bodyObj.message ?? bodyObj.Message ?? (typeof r.response.body === "string" ? r.response.body.slice(0, 200) : null);
  addHop(run, { from: "APP", to: toLabel, kind: "http", phase: "Phase 12",
    title: `Invoke A1 on ${target === "agentcore" ? "Bedrock AgentCore" : "the local runtime"} with ${tokenName}${mode === "obo" ? " (mode=obo → Phase 16)" : ""}`,
    request: r.request, response: { ...r.response, body: target === "local" ? { ...bodyObj, hops: undefined } : r.response.body },
    tokens: [summarizeToken(tokenName, token, { oid: cfg.users[sess.userKey]?.objectId ?? sess.user.oid, azp: cfg.app.clientId, aud: cfg.bp.clientId, scp: cfg.bp.scope, role: cfg.bp.roleValue }, { kind: "access" })],
    verdict: r.ok ? "allow" : "deny",
    summary: r.ok ? `HTTP ${r.response.status} — ${target === "agentcore" ? "AgentCore's JWT authorizer admitted the token (aud + azp + roles) and the container ran" : "A1 admitted the token"}.`
                  : `HTTP ${r.response.status} — ${target === "agentcore" ? "AgentCore rejected the token before any container ran" : "A1 rejected the token"}: ${reason ?? ""}` });
  if (target === "local" && Array.isArray(bodyObj.hops)) spliceHops(run, bodyObj.hops);
  // Evidence
  const wrongAud = claims.aud !== cfg.bp.clientId;
  const wrongAzp = claims.azp !== cfg.app.clientId;
  if (wrongAud) evidence(run, "T06", r.response.status === 401 || r.response.status === 403 ? "pass" : "unexpected", `aud=${label(claims.aud) ?? claims.aud} → HTTP ${r.response.status} (${target})`);
  else if (wrongAzp) evidence(run, "T05", (r.response.status === 401 || r.response.status === 403) ? "pass" : (r.ok ? "allowed-by-policy" : "unexpected"), `azp=${label(claims.azp) ?? claims.azp} → HTTP ${r.response.status} (${target})`);
  else if (!(claims.roles ?? []).includes(cfg.bp.roleValue)) evidence(run, "T09", (r.response.status === 401 || r.response.status === 403) ? "pass" : "unexpected", `${label(claims.oid) ?? claims.oid} token WITHOUT ${cfg.bp.roleValue} → HTTP ${r.response.status} (${target})`);
  else evidence(run, "T12", r.ok ? "pass" : "unexpected", `Alex token → HTTP ${r.response.status} (${target})`);
  if (mode === "obo" && target === "local") evidence(run, "T08", bodyObj.obo?.ok ? "pass" : "fail", bodyObj.obo?.ok ? `OBO token oid=${label(bodyObj.obo.subject) ?? bodyObj.obo.subject}, azp=AGENT-A1; Graph /me answered for ${bodyObj.obo.downstream?.displayName}` : `${bodyObj.obo?.stage}: ${bodyObj.obo?.error?.code ?? bodyObj.obo?.error?.description ?? "not run"}`);
  finish(run);
}

// ---------------------------------------------------------------- Azure CLI import (the operator's own token, no browser)
async function importAzCli(run, scopeForm) {
  // Four spellings of the same resource. The Azure CLI caches access tokens by the literal
  // scope string, so alternating spellings forces a genuinely fresh issuance from Entra.
  const scope = { named: cfg.bp.fullScope, default: `${cfg.bp.uri}/.default`,
                  "guid-named": `${cfg.bp.clientId}/${cfg.bp.scope}`, "guid-default": `${cfg.bp.clientId}/.default` }[scopeForm] ?? cfg.bp.fullScope;
  let t, err;
  try { t = await azAccessToken(["--scope", scope]); } catch (e) { err = String(e?.stderr ?? e?.message ?? e); }
  const claims = t ? decode(t.token)?.claims : null;
  const code = err?.match(/AADSTS\d+/)?.[0];
  // Entra backdates iat/nbf by 5 minutes for clock skew, so issue time ~= iat + 300s.
  const ageSeconds = claims ? Math.round(Date.now() / 1000 - (claims.iat + 300)) : null;
  const cached = claims ? ageSeconds > 90 : false;
  addHop(run, { actor: "AZ-CLI", from: "AZ-CLI", to: "ENTRA", kind: "local", phase: "pre-flight",
    title: `Azure CLI requests a BP-A1 token for the signed-in operator (scope=${scope})`,
    request: { method: "exec", url: `az account get-access-token --scope "${scope}"`, headers: {}, body: null, bodyType: "none", curl: `az account get-access-token --scope "${scope}" -o json` },
    response: t ? { status: 200, durationMs: t.durationMs, body: { expiresOn: t.expiresOn, accessToken: t.token } } : { status: 400, body: err },
    tokens: t ? [summarizeToken("LABSOBO_T_APP_A1 (via Azure CLI)", t.token, { oid: cfg.users.alex.objectId, azp: cfg.azureCliAppId, aud: cfg.bp.clientId, scp: cfg.bp.scope, role: cfg.bp.roleValue }, { kind: "access" })] : [],
    verdict: t ? (cached ? "info" : "allow") : "deny",
    summary: t ? (cached ? `The Azure CLI returned a CACHED token (issued ~${ageSeconds}s ago, uti ${claims?.uti}); this is not a fresh issuance and records no evidence. roles=${JSON.stringify(claims?.roles ?? null)}.`
                         : `Entra issued a fresh BP-A1 token to the Azure CLI client for ${claims?.name} (oid ${label(claims?.oid) ?? claims?.oid}): roles=${JSON.stringify(claims?.roles ?? null)}. The blueprint pre-authorizes the Azure CLI on ${cfg.bp.scope}, so this is the Phase 15 shape: a different azp, same assignment.`)
               : `Entra refused the Azure CLI: ${code ?? ""} ${err?.split("\n")[0] ?? ""}`,
    note: "The Azure CLI caches tokens per scope string; alternate between the named scope and /.default to force a fresh issuance after a directory change." });
  if (!t) { evidenceForTokenOutcome(run, { userKey: userKeyFor(cfg.users.alex.objectId), clientKey: "azcli" }, { denied: true, code }); finish(run, "denied"); return null; }
  const sid = randomUUID();
  const sess = { id: sid, userKey: userKeyFor(claims.oid), clientKey: "azcli", user: { oid: claims.oid, name: claims.name, upn: claims.preferred_username }, refreshToken: null, graphToken: null, bpToken: t.token, bpTokenClaims: claims, createdAt: new Date().toISOString(), runId: run.id };
  try { const g = await azAccessToken(["--resource-type", "ms-graph"]); sess.graphToken = g.token; } catch { /* optional */ }
  sessions.set(sid, sess); saveSessions(); run.session = { user: sess.user, userKey: sess.userKey, clientKey: "azcli" };
  if (!cached) evidenceForTokenOutcome(run, { userKey: sess.userKey, clientKey: "azcli" }, { denied: false, claims, flow: "refresh_token (Azure CLI)" });
  finish(run); return sid;
}

// ---------------------------------------------------------------- admin ops (Phase 13/14)
async function setAssignment(run, userKey, assign) {
  const user = cfg.users[userKey];
  const tok = await adminToken(run);
  await refreshDirectory(null);
  const existingId = directory.state[`${userKey}AssignmentId`];
  if (assign && !existingId) {
    await graph(run, { method: "POST", path: `v1.0/users/${user.objectId}/appRoleAssignments`, expectStatus: 201, phase: "Phase 14",
      json: { principalId: user.objectId, resourceId: cfg.bp.principalId, appRoleId: cfg.bp.roleId },
      title: `Phase 14 — assign ${user.displayName} → ${cfg.bp.roleValue} → BP-A1`, note: "principalId = user · resourceId = blueprint principal · appRoleId = role" }, tok);
  } else if (!assign && existingId) {
    await graph(run, { method: "DELETE", path: `v1.0/users/${user.objectId}/appRoleAssignments/${existingId}`, expectStatus: 204, phase: "Phase 13",
      title: `Phase 13 — REMOVE ${user.displayName} → ${cfg.bp.roleValue} → BP-A1`, note: "Existing tokens stay valid until expiry; only NEW issuance is affected. Request a fresh token to see the effect." }, tok);
  } else {
    addHop(run, { actor: "ADMIN", from: "APP", to: "APP", kind: "note", title: `No change: ${user.displayName} is already ${assign ? "assigned" : "unassigned"}`, request: null, response: { status: 200, body: null }, verdict: "info", summary: "" });
  }
  await refreshDirectory(run);
  finish(run);
}
async function setAssignmentRequired(run, value) {
  const tok = await adminToken(run);
  await graph(run, { method: "PATCH", path: `v1.0/servicePrincipals/${cfg.bp.principalId}`, expectStatus: 204, phase: "Phase 4",
    json: { appRoleAssignmentRequired: value }, title: `Phase 4 — set appRoleAssignmentRequired=${value} on the BP-A1 principal` }, tok);
  await refreshDirectory(run); finish(run);
}

// ---------------------------------------------------------------- test matrix
const TESTS = [
  { id: "T01", title: "Alex, assigned, via APP", expected: "Token issued with roles=[labsOBO.AgentInvoker]" },
  { id: "T02", title: "Sam, not assigned, via APP", expected: "Denied — AADSTS50105" },
  { id: "T03", title: "Alex after role removed", expected: "New token denied — AADSTS50105" },
  { id: "T04", title: "Sam after role added", expected: "Token issued with the role" },
  { id: "T05", title: "Alex, wrong client (azp)", expected: "A1 / AgentCore rejects on azp policy" },
  { id: "T06", title: "Alex, wrong audience", expected: "A1 / AgentCore rejects on aud" },
  { id: "T07", title: "Alex via DIRECT client", expected: "Token issued; assignment unchanged (azp differs)" },
  { id: "CONSENT", title: "Consent simulation (admin grant revoked)", expected: "Case A: no screen with admin consent · Case B: consent screen · Case C: 'Need admin approval'" },
  { id: "CTRL", title: "Control: ordinary API, assignment required, user not assigned", expected: "Whatever Entra does here is the baseline the blueprint is compared against" },
  { id: "T09", title: "Token WITHOUT the role → A1 runtime", expected: "A1 / AgentCore rejects on roles CONTAINS (the enforcement point)" },
  { id: "T12", title: "Alex token → A1 runtime", expected: "All claims pass; A1 runs (HTTP 200)" },
  { id: "T08", title: "A1 OBO downstream for Alex", expected: "T_A1_OBO: oid=Alex, azp=AGENT-A1; Graph /me answers as Alex" },
];
function testMatrix() {
  const latest = {};
  for (const r of [...runs.values()].sort((a, b) => a.seq - b.seq)) for (const e of r.evidence) latest[e.test] = { ...e, runId: r.id, runTitle: r.title };
  return TESTS.map((t) => ({ ...t, evidence: latest[t.id] ?? null }));
}

// ---------------------------------------------------------------- HTTP plumbing
const send = (res, status, body, headers = {}) => { res.writeHead(status, { "Content-Type": "application/json", ...headers }); res.end(JSON.stringify(body)); };
const readBody = (req) => new Promise((r) => { let s = ""; req.on("data", (c) => (s += c)); req.on("end", () => { try { r(s ? JSON.parse(s) : {}); } catch { r({}); } }); });
const runSummary = (r) => ({ id: r.id, seq: r.seq, kind: r.kind, title: r.title, user: r.user, client: r.client, status: r.status, startedAt: r.startedAt, hops: r.hops.length, evidence: r.evidence, session: r.session ?? null });
async function a1Policy() { try { const r = await fetch(`${A1_LOCAL}/policy`, { signal: AbortSignal.timeout(1500) }); return { up: true, policy: await r.json() }; } catch { return { up: false, policy: null }; } }

const server = createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`); const p = url.pathname;
  try {
    if (req.method === "GET" && (p === "/" || p === "/index.html")) { res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" }); return res.end(readFileSync(resolve(HERE, "public/index.html"))); }
    if (req.method === "GET" && p === "/login") return loginRedirect(req, res, url.searchParams);
    if (req.method === "GET" && p === "/auth/callback") return callback(req, res, url, "app");
    if (req.method === "GET" && p === "/auth/callback/direct") return callback(req, res, url, "direct");
    if (req.method === "GET" && p === "/logout") { sessions.delete(cookieOf(req).labsobo_sid); saveSessions(); res.writeHead(302, { Location: "/", "Set-Cookie": "labsobo_sid=; Path=/; Max-Age=0" }); return res.end(); }

    if (req.method === "GET" && p === "/api/state") {
      const sess = sessionOf(req); const a1 = await a1Policy();
      const arn = existsSync(resolve(ROOT, ".lab/a1_runtime_arn.txt")) ? readFileSync(resolve(ROOT, ".lab/a1_runtime_arn.txt"), "utf8").trim() : null;
      return send(res, 200, {
        lab: { tenantId: cfg.tenantId, bp: cfg.bp, app: { name: cfg.app.name, clientId: cfg.app.clientId, redirectUri: cfg.app.redirectUri }, direct: cfg.direct, agent: { name: cfg.agent.name, clientId: cfg.agent.clientId },
               users: cfg.users, azureCliAppId: cfg.azureCliAppId, labels: LABELS, endpoints: { authorize: cfg.authorizeEndpoint, token: cfg.tokenEndpoint, issuer: cfg.issuer, discovery: cfg.discoveryUrl } },
        session: sess ? { userKey: sess.userKey, clientKey: sess.clientKey, user: sess.user, hasBpToken: !!sess.bpToken, hasGraphToken: !!sess.graphToken, hasRefreshToken: !!sess.refreshToken, bpTokenClaims: sess.bpTokenClaims ? { roles: sess.bpTokenClaims.roles, exp: sess.bpTokenClaims.exp, azp: sess.bpTokenClaims.azp } : null } : null,
        directory: directory.state, a1Local: { url: A1_LOCAL, ...a1 }, agentcore: { runtimeArn: arn, region: cfg.aws.region },
        runs: [...runs.values()].sort((a, b) => b.seq - a.seq).map(runSummary), tests: testMatrix(),
      });
    }
    if (req.method === "GET" && p.startsWith("/api/runs/")) {
      const r = runs.get(p.slice("/api/runs/".length)); if (!r) return send(res, 404, { error: "no such run" });
      return send(res, 200, redactDeep(r, url.searchParams.get("reveal") === "1"));
    }
    if (req.method === "POST" && p === "/api/runs/clear") { for (const r of runs.values()) { try { writeFileSync(resolve(TRACE_DIR, `${r.id}.json`), JSON.stringify({ ...r, archived: true })); } catch {} } runs.clear(); return send(res, 200, { ok: true }); }

    if (req.method === "POST" && p === "/api/directory/refresh") { const run = newRun({ kind: "directory", title: "Directory check (Phase 4 + Phase 6)" }); await refreshDirectory(run); finish(run); return send(res, 200, { runId: run.id, directory: directory.state }); }
    if (req.method === "POST" && p === "/api/directory/assign") { const b = await readBody(req); if (!cfg.users[b.user]) return send(res, 400, { error: `unknown user '${b.user}' (alex|sam)` }); const run = newRun({ kind: "directory", title: `${b.assign ? "Assign" : "Remove"} ${cfg.bp.roleValue} for ${cfg.users[b.user]?.displayName ?? b.user}` }); await setAssignment(run, b.user, !!b.assign); return send(res, 200, { runId: run.id, directory: directory.state }); }
    if (req.method === "POST" && p === "/api/directory/consent") {
      // Simulate the three consent cases: revoke the AllPrincipals (admin) grant for APP -> BP-A1 and see what Entra shows the user; restore it afterwards.
      const b = await readBody(req); const run = newRun({ kind: "directory", title: `${b.grant ? "Restore" : "REVOKE"} admin consent: APP → ${cfg.bp.scope} on BP-A1` });
      const tok = await adminToken(run);
      const g = await graph(run, { path: `v1.0/oauth2PermissionGrants?$filter=clientId eq '${cfg.app.principalId}' and resourceId eq '${cfg.bp.principalId}'`, phase: "consent", title: "Read APP's consent grants on BP-A1 (AllPrincipals = admin consent, Principal = a user consented for themselves)" }, tok);
      const grants = g.response.body?.value ?? [];
      if (b.grant) {
        if (!grants.some((x) => x.consentType === "AllPrincipals")) await graph(run, { method: "POST", path: "v1.0/oauth2PermissionGrants", expectStatus: 201, phase: "consent", json: { clientId: cfg.app.principalId, consentType: "AllPrincipals", resourceId: cfg.bp.principalId, scope: cfg.bp.scope }, title: "Phase 7 — grant admin consent (AllPrincipals) for APP → labsOBO_access_agent" }, tok);
        else addHop(run, { actor: "ADMIN", from: "APP", to: "APP", kind: "note", title: "Admin consent already present", request: null, response: { status: 200, body: null }, verdict: "info", summary: "" });
      } else {
        for (const x of grants) await graph(run, { method: "DELETE", path: `v1.0/oauth2PermissionGrants/${x.id}`, expectStatus: 204, phase: "consent", title: `Revoke ${x.consentType} grant ${x.principalId ? "for " + (label(x.principalId) ?? x.principalId) : ""} (scope: ${x.scope})`, note: "Case B/C simulation: with no grant, Entra must ask the user (if the tenant allows user consent) or demand admin approval." }, tok);
      }
      const after = await graph(run, { path: `v1.0/oauth2PermissionGrants?$filter=clientId eq '${cfg.app.principalId}' and resourceId eq '${cfg.bp.principalId}'`, phase: "consent", title: "Consent grants after the change" }, tok);
      finish(run); return send(res, 200, { runId: run.id, grants: after.response.body?.value ?? [] });
    }
    if (req.method === "GET" && p === "/api/directory/consent") {
      const tok = await adminToken(null);
      const g = await graph(null, { path: `v1.0/oauth2PermissionGrants?$filter=clientId eq '${cfg.app.principalId}' and resourceId eq '${cfg.bp.principalId}'` }, tok);
      const pol = await graph(null, { path: "v1.0/policies/authorizationPolicy?$select=defaultUserRolePermissions" }, tok);
      return send(res, 200, { grants: g.response.body?.value ?? [], userConsentPolicies: pol.response.body?.defaultUserRolePermissions?.permissionGrantPoliciesAssigned ?? null });
    }
    if (req.method === "POST" && p === "/api/directory/assignment-required") { const b = await readBody(req); const run = newRun({ kind: "directory", title: `Set appRoleAssignmentRequired=${!!b.value}` }); await setAssignmentRequired(run, !!b.value); return send(res, 200, { runId: run.id, directory: directory.state }); }

    if (req.method === "POST" && p === "/api/session/token") {
      const sess = sessionOf(req); if (!sess) return send(res, 401, { error: "no session" });
      if (sess.clientKey === "azcli") { const run = newRun({ kind: "action", title: `Fresh BP-A1 token via Azure CLI for ${sess.user.name}`, user: sess.userKey, client: "azcli" }); const b = await readBody(req); const sid = await importAzCli(run, b.scopeForm ?? "default"); return send(res, 200, { runId: run.id }, sid ? { "Set-Cookie": `labsobo_sid=${sid}; Path=/; HttpOnly` } : {}); }
      if (!sess.refreshToken) return send(res, 400, { error: "session has no refresh token" });
      const run = newRun({ kind: "action", title: `Fresh BP-A1 token for ${sess.user.name} via ${sess.clientKey === "direct" ? "DIRECT" : "APP"}`, user: sess.userKey, client: sess.clientKey });
      run.session = { user: sess.user, userKey: sess.userKey, clientKey: sess.clientKey };
      const t = await requestBpToken(run, sess, "Phase 13/14"); finish(run, t.ok ? "done" : "denied"); return send(res, 200, { runId: run.id, ok: t.ok });
    }
    if (req.method === "POST" && p === "/api/session/invoke") {
      const sess = sessionOf(req); if (!sess) return send(res, 401, { error: "no session" });
      const b = await readBody(req);
      const run = newRun({ kind: "action", title: `Invoke A1 (${b.target ?? "local"}, ${b.mode ?? "echo"}${b.tokenKind === "graph" ? ", wrong-audience token" : ""}) as ${sess.user.name}`, user: sess.userKey, client: sess.clientKey });
      run.session = { user: sess.user, userKey: sess.userKey, clientKey: sess.clientKey };
      await invokeA1(run, sess, b); return send(res, 200, { runId: run.id });
    }
    if (req.method === "POST" && p === "/api/azcli/import") {
      const b = await readBody(req); const run = newRun({ kind: "signin", title: "Pre-flight: operator's Azure CLI token for BP-A1 (no browser)", user: "alex", client: "azcli", scopeMode: "azcli" });
      const sid = await importAzCli(run, b.scopeForm ?? "named"); return send(res, 200, { runId: run.id, ok: !!sid }, sid ? { "Set-Cookie": `labsobo_sid=${sid}; Path=/; HttpOnly` } : {});
    }
    if (req.method === "POST" && p === "/api/session/adopt") {
      // LAB ONLY: make the saved LABSOBO_T_APP_A1 for <user>.<client> (issued by an earlier browser run) the current session,
      // so CLI-driven tests can exercise the real APP-issued token. Prefers a live session (with refresh token) when one exists.
      const b = await readBody(req); const userKey = b.user ?? "alex", clientKey = b.client ?? "app";
      const live = [...sessions.values()].filter((x) => x.userKey === userKey && x.clientKey === clientKey && x.bpToken).sort((a, c) => (c.createdAt > a.createdAt ? 1 : -1))[0];
      let sess = live ? { ...live, id: randomUUID(), adoptedFrom: live.id } : null;
      if (!sess) {
        const f = resolve(TOKEN_DIR, `T_APP_A1.${userKey}.${clientKey}.json`);
        if (!existsSync(f)) return send(res, 404, { error: `no saved token for ${userKey}.${clientKey}; sign in through the browser first` });
        const saved = JSON.parse(readFileSync(f, "utf8")); const c = saved.claims ?? decode(saved.access_token)?.claims;
        if (!c || c.exp * 1000 < Date.now()) return send(res, 410, { error: "saved token has expired; sign in again" });
        sess = { id: randomUUID(), userKey, clientKey, user: { oid: c.oid, name: c.name, upn: c.preferred_username }, refreshToken: null, graphToken: null, bpToken: saved.access_token, bpTokenClaims: c, createdAt: new Date().toISOString(), adoptedFrom: f };
      }
      if (!sess.graphToken) { try { sess.graphToken = (await azAccessToken(["--resource-type", "ms-graph"])).token; } catch { /* optional */ } }
      sessions.set(sess.id, sess); saveSessions();
      return send(res, 200, { ok: true, user: sess.user, clientKey, hasRefreshToken: !!sess.refreshToken, exp: sess.bpTokenClaims?.exp }, { "Set-Cookie": `labsobo_sid=${sess.id}; Path=/; HttpOnly` });
    }
    if (req.method === "POST" && p === "/api/a1/policy") { const b = await readBody(req); const r = await fetch(`${A1_LOCAL}/policy`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(b) }); return send(res, r.status, await r.json()); }
    send(res, 404, { error: "not found" });
  } catch (e) { console.error(e); send(res, 500, { error: String(e?.message ?? e) }); }
});
server.listen(PORT, () => { console.log(`labsOBO calling app listening on http://localhost:${PORT}`); refreshDirectory(null).then((d) => console.log(`directory: assignmentRequired=${d.assignmentRequired} alex=${d.alex} sam=${d.sam}${d.error ? " error=" + d.error : ""}`)); });
