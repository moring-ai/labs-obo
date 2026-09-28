/**
 * labsOBO | the Jira broker (steps 15-16). Its own trust boundary: the API registered in Entra as
 * labsOBO-jira-broker. It accepts only T_A1_BROKER, and it is the only component that reads the vault.
 *
 *   POST /invocations   Authorization: Bearer T_A1_BROKER   {"op":"create_issue", "issue":{...}, "provenance":{...}}
 *     1. validate T_A1_BROKER: signature, issuer, expiry, aud = broker, azp = AGENT-A1, scp ∋ labsOBO_jira.create
 *     2. (tid, oid) from the token -> the user's Atlassian binding; none -> {"status":"authorization_required","resource":"jira"}
 *     3. refresh the Atlassian token -> T_JIRA_USER, write the rotated refresh token back
 *     4. create the issue with T_JIRA_USER and record the provenance on it
 *
 * Runs on Bedrock AgentCore (LABSOBO_ROLE=broker, port 8080, a JWT authorizer in front that already
 * checks aud + azp + scp) or locally on :3102. Every step comes back as a hop for the timeline.
 */
import { createServer } from "node:http";
import { randomUUID } from "node:crypto";
import { cfg, env, verify, summarizeToken, label } from "../../lib/entra.mjs";
import { userToken, createIssue } from "../../lib/jira.mjs";

const PORT = Number(process.env.PORT ?? 3102);
const AUDIENCE = env.LABSOBO_JIRA_BROKER_CLIENT_ID;
const SCOPE = env.LABSOBO_JIRA_SCOPE_VALUE ?? "labsOBO_jira.create";
const hop = (p) => ({ id: randomUUID(), ts: new Date().toISOString(), actor: "BROKER", ...p });
const json = (res, status, body) => { res.writeHead(status, { "Content-Type": "application/json" }); res.end(JSON.stringify(body)); };
const readBody = (req) => new Promise((r) => { let s = ""; req.on("data", (c) => (s += c)); req.on("end", () => { try { r(s ? JSON.parse(s) : {}); } catch { r({}); } }); });

async function authorize(token) {
  const checks = [];
  if (!token) return { ok: false, reason: "no bearer token", checks };
  const v = await verify(token, { audience: AUDIENCE });
  checks.push({ check: `signature + issuer + expiry + aud = ${label(AUDIENCE) ?? "labsOBO-jira-broker"}`, ok: v.ok, detail: v.ok ? `kid ${v.header.kid}` : v.reason });
  if (!v.ok) return { ok: false, reason: v.reason, checks };
  const c = v.claims;
  const azpOk = c.azp === cfg.agent.clientId;
  checks.push({ check: "azp = AGENT-A1 (only the agent may ask)", ok: azpOk, detail: `azp = ${c.azp}` });
  const scpOk = String(c.scp ?? "").split(" ").includes(SCOPE);
  checks.push({ check: `scp contains ${SCOPE}`, ok: scpOk, detail: `scp = ${c.scp ?? "(absent)"}` });
  const userOk = !!(c.oid && c.tid) && c.idtyp !== "app";
  checks.push({ check: "a delegated user token (oid + tid, not app-only)", ok: userOk, detail: `oid = ${c.oid}, tid = ${c.tid}` });
  const ok = azpOk && scpOk && userOk;
  return { ok, reason: ok ? null : !azpOk ? "only AGENT-A1 may call the broker" : !scpOk ? `token lacks ${SCOPE}` : "not a delegated user token", checks, claims: c };
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);
  if (req.method === "GET" && url.pathname === "/ping") return json(res, 200, { status: "Healthy", service: "labsOBO-jira-broker" });
  if (req.method !== "POST" || url.pathname !== "/invocations") return json(res, 404, { error: "not found" });
  const body = await readBody(req);
  const auth = req.headers.authorization ?? "";
  const token = auth.toLowerCase().startsWith("bearer ") ? auth.slice(7).trim() : null;
  const hops = [];
  const a = await authorize(token);
  hops.push(hop({ from: "BROKER", to: "BROKER", step: "15", kind: "local", label: a.ok ? "Validate T_A1_BROKER: you asked, A1 is acting, jira.create" : `Rejected: ${a.reason}`,
    title: "Broker validates T_A1_BROKER", request: null, response: { status: a.ok ? 200 : 401, body: { checks: a.checks } }, checks: a.checks,
    tokens: token ? [summarizeToken("T_A1_BROKER", token, { oid: a.claims?.oid, azp: cfg.agent.clientId, aud: AUDIENCE, scp: SCOPE })] : [],
    verdict: a.ok ? "allow" : "deny", summary: a.ok ? `Human = ${a.claims.name ?? a.claims.oid}, actor = AGENT-A1, permission = ${SCOPE}.` : a.reason }));
  if (!a.ok) return json(res, 401, { status: "denied", error: a.reason, hops });
  if (body.op !== "create_issue" || !body.issue?.summary) return json(res, 400, { status: "error", error: "expected {op:'create_issue', issue:{summary, description, labels}}", hops });

  const user = { tid: a.claims.tid, oid: a.claims.oid, name: a.claims.name ?? a.claims.preferred_username ?? a.claims.oid, upn: a.claims.preferred_username };
  try {
    const t = await userToken({ user });
    hops.push(...t.hops);
    if (t.status === "authorization_required") return json(res, 200, { status: "authorization_required", resource: "jira", hops });
    const c = await createIssue({ accessToken: t.accessToken, binding: t.binding, issue: body.issue,
      provenance: { ...(body.provenance ?? {}), requestedBy: { oid: user.oid, tid: user.tid, name: user.name, upn: user.upn }, broker: "labsOBO-jira-broker", createdAt: new Date().toISOString() } });
    hops.push(...c.hops);
    console.log(JSON.stringify({ audit: "jira.create", ok: c.ok, key: c.issue?.key ?? null, user: user.oid, tid: user.tid, agent: a.claims.azp, source: body.provenance?.source ?? null }));
    return json(res, 200, c.ok ? { status: "created", issue: c.issue, hops } : { status: "error", error: c.error, hops });
  } catch (e) {
    hops.push(hop({ from: "BROKER", to: "BROKER", step: "15", kind: "note", label: `Broker error: ${e.message}`, title: "Broker error", request: null, response: { status: 500, body: String(e.message) }, verdict: "error", summary: String(e.message) }));
    return json(res, 200, { status: "error", error: String(e.message), hops });
  }
});
server.listen(PORT, () => console.log(`labsOBO Jira broker listening on :${PORT}  audience=${AUDIENCE} azp=AGENT-A1 scope=${SCOPE}`));
