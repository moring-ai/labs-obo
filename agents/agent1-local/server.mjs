/**
 * labsOBO | Agent A1. Runs on Bedrock AgentCore (port 8080, behind the JWT authorizer) or locally on :3101.
 *
 * A1 holds two proofs: T_APP_A1 ("the user asked me", forwarded in Authorization) and T1 ("I am A1").
 *
 *   authorizer  the claim checks AgentCore's JWT authorizer applies: aud = BP-A1, azp = APP,
 *               roles ∋ labsOBO.AgentInvoker, scp ∋ labsOBO_access_agent. On AgentCore they already
 *               ran before this container saw the request; locally this is the stand-in.
 *   step 7      T1   AgentCore: AWS STS signs a workload JWT for the runtime role, and Entra accepts it
 *                    through the federated credential on BP-A1 (no secret, no certificate).
 *                    Local runtime: the blueprint certificate proves the same thing.
 *   tools       resource + endpoint of each tool come from the runtime registry (lib/tools.mjs, SSM);
 *               nothing about Defender or the broker is in this file.
 *   step 8-9    OBO  client_id = AGENT-A1, client_assertion = T1, assertion = T_APP_A1, scope = <resource>/.default
 *                    -> T_A1_DEFENDER (oid = the user, actor = A1, aud = Defender). The scopes in it are the ones
 *                    an admin consented for A1 on that resource; A1 reads them from scp at runtime.
 *   step 10     KQL  the Advanced Hunting endpoint from the registry, with T_A1_DEFENDER
 *   step 11     decide: deterministic analysis; a ticket only if the prompt asked for one and severity >= Medium
 *   step 14     OBO  scope = <broker resource>/.default -> T_A1_BROKER, then POST to the broker (steps 15-16 happen there).
 *               First time: the broker has no Atlassian binding and A1 returns {"status":"authorization_required","resource":"jira"}.
 *
 * Modes: echo | obo (lab Phase 16: OBO -> Graph /me) | investigate (the flow above).
 * Every step is returned as a hop so the calling app can splice it into one timeline.
 */
import { createServer } from "node:http";
import { randomUUID } from "node:crypto";
import { cfg, env, verify, decode, summarizeToken, tokenRequest, doHttp, clientAssertion, ASSERTION_TYPE, label } from "../../lib/entra.mjs";
import { planInvestigation, runHunt, triage } from "../../lib/secops.mjs";
import { tool } from "../../lib/tools.mjs";

const PORT = Number(process.env.PORT ?? cfg.ports.agent);
const ON_AGENTCORE = process.env.A1_T1_CREDENTIAL === "aws-sts";
let policy = {
  audience: cfg.bp.clientId,
  allowedAzp: [cfg.app.clientId],
  requiredRole: cfg.bp.roleValue,
  requiredScope: cfg.bp.scope,
  enforceScope: true,
};

const hop = (p) => ({ id: randomUUID(), ts: new Date().toISOString(), actor: "A1", ...p });
const json = (res, status, body) => { res.writeHead(status, { "Content-Type": "application/json" }); res.end(JSON.stringify(body)); };
const readBody = (req) => new Promise((r) => { let s = ""; req.on("data", (c) => (s += c)); req.on("end", () => { try { r(s ? JSON.parse(s) : {}); } catch { r({ raw: s }); } }); });
const firstLine = (e) => `${e?.code ?? e?.error ?? ""} ${String(e?.description ?? "").split(/\r?\n| Trace ID/)[0]}`.trim();

async function authorize(token) {
  const checks = [];
  const push = (check, ok, detail) => checks.push({ check, ok, detail });
  if (!token) { push("bearer token present", false, "no Authorization: Bearer header"); return { ok: false, reason: "missing bearer token", checks }; }
  const v = await verify(token, { audience: policy.audience });
  push(`signature + issuer (${cfg.issuer}) + expiry + aud == ${label(policy.audience)}`, v.ok, v.ok ? `kid ${v.header.kid}` : v.reason);
  if (!v.ok) return { ok: false, reason: v.reason, checks };
  const c = v.claims;
  const azpOk = policy.allowedAzp.includes(c.azp);
  push(`azp IN allowed clients [${policy.allowedAzp.map((a) => label(a) ?? a).join(", ")}]`, azpOk, `azp = ${c.azp} ${label(c.azp) ? `(${label(c.azp)})` : ""}`);
  const roles = Array.isArray(c.roles) ? c.roles : [];
  const roleOk = roles.includes(policy.requiredRole);
  push(`roles CONTAINS ${policy.requiredRole}`, roleOk, `roles = ${JSON.stringify(c.roles ?? null)}`);
  const scp = typeof c.scp === "string" ? c.scp.split(" ") : [];
  const scpOk = !policy.enforceScope || scp.includes(policy.requiredScope);
  push(`scp CONTAINS ${policy.requiredScope}${policy.enforceScope ? "" : " (not enforced)"}`, scpOk, `scp = ${c.scp ?? "(absent)"}`);
  const ok = azpOk && roleOk && scpOk;
  const reason = !azpOk ? `client ${c.azp} is not an allowed caller (azp)` : !roleOk ? `token lacks role ${policy.requiredRole}` : !scpOk ? `token lacks scope ${policy.requiredScope}` : null;
  return { ok, reason, checks, claims: c, header: v.header };
}

// ---------------------------------------------------------------- step 7: T1, "I am A1"
async function getT1(hops) {
  let assertion, assertionName;
  if (ON_AGENTCORE) {
    // AWS STS signs a workload JWT for the runtime's execution role; BP-A1 trusts it through a federated credential.
    const req = { Audience: ["api://AzureADTokenExchange"], SigningAlgorithm: "RS256", DurationSeconds: 300 };
    const t0 = Date.now();
    try {
      const { STSClient, GetWebIdentityTokenCommand } = await import("@aws-sdk/client-sts");
      const r = await new STSClient({ region: cfg.aws.region }).send(new GetWebIdentityTokenCommand(req));
      assertion = r.WebIdentityToken; assertionName = "AWS_WORKLOAD_JWT";
      const c = decode(assertion)?.claims ?? {};
      hops.push(hop({ from: "A1", to: "STS", step: "7", kind: "sdk", label: "Get an AWS workload JWT from STS (runtime role)",
        title: "sts:GetWebIdentityToken → AWS workload JWT",
        request: { method: "POST", url: "https://sts.amazonaws.com/ GetWebIdentityToken", headers: {}, body: req, bodyType: "json",
                   curl: "aws sts get-web-identity-token --audience api://AzureADTokenExchange --signing-algorithm RS256 --duration-seconds 300" },
        response: { status: 200, durationMs: Date.now() - t0, body: { WebIdentityToken: assertion, Expiration: r.Expiration } },
        tokens: [{ name: "AWS workload JWT", header: decode(assertion)?.header, claims: c, raw: assertion,
          checks: [{ claim: "iss", value: c.iss, expect: null, ok: null, meaning: "This AWS account's STS issuer" },
                   { claim: "sub", value: c.sub, expect: null, ok: null, meaning: "The IAM role the runtime runs as" },
                   { claim: "aud", value: Array.isArray(c.aud) ? c.aud.join(" ") : c.aud, expect: "api://AzureADTokenExchange", ok: [].concat(c.aud).includes("api://AzureADTokenExchange"), meaning: "Entra's token exchange audience" }] }],
        verdict: "allow", summary: `iss = ${c.iss}, sub = ${c.sub}. "This workload is the approved AWS runtime."` }));
    } catch (e) {
      hops.push(hop({ from: "A1", to: "STS", step: "7", kind: "sdk", label: `AWS STS refused: ${e.name}`, title: "sts:GetWebIdentityToken", request: { method: "POST", url: "sts:GetWebIdentityToken", headers: {}, body: req, bodyType: "json" },
        response: { status: e.$metadata?.httpStatusCode ?? 0, body: String(e.message) }, verdict: "deny", summary: String(e.message) }));
      return { ok: false, error: { code: e.name, description: e.message } };
    }
  } else {
    const a = await clientAssertion({ clientId: cfg.bp.clientId, keyPath: cfg.agent.bpKeyPath, certPath: cfg.agent.bpCertPath });
    assertion = a.assertion; assertionName = "LABSOBO_BP_A1_ASSERTION";
  }
  const t1 = await tokenRequest({ grant_type: "client_credentials", client_id: cfg.bp.clientId, scope: "api://AzureADTokenExchange/.default", fmi_path: cfg.agent.clientId,
                                  client_assertion_type: ASSERTION_TYPE, client_assertion: assertion }, { secretNames: { client_assertion: assertionName } });
  hops.push(hop({ from: "A1", to: "ENTRA", step: "7", kind: "http",
    label: ON_AGENTCORE ? "Exchange it at Entra for T1 (BP-A1 federated credential)" : "Get T1 with the blueprint certificate (local runtime)",
    title: "T1 — client_credentials: client_id = BP-A1, fmi_path = AGENT-A1",
    request: t1.request, response: t1.response,
    tokens: t1.tokens ? [summarizeToken("T1", t1.tokens.access_token, { azp: cfg.bp.clientId, aud: cfg.tokenExchangeAppId })] : [],
    verdict: t1.ok ? "allow" : "deny",
    summary: t1.ok ? `Entra issued T1: "I am labsOBO-agent1", proven by ${ON_AGENTCORE ? "the AWS workload JWT" : "the blueprint certificate"}.` : `T1 refused: ${firstLine(t1.error)}` }));
  return t1;
}

// ---------------------------------------------------------------- tools from the runtime registry
async function resolveTool(hops, id, { step, label: lbl }) {
  try {
    const t = await tool(id);
    hops.push(hop({ from: "A1", to: "REGISTRY", step, kind: "sdk", label: lbl, title: `Tool registry ${t.registry.name} (v${t.registry.version}) → ${id}`,
      request: { method: "GET", url: `ssm:GetParameter ${t.registry.name}`, headers: {}, body: null, bodyType: "none", curl: `aws ssm get-parameter --name "${t.registry.name}"` },
      response: { status: 200, durationMs: t.registry.ms, body: { [id]: { resource: t.resource, endpoint: t.endpoint }, version: t.registry.version, cached: t.registry.cached } },
      verdict: "info", summary: `resource = ${label(t.resource) ?? t.resource}, endpoint = ${t.endpoint}${t.registry.cached ? " (cached)" : ""}. No scope names here: Entra decides them.` }));
    return t;
  } catch (e) {
    hops.push(hop({ from: "A1", to: "REGISTRY", step, kind: "sdk", label: `No "${id}" in the tool registry`, title: "Tool registry lookup failed", request: null,
      response: { status: 404, body: String(e.message) }, verdict: "deny", summary: String(e.message) }));
    return null;
  }
}

// ---------------------------------------------------------------- steps 8-9 / 14: on-behalf-of with <resource>/.default
async function obo(hops, { t1, userToken, resource, name, step, label: lbl, user }) {
  const scope = `${resource.replace(/\/+$/, "")}/.default`;
  const r = await tokenRequest({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", client_id: cfg.agent.clientId,
                                 client_assertion_type: ASSERTION_TYPE, client_assertion: t1, assertion: userToken, requested_token_use: "on_behalf_of", scope },
                               { secretNames: { client_assertion: "T1", assertion: "T_APP_A1" } });
  const c = r.tokens ? decode(r.tokens.access_token)?.claims : null;
  // v2 tokens carry the resource's app id as aud, v1 tokens its URI: both mean "this resource".
  const audOk = !!c && [resource, resource.replace(/^api:\/\//, "")].includes(c.aud);
  hops.push(hop({ from: "A1", to: "ENTRA", step, kind: "http", label: lbl, title: `OBO — client_assertion = T1, assertion = T_APP_A1, scope = ${scope}`,
    request: r.request, response: r.response,
    tokens: r.tokens ? [summarizeToken(name, r.tokens.access_token, { oid: user.oid, azp: cfg.agent.clientId, aud: audOk ? c.aud : resource })] : [],
    verdict: r.ok ? "allow" : "deny",
    summary: r.ok ? `Entra granted scp = ${c.scp ?? "(none)"}: the delegated permissions an admin consented for A1 on ${label(c.aud) ?? c.aud}. oid = ${user.name} (the human survives the hop), actor = AGENT-A1.`
                  : `OBO refused: ${firstLine(r.error)}` }));
  return r;
}

// ---------------------------------------------------------------- step 14: A1 -> Jira broker
async function jiraLeg(hops, { t1, userToken, user, issue, provenance }) {
  const jt = await resolveTool(hops, "jira.create_issue", { step: "14", label: "Find the Jira broker in the runtime registry" });
  if (!jt) return { status: "error", stage: "tool registry", error: 'no "jira.create_issue" tool' };
  const bt = await obo(hops, { t1, userToken, resource: jt.resource, name: "T_A1_BROKER", step: "14", label: "Get T_A1_BROKER by OBO for the Jira broker", user });
  if (!bt.ok) return { status: "error", stage: "T_A1_BROKER", error: firstLine(bt.error) };
  const onAgentCore = jt.endpoint.includes("bedrock-agentcore");
  const r = await doHttp({ method: "POST", url: jt.endpoint, json: { op: "create_issue", issue, provenance }, secretNames: { bearer: "T_A1_BROKER" }, timeoutMs: 90000,
    headers: { Authorization: `Bearer ${bt.tokens.access_token}`, ...(onAgentCore ? { "X-Amzn-Bedrock-AgentCore-Runtime-Session-Id": `labsOBO-broker-${randomUUID()}` } : {}) } });
  const b = r.response.body && typeof r.response.body === "object" ? r.response.body : {};
  hops.push(hop({ from: "A1", to: "BROKER", step: "14", kind: "http", label: `Ask the Jira broker to create the issue${onAgentCore ? " (AgentCore)" : " (local broker)"}`,
    title: `POST ${onAgentCore ? "AgentCore labsOBO_jira_broker" : jt.endpoint} with T_A1_BROKER`,
    request: r.request, response: { ...r.response, body: { ...b, hops: undefined } },
    verdict: !r.ok ? "deny" : b.status === "created" ? "allow" : b.status === "authorization_required" ? "info" : "error",
    summary: !r.ok ? `Broker answered HTTP ${r.response.status}: ${b.error ?? b.message ?? b.Message ?? ""}` : b.status === "created" ? `${b.issue.key} created.`
           : b.status === "authorization_required" ? "authorization_required: the user has not linked Atlassian yet." : `Broker error: ${b.error}` }));
  hops.push(...(Array.isArray(b.hops) ? b.hops : []));
  if (!r.ok) return { status: "error", stage: "broker", error: b.error ?? b.message ?? b.Message ?? `HTTP ${r.response.status}` };
  return { status: b.status, issue: b.issue ?? null, error: b.error ?? null };
}

// ---------------------------------------------------------------- lab Phase 16 (kept for the lab console): OBO -> Graph /me
async function oboLeg(inboundToken, inbound) {
  const hops = [];
  const gt = await resolveTool(hops, "graph.me", { step: "16", label: "Find the Graph /me tool in the runtime registry" });
  if (!gt) return { ok: false, stage: "tool registry", error: { description: 'no "graph.me" tool' }, hops };
  const t1 = await getT1(hops);
  if (!t1.ok) return { ok: false, stage: "T1", error: t1.error, hops };
  const o = await obo(hops, { t1: t1.tokens.access_token, userToken: inboundToken, resource: gt.resource, name: "LABSOBO_T_A1_OBO", step: "16",
                              label: "Exchange your token for a Graph token (OBO)", user: { oid: inbound.oid, name: inbound.name } });
  if (!o.ok) return { ok: false, stage: "OBO", error: o.error, hops };
  const me = await doHttp({ method: "GET", url: gt.endpoint,
                            headers: { Authorization: `Bearer ${o.tokens.access_token}` }, secretNames: { bearer: "LABSOBO_T_A1_OBO" } });
  const sameUser = me.ok && me.response.body?.id === inbound.oid;
  hops.push(hop({ from: "A1", to: "GRAPH", phase: "Phase 16", kind: "http", label: "Confirm with Graph who I am acting for", title: "Downstream call — GET /me as the user, performed by A1",
    request: me.request, response: me.response, verdict: me.ok ? (sameUser ? "allow" : "error") : "deny",
    summary: me.ok ? `Graph answered for ${me.response.body?.displayName} <${me.response.body?.userPrincipalName}> — ${sameUser ? "the same oid as the inbound user" : "a DIFFERENT principal than the inbound user"}.` : `Graph refused: HTTP ${me.response.status}` }));
  return { ok: me.ok && sameUser, stage: "done", downstream: me.response.body, hops };
}

// ---------------------------------------------------------------- steps 7-11 (+14): investigate
async function investigate(result, token, inbound, message, runId) {
  const user = { oid: inbound.oid, name: inbound.name, upn: inbound.upn, tid: inbound.tid };
  const plan = planInvestigation(message, { user, ids: { bp: cfg.bp.clientId, agent: cfg.agent.clientId } });
  result.plan = plan;
  if (plan.intent === "identity") {
    result.identity = { human: user.name, upn: user.upn, client: label(inbound.azp) ?? inbound.azp, roles: inbound.roles, agent: cfg.agent.name };
    return;
  }
  const t1 = await getT1(result.hops);
  if (!t1.ok) { result.error = { stage: "T1", detail: firstLine(t1.error) }; return; }
  const dtool = await resolveTool(result.hops, "defender.advanced_hunting", { step: "8", label: "Find the Defender tool in the runtime registry" });
  if (!dtool) { result.error = { stage: "tool registry", detail: 'no "defender.advanced_hunting" tool' }; return; }
  const dt = await obo(result.hops, { t1: t1.tokens.access_token, userToken: token, resource: dtool.resource, name: "T_A1_DEFENDER", step: "8",
                                      label: "Get T_A1_DEFENDER by OBO: Entra grants what an admin consented; you stay the user", user });
  if (!dt.ok) { result.error = { stage: "T_A1_DEFENDER", detail: firstLine(dt.error) }; return; }

  const hunt = await runHunt(dt.tokens.access_token, plan.kql, dtool.endpoint);
  result.hops.push(hop({ from: "A1", to: "DEFENDER", step: "10", kind: "http", label: `Run KQL on ${plan.table}, last ${plan.window}`,
    title: `POST ${dtool.endpoint} with T_A1_DEFENDER`, request: hunt.http.request, response: hunt.http.response,
    verdict: hunt.ok ? "allow" : "deny", summary: hunt.ok ? `${hunt.rowCount} rows in ${hunt.ms} ms, visible to ${user.name} under their own Defender permissions.` : `Defender: ${hunt.error}` }));
  const tri = triage(plan, hunt, user);
  result.hops.push(hop({ from: "A1", to: "A1", step: "11", kind: "local",
    label: tri.finding ? `Analyse: ${tri.finding.severity}, ${tri.finding.title}` : hunt.ok ? "Analyse: nothing matched" : "Analyse: the hunt failed",
    title: "Deterministic analysis of the rows", request: null, response: { status: 200, body: { finding: tri.finding, ticket: tri.needsTicket, reason: tri.reason } },
    verdict: "info", summary: tri.needsTicket ? `A Jira ticket is needed: ${tri.reason}.` : tri.reason ? `No ticket: ${tri.reason}.` : "No ticket asked for." }));
  result.investigation = { title: plan.title, table: plan.table, window: plan.window, query: plan.kql, columns: hunt.columns, rows: hunt.rows.slice(0, 100), rowCount: hunt.rowCount,
                           ms: hunt.ms, error: hunt.error, finding: tri.finding, summary: tri.summary, needsTicket: tri.needsTicket, reason: tri.reason };
  if (!tri.needsTicket) return;

  const j = await jiraLeg(result.hops, { t1: t1.tokens.access_token, userToken: token, user, issue: tri.issue,
    provenance: { executedBy: { name: cfg.agent.name, clientId: cfg.agent.clientId }, via: label(inbound.azp) ?? inbound.azp,
                  source: `Defender Advanced Hunting: ${plan.table}, last ${plan.window}`, query: plan.kql, runId: runId ?? null } });
  result.jira = j;
  if (j.status === "authorization_required") { result.status = "authorization_required"; result.resource = "jira"; }
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);
  if (req.method === "GET" && url.pathname === "/ping") return json(res, 200, { status: "Healthy", agent: cfg.agent.name, agentIdentityId: cfg.agent.clientId, t1: ON_AGENTCORE ? "aws-sts" : "certificate", policy });
  if (req.method === "GET" && url.pathname === "/policy") return json(res, 200, policy);
  if (req.method === "POST" && url.pathname === "/policy") {
    const b = await readBody(req);
    if (Array.isArray(b.allowedAzp)) policy.allowedAzp = b.allowedAzp;
    if (typeof b.enforceScope === "boolean") policy.enforceScope = b.enforceScope;
    return json(res, 200, policy);
  }
  if (req.method === "POST" && url.pathname === "/invocations") {
    const body = await readBody(req);
    const auth = req.headers.authorization ?? "";
    const token = auth.toLowerCase().startsWith("bearer ") ? auth.slice(7).trim() : null;
    const a = await authorize(token);
    const inboundHop = hop({
      from: "A1", to: "A1", step: "6", phase: "Phase 12", kind: "local",
      label: !a.ok ? `Token rejected: ${a.reason}` : ON_AGENTCORE ? "Read the forwarded T_APP_A1 (AgentCore already validated it)" : "Check T_APP_A1: aud, azp, roles, scp (local stand-in for AgentCore's authorizer)",
      title: `A1 runtime authorizer — ${a.ok ? "all claim checks pass" : "REJECTED: " + a.reason}`,
      request: { method: "POST", url: `http://localhost:${PORT}/invocations`, headers: { Authorization: auth, "Content-Type": "application/json" }, body, bodyType: "json" },
      response: { status: a.ok ? 200 : 401, body: { checks: a.checks, reason: a.reason ?? null } },
      tokens: token ? [summarizeToken("LABSOBO_T_APP_A1 (inbound)", token, { aud: policy.audience, role: policy.requiredRole, scp: policy.enforceScope ? policy.requiredScope : null })] : [],
      checks: a.checks, verdict: a.ok ? "allow" : "deny",
      summary: a.ok ? `Caller ${label(a.claims.azp) ?? a.claims.azp} presenting ${label(a.claims.oid) ?? a.claims.oid} with roles ${JSON.stringify(a.claims.roles)} — admitted.` : a.reason,
    });
    if (!a.ok) return json(res, 401, { status: "denied", reason: a.reason, checks: a.checks, hops: [inboundHop] });

    const mode = body?.mode ?? "echo";
    const inbound = { oid: a.claims.oid, tid: a.claims.tid, name: a.claims.name, upn: a.claims.preferred_username, azp: a.claims.azp, roles: a.claims.roles, scp: a.claims.scp };
    const result = { status: "agent1-reached", logicalAgent: cfg.agent.name, agentIdentityId: cfg.agent.clientId, runtime: ON_AGENTCORE ? "agentcore" : "local", mode, message: body?.message ?? null,
                     inbound: { user: { oid: inbound.oid, name: inbound.name, upn: inbound.upn }, client: inbound.azp, roles: inbound.roles, scp: inbound.scp, checks: a.checks },
                     hops: [inboundHop] };
    try {
      if (mode === "obo") {
        const o = await oboLeg(token, inbound);
        result.obo = { ok: o.ok, stage: o.stage, error: o.error ?? null, downstream: o.downstream ?? null, actor: cfg.agent.clientId, subject: inbound.oid };
        result.hops.push(...o.hops);
      }
      if (mode === "investigate") await investigate(result, token, inbound, body?.message, body?.trace_id);
    } catch (e) {
      result.error = { stage: "A1", detail: String(e?.message ?? e) };
      result.hops.push(hop({ from: "A1", to: "A1", kind: "note", label: `A1 error: ${e?.message ?? e}`, title: "A1 error", request: null, response: { status: 500, body: String(e?.stack ?? e) }, verdict: "error", summary: String(e?.message ?? e) }));
    }
    return json(res, 200, result);
  }
  json(res, 404, { error: "not found" });
});
server.listen(PORT, () => console.log(`labsOBO A1 listening on :${PORT}  T1 via ${ON_AGENTCORE ? "AWS STS workload JWT" : "blueprint certificate"}  tools from ${process.env.LABSOBO_TOOL_REGISTRY ?? env.LABSOBO_TOOL_REGISTRY ?? "(no registry configured)"}  audience=${cfg.bp.clientId} allowedAzp=${policy.allowedAzp.join(",")}`));
