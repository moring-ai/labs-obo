/**
 * labsOBO | A1 as a LOCAL runtime (http://localhost:3101).
 *
 * Mirrors what the AgentCore JWT authorizer does in front of the container:
 *   signature + issuer + expiry (tenant JWKS)      <- discoveryUrl
 *   aud   == BP-A1 client id                        <- allowedAudience
 *   azp   IN  allowedAzp (default: APP only)        <- customClaims azp EQUALS
 *   roles CONTAINS labsOBO.AgentInvoker             <- customClaims roles CONTAINS
 *   scp   CONTAINS labsOBO_access_agent (optional)  <- extra, the plan's "optionally also enforce"
 *
 * Then, in mode=obo, does what a real A1 would do next (Phase 16):
 *   T1   blueprint certificate + fmi_path=<A1>  -> exchange credential
 *   OBO  client_id=A1, client_assertion=T1, assertion=<inbound user token>
 *   GET  https://graph.microsoft.com/v1.0/me with the OBO token  (the downstream call)
 *
 * Every step is returned as a hop so the calling app can splice it into one timeline.
 */
import { createServer } from "node:http";
import { randomUUID } from "node:crypto";
import { cfg, verify, summarizeToken, tokenRequest, doHttp, clientAssertion, ASSERTION_TYPE, label } from "../../lib/entra.mjs";

const PORT = Number(process.env.PORT ?? cfg.ports.agent);
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

async function oboLeg(inboundToken, inbound) {
  const hops = [];
  // T1 — the blueprint proves itself; fmi_path names the child agent.
  const { assertion, info } = await clientAssertion({ clientId: cfg.bp.clientId, keyPath: cfg.agent.bpKeyPath, certPath: cfg.agent.bpCertPath });
  const t1 = await tokenRequest({
    grant_type: "client_credentials", client_id: cfg.bp.clientId,
    scope: "api://AzureADTokenExchange/.default", fmi_path: cfg.agent.clientId,
    client_assertion_type: ASSERTION_TYPE, client_assertion: assertion,
  }, { secretNames: { client_assertion: "LABSOBO_BP_A1_ASSERTION" } });
  hops.push(hop({
    from: "A1", to: "ENTRA", phase: "Phase 16", kind: "http",
    title: "T1 — blueprint credential + fmi_path=A1 → exchange credential for the agent",
    request: t1.request, response: t1.response,
    tokens: t1.tokens ? [summarizeToken("LABSOBO_T1_A1", t1.tokens.access_token, { azp: cfg.bp.clientId, aud: cfg.tokenExchangeAppId })] : [],
    verdict: t1.ok ? "allow" : "error",
    summary: t1.ok ? "Entra issued T1: aud=AzureADTokenExchange, azp=BP-A1. This is a credential for A1, not a resource token."
                   : `T1 refused: ${t1.error?.code ?? ""} ${t1.error?.description ?? ""}`,
    note: `client assertion: ${info.alg}, x5t=${info.x5t}, iss=sub=BP-A1, aud=token endpoint`,
  }));
  if (!t1.ok) return { ok: false, stage: "T1", error: t1.error, hops };

  // OBO — A1 acts for the user: its own credential is T1, the user assertion is the inbound token.
  const obo = await tokenRequest({
    grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
    client_id: cfg.agent.clientId,
    client_assertion_type: ASSERTION_TYPE, client_assertion: t1.tokens.access_token,
    assertion: inboundToken, requested_token_use: "on_behalf_of",
    scope: cfg.agent.downstreamScope,
  }, { secretNames: { client_assertion: "LABSOBO_T1_A1", assertion: "LABSOBO_T_APP_A1" } });
  hops.push(hop({
    from: "A1", to: "ENTRA", phase: "Phase 16", kind: "http",
    title: "OBO — A1 exchanges the user's token for a downstream token (Microsoft Graph)",
    request: obo.request, response: obo.response,
    tokens: obo.tokens ? [summarizeToken("LABSOBO_T_A1_OBO", obo.tokens.access_token, { oid: inbound.oid, azp: cfg.agent.clientId, aud: cfg.graphAppId, scp: "User.Read" })] : [],
    verdict: obo.ok ? "allow" : "deny",
    summary: obo.ok ? `Entra issued T_A1_OBO: oid=${label(inbound.oid) ?? inbound.oid} (the user survives), azp=AGENT-A1 (the agent is acting), aud=Microsoft Graph.`
                    : `OBO refused: ${obo.error?.code ?? ""} ${obo.error?.description ?? ""}`,
  }));
  if (!obo.ok) return { ok: false, stage: "OBO", error: obo.error, hops };

  // Downstream — the proof that the delegated token works for THIS user.
  const me = await doHttp({ method: "GET", url: "https://graph.microsoft.com/v1.0/me?$select=id,displayName,userPrincipalName",
                            headers: { Authorization: `Bearer ${obo.tokens.access_token}` }, secretNames: { bearer: "LABSOBO_T_A1_OBO" } });
  const sameUser = me.ok && me.response.body?.id === inbound.oid;
  hops.push(hop({
    from: "A1", to: "GRAPH", phase: "Phase 16", kind: "http",
    title: "Downstream call — GET /me as the user, performed by A1",
    request: me.request, response: me.response,
    verdict: me.ok ? (sameUser ? "allow" : "error") : "deny",
    summary: me.ok ? `Graph answered for ${me.response.body?.displayName} <${me.response.body?.userPrincipalName}> — ${sameUser ? "the same oid as the inbound user" : "a DIFFERENT principal than the inbound user"}.`
                   : `Graph refused: HTTP ${me.response.status}`,
  }));
  return { ok: me.ok && sameUser, stage: "done", downstream: me.response.body, hops };
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);
  if (req.method === "GET" && url.pathname === "/ping") return json(res, 200, { status: "Healthy", agent: cfg.agent.name, agentIdentityId: cfg.agent.clientId, policy });
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
      from: "A1", to: "A1", phase: "Phase 12", kind: "local",
      title: `A1 runtime authorizer — ${a.ok ? "all claim checks pass" : "REJECTED: " + a.reason}`,
      request: { method: "POST", url: `http://localhost:${PORT}/invocations`, headers: { Authorization: auth, "Content-Type": "application/json" }, body, bodyType: "json" },
      response: { status: a.ok ? 200 : 401, body: { checks: a.checks, reason: a.reason ?? null } },
      tokens: token ? [summarizeToken("LABSOBO_T_APP_A1 (inbound)", token, { aud: policy.audience, role: policy.requiredRole, scp: policy.enforceScope ? policy.requiredScope : null })] : [],
      checks: a.checks, verdict: a.ok ? "allow" : "deny",
      summary: a.ok ? `Caller ${label(a.claims.azp) ?? a.claims.azp} presenting ${label(a.claims.oid) ?? a.claims.oid} with roles ${JSON.stringify(a.claims.roles)} — admitted.` : a.reason,
    });
    if (!a.ok) return json(res, 401, { status: "denied", reason: a.reason, checks: a.checks, hops: [inboundHop] });

    const mode = body?.mode ?? "echo";
    const inbound = { oid: a.claims.oid, name: a.claims.name, upn: a.claims.preferred_username, azp: a.claims.azp, roles: a.claims.roles, scp: a.claims.scp };
    const result = { status: "agent1-reached", logicalAgent: cfg.agent.name, agentIdentityId: cfg.agent.clientId, mode, message: body?.message ?? null,
                     inbound: { user: { oid: inbound.oid, name: inbound.name, upn: inbound.upn }, client: inbound.azp, roles: inbound.roles, scp: inbound.scp, checks: a.checks },
                     hops: [inboundHop] };
    if (mode === "obo") {
      const o = await oboLeg(token, inbound);
      result.obo = { ok: o.ok, stage: o.stage, error: o.error ?? null, downstream: o.downstream ?? null, actor: cfg.agent.clientId, subject: inbound.oid };
      result.hops.push(...o.hops);
    }
    return json(res, 200, result);
  }
  json(res, 404, { error: "not found" });
});
server.listen(PORT, () => console.log(`labsOBO A1 (local runtime) listening on http://localhost:${PORT}  audience=${cfg.bp.clientId} allowedAzp=${policy.allowedAzp.join(",")}`));
