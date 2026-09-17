# labsOBO — findings

Measured 2026-09-09 in the MoringAI tenant. Every statement below has a recorded request
and response behind it (`.lab/traces/<run>.json`, visible in the UI at :3100). Role names
are used throughout; the real ids are in `.lab/labsOBO.env`.

## 1. The token does carry the user ↔ agent authorization — when the assignment exists

With ALEX assigned `labsOBO.AgentInvoker` on BP-A1 and `appRoleAssignmentRequired=true`
on the blueprint principal, the calling app obtained, through the browser and a
certificate-authenticated code redemption (runs 033, 036→041):

```
aud    BP-A1 client id            which agent API boundary   (v2 token: the GUID, not api://)
oid    ALEX                       which human
azp    APP                        which OAuth client
scp    labsOBO_access_agent       what delegated operation was consented
roles  ["labsOBO.AgentInvoker"]   the app-role assignment, emitted by Entra
```

The same token was admitted by the local A1 authorizer and by the Bedrock AgentCore JWT
authorizer (`allowedAudience` = BP-A1, `azp EQUALS APP`, `roles CONTAINS
labsOBO.AgentInvoker`); the container ran and echoed the checks it saw (run 023, HTTP 200,
execution role `labsOBO-Agent1ExecutionRole`).

## 2. Entra did NOT refuse the unassigned user; it issued the token without `roles`

This is the result that contradicts the plan, and it is the most important one.

ALEX's assignment was removed (Graph `DELETE …/appRoleAssignments/<id>`, HTTP 204) and a
**brand-new** token was requested. Four flows, same answer:

| flow | client | result |
|---|---|---|
| Azure CLI (`az account get-access-token --scope api://BP-A1/labsOBO_access_agent`) | Azure CLI | issued, `roles` absent (runs 028, 029 — 32 s and 94 s after the DELETE) |
| refresh_token → agent scope | APP | issued, `roles` absent (run 035) |
| authorization_code with the agent scope at `/authorize` | APP | code returned, token issued, `roles` absent (run 036) |
| the same, against an ordinary API registration with the same setup (CONTROL) | APP | issued, `roles` absent (run 045) |

No AADSTS50105 anywhere. The tokens were freshly issued: Entra backdates `iat` by 300 s,
and `iat + 300` lands seconds after the request, with `roles` already gone — so the token
service saw the removal and still issued.

What denied the call was the **runtime**: the local A1 mirror and AgentCore both returned
401 for the role-less token (runs 037, 038; AgentCore: `Authorization denied`,
`x-amzn-errortype: UnrecognizedClientException`, no container started).

So in this tenant the plan's line "Sam authenticated ✅ / Sam entitled ❌ → NO TOKEN"
holds only as "no **usable** token": Entra encodes the entitlement in `roles`, and the
resource must enforce it. `appRoleAssignmentRequired=true` on the blueprint principal did
not change token issuance for a delegated request from a separate client app.

What is *not* yet measured, and could change this picture:

- a non-admin user. ALEX is a Global Administrator; SAM (Rajan) has not signed in yet.
  "Sign in as SAM via APP" in the UI is the test.
- the v1 token endpoint (`requestedAccessTokenVersion: 2` was used throughout).
- a Conditional Access policy targeting BP-A1 as the resource — the Entra-side mechanism
  that *would* block at `/authorize`, independent of app roles.

Re-assigning ALEX (Graph `POST …/appRoleAssignments`, HTTP 201) and requesting a new
token restored `roles` (run 041).

## 3. The APP is not what maps ALEX to A1

The Azure CLI, pre-authorized on the blueprint's scope, obtained a BP-A1 token for ALEX
with `azp` = Azure CLI and the same `roles` (run 019). The assignment did not change; only
the client did. The runtime then rejected that token on `azp` alone (runs 020, 021),
which is the policy in the plan: the *mapping* lives in Entra, the *allowed caller* is
the resource's decision.

## 4. Consent is a separate question, and it was simulated explicitly

Tenant policy: `ManagePermissionGrantsForSelf.microsoft-user-default-recommended` plus
`…-allow-consent-apps` (users may consent to tenant apps for low-impact permissions).

- Case A (admin consent, `oauth2PermissionGrant` with `consentType=AllPrincipals`): every
  sign-in went straight from the account picker to the callback. No consent screen.
- Case B: with the admin grant revoked (run 042), the same `/authorize` showed
  "Permissions requested (1 of 2 apps) — labsOBO-calling-app would like to: Invoke labsOBO
  Agent A1 on your behalf (labsOBO-agent1-blueprint); View your basic profile; Maintain
  access to data you have given it access to". Cancel returned
  `error=consent_required, AADSTS65004` to the callback (run 043). Nobody accepted; the
  admin grant was restored (run 044).
- Case C ("Need admin approval") was not observed because the operator is an admin; it
  is what a non-admin user should see for a custom API scope under this policy. Untested.

The UI has buttons for revoke / restore so the case can be replayed with SAM.

## 5. Phase 16: the agent acting for ALEX

The local A1 minted T1 (blueprint certificate, `fmi_path` = A1, `aud` = AzureADTokenExchange,
`azp` = BP-A1), exchanged ALEX's inbound token with the OBO grant (`client_id` = A1,
`client_assertion` = T1), and called `GET /me` (run 024):

```
T_A1_OBO   aud = Microsoft Graph   azp = AGENT-A1   oid = ALEX   scp = User.Read
Graph /me  → Balaji Nagaraj Kumar (same oid as the inbound token)
```

Consent for the downstream scope had to be written against the agent identity's own
service principal, as in the earlier lab.

## 6. Smaller things worth knowing

- An `agentIdentityBlueprint` and an `agentIdentity` are created with **object id ==
  appId** (the same GUID); ordinary applications get two different ids.
- beta names the pre-authorization field `permissionIds`; v1.0 names it
  `delegatedPermissionIds`. The blueprint accepted `preAuthorizedApplications` on beta.
- The v2 token endpoint issues one resource per request: asking for `User.Read` together
  with the agent scope returns a Graph token, not a BP-A1 token. The lab's single-step
  mode therefore requests only the agent scope at redemption and fetches a Graph token
  separately (visible as its own hop).
- The Azure CLI caches access tokens by the literal scope string. A "brand-new token" test
  through the CLI needs a different spelling of the same resource, or it silently returns
  the cached token (run 031 was exactly that and is marked as such).
- AgentCore's authorizer rejects before any container starts: the 401s carry
  `www-authenticate: Bearer resource_metadata=…/.well-known/oauth-protected-resource`.
