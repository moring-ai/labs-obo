# labsOBO — who may invoke Agent A1?

A local lab that proves, hop by hop, how Microsoft Entra app-role assignment on an
**agent identity blueprint** decides which human may invoke an agent, and where that
decision is actually enforced. Every OAuth call, Graph call, agent invocation and its
response is recorded and shown in a small UI at <http://localhost:3100>.

Built and measured on 2026-09-09 against the MoringAI tenant and AWS account 603011031216.
Nothing in this lab is simulated: every hop in the UI is a real request with its real response.

## The cast

| Role | Real object | Notes |
|---|---|---|
| ALEX (entitled) | Balaji Nagaraj Kumar (the operator, tenant admin) | assigned `labsOBO.AgentInvoker` on BP-A1 |
| SAM (not entitled) | Rajan | **not** assigned |
| APP | `labsOBO-calling-app` | confidential client, certificate assertion, redirect `http://localhost:3100/auth/callback` |
| DIRECT | `labsOBO-direct-client` | public client (PKCE only), Phase 15 contrast |
| BP-A1 | `labsOBO-agent1-blueprint` | agent identity blueprint; exposes `labsOBO_access_agent`; publishes app role `labsOBO.AgentInvoker`; `appRoleAssignmentRequired=true` |
| A1 | `labsOBO-agent1` | agent identity under BP-A1 (used for the OBO leg) |
| A1 runtime (local) | `agents/agent1-local` on :3101 | mirrors the AgentCore JWT authorizer, then does T1 → OBO → Graph `/me` |
| A1 runtime (AWS) | `labsOBO_agent1_runtime` (Bedrock AgentCore, us-east-1) | JWT authorizer: `aud` = BP-A1, `azp` = APP, `roles CONTAINS labsOBO.AgentInvoker` |
| CONTROL | `labsOBO-control-api` | an ordinary API registration with the same assignment-required setup, for comparison |

All ids live in `.lab/labsOBO.env` (the `LABSOBO_*` names from the plan) and `.lab/lab-state.json`.

## Run it

```bash
cd labsOBO
node agents/agent1-local/server.mjs      # local A1 runtime, :3101
node apps/calling-app/server.mjs         # calling app + UI, :3100
open http://localhost:3100
```

Prerequisites: `az login` as a tenant admin (the app borrows Graph tokens from that session
for the directory reads/writes), and `aws sso login` for the AgentCore hops.

Provisioning is idempotent and already done; re-run only if objects are missing:

```bash
./scripts/10-entra-provision.sh    # Phases 1-7 (+ direct client, agent identity, consents)
./scripts/20-verify-directory.sh   # Phase 6 proof from Graph
./scripts/40-create-runtime.sh     # AgentCore runtime (Phase 12)
./tests/run-preflight.sh           # the autonomous suite (no browser)
python3 tests/show-runs.py         # print every recorded run + the matrix
```

## What the UI shows

Left: who is signed in, the sign-in buttons (Alex / Sam, via APP or DIRECT), the
"then" actions (fresh token, invoke local A1, invoke with OBO, invoke AgentCore, wrong
audience), the directory admin actions (remove/add assignments, toggle
`appRoleAssignmentRequired`, revoke/restore consent), the local A1 policy, and the
test matrix filled from real evidence. Right: the selected run as a numbered timeline of
hops — request (method, URL, headers, body), the equivalent `curl`, the response
(status, headers, body), and every token decoded with the five claims that matter
(`oid`, `azp`, `aud`, `scp`, `roles`) checked against what this situation requires.

Tokens and codes are redacted until "reveal tokens & codes" is ticked.

## Measured results

| Test | Expected by the plan | Measured (run ids in `.lab/traces`) |
|---|---|---|
| T01 Alex, assigned, via APP | token with `roles=[labsOBO.AgentInvoker]` | **pass** — runs 009, 033, 036→041: `oid`=Alex, `azp`=APP, `aud`=BP-A1, `scp`, `roles` all present |
| T02 Sam, not assigned, via APP | denied | **not yet run** — needs Rajan at the keyboard ("Sign in as SAM via APP") |
| T03 Alex after role removed | new token denied (AADSTS50105) | **issued without the role** — runs 028/029 (Azure CLI), 035 (refresh_token), 036 (authorization_code): Entra issued, `roles` absent |
| T04 Sam after role added | token issued | not yet run (needs Rajan) |
| T05 Alex, wrong client | rejected on `azp` | **pass** — local A1 401 (run 020), AgentCore 401 (run 021) |
| T06 Alex, wrong audience | rejected on `aud` | **pass** — local A1 401 (run 025), AgentCore 401 (run 026) |
| T07 Alex via a different client | token issued, assignment unchanged | **pass** for the Azure CLI client (run 019); the DIRECT browser client is wired but not yet clicked |
| T09 token without the role → runtime | rejected on `roles` | **pass** — local A1 401 (run 037), AgentCore 401 (run 038) |
| T12 Alex token → runtime | HTTP 200 | **pass** — local A1 (run 022), AgentCore container ran and echoed the checks (run 023) |
| T08 A1 OBO downstream | `oid`=Alex, `azp`=A1, Graph answers as Alex | **pass** — run 024: T1 → OBO → `GET /me` returns Balaji |
| CONSENT | Case A/B/C | with admin consent: no screen (every run). Admin grant revoked: Entra showed the consent screen listing "Invoke labsOBO Agent A1 on your behalf (labsOBO-agent1-blueprint)"; Cancel → `consent_required / AADSTS65004` (run 043) |
| CTRL ordinary API, assignment required, not assigned | baseline | **issued without the role** (run 045) — same as the blueprint |

The one result that contradicts the plan is T03 (and therefore what T02 will show):
see `docs/findings.md`. The short version: in this tenant Entra did not refuse the
unassigned user; it issued the token with the `roles` claim absent, and the runtime's
`roles CONTAINS labsOBO.AgentInvoker` check is what denied the call.

## Layout

```
scripts/     10-entra-provision.sh  20-verify-directory.sh  40-create-runtime.sh  45-set-authorizer-azp.sh  lib.sh
apps/calling-app/   server.mjs (OAuth client, hop recorder, admin ops)   public/index.html (the UI)
agents/agent1-local/server.mjs   local A1 runtime: authorizer mirror + T1/OBO/Graph
lib/entra.mjs        shared: config, client assertion, PKCE, JWKS verify, curl rendering, redaction
infra/entra/certs/   APP and BP-A1 certificates (gitignored)     infra/aws/   runtime config + IAM
tests/               run-preflight.sh (autonomous suite), show-runs.py
docs/                findings.md, test-results.md
.lab/                labsOBO.env, lab-state.json, traces/ (every run), tokens/, sessions.json (gitignored)
```
