# labsOBO — test results (2026-09-09)

Evidence is the recorded run (`.lab/traces/<id>.json`; open it in the UI with `/?run=<id>`).
"Measured in this lab" means the request and response are in that file.

| Id | Scenario | Directory at request | Outcome | Run(s) |
|---|---|---|---|---|
| T01 | ALEX via APP, agent scope at `/authorize` | required=true, alex=assigned | token issued, `roles=[labsOBO.AgentInvoker]` | 033, 036→041 |
| T01 (two-step) | ALEX via APP, OIDC first then refresh_token → agent scope | same | token issued with the role | 009, 014 |
| T02 | SAM via APP | required=true, sam=unassigned | **not run** (needs Rajan at the keyboard) | — |
| T03 | ALEX, assignment removed, brand-new token | required=true, alex=unassigned | issued, `roles` absent — no AADSTS50105 | 028, 029 (Azure CLI), 035 (refresh), 036 (auth code) |
| T04 | SAM assigned then token | — | not run | — |
| T05 | ALEX token with `azp` = Azure CLI → runtimes (policy: APP only) | assigned | local A1 401 `azp`; AgentCore 401 `Authorization denied` | 020, 021 |
| T06 | Graph-audience token → runtimes | assigned | local A1 401 (signature/aud); AgentCore 401 | 025, 026 |
| T07 | ALEX via another client (Azure CLI, pre-authorized) | assigned | token issued with the role, `azp` differs | 019 |
| T09 | role-less ALEX token → runtimes | unassigned | local A1 401 `roles`; AgentCore 401 | 037, 038 |
| T12 | ALEX APP token → local A1 / AgentCore | assigned | HTTP 200 both; AgentCore container echoed `roleSatisfied: true` | 022, 023 |
| T08 | local A1: T1 → OBO → Graph `/me` | assigned | `T_A1_OBO` `oid`=ALEX `azp`=A1; Graph answers as Balaji | 024 |
| CONSENT | admin grant revoked, ALEX signs in | assigned | consent screen shown; Cancel → `consent_required` AADSTS65004; grant restored | 042, 043, 044 |
| CTRL | ordinary API, `appRoleAssignmentRequired=true`, ALEX not assigned | — | token issued, `roles` absent | 045 |
| Phase 6 | directory proof | — | `appRoleAssignmentRequired=true`; ALEX assigned; SAM not; admin consents present | `.lab/phase6-directory.txt` |

Final state left in the tenant and account: `appRoleAssignmentRequired=true`; ALEX assigned,
SAM not; admin consent APP → `labsOBO_access_agent` present; AgentCore authorizer `azp` = APP;
local A1 policy = APP only. Extra objects created for the experiments and kept:
`labsOBO-control-api` (control), the Azure CLI pre-authorization on BP-A1's scope.

Runs 001–008 and 010–013 were produced by a first version of the pre-flight script with a
JSON quoting bug (bodies arrived empty); they are harmless duplicates and were superseded.
