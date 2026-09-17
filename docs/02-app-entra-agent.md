# labsOBO — Calling App → Entra / Agent Boundary → AGENT-A1

> **Boundary**  
> The human-bound token enters the agent runtime, and the executing workload independently proves which agent it is.
>
> **Input**  
> `T_APP_A1`
>
> **Output**  
> `T1`

---

## 1. Two proofs enter this boundary

```text
T_APP_A1
= human + calling-app proof

AWS workload assertion
= executing-workload proof
```

They solve different problems.

```text
T_APP_A1 answers:
Who initiated this?
Which app called?
Is the user entitled?

AWS workload assertion answers:
Which AWS workload is actually executing?
```

---

## 2. Full sequence

```text
CALLING APP
    │
    │ Bearer T_APP_A1
    ▼
AGENTCORE JWT AUTHORIZER
    │
    │ validate:
    │ iss / aud / azp / scp / roles
    ▼
A1 STARTS
    │
    │ propagated T_APP_A1
    │
    ├────────────────────────────────────┐
    │                                    │
    │ sts:GetWebIdentityToken            │
    ▼                                    │
AWS STS                                  │
    │                                    │
    │ AWS signed OIDC assertion          │
    ▼                                    │
ENTRA                                    │
    │                                    │
    │ FIC match + fmi_path               │
    ▼                                    │
T1                                       │
                                         │
A1 now holds: T_APP_A1 + T1 ◀────────────┘
```

---

## 3. App invokes AgentCore

Representation:

```bash
curl -X POST \
  "${LABSOBO_AGENTCORE_INVOKE_URL}" \
  -H "Authorization: Bearer ${LABSOBO_T_APP_A1}" \
  -H "Content-Type: application/json" \
  -H "X-Amzn-Bedrock-AgentCore-Runtime-Session-Id: labsOBO-<session>" \
  -d '{
    "workflow_id": "labsOBO-WF-9281",
    "prompt": "Analyze Defender for suspicious PowerShell activity"
  }'
```

Identity does **not** come from the body.

Trusted:

```text
Authorization: Bearer T_APP_A1
```

Untrusted for identity:

```json
{
  "workflow_id": "...",
  "prompt": "..."
}
```

---

## 4. AgentCore authorization contract

AgentCore validates before A1 executes.

```text
signature valid
issuer trusted
token not expired

aud   = BP-A1
azp   = labsOBO-calling-app
scp   contains labsOBO_access_agent
roles contains labsOBO.AgentInvoker
```

Conceptual token:

```json
{
  "oid": "RAJARAJAN",
  "azp": "labsOBO-calling-app",
  "aud": "BP-A1",
  "scp": "labsOBO_access_agent",
  "roles": [
    "labsOBO.AgentInvoker"
  ]
}
```

Measured source-lab failures:

```text
wrong aud    → 401 Authorization denied
wrong azp    → 401 Authorization denied
missing role → 401 Authorization denied
```

---

## 5. Why `azp` is explicitly checked

The observed Entra v2 token identifies the authorized client with:

```text
azp
```

The source lab therefore used a custom claim check for:

```text
azp = labsOBO-calling-app
```

rather than assuming an inbound `client_id` claim exists.

---

## 6. Propagate `T_APP_A1`

AgentCore validates the bearer token first.

A1 then needs that same token for downstream OBO.

Header allowlist:

```json
{
  "requestHeaderConfiguration": {
    "requestHeaderAllowlist": [
      "Authorization"
    ]
  }
}
```

Inside A1:

```python
auth_header = context.request_headers.get("Authorization")
t_app_a1 = auth_header.removeprefix("Bearer ").strip()
```

At this point:

```text
A1 has the user proof.
A1 still needs its own workload proof.
```

---

# WORKLOAD PROOF

## 7. A1 asks AWS STS to attest the workload

```bash
aws sts get-web-identity-token \
  --region "${LABSOBO_AWS_REGION}" \
  --audience "api://AzureADTokenExchange" \
  --signing-algorithm RS256 \
  --duration-seconds 300
```

Conceptual assertion:

```json
{
  "iss": "https://<aws-issuer>.tokens.sts.global.api.aws",
  "sub": "arn:aws:iam::<account>:role/labsOBO-agent1-execution-role",
  "aud": "api://AzureADTokenExchange",
  "exp": "<short-lived>"
}
```

Meaning:

```text
AWS STS cryptographically certifies the IAM execution principal.
```

---

## 8. This is not AgentCore WorkloadAccessToken

Do not confuse:

```text
AgentCore WorkloadAccessToken
```

with:

```text
AWS STS GetWebIdentityToken JWT
```

Source-lab finding:

```text
GetWorkloadAccessToken was refused from inside the runtime.
```

The usable external federation proof in this design is:

```text
AWS STS signed OIDC JWT
```

---

## 9. Entra FIC validation

BP-A1 has a Federated Identity Credential containing:

```text
issuer   = AWS OIDC issuer
subject  = exact A1 execution role ARN
audience = api://AzureADTokenExchange
```

Entra validates:

```text
AWS JWT signature
iss exact match
sub exact match
aud exact match
```

This establishes:

```text
this exact AWS role may authenticate the BP-A1 trust root
```

---

## 10. Exchange AWS proof for `T1`

```bash
curl -X POST \
  "https://login.microsoftonline.com/${LABSOBO_TENANT_ID}/oauth2/v2.0/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "client_id=${LABSOBO_BP_A1_CLIENT_ID}" \
  --data-urlencode "grant_type=client_credentials" \
  --data-urlencode "scope=api://AzureADTokenExchange/.default" \
  --data-urlencode "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
  --data-urlencode "client_assertion=${LABSOBO_AWS_ASSERTION}" \
  --data-urlencode "fmi_path=${LABSOBO_AGENT_A1_CLIENT_ID}"
```

Parameter meaning:

| Parameter | Meaning |
|---|---|
| `client_id=BP-A1` | blueprint trust root authenticating |
| `client_assertion` | AWS workload proof |
| `fmi_path=AGENT-A1` | bind acquisition to child agent |
| token-exchange scope | obtain agent authentication proof, not a resource token |

`fmi_path` is critical.

Without the child-agent binding, the result is not the intended AGENT-A1 proof.

---

## 11. `T1` response

```json
{
  "token_type": "Bearer",
  "expires_in": 3599,
  "access_token": "<T1>"
}
```

`T1` is not:

```text
a Defender token
a Jira token
a user token
```

It is:

```text
AGENT-A1 authentication proof for the next Entra exchange
```

Observed source-lab shape:

```text
aud    AzureADTokenExchange resource
azp    BP-A1
sub    FMI path ending in AGENT-A1 client ID
idtyp  app
```

---

## 12. Boundary result

A1 now holds two independent proofs:

```text
T_APP_A1
OID = RAJARAJAN
AZP = Calling App
AUD = BP-A1

T1
Agent binding = AGENT-A1
Workload root = A1 execution role
```

This is the key precondition for OBO.

```text
human proof + agent proof
```

---

## 13. Failure map

| Failure | Meaning |
|---|---|
| AgentCore wrong `aud` | token not intended for BP-A1 |
| AgentCore wrong `azp` | wrong calling application |
| missing role | human is not entitled |
| `GetWebIdentityToken` denied | execution role / AWS outbound federation problem |
| FIC issuer mismatch | wrong AWS issuer |
| FIC subject mismatch | wrong execution role |
| FIC audience mismatch | wrong exchange audience |
| wrong `fmi_path` | child Agent Identity binding fails |

---

## 14. Handoff to downstream playbooks

A1 now has:

```text
T_APP_A1 = human proof
T1       = agent proof
```

Downstream OBO combines them.

```text
T_APP_A1 + T1
        ↓
      Entra
        ↓
resource-specific delegated token
```

---

## References

- https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/inbound-jwt-authorizer.html
- https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-header-allowlist.html
- https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_outbound_getting_started.html
- https://docs.aws.amazon.com/STS/latest/APIReference/API_GetWebIdentityToken.html
- https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation-create-trust
- https://learn.microsoft.com/en-us/entra/agent-id/agent-autonomous-app-oauth-flow
