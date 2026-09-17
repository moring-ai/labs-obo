# labsOBO — Setup & Access Playbook

> **Purpose**  
> Establish the control-plane objects, permissions, trust relationships, and ownership needed by the runtime flows.
>
> **This document is configuration only.**  
> Runtime token movement starts in the next playbook.

---

## 1. Target architecture

```text
RAJARAJAN
    │
    │ Entra sign-in / delegated authority
    ▼
labsOBO-calling-app
    │
    │ T_APP_A1
    ▼
BP-A1 / AgentCore boundary
    │
    │ executes as AGENT-A1
    ▼
AGENT-A1
    ├──────────────▶ Defender
    │                 delegated OBO
    │
    └──────────────▶ Credential Broker ─────▶ Jira
                      Entra OBO               Atlassian 3LO
```

The setup exists to support four separate trust statements:

| Trust | Meaning | Where it lives |
|---|---|---|
| User → Agent | RAJARAJAN is entitled to invoke A1 | BP-A1 app role assignment |
| App → Agent boundary | only the calling app may present the inbound delegated token | AgentCore JWT authorizer |
| AWS workload → Entra | the running AgentCore workload may authenticate BP-A1 / AGENT-A1 | AWS STS + BP-A1 FIC |
| Agent → downstream | AGENT-A1 may request delegated downstream tokens | Entra delegated permissions / admin consent |

Do not collapse these into one broad permission.

---

## 2. Control-plane ownership

| Area | Team must control |
|---|---|
| Microsoft Entra | app registrations, Agent Identity Blueprint, Agent Identity, app roles, delegated scopes, consent, FIC |
| Microsoft Graph | service principals, app-role assignments, `oauth2PermissionGrant`, FIC automation |
| AWS | execution role, outbound web identity federation, AgentCore runtime |
| Microsoft Defender XDR | delegated hunting permission, user Defender access |
| Atlassian | OAuth 2.0 (3LO) integration |
| Credential Broker | Atlassian client secret, per-user refresh token vault |
| Calling App | app private key / certificate, application session |
| Agent A1 | short-lived inbound / workload / downstream tokens only |

---

## 3. Core identities

### Human

```text
RAJARAJAN
oid = 2faa25c9-590d-4723-aebb-f39f819ce489
```

Negative-control user:

```text
SAM
```

SAM remains unassigned to `labsOBO.AgentInvoker`.

---

### Calling application

```text
Name      labsOBO-calling-app
Client ID 05d1bf77-a2e4-4c1c-9ef1-31dff291dd45
Type      confidential web application
```

Redirect:

```text
http://localhost:3100/auth/callback
```

Credential:

```text
preferred: certificate / private_key_jwt
lab alternative: client secret
```

The application is an OAuth client.

It is **not** the protected resource.

---

### Agent Identity Blueprint

```text
Name      labsOBO-agent1-blueprint
Client ID 5e5c2e3c-35b8-4817-8dc9-96b09adb6865
Alias     BP-A1
```

BP-A1 is both:

```text
1. inbound OAuth resource boundary for A1
2. parent identity object for AGENT-A1
```

Resource URI:

```text
api://5e5c2e3c-35b8-4817-8dc9-96b09adb6865
```

Delegated scope:

```text
labsOBO_access_agent
```

Token version:

```text
requestedAccessTokenVersion = 2
```

---

### Agent Identity

```text
Name  labsOBO-agent1
Alias AGENT-A1
```

Important:

```text
AGENT-A1 does not hold credentials.
```

Credential material belongs to the blueprint.

The source lab confirmed that attempting to place credentials directly on the Agent Identity produced:

```text
IncompatibleWithAgentIdentity
```

---

## 4. User entitlement model

Create app role on BP-A1:

```text
Display name  labsOBO Agent Invoker
Value         labsOBO.AgentInvoker
Member type   Users/Groups
```

Directory relationship:

```text
RAJARAJAN
    │
    │ appRoleAssignment
    │ labsOBO.AgentInvoker
    ▼
BP-A1
```

Enforcement property:

```text
appRoleAssignmentRequired = true
```

Expected delegated token for an entitled user:

```text
roles = ["labsOBO.AgentInvoker"]
```

Measured source-lab behavior:

```text
assignment removed
      ↓
Entra still issued a new BP-A1 token
      ↓
token had no roles claim
      ↓
AgentCore rejected it
```

Therefore the runtime check is mandatory:

```text
roles CONTAINS labsOBO.AgentInvoker
```

---

## 5. Calling app → BP-A1 permission

The calling application needs delegated permission:

```text
api://<BP-A1>/labsOBO_access_agent
```

Enterprise-lab model:

```text
admin consent       = pre-granted
user entitlement    = controlled by app-role assignment
```

Keep these separate:

| Control | Question |
|---|---|
| OAuth consent | may this client request the delegated scope? |
| App role | may this human invoke A1? |
| Assignment required | is explicit entitlement expected? |

---

## 6. AgentCore runtime boundary

Runtime:

```text
labsOBO_agent1_runtime
```

Execution role:

```text
labsOBO-agent1-execution-role
```

Inbound JWT checks:

```text
iss   trusted Entra tenant
aud   exact observed BP-A1 audience
azp   labsOBO-calling-app
scp   contains labsOBO_access_agent
roles contains labsOBO.AgentInvoker
```

Conceptual contract:

```json
{
  "aud": "5e5c2e3c-35b8-4817-8dc9-96b09adb6865",
  "azp": "05d1bf77-a2e4-4c1c-9ef1-31dff291dd45",
  "scp": "labsOBO_access_agent",
  "roles": [
    "labsOBO.AgentInvoker"
  ]
}
```

Observed source-lab result:

```text
wrong aud    → 401
wrong azp    → 401
missing role → 401
```

The inbound `Authorization` header is deliberately forwarded to A1 because A1 needs `T_APP_A1` for later OBO.

---

## 7. AWS → Entra workload federation

A1 uses the AgentCore execution role as its workload root of trust.

```text
AgentCore workload
      │
      │ sts:GetWebIdentityToken
      ▼
AWS STS
      │
      │ signed OIDC JWT
      ▼
Entra FIC on BP-A1
```

AWS assertion audience:

```text
api://AzureADTokenExchange
```

FIC contract:

```text
issuer   = AWS outbound federation issuer
subject  = exact A1 execution-role ARN
audience = api://AzureADTokenExchange
```

Example:

```json
{
  "issuer": "https://<id>.tokens.sts.global.api.aws",
  "subject": "arn:aws:iam::<account>:role/labsOBO-agent1-execution-role",
  "audiences": [
    "api://AzureADTokenExchange"
  ]
}
```

Use one execution role per agent.

Reason:

```text
AWS JWT sub = execution role ARN
```

Any workload capable of assuming that role inherits that workload identity.

---

## 8. Defender authorization

Delegated permission:

```text
AdvancedHunting.Read
```

Grant to:

```text
AGENT-A1
```

Not:

```text
calling app
BP-A1
```

Human-side Defender controls still apply:

```text
RAJARAJAN must have View Data
RAJARAJAN must have device / device-group access
```

The downstream call is therefore bounded by both:

```text
AGENT-A1 delegated scope
AND
RAJARAJAN Defender authority
```

---

## 9. Jira authorization domain

Jira does not consume Entra tokens.

Atlassian issues its own OAuth tokens.

```text
Entra domain                     Atlassian domain

RAJARAJAN                        RAJARAJAN
   │                                │
   ▼                                ▼
T_A1_BROKER_OBO               Atlassian 3LO grant
   │                                │
   └────────▶ Broker ◀───────────────┘
```

Atlassian integration:

```text
Name      labsOBO-security-investigation-agent
Callback  http://localhost:3100/oauth/jira/callback

Scopes
write:jira-work
offline_access
```

Broker Entra scope:

```text
api://<BROKER_CLIENT_ID>/labsOBO_jira.create
```

Broker trust contract:

```text
iss = trusted Entra tenant
aud = broker
oid = RAJARAJAN
azp = AGENT-A1
scp contains labsOBO_jira.create
AGENT-A1 allow-listed
```

Long-lived material belongs only in the broker:

```text
Atlassian client secret
Atlassian refresh token
```

---

## 10. Identifier rule

These are not interchangeable:

| ID | Meaning | Typical use |
|---|---|---|
| Client ID / `appId` | OAuth identity | `client_id`, `aud`, `azp` |
| Application Object ID | application directory object | application configuration |
| Service Principal Object ID | tenant-local principal | assignments, consent |

---

## 11. Secrets rule

Safe to document:

```text
tenant ID
client ID
object ID
role ID
resource URI
scope name
```

Do not document:

```text
private key
client secret
authorization code
access token
refresh token
AWS temporary credentials
```

---

## 12. Setup output

At the end of setup, the runtime playbooks assume these objects exist:

```text
RAJARAJAN
SAM

labsOBO-calling-app

BP-A1
  ├─ labsOBO_access_agent
  ├─ labsOBO.AgentInvoker
  └─ FIC trusting A1 execution role

AGENT-A1

AgentCore runtime
A1 execution role

Defender delegated grant to AGENT-A1

Credential Broker
Atlassian 3LO app
```

---

## References

- https://learn.microsoft.com/en-us/entra/agent-id/
- https://learn.microsoft.com/en-us/entra/agent-id/create-blueprint
- https://learn.microsoft.com/en-us/entra/agent-id/create-delete-agent-identities
- https://learn.microsoft.com/en-us/entra/agent-id/control-user-access-agents
- https://learn.microsoft.com/en-us/entra/identity-platform/howto-add-app-roles-in-apps
- https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation
- https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/inbound-jwt-authorizer.html
- https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_outbound_getting_started.html
- https://learn.microsoft.com/en-us/defender-xdr/api-create-app-user
- https://developer.atlassian.com/cloud/jira/platform/oauth-2-3lo-apps/
