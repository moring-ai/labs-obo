# labsOBO — AGENT-A1 → Jira

> **Boundary**  
> A1 crosses from the Entra identity domain into Atlassian's OAuth domain.
>
> **Input**  
> `T_APP_A1` + `T1`
>
> **Output**  
> Jira issue created under RAJARAJAN's Atlassian authority, with agent provenance recorded separately.

---

## 1. The key constraint

Jira is not an Entra-protected resource.

```text
Entra cannot mint a Jira access token.

Atlassian does not understand:
T_APP_A1
T1
AGENT-A1 Entra identity
```

Therefore the architecture needs a broker.

---

## 2. Trust bridge

```text
                    ENTRA DOMAIN

T_APP_A1 + T1
      │
      ▼
     Entra
      │
      │ OBO
      ▼
T_A1_BROKER_OBO
OID = RAJARAJAN
AZP = AGENT-A1
      │
      ▼
CREDENTIAL BROKER
      │
      │ resolve immutable user identity
      │ tid + oid
      │
      ├──────── no Atlassian grant ───────▶ browser consent
      │
      └──────── existing grant ───────────▶ use / refresh token

                 ATLASSIAN DOMAIN

JIRA_AT_RAJARAJAN
      │
      ▼
     Jira
```

---

## 3. Why the broker exists

Without a broker, A1 would need to hold:

```text
Atlassian client secret
every user's Atlassian refresh token
```

That violates the runtime trust model.

A1 should hold only:

```text
short-lived access tokens
short-lived Entra proofs
```

The broker holds:

```text
Atlassian client secret
per-user access token
per-user refresh token
cloudId
grant metadata
```

---

## 4. Entra side: A1 → Broker OBO

Target broker scope:

```text
api://<BROKER_CLIENT_ID>/labsOBO_jira.create
```

OBO request:

```bash
curl -X POST \
  "https://login.microsoftonline.com/${LABSOBO_TENANT_ID}/oauth2/v2.0/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "client_id=${LABSOBO_AGENT_A1_CLIENT_ID}" \
  --data-urlencode "scope=api://${LABSOBO_BROKER_CLIENT_ID}/labsOBO_jira.create" \
  --data-urlencode "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
  --data-urlencode "client_assertion=${LABSOBO_T1_A1}" \
  --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer" \
  --data-urlencode "assertion=${LABSOBO_T_APP_A1}" \
  --data-urlencode "requested_token_use=on_behalf_of"
```

Expected token:

```text
T_A1_BROKER_OBO
```

Expected claims:

```json
{
  "oid": "2faa25c9-590d-4723-aebb-f39f819ce489",
  "azp": "<AGENT_A1_CLIENT_ID>",
  "aud": "<BROKER_RESOURCE_ID>",
  "scp": "labsOBO_jira.create"
}
```

---

## 5. Broker trust contract

Broker validates:

```text
signature
issuer
expiry

aud = broker
oid = RAJARAJAN
azp = AGENT-A1
scp contains labsOBO_jira.create

AGENT-A1 is in broker allow-list
```

Identity key:

```text
tid + oid
```

Do not key on:

```text
email
preferred_username
display name
```

---

## 6. A1 asks broker for Jira authority

Representative request:

```bash
curl -X POST \
  "http://localhost:3100/credentials/jira/token" \
  -H "Authorization: Bearer ${LABSOBO_T_A1_BROKER_OBO}" \
  -H "Content-Type: application/json" \
  -d '{
    "purpose": "create_issue",
    "project": "SEC",
    "workflow_id": "labsOBO-WF-9281",
    "trace_id": "labsOBO-TRACE-882"
  }'
```

Trusted:

```text
oid
azp
scp
```

from the Entra token.

Not trusted for identity:

```json
{
  "user": "RAJARAJAN"
}
```

Request-body metadata may narrow a request.

It may never widen authority.

---

# FIRST-TIME JIRA CONNECTION

## 7. No grant exists

Vault lookup:

```text
tenant + RAJARAJAN oid + provider=Atlassian
```

No record:

```http
HTTP/1.1 428 Precondition Required
Content-Type: application/json
```

```json
{
  "error": "consent_required",
  "provider": "atlassian",
  "workflow_id": "labsOBO-WF-9281",
  "authorization_url": "https://auth.atlassian.com/authorize?..."
}
```

A1 does not open a browser.

It returns the authorization requirement to the application.

---

## 8. Atlassian 3LO

Browser flow:

```text
APP
 │
 │ 302
 ▼
Atlassian authorize
 │
 │ user authenticates / SSO
 │ user grants permission
 ▼
callback
```

Requested scopes:

```text
write:jira-work
offline_access
```

State must bind:

```text
Entra user
workflow
browser session
Atlassian authorization transaction
```

Server-side example:

```json
{
  "state": "labsOBO-atlassian-state-X92KA",
  "entra_oid": "2faa25c9-590d-4723-aebb-f39f819ce489",
  "workflow_id": "labsOBO-WF-9281",
  "used": false,
  "expires_at": "<short-expiry>"
}
```

State properties:

```text
random
single-use
short-lived
session-bound
```

---

## 9. Atlassian callback

```http
HTTP/1.1 302 Found
Location: http://localhost:3100/oauth/jira/callback?code=<JIRA_CODE>&state=<STATE>
```

Broker verifies:

```text
state exists
state not expired
state unused
state belongs to RAJARAJAN application session
workflow matches
```

This is the binding:

```text
Entra RAJARAJAN
        ↕
Atlassian authorization transaction
```

---

## 10. Broker exchanges Atlassian code

```bash
curl -X POST \
  "https://auth.atlassian.com/oauth/token" \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "authorization_code",
    "client_id": "'"${LABSOBO_ATLASSIAN_CLIENT_ID}"'",
    "client_secret": "'"${LABSOBO_ATLASSIAN_CLIENT_SECRET}"'",
    "code": "'"${LABSOBO_JIRA_AUTH_CODE}"'",
    "redirect_uri": "'"${LABSOBO_ATLASSIAN_CALLBACK}"'"
  }'
```

Expected:

```json
{
  "access_token": "<JIRA_AT_RAJARAJAN>",
  "refresh_token": "<JIRA_RT_RAJARAJAN>",
  "expires_in": 3600,
  "scope": "write:jira-work offline_access",
  "token_type": "Bearer"
}
```

The Atlassian client secret never enters A1.

---

## 11. Discover Jira site

Atlassian token is not site-specific.

Discover:

```bash
curl \
  "https://api.atlassian.com/oauth/token/accessible-resources" \
  -H "Authorization: Bearer ${JIRA_AT_RAJARAJAN}" \
  -H "Accept: application/json"
```

Representative response:

```json
[
  {
    "id": "<JIRA_CLOUD_ID>",
    "name": "Company Jira",
    "url": "https://company.atlassian.net",
    "scopes": [
      "write:jira-work"
    ]
  }
]
```

Broker stores:

```text
tid
oid
cloud_id
access_token
refresh_token
scope
expiry
```

---

## 12. What broker returns to A1

Only short-lived material:

```json
{
  "access_token": "<JIRA_AT_RAJARAJAN>",
  "cloud_id": "<JIRA_CLOUD_ID>",
  "expires_in": 1200
}
```

Never return:

```text
Atlassian client secret
JIRA_RT_RAJARAJAN
```

---

## 13. A1 creates Jira issue

```bash
curl -X POST \
  "https://api.atlassian.com/ex/jira/${JIRA_CLOUD_ID}/rest/api/3/issue" \
  -H "Authorization: Bearer ${JIRA_AT_RAJARAJAN}" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  -d '{
    "fields": {
      "project": {
        "key": "SEC"
      },
      "issuetype": {
        "name": "Incident"
      },
      "summary": "Suspicious encoded PowerShell activity detected",
      "description": {
        "type": "doc",
        "version": 1,
        "content": []
      }
    },
    "properties": [
      {
        "key": "labsOBO.agentProvenance",
        "value": {
          "agentId": "labsOBO-agent1",
          "initiatingUserOid": "2faa25c9-590d-4723-aebb-f39f819ce489",
          "workflowId": "labsOBO-WF-9281",
          "traceId": "labsOBO-TRACE-882",
          "source": "Microsoft Defender",
          "executionMode": "OBO"
        }
      }
    ]
  }'
```

Jira evaluates its own authorization:

```text
access token valid
OAuth integration valid
RAJARAJAN grant includes write permission
RAJARAJAN may browse project SEC
RAJARAJAN may create issues in SEC
```

---

## 14. Provenance model

Atlassian token proves:

```text
Jira authority = RAJARAJAN
```

It does not prove:

```text
which Entra agent performed the action
```

Therefore the workflow records separate provenance:

```json
{
  "agentId": "labsOBO-agent1",
  "initiatingUserOid": "2faa25c9-590d-4723-aebb-f39f819ce489",
  "workflowId": "labsOBO-WF-9281",
  "traceId": "labsOBO-TRACE-882",
  "source": "Microsoft Defender",
  "executionMode": "OBO"
}
```

Two proofs coexist:

```text
Jira native user authority
+
application-level agent provenance
```

---

## 15. Refresh-token model

Atlassian refresh tokens rotate.

```text
old refresh token
      │
      ▼
token endpoint
      │
      ├─ new access token
      └─ new refresh token
```

Broker rule:

```text
persist the new pair atomically
serialize refreshes per user
```

A failed rotation write can invalidate the stored grant.

Recovery:

```text
delete unusable vault record
restart Atlassian 3LO
```

---

## 16. Failure map

| Failure | Meaning |
|---|---|
| broker rejects `aud` | wrong Entra resource token |
| broker rejects `azp` | wrong agent |
| no grant | first-time Atlassian consent required |
| Atlassian `invalid_grant` | revoked/expired/lost rotating refresh token |
| valid OAuth but Jira rejects issue | Jira native project permission missing |
| wrong user attached to callback | state/session binding failure |

---

## 17. Final chain

```text
ENTRA

OID = RAJARAJAN
AZP = AGENT-A1
AUD = Broker

        ↓ broker maps immutable user identity

ATLASSIAN

JIRA_AT_RAJARAJAN

        ↓

JIRA

action executes under RAJARAJAN's Jira authority
agent provenance stored separately
```

---

## References

- https://learn.microsoft.com/en-us/entra/agent-id/agent-on-behalf-of-oauth-flow
- https://developer.atlassian.com/cloud/jira/platform/oauth-2-3lo-apps/
- https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issues/#api-rest-api-3-issue-post
