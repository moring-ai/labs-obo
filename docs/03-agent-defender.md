# labsOBO — AGENT-A1 → Microsoft Defender

> **Boundary**  
> A1 calls Defender while preserving RAJARAJAN as the human authority.
>
> **Input**  
> `T_APP_A1` + `T1`
>
> **Output**  
> `T_A1_DEFENDER_OBO`

---

## 1. Objective

Convert:

```text
human proof
+
agent proof
```

into:

```text
Defender delegated access token
```

with this identity result:

```text
OID = RAJARAJAN
AZP = AGENT-A1
AUD = Defender
SCP = AdvancedHunting.Read
```

The human is preserved.

The actor changes.

---

## 2. Starting state

A1 holds:

```text
T_APP_A1
OID = RAJARAJAN
AZP = Calling App
AUD = BP-A1
```

and:

```text
T1
Agent binding = AGENT-A1
```

Neither can call Defender directly.

Why:

```text
T_APP_A1
aud = BP-A1
not Defender

T1
contains no human delegated authority
```

---

## 3. Permission model

AGENT-A1 has delegated permission:

```text
AdvancedHunting.Read
```

RAJARAJAN separately needs Defender authority:

```text
View Data
relevant device / device-group access
```

Effective authorization is the intersection:

```text
AGENT-A1 delegated scope
∩
RAJARAJAN Defender permissions
```

---

## 4. OBO exchange

```text
AGENT-A1
    │
    │ T1
    │ T_APP_A1
    ▼
ENTRA TOKEN ENDPOINT
    │
    │ validate agent
    │ validate user assertion
    │ validate downstream consent
    ▼
T_A1_DEFENDER_OBO
```

Representative request:

```bash
curl -X POST \
  "https://login.microsoftonline.com/${LABSOBO_TENANT_ID}/oauth2/v2.0/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "client_id=${LABSOBO_AGENT_A1_CLIENT_ID}" \
  --data-urlencode "scope=https://api.security.microsoft.com/AdvancedHunting.Read" \
  --data-urlencode "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
  --data-urlencode "client_assertion=${LABSOBO_T1_A1}" \
  --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer" \
  --data-urlencode "assertion=${LABSOBO_T_APP_A1}" \
  --data-urlencode "requested_token_use=on_behalf_of"
```

Parameter contract:

| Parameter | Carries |
|---|---|
| `client_id=AGENT-A1` | downstream actor |
| `client_assertion=T1` | proof of AGENT-A1 |
| `assertion=T_APP_A1` | human context |
| `requested_token_use=on_behalf_of` | delegation semantics |
| Defender scope | requested downstream authority |

---

## 5. Entra preconditions

Microsoft Agent OBO expects:

```text
T_APP_A1 aud = BP-A1
T1 bound to BP-A1
T1 resolves to AGENT-A1
AGENT-A1 has downstream delegated permission
```

Important failure:

```text
user assertion audienced to another resource
        ↓
OBO fails
```

The source lab cites `AADSTS50013` for an assertion with the wrong audience.

---

## 6. Downstream token

Expected:

```json
{
  "oid": "2faa25c9-590d-4723-aebb-f39f819ce489",
  "azp": "<AGENT_A1_CLIENT_ID>",
  "aud": "<Defender resource>",
  "scp": "AdvancedHunting.Read"
}
```

Do not make authorization depend on:

```text
idtyp = user
```

Measured source-lab observation:

```text
idtyp was not emitted on delegated tokens in this tenant
```

Reliable delegated indicators here are:

```text
scp present
oid != azp
```

---

## 7. Identity transition

```text
BEFORE OBO

T_APP_A1
OID = RAJARAJAN
AZP = Calling App
AUD = BP-A1

        +

T1
Agent = AGENT-A1


AFTER OBO

T_A1_DEFENDER_OBO
OID = RAJARAJAN
AZP = AGENT-A1
AUD = Defender
SCP = AdvancedHunting.Read
```

This is the central proof:

```text
Human preserved.
Actor changed.
```

---

## 8. Defender call

Example KQL:

```kusto
DeviceProcessEvents
| where Timestamp > ago(1h)
| where FileName =~ "powershell.exe"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| take 100
```

HTTP call:

```bash
curl -X POST \
  "https://api.security.microsoft.com/api/advancedhunting/run" \
  -H "Authorization: Bearer ${LABSOBO_T_A1_DEFENDER_OBO}" \
  -H "Content-Type: application/json" \
  -d '{
    "Query": "DeviceProcessEvents | where Timestamp > ago(1h) | where FileName =~ '\''powershell.exe'\'' | project Timestamp, DeviceName, AccountName, ProcessCommandLine | take 100"
  }'
```

Representative response:

```json
{
  "Stats": {
    "ExecutionTime": 0.42
  },
  "Results": [
    {
      "DeviceName": "SEC-LAPTOP-22",
      "AccountName": "john",
      "ProcessCommandLine": "powershell.exe -EncodedCommand ..."
    }
  ]
}
```

---

## 9. Responsibility split

```text
LLM
  proposes KQL

A1 host
  validates KQL
  obtains downstream token
  performs HTTP call
  returns result

Defender
  validates token
  applies delegated user permissions
```

Do not expose to the model:

```text
T1
refresh tokens
client secrets
AWS credentials
```

The model needs:

```text
query intent
tool schema
result data
```

---

## 10. Audit interpretation

```text
RAJARAJAN initiated the workflow.
AGENT-A1 became the downstream OAuth actor.
Defender evaluated RAJARAJAN's delegated authority.
```

A1 should separately correlate:

```text
workflow_id
user oid
agent id
calling client
query hash
downstream request
```

---

## 11. Autonomous comparison

Autonomous Defender is a different mode.

```text
client_credentials
+
AdvancedHunting.Read.All
```

Token semantics:

```text
OID   = AGENT-A1
AZP   = AGENT-A1
idtyp = app
roles = AdvancedHunting.Read.All

NO RAJARAJAN
```

Use that for:

```text
scheduled
system-initiated
non-user workflows
```

Do not silently switch a human-initiated workflow to autonomous mode.

---

## 12. Failure map

| Failure | Check |
|---|---|
| OBO assertion rejected | `T_APP_A1 aud == BP-A1` |
| `AADSTS65001` | delegated consent likely granted to wrong principal; it must be AGENT-A1 |
| valid token but no Defender data | human Defender role/device access |
| wrong downstream actor | inspect `azp` |
| user disappeared | autonomous token was used instead of OBO |

---

## References

- https://learn.microsoft.com/en-us/entra/agent-id/agent-on-behalf-of-oauth-flow
- https://learn.microsoft.com/en-us/defender-xdr/api-advanced-hunting
- https://learn.microsoft.com/en-us/defender-xdr/api-create-app-user
- https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables
