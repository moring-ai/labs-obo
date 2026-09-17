# labsOBO — User → Entra → Calling App

> **Boundary**  
> Human identity enters the system here.
>
> **Input**  
> authenticated browser session / interactive Entra authentication
>
> **Output**  
> `T_APP_A1`

---

## 1. What this hop proves

```text
Who is the human?
        ↓
RAJARAJAN

Which client requested access?
        ↓
labsOBO-calling-app

Which agent boundary is targeted?
        ↓
BP-A1

Is the human entitled?
        ↓
labsOBO.AgentInvoker
```

Result:

```text
T_APP_A1
```

Expected identity contract:

```text
oid   = RAJARAJAN
azp   = labsOBO-calling-app
aud   = BP-A1
scp   = labsOBO_access_agent
roles = labsOBO.AgentInvoker
```

---

## 2. Sequence

```text
RAJARAJAN
    │
    │ clicks Run Agent
    ▼
CALLING APP
    │
    │ 302 /authorize
    │ state + nonce + PKCE
    ▼
BROWSER
    │
    │ existing Entra session
    │ or interactive authentication
    ▼
ENTRA
    │
    │ authenticates human
    │ evaluates delegated permission
    │ evaluates assignment
    ▼
AUTHORIZATION CODE
    │
    ▼
CALLING APP
    │
    │ code + PKCE
    │ client assertion
    ▼
ENTRA /token
    │
    ▼
T_APP_A1
```

---

## 3. Browser authentication rule

The application does not tell Entra:

```text
oid=RAJARAJAN
```

There is no trusted OAuth parameter for that.

Entra identifies the human from:

```text
existing Entra browser session
OR
fresh interactive authentication
```

The calling app never receives the Microsoft SSO cookie.

---

## 4. Authorization request

Target:

```text
https://login.microsoftonline.com/<TENANT_ID>/oauth2/v2.0/authorize
```

Contract:

```text
client_id      = labsOBO-calling-app
response_type  = code
redirect_uri   = http://localhost:3100/auth/callback

scope =
  openid
  profile
  offline_access
  api://<BP-A1>/labsOBO_access_agent

code_challenge_method = S256
state                  = random / single transaction
nonce                  = random / single transaction
```

Representation:

```bash
curl -G \
  "https://login.microsoftonline.com/${LABSOBO_TENANT_ID}/oauth2/v2.0/authorize" \
  --data-urlencode "client_id=${LABSOBO_CALLING_APP_CLIENT_ID}" \
  --data-urlencode "response_type=code" \
  --data-urlencode "redirect_uri=${LABSOBO_REDIRECT_URI}" \
  --data-urlencode "scope=openid profile offline_access api://${LABSOBO_BP_A1_CLIENT_ID}/${LABSOBO_ACCESS_SCOPE}" \
  --data-urlencode "code_challenge=${LABSOBO_PKCE_CHALLENGE}" \
  --data-urlencode "code_challenge_method=S256" \
  --data-urlencode "state=<STATE>" \
  --data-urlencode "nonce=<NONCE>"
```

This command is only a representation of the authorization request.

The real request is browser-driven.

---

## 5. Entra decisions

Entra evaluates three independent facts:

```text
1. USER
   browser session
   → RAJARAJAN

2. ENTITLEMENT
   appRoleAssignment
   → labsOBO.AgentInvoker on BP-A1

3. CLIENT
   client_id + redirect_uri
   → labsOBO-calling-app
```

Consent is separate.

```text
consent     = app may request delegated API permission
entitlement = this user may invoke this agent
```

For the enterprise lab:

```text
consent already granted
entitlement varies by user
```

---

## 6. Authorization code

Successful callback:

```http
HTTP/1.1 302 Found
Location: http://localhost:3100/auth/callback?code=<AUTH_CODE>&state=<STATE>
```

The application validates:

```text
state exists
state not expired
state unused
state belongs to this application session
```

The code is:

```text
short-lived
single-use
bound to client + redirect URI + PKCE transaction
not an access token
```

---

## 7. Calling-app proof

The confidential application authenticates itself with a short-lived client assertion.

Conceptual JWT:

```json
{
  "aud": "https://login.microsoftonline.com/<TENANT_ID>/oauth2/v2.0/token",
  "iss": "<CALLING_APP_CLIENT_ID>",
  "sub": "<CALLING_APP_CLIENT_ID>",
  "jti": "<random-guid>",
  "nbf": "<now>",
  "exp": "<now+300s>"
}
```

Signed with:

```text
labsOBO-calling-app private key
```

Entra verifies it against the registered public certificate.

---

## 8. Code exchange

```bash
curl -X POST \
  "https://login.microsoftonline.com/${LABSOBO_TENANT_ID}/oauth2/v2.0/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=authorization_code" \
  --data-urlencode "client_id=${LABSOBO_CALLING_APP_CLIENT_ID}" \
  --data-urlencode "code=${LABSOBO_RAJARAJAN_AUTH_CODE}" \
  --data-urlencode "redirect_uri=${LABSOBO_REDIRECT_URI}" \
  --data-urlencode "code_verifier=${LABSOBO_PKCE_VERIFIER}" \
  --data-urlencode "scope=openid profile offline_access api://${LABSOBO_BP_A1_CLIENT_ID}/${LABSOBO_ACCESS_SCOPE}" \
  --data-urlencode "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
  --data-urlencode "client_assertion=${LABSOBO_CALLING_APP_ASSERTION}"
```

Not present:

```text
username
password
oid=RAJARAJAN
Microsoft SSO cookie
```

Expected response:

```json
{
  "token_type": "Bearer",
  "scope": "api://<BP-A1>/labsOBO_access_agent",
  "expires_in": 3599,
  "access_token": "<T_APP_A1>",
  "refresh_token": "<if offline_access was granted>",
  "id_token": "<if openid was requested>"
}
```

---

## 9. `T_APP_A1` contract

Observed source-lab claims:

| Claim | Meaning |
|---|---|
| `oid` | human user |
| `azp` | calling application |
| `aud` | BP-A1 |
| `scp` | delegated invocation permission |
| `roles` | explicit human entitlement |

Observed values:

```text
oid
2faa25c9-590d-4723-aebb-f39f819ce489

azp
05d1bf77-a2e4-4c1c-9ef1-31dff291dd45

aud
5e5c2e3c-35b8-4817-8dc9-96b09adb6865

scp
labsOBO_access_agent

roles
labsOBO.AgentInvoker
```

Important audience observation:

```text
requestedAccessTokenVersion = 2
        ↓
aud = BP-A1 client-id GUID
```

Do not assume:

```text
aud = api://BP-A1
```

Configure downstream validation from the actual token claim.

---

## 10. Positive proof

```text
T_APP_A1

OID   = RAJARAJAN
AZP   = Calling App
AUD   = BP-A1
SCP   = labsOBO_access_agent
ROLES = labsOBO.AgentInvoker
```

Meaning:

```text
Human identity preserved.
Calling client identified.
Target boundary identified.
Delegated operation identified.
Human entitlement carried cryptographically.
```

---

## 11. Negative control

Repeat the exact same authorization flow as SAM.

Keep constant:

```text
calling app
BP-A1
scope
redirect URI
authorization flow
```

Change:

```text
user = SAM
```

Expected:

```text
SAM cannot reach A1 with a usable authorized context.
```

Two possible shapes:

```text
A. Entra refuses issuance

or

B. Entra issues a token without roles
   AgentCore rejects it
```

Measured source-lab behavior for assignment removal:

```text
new token issued
roles missing
runtime denied
```

This proves:

```text
the calling application is not the user entitlement relationship
```

---

## 12. Handoff to next playbook

Input to the next boundary:

```text
T_APP_A1
```

The next playbook answers:

```text
Can the calling application present this user-bound token to A1?
Which workload is actually executing?
How does that workload obtain an Entra agent proof?
```

---

## References

- https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow
- https://www.rfc-editor.org/rfc/rfc7636
- https://learn.microsoft.com/en-us/entra/identity-platform/certificate-credentials
- https://learn.microsoft.com/en-us/entra/identity-platform/access-token-claims-reference
- https://learn.microsoft.com/en-us/entra/identity-platform/permissions-consent-overview
