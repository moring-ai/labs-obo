# labsOBO — Setup & Access

> **Purpose:** configure every identity object, permission, and trust relationship required before runtime.
>
> **Format:** every setup item has two paths:
>
> ```text
> PORTAL
> exact UI steps + screenshot
>
> TERMINAL
> CLI / Graph / API equivalent
> ```
>
> `01-user-entra-app.md` starts only after this document is complete.

---

# 0. Setup sequence

```text
01  Administrator access
02  Create labsOBO-calling-app
03  Configure calling-app redirect URI
04  Configure calling-app certificate

05  Create BP-A1 agent blueprint
06  Configure BP-A1 identifier URI + delegated scope
07  Create labsOBO.AgentInvoker app role
08  Require assignment on BP-A1
09  Assign RAJARAJAN → AgentInvoker

10  Connect calling app → BP-A1
11  Grant tenant-wide delegated consent

12  Create AGENT-A1

13  Create AgentCore execution role
14  Create/configure AgentCore runtime
15  Enable AWS outbound identity federation
16  Configure BP-A1 FIC for the AWS role

17  Grant AGENT-A1 → Defender delegated permission

18  Create Jira credential-broker Entra application
19  Grant AGENT-A1 → Broker delegated permission
20  Create Atlassian 3LO application

21  Verify the final configuration graph
22  Export runtime configuration
23  Completion check
```

---

# 1. Administrator access

The team needs setup rights in five control planes.

| Platform | Required capability |
|---|---|
| Microsoft Entra | applications, Agent ID, roles, scopes, assignments, consent, FIC |
| Microsoft Graph | Agent ID and permission-management APIs |
| AWS | IAM, AgentCore, outbound identity federation |
| Defender XDR | delegated Advanced Hunting configuration |
| Atlassian | OAuth 2.0 / 3LO integration |

For Microsoft Entra Agent ID, current Microsoft documentation lists **Agent ID Developer** and **Agent ID Administrator** for Agent ID provisioning, with Entra application/admin roles additionally required for permission and consent operations.

## Portal

1. Sign in to the **Microsoft Entra admin center**.

2. Confirm that the account being used can access:

   ```text
   Entra ID
   App registrations
   Enterprise apps
   Agents
   ```

3. Sign in to AWS and confirm access to:

   ```text
   IAM
   Bedrock AgentCore
   ```

4. Confirm an administrator can manage the tenant's Defender API permissions.

5. Confirm access to the Atlassian **Developer console**.

## Terminal equivalent

### Entra / Azure CLI

```bash
az login --tenant "${LABSOBO_TENANT_ID}"

az account show \
  --query '{tenantId:tenantId,user:user.name}' \
  -o table
```

### Microsoft Graph PowerShell

```powershell
Connect-MgGraph `
  -TenantId $env:LABSOBO_TENANT_ID `
  -Scopes `
    "Application.ReadWrite.All",
    "AppRoleAssignment.ReadWrite.All",
    "DelegatedPermissionGrant.ReadWrite.All",
    "User.Read"
```

Check the active Graph session:

```powershell
Get-MgContext
```

### AWS

```bash
aws sts get-caller-identity
```

> These commands prove the authenticated control-plane sessions. They do **not** by themselves prove that every required administrator role has been assigned.

Reference:

https://learn.microsoft.com/en-us/entra/agent-id/create-blueprint

---

# 2. Create `labsOBO-calling-app`

This is the confidential web application used by the human.

```text
Name
labsOBO-calling-app
```

## Portal

1. Sign in to the **Microsoft Entra admin center**.

2. Browse to:

   **Entra ID > App registrations**

3. Select **New registration**.

4. In **Name**, enter:

   ```text
   labsOBO-calling-app
   ```

5. Under **Supported account types**, select:

   ```text
   Accounts in this organizational directory only
   ```

6. Select **Register**.

![Register an application](https://learn.microsoft.com/en-us/graph/images/quickstart-register-app/portal-02-app-reg-01.png)

7. On **Overview**, record:

   ```text
   Application (client) ID
   Object ID
   Directory (tenant) ID
   ```

Known client ID from the existing lab:

```text
05d1bf77-a2e4-4c1c-9ef1-31dff291dd45
```

## Terminal equivalent

Create the application object:

```bash
APP_JSON="$(
  az ad app create \
    --display-name "labsOBO-calling-app" \
    --sign-in-audience AzureADMyOrg
)"

export LABSOBO_CALLING_APP_CLIENT_ID="$(
  printf '%s' "$APP_JSON" | jq -r '.appId'
)"

export LABSOBO_CALLING_APP_OBJECT_ID="$(
  printf '%s' "$APP_JSON" | jq -r '.id'
)"
```

Create its tenant service principal explicitly:

```bash
SP_JSON="$(
  az ad sp create \
    --id "${LABSOBO_CALLING_APP_CLIENT_ID}"
)"

export LABSOBO_CALLING_APP_PRINCIPAL_ID="$(
  printf '%s' "$SP_JSON" | jq -r '.id'
)"
```

Verify:

```bash
az ad app show \
  --id "${LABSOBO_CALLING_APP_CLIENT_ID}" \
  --query '{displayName:displayName,appId:appId,id:id,signInAudience:signInAudience}' \
  -o yaml
```

---

# 3. Configure the calling-app redirect URI

Required callback:

```text
http://localhost:3100/auth/callback
```

## Portal

1. Open:

   **Entra ID > App registrations > labsOBO-calling-app**

2. Under **Manage**, select **Authentication**.

3. Under **Platform configurations**, select **Add a platform**.

4. Select **Web**.

![Choose Web platform](https://learn.microsoft.com/en-us/graph/images/quickstart-register-app/portal-04-app-reg-03-platform-config.png)

5. Enter:

   ```text
   http://localhost:3100/auth/callback
   ```

6. Select **Configure**.

The platform is:

```text
Web
```

not:

```text
Single-page application
Mobile and desktop applications
```

## Terminal equivalent

```bash
az ad app update \
  --id "${LABSOBO_CALLING_APP_CLIENT_ID}" \
  --web-redirect-uris \
    "http://localhost:3100/auth/callback"
```

Verify:

```bash
az ad app show \
  --id "${LABSOBO_CALLING_APP_CLIENT_ID}" \
  --query 'web.redirectUris' \
  -o json
```

Expected:

```json
[
  "http://localhost:3100/auth/callback"
]
```

---

# 4. Configure the calling-app certificate

The calling backend authenticates with:

```text
private_key_jwt
```

rather than sending a client password.

## Portal

Generate a development certificate:

```bash
mkdir -p certs

openssl req \
  -x509 \
  -newkey rsa:3072 \
  -keyout certs/labsOBO-calling-app.key \
  -out certs/labsOBO-calling-app.crt \
  -days 30 \
  -nodes \
  -subj "/CN=labsOBO-calling-app"
```

Then:

1. Open:

   **Entra ID > App registrations > labsOBO-calling-app**

2. Select:

   **Certificates & secrets**

3. Select **Certificates**.

4. Select **Upload certificate**.

5. Upload:

   ```text
   certs/labsOBO-calling-app.crt
   ```

6. Select **Add**.

![Certificates and secrets](https://learn.microsoft.com/en-us/graph/images/quickstart-register-app/portal-05-app-reg-04-credentials.png)

Never upload:

```text
certs/labsOBO-calling-app.key
```

## Terminal equivalent

The same public certificate can be appended with Azure CLI:

```bash
az ad app credential reset \
  --id "${LABSOBO_CALLING_APP_CLIENT_ID}" \
  --cert "@certs/labsOBO-calling-app.crt" \
  --append \
  --display-name "labsOBO calling-app certificate"
```

Verify certificate metadata:

```bash
az ad app credential list \
  --id "${LABSOBO_CALLING_APP_CLIENT_ID}" \
  --cert \
  -o table
```

The private key remains only on the calling-app backend.

Reference:

https://learn.microsoft.com/en-us/entra/identity-platform/certificate-credentials

---

# 5. Create BP-A1 — Agent Identity Blueprint

```text
Name
labsOBO-agent1-blueprint

Alias
BP-A1
```

## Portal

1. Sign in to the **Microsoft Entra admin center**.

2. Browse to:

   **Entra ID > Agents > Agent blueprints**

3. Select:

   **New agent blueprint (Preview)**

4. On **Basics**, enter:

   ```text
   labsOBO-agent1-blueprint
   ```

5. Select **Next**.

![Create Agent Blueprint](images/05-create-blueprint-user-example.png)

6. On **Owners & Sponsors**:

   - add/confirm an **Owner**
   - add/confirm a **Sponsor**

7. Select **Next**.

8. Review the values.

9. Select **Create**.

10. Select **Go to agent blueprint**.

The portal wizard creates both:

```text
Agent Identity Blueprint application
Agent Identity Blueprint principal
```

Capture:

```text
BP-A1 Application / Client ID
BP-A1 Application Object ID
BP-A1 Principal / Service Principal Object ID
```

Known client ID:

```text
5e5c2e3c-35b8-4817-8dc9-96b09adb6865
```

## Terminal equivalent

Current Microsoft documentation supports programmatic creation through Microsoft Graph PowerShell.

Connect:

```powershell
Connect-MgGraph `
  -TenantId $env:LABSOBO_TENANT_ID `
  -Scopes `
    "AgentIdentityBlueprint.Create",
    "AgentIdentityBlueprintPrincipal.Create",
    "User.Read"
```

Resolve the current user for owner/sponsor:

```powershell
$currentUser = (Get-MgContext).Account
$user = Get-MgUser -UserId $currentUser
```

Create the blueprint:

```powershell
$body = @{
    "@odata.type" = "Microsoft.Graph.AgentIdentityBlueprint"
    "displayName" = "labsOBO-agent1-blueprint"
    "sponsors@odata.bind" = @(
        "https://graph.microsoft.com/v1.0/users/$($user.Id)"
    )
    "owners@odata.bind" = @(
        "https://graph.microsoft.com/v1.0/users/$($user.Id)"
    )
} | ConvertTo-Json -Depth 5

$bp = Invoke-MgGraphRequest `
    -Method POST `
    -Uri "https://graph.microsoft.com/v1.0/applications/microsoft.graph.agentIdentityBlueprint" `
    -Headers @{ "OData-Version" = "4.0" } `
    -Body $body `
    -ContentType "application/json"
```

Capture:

```powershell
$env:LABSOBO_BP_A1_CLIENT_ID = $bp.appId
$env:LABSOBO_BP_A1_OBJECT_ID = $bp.id
```

Create the blueprint principal:

```powershell
$spBody = @{
    appId = $bp.appId
} | ConvertTo-Json

$bpPrincipal = Invoke-MgGraphRequest `
    -Method POST `
    -Uri "https://graph.microsoft.com/v1.0/serviceprincipals/microsoft.graph.agentIdentityBlueprintPrincipal" `
    -Headers @{ "OData-Version" = "4.0" } `
    -Body $spBody `
    -ContentType "application/json"
```

Capture:

```powershell
$env:LABSOBO_BP_A1_PRINCIPAL_ID = $bpPrincipal.id
```

Reference:

https://learn.microsoft.com/en-us/entra/agent-id/create-blueprint

---

# 6. Expose BP-A1 as the inbound OAuth resource

The calling app needs a delegated token **for BP-A1**.

```text
Application ID URI
api://<BP-A1-client-id>

Scope
labsOBO_access_agent
```

For this lab:

```text
api://5e5c2e3c-35b8-4817-8dc9-96b09adb6865/labsOBO_access_agent
```

## Portal

1. Open BP-A1.

2. Open the API configuration / **Expose an API** page.

3. Set:

   ```text
   Application ID URI
   api://<BP-A1-client-id>
   ```

4. Select **Add a scope**.

![Expose an API](https://learn.microsoft.com/en-us/entra/identity-platform/media/quickstart-configure-app-expose-web-apis/portal-02-expose-api.png)

5. Configure:

   ```text
   Scope name
   labsOBO_access_agent

   Who can consent
   Admins and users

   Admin consent display name
   Invoke labsOBO Agent A1

   State
   Enabled
   ```

6. Keep access-token version:

   ```text
   requestedAccessTokenVersion = 2
   ```

## Terminal equivalent

Connect with the Agent ID auth-property scope:

```powershell
Connect-MgGraph `
  -TenantId $env:LABSOBO_TENANT_ID `
  -Scopes "AgentIdentityBlueprint.UpdateAuthProperties.All"
```

Create a scope ID:

```powershell
$scopeId = [guid]::NewGuid()
$env:LABSOBO_ACCESS_SCOPE_ID = $scopeId.ToString()
```

Build the API configuration:

```powershell
$body = @{
    identifierUris = @(
        "api://$($env:LABSOBO_BP_A1_CLIENT_ID)"
    )
    api = @{
        requestedAccessTokenVersion = 2
        oauth2PermissionScopes = @(
            @{
                adminConsentDescription = "Allow the application to invoke labsOBO Agent A1 on behalf of the signed-in user."
                adminConsentDisplayName = "Invoke labsOBO Agent A1"
                userConsentDescription = "Allows the app to invoke labsOBO Agent A1 on your behalf."
                userConsentDisplayName = "Invoke labsOBO Agent A1 on your behalf"
                id = $scopeId
                isEnabled = $true
                type = "User"
                value = "labsOBO_access_agent"
            }
        )
    }
} | ConvertTo-Json -Depth 10
```

Apply:

```powershell
Invoke-MgGraphRequest `
  -Method PATCH `
  -Uri "https://graph.microsoft.com/v1.0/applications/$($env:LABSOBO_BP_A1_OBJECT_ID)" `
  -Headers @{ "OData-Version" = "4.0" } `
  -Body $body `
  -ContentType "application/json"
```

Expected:

```text
HTTP 204
```

Verify:

```powershell
Get-MgApplication `
  -ApplicationId $env:LABSOBO_BP_A1_OBJECT_ID `
  -Property AppId,IdentifierUris,Api |
  Format-List
```

Reference:

https://learn.microsoft.com/en-us/entra/agent-id/create-blueprint

---

# 7. Create `labsOBO.AgentInvoker`

This role is the human entitlement:

```text
RAJARAJAN may invoke A1
```

It is independent of OAuth consent.

## Portal

1. Open BP-A1.

2. Under **Manage**, select **App roles**.

3. Select **Create app role**.

![App roles](https://learn.microsoft.com/en-us/entra/identity-platform/media/howto-add-app-roles-in-apps/app-roles-overview-pane.png)

4. Configure:

   ```text
   Display name
   labsOBO Agent Invoker

   Allowed member types
   Users/Groups

   Value
   labsOBO.AgentInvoker

   Description
   Allows an explicitly assigned human to invoke labsOBO Agent A1

   Enabled
   Yes
   ```

![Create app role](https://learn.microsoft.com/en-us/entra/identity-platform/media/howto-add-app-roles-in-apps/app-roles-create-context-pane.png)

5. Select **Apply**.

## Terminal equivalent

For a fresh lab blueprint with no pre-existing custom roles:

```powershell
Connect-MgGraph `
  -TenantId $env:LABSOBO_TENANT_ID `
  -Scopes "Application.ReadWrite.All"
```

Generate the role ID:

```powershell
$roleId = [guid]::NewGuid()
$env:LABSOBO_AGENT_INVOKER_ROLE_ID = $roleId.ToString()
```

Create the role:

```powershell
$role = @{
    id = $roleId
    allowedMemberTypes = @("User")
    description = "Allows an explicitly assigned human to invoke labsOBO Agent A1"
    displayName = "labsOBO Agent Invoker"
    isEnabled = $true
    value = "labsOBO.AgentInvoker"
}

Update-MgApplication `
  -ApplicationId $env:LABSOBO_BP_A1_OBJECT_ID `
  -BodyParameter @{
      appRoles = @($role)
  }
```

Verify:

```powershell
(Get-MgApplication `
  -ApplicationId $env:LABSOBO_BP_A1_OBJECT_ID `
  -Property AppRoles).AppRoles |
  Format-Table DisplayName,Value,Id,IsEnabled
```

Expected:

```text
labsOBO Agent Invoker
labsOBO.AgentInvoker
```

> If the blueprint already contains other app roles, preserve them when updating the `appRoles` collection rather than replacing the collection with only this role.

Reference:

https://learn.microsoft.com/en-us/entra/identity-platform/howto-add-app-roles-in-apps

---

# 8. Require explicit user assignment

The resource must not rely only on:

```text
scp = labsOBO_access_agent
```

It also requires:

```text
roles contains labsOBO.AgentInvoker
```

## Portal

1. Browse to:

   **Entra ID > Enterprise apps > All applications**

2. Open the BP-A1 principal.

3. Select **Properties**.

4. Set:

   ```text
   Assignment required?
   Yes
   ```

5. Select **Save**.

## Terminal equivalent — tested labsOBO configuration

The source lab set the property on the **BP-A1 service principal**:

```powershell
Connect-MgGraph `
  -TenantId $env:LABSOBO_TENANT_ID `
  -Scopes "Application.ReadWrite.All"

Update-MgServicePrincipal `
  -ServicePrincipalId $env:LABSOBO_BP_A1_PRINCIPAL_ID `
  -BodyParameter @{
      appRoleAssignmentRequired = $true
  }
```

Verify:

```powershell
Get-MgServicePrincipal `
  -ServicePrincipalId $env:LABSOBO_BP_A1_PRINCIPAL_ID `
  -Property DisplayName,AppRoleAssignmentRequired |
  Select DisplayName,AppRoleAssignmentRequired
```

Expected:

```text
AppRoleAssignmentRequired = True
```

### Note on current Microsoft documentation

Microsoft's current Agent ID access-control article also documents `assignmentRequired` through an application update endpoint. This playbook keeps the **service-principal configuration that was actually exercised in labsOBO**.

Measured labsOBO behavior:

```text
remove AgentInvoker assignment
      ↓
request a NEW token
      ↓
token may still be issued
      ↓
roles claim missing
      ↓
AgentCore rejects it
```

Therefore:

```text
roles CONTAINS labsOBO.AgentInvoker
```

remains a mandatory runtime check.

---

# 9. Assign RAJARAJAN → `labsOBO.AgentInvoker`

Positive control:

```text
RAJARAJAN
oid = 2faa25c9-590d-4723-aebb-f39f819ce489
```

Negative control:

```text
SAM
```

SAM remains unassigned.

## Portal

1. Browse to:

   **Entra ID > Enterprise apps > All applications**

2. Open:

   ```text
   labsOBO-agent1-blueprint
   ```

3. Select **Users and groups**.

4. Select **Add user/group**.

![Assign users](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/media/add-application-portal-assign-users/assign-user.png)

5. Select **None Selected**.

6. Select **RAJARAJAN**.

7. Under **Select a role**, choose:

   ```text
   labsOBO Agent Invoker
   ```

8. Select **Assign**.

Result:

```text
RAJARAJAN
    │
    │ labsOBO.AgentInvoker
    ▼
BP-A1
```

## Terminal equivalent

```powershell
Connect-MgGraph `
  -TenantId $env:LABSOBO_TENANT_ID `
  -Scopes "AppRoleAssignment.ReadWrite.All","Application.Read.All"
```

Create the assignment:

```powershell
$params = @{
    PrincipalId = [guid]$env:LABSOBO_RAJARAJAN_USER_OBJECT_ID
    ResourceId  = [guid]$env:LABSOBO_BP_A1_PRINCIPAL_ID
    AppRoleId   = [guid]$env:LABSOBO_AGENT_INVOKER_ROLE_ID
}

New-MgUserAppRoleAssignment `
  -UserId $env:LABSOBO_RAJARAJAN_USER_OBJECT_ID `
  -BodyParameter $params
```

Verify from the user side:

```powershell
Get-MgUserAppRoleAssignment `
  -UserId $env:LABSOBO_RAJARAJAN_USER_OBJECT_ID |
  Where-Object {
      $_.ResourceId -eq $env:LABSOBO_BP_A1_PRINCIPAL_ID
  } |
  Format-Table PrincipalDisplayName,ResourceDisplayName,AppRoleId
```

Do **not** perform the equivalent assignment for SAM.

Reference:

https://learn.microsoft.com/en-us/entra/agent-id/control-user-access-agents

---

# 10. Connect the calling app → BP-A1

This is a different relationship:

```text
labsOBO-calling-app
        │
        │ delegated scope
        ▼
BP-A1
```

It answers:

```text
May this CLIENT request labsOBO_access_agent?
```

It does **not** answer:

```text
May this HUMAN invoke A1?
```

## Portal

1. Browse to:

   **Entra ID > App registrations**

2. Open:

   ```text
   labsOBO-calling-app
   ```

3. Select **API permissions**.

4. Select **Add a permission**.

5. Select **My APIs**.

6. Select:

   ```text
   labsOBO-agent1-blueprint
   ```

7. Choose **Delegated permissions**.

8. Select:

   ```text
   labsOBO_access_agent
   ```

9. Select **Add permissions**.

The generic API-permission workflow appears like this:

![Add API permission](https://learn.microsoft.com/en-us/entra/identity-platform/media/quickstart-configure-app-expose-web-apis/portal-02-expose-api.png)

> The screenshot above shows the resource's **Expose an API** side; the calling app's **API permissions > Add a permission > My APIs** view consumes the scope created there.

## Terminal equivalent

Static API permissions on the calling-app registration can be added with Azure CLI.

You need the **scope ID** created in section 6:

```bash
export LABSOBO_ACCESS_SCOPE_ID="<scope-guid>"
```

Add the delegated permission:

```bash
az ad app permission add \
  --id "${LABSOBO_CALLING_APP_CLIENT_ID}" \
  --api "${LABSOBO_BP_A1_CLIENT_ID}" \
  --api-permissions "${LABSOBO_ACCESS_SCOPE_ID}=Scope"
```

Verify:

```bash
az ad app permission list \
  --id "${LABSOBO_CALLING_APP_CLIENT_ID}" \
  -o json
```

Look for:

```text
resourceAppId = BP-A1 client ID
resourceAccess.id = labsOBO_access_agent scope GUID
resourceAccess.type = Scope
```

---

# 11. Grant tenant-wide delegated consent

For the enterprise lab:

```text
OAuth consent is settled ahead of runtime.
Role assignment is the variable used to test user entitlement.
```

## Portal

1. Stay in:

   **labsOBO-calling-app > API permissions**

2. Review:

   ```text
   labsOBO-agent1-blueprint
   Delegated
   labsOBO_access_agent
   ```

3. Select:

   **Grant admin consent for <tenant>**

4. Confirm the grant.

A tenant-wide admin-consent view looks like:

![Grant admin consent](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/media/grant-tenant-wide-admin-consent/grant-tenant-wide-admin-consent.png)

## Terminal equivalent

Admin consent for a delegated custom API scope is an `oauth2PermissionGrant`.

```powershell
Connect-MgGraph `
  -TenantId $env:LABSOBO_TENANT_ID `
  -Scopes "Application.ReadWrite.All","DelegatedPermissionGrant.ReadWrite.All"
```

Create:

```powershell
$params = @{
    ClientId    = $env:LABSOBO_CALLING_APP_PRINCIPAL_ID
    ConsentType = "AllPrincipals"
    ResourceId  = $env:LABSOBO_BP_A1_PRINCIPAL_ID
    Scope       = "labsOBO_access_agent"
}

New-MgOauth2PermissionGrant `
  -BodyParameter $params
```

Verify:

```powershell
Get-MgOauth2PermissionGrant `
  -Filter "clientId eq '$($env:LABSOBO_CALLING_APP_PRINCIPAL_ID)' and consentType eq 'AllPrincipals'" |
  Format-Table ClientId,ResourceId,Scope,ConsentType
```

Expected scope:

```text
labsOBO_access_agent
```

Keep these three controls separate:

| Control | Question |
|---|---|
| `requiredResourceAccess` | what permission does the client declare it needs? |
| `oauth2PermissionGrant` | has that delegated permission been consented? |
| `appRoleAssignment` | is this human entitled to A1? |

---

# 12. Create AGENT-A1

```text
Name
labsOBO-agent1

Parent
labsOBO-agent1-blueprint
```

## Portal

1. Browse to:

   **Entra ID > Agents > Agent identities**

2. Select:

   **New agent identity (Preview)**

3. On **Basics**:

   ```text
   Agent blueprint
   labsOBO-agent1-blueprint

   Agent identity name
   labsOBO-agent1
   ```

4. Select **Next**.

5. Configure **Owners & Sponsors**.

6. Select **Next**.

7. Review.

8. Select **Create**.

9. Select **Go to agent identity**.

Capture:

```text
AGENT-A1 client ID
AGENT-A1 service-principal Object ID
```

## Terminal / Graph equivalent

Current Microsoft documentation exposes agent creation through the Graph beta endpoint.

The caller needs a Graph access token authorized to create the Agent Identity from BP-A1.

```bash
export AGENT_CREATE_GRAPH_TOKEN="<graph-access-token>"
export SPONSOR_OBJECT_ID="<sponsor-user-object-id>"
```

Request:

```bash
curl -X POST \
  "https://graph.microsoft.com/beta/serviceprincipals/Microsoft.Graph.AgentIdentity" \
  -H "Authorization: Bearer ${AGENT_CREATE_GRAPH_TOKEN}" \
  -H "OData-Version: 4.0" \
  -H "Content-Type: application/json" \
  -d '{
    "displayName": "labsOBO-agent1",
    "agentIdentityBlueprintId": "'"${LABSOBO_BP_A1_CLIENT_ID}"'",
    "sponsors@odata.bind": [
      "https://graph.microsoft.com/v1.0/users/'"${SPONSOR_OBJECT_ID}"'"
    ]
  }'
```

Capture from the response:

```text
appId / client ID
id / service-principal Object ID
```

Critical constraint observed in labsOBO:

```text
AGENT-A1 cannot hold its own certificate or secret.

Attempt:
PATCH keyCredentials on Agent Identity

Result:
IncompatibleWithAgentIdentity
```

Credentials belong to BP-A1.

Reference:

https://learn.microsoft.com/en-us/entra/agent-id/create-delete-agent-identities

---

# 13. Create the AgentCore execution role

Use a dedicated role:

```text
labsOBO-agent1-execution-role
```

One role per agent is important because AWS places the role identity into the outbound assertion.

## Portal

1. Open the **AWS Management Console**.

2. Browse to:

   **IAM > Roles**

3. Select **Create role**.

4. Configure AgentCore as the trusted service / use the AgentCore runtime trust relationship.

5. Name the role:

   ```text
   labsOBO-agent1-execution-role
   ```

6. Attach the runtime permissions required for the actual A1 container:

   ```text
   ECR image access
   CloudWatch logging
   model/tool permissions used by A1
   ```

7. Add:

   ```text
   sts:GetWebIdentityToken
   ```

   with the outbound-token restrictions shown below.

## Terminal equivalent

Create the trust policy:

```bash
cat > /tmp/labsOBO-agentcore-trust.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AssumeRolePolicy",
      "Effect": "Allow",
      "Principal": {
        "Service": "bedrock-agentcore.amazonaws.com"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "aws:SourceAccount": "${LABSOBO_AWS_ACCOUNT_ID}"
        },
        "ArnLike": {
          "aws:SourceArn": "arn:aws:bedrock-agentcore:${LABSOBO_AWS_REGION}:${LABSOBO_AWS_ACCOUNT_ID}:*"
        }
      }
    }
  ]
}
EOF
```

Create the role:

```bash
aws iam create-role \
  --role-name "labsOBO-agent1-execution-role" \
  --assume-role-policy-document \
    file:///tmp/labsOBO-agentcore-trust.json
```

Create the outbound-federation policy:

```bash
cat > /tmp/labsOBO-agent-outbound-token.json <<'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "sts:GetWebIdentityToken",
      "Resource": "*",
      "Condition": {
        "ForAllValues:StringEquals": {
          "sts:IdentityTokenAudience": "api://AzureADTokenExchange"
        },
        "NumericLessThanEquals": {
          "sts:DurationSeconds": 300
        }
      }
    }
  ]
}
EOF
```

Attach inline:

```bash
aws iam put-role-policy \
  --role-name "labsOBO-agent1-execution-role" \
  --policy-name "labsOBO-AgentOutboundIdentity" \
  --policy-document \
    file:///tmp/labsOBO-agent-outbound-token.json
```

Retrieve ARN:

```bash
export LABSOBO_A1_EXECUTION_ROLE_ARN="$(
  aws iam get-role \
    --role-name "labsOBO-agent1-execution-role" \
    --query 'Role.Arn' \
    --output text
)"
```

> Merge the ECR, logs, model, and any tool permissions required by your actual runtime with this role. Those permissions are workload-specific and are not replaced by the outbound-token statement above.

Reference:

https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-permissions.html

---

# 14. Create/configure the AgentCore runtime

Runtime:

```text
labsOBO_agent1_runtime
```

Execution role:

```text
labsOBO-agent1-execution-role
```

## Portal

In Amazon Bedrock AgentCore, create the A1 runtime using:

```text
Runtime name
labsOBO_agent1_runtime

Execution role
labsOBO-agent1-execution-role

Protocol
HTTP

Inbound authorization
Custom JWT
```

Configure the Entra discovery URL:

```text
https://login.microsoftonline.com/<TENANT_ID>/v2.0/.well-known/openid-configuration
```

Configure:

```text
aud
= exact observed BP-A1 audience

scope
= labsOBO_access_agent

azp
= labsOBO-calling-app client ID

roles
contains labsOBO.AgentInvoker
```

Also allow the inbound header:

```text
Authorization
```

to reach A1 after AgentCore validates it.

## Terminal equivalent

Prepare runtime configuration:

```bash
export A1_CONTAINER_URI="<account>.dkr.ecr.${LABSOBO_AWS_REGION}.amazonaws.com/<repo>:<tag>"
```

Create:

```bash
aws bedrock-agentcore-control create-agent-runtime \
  --region "${LABSOBO_AWS_REGION}" \
  --agent-runtime-name "labsOBO_agent1_runtime" \
  --agent-runtime-artifact \
    "containerConfiguration={containerUri=${A1_CONTAINER_URI}}" \
  --role-arn "${LABSOBO_A1_EXECUTION_ROLE_ARN}" \
  --network-configuration 'networkMode=PUBLIC' \
  --protocol-configuration 'serverProtocol=HTTP' \
  --authorizer-configuration '{
    "customJWTAuthorizer": {
      "discoveryUrl": "https://login.microsoftonline.com/'"${LABSOBO_TENANT_ID}"'/v2.0/.well-known/openid-configuration",
      "allowedAudience": [
        "'"${LABSOBO_BP_A1_CLIENT_ID}"'"
      ],
      "allowedScopes": [
        "labsOBO_access_agent"
      ],
      "customClaims": [
        {
          "inboundTokenClaimName": "azp",
          "inboundTokenClaimValueType": "STRING",
          "authorizingClaimMatchValue": {
            "claimMatchOperator": "EQUALS",
            "claimMatchValue": {
              "matchValueString": "'"${LABSOBO_CALLING_APP_CLIENT_ID}"'"
            }
          }
        },
        {
          "inboundTokenClaimName": "roles",
          "inboundTokenClaimValueType": "STRING_ARRAY",
          "authorizingClaimMatchValue": {
            "claimMatchOperator": "CONTAINS",
            "claimMatchValue": {
              "matchValueString": "labsOBO.AgentInvoker"
            }
          }
        }
      ]
    }
  }' \
  --request-header-configuration \
    'requestHeaderAllowlist=Authorization' \
  --environment-variables \
    "LABSOBO_TENANT_ID=${LABSOBO_TENANT_ID},LABSOBO_BP_A1_CLIENT_ID=${LABSOBO_BP_A1_CLIENT_ID},LABSOBO_AGENT_A1_CLIENT_ID=${LABSOBO_AGENT_A1_CLIENT_ID},LABSOBO_BROKER_CLIENT_ID=${LABSOBO_BROKER_CLIENT_ID}"
```

Capture the response:

```text
agentRuntimeId
agentRuntimeArn
```

Verify:

```bash
aws bedrock-agentcore-control get-agent-runtime \
  --region "${LABSOBO_AWS_REGION}" \
  --agent-runtime-id "${LABSOBO_AGENTCORE_RUNTIME_ID}"
```

> If your installed AgentCore control-plane CLI version rejects a field in the inline JSON, use `aws bedrock-agentcore-control create-agent-runtime --generate-cli-skeleton input` and place the same configuration into the generated version-specific JSON schema.

References:

https://docs.aws.amazon.com/cli/latest/reference/bedrock-agentcore-control/create-agent-runtime.html

https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/inbound-jwt-authorizer.html

---

# 15. Enable AWS outbound identity federation

This allows AWS STS to mint a signed JWT representing the A1 execution role.

## Portal

1. Open **AWS IAM**.

2. Select:

   **Account settings**

3. Locate:

   **Outbound Identity Federation**

4. Select **Enable**.

![Enable AWS outbound identity federation](https://docs.aws.amazon.com/images/IAM/latest/UserGuide/images/outbound-screen-1.png)

5. After enabling, record the **Token issuer URL**.

![AWS outbound identity issuer](https://docs.aws.amazon.com/images/IAM/latest/UserGuide/images/outbound-screen-2.png)

Expected shape:

```text
https://<unique-id>.tokens.sts.global.api.aws
```

## Terminal equivalent

Enable:

```bash
aws iam enable-outbound-web-identity-federation
```

Read current configuration:

```bash
aws iam get-outbound-web-identity-federation-info
```

Capture:

```bash
export LABSOBO_AWS_OIDC_ISSUER="$(
  aws iam get-outbound-web-identity-federation-info \
    --query 'IssuerUrl' \
    --output text
)"
```

Inspect discovery:

```bash
curl \
  "${LABSOBO_AWS_OIDC_ISSUER}/.well-known/openid-configuration" |
jq
```

Inspect signing keys:

```bash
curl \
  "${LABSOBO_AWS_OIDC_ISSUER}/.well-known/jwks.json" |
jq
```

Reference:

https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_outbound_getting_started.html

---

# 16. Configure BP-A1 to trust the AWS role

Trust statement:

```text
The exact A1 execution role may authenticate BP-A1
for the AzureADTokenExchange audience.
```

FIC:

```text
name
labsOBO-agentcore-aws

issuer
LABSOBO_AWS_OIDC_ISSUER

subject
LABSOBO_A1_EXECUTION_ROLE_ARN

audience
api://AzureADTokenExchange
```

## Portal

Where the blueprint's **Federated credentials** page supports an external OIDC issuer:

1. Open BP-A1.

2. Open the blueprint credential / federated credential configuration.

3. Create a federated credential.

4. Use:

   ```text
   Issuer
   <LABSOBO_AWS_OIDC_ISSUER>

   Subject
   <LABSOBO_A1_EXECUTION_ROLE_ARN>

   Audience
   api://AzureADTokenExchange
   ```

5. Save.

For this lab, the Graph/API form below is the canonical representation because the AWS issuer/subject pairing is explicit and unambiguous.

## Terminal equivalent

```powershell
Connect-MgGraph `
  -TenantId $env:LABSOBO_TENANT_ID `
  -Scopes "AgentIdentityBlueprint.AddRemoveCreds.All"
```

Create:

```powershell
$fic = @{
    Name      = "labsOBO-agentcore-aws"
    Issuer    = $env:LABSOBO_AWS_OIDC_ISSUER
    Subject   = $env:LABSOBO_A1_EXECUTION_ROLE_ARN
    Audiences = @("api://AzureADTokenExchange")
}

New-MgApplicationFederatedIdentityCredential `
  -ApplicationId $env:LABSOBO_BP_A1_OBJECT_ID `
  -BodyParameter $fic
```

Verify:

```powershell
Get-MgApplicationFederatedIdentityCredential `
  -ApplicationId $env:LABSOBO_BP_A1_OBJECT_ID |
  Format-Table Name,Issuer,Subject
```

The later token exchange depends on exact matching:

```text
AWS JWT iss == FIC issuer
AWS JWT sub == FIC subject
AWS JWT aud == FIC audience
```

Reference:

https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation-create-trust

---

# 17. Grant AGENT-A1 → Defender delegated permission

Required delegated permission:

```text
AdvancedHunting.Read
```

Grant it to:

```text
AGENT-A1
```

not:

```text
labsOBO-calling-app
BP-A1
```

## Portal / administrative model

The Agent Identity itself does not open an interactive consent screen.

The permission must be preconfigured/admin-consented for AGENT-A1.

The human also needs native Defender authorization:

```text
RAJARAJAN
  View Data
  relevant device/device-group access
```

## Terminal equivalent

The source lab creates the delegated consent record directly.

```powershell
Connect-MgGraph `
  -TenantId $env:LABSOBO_TENANT_ID `
  -Scopes "Application.Read.All","DelegatedPermissionGrant.ReadWrite.All"
```

Set the Defender resource service-principal ID:

```powershell
$env:LABSOBO_DEFENDER_RESOURCE_SP_ID = "<Defender-API-service-principal-object-id>"
```

Grant:

```powershell
$params = @{
    ClientId    = $env:LABSOBO_AGENT_A1_OBJECT_ID
    ConsentType = "AllPrincipals"
    ResourceId  = $env:LABSOBO_DEFENDER_RESOURCE_SP_ID
    Scope       = "AdvancedHunting.Read"
}

New-MgOauth2PermissionGrant `
  -BodyParameter $params
```

Verify:

```powershell
Get-MgOauth2PermissionGrant `
  -Filter "clientId eq '$($env:LABSOBO_AGENT_A1_OBJECT_ID)'" |
  Where-Object {
      $_.ResourceId -eq $env:LABSOBO_DEFENDER_RESOURCE_SP_ID
  } |
  Format-Table ClientId,ResourceId,Scope,ConsentType
```

Expected:

```text
AdvancedHunting.Read
```

Reference:

https://learn.microsoft.com/en-us/defender-xdr/api-create-app-user

---

# 18. Create the Jira credential-broker Entra application

Example:

```text
labsOBO-credential-broker
```

The broker is a normal Entra-protected API.

## Portal

1. Browse to:

   **Entra ID > App registrations > New registration**

2. Enter:

   ```text
   labsOBO-credential-broker
   ```

3. Select:

   ```text
   Accounts in this organizational directory only
   ```

4. Select **Register**.

5. Open **Expose an API**.

6. Configure the Application ID URI:

   ```text
   api://<BROKER-CLIENT-ID>
   ```

7. Select **Add a scope**.

![Expose broker API](https://learn.microsoft.com/en-us/entra/identity-platform/media/quickstart-configure-app-expose-web-apis/portal-02-expose-api.png)

8. Create:

   ```text
   labsOBO_jira.create
   ```

## Terminal equivalent

Create app + service principal:

```bash
BROKER_JSON="$(
  az ad app create \
    --display-name "labsOBO-credential-broker" \
    --sign-in-audience AzureADMyOrg
)"

export LABSOBO_BROKER_CLIENT_ID="$(
  printf '%s' "$BROKER_JSON" | jq -r '.appId'
)"

export LABSOBO_BROKER_OBJECT_ID="$(
  printf '%s' "$BROKER_JSON" | jq -r '.id'
)"

BROKER_SP_JSON="$(
  az ad sp create \
    --id "${LABSOBO_BROKER_CLIENT_ID}"
)"

export LABSOBO_BROKER_PRINCIPAL_ID="$(
  printf '%s' "$BROKER_SP_JSON" | jq -r '.id'
)"
```

Configure its scope with Graph PowerShell:

```powershell
Connect-MgGraph `
  -TenantId $env:LABSOBO_TENANT_ID `
  -Scopes "Application.ReadWrite.All"

$scopeId = [guid]::NewGuid()
$env:LABSOBO_BROKER_SCOPE_ID = $scopeId.ToString()

$body = @{
    identifierUris = @(
        "api://$($env:LABSOBO_BROKER_CLIENT_ID)"
    )
    api = @{
        requestedAccessTokenVersion = 2
        oauth2PermissionScopes = @(
            @{
                adminConsentDescription = "Allow Agent A1 to request Jira credentials on behalf of the signed-in user."
                adminConsentDisplayName = "Create Jira issues through labsOBO broker"
                userConsentDescription = "Allows Agent A1 to create Jira issues on your behalf through the broker."
                userConsentDisplayName = "Create Jira issues on your behalf"
                id = $scopeId
                isEnabled = $true
                type = "User"
                value = "labsOBO_jira.create"
            }
        )
    }
} | ConvertTo-Json -Depth 10

Invoke-MgGraphRequest `
  -Method PATCH `
  -Uri "https://graph.microsoft.com/v1.0/applications/$($env:LABSOBO_BROKER_OBJECT_ID)" `
  -Body $body `
  -ContentType "application/json"
```

Expected full scope:

```text
api://<BROKER-CLIENT-ID>/labsOBO_jira.create
```

---

# 19. Grant AGENT-A1 → Broker delegated permission

The OBO client for this hop is:

```text
AGENT-A1
```

The calling application must not be substituted here.

## Portal / administrative model

Grant/admin-consent:

```text
AGENT-A1
      │
      │ delegated
      │ labsOBO_jira.create
      ▼
Credential Broker
```

The broker later validates:

```text
oid = RAJARAJAN
azp = AGENT-A1
aud = Broker
scp = labsOBO_jira.create
```

## Terminal equivalent

```powershell
Connect-MgGraph `
  -TenantId $env:LABSOBO_TENANT_ID `
  -Scopes "DelegatedPermissionGrant.ReadWrite.All","Application.Read.All"
```

Grant:

```powershell
$params = @{
    ClientId    = $env:LABSOBO_AGENT_A1_OBJECT_ID
    ConsentType = "AllPrincipals"
    ResourceId  = $env:LABSOBO_BROKER_PRINCIPAL_ID
    Scope       = "labsOBO_jira.create"
}

New-MgOauth2PermissionGrant `
  -BodyParameter $params
```

Verify:

```powershell
Get-MgOauth2PermissionGrant `
  -Filter "clientId eq '$($env:LABSOBO_AGENT_A1_OBJECT_ID)'" |
  Where-Object {
      $_.ResourceId -eq $env:LABSOBO_BROKER_PRINCIPAL_ID
  } |
  Format-Table ClientId,ResourceId,Scope,ConsentType
```

Expected:

```text
labsOBO_jira.create
```

---

# 20. Create the Atlassian OAuth 2.0 / 3LO application

Atlassian is a second OAuth authority.

```text
Name
labsOBO-security-investigation-agent

Callback
http://localhost:3100/oauth/jira/callback

Scopes used by the lab
write:jira-work
offline_access
```

## Portal

1. Sign in to:

   **developer.atlassian.com**

2. Open the **Developer console**.

3. Create an OAuth 2.0 integration.

4. Name it:

   ```text
   labsOBO-security-investigation-agent
   ```

5. Open **Authorization**.

6. Configure OAuth 2.0 (3LO).

7. Set callback:

   ```text
   http://localhost:3100/oauth/jira/callback
   ```

8. Configure the Jira write scope needed by the integration.

9. Record:

   ```text
   Atlassian client ID
   Atlassian client secret
   ```

Storage boundary:

```text
client secret  → Broker only
refresh token  → Broker only
```

## CLI equivalent

**No supported Atlassian CLI/API equivalent is documented for provisioning the 3LO application itself.**

This setup remains a developer-console action.

After the app exists, the *runtime OAuth exchanges* are HTTP APIs and are covered in:

```text
04-agent-jira.md
```

For example, the broker later exchanges an authorization code at:

```text
POST https://auth.atlassian.com/oauth/token
```

Do not invent an infrastructure-provisioning CLI for this step.

Reference:

https://developer.atlassian.com/cloud/jira/platform/oauth-2-3lo-apps/

---

# 21. Verify the final configuration graph

Expected directory/resource relationships:

```text
RAJARAJAN
   │
   │ labsOBO.AgentInvoker
   ▼
BP-A1
   ▲
   │ labsOBO_access_agent
   │
labsOBO-calling-app


AWS execution role
   │
   │ STS outbound OIDC
   ▼
BP-A1 FIC
   │
   │ child binding
   ▼
AGENT-A1


AGENT-A1
   ├── AdvancedHunting.Read ─────▶ Defender
   │
   └── labsOBO_jira.create ─────▶ Broker
                                      │
                                      └── Atlassian 3LO ─────▶ Jira
```

## Terminal verification

### Calling app

```bash
az ad app show \
  --id "${LABSOBO_CALLING_APP_CLIENT_ID}" \
  -o yaml
```

### BP-A1 user assignment

```powershell
Get-MgUserAppRoleAssignment `
  -UserId $env:LABSOBO_RAJARAJAN_USER_OBJECT_ID |
  Where-Object {
      $_.ResourceId -eq $env:LABSOBO_BP_A1_PRINCIPAL_ID
  }
```

### Delegated grants

```powershell
Get-MgOauth2PermissionGrant |
  Where-Object {
      $_.ClientId -in @(
          $env:LABSOBO_CALLING_APP_PRINCIPAL_ID,
          $env:LABSOBO_AGENT_A1_OBJECT_ID
      )
  } |
  Format-Table ClientId,ResourceId,Scope,ConsentType
```

### AWS federation

```bash
aws iam get-outbound-web-identity-federation-info
```

### AgentCore runtime

```bash
aws bedrock-agentcore-control get-agent-runtime \
  --region "${LABSOBO_AWS_REGION}" \
  --agent-runtime-id "${LABSOBO_AGENTCORE_RUNTIME_ID}"
```

---

# 22. Export the runtime configuration

The setup team hands identifiers/configuration to the runtime developers.

```bash
export LABSOBO_TENANT_ID="<tenant-id>"

export LABSOBO_CALLING_APP_CLIENT_ID="05d1bf77-a2e4-4c1c-9ef1-31dff291dd45"
export LABSOBO_CALLING_APP_OBJECT_ID="<application-object-id>"
export LABSOBO_CALLING_APP_PRINCIPAL_ID="<service-principal-object-id>"

export LABSOBO_BP_A1_CLIENT_ID="5e5c2e3c-35b8-4817-8dc9-96b09adb6865"
export LABSOBO_BP_A1_OBJECT_ID="<blueprint-application-object-id>"
export LABSOBO_BP_A1_PRINCIPAL_ID="<blueprint-principal-object-id>"

export LABSOBO_ACCESS_SCOPE="labsOBO_access_agent"
export LABSOBO_ACCESS_SCOPE_ID="<scope-guid>"

export LABSOBO_AGENT_INVOKER_ROLE="labsOBO.AgentInvoker"
export LABSOBO_AGENT_INVOKER_ROLE_ID="<role-guid>"

export LABSOBO_AGENT_A1_CLIENT_ID="<agent-client-id>"
export LABSOBO_AGENT_A1_OBJECT_ID="<agent-service-principal-object-id>"

export LABSOBO_RAJARAJAN_USER_OBJECT_ID="2faa25c9-590d-4723-aebb-f39f819ce489"

export LABSOBO_REDIRECT_URI="http://localhost:3100/auth/callback"

export LABSOBO_AWS_ACCOUNT_ID="<aws-account-id>"
export LABSOBO_AWS_REGION="us-east-1"
export LABSOBO_A1_EXECUTION_ROLE_ARN="arn:aws:iam::<account>:role/labsOBO-agent1-execution-role"
export LABSOBO_AWS_OIDC_ISSUER="https://<id>.tokens.sts.global.api.aws"

export LABSOBO_AGENTCORE_RUNTIME_ID="<runtime-id>"
export LABSOBO_AGENTCORE_RUNTIME_ARN="<runtime-arn>"
export LABSOBO_AGENTCORE_INVOKE_URL="<invoke-url>"

export LABSOBO_BROKER_CLIENT_ID="<broker-client-id>"
export LABSOBO_BROKER_OBJECT_ID="<broker-object-id>"
export LABSOBO_BROKER_PRINCIPAL_ID="<broker-service-principal-id>"

export LABSOBO_ATLASSIAN_CLIENT_ID="<atlassian-client-id>"
export LABSOBO_ATLASSIAN_CALLBACK="http://localhost:3100/oauth/jira/callback"
```

Do **not** place these in the shared configuration document:

```text
calling-app private key
Atlassian client secret
access tokens
refresh tokens
AWS temporary credentials
```

---

# 23. Completion check

```text
CALLING APPLICATION
[ ] labsOBO-calling-app exists
[ ] single tenant
[ ] Web callback registered
[ ] public certificate registered
[ ] private key remains outside Entra

BP-A1
[ ] blueprint exists
[ ] principal exists
[ ] owner/sponsor configured
[ ] identifier URI exists
[ ] labsOBO_access_agent exists
[ ] requestedAccessTokenVersion = 2

USER ENTITLEMENT
[ ] labsOBO.AgentInvoker exists
[ ] assignment required
[ ] RAJARAJAN assigned
[ ] SAM unassigned

APP → BP-A1
[ ] calling app declares labsOBO_access_agent
[ ] tenant-wide delegated consent exists

AGENT-A1
[ ] child identity exists
[ ] parent = BP-A1
[ ] no agent-local secret/certificate

AGENTCORE / AWS
[ ] dedicated A1 execution role exists
[ ] runtime exists
[ ] Entra discovery URL configured
[ ] BP-A1 audience checked
[ ] calling-app azp checked
[ ] scope checked
[ ] AgentInvoker role checked
[ ] Authorization header forwarded
[ ] outbound identity federation enabled
[ ] issuer recorded
[ ] sts:GetWebIdentityToken restricted
[ ] BP-A1 FIC matches issuer / role / audience

DEFENDER
[ ] AGENT-A1 delegated grant includes AdvancedHunting.Read
[ ] RAJARAJAN has Defender View Data
[ ] RAJARAJAN has device/device-group access

JIRA
[ ] Broker app exists
[ ] Broker scope labsOBO_jira.create exists
[ ] AGENT-A1 delegated Broker grant exists
[ ] Atlassian 3LO application exists
[ ] callback configured
[ ] Atlassian secret stored only in Broker
```

Quick terminal sanity check:

```bash
set -eu

test -n "${LABSOBO_TENANT_ID}"
test -n "${LABSOBO_CALLING_APP_CLIENT_ID}"
test -n "${LABSOBO_BP_A1_CLIENT_ID}"
test -n "${LABSOBO_AGENT_A1_CLIENT_ID}"
test -n "${LABSOBO_A1_EXECUTION_ROLE_ARN}"
test -n "${LABSOBO_AWS_OIDC_ISSUER}"
test -n "${LABSOBO_AGENTCORE_RUNTIME_ID}"
test -n "${LABSOBO_BROKER_CLIENT_ID}"

echo "Core labsOBO setup identifiers are populated."
```

Once complete:

```text
NEXT
01-user-entra-app.md
```

---

# Official references

## Microsoft Entra / Agent ID

- https://learn.microsoft.com/en-us/graph/auth-register-app-v2
- https://learn.microsoft.com/en-us/entra/agent-id/create-blueprint
- https://learn.microsoft.com/en-us/entra/agent-id/create-delete-agent-identities
- https://learn.microsoft.com/en-us/entra/agent-id/control-user-access-agents
- https://learn.microsoft.com/en-us/entra/identity-platform/howto-add-app-roles-in-apps
- https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-configure-app-expose-web-apis
- https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/assign-user-or-group-access-portal
- https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/grant-admin-consent
- https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation-create-trust
- https://learn.microsoft.com/en-us/graph/api/oauth2permissiongrant-post

## AWS

- https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-permissions.html
- https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/inbound-jwt-authorizer.html
- https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-header-allowlist.html
- https://docs.aws.amazon.com/cli/latest/reference/bedrock-agentcore-control/create-agent-runtime.html
- https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_outbound_getting_started.html
- https://docs.aws.amazon.com/STS/latest/APIReference/API_GetWebIdentityToken.html

## Defender

- https://learn.microsoft.com/en-us/defender-xdr/api-create-app-user
- https://learn.microsoft.com/en-us/defender-xdr/api-advanced-hunting

## Atlassian

- https://developer.atlassian.com/cloud/jira/platform/oauth-2-3lo-apps/
