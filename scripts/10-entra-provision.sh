#!/usr/bin/env bash
# labsOBO | Phases 1-7 (+ direct client + agent identity), all in Entra.
#
# Idempotent: every step looks the object up by name first and only creates
# what is missing, so the script can be re-run after a partial failure.
#
# Creates
#   labsOBO-agent1-blueprint   agentIdentityBlueprint   BP-A1 (the agent API boundary)
#   labsOBO-agent1             agentIdentity            A1 (child of BP-A1, used for OBO)
#   labsOBO-calling-app        confidential client      APP (cert, redirect :3100)
#   labsOBO-direct-client      public client            Phase 15 contrast client
#   Alex = Balaji (existing user, assigned)   Sam = Rajan (existing user, NOT assigned)
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/lib.sh

ME=$(az ad signed-in-user show --query id -o tsv)
ME_UPN=$(az ad signed-in-user show --query userPrincipalName -o tsv)
TENANT=$(az account show --query tenantId -o tsv)
DOMAIN=$(gget "v1.0/domains?\$select=id,isDefault" | jq_ 'print([x["id"] for x in d["value"] if x.get("isDefault")][0])')
say tenant "$TENANT"; say admin "$ME_UPN ($ME)"; say domain "$DOMAIN"
state_set tenantId "\"$TENANT\""
state_set admin "{\"upn\":\"$ME_UPN\",\"objectId\":\"$ME\",\"role\":\"tenant admin running this lab (sponsor of the blueprint and agent)\"}"

# ---------------------------------------------------------------- Phase 1: BP-A1
echo; echo "Phase 1 - blueprint"
BP_APP=$(gget "beta/applications?\$filter=displayName eq '${LABSOBO_BP_A1_NAME}'&\$select=id,appId" | jq_ 'v=d["value"]; print(v[0]["appId"]+" "+v[0]["id"] if v else "")')
if [ -z "$BP_APP" ]; then
  BP_APP=$(gpost "beta/applications" "{\"@odata.type\":\"#microsoft.graph.agentIdentityBlueprint\",
     \"displayName\":\"${LABSOBO_BP_A1_NAME}\",
     \"sponsors@odata.bind\":[\"https://graph.microsoft.com/beta/directoryObjects/${ME}\"]}" \
     | jq_ 'print(d["appId"]+" "+d["id"])')
  say "created blueprint" "$BP_APP"
else
  say "blueprint exists" "$BP_APP"
fi
BP_CLIENT_ID=${BP_APP%% *}; BP_OBJECT_ID=${BP_APP##* }

# ---------------------------------------------------------------- Phase 2+3: API + app role
echo; echo "Phase 2/3 - expose API scope + AgentInvoker app role"
BP_JSON=$(gget "beta/applications/${BP_OBJECT_ID}")
SCOPE_ID=$(echo "$BP_JSON" | jq_ 's=[x for x in d.get("api",{}).get("oauth2PermissionScopes",[]) if x["value"]=="'"$LABSOBO_ACCESS_SCOPE_VALUE"'"]; print(s[0]["id"] if s else "")')
ROLE_ID=$(echo "$BP_JSON"  | jq_ 'r=[x for x in d.get("appRoles",[]) if x["value"]=="'"$LABSOBO_AGENT_INVOKER_ROLE_VALUE"'"]; print(r[0]["id"] if r else "")')
[ -n "$SCOPE_ID" ] || SCOPE_ID=$(python3 -c "import uuid;print(uuid.uuid4())")
[ -n "$ROLE_ID" ]  || ROLE_ID=$(python3 -c "import uuid;print(uuid.uuid4())")

# Blueprint certificate: the credential behind T1 in Phase 16 (agent OBO).
# Agent identities cannot hold credentials; only the blueprint can.
CERT_DIR=infra/entra/certs
if [ ! -f "$CERT_DIR/${LABSOBO_BP_A1_NAME}.key.pem" ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -keyout "$CERT_DIR/${LABSOBO_BP_A1_NAME}.key.pem" \
    -out "$CERT_DIR/${LABSOBO_BP_A1_NAME}.cert.pem" -days 365 -subj "/CN=${LABSOBO_BP_A1_NAME}" 2>/dev/null
  chmod 600 "$CERT_DIR/${LABSOBO_BP_A1_NAME}.key.pem"
  say "generated cert" "$LABSOBO_BP_A1_NAME"
fi
BP_KEY_B64=$(openssl x509 -in "$CERT_DIR/${LABSOBO_BP_A1_NAME}.cert.pem" -outform DER | base64)
BP_X5T=$(openssl x509 -in "$CERT_DIR/${LABSOBO_BP_A1_NAME}.cert.pem" -outform DER | openssl dgst -sha1 -binary | base64)

gpatch "beta/applications/${BP_OBJECT_ID}" "{
  \"identifierUris\":[\"api://${BP_CLIENT_ID}\"],
  \"api\":{\"requestedAccessTokenVersion\":2,
           \"oauth2PermissionScopes\":[{
             \"id\":\"${SCOPE_ID}\",\"value\":\"${LABSOBO_ACCESS_SCOPE_VALUE}\",\"type\":\"User\",\"isEnabled\":true,
             \"adminConsentDisplayName\":\"Invoke labsOBO Agent A1\",
             \"adminConsentDescription\":\"Allows the calling application to invoke labsOBO Agent A1 on behalf of the signed-in user.\",
             \"userConsentDisplayName\":\"Invoke labsOBO Agent A1 on your behalf\",
             \"userConsentDescription\":\"Allows the app to invoke labsOBO Agent A1 on your behalf.\"}]},
  \"appRoles\":[{
    \"id\":\"${ROLE_ID}\",\"allowedMemberTypes\":[\"User\"],\"isEnabled\":true,
    \"value\":\"${LABSOBO_AGENT_INVOKER_ROLE_VALUE}\",
    \"displayName\":\"${LABSOBO_AGENT_INVOKER_ROLE_DISPLAY}\",
    \"description\":\"${LABSOBO_AGENT_INVOKER_ROLE_DESC}\"}],
  \"keyCredentials\":[{\"type\":\"AsymmetricX509Cert\",\"usage\":\"Verify\",\"key\":\"${BP_KEY_B64}\",
    \"customKeyIdentifier\":\"${BP_X5T}\",\"displayName\":\"${LABSOBO_BP_A1_NAME} (T1 credential)\"}]
}" >/dev/null
say "identifier uri" "api://${BP_CLIENT_ID}"
say "scope" "${LABSOBO_ACCESS_SCOPE_VALUE} ($SCOPE_ID)"
say "app role" "${LABSOBO_AGENT_INVOKER_ROLE_VALUE} ($ROLE_ID)"

# Pre-authorize the Azure CLI on the scope so the operator's existing az session
# can obtain a real user token for BP-A1 (the autonomous pre-flight; no browser).
# beta names the field permissionIds; v1.0 names it delegatedPermissionIds. Try both.
if gpatch "beta/applications/${BP_OBJECT_ID}" "{\"api\":{\"preAuthorizedApplications\":[{\"appId\":\"${AZURE_CLI_APP_ID}\",\"permissionIds\":[\"${SCOPE_ID}\"]}]}}" >/dev/null 2>.lab/preauth.err \
   || gpatch "v1.0/applications/${BP_OBJECT_ID}" "{\"api\":{\"preAuthorizedApplications\":[{\"appId\":\"${AZURE_CLI_APP_ID}\",\"delegatedPermissionIds\":[\"${SCOPE_ID}\"]}]}}" >/dev/null 2>>.lab/preauth.err; then
  say "pre-authorized" "Azure CLI ($AZURE_CLI_APP_ID) on $LABSOBO_ACCESS_SCOPE_VALUE"
  state_set azureCli "{\"appId\":\"${AZURE_CLI_APP_ID}\",\"preAuthorizedOnScope\":true}"
else
  say "pre-authorize FAILED" "$(head -c 300 .lab/preauth.err)"
  state_set azureCli "{\"appId\":\"${AZURE_CLI_APP_ID}\",\"preAuthorizedOnScope\":false}"
fi

BP_SP=$(gget "beta/servicePrincipals?\$filter=appId eq '${BP_CLIENT_ID}'&\$select=id" | jq_ 'v=d["value"]; print(v[0]["id"] if v else "")')
if [ -z "$BP_SP" ]; then
  BP_SP=$(gpost "beta/servicePrincipals" "{\"appId\":\"${BP_CLIENT_ID}\"}" | jq_ 'print(d["id"])')
  say "created blueprint SP" "$BP_SP"
else
  say "blueprint SP exists" "$BP_SP"
fi

# ---------------------------------------------------------------- Phase 4: assignment required
echo; echo "Phase 4 - appRoleAssignmentRequired=true on the blueprint principal"
gpatch "v1.0/servicePrincipals/${BP_SP}" '{"appRoleAssignmentRequired": true}' >/dev/null
ARR=$(gget "v1.0/servicePrincipals/${BP_SP}?\$select=id,appId,displayName,appRoleAssignmentRequired" | jq_ 'print(d["appRoleAssignmentRequired"])')
say "appRoleAssignmentRequired" "$ARR"

state_set blueprintA1 "{\"label\":\"BP-A1\",\"displayName\":\"${LABSOBO_BP_A1_NAME}\",
  \"clientId\":\"${BP_CLIENT_ID}\",\"objectId\":\"${BP_OBJECT_ID}\",\"principalId\":\"${BP_SP}\",
  \"identifierUri\":\"api://${BP_CLIENT_ID}\",\"requestedAccessTokenVersion\":2,
  \"scope\":{\"value\":\"${LABSOBO_ACCESS_SCOPE_VALUE}\",\"id\":\"${SCOPE_ID}\",\"full\":\"api://${BP_CLIENT_ID}/${LABSOBO_ACCESS_SCOPE_VALUE}\"},
  \"appRole\":{\"value\":\"${LABSOBO_AGENT_INVOKER_ROLE_VALUE}\",\"id\":\"${ROLE_ID}\",\"displayName\":\"${LABSOBO_AGENT_INVOKER_ROLE_DISPLAY}\",\"allowedMemberTypes\":[\"User\"]},
  \"appRoleAssignmentRequired\":$(echo "$ARR" | tr "A-Z" "a-z"),
  \"certificate\":\"infra/entra/certs/${LABSOBO_BP_A1_NAME}.{key,cert}.pem (T1 credential for Phase 16)\"}"

# ---------------------------------------------------------------- Users (existing)
echo; echo "Users - Alex and Sam are EXISTING tenant users (no accounts are created)"
lookup() { gget "v1.0/users?\$filter=userPrincipalName eq '$1'&\$select=id,displayName" | jq_ 'v=d["value"]; print(v[0]["id"]+" "+v[0]["displayName"] if v else "")'; }
ALEX_INFO=$(lookup "$LABSOBO_ALEX_UPN"); SAM_INFO=$(lookup "$LABSOBO_SAM_UPN")
[ -n "$ALEX_INFO" ] || { echo "Alex user $LABSOBO_ALEX_UPN not found"; exit 1; }
[ -n "$SAM_INFO" ]  || { echo "Sam user $LABSOBO_SAM_UPN not found"; exit 1; }
ALEX=${ALEX_INFO%% *}; ALEX_NAME=${ALEX_INFO#* }
SAM=${SAM_INFO%% *};   SAM_NAME=${SAM_INFO#* }
say "Alex =" "$ALEX_NAME <$LABSOBO_ALEX_UPN> ($ALEX)"
say "Sam  =" "$SAM_NAME <$LABSOBO_SAM_UPN> ($SAM)"
state_set users "{\"alex\":{\"role\":\"Alex - the entitled user\",\"displayName\":\"${ALEX_NAME}\",\"upn\":\"${LABSOBO_ALEX_UPN}\",\"objectId\":\"${ALEX}\",\"assigned\":true},
                  \"sam\":{\"role\":\"Sam - the non-entitled user\",\"displayName\":\"${SAM_NAME}\",\"upn\":\"${LABSOBO_SAM_UPN}\",\"objectId\":\"${SAM}\",\"assigned\":false}}"

# ---------------------------------------------------------------- Phase 5: assign Alex only
echo; echo "Phase 5 - assign Alex -> ${LABSOBO_AGENT_INVOKER_ROLE_VALUE} -> BP-A1 (Sam deliberately not assigned)"
HAS=$(gget "v1.0/users/${ALEX}/appRoleAssignments" | jq_ 'print(any(a["resourceId"]=="'"$BP_SP"'" and a["appRoleId"]=="'"$ROLE_ID"'" for a in d["value"]))')
if [ "$HAS" != "True" ]; then
  gpost "v1.0/users/${ALEX}/appRoleAssignments" "{\"principalId\":\"${ALEX}\",\"resourceId\":\"${BP_SP}\",\"appRoleId\":\"${ROLE_ID}\"}" | jq_ 'print("  assigned", d["principalDisplayName"], "->", d["resourceDisplayName"], d["id"])'
else
  say "Alex already assigned" ""
fi

# ---------------------------------------------------------------- Phase 7: calling app (+ direct client)
echo; echo "Phase 7 - calling application + Phase 15 direct client"
GRAPH_SP=$(gget "v1.0/servicePrincipals?\$filter=appId eq '${GRAPH_APP_ID}'&\$select=id" | jq_ 'print(d["value"][0]["id"])')
GRAPH_SCOPES=$(gget "v1.0/servicePrincipals/${GRAPH_SP}?\$select=oauth2PermissionScopes" | jq_ 'print(json.dumps({s["value"]:s["id"] for s in d["oauth2PermissionScopes"] if s["value"] in ("openid","profile","offline_access","User.Read")}))')
gscope() { echo "$GRAPH_SCOPES" | jq_ "print(d['$1'])"; }

if [ ! -f "$CERT_DIR/${LABSOBO_CALLING_APP_NAME}.key.pem" ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -keyout "$CERT_DIR/${LABSOBO_CALLING_APP_NAME}.key.pem" \
    -out "$CERT_DIR/${LABSOBO_CALLING_APP_NAME}.cert.pem" -days 365 -subj "/CN=${LABSOBO_CALLING_APP_NAME}" 2>/dev/null
  chmod 600 "$CERT_DIR/${LABSOBO_CALLING_APP_NAME}.key.pem"
  say "generated cert" "$LABSOBO_CALLING_APP_NAME"
fi
APP_KEY_B64=$(openssl x509 -in "$CERT_DIR/${LABSOBO_CALLING_APP_NAME}.cert.pem" -outform DER | base64)
APP_X5T=$(openssl x509 -in "$CERT_DIR/${LABSOBO_CALLING_APP_NAME}.cert.pem" -outform DER | openssl dgst -sha1 -binary | base64)

RRA="[{\"resourceAppId\":\"${BP_CLIENT_ID}\",\"resourceAccess\":[{\"id\":\"${SCOPE_ID}\",\"type\":\"Scope\"}]},
      {\"resourceAppId\":\"${GRAPH_APP_ID}\",\"resourceAccess\":[
        {\"id\":\"$(gscope openid)\",\"type\":\"Scope\"},{\"id\":\"$(gscope profile)\",\"type\":\"Scope\"},
        {\"id\":\"$(gscope offline_access)\",\"type\":\"Scope\"},{\"id\":\"$(gscope User.Read)\",\"type\":\"Scope\"}]}]"

grant() {  # <clientSpId> <resourceSpId> <scopes>
  local EXIST; EXIST=$(gget "v1.0/oauth2PermissionGrants?\$filter=clientId eq '$1' and resourceId eq '$2'" | jq_ 'v=d["value"]; print(v[0]["id"] if v else "")')
  if [ -z "$EXIST" ]; then
    gpost "v1.0/oauth2PermissionGrants" "{\"clientId\":\"$1\",\"consentType\":\"AllPrincipals\",\"resourceId\":\"$2\",\"scope\":\"$3\"}" >/dev/null
    say "admin consent" "$3"
  else
    gpatch "v1.0/oauth2PermissionGrants/${EXIST}" "{\"scope\":\"$3\"}" >/dev/null
    say "admin consent (kept)" "$3"
  fi
}

mkclient() {  # <name> <json-app-body>  -> "appId objectId spId"
  local NAME="$1" BODY="$2"
  local IDS; IDS=$(gget "v1.0/applications?\$filter=displayName eq '${NAME}'&\$select=id,appId" | jq_ 'v=d["value"]; print(v[0]["appId"]+" "+v[0]["id"] if v else "")')
  if [ -z "$IDS" ]; then
    IDS=$(gpost "v1.0/applications" "$BODY" | jq_ 'print(d["appId"]+" "+d["id"])')
    say "created app" "$NAME ${IDS%% *}"
  else
    say "app exists" "$NAME ${IDS%% *}"
  fi
  local APPID=${IDS%% *}
  local SP; SP=$(gget "v1.0/servicePrincipals?\$filter=appId eq '${APPID}'&\$select=id" | jq_ 'v=d["value"]; print(v[0]["id"] if v else "")')
  [ -n "$SP" ] || SP=$(gpost "v1.0/servicePrincipals" "{\"appId\":\"${APPID}\",\"tags\":[\"labsOBO\"]}" | jq_ 'print(d["id"])')
  grant "$SP" "$BP_SP" "$LABSOBO_ACCESS_SCOPE_VALUE"
  grant "$SP" "$GRAPH_SP" "openid profile offline_access User.Read"
  echo "$IDS $SP"
}

APP_IDS=$(mkclient "$LABSOBO_CALLING_APP_NAME" "{
  \"displayName\":\"${LABSOBO_CALLING_APP_NAME}\",\"signInAudience\":\"AzureADMyOrg\",\"tags\":[\"labsOBO\"],
  \"notes\":\"labsOBO | APP - the calling application (confidential client, certificate credential).\",
  \"web\":{\"redirectUris\":[\"${LABSOBO_REDIRECT_URI}\"]},
  \"requiredResourceAccess\":${RRA},
  \"keyCredentials\":[{\"type\":\"AsymmetricX509Cert\",\"usage\":\"Verify\",\"key\":\"${APP_KEY_B64}\",
     \"customKeyIdentifier\":\"${APP_X5T}\",\"displayName\":\"${LABSOBO_CALLING_APP_NAME} client assertion\"}]}" | tail -1)
read -r APP_CLIENT_ID APP_OBJECT_ID APP_SP <<<"$APP_IDS"
state_set callingApp "{\"label\":\"APP\",\"displayName\":\"${LABSOBO_CALLING_APP_NAME}\",\"clientId\":\"${APP_CLIENT_ID}\",
  \"objectId\":\"${APP_OBJECT_ID}\",\"principalId\":\"${APP_SP}\",\"redirectUri\":\"${LABSOBO_REDIRECT_URI}\",
  \"clientType\":\"confidential (certificate client assertion)\",
  \"certificate\":\"infra/entra/certs/${LABSOBO_CALLING_APP_NAME}.{key,cert}.pem\",
  \"adminConsent\":[\"${LABSOBO_ACCESS_SCOPE_VALUE} on BP-A1\",\"openid profile offline_access User.Read on Microsoft Graph\"]}"

DC_IDS=$(mkclient "$LABSOBO_DIRECT_CLIENT_NAME" "{
  \"displayName\":\"${LABSOBO_DIRECT_CLIENT_NAME}\",\"signInAudience\":\"AzureADMyOrg\",\"tags\":[\"labsOBO\"],
  \"notes\":\"labsOBO | Phase 15 contrast client - public client, no credential. Proves the APP is not what maps Alex to A1.\",
  \"isFallbackPublicClient\":true,
  \"publicClient\":{\"redirectUris\":[\"${LABSOBO_DIRECT_REDIRECT_URI}\"]},
  \"requiredResourceAccess\":${RRA}}" | tail -1)
read -r DC_CLIENT_ID DC_OBJECT_ID DC_SP <<<"$DC_IDS"
state_set directClient "{\"label\":\"DIRECT\",\"displayName\":\"${LABSOBO_DIRECT_CLIENT_NAME}\",\"clientId\":\"${DC_CLIENT_ID}\",
  \"objectId\":\"${DC_OBJECT_ID}\",\"principalId\":\"${DC_SP}\",\"redirectUri\":\"${LABSOBO_DIRECT_REDIRECT_URI}\",
  \"clientType\":\"public (PKCE, no credential)\",
  \"adminConsent\":[\"${LABSOBO_ACCESS_SCOPE_VALUE} on BP-A1\",\"openid profile offline_access User.Read on Microsoft Graph\"]}"

# ---------------------------------------------------------------- Phase 16 prep: agent identity
echo; echo "Phase 16 prep - agent identity ${LABSOBO_AGENT_A1_NAME} under BP-A1"
AG=$(gget "beta/servicePrincipals?\$filter=displayName eq '${LABSOBO_AGENT_A1_NAME}'&\$select=id,appId" | jq_ 'v=d["value"]; print(v[0]["appId"]+" "+v[0]["id"] if v else "")')
if [ -z "$AG" ]; then
  AG=$(gpost "beta/servicePrincipals" "{\"@odata.type\":\"#microsoft.graph.agentIdentity\",
     \"displayName\":\"${LABSOBO_AGENT_A1_NAME}\",\"agentIdentityBlueprintId\":\"${BP_CLIENT_ID}\",
     \"sponsors@odata.bind\":[\"https://graph.microsoft.com/beta/directoryObjects/${ME}\"]}" | jq_ 'print(d["appId"]+" "+d["id"])')
  say "created agent identity" "$AG"
else
  say "agent identity exists" "$AG"
fi
AG_CLIENT_ID=${AG%% *}; AG_OBJECT_ID=${AG##* }
# The OBO leg targets Microsoft Graph (/me). Consent must be written against the
# AGENT identity itself (finding from lab 2): an agent cannot consent interactively.
grant "$AG_OBJECT_ID" "$GRAPH_SP" "User.Read"
state_set agentA1 "{\"label\":\"A1\",\"displayName\":\"${LABSOBO_AGENT_A1_NAME}\",\"clientId\":\"${AG_CLIENT_ID}\",\"objectId\":\"${AG_OBJECT_ID}\",
  \"parentBlueprint\":\"${BP_CLIENT_ID}\",\"credential\":\"none - agent identities cannot hold credentials; T1 uses the blueprint certificate\",
  \"downstream\":{\"resource\":\"Microsoft Graph\",\"scope\":\"User.Read\",\"call\":\"GET https://graph.microsoft.com/v1.0/me\",\"consentPrincipal\":\"the agent identity SP\"}}"

# ---------------------------------------------------------------- persist env
echo; echo "Persisting .lab/labsOBO.env"
cat > .lab/labsOBO.env <<ENV
# Generated by scripts/10-entra-provision.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ). Names from the lab plan.
LABSOBO_PREFIX="${LABSOBO_PREFIX}"
LABSOBO_CALLING_APP_NAME="${LABSOBO_CALLING_APP_NAME}"
LABSOBO_BP_A1_NAME="${LABSOBO_BP_A1_NAME}"
LABSOBO_AGENT_A1_NAME="${LABSOBO_AGENT_A1_NAME}"
LABSOBO_AGENT_INVOKER_ROLE_VALUE="${LABSOBO_AGENT_INVOKER_ROLE_VALUE}"
LABSOBO_ACCESS_SCOPE_VALUE="${LABSOBO_ACCESS_SCOPE_VALUE}"
LABSOBO_REDIRECT_URI="${LABSOBO_REDIRECT_URI}"
LABSOBO_AGENTCORE_RUNTIME_NAME="${LABSOBO_AGENTCORE_RUNTIME_NAME}"

LABSOBO_TENANT_ID="${TENANT}"
LABSOBO_CALLING_APP_CLIENT_ID="${APP_CLIENT_ID}"
LABSOBO_CALLING_APP_OBJECT_ID="${APP_OBJECT_ID}"
LABSOBO_CALLING_APP_PRINCIPAL_ID="${APP_SP}"
LABSOBO_DIRECT_CLIENT_ID="${DC_CLIENT_ID}"

LABSOBO_BP_A1_CLIENT_ID="${BP_CLIENT_ID}"
LABSOBO_BP_A1_OBJECT_ID="${BP_OBJECT_ID}"
LABSOBO_BP_A1_PRINCIPAL_ID="${BP_SP}"
LABSOBO_ACCESS_SCOPE_ID="${SCOPE_ID}"

LABSOBO_AGENT_A1_CLIENT_ID="${AG_CLIENT_ID}"
LABSOBO_AGENT_A1_OBJECT_ID="${AG_OBJECT_ID}"

LABSOBO_AGENT_INVOKER_ROLE_ID="${ROLE_ID}"

LABSOBO_ALEX_USER_ID="${ALEX}"
LABSOBO_SAM_USER_ID="${SAM}"
LABSOBO_ALEX_UPN="${LABSOBO_ALEX_UPN}"
LABSOBO_SAM_UPN="${LABSOBO_SAM_UPN}"
ENV
cat .lab/labsOBO.env | grep -v '^#'
