#!/usr/bin/env bash
# labsOBO | Phase 6 - prove the directory state BEFORE any OAuth flow runs.
# Pure Graph reads. Output is the first lab evidence (Entra directory screenshot).
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/lib.sh
source .lab/labsOBO.env

echo "== BP-A1 principal (assignment required?) =="
gget "v1.0/servicePrincipals/${LABSOBO_BP_A1_PRINCIPAL_ID}?\$select=id,appId,displayName,appRoleAssignmentRequired" \
  | jq_ 'print(json.dumps({k:d[k] for k in ("displayName","appId","appRoleAssignmentRequired")}, indent=2))'

echo; echo "== App roles published by BP-A1 =="
gget "beta/applications/${LABSOBO_BP_A1_OBJECT_ID}?\$select=appRoles,identifierUris,api" \
  | jq_ 'print(json.dumps({"identifierUris":d["identifierUris"],"appRoles":[{k:r[k] for k in ("id","value","displayName","allowedMemberTypes","isEnabled")} for r in d["appRoles"]],"scopes":[{k:s[k] for k in ("id","value","type","isEnabled")} for s in d["api"]["oauth2PermissionScopes"]],"preAuthorizedApplications":d["api"].get("preAuthorizedApplications")}, indent=2))'

check_user() {  # <label> <userId>
  echo; echo "== $1 ($2) appRoleAssignments =="
  gget "v1.0/users/$2/appRoleAssignments" | jq_ '
import json
bp="'"$LABSOBO_BP_A1_PRINCIPAL_ID"'"; role="'"$LABSOBO_AGENT_INVOKER_ROLE_ID"'"
hits=[a for a in d["value"] if a["resourceId"]==bp]
for a in d["value"]:
    print("   ", a["resourceDisplayName"].ljust(32), a["appRoleId"], "<-- BP-A1 " + ("labsOBO.AgentInvoker" if a["appRoleId"]==role else "?") if a["resourceId"]==bp else "")
print("   RESULT:", ("ASSIGNED to BP-A1 with " + ("labsOBO.AgentInvoker" if any(a["appRoleId"]==role for a in hits) else "another role")) if hits else "NO assignment to BP-A1")'
}
check_user "Alex = ${LABSOBO_ALEX_UPN}" "$LABSOBO_ALEX_USER_ID"
check_user "Sam  = ${LABSOBO_SAM_UPN}"  "$LABSOBO_SAM_USER_ID"

echo; echo "== BP-A1 appRoleAssignedTo (who holds a role on the blueprint) =="
gget "v1.0/servicePrincipals/${LABSOBO_BP_A1_PRINCIPAL_ID}/appRoleAssignedTo" \
  | jq_ 'print(json.dumps([{k:a[k] for k in ("principalDisplayName","principalType","appRoleId","id")} for a in d["value"]], indent=2))'

echo; echo "== Admin consent grants (oauth2PermissionGrants) =="
for pair in "APP:${LABSOBO_CALLING_APP_PRINCIPAL_ID}" "DIRECT:$(state_get directClient.principalId)" "AGENT-A1:${LABSOBO_AGENT_A1_OBJECT_ID}"; do
  gget "v1.0/oauth2PermissionGrants?\$filter=clientId eq '${pair#*:}'" | jq_ '
for g in d["value"]:
    res = "BP-A1" if g["resourceId"]=="'"$LABSOBO_BP_A1_PRINCIPAL_ID"'" else ("Microsoft Graph" if g["resourceId"]=="c5d922ee-be5f-42bd-ac6f-1a2681d7eb60" else g["resourceId"])
    print("   '"${pair%%:*}"'".ljust(10), g["consentType"].ljust(14), res.ljust(16), g["scope"])'
done
