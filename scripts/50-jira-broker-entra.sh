#!/usr/bin/env bash
# labsOBO | Jira path, Entra side (steps 14-15): the Jira broker API that A1 calls OBO.
#
# Creates
#   labsOBO-jira-broker   an ordinary API registration exposing the delegated scope labsOBO_jira.create
#                         (v2 access tokens, so the acting agent shows up as azp).
#                         T_A1_BROKER = OBO(T_APP_A1 + T1) for api://<broker>/labsOBO_jira.create:
#                         oid = the user, azp = AGENT-A1, aud = the broker, scp = labsOBO_jira.create.
#   admin consent         labsOBO_jira.create for the agent identity A1. An agent cannot consent
#                         interactively, so the grant is written against A1 itself (same as its Graph grant).
# Idempotent: re-running only fills in what is missing.
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/lib.sh
source .lab/labsOBO.env

BROKER_NAME="labsOBO-jira-broker"
SCOPE_VALUE="labsOBO_jira.create"

echo "Jira broker API"
APP=$(gget "v1.0/applications?\$filter=displayName eq '${BROKER_NAME}'&\$select=id,appId" | jq_ 'v=d["value"]; print(v[0]["appId"]+" "+v[0]["id"] if v else "")')
if [ -z "$APP" ]; then
  APP=$(gpost "v1.0/applications" "{\"displayName\":\"${BROKER_NAME}\",\"signInAudience\":\"AzureADMyOrg\",\"tags\":[\"labsOBO\"],
     \"notes\":\"labsOBO | Jira broker API (steps 14-16). Accepts T_A1_BROKER from AGENT-A1 and creates Jira issues with the user's own Atlassian grant.\",
     \"api\":{\"requestedAccessTokenVersion\":2}}" | jq_ 'print(d["appId"]+" "+d["id"])')
  say "created broker app" "$APP"
else
  say "broker app exists" "$APP"
fi
BROKER_CLIENT_ID=${APP%% *}; BROKER_OBJECT_ID=${APP##* }

SCOPE_ID=$(gget "v1.0/applications/${BROKER_OBJECT_ID}?\$select=api" | jq_ 's=[x for x in d.get("api",{}).get("oauth2PermissionScopes",[]) if x["value"]=="'"$SCOPE_VALUE"'"]; print(s[0]["id"] if s else "")')
if [ -z "$SCOPE_ID" ]; then
  SCOPE_ID=$(python3 -c "import uuid;print(uuid.uuid4())")
  gpatch "v1.0/applications/${BROKER_OBJECT_ID}" "{\"identifierUris\":[\"api://${BROKER_CLIENT_ID}\"],
     \"api\":{\"requestedAccessTokenVersion\":2,\"oauth2PermissionScopes\":[{\"id\":\"${SCOPE_ID}\",\"value\":\"${SCOPE_VALUE}\",\"type\":\"Admin\",\"isEnabled\":true,
       \"adminConsentDisplayName\":\"Create Jira issues through the labsOBO broker\",
       \"adminConsentDescription\":\"Lets an agent ask the labsOBO Jira broker to create Jira issues as the signed-in user, with that user's own Atlassian grant.\"}]}}" >/dev/null
  say "exposed scope" "api://${BROKER_CLIENT_ID}/${SCOPE_VALUE}"
else
  say "scope exists" "api://${BROKER_CLIENT_ID}/${SCOPE_VALUE}"
fi

SP=$(gget "v1.0/servicePrincipals?\$filter=appId eq '${BROKER_CLIENT_ID}'&\$select=id" | jq_ 'v=d["value"]; print(v[0]["id"] if v else "")')
[ -n "$SP" ] || { SP=$(gpost "v1.0/servicePrincipals" "{\"appId\":\"${BROKER_CLIENT_ID}\",\"tags\":[\"labsOBO\"]}" | jq_ 'print(d["id"])'); say "created broker principal" "$SP"; }

echo; echo "Admin consent: A1 -> ${SCOPE_VALUE}"
EXIST=$(gget "v1.0/oauth2PermissionGrants?\$filter=clientId eq '${LABSOBO_AGENT_A1_OBJECT_ID}' and resourceId eq '${SP}'" | jq_ 'v=d["value"]; print(v[0]["id"] if v else "")')
if [ -z "$EXIST" ]; then
  gpost "v1.0/oauth2PermissionGrants" "{\"clientId\":\"${LABSOBO_AGENT_A1_OBJECT_ID}\",\"consentType\":\"AllPrincipals\",\"resourceId\":\"${SP}\",\"scope\":\"${SCOPE_VALUE}\"}" >/dev/null
  say "granted" "$SCOPE_VALUE"
else
  gpatch "v1.0/oauth2PermissionGrants/${EXIST}" "{\"scope\":\"${SCOPE_VALUE}\"}" >/dev/null
  say "grant kept" "$SCOPE_VALUE"
fi

echo; echo "Persisting"
python3 - "$BROKER_CLIENT_ID" "$BROKER_OBJECT_ID" "$SP" "$SCOPE_VALUE" <<'PY'
import re, sys
cid, oid, sp, scope = sys.argv[1:]
p = ".lab/labsOBO.env"; s = open(p).read()
for k, v in {"LABSOBO_JIRA_BROKER_NAME": "labsOBO-jira-broker", "LABSOBO_JIRA_BROKER_CLIENT_ID": cid, "LABSOBO_JIRA_BROKER_OBJECT_ID": oid,
             "LABSOBO_JIRA_BROKER_PRINCIPAL_ID": sp, "LABSOBO_JIRA_SCOPE_VALUE": scope}.items():
    line = f'{k}="{v}"'
    s = re.sub(rf"^{k}=.*$", line, s, flags=re.M) if re.search(rf"^{k}=", s, flags=re.M) else s.rstrip("\n") + "\n" + line + "\n"
open(p, "w").write(s)
PY
state_set jiraBroker "{\"displayName\":\"${BROKER_NAME}\",\"clientId\":\"${BROKER_CLIENT_ID}\",\"objectId\":\"${BROKER_OBJECT_ID}\",\"principalId\":\"${SP}\",
  \"scope\":\"api://${BROKER_CLIENT_ID}/${SCOPE_VALUE}\",\"consent\":\"${SCOPE_VALUE} granted to the agent identity A1 (AllPrincipals)\"}"
say "wrote" ".lab/labsOBO.env + lab-state.json"
