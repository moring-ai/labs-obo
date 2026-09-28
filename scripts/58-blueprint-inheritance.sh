#!/usr/bin/env bash
# labsOBO | A1's Defender permission comes from the blueprint, by inheritance, not from a grant on A1.
#
#   1. BP-A1.requiredResourceAccess   Defender XDR API (Microsoft Threat Protection): AdvancedHunting.Read, type Scope.
#                                     A declaration of what the blueprint needs; it grants nothing by itself.
#   2. BP-A1.inheritablePermissions   Defender only: delegated scopes allAllowed, application roles none.
#                                     The API has no per-scope list (only allAllowed | none per resource), so the
#                                     scopes that flow to A1 are exactly those granted to the BP-A1 principal in 3.
#   3. admin consent                  client = BP-A1 principal, resource = Defender, scope = AdvancedHunting.Read, AllPrincipals.
#   --remove-direct                   4. delete A1's own Defender grant, so a working OBO can only be the inherited path.
#
# Nothing about A1 changes: same agent identity, federated credential, T1 and OBO request.
# Inherited permissions don't show on A1 in Graph; they only appear in its tokens (scp), merged at issuance.
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/lib.sh
source .lab/labsOBO.env
DEFENDER_APP=8ee8fdad-f234-4243-8f3b-15c294843740   # Microsoft Threat Protection = the Defender XDR API
SCOPE_VALUE=AdvancedHunting.Read
REMOVE_DIRECT=false; [ "${1:-}" = "--remove-direct" ] && REMOVE_DIRECT=true
BP=$LABSOBO_BP_A1_OBJECT_ID; BP_SP=$LABSOBO_BP_A1_PRINCIPAL_ID; A1_SP=$LABSOBO_AGENT_A1_OBJECT_ID
IP="$G/v1.0/applications/microsoft.graph.agentIdentityBlueprint/${BP}/inheritablePermissions"
ipget() { az rest --method GET --url "$IP" --headers "OData-Version=4.0" -o json; }

DEF_SP=$(gget "v1.0/servicePrincipals?\$filter=appId eq '${DEFENDER_APP}'&\$select=id" | jq_ 'print(d["value"][0]["id"])')
SCOPE_ID=$(gget "v1.0/servicePrincipals/${DEF_SP}?\$select=oauth2PermissionScopes" | jq_ 'print([s["id"] for s in d["oauth2PermissionScopes"] if s["value"]=="'"$SCOPE_VALUE"'"][0])')
say "Defender resource" "appId ${DEFENDER_APP}, principal ${DEF_SP}"
say "${SCOPE_VALUE}" "scope id ${SCOPE_ID}"

echo; echo "1. BP-A1.requiredResourceAccess"
PATCH=$(gget "beta/applications/${BP}?\$select=requiredResourceAccess" | python3 -c '
import json, sys
app, sid = sys.argv[1], sys.argv[2]
rra = json.load(sys.stdin).get("requiredResourceAccess") or []
e = next((x for x in rra if x["resourceAppId"] == app), None)
if e is None: rra.append({"resourceAppId": app, "resourceAccess": [{"id": sid, "type": "Scope"}]})
elif not any(a["id"] == sid for a in e["resourceAccess"]): e["resourceAccess"].append({"id": sid, "type": "Scope"})
else: sys.exit(0)
print(json.dumps({"requiredResourceAccess": rra}))' "$DEFENDER_APP" "$SCOPE_ID")
if [ -n "$PATCH" ]; then gpatch "beta/applications/${BP}" "$PATCH" >/dev/null; say "declared" "Defender ${SCOPE_VALUE} (Scope)"; else say "already declared" "Defender ${SCOPE_VALUE}"; fi

echo; echo "2. BP-A1.inheritablePermissions"
SETTINGS='"inheritableScopes":{"@odata.type":"#microsoft.graph.allAllowedScopes","kind":"allAllowed"},"inheritableRoles":{"@odata.type":"#microsoft.graph.noRoles","kind":"none"}'
if [ "$(ipget | jq_ 'print(any(x["resourceAppId"]=="'"$DEFENDER_APP"'" for x in d["value"]))')" = "True" ]; then
  az rest --method PATCH --url "$IP/${DEFENDER_APP}" --headers "Content-Type=application/json" "OData-Version=4.0" --body "{${SETTINGS}}" >/dev/null
  say "updated" "Defender: delegated scopes allAllowed, roles none"
else
  az rest --method POST --url "$IP" --headers "Content-Type=application/json" "OData-Version=4.0" --body "{\"resourceAppId\":\"${DEFENDER_APP}\",${SETTINGS}}" >/dev/null
  say "added" "Defender: delegated scopes allAllowed, roles none"
fi

echo; echo "3. Admin consent to the BP-A1 principal"
GRANT=$(gget "v1.0/oauth2PermissionGrants?\$filter=clientId eq '${BP_SP}' and resourceId eq '${DEF_SP}'" | jq_ 'v=d["value"]; print(v[0]["id"]+"|"+(v[0].get("scope") or "") if v else "")')
if [ -z "$GRANT" ]; then
  gpost "v1.0/oauth2PermissionGrants" "{\"clientId\":\"${BP_SP}\",\"consentType\":\"AllPrincipals\",\"resourceId\":\"${DEF_SP}\",\"scope\":\"${SCOPE_VALUE}\"}" >/dev/null
  say "granted" "BP-A1 principal → Defender ${SCOPE_VALUE} (AllPrincipals)"
else
  GID=${GRANT%%|*}; CUR=${GRANT#*|}
  case " $CUR " in
    *" $SCOPE_VALUE "*) say "grant exists" "$CUR";;
    *) gpatch "v1.0/oauth2PermissionGrants/${GID}" "{\"scope\":\"$(echo "$CUR $SCOPE_VALUE" | xargs)\"}" >/dev/null; say "grant extended" "$CUR $SCOPE_VALUE";;
  esac
fi

if $REMOVE_DIRECT; then
  echo; echo "4. Remove A1's direct Defender grant"
  DID=$(gget "v1.0/oauth2PermissionGrants?\$filter=clientId eq '${A1_SP}' and resourceId eq '${DEF_SP}'" | jq_ 'v=d["value"]; print(v[0]["id"] if v else "")')
  if [ -n "$DID" ]; then gdel "v1.0/oauth2PermissionGrants/${DID}"; say "deleted" "$DID"; else say "nothing to delete" "A1 has no direct Defender grant"; fi
fi

echo; echo "Where A1's Defender permission comes from"
A1G=$(gget "v1.0/oauth2PermissionGrants?\$filter=clientId eq '${A1_SP}' and resourceId eq '${DEF_SP}'" | jq_ 'v=d["value"]; print(v[0]["scope"] if v else "NONE")')
BPG=$(gget "v1.0/oauth2PermissionGrants?\$filter=clientId eq '${BP_SP}' and resourceId eq '${DEF_SP}'" | jq_ 'v=d["value"]; print(v[0]["scope"]+" ("+v[0]["consentType"]+")" if v else "NONE")')
INH=$(ipget | jq_ 'v=[x for x in d["value"] if x["resourceAppId"]=="'"$DEFENDER_APP"'"]; print("scopes "+v[0]["inheritableScopes"]["kind"]+", roles "+v[0]["inheritableRoles"]["kind"] if v else "NOT inheritable")')
say "A1 direct grant" "$A1G"
say "BP-A1 admin grant" "$BPG"
say "BP-A1 inheritance" "Defender: $INH"
say "BP-A1 declares" "Defender $SCOPE_VALUE in requiredResourceAccess"
state_set agentA1.defenderPermission "{\"source\":\"blueprint inheritance\",\"a1DirectGrant\":\"${A1G}\",\"blueprintGrant\":\"${BPG}\",\"inheritable\":\"Defender: ${INH}\",\"requiredResourceAccess\":\"Defender ${SCOPE_VALUE}\"}"
