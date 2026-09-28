#!/usr/bin/env bash
# labsOBO | register A1's tools in the runtime registry (SSM Parameter Store).
#
# A1 reads this at runtime (lib/tools.mjs); its code names no resource, endpoint or permission.
# Each entry says WHERE a tool is (the Entra resource and the URL), never WHAT A1 may do there:
# A1 asks Entra for <resource>/.default and gets the scopes an admin consented for it on that resource.
#   defender.advanced_hunting  step 10: KQL against Microsoft Defender
#   jira.create_issue          step 14: the Jira broker on AgentCore
#   graph.me                   lab Phase 16 (lab console only)
# Re-run after changing a tool; A1 picks the new version up within a minute, no redeploy.
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/lib.sh
source .lab/labsOBO.env
export AWS_PAGER=""
REGION=${AWS_REGION:-us-east-1}
NAME=/labsobo/a1/tools
BROKER_ARN=$(cat .lab/broker_runtime_arn.txt)

VALUE=$(python3 - "$REGION" "$BROKER_ARN" "$LABSOBO_JIRA_BROKER_CLIENT_ID" <<'PY'
import json, sys, urllib.parse
region, broker_arn, broker_app = sys.argv[1:]
print(json.dumps({
  "defender.advanced_hunting": {"resource": "https://api.security.microsoft.com",
                                "endpoint": "https://api.security.microsoft.com/api/advancedhunting/run"},
  "jira.create_issue": {"resource": f"api://{broker_app}",
                        "endpoint": f"https://bedrock-agentcore.{region}.amazonaws.com/runtimes/{urllib.parse.quote(broker_arn, safe='')}/invocations?qualifier=DEFAULT"},
  "graph.me": {"resource": "https://graph.microsoft.com",
               "endpoint": "https://graph.microsoft.com/v1.0/me?$select=id,displayName,userPrincipalName"},
}, indent=1))
PY
)
VERSION=$(aws ssm put-parameter --region "$REGION" --name "$NAME" --type String --overwrite --value "$VALUE" \
  --description "labsOBO A1 tool registry: resource + endpoint per tool (scopes come from Entra consent)" --query Version --output text)
say "registry" "$NAME v$VERSION"

python3 - "ssm:$NAME" <<'PY'
import re, sys
p = ".lab/labsOBO.env"; s = open(p).read(); line = f'LABSOBO_TOOL_REGISTRY="{sys.argv[1]}"'
s = re.sub(r"^LABSOBO_TOOL_REGISTRY=.*$", line, s, flags=re.M) if re.search(r"^LABSOBO_TOOL_REGISTRY=", s, flags=re.M) else s.rstrip("\n") + "\n" + line + "\n"
open(p, "w").write(s)
PY
say "wrote" ".lab/labsOBO.env LABSOBO_TOOL_REGISTRY=ssm:$NAME"
state_set aws.toolRegistry "{\"parameter\":\"${NAME}\",\"version\":${VERSION}}"
