#!/usr/bin/env bash
# labsOBO | change which client (azp) the AgentCore authorizer admits, without recreating the runtime.
#   ./45-set-authorizer-azp.sh <clientId>
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/lib.sh
source .lab/labsOBO.env
export AWS_PAGER=""
REGION=${AWS_REGION:-us-east-1}
AZP=${1:?usage: $0 <clientId>}
ID=$(cat .lab/a1_runtime_id.txt)
python3 - "$AZP" "$ID" <<'PY'
import json, sys
azp, rid = sys.argv[1:]
d = json.load(open('infra/aws/agent1-runtime/create.json'))
d['authorizerConfiguration']['customJWTAuthorizer']['customClaims'][0]['authorizingClaimMatchValue']['claimMatchValue']['matchValueString'] = azp
json.dump(d, open('infra/aws/agent1-runtime/create.json', 'w'), indent=2)
u = {k: v for k, v in d.items() if k not in ('agentRuntimeName', 'tags')}
u['agentRuntimeId'] = rid
json.dump(u, open('.lab/a1-update.json', 'w'), indent=2)
PY
aws bedrock-agentcore-control update-agent-runtime --region "$REGION" --cli-input-json file://.lab/a1-update.json --query '{version:agentRuntimeVersion,status:status}' --output json
until [ "$(aws bedrock-agentcore-control get-agent-runtime --region "$REGION" --agent-runtime-id "$ID" --output text --query status)" = "READY" ]; do sleep 5; done
state_set aws.runtime.authorizer.azp "\"$AZP\""
echo "  READY  authorizer azp = $AZP"
