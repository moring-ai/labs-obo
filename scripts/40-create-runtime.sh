#!/usr/bin/env bash
# labsOBO | Phase 12 - create the AgentCore runtime for A1 with a JWT authorizer
# that enforces aud (BP-A1) + azp (a specific client) + roles CONTAINS AgentInvoker.
#
#   ./40-create-runtime.sh            azp = the calling app (final lab state)
#   ./40-create-runtime.sh <clientId> azp = another client (used for the pre-flight)
#
# The container image is the labtesta2a echo agent (labtesta2a-agent1:v9): in
# AGENT_MODE=echo it only reports the inbound identity, which is exactly what
# Phase 12 needs. Authorization happens in AgentCore, before the container runs.
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/lib.sh
source .lab/labsOBO.env
export AWS_PAGER=""
REGION=${AWS_REGION:-us-east-1}
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
AZP=${1:-$LABSOBO_CALLING_APP_CLIENT_ID}

python3 - "$ACCOUNT" "$REGION" "$AZP" <<'PY'
import json, os, sys
acct, region, azp = sys.argv[1:]
env = dict(l.split('=',1) for l in open('.lab/labsOBO.env').read().splitlines() if '=' in l and not l.startswith('#'))
env = {k: v.strip('"') for k, v in env.items()}
cfg = {
  "agentRuntimeName": "labsOBO_agent1_runtime",
  "description": "labsOBO | A1 - proves runtime authorization by claims (aud + azp + roles). Echo image reused from labtesta2a.",
  "agentRuntimeArtifact": {"containerConfiguration": {"containerUri": f"{acct}.dkr.ecr.{region}.amazonaws.com/labtesta2a-agent1:v9"}},
  "roleArn": f"arn:aws:iam::{acct}:role/labsOBO-Agent1ExecutionRole",
  "networkConfiguration": {"networkMode": "PUBLIC"},
  "protocolConfiguration": {"serverProtocol": "HTTP"},
  "authorizerConfiguration": {"customJWTAuthorizer": {
    "discoveryUrl": f"https://login.microsoftonline.com/{env['LABSOBO_TENANT_ID']}/v2.0/.well-known/openid-configuration",
    "allowedAudience": [env["LABSOBO_BP_A1_CLIENT_ID"]],
    "customClaims": [
      {"inboundTokenClaimName": "azp", "inboundTokenClaimValueType": "STRING",
       "authorizingClaimMatchValue": {"claimMatchValue": {"matchValueString": azp}, "claimMatchOperator": "EQUALS"}},
      {"inboundTokenClaimName": "roles", "inboundTokenClaimValueType": "STRING_ARRAY",
       "authorizingClaimMatchValue": {"claimMatchValue": {"matchValueString": env["LABSOBO_AGENT_INVOKER_ROLE_VALUE"]}, "claimMatchOperator": "CONTAINS"}}
    ]}},
  "requestHeaderConfiguration": {"requestHeaderAllowlist": ["Authorization"]},
  "environmentVariables": {
    "AGENT_MODE": "echo", "AGENT_LABEL": "A1", "AGENT_DISPLAY_NAME": env["LABSOBO_AGENT_A1_NAME"],
    "AGENT_IDENTITY_ID": env["LABSOBO_AGENT_A1_CLIENT_ID"], "BLUEPRINT_APP_ID": env["LABSOBO_BP_A1_CLIENT_ID"],
    "TENANT_ID": env["LABSOBO_TENANT_ID"], "REQUIRED_ROLE": env["LABSOBO_AGENT_INVOKER_ROLE_VALUE"], "CREDENTIAL_MODE": "none"},
  "tags": {"Name": "labsOBO_agent1_runtime", "lab": "labsOBO"}
}
json.dump(cfg, open('infra/aws/agent1-runtime/create.json', 'w'), indent=2)
print("  wrote infra/aws/agent1-runtime/create.json  azp =", azp)
PY

EXISTING=$(aws bedrock-agentcore-control list-agent-runtimes --region "$REGION" --query "agentRuntimes[?agentRuntimeName=='labsOBO_agent1_runtime'].agentRuntimeId" --output text)
if [ -n "$EXISTING" ] && [ "$EXISTING" != "None" ]; then
  echo "  runtime exists: $EXISTING (use 45-set-authorizer-azp.sh to change azp)"; exit 0
fi
OUT=$(aws bedrock-agentcore-control create-agent-runtime --region "$REGION" --cli-input-json file://infra/aws/agent1-runtime/create.json --output json)
ARN=$(echo "$OUT" | python3 -c "import sys,json;print(json.load(sys.stdin)['agentRuntimeArn'])")
ID=$(echo "$OUT"  | python3 -c "import sys,json;print(json.load(sys.stdin)['agentRuntimeId'])")
echo "$ARN" > .lab/a1_runtime_arn.txt; echo "$ID" > .lab/a1_runtime_id.txt
echo "  created $ARN"
until [ "$(aws bedrock-agentcore-control get-agent-runtime --region "$REGION" --agent-runtime-id "$ID" --output text --query status)" = "READY" ]; do sleep 5; done
echo "  READY"
state_set aws "{\"accountId\":\"$ACCOUNT\",\"region\":\"$REGION\",\"executionRole\":\"labsOBO-Agent1ExecutionRole\",\"runtime\":{\"name\":\"labsOBO_agent1_runtime\",\"arn\":\"$ARN\",\"id\":\"$ID\",\"image\":\"labtesta2a-agent1:v9 (echo mode)\",\"authorizer\":{\"aud\":\"BP-A1\",\"azp\":\"$AZP\",\"roles\":\"CONTAINS ${LABSOBO_AGENT_INVOKER_ROLE_VALUE}\"}}}"
