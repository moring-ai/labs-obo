#!/usr/bin/env bash
# labsOBO | build the image and deploy both runtimes to Bedrock AgentCore.
#
#   labsOBO_jira_broker     (created or updated)  steps 15-16
#       JWT authorizer: aud = JIRA-BROKER, azp = AGENT-A1, allowedScopes = labsOBO_jira.create
#   labsOBO_agent1_runtime  (updated)             steps 5-11, 14
#       JWT authorizer: aud = BP-A1, azp = APP, roles ∋ labsOBO.AgentInvoker, allowedScopes = labsOBO_access_agent
#       env: A1_T1_CREDENTIAL=aws-sts (step 7 via the STS workload JWT); tools come from the SSM registry (57-tool-registry.sh)
# Both forward the Authorization header to the container (step 6: JWT passthrough).
# Needs: scripts/55-agentcore-federation.sh first; docker with buildx; aws sso login.
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/lib.sh
source .lab/labsOBO.env
export AWS_PAGER=""
REGION=${AWS_REGION:-us-east-1}
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
REPO=labsobo-agents
REGISTRY=${ACCOUNT}.dkr.ecr.${REGION}.amazonaws.com
IMAGE=${REGISTRY}/${REPO}:${TAG:-$(date -u +%Y%m%d-%H%M%S)}
mkdir -p infra/aws/jira-broker-runtime

echo "Image"
aws ecr describe-repositories --region "$REGION" --repository-names "$REPO" >/dev/null 2>&1 || {
  aws ecr create-repository --region "$REGION" --repository-name "$REPO" --image-scanning-configuration scanOnPush=true --tags Key=lab,Value=labsOBO >/dev/null
  say "created repo" "$REPO"; }
aws ecr get-login-password --region "$REGION" | docker login --username AWS --password-stdin "$REGISTRY" >/dev/null
docker buildx build --platform linux/arm64 -t "$IMAGE" --push .
say "pushed" "$IMAGE"

wait_ready() {  # <runtimeId>
  local s
  for _ in $(seq 1 90); do
    s=$(aws bedrock-agentcore-control get-agent-runtime --region "$REGION" --agent-runtime-id "$1" --query status --output text)
    case "$s" in READY) say "status" "READY"; return 0;; *FAILED*) aws bedrock-agentcore-control get-agent-runtime --region "$REGION" --agent-runtime-id "$1" --query failureReason --output text; return 1;; esac
    sleep 5
  done
  echo "timed out waiting for $1"; return 1
}

# one generator for both runtime definitions
gen() {  # <broker|a1> <out.json> [brokerArn]
  python3 - "$1" "$2" "$ACCOUNT" "$REGION" "$IMAGE" "${3:-}" <<'PY'
import json, sys, urllib.parse
kind, out, acct, region, image, broker_arn = sys.argv[1:]
env = {k: v.strip('"') for k, v in (l.split("=", 1) for l in open(".lab/labsOBO.env").read().splitlines() if "=" in l and not l.startswith("#"))}
disc = f"https://login.microsoftonline.com/{env['LABSOBO_TENANT_ID']}/v2.0/.well-known/openid-configuration"
claim = lambda name, typ, op, val: {"inboundTokenClaimName": name, "inboundTokenClaimValueType": typ,
                                    "authorizingClaimMatchValue": {"claimMatchValue": {"matchValueString": val}, "claimMatchOperator": op}}
common = {"agentRuntimeArtifact": {"containerConfiguration": {"containerUri": image}}, "networkConfiguration": {"networkMode": "PUBLIC"},
          "protocolConfiguration": {"serverProtocol": "HTTP"}, "requestHeaderConfiguration": {"requestHeaderAllowlist": ["Authorization"]}}
if kind == "broker":
    cfg = {"agentRuntimeName": "labsOBO_jira_broker", **common,
           "description": "labsOBO | Jira broker (steps 15-16): accepts only T_A1_BROKER; holds the Atlassian vault.",
           "roleArn": f"arn:aws:iam::{acct}:role/labsOBO-JiraBrokerExecutionRole",
           "authorizerConfiguration": {"customJWTAuthorizer": {"discoveryUrl": disc, "allowedAudience": [env["LABSOBO_JIRA_BROKER_CLIENT_ID"]],
               "allowedScopes": [env.get("LABSOBO_JIRA_SCOPE_VALUE", "labsOBO_jira.create")],
               "customClaims": [claim("azp", "STRING", "EQUALS", env["LABSOBO_AGENT_A1_CLIENT_ID"])]}},
           "environmentVariables": {"LABSOBO_ROLE": "broker", "AWS_REGION": region, "JIRA_SITE": "moring-ai", "JIRA_PROJECT": "SEC"}}
else:
    cfg = {"agentRuntimeId": open(".lab/a1_runtime_id.txt").read().strip(), **common,
           "description": "labsOBO | Agent A1: T1 from the AWS STS workload JWT; OBO to Defender and to the Jira broker.",
           "roleArn": f"arn:aws:iam::{acct}:role/labsOBO-Agent1ExecutionRole",
           "authorizerConfiguration": {"customJWTAuthorizer": {"discoveryUrl": disc, "allowedAudience": [env["LABSOBO_BP_A1_CLIENT_ID"]],
               "customClaims": [claim("azp", "STRING", "EQUALS", env["LABSOBO_CALLING_APP_CLIENT_ID"]),
                                claim("roles", "STRING_ARRAY", "CONTAINS", env["LABSOBO_AGENT_INVOKER_ROLE_VALUE"])],
               "allowedScopes": [env["LABSOBO_ACCESS_SCOPE_VALUE"]]}},
           "environmentVariables": {"LABSOBO_ROLE": "a1", "A1_T1_CREDENTIAL": "aws-sts", "AWS_REGION": region}}
json.dump(cfg, open(out, "w"), indent=2)
PY
}

echo; echo "Jira broker runtime"
BROKER_ID=$(aws bedrock-agentcore-control list-agent-runtimes --region "$REGION" --query "agentRuntimes[?agentRuntimeName=='labsOBO_jira_broker'].agentRuntimeId" --output text)
if [ -z "$BROKER_ID" ] || [ "$BROKER_ID" = "None" ]; then
  gen broker infra/aws/jira-broker-runtime/create.json
  OUT=$(aws bedrock-agentcore-control create-agent-runtime --region "$REGION" --cli-input-json file://infra/aws/jira-broker-runtime/create.json --output json)
  BROKER_ID=$(echo "$OUT" | jq_ 'print(d["agentRuntimeId"])')
  say "created" "$BROKER_ID"
else
  gen broker infra/aws/jira-broker-runtime/create.json
  python3 - "$BROKER_ID" <<'PY'
import json, sys
c = json.load(open("infra/aws/jira-broker-runtime/create.json")); c.pop("agentRuntimeName"); c["agentRuntimeId"] = sys.argv[1]
json.dump(c, open("infra/aws/jira-broker-runtime/update.json", "w"), indent=2)
PY
  aws bedrock-agentcore-control update-agent-runtime --region "$REGION" --cli-input-json file://infra/aws/jira-broker-runtime/update.json >/dev/null
  say "updated" "$BROKER_ID"
fi
wait_ready "$BROKER_ID"
BROKER_ARN=$(aws bedrock-agentcore-control get-agent-runtime --region "$REGION" --agent-runtime-id "$BROKER_ID" --query agentRuntimeArn --output text)
echo "$BROKER_ARN" > .lab/broker_runtime_arn.txt
say "arn" "$BROKER_ARN"

echo; echo "Agent A1 runtime"
gen a1 infra/aws/agent1-runtime/update.json "$BROKER_ARN"
A1_ID=$(cat .lab/a1_runtime_id.txt)
aws bedrock-agentcore-control update-agent-runtime --region "$REGION" --cli-input-json file://infra/aws/agent1-runtime/update.json >/dev/null
say "updated" "$A1_ID"
wait_ready "$A1_ID"

state_set aws.runtimes "{\"image\":\"${IMAGE}\",\"a1\":\"${A1_ID}\",\"broker\":\"${BROKER_ID}\",\"brokerArn\":\"${BROKER_ARN}\"}"
