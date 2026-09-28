#!/usr/bin/env bash
# labsOBO | step 7 on AgentCore: T1 without a secret, plus the Jira broker's runtime role.
#
#   A1 runtime role     may call sts:GetWebIdentityToken, only for Entra's token-exchange audience,
#                       RS256, at most 300 s (infra/aws/iam/agent1-base-policy.json).
#   BP-A1 (Entra)       a federated identity credential that trusts exactly that role's STS tokens:
#                       issuer  = this account's STS issuer (IAM outbound identity federation)
#                       subject = arn:aws:iam::<account>:role/labsOBO-Agent1ExecutionRole
#                       audience= api://AzureADTokenExchange
#   Jira broker role    reads the Atlassian app credentials and reads/writes the per-user vault
#                       secrets (infra/aws/iam/jira-broker-policy.json). A1 has no access to either.
# Idempotent.
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/lib.sh
source .lab/labsOBO.env
export AWS_PAGER=""
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
A1_ROLE=labsOBO-Agent1ExecutionRole
BROKER_ROLE=labsOBO-JiraBrokerExecutionRole

echo "AWS: A1 runtime role"
aws iam put-role-policy --role-name "$A1_ROLE" --policy-name labsOBO-Agent1BasePolicy --policy-document file://infra/aws/iam/agent1-base-policy.json
say "policy updated" "$A1_ROLE: + sts:GetWebIdentityToken (aud api://AzureADTokenExchange, RS256, <=300s)"

echo; echo "AWS: Jira broker runtime role"
if ! aws iam get-role --role-name "$BROKER_ROLE" >/dev/null 2>&1; then
  aws iam create-role --role-name "$BROKER_ROLE" --assume-role-policy-document file://infra/aws/iam/trust-policy.json \
    --description "labsOBO | Jira broker on AgentCore: Atlassian vault + app credentials" --tags Key=lab,Value=labsOBO >/dev/null
  say "created role" "$BROKER_ROLE"
else
  say "role exists" "$BROKER_ROLE"
fi
aws iam put-role-policy --role-name "$BROKER_ROLE" --policy-name labsOBO-JiraBrokerPolicy --policy-document file://infra/aws/iam/jira-broker-policy.json
say "policy updated" "$BROKER_ROLE"

echo; echo "Entra: federated credential on BP-A1"
ISSUER=$(aws iam get-outbound-web-identity-federation-info --query IssuerIdentifier --output text)
SUBJECT="arn:aws:iam::${ACCOUNT}:role/${A1_ROLE}"
FIC_NAME="labsOBO-agentcore-a1-runtime"
EXIST=$(gget "beta/applications(appId='${LABSOBO_BP_A1_CLIENT_ID}')/federatedIdentityCredentials" | jq_ 'v=[x for x in d["value"] if x["name"]=="'"$FIC_NAME"'"]; print(v[0]["id"] if v else "")')
if [ -z "$EXIST" ]; then
  gpost "beta/applications(appId='${LABSOBO_BP_A1_CLIENT_ID}')/federatedIdentityCredentials" "{\"name\":\"${FIC_NAME}\",
     \"issuer\":\"${ISSUER}\",\"subject\":\"${SUBJECT}\",\"audiences\":[\"api://AzureADTokenExchange\"],
     \"description\":\"labsOBO step 7: the AgentCore A1 runtime role proves BP-A1 with an AWS STS workload JWT\"}" >/dev/null
  say "created" "$FIC_NAME"
else
  say "exists" "$FIC_NAME"
fi
say "issuer" "$ISSUER"
say "subject" "$SUBJECT"

state_set aws.federation "{\"issuer\":\"${ISSUER}\",\"subject\":\"${SUBJECT}\",\"audience\":\"api://AzureADTokenExchange\",\"entraCredential\":\"${FIC_NAME} on BP-A1\",\"brokerRole\":\"${BROKER_ROLE}\"}"
