#!/usr/bin/env bash
# labsOBO | store the Atlassian OAuth 2.0 (3LO) app credentials for the Jira broker.
#
# The broker (and the calling app's consent callback) read them from AWS Secrets Manager as
#   labsobo/jira/oauth-client = {"clientId": "...", "clientSecret": "..."}
# Run this yourself: it prompts for the secret without echoing it, so it never appears in a
# terminal, a log, or a chat transcript.
set -euo pipefail
export AWS_PAGER=""
REGION=${AWS_REGION:-us-east-1}
NAME=labsobo/jira/oauth-client

read -r -p "Atlassian client ID: " ATL_ID
read -r -s -p "Atlassian secret (hidden): " ATL_SECRET; echo
[ -n "$ATL_ID" ] && [ -n "$ATL_SECRET" ] || { echo "both values are required"; exit 1; }

BODY=$(ATL_ID="$ATL_ID" ATL_SECRET="$ATL_SECRET" python3 -c 'import json,os; print(json.dumps({"clientId": os.environ["ATL_ID"], "clientSecret": os.environ["ATL_SECRET"]}))')
unset ATL_SECRET

if aws secretsmanager describe-secret --region "$REGION" --secret-id "$NAME" >/dev/null 2>&1; then
  aws secretsmanager put-secret-value --region "$REGION" --secret-id "$NAME" --secret-string "$BODY" --query ARN --output text
  echo "updated $NAME"
else
  aws secretsmanager create-secret --region "$REGION" --name "$NAME" --description "labsOBO Jira broker: Atlassian OAuth 2.0 (3LO) client" \
    --tags Key=lab,Value=labsOBO --secret-string "$BODY" --query ARN --output text
  echo "created $NAME"
fi
unset BODY
