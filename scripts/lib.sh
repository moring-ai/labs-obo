#!/usr/bin/env bash
# Shared names + helpers for the labsOBO lab. Source this; do not run it.
# Every object created by this lab carries the labsOBO prefix so it can be
# found, audited and torn down without touching anything else in the tenant.

LABSOBO_PREFIX="labsOBO"
LABSOBO_CALLING_APP_NAME="labsOBO-calling-app"
LABSOBO_DIRECT_CLIENT_NAME="labsOBO-direct-client"
LABSOBO_BP_A1_NAME="labsOBO-agent1-blueprint"
LABSOBO_AGENT_A1_NAME="labsOBO-agent1"
LABSOBO_AGENT_INVOKER_ROLE_VALUE="labsOBO.AgentInvoker"
LABSOBO_AGENT_INVOKER_ROLE_DISPLAY="labsOBO Agent Invoker"
LABSOBO_AGENT_INVOKER_ROLE_DESC="Allows explicitly assigned users to invoke labsOBO Agent A1"
LABSOBO_ACCESS_SCOPE_VALUE="labsOBO_access_agent"
LABSOBO_REDIRECT_URI="http://localhost:3100/auth/callback"
LABSOBO_DIRECT_REDIRECT_URI="http://localhost:3100/auth/callback/direct"
LABSOBO_AGENTCORE_RUNTIME_NAME="labsOBO-agent1-runtime"
# AgentCore's name pattern is [a-zA-Z][a-zA-Z0-9_]{0,47}; hyphens are rejected.
LABSOBO_AGENTCORE_RUNTIME_ID_NAME="labsOBO_agent1_runtime"
# Existing tenant users play the two roles (user decision, 2026-09-09): no test accounts are created.
LABSOBO_ALEX_UPN="BalajiNagarajKumar@MoringAI.onmicrosoft.com"   # Alex  - entitled
LABSOBO_SAM_UPN="rajarajan@MoringAI.onmicrosoft.com"             # Sam   - not entitled
AZURE_CLI_APP_ID="04b07795-8ddb-461a-bbee-02f9e1bf7b46"
GRAPH_APP_ID="00000003-0000-0000-c000-000000000000"

STATE=.lab/lab-state.json
[ -f "$STATE" ] || echo '{"labPrefix":"labsOBO"}' > "$STATE"

# state_set <dotted.path> <json-value>
state_set() {
  python3 - "$STATE" "$1" "$2" <<'PY'
import json, sys
p, path, raw = sys.argv[1:]
d = json.load(open(p))
try: val = json.loads(raw)
except Exception: val = raw
cur = d
keys = path.split('.')
for k in keys[:-1]: cur = cur.setdefault(k, {})
cur[keys[-1]] = val
json.dump(d, open(p, 'w'), indent=2)
PY
}
# state_get <dotted.path>
state_get() {
  python3 - "$STATE" "$1" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
try:
    for k in sys.argv[2].split('.'): d = d[k]
    print(d if isinstance(d, str) else json.dumps(d))
except Exception: print("")
PY
}

G="https://graph.microsoft.com"
gget()   { az rest --method GET   --url "$G/$1" -o json; }
gpost()  { az rest --method POST  --url "$G/$1" --headers "Content-Type=application/json" --body "$2" -o json; }
gpatch() { az rest --method PATCH --url "$G/$1" --headers "Content-Type=application/json" --body "$2" -o json; }
gdel()   { az rest --method DELETE --url "$G/$1"; }
jq_() { python3 -c "import sys,json; d=json.load(sys.stdin); $1"; }
say() { printf '  %-28s %s\n' "$1" "$2"; }
