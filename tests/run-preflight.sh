#!/usr/bin/env bash
# labsOBO | autonomous pre-flight through the calling app's API (no browser, no password).
#
# Two sessions:
#   JAR_CLI  the operator's Azure CLI token for BP-A1 (Balaji = ALEX, azp = Azure CLI)  -> wrong-client tests
#   JAR_APP  the LABSOBO_T_APP_A1 a real browser sign-in obtained via the calling app     -> positive path
# Records everything into .lab/traces so the UI shows it afterwards.
set -uo pipefail
cd "$(dirname "$0")/.."
source .lab/labsOBO.env
APP=http://localhost:3100
JAR_CLI=.lab/preflight-cli.cookies; JAR_APP=.lab/preflight-app.cookies; rm -f "$JAR_CLI" "$JAR_APP"
post() { local JAR="$1" PATHX="$2" BODY="${3:-}"; [ -n "$BODY" ] || BODY='{}'; curl -s -b "$JAR" -c "$JAR" -H "Content-Type: application/json" -X POST "$APP$PATHX" -d "$BODY"; }
rid() { python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('runId') or ('ERROR: '+json.dumps(d)))"; }
show() { case "$1" in ERROR*) echo "  $1";; *) python3 tests/show-runs.py "$1";; esac; }
step() { echo; echo "================================================================"; echo "STEP $1"; }
status_of() { curl -s "$APP/api/runs/$1" | python3 -c "import sys,json;print(json.load(sys.stdin)['status'])"; }

step "A  operator's Azure CLI token for BP-A1 (Alex, azp = Azure CLI)"
show "$(post $JAR_CLI /api/azcli/import '{"scopeForm":"named"}' | rid)"

step "B  T05 wrong client: that token to local A1 (policy = APP only) and to AgentCore (authorizer azp = APP)"
post $JAR_CLI /api/a1/policy "{\"allowedAzp\":[\"$LABSOBO_CALLING_APP_CLIENT_ID\"]}" >/dev/null
show "$(post $JAR_CLI /api/session/invoke '{"target":"local","mode":"echo"}' | rid)"
show "$(post $JAR_CLI /api/session/invoke '{"target":"agentcore","mode":"echo"}' | rid)"

step "C  adopt the real APP-issued LABSOBO_T_APP_A1 (from the browser sign-in) as the session"
ADOPT=$(post $JAR_APP /api/session/adopt '{"user":"alex","client":"app"}'); echo "  $ADOPT"
if echo "$ADOPT" | grep -q '"ok":true'; then
  step "D  T12 Phase 12: Alex's APP token -> local A1 (200) and -> Bedrock AgentCore JWT authorizer (200)"
  show "$(post $JAR_APP /api/session/invoke '{"target":"local","mode":"echo"}' | rid)"
  show "$(post $JAR_APP /api/session/invoke '{"target":"agentcore","mode":"echo"}' | rid)"
  step "E  T08 Phase 16: local A1 does T1 -> OBO -> Graph /me for Alex"
  show "$(post $JAR_APP /api/session/invoke '{"target":"local","mode":"obo"}' | rid)"
  step "F  T06 wrong audience: a Microsoft Graph token to local A1 and to AgentCore"
  show "$(post $JAR_APP /api/session/invoke '{"target":"local","mode":"echo","tokenKind":"graph"}' | rid)"
  show "$(post $JAR_APP /api/session/invoke '{"target":"agentcore","mode":"echo","tokenKind":"graph"}' | rid)"
else
  echo "  no APP token to adopt - sign in as ALEX via APP in the browser first; skipping D-F"
fi

step "G  Phase 13 on Alex: REMOVE the role, wait for replication, ask for a brand-new token (fresh scope spelling) -> expect AADSTS50105"
show "$(post $JAR_CLI /api/directory/assign '{"user":"alex","assign":false}' | rid)"
sleep 30
R=$(post $JAR_CLI /api/session/token '{"scopeForm":"guid-named"}' | rid); show "$R"
if [ "$(status_of "$R")" != "denied" ]; then echo "  unexpected: still issued after removal; waiting 60s and retrying with the last unused spelling"; sleep 60; R=$(post $JAR_CLI /api/session/token '{"scopeForm":"guid-default"}' | rid); show "$R"; fi

step "H  Phase 14 on Alex: RE-ASSIGN, wait, brand-new token -> expect issued with roles"
show "$(post $JAR_CLI /api/directory/assign '{"user":"alex","assign":true}' | rid)"
sleep 30
R=$(post $JAR_CLI /api/session/token '{"scopeForm":"guid-default"}' | rid); show "$R"
if [ "$(status_of "$R")" != "done" ]; then echo "  still denied; waiting 60s and retrying"; sleep 60; show "$(post $JAR_CLI /api/session/token '{"scopeForm":"guid-named"}' | rid)"; fi

step "I  final state"
post $JAR_CLI /api/a1/policy "{\"allowedAzp\":[\"$LABSOBO_CALLING_APP_CLIENT_ID\"]}" >/dev/null
show "$(post $JAR_CLI /api/directory/refresh | rid)"
python3 tests/show-runs.py __none__ 2>/dev/null | tail -0; python3 - <<'PY'
import json, urllib.request
s = json.load(urllib.request.urlopen("http://localhost:3100/api/state"))
print("\n== test matrix ==")
for t in s["tests"]:
    e = t["evidence"]; print("  %s  %-34s %-18s %s" % (t["id"], t["title"], e["result"] if e else "not yet", e["detail"][:110] if e else ""))
d = s["directory"]; print("\n== directory now ==", {k: d[k] for k in ("assignmentRequired", "alex", "sam")})
PY
