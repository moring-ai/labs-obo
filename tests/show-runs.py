#!/usr/bin/env python3
"""Print recorded runs (hops + evidence) from the calling app. Usage: show-runs.py [runId ...] (default: all)."""
import json, sys, urllib.request
APP = "http://localhost:3100"
get = lambda p: json.load(urllib.request.urlopen(APP + p))
ids = sys.argv[1:] or [r["id"] for r in sorted(get("/api/state")["runs"], key=lambda r: r["seq"])]
for rid in ids:
    r = get("/api/runs/" + rid)
    print("\n### run %s  %s  [%s]" % (r["id"], r["title"], r["status"]))
    for h in r["hops"]:
        st = (h.get("response") or {}).get("status")
        print("  %2d. %8s -> %-9s %-6s HTTP %-4s %s" % (h["n"], h["from"], h["to"], h["verdict"], st, h["title"][:100]))
        if h.get("summary"): print("       " + h["summary"][:230])
    for e in r["evidence"]: print("  EVIDENCE %s: %s  %s" % (e["test"], e["result"], e["detail"][:170]))
if not sys.argv[1:]:
    print("\n== test matrix ==")
    for t in get("/api/state")["tests"]:
        e = t["evidence"]
        print("  %s  %-34s %-18s %s" % (t["id"], t["title"], e["result"] if e else "not yet", e["detail"][:110] if e else ""))
    d = get("/api/state")["directory"]; print("\n== directory now ==", {k: d[k] for k in ("assignmentRequired", "alex", "sam", "checkedAt")})
