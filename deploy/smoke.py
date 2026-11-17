"""Check an installed GuardianAI from inside the cluster: tenants, approvals across replicas, probes.

Run it in a pod that can reach the Service, with the keys the chart was installed with:

    kubectl -n <ns> exec -i <pod with python> -- env GUARDIAN_URL=http://<release>-guardian-ai:8000 \
        PAYMENTS_AGENT_KEY=... SEARCH_AGENT_KEY=... PAYMENTS_APPROVER_KEY=... SEARCH_APPROVER_KEY=... \
        python - < deploy/smoke.py

It expects two tenants, "payments" and "search", where payments has the rules

    - {id: payments-refund, match: {tool: "payments.refund"}, effect: require_approval}
    - {id: payments-lookup, match: {tool: "payments.lookup"}, effect: allow}

and the base policy is the shipped default. Standard library only. Exits 1 if any check fails.
"""
import os
import sys
import json
import urllib.error
import urllib.request

U = os.environ.get("GUARDIAN_URL", "http://guardian-guardian-ai:8000")
def call(method, path, key=None, body=None):
    req=urllib.request.Request(U+path, method=method, data=json.dumps(body).encode() if body is not None else None, headers={"Content-Type":"application/json", **({"Authorization":"Bearer "+key} if key else {})})
    try:
        r=urllib.request.urlopen(req, timeout=20); return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")
PAY, SEA = os.environ["PAYMENTS_AGENT_KEY"], os.environ["SEARCH_AGENT_KEY"]
ALICE, SAM = os.environ["PAYMENTS_APPROVER_KEY"], os.environ["SEARCH_APPROVER_KEY"]
chk=lambda key,tool,args=None: call("POST","/api/check",key,{"tool":{"name":tool},"arguments":args or {}})
out=[]
def ok(name, cond): out.append((name, bool(cond))); print(("PASS " if cond else "FAIL ")+name)
s,b=call("GET","/readyz"); ok("readyz reports policy, approvals and audit ready", s==200 and b["checks"]=={"policy":True,"approvals":True,"audit":True} and b["shared_state"])
s,b=chk(PAY,"payments.lookup"); ok("payments tenant: its own rule allows", s==200 and b["rule_id"]=="payments-lookup")
s,b=chk(SEA,"payments.lookup"); ok("search tenant: payments rule does not apply, denied by default", s==403 and b["rule_id"]=="default")
s,b=chk(SEA,"web.search"); ok("a base allow applies to every tenant (base rules decide first)", s==200 and b["rule_id"]=="allow-read-only")
s,b=call("GET","/api/policy",PAY); ok("policy endpoint shows payments its tenant", b.get("tenant")=="payments" and "payments-refund" in [r["id"] for r in b["rules"]])
s,b=chk(None,"payments.lookup"); ok("no key is refused", s==401)
s,b=chk(PAY,"payments.refund",{"amount":40,"to":"acct-1"}); ok("refund needs approval", s==202); aid=b["approval_id"]
seen=set()
for _ in range(12):
    s,b=chk(PAY,"payments.refund",{"amount":40,"to":"acct-1"}); seen.add((s,b.get("approval_id")))
ok("12 retries across replicas join the one approval", seen=={(202,aid)})
s,b=call("POST",f"/api/approvals/{aid}",SAM,{"approve":True}); ok("another tenant's approver cannot answer", s==404)
s,b=call("POST",f"/api/approvals/{aid}",PAY,{"approve":True}); ok("the agent's own key cannot approve", s in (401,403,404))
s,b=call("POST",f"/api/approvals/{aid}",ALICE,{"approve":True}); ok("the tenant's approver approves", s==200 and b["resolved_by"]=="payments.alice")
res=[chk(PAY,"payments.refund",{"amount":40,"to":"acct-1"})[0] for _ in range(6)]
ok("the single-use grant lets exactly one call through", res.count(200)==1 and res.count(202)==5)
s,b=chk(PAY,"payments.refund",{"amount":4000,"to":"acct-1"}); ok("a changed amount needs its own approval", s==202 and b["approval_id"]!=aid)
print("ALL PASS" if all(c for _,c in out) else "SOME FAILED", f"{sum(c for _,c in out)}/{len(out)}")
sys.exit(0 if all(c for _, c in out) else 1)
