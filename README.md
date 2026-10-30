# GuardianAI

A policy decision point for AI agent tool calls, plus a live dashboard. Agents (or the apps that run them) ask `POST /api/check` "may this agent call this tool with these arguments?" and get an allow or deny decided by a YAML policy file and a set of built-in detectors mapped to the OWASP Top 10 for LLM Applications (2025) and the OWASP Top 10 for Agentic Applications (2026). Separately, GuardianAI can passively observe apps through a WebSocket tap and show what the same policy would have decided; the tap cannot stop anything.

## Screenshots

![GuardianAI Dashboard](screenshot.png)

## What it does

- **Decides** (`POST /api/check`): evaluates a structured tool call `{tool, arguments, agent}` against `policies/default.yaml` and returns allow (200), deny (403) or pending human approval (202). Your agent runtime must call it before running the tool and honor the answer; GuardianAI does not sit in the call path by itself.
- **Observes** (guardian-tap): connects to your app's `/ws-observe` endpoint, finds tool calls inside every event it sees (any event type, OpenAI and Anthropic tool-call shapes included) and runs the same policy over them. These decisions are shown as `OBSERVED`/`FLAGGED`; the traffic has already happened.

**Left panel**: live feed of agent activity. **Right panel**: decisions with the policy rule that decided, the detectors that fired, severity, OWASP categories and remediation.

## Detectors

Detectors are regex and URL checks run over every string in the arguments (keys included, at any depth, and over the joined text so a phrase split across two fields is still found). They are inputs to the policy, not the policy itself.

| Detector | OWASP LLM 2025 | OWASP Agentic 2026 | Detects |
|------|----------------|--------------------|---------|
| `prompt_injection` | LLM01 Prompt Injection | ASI01 Agent Goal Hijack | Instruction overrides, DAN patterns, guardrail bypass. Weaker phrases such as "you are now ..." count only inside untrusted content (fetched pages, documents) |
| `sensitive_data_leak` | LLM02 Sensitive Information Disclosure | ASI03 Identity and Privilege Abuse | API keys (OpenAI, Anthropic, AWS, GitHub, Slack, DO), JWTs, private keys |
| `data_exfiltration` | LLM02 Sensitive Information Disclosure | ASI02 Tool Misuse and Exploitation | Known exfil hosts (webhook.site, ngrok, ...), raw public IP URLs, curl/wget uploads, markdown/HTML image beacons |
| `ssrf` | LLM05 Improper Output Handling | ASI02 Tool Misuse and Exploitation | Loopback, private, link-local and metadata addresses in any spelling (`2130706433`, `0x7f000001`, `[::1]`, `user@127.0.0.1`, bare hosts under URL-like keys), and `file:`/`gopher:` style schemes |
| `dangerous_code` | LLM05 Improper Output Handling | ASI05 Unexpected Code Execution | rm -rf, reverse shells, download piped to a shell, reading `.env` or cloud credentials, sudo with destructive commands |
| `injection` | LLM05 Improper Output Handling | ASI02 Tool Misuse and Exploitation | SQL injection payloads, XSS, command injection |
| `excessive_agency` | LLM06 Excessive Agency | ASI02 Tool Misuse and Exploitation | Real deployments via terraform/kubectl/docker/aws/gcloud |
| `eval_manipulation` | none (anomaly signal) | none | Anomalous evaluation scores below 2/10 |
| `scan_limit_exceeded` | none | none | The arguments were too large to scan completely (over 10,000 nodes or 1,000,000 characters); treated as HIGH so it fails closed |

## Policy

The policy is a YAML file: `policies/default.yaml` by default, or the path in `GUARDIAN_POLICY_FILE`. The default file documents the whole format in its header comments. In short:

- Rules are checked in order; the first rule whose `match` holds decides. Nothing matching means `default_effect` (deny in the shipped policy, so unknown tools are refused).
- `match` can test the tool name (globs), the MCP server, the agent, argument predicates (`host_in`, `host_not_in_private_ranges`, `path_prefix`, `max_length`, `regex`, `equals`, `one_of`, `exists`, with `*` in paths), which detectors fired and at what severity, and `not`/`any` combinations.
- Effects are `allow`, `deny` and `require_approval` (see Approvals below).
- `untrusted_inputs` names argument paths that carry content the agent did not write; detectors apply their weaker signals only there.
- `mode: monitor` computes and shows every decision but lets every call through.
- The file is reloaded on change without a restart. An invalid edit is rejected, the last good policy stays in force, and `GET /api/policy` reports the error. An invalid policy at startup stops the server from starting.

The shipped policy denies anything a detector flags at or above `BLOCK_THRESHOLD`, reserves `shell.*` for the `ops` agent, sends deploys and non-allowlisted fetches to `require_approval`, allows read-only tools, chat replies and legacy content checks, and denies everything else.

YAML rather than Rego or Cedar keeps the format readable and the engine small (`backend/policy/engine.py`). The engine is called through one function, `evaluate()`, so an OPA or Cedar backend could replace it without touching the endpoints.

## `POST /api/check`

```bash
curl -s -X POST localhost:8000/api/check \
  -H 'Content-Type: application/json' \
  -d '{"tool": {"name": "http.fetch"}, "arguments": {"url": "http://[::1]:8080/admin"}, "agent": {"id": "researcher"}}'
```

The response carries `effect`, `blocked`, `enforced`, `rule_id`, `reasons`, `matched_detectors`, `matches` (each with severity, OWASP ids, evidence paths and `blocking`), both OWASP ids for the decision, and the policy version and sha256. HTTP 200 means allow, 403 deny, 202 waiting for a human, 429 too many approvals already waiting (refused).

The older shapes still work: `{"content": "..."}` is checked as the tool `guardian.content` and `{"event": {"type": "...", "data": {...}}}` as `guardian.event.<type>`. Matches below `BLOCK_THRESHOLD` are listed with `"blocking": false`.

**Authentication.** With `GUARDIAN_API_KEYS` unset, `/api/check` is open demo behaviour: sessions come from `X-Session-Id` (at most 1000 are kept, least recently used evicted), and the `agent` in the body is self-reported, so a policy rule on `agent` is a label, not a control. With `GUARDIAN_API_KEYS=billing=<key>,ops=<key>` set, every call needs `Authorization: Bearer <key>` (401 otherwise), the agent identity used for `agent:` rules is the key's name, and decisions go to the dashboard session `app:<name>`, which a browser can only watch with `?token=<that key or an approver key>`. Client session ids starting with `app:` are rejected.

## Approvals

When a rule says `require_approval` (and the policy is in enforce mode), `/api/check` answers 202:

```json
{"status": "pending", "approval_id": "apr_...", "poll_url": "/api/approvals/apr_...", "expires_at": 1793373576.4, "effect": "require_approval", "rule_id": "approve-deploys", ...}
```

The caller must not run the tool yet. It polls `GET /api/approvals/{id}?wait=30` (held open up to 60 s until something changes). A human answers on the dashboard's Approvals lane, which shows the arguments, what changed since the previous approval for the same tool, the policy rule and a countdown, or with `POST /api/approvals/{id}` and `{"approve": true, "note": "..."}`. Once the status is `approved`, the caller sends the identical call to `/api/check` again and gets 200.

- **Bound to the exact call.** An approval covers one session, one caller and `sha256` of the tool, server and canonical JSON arguments. Changing any argument opens a new approval; retrying the same call while it is pending joins the existing one.
- **Single use by default.** An approval lets one identical call through, and that call must come within the rule's timeout after the approval. `approval.grant_ttl_seconds` on a rule lets identical calls through for that window instead.
- **Fails closed.** No answer within `approval.timeout_seconds` (policy default, or per rule) resolves as `denied` with reason `timeout`. Answering after that returns 409.
- **Who may answer.** With `GUARDIAN_APPROVER_KEYS` set, only a request with an approver key (`Authorization: Bearer`) can answer. Without approver keys, approvals for API-key sessions (`app:<name>`) cannot be answered at all and time out, so an agent's own key never approves its own call. In open demo mode (no keys) anyone with the session id can answer, which includes the agent itself: a real deployment needs approver keys, or SSO in front of these endpoints. To watch and answer an API-key session in the dashboard, open `/?session=app:<name>&token=<approver key>`.
- **Storage.** Approvals live in process memory (`backend/approvals/store.py`, behind an `ApprovalStore` interface): they are lost on restart and not shared between processes. At most 100 can wait per session and 10,000 in total; beyond that the call is refused with 429.

Dashboard event streams are bounded (1000 events per browser); a browser that stops reading loses its oldest events.

![Approvals lane](docs/images/approvals-lane.png)

## Connect Your App

GuardianAI works with any FastAPI (Python) or Express (Node.js) app. Two lines of code:

### Python (FastAPI)

```bash
pip install guardian-tap
```

```python
from guardian_tap import attach_observer
attach_observer(app)
```

### Node.js (Express)

```bash
npm install github:bnarasimha21/guardian-tap-typescript
```

```javascript
import { attachObserver } from 'guardian-tap';
attachObserver(app);
```

That's it. Your app now exposes a `/ws-observe` endpoint that GuardianAI connects to. No other code changes needed.

## Features

- **Multi-app monitoring**: Connect and monitor multiple apps from one dashboard
- **Per-user isolation**: Each browser session gets its own workspace
- **Generic event classification**: Works with any agent system (WebSocket, SSE, REST JSON)
- **Health check verification**: Validates guardian-tap installation before connecting
- **Policy as code**: one YAML file decides, reloaded on change
- **Human approvals**: Approve/Deny on the dashboard, bound to the exact arguments, fail closed on timeout
- **Expandable flagged cards**: Click to see OWASP context, remediation steps, and raw event data
- **App and event filtering**: Filter by connected app or event category
- **Rolling summary**: Real-time stats with per-app breakdowns
- **Usage logging**: Tracks sessions, connections, and flagged threats via Supabase

## Architecture

```
Your App (FastAPI/Express)
    |
    | guardian-tap package adds /ws-observe endpoint
    | (intercepts WebSocket, SSE, and JSON responses)
    |
    v
GuardianAI Server (FastAPI)
    |
    |-- WebSocket tap client (passive observer, decisions are observed only)
    |-- Detectors (backend/guardian/rules.py)
    |-- Policy engine + hot-reloaded YAML policy (backend/policy)
    |-- POST /api/check (policy decision point: 200 allow, 403 deny, 202 approval)
    |-- Approval queue (in memory) + /api/approvals
    |-- Per-session event bus
    |-- Supabase usage logging
    |
    v
Browser Dashboard
    |-- Agent Activity (left panel)
    |-- Guardian Decisions (right panel)
    |-- Summary card with stats
```

## Running Locally

```bash
pip install -r requirements.txt
uvicorn server:app --host 0.0.0.0 --port 8000 --reload
```

Open http://localhost:8000 and click "Connect App" to get started. To observe an
app running on your own machine (`ws://localhost:...`), start GuardianAI with
`ALLOW_PRIVATE_TARGETS=true`; by default it refuses to connect to loopback,
private, link-local and cloud metadata addresses.

## Tests

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
python -m pytest
```

The suite runs offline: DNS, outbound HTTP and Supabase are replaced in
`tests/conftest.py`.

## Environment Variables

```
HOST=0.0.0.0
PORT=8000
BLOCK_THRESHOLD=high                              # severity that the policy's "block_threshold" means: low, medium, high, critical
ALLOW_PRIVATE_TARGETS=false                       # let targets point at loopback/private addresses (local dev only)
GUARDIAN_POLICY_FILE=                             # policy YAML path (default policies/default.yaml)
GUARDIAN_API_KEYS=                                # name=key,name=key; when set, /api/check needs a Bearer key (16+ chars)
GUARDIAN_APPROVER_KEYS=                           # name=key; may watch every app:* dashboard session
SUPABASE_URL=https://your-project.supabase.co    # optional, for usage logging
SUPABASE_ANON_KEY=your-anon-key                   # optional, for usage logging
```

## Related Repos

- [guardian-tap-python](https://github.com/bnarasimha21/guardian-tap-python) - Python (FastAPI) integration package
- [guardian-tap-typescript](https://github.com/bnarasimha21/guardian-tap-typescript) - TypeScript (Express) integration package

## Live Demo

[narasimha-badrinath.com/guardian-ai](https://narasimha-badrinath.com/guardian-ai/)
