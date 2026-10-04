<div align="center">

<img src="https://raw.githubusercontent.com/Harshith029/SENTINEL/main/assets/banner.png" alt="SENTINEL — provenance-aware security for AI agents" width="680">

[![PyPI](https://img.shields.io/pypi/v/sentinel-prox?style=for-the-badge&labelColor=0B1220&color=22D3EE&label=PYPI)](https://pypi.org/project/sentinel-prox/)
[![Python](https://img.shields.io/pypi/pyversions/sentinel-prox?style=for-the-badge&labelColor=0B1220&color=3B82F6&label=PYTHON)](https://pypi.org/project/sentinel-prox/)
[![CI](https://img.shields.io/github/actions/workflow/status/Harshith029/SENTINEL/ci.yml?style=for-the-badge&labelColor=0B1220&color=22D3EE&label=CI)](https://github.com/Harshith029/SENTINEL/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/LICENSE-MIT-3B82F6?style=for-the-badge&labelColor=0B1220)](./LICENSE)
[![Live demo](https://img.shields.io/badge/DEMO-LIVE-6366F1?style=for-the-badge&labelColor=0B1220)](https://sentinel-i63x.onrender.com)

[![mypy](https://img.shields.io/badge/MYPY-STRICT-3B82F6?style=for-the-badge&labelColor=0B1220)](http://mypy-lang.org/)
[![ruff](https://img.shields.io/badge/LINT-RUFF-3B82F6?style=for-the-badge&labelColor=0B1220)](https://github.com/astral-sh/ruff)
[![no eval](https://img.shields.io/badge/CODEBASE-NO%20EVAL-22D3EE?style=for-the-badge&labelColor=0B1220)](./src/sentinel/authorization/ast.py)

**Stop prompt-injection attacks at the action layer — where the damage happens.**

</div>

SENTINEL sits between your agent and your MCP tool servers, tracks which tool results
each action could have been influenced by, and refuses the actions you guard when that
lineage includes untrusted content — **even when the attack slipped past your content
filter**. Read *Known limitations* before relying on it: the lineage is per MCP session,
and only the tools you write rules for are guarded.

<div align="center">
<img src="https://raw.githubusercontent.com/Harshith029/SENTINEL/main/assets/dashboard.png" alt="SENTINEL blocking an exfiltration attempt: the content filter missed the injection, but the action was refused because its lineage was tainted" width="820">
<br>
<sub><i>A poisoned page induces the agent to email a customer record to an attacker. The
Layer-1 filter <b>misses</b> the obfuscated injection — the action is refused anyway,
because its lineage traces back to untrusted content.</i></sub>
</div>

```bash
pip install sentinel-prox # the import package and CLI are both `sentinel`
sentinel init             # write sentinel.yaml
sentinel check            # run serve's startup checks without serving; non-zero if serve would fail
sentinel scaffold > policy.yaml
sentinel serve            # your agent points at http://127.0.0.1:8765/mcp
```

Your agent needs **no code changes**: point its MCP endpoint at SENTINEL instead of
directly at your tool servers. Interception is guaranteed by topology, not by asking
the agent to cooperate.

---

## Status and known limitations

Read this before deploying anything.

| Area | State |
|---|---|
| Provenance tracking + deterministic default-deny enforcement | Working, tested |
| Forensic spans, replay, audit trail | Working; payloads redacted before persistence. Each run's tenant is recorded, so history stays with its tenant across restarts. Traces are deleted after `SENTINEL_FORENSIC_RETENTION_DAYS` (default 90). Not encrypted at rest by SENTINEL (see *Forensic data*) |
| Catalogue integrity (poisoning, cross-server shadowing, rug pulls) | Working, tested. Checked at connect, on tool listing and every `SENTINEL_CATALOGUE_RECHECK_SECONDS`; findings appear in `GET /downstream` and the logs, not in the forensic store. Re-approving a changed catalogue means restarting |
| Authentication | Every endpoint gated; fails closed when unconfigured |
| Policy config (`allowed_domains`, limits) | Declared per tenant in the policy document |
| Declassification (`StructuredExtractor`) | Wired into enforcement; opt-in per tool via policy |
| Stable agent identity across reconnect | Derived from the authenticated credential; trust and an enforced quarantine survive reconnect (per process, and only when authenticated) |
| Multi-tenant isolation | Per-tenant credentials (`SENTINEL_API_TOKENS`); runs, events, SSE and MCP sessions scoped to the credential's tenant; per-tenant policy via `SENTINEL_TENANT_POLICIES` |
| Operator separation | Only `SENTINEL_ADMIN_TOKEN` can change policy or clear a quarantine; tenant (agent) credentials cannot |
| Resource bounds | Request body, request rate, runs in flight, retained runs, live-stream subscribers, event page and tool-result size are all capped (see *Resource limits*). Counters are per process: replicas do not share them |
| Self-hosting (Docker / `deploy/compose.yaml`) | Verified locally; CI builds and starts the image on every push |
| Azure deployment (Bicep) | Optional. **Never deployed**; CI only proves the template compiles |
| Downstream reconnect within one process | **Blocked** by an unresolved transport defect |

### Known limitations

These are open, verified, and not yet fixed. Each one changes what SENTINEL
protects you from.

| Limitation | What it means for you |
|---|---|
| **Taint is per MCP session** | Lineage covers the calls made in one MCP session. A client that opens a new session for every tool call (LangChain's `MultiServerMCPClient` does by default) gets **no** taint carried from one call to the next, so a page read in one call does not taint an email sent in the next. A long-lived session has the opposite problem: after its first untrusted result, every guarded action in it is denied until it reconnects. |
| **Every tool result is untrusted** | All tool output is labelled retrieved content, including your own internal systems. A benign flow such as "look up the customer, then email them" is denied if the email tool has a taint rule. Only per-tool declassification (a value that validates against a strict schema) clears taint. |
| **Only guarded tools are guarded** | A tool with no rules can carry tainted data out: a URL's query string in a fetch tool, for example. The bundled example policy leaves `web_fetch` unrestricted. Rules are deny-only and there is no notion of an outbound "sink" yet. |
| **Quarantine is recorded, not enforced** (default) | The trust score never recovers, so agents making only allowed calls cross the threshold within tens of calls. By default that crossing is logged, not acted on. `SENTINEL_ENFORCE_QUARANTINE=1` enforces it, for every agent that shares a credential. |
| **Downstream servers: HTTP only** | No stdio servers, no per-server credentials or OAuth, one shared session per server, and no reconnect. Most published MCP servers are stdio. |
| **The dashboard is always served** | `dashboard: false` in `sentinel.yaml` does not unmount `/` or the demo endpoints. |

`SENTINEL_API_TOKEN` must be set for any deployment reachable from a network.
With neither it nor `SENTINEL_ALLOW_ANONYMOUS=1` set, the service refuses to
serve rather than serving openly.


## The problem

AI agents don't just answer questions any more — they send email, query business
systems, and read the open web. That makes **indirect prompt injection** an action
problem, not a text problem: an attacker hides an instruction inside content the
agent will read, and it executes with the agent's full privileges.
*"Summarize this pricing page"* quietly becomes *"email this customer's SSN to the
attacker."*

Content filters scan the words. Microsoft's own Prompt Shields documentation says it
"may not catch all attack vectors" and recommends additional validation layers.
**The gap: security is applied to the words, while the damage is done by the actions.**

SENTINEL closes it by judging an action on **where its data came from**, not on how
the request was phrased.

## What it protects against

| Attack | How SENTINEL stops it |
|---|---|
| **Indirect prompt injection** | Actions whose lineage includes untrusted content are denied — regardless of phrasing, so obfuscation doesn't help |
| **Data exfiltration** | A `send_email` built from a retrieved page is refused before it executes |
| **Tool poisoning** | Tool descriptions *and* input schemas are scanned at connect; a poisoned catalogue is refused |
| **Cross-server shadowing** | Two servers claiming one tool name fails closed — SENTINEL won't guess which is authoritative |
| **Rug pulls** | The catalogue is fingerprinted at approval and re-checked on every tool listing and on a schedule. A tool that changes after approval is refused at call time; so is any tool that was not in the approved catalogue |
| **Privilege escalation** | Unknown tools are default-denied until you write a rule |
| **Repeated abuse** | A trust score degrades on blocked calls and quarantines the agent |

Every decision becomes an immutable, replayable forensic record, exportable as
SIEM-ready JSONL.

<div align="center">
<img src="https://raw.githubusercontent.com/Harshith029/SENTINEL/main/assets/outbox-diff.png" alt="The same attack with and without SENTINEL: without it the SSN and API key reach the attacker; with it the email is never sent" width="820">
<br>
<sub><i>The same attack, run twice. Without SENTINEL the customer's SSN and API key reach
the attacker's inbox; with it, the email is never sent.</i></sub>
</div>

## How it works

<div align="center">
<img src="https://raw.githubusercontent.com/Harshith029/SENTINEL/main/assets/architecture.png" alt="Architecture: the agent reaches its tools only through SENTINEL, which traces origins, authorizes, contains, and records" width="760">
</div>

```
 your agent  ──MCP──▶  SENTINEL  ──MCP──▶  your MCP servers
                          │
       1. trace      label the origin of everything the agent has seen
       2. authorize  policy decides each call using that lineage (deny-overrides)
       3. contain    trust score + automatic quarantine
       4. record     immutable spans → replay + SOC export
```

Provenance is a **set of trust labels** (`SYSTEM > USER > AGENT > RETRIEVED_CONTENT`)
unioned over an action's transitive `derived_from` ancestry — computed by a real
cycle-safe graph walk, not a mutable flag. An action is tainted iff
`RETRIEVED_CONTENT` is in that set.

Taint clears exactly one way: **declassification**, declared per tool in policy.

```yaml
tools:
  read_price:
    declassify:
      schema: decimal_amount   # output crosses the boundary only if it validates
    rules: []
```

`StructuredExtractor` then validates that tool's output against the named schema.
On a match the value starts fresh at SYSTEM trust with no inherited ancestry; on
a mismatch it stays exactly as tainted as it was. Opt-in per tool, so a tool with
no `declassify` block can never clear taint, and the schema registry is closed —
policy names a reviewed schema or the policy fails to load. A cleared value
cannot launder a tainted sibling, because recombination re-taints.

Policy compiles to a **typed condition AST** and is evaluated by tree-walk;
there is no `eval` anywhere in the codebase. Rules are deny-only with
deny-overrides, and **unknown tools are default-denied**.

## Configuration

`sentinel.yaml` (created by `sentinel init`):

```yaml
servers:                      # YOUR MCP servers — SENTINEL ships no tools
  - name: github
    url: https://mcp.example/gh
policy: ./policy.yaml         # your rules; generate with `sentinel scaffold`
host: 127.0.0.1
port: 8765
dashboard: false              # the bundled UI is a DEMO, opt-in only
catalogue_strict: true        # refuse catalogues containing injection markers
```

### Seeing enforcement

Every decision is logged where you are actually looking — blocks at `WARNING`,
allowed calls at `INFO`, each carrying the `trace_id` that ties the line back to
the full forensic record:

```
23:16:40 INFO    ALLOW  get_customer_record  [trace 2ad33998e093]
23:16:40 INFO    ALLOW  web_fetch  [trace 2ad33998e093]
23:16:40 WARNING BLOCK  send_email  rule=block-untrusted-origin  [trace 2ad33998e093]
```

`sentinel serve --log-format json` emits one JSON object per line for an
aggregator, and `--log-level WARNING` narrows it to refusals and quarantines.

**Tool arguments are never logged.** The payloads SENTINEL inspects are the very
secrets it exists to protect, so writing them to a log would move the secret from
a blocked call into a plaintext file that ships off-box — performing the
exfiltration that was just prevented. The decision is logged; the data stays in the
access-controlled forensic store. There is a test asserting the synthetic SSN and
API key never appear in log output.

Precedence is **CLI flag > environment variable > config file > default**, so a
container can override a checked-in file. Every key has an env equivalent
(`SENTINEL_MCP_SERVERS`, `SENTINEL_POLICY_FILE`, …) — see [`.env.example`](./.env.example).

### Writing policy

Rules are **deny-only**: a call is allowed when no deny rule matches. `sentinel
scaffold` emits every discovered tool explicitly denied, with its description and a
recommended starting rule, so you edit rather than invent.

```yaml
policy_version: 1
tools:
  send_email:
    rules:
      - id: block-untrusted-origin
        deny_if: "RETRIEVED_CONTENT in effective_provenance"
      - id: domain-allowlist
        deny_if: "recipient_domain not in allowed_domains"
  delete_record:
    rules:
      - id: never
        deny_always: true
```

Predicates support `== != < >= in "not in"`, set literals (`{USER}`), tool arguments,
and config values.

## Deployment

Self-hosting is free and needs no cloud account:

```bash
python -c "import secrets; print('SENTINEL_API_TOKEN=' + secrets.token_urlsafe(32))" > .env
docker compose -f deploy/compose.yaml --env-file .env up -d --build
```

This keeps forensic history on a volume, refuses to start without the token, and
listens on loopback only. [`deploy/DEPLOY.md`](./deploy/DEPLOY.md) covers the local
demo, reaching SENTINEL from other machines (free options, and which ones we have
tested), platforms that set `PORT`, and the optional, untested Azure template.

Put your tool servers on an internal network reachable **only** by SENTINEL — that
topology is what makes interception unbypassable.

Authentication is required: with no credential configured SENTINEL refuses to serve.
Set `SENTINEL_API_TOKEN`, or `SENTINEL_API_TOKENS` for per-tenant credentials plus
`SENTINEL_ADMIN_TOKEN` for the operator (see [`.env.example`](./.env.example)).

### Resource limits

Every per-request and per-tenant resource is capped, so one caller cannot exhaust
the service. The defaults sit well above normal use and only affect abuse.

| Setting | Default | Over the limit |
|---|---|---|
| `SENTINEL_MAX_BODY_BYTES` | 4 MiB | `413`. Chunked bodies are counted as they stream |
| `SENTINEL_RATE_LIMIT_PER_MINUTE` | 600 | `429` + `Retry-After`. `0` disables |
| `SENTINEL_MAX_ACTIVE_RUNS` | 8 per tenant | `429` + `Retry-After` |
| `SENTINEL_MAX_RETAINED_RUNS` | 1000 | Oldest *finished* run leaves the run index; its spans stay in the forensic store |
| `SENTINEL_MAX_SSE_SUBSCRIBERS` | 100 | `503` |
| `SENTINEL_MAX_RESULT_BYTES` | 1 MiB | The tool result is withheld and the agent gets an error. The call is still recorded |

`GET /events` returns at most 1000 events per call, with `next_since` to resume.

The rate limit is keyed by **tenant** for a valid credential and by **client
address** for everything else, including invalid credentials and anonymous
traffic. Inventing a new token for each request therefore does not buy a new
budget. Behind a reverse proxy, the client address is the proxy's unless uvicorn
trusts it: set `FORWARDED_ALLOW_IPS` to the proxy's address or CIDR. Do not set
it to `*` on a host clients can reach directly, because uvicorn then takes the
client-supplied `X-Forwarded-For` at face value. Until you configure it, all
unauthenticated callers share one budget.

These counters live in process memory. Two replicas give a tenant twice the
budget; enforce a global limit at the load balancer if you need one.

### Forensic data

The default store is SQLite at `${SENTINEL_DATA_DIR:-./var}/sentinel.db`.

- **Retention.** A trace is deleted, whole, once its newest span is older than
  `SENTINEL_FORENSIC_RETENTION_DAYS` (default 90; `0` keeps everything). The
  purge runs the first time runs are listed or started after startup, then at
  most once a day while runs are being started, so an idle service purges
  nothing. Runs in flight are never deleted. Set the window to what your audit
  obligations require.
- **Ownership.** Each run's tenant is recorded when it starts, so after a
  restart every tenant sees its own history and no one else's. History written
  by a version before that has no recorded owner; it is shown only to the
  operator (`SENTINEL_ADMIN_TOKEN`) rather than guessed at.
- **Encryption at rest.** SENTINEL does not encrypt the database. Tool
  arguments and results are redacted before they are written, but tool names,
  decisions and timings are stored in the clear. Put `SENTINEL_DATA_DIR` on an
  encrypted volume.
- **Backup.** A clean shutdown checkpoints the write-ahead log, so the `.db`
  file of a stopped service is complete on its own. While it runs, copy it with
  SQLite's online backup (`sqlite3 sentinel.db ".backup copy.db"`), not a
  file copy: the newest writes can still be in `sentinel.db-wal`.
- **Cosmos DB.** Retention there is the container's time-to-live (`defaultTtl`),
  set on the container; SENTINEL does not purge Cosmos itself.

### Running at zero cost

Nothing in SENTINEL requires a paid service. Enforcement — provenance tracking and
the authorization engine — runs locally and is identical everywhere. The paid
integrations improve detection, labelling and telemetry; they are upgrades, not
prerequisites, and `GET /capabilities` reports which backend each capability is
actually running on.

| Capability | Free default | Optional paid upgrade |
|---|---|---|
| Enforcement (provenance + policy) | Built in | — |
| Layer-1 injection shield | Local heuristic detector (`SENTINEL_SHIELD=local`) | Azure AI Content Safety |
| Attack classifier (SOC labels) | Rule-based | Azure OpenAI |
| Forensic persistence | SQLite on local disk | Azure Cosmos DB |
| Agent model | Ollama locally, or any OpenAI-compatible endpoint via `OPENAI_BASE_URL` | OpenAI / Azure OpenAI |
| Hosting | Render free tier (`render.yaml`), or any Docker host | Azure Container Apps |

The Layer-1 shield only *flags*; it never blocks. The authorization engine refuses a
tainted action whether or not anything flagged the text that tainted it, so a
simpler free detector does not weaken enforcement.

An Azure Container Apps blueprint is in [`deploy/`](./deploy). It is optional and has
**not** been deployed or smoke-tested; see *Status and known limitations*.

## Try the demo

A bundled demo shows the whole pipeline on a scripted attack — useful for seeing what
a block looks like, but **not** the product surface:

```bash
sentinel serve --dashboard     # → http://localhost:8765
```

Hosted: **https://sentinel-i63x.onrender.com** (free tier — first load may take ~50 s
to wake). It runs in **anonymous demo mode with authentication disabled**, so treat
it as a public sandbox, not as an example of a secured deployment: everything in it
is synthetic and anyone can drive it. A real deployment must set
`SENTINEL_API_TOKEN`. A poisoned page induces the agent to email a synthetic customer record to an
attacker; the Layer-1 filter misses the obfuscated variant and authorization blocks it
anyway. All demo data is synthetic — the record is a labelled fake
(SSN `000-00-0000`, a non-functional `sk-synthetic-DO-NOT-USE` key) and `send_email`
writes to an in-memory sink. Nothing is ever sent.

### With a real model

The default agent is a real LLM whenever a credential is present — set
`OPENAI_API_KEY`, or `AZURE_OPENAI_ENDPOINT` + `AZURE_OPENAI_DEPLOYMENT`. With no
credential it falls back to a deterministic scripted transcript so CI stays key-free.
For a free local model, point `OPENAI_BASE_URL` at any OpenAI-compatible endpoint:

```bash
ollama serve && ollama pull llama3.2
export OPENAI_BASE_URL=http://localhost:11434/v1 OPENAI_MODEL=llama3.2
```

## What SENTINEL does *not* protect against

Stating the boundary precisely is what separates a security product from a demo.

- Provenance is tracked at **message / tool-result granularity**, not token-level
  inside model reasoning. Taint spreads conservatively unless a sanitizer clears it.
- It secures the **action layer**, not the model's cognition. It does not stop a model
  being *persuaded* — it stops the resulting unauthorized **action**.
- The proxy and the policy store are **trusted** components.
- One trace is handled by one proxy instance; horizontal scaling is *across* traces.
- **Conservative tainting is intentional.** The escape hatch is declassification,
  declared per tool in policy, and it is deliberately narrow: syntactic schema
  validation only. Taint saturation is the correct bias for action-layer
  security, so clearing it must be something an operator opts into for a
  specific tool and a specific shape of value.
- **Sanitization is syntactic, not semantic.** A schema-valid `{"price": 999999}` is
  well-formed but still subject to argument-level rules such as an amount cap.

## Development

```bash
python -m venv .venv
.venv/bin/python -m pip install -e ".[dev]" -c versions.lock   # Windows: .venv\Scripts\python.exe
.venv/bin/python -m pytest        # 370 tests
.venv/bin/python -m ruff check src tests
.venv/bin/python -m mypy src      # strict
```

Install `-c versions.lock` so local matches CI and the container — a floating
dependency is how a production deploy once broke. Requires Python 3.11+.

See [CONTRIBUTING.md](./CONTRIBUTING.md) for the security invariants a change must
preserve, and [CHANGELOG.md](./CHANGELOG.md) for release notes. Design notes live in
[`docs/`](./docs): the scoping analysis for proxying arbitrary MCP servers, and the
competitive/threat-landscape research behind the roadmap.

## License & credits

MIT — see [LICENSE](./LICENSE).

Built on the [Model Context Protocol](https://modelcontextprotocol.io) Python SDK,
FastAPI, Starlette, `sse-starlette`, Uvicorn, Pydantic, OpenTelemetry, PyYAML, httpx,
pytest, ruff, mypy, gitleaks, and the Azure SDKs for Python. Thank you to their
maintainers.

**AI tools used in development:** Claude Code (Anthropic) and GitHub Copilot.
SENTINEL also *integrates* Azure OpenAI (attack classification) and Azure AI Content
Safety / Prompt Shields (Layer-1 screening) as optional components.

Originally built for the Microsoft Build AI Hackathon 2026 — *Security in the Agentic
Future* — by Pali Krishna Harshith.
