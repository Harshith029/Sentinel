<div align="center">

<img src="https://raw.githubusercontent.com/Harshith029/Sentinel/main/assets/banner.png" alt="SENTINEL — provenance-aware security for AI agents" width="640">

[![PyPI](https://img.shields.io/pypi/v/sentinel-prox?color=38BDF8&label=pypi)](https://pypi.org/project/sentinel-prox/)
[![Python](https://img.shields.io/pypi/pyversions/sentinel-prox?color=38BDF8)](https://pypi.org/project/sentinel-prox/)
[![CI](https://github.com/Harshith029/Sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/Harshith029/Sentinel/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-38BDF8.svg)](./LICENSE)
[![Checked with mypy](https://img.shields.io/badge/mypy-strict-2ea44f.svg)](http://mypy-lang.org/)
[![Ruff](https://img.shields.io/badge/lint-ruff-2ea44f.svg)](https://github.com/astral-sh/ruff)
[![Live demo](https://img.shields.io/badge/demo-live-2ea44f.svg)](https://sentinel-i63x.onrender.com)

**Stop prompt-injection attacks at the action layer — where the damage happens.**

</div>

SENTINEL sits between your agent and your MCP tool servers, tracks where every byte of
context came from, and refuses actions whose data originated in untrusted content —
**even when the attack slipped past your content filter**.

<div align="center">
<img src="https://raw.githubusercontent.com/Harshith029/Sentinel/main/assets/dashboard.png" alt="SENTINEL blocking an exfiltration attempt: the content filter missed the injection, but the action was refused because its lineage was tainted" width="820">
<br>
<sub><i>A poisoned page induces the agent to email a customer record to an attacker. The
Layer-1 filter <b>misses</b> the obfuscated injection — the action is refused anyway,
because its lineage traces back to untrusted content.</i></sub>
</div>

```bash
pip install sentinel-prox    # imports and CLI are both `sentinel`
sentinel init             # write sentinel.yaml
sentinel check            # validate config, connect to your servers, vet their tools
sentinel scaffold > policy.yaml
sentinel serve            # your agent points at http://127.0.0.1:8765/mcp
```

Your agent needs **no code changes**: point its MCP endpoint at SENTINEL instead of
directly at your tool servers. Interception is guaranteed by topology, not by asking
the agent to cooperate.

---

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
| **Rug pulls** | The catalogue is fingerprinted at approval and re-checked; post-approval mutation is detected |
| **Privilege escalation** | Unknown tools are default-denied until you write a rule |
| **Repeated abuse** | A trust score degrades on blocked calls and quarantines the agent |

Every decision becomes an immutable, replayable forensic record, exportable as
SIEM-ready JSONL.

<div align="center">
<img src="https://raw.githubusercontent.com/Harshith029/Sentinel/main/assets/outbox-diff.png" alt="The same attack with and without SENTINEL: without it the SSN and API key reach the attacker; with it the email is never sent" width="820">
<br>
<sub><i>The same attack, run twice. Without SENTINEL the customer's SSN and API key reach
the attacker's inbox; with it, the email is never sent.</i></sub>
</div>

## How it works

<div align="center">
<img src="https://raw.githubusercontent.com/Harshith029/Sentinel/main/assets/architecture.png" alt="Architecture: the agent reaches its tools only through SENTINEL, which traces origins, authorizes, contains, and records" width="760">
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
`RETRIEVED_CONTENT` is in that set. Taint clears only through an explicit, auditable
`StructuredExtractor` (strict schema validation produces a fresh SYSTEM-trust value
with no inherited ancestry), and a sanitized value **cannot launder a tainted
sibling** — recombination re-taints.

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

```bash
docker build -t sentinel -f deploy/Dockerfile .
docker run --rm -p 8765:8765 -v $(pwd)/sentinel.yaml:/app/sentinel.yaml sentinel
```

Put your tool servers on an internal network reachable **only** by SENTINEL — that
topology is what makes interception unbypassable. An Azure Container Apps blueprint
(internal-ingress tool servers, KEDA scaling, managed identity, Cosmos persistence)
is in [`deploy/`](./deploy).

Gate the endpoint on any public deploy with `SENTINEL_API_TOKEN`.

## Try the demo

A bundled demo shows the whole pipeline on a scripted attack — useful for seeing what
a block looks like, but **not** the product surface:

```bash
sentinel serve --dashboard     # → http://localhost:8765
```

Hosted: **https://sentinel-i63x.onrender.com** (free tier — first load may take ~50 s
to wake). A poisoned page induces the agent to email a synthetic customer record to an
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
- **Conservative tainting is intentional.** Some benign workflows will need explicit
  sanitization. Taint saturation is the correct bias for action-layer security.
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
