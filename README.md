<div align="center">

<img src="https://raw.githubusercontent.com/Harshith029/Sentinel/main/assets/banner.png" alt="SENTINEL — provenance-aware security for AI agents" width="680">

**Stop prompt-injection attacks at the action layer, where the damage happens.**

[![PyPI](https://img.shields.io/pypi/v/sentinel-prox?style=flat-square&labelColor=0B1220&color=22D3EE&label=pypi)](https://pypi.org/project/sentinel-prox/)
[![Python](https://img.shields.io/pypi/pyversions/sentinel-prox?style=flat-square&labelColor=0B1220&color=3B82F6&label=python)](https://pypi.org/project/sentinel-prox/)
[![CI](https://img.shields.io/github/actions/workflow/status/Harshith029/Sentinel/ci.yml?branch=main&style=flat-square&labelColor=0B1220&label=ci)](https://github.com/Harshith029/Sentinel/actions/workflows/ci.yml)
[![Docs](https://img.shields.io/badge/docs-website-6366F1?style=flat-square&labelColor=0B1220)](https://harshith029.github.io/Sentinel/)
[![License: MIT](https://img.shields.io/badge/license-MIT-3B82F6?style=flat-square&labelColor=0B1220)](https://github.com/Harshith029/Sentinel/blob/main/LICENSE)

[**Website**](https://harshith029.github.io/Sentinel/) ·
[Quick start](https://harshith029.github.io/Sentinel/guide/quick-start) ·
[Writing policy](https://harshith029.github.io/Sentinel/guide/policy) ·
[Limitations](https://harshith029.github.io/Sentinel/guide/limitations) ·
[FAQ](https://harshith029.github.io/Sentinel/faq) ·
[Changelog](https://github.com/Harshith029/Sentinel/blob/main/CHANGELOG.md)

</div>

SENTINEL is a security proxy for AI agents that use the
[Model Context Protocol](https://modelcontextprotocol.io) (MCP). It sits between
your agent and your MCP tool servers, tracks which tool results each action could
have been influenced by, and refuses the actions you guard when that lineage
includes untrusted content, **even when the attack got past your content filter**.

Your agent needs **no code changes**: point its MCP endpoint at SENTINEL instead of
at your tool servers. Interception comes from the network topology, not from
asking the agent to cooperate.

<div align="center">
<img src="https://raw.githubusercontent.com/Harshith029/Sentinel/main/assets/dashboard.png" alt="SENTINEL blocking an exfiltration attempt: the content filter missed the injection, but the action was refused because its lineage was tainted" width="820">
<br>
<sub><i>A poisoned page induces the agent to email a customer record to an attacker. The
Layer-1 filter <b>misses</b> the obfuscated injection; the action is refused anyway,
because its lineage includes untrusted tool output. (Bundled demo, synthetic data.)</i></sub>
</div>

> **Important:** install **0.2.2 or later**. The 0.1.x releases are insecure (an open `/mcp`
> endpoint, overridable policy config, unredacted forensics). SENTINEL is beta:
> read [Status and known limitations](#status-and-known-limitations) before you
> rely on it.

## Contents

- [Quick start](#quick-start)
- [How it works](#how-it-works)
- [What it protects against](#what-it-protects-against)
- [Status and known limitations](#status-and-known-limitations)
- [Writing policy](#writing-policy)
- [Try the demo](#try-the-demo)
- [Documentation](#documentation)
- [FAQ](#faq)
- [Contributing](#contributing)
- [License and credits](#license-and-credits)

## Quick start

Requires Python 3.11+ and MCP servers that speak the streamable HTTP transport.

```bash
pip install "sentinel-prox>=0.2.2"
sentinel init                    # write sentinel.yaml; list your servers under `servers:`
export SENTINEL_API_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
sentinel check                   # connect, vet each catalogue; non-zero if serve would fail
sentinel scaffold > policy.yaml  # every discovered tool, denied, with a suggested rule
sentinel serve                   # agents connect to http://127.0.0.1:8765/mcp
```

Your agent then uses `http://127.0.0.1:8765/mcp` with
`Authorization: Bearer $SENTINEL_API_TOKEN`. Put your tool servers on a network
that **only** SENTINEL can reach, so nothing can go around it.

SENTINEL is fail-closed: with no credential configured, every data route answers
`503` rather than serving openly. The full walkthrough, including a client example,
is in the [quick start guide](https://harshith029.github.io/Sentinel/guide/quick-start).

## How it works

<div align="center">
<img src="https://raw.githubusercontent.com/Harshith029/Sentinel/main/assets/architecture.png" alt="Architecture: the agent reaches its tools only through SENTINEL, which traces origins, authorizes, contains, and records" width="760">
</div>

1. **Trace.** Everything the agent sees carries a trust label
   (`SYSTEM > USER > AGENT > RETRIEVED_CONTENT`). An action's provenance is the
   **set** of labels over its whole transitive ancestry, never just the most
   recent step. It is tainted if and only if `RETRIEVED_CONTENT` is in that set.
2. **Authorize.** Your policy compiles to a typed condition tree; there is no
   `eval` anywhere in the codebase. Rules are deny-only with deny-overrides, and
   **unknown tools are denied by default**.
3. **Contain.** A trust score drops on denied calls and other signals, and can
   quarantine the agent.
4. **Record.** Every decision is an immutable, replayable forensic span,
   exportable as JSONL for a SIEM. Tool arguments are redacted before storage and
   never logged.

Taint clears exactly one way: **declassification**, declared per tool, when the
tool's output validates against a strict, closed schema. A tool whose output no
outsider can write to can instead be marked `trusted_output: true`.
[More on how it works.](https://harshith029.github.io/Sentinel/guide/how-it-works)

## What it protects against

| Attack | How SENTINEL stops it |
|---|---|
| **Indirect prompt injection** | Actions whose lineage includes untrusted content are denied, whatever the wording, so obfuscation does not help |
| **Data exfiltration** | A `send_email` built from a retrieved page is refused before it runs |
| **Tool poisoning** | Every agent-visible part of a tool definition is scanned at connect; a poisoned catalogue is refused |
| **Cross-server shadowing** | Two servers claiming one tool name fails closed |
| **Rug pulls** | The catalogue is fingerprinted at approval and re-checked; a tool that changed, or was never approved, is refused at call time |
| **Privilege escalation** | Unknown tools are denied until you write a rule |
| **Repeated abuse** | A trust score degrades and can quarantine the agent |

<div align="center">
<img src="https://raw.githubusercontent.com/Harshith029/Sentinel/main/assets/outbox-diff.png" alt="The same attack with and without SENTINEL: without it the SSN and API key reach the attacker; with it the email is never sent" width="820">
<br>
<sub><i>The same attack, run twice. Without SENTINEL the customer's SSN and API key reach
the attacker's inbox; with it, the email is never sent.</i></sub>
</div>

## Status and known limitations

Read this before deploying anything. Each limitation changes what SENTINEL
protects you from.

| Limitation | What it means for you |
|---|---|
| **Taint is per MCP session** | A client that opens a new session for every tool call (LangChain's `MultiServerMCPClient` does by default) gets **no** taint carried between calls. A long-lived session has the opposite problem: after its first untrusted result, every guarded action in it is denied until it reconnects |
| **Every tool result is untrusted by default** | A benign "look up the customer, then email them" is denied if the email tool has a taint rule, unless the lookup tool is marked `trusted_output` or its output is declassified |
| **Only guarded tools are guarded** | A tool without rules can carry tainted data out. Add rules for every outbound tool; there is no general notion of an outbound "sink" yet |
| **Quarantine is recorded, not enforced** (default) | The trust score never recovers, so agents making only allowed calls cross the threshold within tens of calls. `SENTINEL_ENFORCE_QUARANTINE=1` enforces it |
| **Downstream servers: streamable HTTP only** | No stdio servers, no per-server credentials or OAuth, one shared session per server, and no reconnect. Most published MCP servers are stdio |
| **State lives in one process** | Trust scores, MCP sessions, the event feed, the run index and API policy reloads are in memory. Two replicas share none of it |
| **Cosmos persistence is partial** | Needs `pip install "sentinel-prox[cosmos]"`; run ownership, the run index after a restart and retention purging exist only for SQLite |
| **Some state is visible across tenants** | `/events` ids are one global counter; `/downstream` and `/capabilities` describe the whole deployment |
| **Calls the SDK rejects are not recorded** | Arguments that fail a tool's input schema are refused by the MCP SDK before SENTINEL sees them |

Working and tested: provenance tracking, default-deny enforcement, catalogue
integrity, authentication (fail-closed), per-tenant isolation and policy,
operator separation (only `SENTINEL_ADMIN_TOKEN` administers), resource bounds,
forensic replay with redaction and retention, and the Docker image, which CI
builds and starts on every push. The optional Azure Bicep template has **never
been deployed**; CI only proves it compiles. Downstream reconnect within one
process is blocked by an unresolved transport defect.
[Full status.](https://harshith029.github.io/Sentinel/guide/limitations)

Outside the threat model: provenance is per message and tool result, not per
token inside the model's reasoning; SENTINEL stops the unauthorized *action*, not
the persuasion; and the proxy and policy store are trusted components.

## Writing policy

Rules are **deny-only**: a call is allowed when no deny rule matches.
`sentinel scaffold` emits every discovered tool explicitly denied, with its
description and a recommended starting rule, so you edit rather than invent.

```yaml
policy_version: 1
config:
  allowed_domains: ["corp.example"]
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

Predicates support `== != < >= in "not in"`, `and`/`or`/`not`, set literals, and
`true`/`false`. A variable on the right of a comparison is read from `config`
only, never from the call's arguments, so an agent cannot supply its own
allowlist. The [policy guide](https://harshith029.github.io/Sentinel/guide/policy)
covers derived fields, trusted output, declassification and per-tenant policy.

## Try the demo

A bundled demo runs the whole pipeline on a scripted attack with synthetic data.
It shows what a refusal looks like; it is **not** the product surface.

```bash
SENTINEL_ALLOW_ANONYMOUS=1 sentinel serve --dashboard   # then open http://localhost:8765
```

Anonymous mode is only for this local demo, whose tools are in-memory mocks.
Never use it in front of real tools. Without it (or a token) the dashboard loads
but every data route answers `503`. The demo can also run against a real or a
free local model; see [Try the demo](https://harshith029.github.io/Sentinel/guide/demo).

## Documentation

| Guide | What it covers |
|---|---|
| [What is SENTINEL?](https://harshith029.github.io/Sentinel/guide/introduction) | The problem, the approach, and the boundary |
| [Quick start](https://harshith029.github.io/Sentinel/guide/quick-start) | Install, configure, connect an agent |
| [How it works](https://harshith029.github.io/Sentinel/guide/how-it-works) | Provenance, policy, declassification, catalogue integrity, quarantine |
| [Writing policy](https://harshith029.github.io/Sentinel/guide/policy) | The policy language and patterns |
| [Configuration](https://harshith029.github.io/Sentinel/guide/configuration) | `sentinel.yaml`, environment variables, commands |
| [Authentication](https://harshith029.github.io/Sentinel/guide/authentication) | Agent tokens, tenants, the operator token, anonymous mode |
| [Logs and forensics](https://harshith029.github.io/Sentinel/guide/forensics) | Decision logs, replay, SIEM export, retention, backup |
| [Deployment](https://harshith029.github.io/Sentinel/guide/deployment) | Docker Compose, network topology, reverse proxies, Azure |
| [Resource limits](https://harshith029.github.io/Sentinel/guide/limits) | Every cap and what happens over it |
| [Free and paid backends](https://harshith029.github.io/Sentinel/guide/backends) | Running at zero cost, and the optional Azure upgrades |

Every setting is also documented in
[`.env.example`](https://github.com/Harshith029/Sentinel/blob/main/.env.example), and
the [examples](https://github.com/Harshith029/Sentinel/tree/main/examples) connect a
real MCP client and a live model.

## FAQ

**Does it need Azure or any paid service?** No. Enforcement, the local injection
detector, the rule-based classifier and the SQLite forensic store are free and
local. Azure Content Safety, Azure OpenAI and Cosmos DB are optional upgrades.

**Is it a prompt-injection filter?** Not mainly. Its Layer-1 detector only flags.
What refuses an attack is the authorization engine, which judges each action by
where its data came from, so an injection no filter catches is still refused.

**Does it log my data?** No tool arguments are ever logged, and arguments and
results are redacted before they reach the forensic store.

**Why is it called `sentinel-prox` on PyPI?** `sentinel` and the obvious variants
were taken. The import package and the command are both `sentinel`.

[More questions.](https://harshith029.github.io/Sentinel/faq)

## Contributing

Contributions are welcome. SENTINEL is a security proxy, so the bar for a change
is "does it preserve the guarantees" more than "does it work".
[CONTRIBUTING.md](https://github.com/Harshith029/Sentinel/blob/main/CONTRIBUTING.md)
lists the security invariants a change must preserve and how to run the checks:

```bash
python -m venv .venv
.venv/bin/python -m pip install -e ".[dev]" -c versions.lock   # Windows: .venv\Scripts\python.exe
.venv/bin/python -m pytest
.venv/bin/python -m ruff check src tests
.venv/bin/python -m mypy src      # strict
```

Please follow the
[code of conduct](https://github.com/Harshith029/Sentinel/blob/main/CODE_OF_CONDUCT.md).
To report a vulnerability, **do not open an issue**: follow the
[security policy](https://github.com/Harshith029/Sentinel/blob/main/SECURITY.md).

## License and credits

MIT. See [LICENSE](https://github.com/Harshith029/Sentinel/blob/main/LICENSE).

Built on the [Model Context Protocol](https://modelcontextprotocol.io) Python SDK,
FastAPI, Starlette, `sse-starlette`, Uvicorn, Pydantic, PyYAML, httpx, pytest, ruff,
mypy, gitleaks, and the Azure SDKs for Python. Thank you to their maintainers.

**AI tools used in development:** Claude Code (Anthropic) and GitHub Copilot.
SENTINEL also *integrates* Azure OpenAI (attack classification) and Azure AI Content
Safety / Prompt Shields (Layer-1 screening) as optional components.

Originally built for the Microsoft Build AI Hackathon 2026 — *Security in the Agentic
Future* — by Pali Krishna Harshith.
