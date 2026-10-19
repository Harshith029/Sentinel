<div align="center">

<img src="https://raw.githubusercontent.com/Harshith029/Sentinel/main/assets/logo.svg" alt="SENTINEL logo" width="88" />

# SENTINEL

### Stop prompt-injection attacks at the action layer, where the damage happens.

**Your content filter will miss an attack eventually. SENTINEL refuses the action anyway.**

[![PyPI](https://img.shields.io/pypi/v/sentinel-prox?style=flat-square&logo=pypi&logoColor=white&label=PyPI&color=0891B2)](https://pypi.org/project/sentinel-prox/)
[![Python](https://img.shields.io/pypi/pyversions/sentinel-prox?style=flat-square&logo=python&logoColor=white&label=Python&color=3B82F6)](https://pypi.org/project/sentinel-prox/)
[![CI](https://img.shields.io/github/actions/workflow/status/Harshith029/Sentinel/ci.yml?branch=main&style=flat-square&logo=githubactions&logoColor=white&label=CI)](https://github.com/Harshith029/Sentinel/actions/workflows/ci.yml)
[![Docs](https://img.shields.io/badge/docs-website-6366F1?style=flat-square&logo=vitepress&logoColor=white)](https://harshith029.github.io/Sentinel/)
[![MCP](https://img.shields.io/badge/MCP-security_proxy-0B1220?style=flat-square)](https://modelcontextprotocol.io)
[![MIT license](https://img.shields.io/badge/license-MIT-22D3EE?style=flat-square)](https://github.com/Harshith029/Sentinel/blob/main/LICENSE)

**[Website](https://harshith029.github.io/Sentinel/) · [Guides](https://harshith029.github.io/Sentinel/guide/introduction) · [Policy reference](https://harshith029.github.io/Sentinel/guide/policy)**

[Quick start](#quick-start) · [How it works](#how-sentinel-works) · [What it stops](#what-it-stops) · [See it in action](#see-it-in-action) · [Limitations](#status-and-known-limitations) · [FAQ](#faq) · [Documentation](#documentation)

<code>pip install "sentinel-prox>=0.2.2"</code>

</div>

> [!IMPORTANT]
> Get SENTINEL from [Harshith029/Sentinel](https://github.com/Harshith029/Sentinel), its
> [website](https://harshith029.github.io/Sentinel/), or the
> [`sentinel-prox` package on PyPI](https://pypi.org/project/sentinel-prox/), and install
> **0.2.2 or later**: the 0.1.x releases are insecure. SENTINEL is beta software, so read the
> [known limitations](#status-and-known-limitations) before you rely on it.

<div align="center">

<br />

<img src="https://raw.githubusercontent.com/Harshith029/Sentinel/main/assets/flow.svg" alt="An AI agent reaches its tools only through SENTINEL. Looking up a customer record is allowed; fetching a web page is allowed and its content is labelled untrusted; emailing the record afterwards is refused, because its lineage includes the page." width="1200" />

<br /><br />

</div>

---

AI agents now send email, query business systems and read the open web. That makes
**indirect prompt injection** an action problem: an attacker hides an instruction in a page
the agent reads, and *"summarize this pricing page"* quietly becomes *"email this customer's
SSN to the attacker."* Content filters judge the words, and no filter catches everything.

SENTINEL is a security proxy for the [Model Context Protocol](https://modelcontextprotocol.io)
(MCP). It sits between your agent and your MCP tool servers, labels where every message and
tool result came from, and refuses the actions you guard when their lineage includes untrusted
content, **however the injection was worded**.

Your agent needs **no code changes**: point its MCP endpoint at SENTINEL instead of at your
tool servers. Everything runs locally and needs no paid service.

> **[Visit the SENTINEL website](https://harshith029.github.io/Sentinel/)** for the quick
> start, the policy guide, and the full documentation.

## Quick start

### Install and declare your servers

Requires Python 3.11+ and MCP servers that speak the streamable HTTP transport.

```bash
pip install "sentinel-prox>=0.2.2"
sentinel init                    # writes sentinel.yaml; list your servers under `servers:`
```

### Check, scaffold a policy, and serve

```bash
export SENTINEL_API_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
sentinel check                   # connects and vets each catalogue; non-zero if serve would fail
sentinel scaffold > policy.yaml  # every discovered tool, denied, with a suggested rule
sentinel serve                   # agents connect to http://127.0.0.1:8765/mcp
```

SENTINEL is fail-closed: with no credential configured, every data route answers `503`
rather than serving openly.

### Point your agent at SENTINEL

Give your agent `http://127.0.0.1:8765/mcp` with `Authorization: Bearer $SENTINEL_API_TOKEN`.
To your agent, SENTINEL is an ordinary MCP server; a refused call comes back as a tool error
that starts with `SENTINEL blocked`. Then put your tool servers on a network that **only**
SENTINEL can reach, so nothing can go around it. The
[quick start guide](https://harshith029.github.io/Sentinel/guide/quick-start) has a complete
client example.

### Or watch it block an attack first

```bash
SENTINEL_ALLOW_ANONYMOUS=1 sentinel serve --dashboard   # then open http://localhost:8765
```

The bundled demo runs a scripted attack against in-memory mock tools with synthetic data.
Anonymous mode is only for this local demo; never use it in front of real tools.

## How SENTINEL works

<div align="center">
<img src="https://raw.githubusercontent.com/Harshith029/Sentinel/main/assets/architecture.png" alt="Architecture: the agent reaches its tools only through SENTINEL, which traces origins, authorizes, contains, and records" width="760" />
</div>

1. **Trace.** Everything the agent sees carries a trust label
   (`SYSTEM > USER > AGENT > RETRIEVED_CONTENT`). An action's provenance is the **set** of
   labels over its whole transitive ancestry, never just the most recent step. It is tainted
   if and only if `RETRIEVED_CONTENT` is in that set.
2. **Authorize.** Your policy compiles to a typed condition tree; there is no `eval`
   anywhere in the codebase. Rules are deny-only with deny-overrides, and **unknown tools are
   denied by default**.
3. **Contain.** A trust score drops on denied calls and other signals, and can quarantine the
   agent.
4. **Record.** Every decision becomes an immutable, replayable forensic span, exportable as
   JSONL for a SIEM. Tool arguments are redacted before storage and never logged.

Taint clears exactly one way: **declassification**, declared per tool, when the tool's output
validates against a strict, closed schema. A tool whose output no outsider can write to can
instead be marked `trusted_output: true`.
[Read more about how it works.](https://harshith029.github.io/Sentinel/guide/how-it-works)

## What it stops

| Attack | How SENTINEL stops it |
|---|---|
| **Indirect prompt injection** | Actions whose lineage includes untrusted content are denied, whatever the wording, so obfuscation does not help |
| **Data exfiltration** | A `send_email` built from a retrieved page is refused before it runs |
| **Tool poisoning** | Every agent-visible part of a tool definition is scanned at connect; a poisoned catalogue is refused |
| **Cross-server shadowing** | Two servers claiming one tool name fails closed |
| **Rug pulls** | The catalogue is fingerprinted at approval and re-checked; a tool that changed, or was never approved, is refused at call time |
| **Privilege escalation** | Unknown tools are denied until you write a rule |
| **Repeated abuse** | A trust score degrades and can quarantine the agent |

## See it in action

### A poisoned page tries to exfiltrate a customer record

<div align="center">
<img src="https://raw.githubusercontent.com/Harshith029/Sentinel/main/assets/dashboard.png" alt="The SENTINEL demo dashboard blocking an exfiltration attempt: the content filter missed the injection, but the action was refused because its lineage was tainted" width="900" />
</div>

The page tells the agent to email a customer record to an attacker. The Layer-1 content
filter **misses** the obfuscated instruction (the page is written to slip past the local
detector, so the miss is staged on purpose). The email is refused anyway, because its lineage
includes the page. All data is synthetic: the SSN is `000-00-0000` and the key is a
non-functional `sk-synthetic-DO-NOT-USE`.

### The same attack, with and without SENTINEL

<div align="center">
<img src="https://raw.githubusercontent.com/Harshith029/Sentinel/main/assets/outbox-diff.png" alt="The same attack with and without SENTINEL: without it the SSN and API key reach the attacker; with it the email is never sent" width="900" />
</div>

Without SENTINEL the customer's SSN and API key reach the attacker's inbox. With it, the
email is never sent, and the attempt is on record. [Run the demo yourself.](https://harshith029.github.io/Sentinel/guide/demo)

## Status and known limitations

Read this before deploying anything. Each limitation changes what SENTINEL protects you from.

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

**Working and tested:** provenance tracking, default-deny enforcement, catalogue integrity,
fail-closed authentication, per-tenant isolation and policy, operator separation (only
`SENTINEL_ADMIN_TOKEN` administers), resource bounds, forensic replay with redaction and
retention, and the Docker image, which CI builds and starts on every push. The optional
Azure Bicep template has **never been deployed**; CI only proves it compiles. Downstream
reconnect within one process is blocked by an unresolved transport defect.
[Full status.](https://harshith029.github.io/Sentinel/guide/limitations)

**Outside the threat model:** provenance is per message and tool result, not per token
inside the model's reasoning; SENTINEL stops the unauthorized *action*, not the persuasion;
and the proxy and policy store are trusted components.

## Writing policy

Rules are **deny-only**: a call is allowed when no deny rule matches. `sentinel scaffold`
writes every discovered tool explicitly denied, with its description and a recommended
starting rule, so you edit rather than invent.

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
`true`/`false`. A variable on the right of a comparison is read from `config` only, never
from the call's arguments, so an agent cannot supply its own allowlist. The
[policy guide](https://harshith029.github.io/Sentinel/guide/policy) covers derived fields,
trusted output, declassification and per-tenant policy.

## FAQ

<details>
<summary><strong>Does my agent need code changes?</strong></summary>

No. To your agent, SENTINEL is an ordinary MCP server. Point its MCP endpoint at SENTINEL
instead of at your tool servers, give it a bearer token, and make sure the tool servers are
reachable only from SENTINEL.

</details>

<details>
<summary><strong>Is SENTINEL a prompt-injection filter?</strong></summary>

Not mainly. It does screen text with a Layer-1 detector, but that detector only flags. What
refuses an attack is the authorization engine, which judges each action by where its data
came from. An injection that no filter catches is still refused if the action it causes has
untrusted lineage and your policy guards that tool.

</details>

<details>
<summary><strong>Which MCP servers can it protect?</strong></summary>

Servers that speak the streamable HTTP transport. Stdio servers, per-server credentials and
OAuth are not supported yet.

</details>

<details>
<summary><strong>Will it block my legitimate workflows?</strong></summary>

It can, by design: every tool result is untrusted by default. Mark tools whose output nobody
outside can influence as `trusted_output: true`, or declassify values that fit a strict
schema. See [writing policy](https://harshith029.github.io/Sentinel/guide/policy#trusted-output).

</details>

<details>
<summary><strong>Does it need Azure or any paid service?</strong></summary>

No. Enforcement, the local injection detector, the rule-based classifier and the SQLite
forensic store are all free and local. Azure Content Safety, Azure OpenAI and Cosmos DB are
optional upgrades, and `GET /capabilities` reports which backend each capability runs on.

</details>

<details>
<summary><strong>Does it log my data?</strong></summary>

No tool arguments are ever logged. Logs carry the decision, the tool name, the rule and a
trace id, and arguments and results are redacted before they reach the forensic store.

</details>

<details>
<summary><strong>Is it ready for production?</strong></summary>

It is beta. Enforcement, catalogue integrity and authentication are tested, but read the
[known limitations](#status-and-known-limitations) and decide for your own threat model.

</details>

<details>
<summary><strong>Why is it called <code>sentinel-prox</code> on PyPI?</strong></summary>

`sentinel` and the obvious variants were taken. The import package and the command are both
`sentinel`.

</details>

## Documentation

- [What is SENTINEL?](https://harshith029.github.io/Sentinel/guide/introduction): the problem, the approach, and the boundary
- [Quick start](https://harshith029.github.io/Sentinel/guide/quick-start): install, configure, connect an agent
- [How it works](https://harshith029.github.io/Sentinel/guide/how-it-works): provenance, policy, declassification, catalogue integrity, quarantine
- [Writing policy](https://harshith029.github.io/Sentinel/guide/policy): the policy language and patterns
- [Configuration](https://harshith029.github.io/Sentinel/guide/configuration): `sentinel.yaml`, environment variables, commands
- [Authentication](https://harshith029.github.io/Sentinel/guide/authentication): agent tokens, tenants, the operator token, anonymous mode
- [Logs and forensics](https://harshith029.github.io/Sentinel/guide/forensics): decision logs, replay, SIEM export, retention, backup
- [Deployment](https://harshith029.github.io/Sentinel/guide/deployment): Docker Compose, network topology, reverse proxies, Azure
- [Resource limits](https://harshith029.github.io/Sentinel/guide/limits): every cap and what happens over it
- [Free and paid backends](https://harshith029.github.io/Sentinel/guide/backends): running at zero cost, and the optional Azure upgrades
- [Examples](https://github.com/Harshith029/Sentinel/tree/main/examples): connect a real MCP client and a live model
- [`.env.example`](https://github.com/Harshith029/Sentinel/blob/main/.env.example): every setting, documented

## Disclaimer

SENTINEL is beta security software, provided under the MIT License without warranty. It
reduces the chance that a prompt-injection attack turns into a harmful action; it does not
make an agent safe on its own. Write rules for every tool that matters, test your policy
against your own tools, and keep other layers of defence in place. The bundled demo uses
synthetic data only.

## Contributing

Contributions are welcome. SENTINEL is a security proxy, so the bar for a change is "does it
preserve the guarantees" more than "does it work".
[CONTRIBUTING.md](https://github.com/Harshith029/Sentinel/blob/main/CONTRIBUTING.md) lists the
security invariants a change must preserve and how to run the checks:

```bash
python -m venv .venv
.venv/bin/python -m pip install -e ".[dev]" -c versions.lock   # Windows: .venv\Scripts\python.exe
.venv/bin/python -m pytest
.venv/bin/python -m ruff check src tests
.venv/bin/python -m mypy src      # strict
```

Please follow the
[code of conduct](https://github.com/Harshith029/Sentinel/blob/main/CODE_OF_CONDUCT.md). To
report a vulnerability, **do not open an issue**: follow the
[security policy](https://github.com/Harshith029/Sentinel/blob/main/SECURITY.md).

## License

MIT. See [LICENSE](https://github.com/Harshith029/Sentinel/blob/main/LICENSE).

Built on the [Model Context Protocol](https://modelcontextprotocol.io) Python SDK, FastAPI,
Starlette, `sse-starlette`, Uvicorn, Pydantic, PyYAML, httpx, pytest, ruff, mypy, gitleaks,
and the Azure SDKs for Python. Thank you to their maintainers.

**AI tools used in development:** Claude Code (Anthropic) and GitHub Copilot. SENTINEL also
*integrates* Azure OpenAI (attack classification) and Azure AI Content Safety / Prompt Shields
(Layer-1 screening) as optional components.

Originally built for the Microsoft Build AI Hackathon 2026 — *Security in the Agentic
Future* — by Pali Krishna Harshith.
