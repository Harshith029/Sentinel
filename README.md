# SENTINEL — a provenance-aware security proxy for agentic AI

> **Thesis.** An AI agent's risk lives in the **causal path from instruction-origin
> to action**, not in the text of either. SENTINEL secures the **action layer**
> (tool calls), authorizing each one against the **provenance** of everything it
> derived from — so an instruction that arrived inside retrieved web content can
> never drive a high-risk action, even when it slips past content filters.

**▶ Live demo: https://sentinel-i63x.onrender.com** — open it and the hero attack
auto-plays; watch the exfiltration get **blocked** in seconds. (Free tier, so the
first load after it's been idle may take ~50 s to wake — just refresh once.)

SENTINEL is an **MCP (Model Context Protocol) proxy**. To a protected agent it
presents as an MCP server; to the real tool servers it is an MCP client. Every
tool call physically traverses SENTINEL — **interception is guaranteed by network
topology, not by code wrapping**. It is agent-agnostic: it secures Microsoft
Foundry agents, Claude, GPT, or any custom MCP client identically, with **no
agent-code modification**.

```
 Agent (Foundry / Claude / GPT / custom)          ← only reachable MCP endpoint
        │  speaks MCP
        ▼
 ┌─────────────────────────────────────────────┐
 │                 SENTINEL                     │
 │  Provenance taint tracker  (set-union model) │   every tool call →
 │  Authorization engine      (typed AST)       │   ToolCallProposed → Authorize
 │  Trust scorer              (tier-2, Laplace) │   → Trust → forward / BLOCK
 │  Forensic span spine       (OTel + seq)      │   → ToolExecuted / ToolBlocked
 └───────────────────┬─────────────────────────┘
                     │  speaks MCP (only AFTER authorization)
                     ▼
   Isolated tool servers  (web_fetch · send_email · get_customer_record …)
   — network-isolated: reachable ONLY from SENTINEL, no external ingress —
```

## The differentiator (provenance, formal)

Provenance is a **SET of trust labels** (`SYSTEM > USER > AGENT > RETRIEVED_CONTENT`)
unioned over a span's transitive `derived_from` ancestry — not a single mutable
enum. `is_tainted(span) := RETRIEVED_CONTENT ∈ effective_provenance(span)`. A real
cycle-safe graph walk computes it; the authorization engine parses policy into a
**typed condition AST** (never `eval`) and blocks `send_email` when the lineage is
tainted. Taint clears only through an explicit, auditable **StructuredExtractor**
(schema validation → a fresh SYSTEM-trust value with no inherited ancestry) — and a
sanitized value cannot launder a tainted sibling.

## Run it

### 1 · Try the live demo (nothing to install)
Open **https://sentinel-i63x.onrender.com** — the hero attack auto-plays and you'll
see the exfiltration blocked within seconds. Click **reset** then **launch attack**
(or **--evasion**) to run it again yourself. Free tier, so the first load after it's
been idle may take ~50 s to wake; just refresh once.

### 2 · Run it locally
**Requires Python 3.11+ and git.**

```bash
git clone https://github.com/Harshith029/Sentinel.git
cd Sentinel
python -m venv .venv
```

Install (editable, with dev extras) and start the dashboard:

```powershell
# Windows (PowerShell)
.venv\Scripts\python.exe -m pip install -e ".[dev]"
.venv\Scripts\python.exe -m uvicorn sentinel.control.app:create_app --factory --host 127.0.0.1 --port 8765
```

```bash
# macOS / Linux   (or just: make dashboard)
.venv/bin/python -m pip install -e ".[dev]"
.venv/bin/python -m uvicorn sentinel.control.app:create_app --factory --host 127.0.0.1 --port 8765
```

Then open **http://localhost:8765** and click **launch attack** (or **--evasion** for
the variant that slips past the content filter).

### 3 · Run with Docker (no Python needed)
```bash
docker build -t sentinel -f deploy/Dockerfile .
docker run --rm -p 8765:8765 sentinel        # → http://localhost:8765
```

### 4 · The full product (adds the real `/mcp` wire endpoint)
`create_gateway_app` exposes a streamable-HTTP MCP server at `/mcp` so an external MCP
client can connect and be secured by the same pipeline — this is what the live demo
and `make serve` run:

```bash
.venv/bin/python -m uvicorn sentinel.control.app:create_gateway_app --factory --host 127.0.0.1 --port 8765
```

### 5 · Tests & checks
```bash
.venv/bin/python -m pytest                 # 277 tests       (make test)
.venv/bin/python -m ruff check src tests   # lint            (make lint)
.venv/bin/python -m mypy src               # mypy --strict   (make typecheck)
```
On Windows, replace `.venv/bin/python` with `.venv\Scripts\python.exe`. The `make`
targets are just Unix shortcuts for the commands above.

**The hero attack.** A user asks the agent to look up a customer record and research
a pricing page. The page is poisoned with a hidden instruction to email the record
to `attacker@evil-corp.io`. The record is retrieved (RETRIEVED_CONTENT); the page is
fetched (RETRIEVED_CONTENT); the induced `send_email` is **blocked** by
`block-untrusted-origin` because its lineage is tainted — the synthetic SSN/api_key
**never reach the outbox**. An *evasion* variant slips past the Layer-1 shield and is
still caught by Authorization (the thesis: the architecture saves the day, not the
filter).

## Put SENTINEL in front of your own agent (MCP over HTTP)

SENTINEL is not just a scripted demo — it speaks MCP over a real network
transport. `make serve` exposes the proxy as a **streamable-HTTP MCP server at
`/mcp`**. Point any MCP client at it (Claude Desktop, an Azure AI Foundry agent,
or the upstream `mcp` SDK) and every tool call the agent makes is run through the
full pipeline; the client needs **no SENTINEL-specific code** — interception is by
topology, not integration.

```bash
make serve                              # control plane + dashboard + /mcp wire endpoint
python examples/connect_over_http.py    # a real MCP client drives the hero attack → BLOCKED
```

Each MCP session is its own trace (own provenance frontier, own per-agent trust);
the live run appears on the dashboard as a `live-mcp` trace. This is proven
end-to-end over a real socket in `tests/test_phase9_mcp_gateway.py` — a real
`mcp` client connects, runs the kill chain, and the exfiltration is refused at the
MCP boundary. By default the downstream tool servers are in-process mocks; set
`SENTINEL_TOOLS_{WEB,EMAIL,RECORDS}_URL` and the gateway instead connects to
**remote tool servers over MCP-over-HTTP** (the real deploy topology) — proven
end-to-end in `tests/test_phase9_mcp_gateway.py`, where the proxy routes to three
HTTP-served tool servers and still blocks the exfiltration.)

**A real LLM in the loop.** The agent doesn't have to be a script. `LLMAgentDriver`
runs a genuine tool-use loop where the *model* decides what to do; SENTINEL is the
backstop. Point it at the `/mcp` endpoint with a real model — or the offline
susceptible stand-in if you have no key:

```bash
OPENAI_API_KEY=sk-... python examples/run_live_agent.py     # a real model, tricked → BLOCKED
python examples/run_live_agent.py --offline                 # no key: faithful stand-in model
```

The model fetches a poisoned page, is induced to email the record to an attacker,
and the call is blocked over the wire — the agent then sees the block and stands
down. The loop (and the OpenAI/Azure adapter's parsing) are covered in
`tests/test_phase10_llm_agent.py`, including the evasion variant where Layer-1 misses
and authorization-by-provenance still catches it.

## Threat model — what SENTINEL does NOT protect against (a strength)

- Provenance is tracked at **message / tool-result** granularity, **not** token-level
  inside opaque model reasoning. Taint spreads conservatively unless a sanitizer clears it.
- SENTINEL secures the **action layer**, not the model's cognition. It does not stop a
  model being *persuaded*; it stops the resulting unauthorized **action**.
- The proxy itself and the policy store are **trusted** components.
- **Trace affinity:** one trace → one proxy instance; horizontal scaling is *across*
  traces, which is why a per-trace monotonic `seq` suffices (vector clocks out of scope).

## Framing

- **Conservative tainting is intentional.** We optimize to never let an untrusted
  instruction reach a high-risk action, accepting that some benign workflows need
  explicit sanitization. Taint saturation is the correct bias for action-layer security.
- **Sanitization is syntactic, not semantic.** A schema-valid `{price: 999999}` is still
  caught by the argument-level `amount >= cap` rule. The sanitizer and the policy engine
  catch *different* classes of problem and compose — a strength, not a gap.
- **MCP is the substrate, not the limit.** Because interception is at the MCP message
  boundary, SENTINEL drops in front of *any* MCP-speaking agent or tool ecosystem with
  no code changes; the proxy is infrastructure, not a sandbox.

## Deployment (Azure Container Apps)

Insertion point: register SENTINEL as the agent's MCP tool server (`MCPTool`,
`server_url=SENTINEL_MCP_URL`, `require_approval="never"`, tools enumerated
explicitly) — **the agent's only reachable MCP endpoint**. The mock tool servers
deploy with **internal ingress only** (no external endpoint); only SENTINEL reaches
them, so topology enforces the thesis. KEDA HTTP-concurrency scaler on the proxy;
system-assigned managed identity + Key Vault RBAC; Cosmos partitioned by `trace_id`
(idempotent upserts, default SDK retry). See [`deploy/`](./deploy) and
[`deploy/DEPLOY.md`](./deploy/DEPLOY.md).

**DEMO MODE vs AZURE MODE.** The security pipeline is **live and identical** in both
modes; only integrations degrade without Azure. The dashboard's *Deployment mode*
panel names the delta: Layer-1 Prompt Shields, the semantic attack classifier
(Azure OpenAI), distributed Cosmos persistence, App Insights observability, the live
Foundry driver, and Key-Vault secret resolution all light up in AZURE MODE. Flipping
the mode shows the delta — the "Azure is load-bearing" proof. Only the agent **driver**
differs between modes.

## Dependencies

Python 3.11+, Pydantic v2. Exact pins are recorded in
[`versions.lock`](./versions.lock); confirmed SDK facts in
[`SDK_VERIFICATION.md`](./SDK_VERIFICATION.md). Key runtime deps:
`mcp==1.27.1`, `azure-ai-projects==2.0.0`, `openai==2.38.0`, `azure-identity`,
`azure-cosmos`, `azure-monitor-opentelemetry`, `fastapi==0.136.3`,
`sse-starlette==3.4.4`, `uvicorn`, `pydantic==2.13.4`, `PyYAML`. Dev:
`pytest`, `ruff`, `mypy`, `httpx`, `pre-commit` (with a `gitleaks` hook).

## Data handling

**All data is synthetic.** The "customer record" is a clearly-labelled fake
(`Jordan Rivera (SYNTHETIC TEST RECORD)`, SSN `000-00-0000`, a non-functional
`sk-synthetic-DO-NOT-USE` key). `send_email` writes to an in-memory **outbox sink** —
nothing is ever sent. Forensic spans are stored in-memory (LRU-bounded) by default;
in AZURE MODE in Cosmos with identity-only auth (no keys in code). No real PII is
processed or persisted. Secrets in dev live in a gitignored `.env`; a `gitleaks`
pre-commit hook blocks accidental commits.

## AI-tools disclosure

- **Claude Code** (Anthropic) — used to author this implementation phase by phase.
- **GitHub Copilot** — inline assistance.
- **Azure OpenAI** — the semantic attack classifier (labels blocked attempts for the SOC panel; AZURE MODE).
- **Azure AI Content Safety · Prompt Shields** — the Layer-1 injection shield (AZURE MODE).

## Open-source credits

Model Context Protocol Python SDK (`mcp`), FastAPI, Starlette, `sse-starlette`,
Uvicorn, Pydantic, OpenTelemetry, PyYAML, httpx, pytest, ruff, mypy, gitleaks, and
the Azure SDKs for Python. Thank you to their maintainers.

## Team & roles

| Member | Role |
|---|---|
| Pali Krishna Harshith (solo) | Architecture, provenance/authorization core, proxy & control plane, dashboard & UX, deployment |
