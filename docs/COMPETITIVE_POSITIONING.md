# Competitive positioning: where Whence actually stands out

Market + literature research (July 2026). Companion to
[`SCOPING_arbitrary_mcp_servers.md`](./SCOPING_arbitrary_mcp_servers.md) — **this research
answers that scoping question**, see §5.

---

## 1. The market is crowded — and commoditized

"MCP gateway" is now a category with a dozen+ entrants: Pomerium, MCP Manager, Proofpoint
MCP Security, obot, MintMCP, TrueFoundry, systemprompt.io. Funding is heavy: **~$3.6B raised
across agentic-AI security**, with ~$392M announced around RSAC 2026 alone. Prompt-injection
attacks are reported up **340% YoY**.

What essentially *all* of them ship:

| Commodity feature | Who has it |
|---|---|
| OAuth 2.0 / identity-aware auth | everyone |
| Per-tool RBAC ("can agent X call tool Y") | everyone |
| Rate limiting | everyone |
| Audit logging | everyone |
| Content inspection / injection pattern matching | everyone |

**Strategic read:** competing as "another MCP gateway with auth + RBAC + logs" is a losing
race against funded incumbents. That is not our differentiation, and we should stop leading
with it.

## 2. The gap — stated by the literature, not by us

Recent peer-reviewed work identifies a specific missing capability:

> "Existing MCP specifications **lack dynamic taint tracking across server boundaries**. No
> mechanism currently prevents contaminated data from flowing between servers… effective
> defenses require implementing **cross-server information flow control** — a capability
> largely absent from production MCP deployments."
> — *MCPHunt*, arXiv 2604.27819

A separate survey concludes that gateway-based enforcement **combined with taint tracking**
is the effective architecture, and that orchestration-layer enforcement is "effective and
model-independent" (arXiv 2511.20920). *Unsafe by Flow* (arXiv 2605.07836) documents the
bidirectional data-flow risks that make this urgent.

**This is precisely Whence's architecture**: gateway-position enforcement + provenance/taint
+ model independence. The differentiator is not "we secure MCP" — it is **information flow
control**, which the category does not ship.

## 3. The closest peer: CaMeL (be honest about it)

**CaMeL** — *Defeating Prompt Injections by Design*, Google DeepMind + ETH Zürich
(arXiv 2503.18813) — is the strongest academic analog and validates the thesis:
capability/provenance metadata attached to values, data + control flow extracted from the
trusted query, policy enforced **before each tool call**. Result: **77% of AgentDojo tasks
solved with provable security**, vs 84% undefended.

| | CaMeL | Whence |
|---|---|---|
| Core idea | provenance/capabilities on values | provenance set over transitive lineage |
| Enforcement point | custom interpreter inside the agent | **network proxy at the MCP boundary** |
| Requires changing the agent? | **Yes** — dual-LLM (privileged/quarantined) + custom interpreter | **No** — zero agent-code modification |
| Works with an off-the-shelf agent? | No | Yes (any MCP speaker) |
| Measured on a benchmark? | **Yes (77% AgentDojo)** | **Not yet** ← our gap |

**Our defensible edge vs CaMeL: deployability.** CaMeL requires rearchitecting the agent into
a dual-LLM interpreter pattern — a research architecture, hard to retrofit onto an existing
product. Whence gets the same class of guarantee by *topology*, with an unmodified agent.
That is the commercially important difference, and it is real.

**Their edge over us: evidence.** They have a number. We have a demo. See §4.

## 4. The single highest-value next move: post an AgentDojo number

**AgentDojo** (the field's standard benchmark) — 97 user tasks, 629 security cases, ~949
(task, injection) pairs across banking/Slack/travel/workspace. Metrics: **benign utility**,
**utility under attack**, **attack success rate (ASR)**. Reference points: baseline GPT-4o
scores 69% benign utility, dropping to 45% under attack, with ASR up to 53.1% on the
canonical "Important message" attack; CaMeL reports 77% with provable security.

Running Whence against AgentDojo would convert the pitch from *"watch this demo block an
attack"* into *"ASR reduced from X% to Y% at Z% utility cost, on the benchmark everyone
publishes against."* That is the difference between an impressive prototype and a credible
security product — and it is directly comparable to a Google DeepMind result.

Feasibility is good: AgentDojo's architecture (agent + tools runtime + environment +
injection generator) maps onto our `DownstreamConnection` seam, and the LLM-driver work is
already done. The honest cost: it needs a real model, so it needs either a local model
(free — the `OPENAI_BASE_URL` path we just shipped) or budget.

## 5. This answers the scoping question

The pending decision was whether to build **arbitrary user-configured downstream MCP servers**.
The research resolves it:

- Single-server taint tracking is a **demo**.
- **Multi-server** taint propagation is the documented, unmet market need — the exact
  capability MCPHunt says "no mechanism currently prevents."
- Proxying arbitrary downstream servers is not just plumbing: it is **what turns Whence into
  the cross-server information-flow-control layer nobody ships.**

So the two workstreams are the same workstream. Recommendation: build it — and frame it as
cross-server IFC, not as "supporting more servers."

## 6. Positioning language (proposed)

- **Don't say:** "an MCP security gateway with policy and audit." (commodity; invites
  feature-comparison against funded incumbents)
- **Do say:** "**cross-server information flow control for AI agents** — we track where every
  byte came from and block actions whose lineage is untrusted, with no changes to your agent."

Supporting proof points, in order of strength:
1. Cross-server taint propagation (the documented category gap)
2. Zero agent modification (vs CaMeL's rearchitecture requirement)
3. Formal model — set-union provenance over transitive lineage; non-launderable sanitizer
4. Forensic replay + SIEM export (the audit trail the literature calls for)

## 7. Honest weaknesses (fix or disclose)

| Weakness | Response |
|---|---|
| **No benchmark number** | Biggest gap. Run AgentDojo (§4). |
| Message-level, not token-level provenance | Disclose; CaMeL shares this class of limitation |
| Conservative tainting costs utility | Same tradeoff CaMeL pays (77 vs 84); quantify it rather than hide it |
| Policy authoring friction for arbitrary tools | The open question in the scoping doc §3 |
| Category is crowded | Precisely why §6 positioning matters |

---

### Sources
- MCPHunt — Cross-Boundary Data Propagation in Multi-Server MCP Agents, arXiv 2604.27819
- Defeating Prompt Injections by Design (CaMeL), arXiv 2503.18813
- Securing the Model Context Protocol: Risks, Controls, Governance, arXiv 2511.20920
- Unsafe by Flow: Bidirectional Data-Flow Risks in the MCP Ecosystem, arXiv 2605.07836
- AgentDojo: A Dynamic Environment to Evaluate Prompt Injection Attacks and Defenses
- Market/funding: Pomerium, obot, MintMCP, TrueFoundry gateway comparisons; RSAC 2026 funding roundups
