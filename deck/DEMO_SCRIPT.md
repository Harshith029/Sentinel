# SENTINEL — 3-minute demo run-of-show + talking points

Companion to `SENTINEL_pitch.pptx`. Everything below is grounded in a run verified
live over the real control plane (not a mock): the 16-span hero-evasion kill chain,
trust 100→70, and the before/after exfiltration contrast.

---

## Before you start (1 min, off-camera)
```bash
make dashboard          # or: make serve  (adds the real /mcp wire endpoint)
# open http://localhost:8765  → wait for "DEMO MODE / live"
```
Have a terminal ready as a fallback in case the browser misbehaves:
```bash
curl -s -XPOST http://127.0.0.1:8765/attack/hero-evasion
```
> The pipeline is identical whether driven from the dashboard button or curl — only
> the agent driver differs. Say that out loud if you fall back to the terminal.

---

## The 3-minute script

### 0:00 — The hook (15s)  · slide 2/3
> "Prompt injection doesn't live in the text — it lives in what the agent *does* with
> it. Microsoft's own Prompt Shields docs say they 'may not catch all attack vectors'
> and to add another validation layer. **SENTINEL is that layer** — it secures the
> action, authorized by where the instruction came from."

### 0:15 — One sentence of architecture (20s)  · slide 4
> "SENTINEL is an MCP proxy. The agent's *only* reachable tool endpoint is SENTINEL;
> the real tools are network-isolated behind it. So interception isn't a convention a
> caller can forget — it's the network topology. Every tool call physically traverses
> the provenance → authorization → trust → forensics pipeline."

### 0:35 — Launch the attack (10s)  · live dashboard
Click **Launch attack** (hero-evasion). Narrate while the kill chain renders (~1–3s):
> "The user asked the agent to look up customer 42 and research a pricing page."

### 0:45 — The record is retrieved (15s)
Point at the first two steps lighting up.
> "Step one pulls the synthetic customer record — SSN, API key. Allowed; it's
> user-initiated. Watch the **origin badge**: it's `{USER, AGENT}` right now."

### 1:00 — The poison lands + the shield MISSES (25s)  · the money beat
> "Step two fetches the page — and the page hides an instruction to email that record
> to an attacker. Here's the obfuscated text" (point at the surfaced poisoned snippet).
> "The Layer-1 shield scans it and **misses** — `attack_detected = false`. The address
> is written `attacker (at) evil-corp (dot) io` to dodge the filter. This is exactly the
> case Microsoft warns about. The badge now reads `{USER, AGENT, RETRIEVED_CONTENT}` —
> the set *acquired* taint; it didn't flip."

### 1:25 — The block (25s)  · the payoff
> "Now the agent is induced to send the email. The payload genuinely contains the SSN
> and API key. But its lineage is tainted — so authorization **denies** it on
> `block-untrusted-origin`. The shield failed; the architecture saved the day. That's
> the whole thesis in one frame."
Point at: red **BLOCKED** banner · matched rule · the secret chips in the payload ·
**NEVER PERSISTED** on the outbox · trust cratering **100 → 70** with the arithmetic.

### 1:50 — Before/after (20s)
Click the **baseline / "without SENTINEL"** view.
> "Same attack, no proxy: the SSN and API key are delivered to the attacker's inbox.
> With SENTINEL the outbox is empty. Same agent, same tools — the only difference is
> whether SENTINEL is in the path."

### 2:10 — Depth on tap (30s)  · slides 5–8
Pick **one** to show, don't rush all:
- **Provenance** is a *set* over the transitive `derived_from` lineage; `is_tainted`
  is just set membership — a real cycle-safe graph walk, no cached flag.
- **Authorization** parses policy into a typed AST and tree-walks it — **never `eval`** —
  deny-overrides, default-deny, fail-closed.
- **SOC export**: every block is classified (`exfiltration / high`) and exportable as
  SIEM-ready JSONL.
- **DEMO vs AZURE** panel: the security pipeline is identical; Azure lights up Prompt
  Shields, the Azure OpenAI classifier, Cosmos, App Insights, the Foundry driver.

### 2:40 — Close (20s)  · slide 10
> "277 tests, `mypy --strict`, zero `eval`. Drop it in front of any MCP agent —
> Foundry, Claude, GPT, custom — with no agent-code modification. Security on the
> causal path, not on the words."

---

## Q&A backstops

- **"Isn't conservative tainting too aggressive?"** Intentional. We optimize to never
  let an untrusted instruction reach a high-risk action; benign flows clear taint
  through an explicit, auditable sanitizer. Taint saturation is the correct bias for
  action-layer security.
- **"What does Trust catch that Authorization doesn't?"** Novel tool-call patterns no
  policy pre-specified — Trust escalates to containment (quarantine) while you write
  the rule. It's anomaly telemetry, not primary prevention. Authorization is the thesis.
- **"What about non-MCP tools?"** Provenance-aware authorization is transport-agnostic;
  MCP is the enforcement target today because it's the emerging standard. The same
  proxy pattern extends to REST/OpenAPI tool calls.
- **"Is the sanitizer just AI cleaning the text?"** No — it's strict schema validation
  across a trust boundary. A schema-valid `{price: 999999}` is structurally trustworthy
  but **still** subject to the argument-level `amount >= cap` rule. The sanitizer and the
  policy engine catch different problems and compose.
- **"Why no vector clocks / how does it scale?"** One trace → one proxy instance (trace
  affinity); horizontal scaling is *across* traces, so a per-trace monotonic `seq`
  suffices. KEDA HTTP-concurrency scaler on the proxy; Cosmos partitioned by `trace_id`.

## What we deliberately do NOT claim (state it — it's a strength)
- Provenance is message/tool-result granularity, **not** token-level inside model cognition.
- SENTINEL secures the **action layer**, not the model's reasoning — it won't stop a model
  being *persuaded*, only the resulting unauthorized **action**.
- The proxy and the policy store are trusted components.
