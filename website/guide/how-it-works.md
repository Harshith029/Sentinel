# How it works

<figure class="shot">
  <img src="/architecture.png" alt="Architecture: the agent reaches its tools only through SENTINEL, which traces origins, authorizes, contains, and records">
</figure>

To your agent, SENTINEL is an MCP server. To your tool servers, it is an MCP
client. Every tool call passes through it, and each one goes through four
stages:

1. **Trace**: label the origin of everything the agent has seen.
2. **Authorize**: the policy decides each call using that lineage.
3. **Contain**: a trust score, and quarantine.
4. **Record**: immutable spans, for replay and SOC export.

## 1. Trace: provenance labels

Everything the agent sees carries one of four trust labels, from most to least
trusted:

| Label | Meaning |
|---|---|
| `SYSTEM` | Trusted sources: output of tools the policy marks `trusted_output`, and values that passed declassification |
| `USER` | What the user asked for |
| `AGENT` | What the agent produced |
| `RETRIEVED_CONTENT` | Tool output: web pages, documents, records, anything that came from outside |

An action's provenance is a **set**: the union of the labels over its whole
transitive ancestry, never just the label of the most recent step. The proxy
keeps that union incrementally as the session runs, and a test checks it
against a full walk of the provenance graph on random sessions.

An action is **tainted** if and only if `RETRIEVED_CONTENT` is in that set.

::: info Every tool result is untrusted by default
All tool output is labelled `RETRIEVED_CONTENT` unless the policy marks the
tool `trusted_output: true`. Do that only for a tool whose output nobody
outside can write to, such as your own records service.
:::

## 2. Authorize: policy

Your policy is YAML that compiles to a **typed condition tree** and is
evaluated by walking that tree. There is no `eval` anywhere in the codebase.

- Rules are **deny-only**, with deny-overrides: a call is allowed when no deny
  rule matches.
- **Unknown tools are denied by default.** Connecting a server never grants
  permission to its tools.
- A predicate that cannot be evaluated denies.

```yaml
tools:
  send_email:
    rules:
      - id: block-untrusted-origin
        deny_if: "RETRIEVED_CONTENT in effective_provenance"
      - id: domain-allowlist
        deny_if: "recipient_domain not in allowed_domains"
```

See [Writing policy](./policy) for the full language.

## Declassification: the one way taint clears

Conservative tainting is intentional. The escape hatch is
**declassification**, declared per tool in policy:

```yaml
tools:
  read_price:
    declassify:
      schema: decimal_amount   # output crosses the boundary only if it validates
    rules: []
```

SENTINEL validates that tool's output against the named schema. On a match the
value starts fresh at `SYSTEM` trust with no inherited ancestry. On a mismatch
it stays exactly as tainted as it was.

- It is opt-in per tool. A tool with no `declassify` block can never clear
  taint.
- The schema registry is closed. Policy names a reviewed schema
  (`decimal_amount` or `iso_date`), or the policy fails to load.
- A cleared value cannot launder a tainted sibling, because recombining them
  re-taints.
- The check is syntactic, not semantic. A schema-valid `{"price": 999999}` is
  well-formed but still subject to argument rules such as an amount cap.

## Catalogue integrity

Provenance cannot catch an attack that arrives in a tool's *definition*,
because the agent reads it before anything is retrieved. So SENTINEL vets the
catalogue itself:

- **Tool poisoning.** Every agent-visible part of each tool definition is
  scanned for injection markers at connect. With `catalogue_strict: true` (the
  default) a poisoned catalogue is refused.
- **Cross-server shadowing.** Two servers claiming one tool name always fails
  closed.
- **Rug pulls.** The catalogue is fingerprinted at approval and re-checked on
  tool listing (at most every 5 seconds) and on a schedule
  (`SENTINEL_CATALOGUE_RECHECK_SECONDS`, default 300). A changed tool is
  refused at call time, and so is any tool missing from the approved
  catalogue.

Approval is trust on first use: what a server presents when SENTINEL connects
is what gets pinned. Review it with `sentinel check` before going live.
Re-approving a changed catalogue means restarting.

## 3. Contain: trust score and quarantine

Each agent starts with a trust score of 100. The score drops when a call is
denied, when a confident shield backend flags a tool result as an injection,
and when the agent makes an unusual sequence of tool calls. Below the
threshold (40 by default) the agent is quarantined.

By default the crossing is **recorded, not enforced**. The score never
recovers, so agents making only allowed calls cross the threshold within tens
of calls. Set `SENTINEL_ENFORCE_QUARANTINE=1` to enforce it. Enforcement
applies to every agent that shares a credential. Only the operator token can
clear a quarantine.

## 4. Record: forensic spans

Every decision becomes an immutable span in the forensic store (SQLite by
default). An identical re-emit is a no-op, and a differing one is rejected.
Runs can be replayed, and each run's audit trail is exportable as SIEM-ready
JSONL. Tool arguments and results are redacted before they are written. See
[Logs and forensics](./forensics).

## The Layer-1 shield only flags

SENTINEL also screens text with an injection detector: a local heuristic by
default, or Azure AI Content Safety Prompt Shields if you configure it. That
shield **only flags**, it never blocks. The authorization engine refuses a
tainted action whether or not anything flagged the text that tainted it, so a
simpler free detector does not weaken enforcement.
