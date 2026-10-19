# What is SENTINEL?

SENTINEL is a security proxy for AI agents that use the
[Model Context Protocol](https://modelcontextprotocol.io) (MCP). It sits between
your agent and your MCP tool servers. It tracks which tool results each action
could have been influenced by, and it refuses the actions you guard when that
lineage includes untrusted content.

It is open source (MIT), written in Python, and published on PyPI as
[`sentinel-prox`](https://pypi.org/project/sentinel-prox/).

## The problem

AI agents now send email, query business systems and read the open web. That
turns **indirect prompt injection** into an action problem, not a text problem.
An attacker hides an instruction inside content the agent will read, and the
instruction runs with the agent's full privileges. *"Summarize this pricing
page"* quietly becomes *"email this customer's SSN to the attacker."*

Content filters scan the words, and no filter catches everything. Microsoft's
own Prompt Shields documentation recommends additional validation layers. The
gap is that security is applied to the words, while the damage is done by the
actions.

## The approach

SENTINEL judges an action by **where its data came from**, not by how the
request was phrased.

Every message and tool result carries a provenance label. An action's
provenance is the set of labels across its whole ancestry, so an email built
after reading a web page carries that page's label even if the page's text was
never flagged. Your policy then decides, per tool, what lineage is acceptable.
A `send_email` whose lineage includes retrieved content can be refused before
it runs.

<figure class="shot">
  <img src="/outbox-diff.png" alt="The same attack with and without SENTINEL: without it the SSN and API key reach the attacker; with it the email is never sent">
  <figcaption>The same attack, run twice. Without SENTINEL the customer's SSN and API key reach the attacker's inbox. With it, the email is never sent.</figcaption>
</figure>

## What it protects against

| Attack | How SENTINEL stops it |
|---|---|
| **Indirect prompt injection** | Actions whose lineage includes untrusted content are denied, whatever the wording, so obfuscation does not help |
| **Data exfiltration** | A `send_email` built from a retrieved page is refused before it runs |
| **Tool poisoning** | Every agent-visible part of a tool definition (description, title, annotations, input and output schemas, metadata) is scanned at connect, and a poisoned catalogue is refused |
| **Cross-server shadowing** | Two servers claiming one tool name fails closed. SENTINEL does not guess which is authoritative |
| **Rug pulls** | The catalogue is fingerprinted at approval and re-checked. A tool that changes after approval is refused at call time, and so is any tool that was not in the approved catalogue |
| **Privilege escalation** | Unknown tools are denied by default until you write a rule |
| **Repeated abuse** | A trust score drops on blocked calls and can quarantine the agent |

Every decision becomes an immutable, replayable forensic record that you can
export as JSONL for a SIEM.

## What it does not protect against

Stating the boundary precisely matters for a security tool.

- Provenance is tracked per **message and tool result**, not per token inside
  the model's reasoning. Taint spreads conservatively unless a declassifier
  clears it.
- It secures the **action layer**, not the model's cognition. It does not stop
  a model from being *persuaded*. It stops the unauthorized **action** that
  follows.
- The proxy and the policy store are **trusted** components.
- Only tools you write rules for are guarded, and lineage is tracked per MCP
  session. See [Status and limitations](./limitations) for what that means in
  practice.

## Next steps

- [Quick start](./quick-start): install SENTINEL and put it in front of your
  servers.
- [How it works](./how-it-works): provenance, policy and declassification in
  detail.
- [Try the demo](./demo): watch it refuse a scripted attack on your own
  machine.
