---
layout: home
title: SENTINEL
titleTemplate: Stop prompt injection at the action layer

hero:
  name: SENTINEL
  text: Stop prompt injection at the action layer
  tagline: An MCP security proxy that tracks where every tool result came from, and refuses the actions you guard when their data came from untrusted content. Even when the attack got past your content filter.
  image:
    src: /logo.svg
    alt: SENTINEL
  actions:
    - theme: brand
      text: Get started
      link: /guide/quick-start
    - theme: alt
      text: What is SENTINEL?
      link: /guide/introduction
    - theme: alt
      text: View on GitHub
      link: https://github.com/Harshith029/Sentinel

features:
  - icon: <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="26" height="26" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M9 2v5M15 2v5"/><path d="M6 7h12v3a6 6 0 0 1-12 0z"/><path d="M12 16v6"/></svg>
    title: No agent code changes
    details: Point your agent's MCP endpoint at SENTINEL instead of your tool servers. Interception comes from the network topology, not from asking the agent to cooperate.
  - icon: <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="26" height="26" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="5" cy="12" r="2.5"/><circle cx="19" cy="5" r="2.5"/><circle cx="19" cy="19" r="2.5"/><path d="M7.3 10.9l9.4-4.8M7.3 13.1l9.4 4.8"/></svg>
    title: Judged by origin, not wording
    details: Every tool result is labelled with where it came from, and the labels are unioned over an action's whole ancestry. Rewording or obfuscating an injection does not change where its data came from.
  - icon: <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="26" height="26" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5"/><path d="M9.5 12.5l5 5M14.5 12.5l-5 5"/></svg>
    title: Deny-only policy, no eval
    details: Policy YAML compiles to a typed condition tree. Rules are deny-only with deny-overrides, and a tool with no rule is denied until you write one.
  - icon: <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="26" height="26" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6z"/><path d="M9 12l2 2 4-4"/></svg>
    title: Catalogue integrity
    details: Tool definitions are scanned for poisoning at connect, two servers claiming one tool name fail closed, and a tool that changes after approval is refused.
  - icon: <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="26" height="26" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v14c0 1.7 3.6 3 8 3s8-1.3 8-3V5"/><path d="M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/></svg>
    title: A record of every decision
    details: Each decision becomes an immutable span you can replay, or export as JSONL for a SIEM. Tool arguments are redacted before they are stored and never written to logs.
  - icon: <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="26" height="26" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 7.5h.01M7 16.5h.01"/></svg>
    title: Free to run
    details: Enforcement runs locally, with SQLite and a local detector. Azure Content Safety, Azure OpenAI and Cosmos DB are optional upgrades, not requirements.
---

<div class="home-section">

## Install

<p class="lede">Python 3.11 or later. The distribution is <code>sentinel-prox</code>; the command it installs is <code>sentinel</code>.</p>

```bash
pip install "sentinel-prox>=0.2.2"
```

</div>

<div class="home-section">

## Three steps to a guarded agent

<p class="lede">SENTINEL ships no tools of its own. It sits in front of the MCP servers you already run.</p>

<div class="steps">
<div class="step">
<h3>Declare your servers</h3>
<p><code>sentinel init</code> writes <code>sentinel.yaml</code>. List your MCP servers under <code>servers:</code>.</p>
</div>
<div class="step">
<h3>Scaffold a policy</h3>
<p><code>sentinel check</code> connects and vets each catalogue. <code>sentinel scaffold &gt; policy.yaml</code> writes every tool, denied, with a suggested rule to start from.</p>
</div>
<div class="step">
<h3>Serve and connect</h3>
<p><code>sentinel serve</code>, then point your agent at <code>http://127.0.0.1:8765/mcp</code> with its bearer token.</p>
</div>
</div>

</div>

<div class="home-section">

## See it refuse an attack

<p class="lede">A poisoned web page tells the agent to email a customer record to an attacker. The content filter misses the obfuscated instruction. The email is refused anyway, because its lineage includes the page.</p>

<figure class="shot">
  <img src="/dashboard.png" alt="The SENTINEL demo dashboard blocking an exfiltration attempt">
  <figcaption>The bundled demo, with synthetic data only. <a href="./guide/demo">Run it locally</a>.</figcaption>
</figure>

</div>

<div class="home-section">

## Honest about its limits

<div class="honest">

SENTINEL is beta software. Taint is tracked per MCP session, only the tools you write rules for are guarded, and downstream servers must speak streamable HTTP. Read [Status and limitations](./guide/limitations) before you rely on it.

</div>

</div>

<div class="home-end"></div>
