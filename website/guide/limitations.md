# Status and limitations

SENTINEL is beta software. Read this page before deploying it: each
limitation below changes what SENTINEL protects you from.

## Status

| Area | State |
|---|---|
| PyPI distribution | `sentinel-prox` 0.2.2 and later carry the fixes in the [changelog](https://github.com/Harshith029/Sentinel/blob/main/CHANGELOG.md). 0.1.x is insecure; do not install it |
| Provenance tracking and default-deny enforcement | Working, tested |
| Forensic spans, replay, audit trail | Working. Payloads are redacted before persistence, each run's tenant is recorded, and traces expire after the retention window. Not encrypted at rest by SENTINEL |
| Catalogue integrity (poisoning, shadowing, rug pulls) | Working, tested. Findings appear in `GET /downstream` and the logs. Re-approving a changed catalogue means restarting |
| Authentication | Every endpoint gated; fails closed when unconfigured |
| Multi-tenant isolation | Per-tenant credentials, with runs, events, streams and MCP sessions scoped to the credential's tenant, and per-tenant policy |
| Operator separation | Only `SENTINEL_ADMIN_TOKEN` can change policy or clear a quarantine |
| Resource bounds | Body size, request rate, runs, subscribers, event pages and result size are all capped. Counters are per process |
| Self-hosting (Docker, `deploy/compose.yaml`) | Verified locally. CI builds and starts the image on every push |
| Azure deployment (Bicep) | Optional, and **never deployed**. CI only proves the template compiles |
| Downstream reconnect within one process | **Blocked** by an unresolved transport defect |

## Known limitations

These are open, verified, and not yet fixed.

### Taint is per MCP session

Lineage covers the calls made in one MCP session. A client that opens a new
session for every tool call (LangChain's `MultiServerMCPClient` does by
default) gets **no** taint carried from one call to the next, so a page read
in one call does not taint an email sent in the next.

A long-lived session has the opposite problem: after its first untrusted
result, every guarded action in it is denied until it reconnects.

### Every tool result is untrusted by default

All tool output is labelled retrieved content unless the policy marks the tool
`trusted_output: true`. Do that only for a tool whose output nobody outside
can write to. Otherwise a benign flow such as "look up the customer, then
email them" is denied if the email tool has a taint rule. Per-tool
declassification also clears taint for values that validate against a strict
schema.

### Only guarded tools are guarded

A tool without policy rules can carry tainted data out. The bundled policy
treats `web_fetch` as an outbound capability and constrains its host through
`allowed_fetch_hosts`; add equivalent rules for every outbound tool you
introduce. Rules are deny-only, and there is no general notion of an outbound
"sink" yet.

### Quarantine is recorded, not enforced (by default)

The trust score never recovers, so agents making only allowed calls cross the
threshold within tens of calls. By default that crossing is logged, not acted
on. `SENTINEL_ENFORCE_QUARANTINE=1` enforces it, for every agent that shares a
credential.

### Downstream servers: streamable HTTP only

No stdio servers, no per-server credentials or OAuth, one shared session per
server, and no reconnect. Most published MCP servers are stdio.

### State lives in one process

Trust scores, MCP sessions, the event feed and the run index are in memory,
and two replicas share none of it. A policy replaced through
`POST /tenants/{tenant}/policy` survives a restart (it is saved under
`SENTINEL_DATA_DIR`), but only on the replica that received it.

### Cosmos persistence is partial

It needs `pip install "sentinel-prox[cosmos]"`. Spans are stored and
replayable, but run ownership, the run index after a restart, and retention
purging exist only for the default SQLite store.

### Some state is visible across tenants

Event ids on `/events` are one global counter, so a tenant can infer how busy
the deployment is. `/downstream` and `/capabilities` describe the whole
deployment to any authenticated caller.

### Calls the SDK rejects are not recorded

Arguments that fail a tool's input schema are refused by the MCP SDK before
SENTINEL sees the call, so they leave no forensic record.

## Outside the threat model

- Provenance is tracked per message and tool result, not per token inside the
  model's reasoning.
- SENTINEL secures the action layer, not the model's cognition: it stops the
  unauthorized action, not the persuasion.
- The proxy and the policy store are trusted components.
- One trace is handled by one proxy instance; horizontal scaling is across
  traces.

Reports outside this boundary are welcome as discussion, but they are not
vulnerabilities in the implementation. See the
[security policy](https://github.com/Harshith029/Sentinel/blob/main/SECURITY.md).
