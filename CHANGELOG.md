# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning is
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed (breaking)
- Catalogue fingerprints cover the whole tool definition: title, annotations,
  output schema, icons and metadata as well as the description and input
  schema. Existing `catalogue_approvals` entries no longer match. Re-run
  `sentinel check` and approve the new fingerprints.
- `POST /runs/custom` and `/runs/custom/baseline` reject `allowed_domains`,
  and any other unknown field, with `422`. A run is authorized by the tenant's
  policy only. `examples/run_custom_attack.py` lost `--allowed-domains`.
- The bundled policy (version 4) denies `web_fetch` to hosts outside its
  `allowed_fetch_hosts`. SENTINEL derives `url_host` from the `url` argument.
- A variable on the right of a comparison (`allowed_domains`, `max_amount`) is
  read from the policy's `config` only, never from the call's arguments. A
  rule whose comparand is not declared denies, and a warning names it when the
  policy loads. `in` with a string on the right is an error (deny), not a
  substring match.
- Python API: `SentinelProxy(authorization_config=...)` and
  `run_demo_session(authorization_config=...)` are gone, and `ToolCall.config`
  is ignored. The engine takes configuration from the policy it compiled.
- A tenant at its MCP session limit is refused at `initialize`, with a
  JSON-RPC error. It used to be refused at its first tool call.
- `GET /events?since=` and the SSE stream answer `409`, with the range still
  available, for a cursor that has expired from the buffer or comes from
  another process; a follower already streaming gets a `resync-required`
  event. A malformed `Last-Event-ID` is a `422`; it used to be ignored.
- Open MCP sessions use the tenant's current policy on every call, so a policy
  reload applies to them at once.

### Added
- `SENTINEL_DOWNSTREAM_TIMEOUT_SECONDS` (default 30, also
  `downstream_timeout_seconds` in `sentinel.yaml`): a deadline for each
  downstream operation. Before, a downstream server that accepted a connection
  and never answered held startup, discovery or a tool call forever.
- `SENTINEL_MCP_ALLOWED_HOST` for the demo tool servers, so they keep MCP's
  Host-header check when deployed behind an internal hostname.

### Security
- An agent could pass the allowlist that judged it: with no `config` block
  declaring `allowed_domains`, a call's own `allowed_domains` argument decided
  the rule.
- A policy with a duplicate YAML key is rejected. PyYAML kept the last value,
  so a second entry for a tool silently replaced its rules. `sentinel scaffold`
  also flattens U+0085 (NEL), which ends a YAML comment: a downstream tool
  description containing it could add entries to the generated policy.
- `web_fetch` connects to the address it validated (the original host stays
  the `Host` header and TLS SNI name), which closes the DNS-rebinding window
  between check and connect. It also blocks 100.64.0.0/10 and refuses URLs
  with user info.
- The downstream MCP client refuses a cross-origin redirect. A 307 or 308
  would have replayed a tool call's JSON-RPC body to another host.
- A request with more than one `Authorization` header is refused. Different
  parts of the gateway read different copies, so one request could
  authenticate as one tenant and run as another.
- A non-ASCII bearer token fails authentication instead of raising a 500.
- A `SENTINEL_API_TOKENS` table with a repeated tenant, a token shared by two
  tenants, or a non-string value is rejected whole. It does not fall back to
  `SENTINEL_API_TOKEN`, which would otherwise also act as the operator.
- MCP sessions count against their tenant's limit from `initialize`. Sessions
  that had not yet made a tool call were not counted, and the limit was
  global, so one tenant could take every slot.
- A regex in the local injection scanner took quadratic time on crafted text.
  It is replaced by a bounded search. Local-scanner flags no longer lower an
  agent's trust score, because the heuristic also flags ordinary text.
- Forensic spans store each argument name as a keyed fingerprint. A caller
  could put data, or a fake log line, in the name.
- Control characters in logged identifiers are escaped, so a tool name cannot
  forge extra log lines.
- The dashboard's audit view renders the export as text, not HTML.
- Trace and span ids come from `secrets`.
- A downstream tool that raises is recorded like any other result and its
  output is withheld. The call used to skip its execution record, and the
  exception text could reach the agent.
- Trust is kept per (tenant, agent). Keyed by agent id alone, a tenant that
  used another tenant's agent id could read that agent's trust score and push
  it down (with quarantine enforced, quarantine it), and an operator reset of
  one tenant's agent reset every tenant's agent with that id.
  `/agents/{id}/trust` and `/reset` act in the caller's tenant; the operator
  names one with `?tenant=`.

### Fixed
- `/capabilities` reported "Azure Monitor · Application Insights" as active
  whenever `APPLICATIONINSIGHTS_CONNECTION_STRING` was set, but nothing ever
  initialized an exporter. Observability is reported as what it is, structured
  local logs, and a connection string that is set is reported as unused. The
  never-called tracer setup was removed; trace and span ids are still minted
  in OpenTelemetry format.
- After a restart, run history was rebuilt longest-trace-first rather than
  most-recent-first: the store ordered traces by their span count. It now
  orders them by each trace's newest span.
- Ordinary tool descriptions stopped SENTINEL from starting. The catalogue
  scan is a heuristic, and flagged three of four plain descriptions in testing
  (for example "Send an email to a recipient, e.g. user@example.com."); strict
  mode, the default, then refused the whole catalogue, and the only way past
  was turning strict mode off for every tool. Approve a reviewed tool instead:
  `catalogue_approvals` maps a tool to the fingerprint of its exact definition,
  which `sentinel check` prints. A changed definition is flagged again.
- Provenance cost grew with the square of a session's length: every call
  re-walked a graph in which each call derived from every earlier result.
  Measured per call: 1.5 ms at call 100, 13 ms at 400, 40 ms at 800, on the
  event loop every session shares. Provenance is now kept as a running union of
  labels, which gives the same answers (checked against the walk) at a flat
  ~0.1 ms per call through 1,600 calls.
- Shutdown closed the run manager, which checkpoints SQLite and drains pending
  writes, only when the MCP gateway was enabled. It now always does.
- Run history is restored from SQLite once at startup and respects
  `SENTINEL_MAX_RETAINED_RUNS`. Every `GET /runs` used to re-add every evicted
  run.
- `/capabilities` reported Azure Key Vault as in use whenever
  `AZURE_KEY_VAULT_URI` was set. Nothing reads it.
- `deploy/compose.yaml` left `SENTINEL_MCP_SERVERS` and `SENTINEL_POLICY_FILE`
  set but empty when not supplied, which masked `sentinel.yaml` and selected
  the bundled demo servers and policy. They are now omitted.
- `deploy/main.bicep` scales the proxy to one replica, not ten: sessions, the
  event bus and the run index live in process memory.

## [0.2.1] — 2026-10-04

### Security
- The demo surface is off unless `SENTINEL_DASHBOARD=1` (or `sentinel serve
  --dashboard`, or `dashboard: true`): the dashboard and its assets, the
  scenario-run, custom-run, attack and baseline endpoints, the browser session
  cookie, and the API docs. Off, they answer 404. Before, they were served by
  every deployment, and the dashboard plus an OpenAPI document listing every
  route needed no credential at all.

## [0.2.0] — 2026-10-04

**Upgrade from 0.1.1.** It predates every change below, including the security
fixes: on 0.1.1, `/mcp` is open when no token is set, request arguments can
override operator policy configuration, and forensic payloads are stored
unredacted.

Read the README's *Known limitations* before relying on 0.2.0: taint is
tracked per MCP session, every tool result is treated as untrusted, only
tools with rules are guarded, and downstream servers must be unauthenticated
streamable-HTTP endpoints.

### Security
- Authentication is fail-closed: no credential and no explicit
  `SENTINEL_ALLOW_ANONYMOUS=1` means 503, on `/mcp` and every data route.
- Per-tenant credentials, an operator-only admin token, and tenant isolation of
  runs, events, MCP sessions and restored history.
- An MCP session is bound to the principal that opened it.
- Argument, recipient, lineage and declassification bypasses closed (see the
  review findings in the git log: F6, F7, F8, F14, F16).
- Payloads are redacted before they are stored or logged.
- Seven dependencies with known vulnerabilities upgraded.

### Changed
- Quarantine is recorded, not enforced, unless `SENTINEL_ENFORCE_QUARANTINE=1`.
- `sentinel check` runs `serve`'s own startup checks.
- The approved tool catalogue is enforced on every call and re-checked on a
  schedule.

### Added
- Resource limits, forensic retention and clean shutdown, `deploy/compose.yaml`,
  `PORT` support, and a much broader CI.

## [0.1.1] — 2026-08-08

### Fixed
- **`pip install sentinel-prox` was broken on a clean machine.** Dependencies
  declared only lower bounds, so a fresh install resolved `mcp` 2.0.0 — a major
  release that removed `create_connected_server_and_client_session`, making the
  package fail on import. Every direct dependency now carries an upper bound as
  well as a floor (`mcp>=1.2,<2` and eleven others). `versions.lock` still pins the
  exact tested versions for CI and the container; these ranges are what protect a
  plain `pip install` for everyone else.

This is the same class of failure that previously broke a production container
deploy. Floors-only dependency ranges are now treated as a defect.

## [0.1.0] — 2026-08-07

First packaged release. Published to PyPI as **`sentinel-prox`** (and later
yanked in favour of 0.1.1); the import package and CLI command are both
`sentinel`. An earlier edit of this file said `sentinel`, which is an unrelated
project on PyPI.

### Added

**Product surface**
- `sentinel` CLI: `init`, `check`, `scaffold`, `serve`.
- `sentinel.yaml` configuration file, with precedence
  CLI flag > environment variable > config file > default.
- `SENTINEL_POLICY_FILE` / `policy:` — load your own authorization policy at
  startup, failing loudly on a bad path rather than silently using the example one.
- `sentinel scaffold` generates a starter policy from your discovered tools: every
  tool explicitly denied, annotated with its description and a recommended rule.

**Securing your own servers**
- Declare arbitrary downstream MCP servers (`SENTINEL_MCP_SERVERS` / `servers:`);
  SENTINEL connects, discovers their tools, and builds routing from discovery
  instead of a hardcoded map.
- Tool-catalogue integrity: tool-poisoning scanning of descriptions *and* input
  schemas, cross-server shadowing detection, and rug-pull detection via catalogue
  fingerprints re-checked on tool discovery.
- `GET /downstream` and a dashboard panel reporting connected servers, discovered
  tools, and active defenses.

**Core security pipeline**
- Provenance tracking as a set of trust labels over transitive lineage, with a
  cycle-safe walk and a non-launderable `StructuredExtractor` sanitizer.
- Authorization engine compiling policy to a typed AST (no `eval`), with
  deny-overrides, default-deny, and fail-closed evaluation.
- Trust scoring with automatic quarantine; immutable OpenTelemetry forensic spans
  with deterministic replay and SIEM-ready JSONL export.
- Real, SSRF-guarded `web_fetch` (`SENTINEL_REAL_WEB_FETCH`).
- A real LLM is the default agent when a credential is present
  (`OPENAI_API_KEY`, Azure OpenAI, or any OpenAI-compatible endpoint via
  `OPENAI_BASE_URL` — including a free local Ollama); deterministic scripted
  fallback otherwise, so CI stays key-free.

### Fixed
- `ToolRouter.list_tools` silently first-won on a tool-name collision while
  `call_tool` could route to a *different* server — the agent read one server's
  description while another executed. Now fails closed.
- The container installed unpinned dependencies despite copying `versions.lock`,
  so a newer `mcp` broke a production deploy. The image now installs with
  `-c versions.lock`.
- Policy scaffolding mangled tool names ending in `.` and emitted invalid YAML for
  an empty catalogue.

### Security
- Untrusted tool metadata cannot escape generated YAML comments in `sentinel scaffold`.
- Cloud metadata endpoints, private, loopback and link-local addresses are blocked in
  `web_fetch`, with per-hop redirect re-validation.

### Known limitations
- Provenance is message/tool-result granularity, not token-level.
- Enforcement is at the action layer, not the model's cognition.
- The proxy and policy store are trusted components.
- Azure integrations (Prompt Shields, Azure OpenAI classifier, Cosmos, Foundry) are
  wired and selection-tested but have not been exercised against a live subscription.

[0.1.0]: https://github.com/Harshith029/SENTINEL/releases/tag/v0.1.0
