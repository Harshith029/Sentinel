# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning is
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security
- Trust is kept per (tenant, agent). Keyed by agent id alone, a tenant that
  used another tenant's agent id could read that agent's trust score and push
  it down (with quarantine enforced, quarantine it), and an operator reset of
  one tenant's agent reset every tenant's agent with that id.
  `/agents/{id}/trust` and `/reset` act in the caller's tenant; the operator
  names one with `?tenant=`.

### Fixed
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
