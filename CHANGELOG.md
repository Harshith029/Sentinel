# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning is
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] — 2026-08-08

### Fixed
- **`pip install whence` was broken on a clean machine.** Dependencies
  declared only lower bounds, so a fresh install resolved `mcp` 2.0.0 — a major
  release that removed `create_connected_server_and_client_session`, making the
  package fail on import. Every direct dependency now carries an upper bound as
  well as a floor (`mcp>=1.2,<2` and eleven others). `versions.lock` still pins the
  exact tested versions for CI and the container; these ranges are what protect a
  plain `pip install` for everyone else.

This is the same class of failure that previously broke a production container
deploy. Floors-only dependency ranges are now treated as a defect.

## [0.1.0] — 2026-08-07

First packaged release. Published to PyPI as **`whence`**; the import
package and CLI command are both `whence`.

### Added

**Product surface**
- `whence` CLI: `init`, `check`, `scaffold`, `serve`.
- `whence.yaml` configuration file, with precedence
  CLI flag > environment variable > config file > default.
- `WHENCE_POLICY_FILE` / `policy:` — load your own authorization policy at
  startup, failing loudly on a bad path rather than silently using the example one.
- `whence scaffold` generates a starter policy from your discovered tools: every
  tool explicitly denied, annotated with its description and a recommended rule.

**Securing your own servers**
- Declare arbitrary downstream MCP servers (`WHENCE_MCP_SERVERS` / `servers:`);
  Whence connects, discovers their tools, and builds routing from discovery
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
- Real, SSRF-guarded `web_fetch` (`WHENCE_REAL_WEB_FETCH`).
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
- Untrusted tool metadata cannot escape generated YAML comments in `whence scaffold`.
- Cloud metadata endpoints, private, loopback and link-local addresses are blocked in
  `web_fetch`, with per-hop redirect re-validation.

### Known limitations
- Provenance is message/tool-result granularity, not token-level.
- Enforcement is at the action layer, not the model's cognition.
- The proxy and policy store are trusted components.
- Azure integrations (Prompt Shields, Azure OpenAI classifier, Cosmos, Foundry) are
  wired and selection-tested but have not been exercised against a live subscription.

[0.1.0]: https://github.com/Harshith029/Whence/releases/tag/v0.1.0
