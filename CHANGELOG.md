# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning is
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- A documentation site, built from `website/` with VitePress and published to
  GitHub Pages: quick start, how it works, policy guide, configuration,
  authentication, logs and forensics, deployment, limits, backends,
  limitations and FAQ. CI builds it on every change and fails on a dead link
  or a vulnerable dependency. Its landing page is animated (an attack-flow
  replay synced to a step list, a typing decision log, a before/after outbox)
  and holds still for visitors who ask for reduced motion.
- `assets/flow.svg`, an animated diagram of SENTINEL refusing an exfiltration
  attempt, used at the top of the README and on the site.
- `SECURITY.md` (supported versions, private reporting, scope),
  `CODE_OF_CONDUCT.md`, issue forms for bugs, features and documentation, and a
  pull request template with the security-invariant checklist.

### Changed
- The README is reorganised around a quick start, with the reference material
  moved to the site. The package's project URLs point at the site and the
  changelog.

### Removed
- The hosted demo on Render and its `render.yaml` blueprint. It ran in
  anonymous mode on the public internet, which is not how SENTINEL should be
  seen running. The demo runs locally instead (`SENTINEL_ALLOW_ANONYMOUS=1
  sentinel serve --dashboard`).
- The hackathon pitch decks, submission documents and video script (`deck/`).
  They remain in the git history. The large-file check is back to its default
  limit, which the decks had needed raised.

### Security
- The Cosmos store writes spans with `create_item`, which fails atomically if
  the id exists. It read first and then upserted, so two writers of one span
  id could both see it absent and the second silently replaced the first.
- The authorization engine denies a rule with no condition instead of failing
  an `assert` outside its fail-closed path (and the asserts on the policy and
  gateway paths are explicit checks, which `python -O` does not strip).

### Fixed
- The README's demo command, `sentinel serve --dashboard`, served a dashboard
  whose every data route answered 503: the demo needs anonymous mode
  (`SENTINEL_ALLOW_ANONYMOUS=1`), which the command did not set.
- Documentation: what "durably emitted" means per store; the trust penalties
  that actually apply; that the evasion page is written against the local
  shield; which keys `sentinel.yaml` accepts; that the non-bypassability test
  covers the proxy's own path, not network topology; a positioning claim of
  "the same class of guarantee" as CaMeL. `docs/design-notes.md` lists the
  catalogue findings kept as they are, and why.
- The rule-based attack classifier labels any server's tools by the verbs in
  their names (`delete_*`, `refundCharge`, `sendSlackMessage`...); it knew only
  the demo's tools, so an operator's own blocks were mostly "unclassified".
- The before/after baseline uses the same driver (scripted or live model) and
  web mode as the protected run; it was always the scripted transcript.
- The dashboard's kill chain and verdict come from the run's data. They named
  `web_fetch`, `block-untrusted-origin` and "the exfiltration" whatever the
  run did. Its trust gauge uses the configured quarantine threshold (now in
  `/capabilities` and the trust endpoint) instead of a hard-coded 40.
- The examples no longer say an external `/mcp` run appears in the live view;
  it is listed in the history tab.
- Cosmos DB persistence could not start: its async Azure clients need aiohttp,
  which is not installed, and setting `AZURE_COSMOS_ENDPOINT` failed at startup
  with a bare import error. Install `sentinel-prox[cosmos]`; without it the
  error now says so. An unused duplicate Cosmos factory was removed.
- Restoring the run index after a restart no longer loads every span of every
  trace to guess a scenario label from redacted input (it never matched).
- The gateway logs an error if the MCP SDK stops exposing the session index it
  reads to release ended sessions, instead of silently never releasing them;
  a test pins that SDK attribute.
- Replay reports a duplicated span id as a duplicate; it was reported as a
  cycle, which with one parent per span it cannot be.
- SQLite stores each span's timestamp in an indexed column (existing databases
  are migrated in place), so listing traces and retention purges no longer
  parse every span's JSON while holding the store lock.
- The test suite's fake Cosmos container refuses queries other than the one it
  can answer; it ignored the SQL entirely.

## [0.2.2] — 2026-10-19

**Upgrade from 0.2.1 or earlier.** Read *Changed (breaking)* first: catalogue
approval fingerprints, the bundled policy, `sentinel.yaml` validation and
administration (`SENTINEL_ADMIN_TOKEN` only) all change.

### Changed (breaking)
- The bundled policy (version 6) trusts `get_customer_record`'s output, and
  the hero demo's scripted agent emails only where the fetched page tells it
  to. The hero block now depends on the poisoned page: before, the record
  lookup alone tainted the session and the agent always sent the email.
- Declassification schemas are strict. `iso_date` takes `YYYY-MM-DD` only
  (`date.fromisoformat` also took `20261018` and ISO week dates), and
  `decimal_amount` takes plain ASCII notation up to 18 digits each side of
  the point (`1_000`, `1e9999` and non-ASCII digits were accepted).
- `TrustScorer(...)` records quarantine by default (`enforce=False`), as the
  service and the scorer's own documentation already did. It enforced by
  default, so the standalone demo enforced while the dashboard did not; the
  trust-collapse demo now asks for enforcement explicitly.
- `sentinel.yaml` rejects unknown keys (a misspelt key was ignored), and
  booleans must be booleans: the quoted string `"false"` used to mean on.
  An environment variable that is set but empty no longer masks the file's
  value.
- Policy language: `true` and `false` are literals (they parsed as variables,
  so a call's argument named `true` set them), and `null`/`None` are refused.
  A boolean never equals a number. `==` reads a numeric string as a number,
  as `<` and `>=` already did, so `"1000"` no longer escapes
  `amount == 1000`. NaN and the infinities are errors, so the rule denies:
  `"-Infinity"` used to pass `amount >= max_amount`. A predicate nesting more
  than 64 levels is refused at load (deep parentheses raised RecursionError,
  a 500 on reload; long chains loaded and then never evaluated), and so are
  duplicate rule ids within a tool.
- The bundled policy (version 5) also denies `transfer_funds` with a negative
  amount; the cap alone let one through.
- A blocked agent is told which rule refused it, not the evaluation detail,
  which could name config values. The forensic record keeps the full reason.
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
- `SENTINEL_AGENT_DRIVER` (`auto`, `scripted`, `llm`) chooses what drives demo
  runs. Configuring Azure OpenAI for the classifier also switched every demo
  run to a live model, with no way to keep the scripted transcript.
- `trusted_output: true` on a policy tool labels its results `SYSTEM` instead of
  `RETRIEVED_CONTENT`, for tools whose output nobody outside can write to.
- `SENTINEL_DOWNSTREAM_TIMEOUT_SECONDS` (default 30, also
  `downstream_timeout_seconds` in `sentinel.yaml`): a deadline for each
  downstream operation. Before, a downstream server that accepted a connection
  and never answered held startup, discovery or a tool call forever.
- `SENTINEL_MCP_ALLOWED_HOST` for the demo tool servers, so they keep MCP's
  Host-header check when deployed behind an internal hostname.

### Removed
- The `azure-monitor-opentelemetry`, `opentelemetry-api` and
  `opentelemetry-sdk` dependencies. Nothing used them once trace and span ids
  came from `secrets`, and they pinned 28 packages in `versions.lock` (the
  Azure Monitor exporter, fifteen OpenTelemetry instrumentation and support
  packages, `msrest`, `psutil`, `wrapt` and others). A project that imported
  OpenTelemetry only because SENTINEL installed it must now depend on it
  directly.

### Security
- The in-memory forensic store keeps and returns private copies of spans. A
  caller holding a returned span could rewrite the stored payload's
  arguments; the SQLite and Cosmos stores were never affected.
- An unauthenticated deployment answers only to loopback and the hosts in
  `SENTINEL_ALLOWED_HOSTS`, and refuses state-changing requests from another
  site's `Origin`. With no credential, a web page the operator had open could
  submit forms to a local instance or, by DNS rebinding, drive `/mcp`.
- Tool approval uses the same `tools/list` snapshot as routing. Preflight
  listed the servers a second time, so a tool could be approved from one
  server's definition and routed to another's.
- Trust state is keyed by a `(tenant, agent)` pair. The joined
  `tenant<US>agent` string let names containing the separator collide.
- Cancelling a caller no longer releases the SQLite store's lock while its
  thread is still using the connection, and spans are written with a plain
  `INSERT` rather than `INSERT OR REPLACE`.
- `structuredContent` counts toward `SENTINEL_MAX_RESULT_BYTES`; it reached
  the agent outside the cap.
- A proxy session can be started once. A second `start()` reset the lineage
  to the user's label alone, clearing the session's taint.
- A recipient address containing a control character is unparseable, so an
  allowlist denies it. The raw value is what is forwarded, and a CRLF in it
  could add mail headers downstream.
- `web_fetch` resolves DNS off the event loop. The blocking `getaddrinfo`
  stalled every session while a lookup ran. It also has an overall deadline
  (`deadline`, 30 s): a server sending a byte just inside the per-read
  timeout kept a fetch going indefinitely. Malformed hosts (a label over 63
  characters, invalid IDNA) are error results; they raised out of a function
  documented never to.
- Downstream connection errors no longer print a server URL's user info,
  query or fragment, where URLs carry credentials.
- An explicit `SENTINEL_SHIELD=azure` is honoured in demo mode, the default.
  It was silently replaced by the local regexes.
- `/mcp` refuses websocket connections at the handshake. `Mount` routes them
  to the gateway too, and they went to the MCP SDK before the credential
  check.
- A `DELETE` the SDK refused no longer forgets the session's owner, which
  locked the owner out of a session that was still alive.
- `tools/list` re-checks the downstream catalogues at most every 5 seconds.
  The SDK runs that handler whenever a call names a tool it has not cached,
  so every call with a made-up tool name cost a `tools/list` on every
  downstream server.
- `SENTINEL_MAX_SSE_SUBSCRIBERS` applies per tenant; one tenant could hold
  every live-stream slot.
- `SENTINEL_API_TOKEN` no longer administers, even in a single-token
  deployment: it is the credential agents hold, so agents could replace their
  own policy and clear their own quarantine. Only `SENTINEL_ADMIN_TOKEN`
  administers; without it nobody does, and `sentinel check` and `sentinel
  serve` say so. (Breaking for single-token deployments that used the policy
  or trust-reset endpoints: set `SENTINEL_ADMIN_TOKEN`.)
- `mcp` is upgraded to 1.30.0 (floor and lock) for CVE-2026-59951
  (GHSA-84m7-p3x7-pcfv): the SDK's streamable-HTTP transport let sessions
  accumulate without bound. SENTINEL's per-tenant session cap limited this on
  `/mcp`, but did not replace the upstream fix. The teardown defect in
  `docs/mcp-streamable-http-teardown.md` is still present in 1.30.0.
  `pytest-timeout`, a dev dependency, is now pinned in `versions.lock` too.
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
- The trust model tracks the previous tool per trace. One value per agent
  mixed concurrent sessions of the same principal, so interleaved calls made
  transitions no session took and were scored as anomalies.
- The dashboard no longer says SENTINEL tracks "every byte" (lineage is per
  tool result) or that its log streams live (it replays a run that finished
  in milliseconds). DEPLOY.md says the Azure template's tool servers rely on
  internal-only ingress, not authentication, and the README says catalogue
  approval is trust on first use.
- A declassified result's execution span names the schema that cleared it
  (`declassified_by`); only the `SYSTEM` label was recorded.
- Loading a policy warns when a config key has the same name as a call field
  a rule reads, since config then replaces that field for every rule.
- `sentinel check` prints the approval fingerprints for flag-only findings as
  it does for a strict refusal, and lists approved findings instead of
  reporting "no poisoning".
- Demo runs honour `SENTINEL_CATALOGUE_APPROVALS`, as `sentinel serve` does.
- With `SENTINEL_REAL_WEB_FETCH=1`, a custom attack's page is served for its
  URL. The protected run fetched the live URL while its baseline used the
  custom page, so the two compared different content.
- `examples/run_live_agent.py` exits 4 when nothing was blocked; it exited 0,
  so a script could not tell a demonstration from a non-event.
- Dashboard: a refused launch (a 4xx such as an unknown scenario or a full
  quota) or a run that fails before emitting anything shows REFUSED with the
  reason; it spun forever. It auto-plays once, on a dashboard with no runs,
  instead of launching a run and a baseline on every page load.
- Security log lines (allow, block, quarantine, injection flag) name the
  tenant, as `tenant` in JSON and `[tenant ...]` in text.
- `/capabilities` reports the manager's running mode; a manager built with
  `demo_mode=False` still said DEMO MODE.
- Discovery follows `tools/list` pagination (up to 100 pages). Only the first
  page was read, so a large server's later tools were never routed or scanned.
- Documentation now matches the code. The README described a per-call graph
  walk for provenance (it is a running union, tested against the walk) and
  implied the hero block depended on the poisoned page; it does not, because
  the record lookup already taints the session. CONTRIBUTING said CI runs
  Python 3.11 only; the pytest timeout comment called a hard process exit an
  ordinary failure. Module docstrings claimed catalogue findings were
  forensic events, a `list_changed` subscription, real records and email
  servers, and an SDK client with no connect timeout. The hackathon write-ups
  under `deck/` carry a dated correction note instead of being rewritten.
- The Foundry registration no longer lists `transfer_funds`, which no demo
  server provides, and refuses an empty tool list, as SDK_VERIFICATION.md
  said it did.
- A failing injection scan (an Azure Prompt Shields outage, say) is recorded
  as `scan failed` instead of raising. For a tool result the tool had already
  run, so the call failed after its side effect.
- The Azure OpenAI classifier builds its credential and client once and
  fetches tokens off the event loop; it built a new credential and fetched a
  token synchronously on every call. An Azure error falls back to the rule
  label instead of failing `/runs/{id}/audit`, and a reply must be exactly
  one class (`"not exfiltration"` was read as exfiltration).
- Live MCP sessions no longer count against `SENTINEL_MAX_ACTIVE_RUNS`; with
  eight agents connected a tenant could not start a scenario. The gateway caps
  sessions itself.
- A run cancelled at shutdown is marked failed; it stayed `running`.
- Retention purges ownership rows for runs that never wrote a span.
- Trust state is capped at 10,000 agents, evicting the least recently used and
  never one that crossed the threshold. The emitter frees a trace's sequence
  counter when its run or session ends. Both grew for the life of the process.
- `sentinel scaffold` kept a long tool name with spaces on one line; PyYAML
  folded it at 80 characters and the generated policy did not load.
- `sentinel init`'s "this file could be committed" check looked at
  `sub/sub/sentinel.yaml` for a config at `sub/sentinel.yaml`.
- A session retired for idleness is told to open a new session. It was told
  the gateway was at capacity and to retry, which could never succeed.
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
