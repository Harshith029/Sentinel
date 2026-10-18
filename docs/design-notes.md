# Design notes: findings kept as they are

The 2026-10-17 findings catalogue listed about 180 items. Most were fixed; see the
CHANGELOG. These were examined and deliberately left as they are. Each says why,
so a later review can disagree with the reasoning rather than rediscover the item.

| ID | What the catalogue said | Why it stays |
|---|---|---|
| PP-04, GW-9 | Taint lives in one MCP session; a new session starts clean. | The proxy has no identity for "the same task" across sessions. Carrying taint per credential would deny every guarded action for an agent forever after one untrusted read. Documented in the README's *Known limitations*. |
| PP-06 | Declassification never clears taint already in the session. | Declassification vouches for one value, not for what the agent did with earlier untrusted content. Clearing the session on it would let any declassifiable tool launder the lineage. |
| PP-11, DEMO-24 | The demo baseline and the Phase 1 skeleton reach tools without `_intercept`. | Both exist to show what happens without SENTINEL. The baseline is reachable only through the demo endpoints, which answer 404 unless `SENTINEL_DASHBOARD=1`; neither is reachable from `/mcp`. |
| PP-14 | The per-session lock is held across the downstream call. | It is what keeps a session's provenance updates ordered. The call is now bounded by `SENTINEL_DOWNSTREAM_TIMEOUT_SECONDS`, so the wait is bounded too. |
| PP-15 | The union-vs-walk test uses the union's own derivation rule. | True, and now stated in the test. It verifies the incremental computation; the rule (each call derives from everything observed before it) is the design. |
| TRUST-2 | The trust score never recovers. | Why quarantine is recorded, not enforced, by default. Documented in *Known limitations*. |
| TRUST-3 | Quarantine flags are set before the event is written. | Fail-closed: if the write fails the agent is still quarantined, and the log line is written first. Reversing it would let an agent through when recording fails. |
| TRUST-5 | Only some events cost trust. | Catalogue refusals are the downstream's change, the user's own prompt is not agent behaviour, and the local shield is a heuristic. Now stated in `trust/config.yaml`. |
| TRUST-6, CM-7, GW-2 | Trust and run state are per process. | Shared state would need a store SENTINEL does not have. The Azure template runs one replica; documented. |
| AUTHZ-14 | "Deny-overrides" is vacuous with deny-only rules. | The term still describes the behaviour correctly (any deny wins); it is simply trivially satisfied. |
| AUTHZ-17 | A module named `ast` shadows the standard library's name. | It is only ever imported as `sentinel.authorization.ast`. Renaming it would break imports for anyone using the package API, for no behaviour change. |
| DCC-18 (part) | `sentinel check` fails on flag-only findings that `serve` accepts. | A readiness check should not pass findings an operator still has to triage. |
| DCC-22 (part) | No way to authenticate to downstream servers. | A missing feature, not a defect; listed in *Known limitations*. |
| CM-13, GW-19 | Global event ids reveal activity volume; `/downstream` and `/capabilities` are deployment-wide. | Per-tenant counters would change the event-cursor protocol. Listed in *Known limitations*. |
| PP-16 | Calls the MCP SDK rejects for schema reasons are not recorded. | They never reach SENTINEL. Recording them would mean turning off the SDK's validation and doing it inside the proxy; listed in *Known limitations*. |
| COSMOS-1 | The Cosmos path has no ownership, restore or retention. | A larger piece of work on a paid path; listed in *Known limitations*. Cosmos can now at least start (it needs the `cosmos` extra). |
| TCD-04, OWN-6 | Real-HTTP tests are order-dependent and can hang. | The open teardown defect in `docs/mcp-streamable-http-teardown.md`, tracked by a strict xfail and the quarantined CI job. |
| RED-1 (rest) | Redaction keeps tool names and deny reasons in the clear. | Argument names and values are redacted. Tool names and reasons are what an investigator reads first, and they come from the catalogue and the policy, not from the caller's data. A caller-invented tool name is still logged with control characters escaped. |
| AUTHZ-15 (rest) | No static check of predicate variables or config types. | Loading now warns about comparands the config does not declare and config keys that shadow call fields, refuses duplicate rule ids, and a scalar where a collection is expected denies at evaluation. A full type checker for config values is not worth its complexity here. |
| DCC-23 (rest) | `verify_catalogue` and `DownstreamTopology.server_of`/`tool_names` are unused in production. | Small, tested, public helpers for anyone building on the package; the truly unused `build_web_server` was removed. |
| TCD-26 | The codebase's history starts with a large root commit. | A fact about the repository's history; nothing to change in the code. |

## Not done

| ID | What | Status |
|---|---|---|
| GW-12 | The browser session cookie is the raw bearer token; there is no server-side session, expiry or revocation. | Open. The cookie is `HttpOnly` and `SameSite=Strict`, and the dashboard is off unless `SENTINEL_DASHBOARD=1`, but a server-side session store remains to be built. |
