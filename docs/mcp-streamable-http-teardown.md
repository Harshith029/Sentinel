# OPEN: streamable-HTTP teardown wedges a later MCP client

**Status: unresolved, and not yet attributed.** This document records what is
established and — just as importantly — what earlier drafts of it claimed
without support.

## Symptom

After `test_remote_http_tool_servers_are_secured` runs, the next real-HTTP MCP
client in the same process blocks forever in `initialize()`, against a
*different* server on a *different* port. Connection setup and `ClientSession`
entry both succeed; the block is inside the MCP handshake. There is no error and
no timeout.

`tests/test_phase9_mcp_gateway.py::test_real_http_sessions_after_remote_downstream`
reproduces it **deterministically** — 3/3 runs — and is bounded at 20s so it
fails fast with a full pending-task dump instead of hanging CI.

## What is NOT established

* **Not attributed to upstream.** `docs/mcp_repro_standalone.py` (only `mcp` and
  `uvicorn`, no Whence code) hung once, which an earlier draft treated as proof
  the defect was upstream. On retest it hangs **0 out of 6** runs. A
  non-deterministic reproducer is not an attribution, so no upstream issue has
  been filed and none should be until the script reproduces reliably.
* **`terminate_on_close=False` is not a workaround.** The standalone script
  suggested it; the suite refutes it. Setting it on Whence's downstream
  connections leaves the sequence failing (3/3), and setting it on the external
  test client leaves it failing too.
* **An explicit `httpx.AsyncClient` is not a workaround.** The suite wedges with
  every client explicitly configured.

## What IS established

* The trigger is not Whence's downstream connections: flipping their
  termination policy changes nothing.
* Whence's gateway does not leak tasks on teardown — a standalone run entered a
  remote-mode gateway, tore it down, and observed **zero** leaked asyncio tasks.
* It is not settings-cache bleed: the second gateway reports
  `downstream_mode == "memory"`, not the previous test's remote URLs.
* It is not the `_free_port` bind/close/rebind race, which was fixed separately.

## Why `terminate_on_close` stays `True`

Independent of the wedge, skipping the session-termination DELETE is unsafe here.
`StreamableHTTPSessionManager.session_idle_timeout` defaults to `None`, so a
server that never receives the DELETE keeps the session in `_server_instances`
**forever**. Those servers belong to the operator, not to us. Whence will not
strand resources on someone else's server to work around a defect in its own
process.

## Deployment exposure

A deployed gateway opens its downstream sessions once at startup and closes them
at shutdown, so it does not re-establish them in-process. The failing sequence is
therefore not on the normal serving path. It becomes reachable if downstream
connections are ever torn down and re-established inside one process — an
in-process config reload or reconnect-on-downstream-restart. Neither exists
today; both are blocked until this is understood.

## Environment

mcp 1.27.1 · anyio 4.13.0 · httpx 0.28.1 · httpcore 1.0.9 · starlette 1.2.0 ·
uvicorn 0.48.0 · CPython 3.11.9 · Windows 11 (Proactor loop).

**Only Windows has been tested.** No Linux or macOS run has been performed, so
the platform matrix is one row wide and must not be described as more.


## Related: F-02 deployment status

The `/mcp` path fix in `deploy/main.bicep` corrected a URL that could never have
connected. It does **not** establish Azure deployability. The template has not
been deployed or smoke-tested, and Key Vault secret consumption, Content
Safety/OpenAI configuration, Cosmos data-plane RBAC and readiness checks remain
unverified. `GET /capabilities` reports this under `deployment_verification`.
