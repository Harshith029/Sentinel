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

## Ruled out, with evidence

Each of these was a plausible mechanism, tested directly, and disproved. They are
listed so the next investigation does not spend its time here again.

| Hypothesis | How it was tested | Result |
|---|---|---|
| Upstream `mcp` defect | Standalone `mcp`+`uvicorn` script (`docs/mcp_repro_standalone.py`) | Hung ONCE, then **0/6** on retest. Not a reproducer, so not an attribution. |
| Gateway leaks asyncio tasks on teardown | Enter a remote-mode gateway, tear down, count pending tasks | **Zero** leaked; downstream sessions and the session manager both close |
| Settings-cache bleed into the next gateway | Assert `downstream_mode` on the second gateway | Reports `memory`, not the previous test's remote URLs |
| `_free_port` bind/close/rebind race | Hand uvicorn a pre-bound listening socket instead | Did not fix it; the change was reverted rather than kept unproven |
| The session-termination `DELETE` | `terminate_on_close=False` on downstream connections, then on the external client | Still wedges either way |
| Letting the SDK build its own HTTP client | Supply an explicit `httpx.AsyncClient` everywhere | Still wedges |
| Number of gateway enter/exit cycles | 0, 5 and 20 cycles, then a real-HTTP session | No wedge at any count |
| A rejected (401) request leaving a half-open transport | One unauthorized attempt, then an authorized session | No wedge; the control run behaves identically |
| Resource exhaustion (handles/sockets/threads) | Per-test `psutil` sampling across the whole suite | Handles ~233→445, threads 1, sockets 0. No runaway. |

## What it actually looks like

* **Windows-only so far.** Linux CI has been green throughout; every observation
  here is from Windows 11 / CPython 3.11 on the Proactor loop.
* **Probabilistic, not ordered.** Measured at HEAD `5bb1dfb` with every test
  bounded: **1 wedge in 8 full runs**. Removing *any* one of several unrelated
  tests makes a failing run pass, which is the signature of a timing race rather
  than a specific bad predecessor.
* **Abandoned in-flight work raises the rate.** Tests that `POST /runs` start the
  scenario as a background task. When a new test module did that without
  draining the manager, the rate rose to **2 in 5**; adding
  `await manager.aclose()` brought it back to **2 in 11**, indistinguishable from
  baseline. That is the first lead on the mechanism rather than another
  elimination: work destroyed mid-flight along with its event loop, instead of
  being cancelled and awaited, appears to leave IOCP state that a later
  overlapped read never recovers from. Every test that starts background work
  must drain it.
* **Always the same shape.** The blocked task sits in
  `GetQueuedCompletionStatus`, waiting on IOCP for a completion that never
  arrives, inside an MCP client handshake.

Because it cannot be attributed, it is **contained** rather than fixed: every
test is bounded (`timeout = 120` in `pyproject.toml`), so a wedge becomes a named
failure with a stack dump instead of a run that hangs indefinitely.

## Why `terminate_on_close` stays `True`

Independent of the wedge, skipping the session-termination DELETE is unsafe here.
`StreamableHTTPSessionManager.session_idle_timeout` defaults to `None`, so a
server that never receives the DELETE keeps the session in `_server_instances`
**forever**. Those servers belong to the operator, not to us. SENTINEL will not
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
