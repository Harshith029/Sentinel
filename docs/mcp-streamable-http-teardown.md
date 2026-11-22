# RESOLVED: a stopped test server silenced every later MCP handshake

**Status: fixed (2026-11-22).** The cause was the test harness's signal
handling interacting with sse-starlette. It was never a defect in SENTINEL's
proxy or in the MCP SDK, and the served product was not affected. Earlier
versions of this page called the defect open and unattributed; the last section
before the appendices says what they got wrong.

## Symptom

After a test stopped its uvicorn servers, a later MCP client in the same pytest
process blocked in `initialize()` against a different server on a different
port, with no error. The server logged `ASGI callable returned without
completing response.` SENTINEL's own downstream connections gave up after their
30 s operation timeout. A test client with no bound on the handshake waited
until pytest-timeout's 120 s thread-mode timeout ended the whole process, with
no summary.

## Cause

Three pieces, each reasonable on its own:

1. **uvicorn owns the process's signal handlers while it serves.**
   `Server.serve()` runs inside `capture_signals()`, which installs
   `Server.handle_exit` for SIGINT and SIGTERM when it runs on the main thread.
   The test harnesses tried to prevent that by overriding
   `install_signal_handlers`, but uvicorn no longer has that method, so the
   override did nothing.
2. **sse-starlette reads the owner of that handler as the process.** Its
   shutdown watcher (`sse_starlette.sse._shutdown_watcher`) polls every 0.5 s,
   finds the uvicorn server through `signal.getsignal(SIGTERM).__self__`, and
   when that server's `should_exit` is true it sets `AppStatus.should_exit`.
   That is a class attribute, so it is process-wide, and nothing resets it.
3. **Every SSE response checks the flag before it starts.** When
   `AppStatus.should_exit` is true, `EventSourceResponse` cancels itself before
   it sends a status line. The MCP streamable-HTTP transport answers every
   POST, `initialize` included, with an SSE response, so once the flag is set
   no MCP handshake in the process can complete.

A test stops its servers by setting `should_exit = True`. When a watcher poll
fell inside that window, which happened whenever a teardown took longer than
about half a second, the flag latched, and every later test that opened an MCP
session hung. Tests that stop several servers, such as
`test_remote_http_tool_servers_are_secured`, latched it in every run measured
here.

## Evidence

Linux: Docker `python:3.12` (CPython 3.12.16), a fresh clone installed with
`pip install -e ".[dev]" -c versions.lock`. Windows 11: CPython 3.11.9. Both
use the pinned mcp 1.30.0, sse-starlette 3.4.4, uvicorn 0.48.0 and
anyio 4.14.2.

| Check | Before | After |
|---|---|---|
| `tests/test_downstream_remote_paths.py`, whole file (opted in before) | 8 failed, 4 passed in 248 s on Linux and 249 s on Windows; each failure a 30 s handshake timeout | 12 passed, in the default suite |
| That file, then `tests/test_phase9_mcp_gateway.py` (Linux) | ended by the 120 s timeout after 349 s, no summary | 23 passed in about 10 s |
| `test_remote_http_tool_servers_are_secured`, then `test_real_http_sessions_after_remote_downstream` (Windows) | failed 3 of 3 | passed 3 of 3 |
| `test_stopping_one_server_does_not_silence_the_next` alone (Linux) | failed 3 of 3 at its 8 s bound | passed 5 of 5 |

A probe inside pytest found `AppStatus.should_exit` already true when the second
test of a failing pair started. Resetting it before each test made the pair
pass, and setting it before a single test made that test fail on its own, with
the same server log line. `docs/mcp_repro_standalone.py` reproduces the hang
with mcp, uvicorn and sse-starlette alone.

## Fix

The test servers no longer capture signals: each one replaces
`capture_signals` with `contextlib.nullcontext`, which is what the dead
override was meant to do. With no uvicorn server owning SIGTERM, the watcher
finds nothing to mistake for the process. The quarantine went with it:
`tests/test_downstream_remote_paths.py` runs in the default suite, the strict
xfail on `test_real_http_sessions_after_remote_downstream` is removed, and the
separate CI job that ran those tests one per process is deleted.

## Deployment exposure

None found. SENTINEL starts a server in two places, `uvicorn.run` in
`src/sentinel/cli.py` (`sentinel serve`) and `server.run(transport="streamable-http")`
in `src/sentinel/demo/toolserver_main.py` (a demo tool server), and each process
runs exactly one. The flag is therefore set only when that server is told to
exit, which means its process is shutting down: the graceful drain sse-starlette
intends. Re-establishing downstream connections inside one process, which this
page used to call blocked, does not touch the flag: SENTINEL's downstream side
is an MCP client and sends no SSE responses. Anything that ran a second uvicorn
server inside one process would need the same care as the test harness.

## What the earlier investigation got wrong

* **Why it looked intermittent.** It depended on whether a teardown outlasted a
  0.5 s poll, so it moved with machine speed and with which tests ran before.
  That explains the rate of 1 wedge in 8 full runs, and why removing any one of
  several unrelated tests changed the result.
* **Why the standalone probe did not reproduce it.** The probe stopped one fast
  server and opened the next session at once, so the second handshake usually
  finished before the watcher polled. It hung once and then 0 of 6 times for
  that reason, not because the cause lay outside the libraries it used.
* **The Windows stacks.** The task blocked in `GetQueuedCompletionStatus` was an
  idle event loop waiting for a response the server was never going to send.
  Nothing was wrong with IOCP. Abandoned background work cannot set the flag,
  because it runs without a uvicorn server; at most it changed timing, and the
  rates measured for it (2 in 5, then 2 in 11) were small samples.
* **The hypotheses this page ruled out**, such as the session-termination
  `DELETE`, the explicit HTTP client and the port race, were correctly ruled
  out. None of them touched the server's SSE response.

## Why `terminate_on_close` stays `True`

Independent of the wedge, skipping the session-termination DELETE is unsafe here.
`StreamableHTTPSessionManager.session_idle_timeout` defaults to `None`, so a
server that never receives the DELETE keeps the session in `_server_instances`
**forever**. Those servers belong to the operator, not to us. SENTINEL will not
strand resources on someone else's server to work around a defect in its own
process.

## Related: F-02 deployment status

The `/mcp` path fix in `deploy/main.bicep` corrected a URL that could never have
connected. It does **not** establish Azure deployability. The template has not
been deployed or smoke-tested, and Key Vault secret consumption, Content
Safety/OpenAI configuration, Cosmos data-plane RBAC and readiness checks remain
unverified. `GET /capabilities` reports this under `deployment_verification`.
