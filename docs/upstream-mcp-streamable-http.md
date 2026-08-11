# Upstream defect: streamable-HTTP client teardown wedges later clients

## Summary

With `mcp` 1.27.1 on Windows/CPython 3.11, opening and closing **one**
streamable-HTTP MCP client session leaves the process unable to complete a
**later** client's `initialize()` — against a different server, on a different
port, in a different task. There is no error and no timeout: the second
`initialize()` never returns.

No SENTINEL code is involved. `docs/upstream_mcp_repro.py` reproduces it with
only `mcp` and `uvicorn`.

## Reproducer

```bash
python docs/upstream_mcp_repro.py skip    # control: second session alone  -> OK (~0.6s)
python docs/upstream_mcp_repro.py first   # one prior session closed first -> HANGS
python docs/upstream_mcp_repro.py noterm  # prior session, terminate_on_close=False -> OK
```

Observed:

```
[  0.50] first server torn down
[  0.53] SECOND: connecting
[  0.77] SECOND: transport entered
[  0.77] SECOND: session entered -> initialize()
[ 24.99] TIMEOUT: 10 tasks pending
```

Connection establishment succeeds. The block is in the MCP handshake, after the
transport and `ClientSession` are both entered.

## Affected versions

| package | version |
|---|---|
| mcp | 1.27.1 |
| anyio | 4.13.0 |
| httpx | 0.28.1 |
| httpcore | 1.0.9 |
| starlette | 1.2.0 |
| uvicorn | 0.48.0 |
| CPython | 3.11.9 (Windows 11, Proactor loop) |

## Trigger and workaround

The trigger is the session-termination `DELETE` that `terminate_on_close=True`
(the default) sends when the first client session closes. Passing
`terminate_on_close=False` to the first session avoids the wedge in the
standalone reproducer.

**Not a workaround:** supplying an explicitly configured `httpx.AsyncClient`
appeared to help in one standalone run, but does **not** hold — the SENTINEL
suite still wedges with every client explicitly configured. Recorded here so the
finding is not mistaken for a fix.

## Affected deployment conditions

A long-lived SENTINEL gateway connects to its downstream servers once at startup
and holds those sessions, so a steady-state deployment does not hit this. It
becomes reachable when downstream sessions are **torn down and re-established**
in one process — config reload, downstream restart with reconnect, or repeated
`sentinel check` runs in a single process. Linux/macOS exposure is unverified;
the reproducer above is the way to check.

## Status

Not yet reported upstream — this document and the reproducer are the report
material. `connect_downstream` now supplies an HTTP client with a bounded connect
timeout, which does not fix this defect but does stop an unreachable downstream
from hanging startup indefinitely.
