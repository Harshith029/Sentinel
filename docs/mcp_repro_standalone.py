"""Standalone probe for the streamable-HTTP teardown wedge — mcp + uvicorn only.

**This is a probe, not a reproducer.** It hung once and then 0/6 on retest, which
is why the defect is NOT attributed to upstream. See
``docs/mcp-streamable-http-teardown.md``. The reliable reproduction currently
lives in the test suite, not here.

Usage::

    python docs/mcp_repro_standalone.py skip     # control: one session only
    python docs/mcp_repro_standalone.py first    # a prior session, then another
    python docs/mcp_repro_standalone.py noterm   # prior session, no DELETE
    python docs/mcp_repro_standalone.py timed    # second session, explicit client

A diagnostic must not carry the bugs it was written to investigate, so it uses
the same pre-bound listener and the same explicit HTTP-client ownership as the
test harness.
"""
from __future__ import annotations

import asyncio
import os
import socket
import sys
import time
from contextlib import AsyncExitStack, asynccontextmanager
from collections.abc import AsyncIterator

import httpx
import uvicorn
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.server.fastmcp import FastMCP
from starlette.applications import Starlette

_START = time.monotonic()
_WATCHDOG_SECONDS = 25.0


def log(message: str) -> None:
    print(f"[{time.monotonic() - _START:6.2f}] {message}", flush=True)


def build_app() -> Starlette:
    server = FastMCP("repro")

    @server.tool()
    def ping() -> str:
        return "pong"

    return server.streamable_http_app()


class Server:
    """uvicorn on a pre-bound listening socket.

    Binding, closing, then letting uvicorn rebind leaves the port unowned in
    between — the race this investigation already fixed in the test harness.
    """

    def __init__(self, app: Starlette) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(128)
        self.port: int = self._sock.getsockname()[1]
        config = uvicorn.Config(
            app,
            host="127.0.0.1",
            port=self.port,
            log_level="error",
            lifespan="on",
            ws="none",
        )
        self._server = uvicorn.Server(config)
        self._server.install_signal_handlers = lambda: None  # type: ignore[method-assign]
        self._task: asyncio.Task[None] | None = None

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/mcp"

    async def __aenter__(self) -> Server:
        self._task = asyncio.create_task(self._server.serve(sockets=[self._sock]))
        while not self._server.started:
            await asyncio.sleep(0.02)
        return self

    async def __aexit__(self, *exc: object) -> None:
        self._server.should_exit = True
        try:
            if self._task is not None:
                await asyncio.wait_for(self._task, timeout=15)
        finally:
            self._sock.close()


@asynccontextmanager
async def _client(explicit: bool) -> AsyncIterator[httpx.AsyncClient | None]:
    """Yield an owned HTTP client, or None to let the SDK build its own.

    The SDK closes the client only when it created it, so an explicitly supplied
    one has to be closed here or the probe leaks a connection pool per run.
    """
    if not explicit:
        yield None
        return
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(None, connect=10.0, pool=10.0),
        follow_redirects=True,  # /mcp answers the MCP POST with a 307 to /mcp/
    ) as client:
        yield client


async def open_session(url: str, tag: str, *, terminate: bool, explicit: bool) -> None:
    log(f"{tag}: connecting (terminate_on_close={terminate}, explicit_client={explicit})")
    async with _client(explicit) as http_client:
        async with streamable_http_client(
            url, http_client=http_client, terminate_on_close=terminate
        ) as (read, write, _session_id):
            log(f"{tag}: transport entered")
            async with ClientSession(read, write) as session:
                log(f"{tag}: session entered -> initialize()")
                await session.initialize()
                log(f"{tag}: initialize OK")


async def watchdog() -> None:
    await asyncio.sleep(_WATCHDOG_SECONDS)
    pending = asyncio.all_tasks()
    log(f"TIMEOUT: {len(pending)} tasks pending")
    for task in pending:
        stack = task.get_stack(limit=1)
        where = f"{stack[0].f_code.co_filename}:{stack[0].f_lineno}" if stack else "?"
        log(f"    {task.get_name()} @ {where}")
    os._exit(3)


async def main() -> None:
    mode = sys.argv[1] if len(sys.argv) > 1 else "skip"
    asyncio.create_task(watchdog())

    async with AsyncExitStack() as stack:
        if mode != "skip":
            first = await stack.enter_async_context(Server(build_app()))
            await open_session(
                first.url, "FIRST", terminate=(mode != "noterm"), explicit=False
            )
            await first.__aexit__()
            log("first server torn down")

        second = await stack.enter_async_context(Server(build_app()))
        await open_session(
            second.url, "SECOND", terminate=True, explicit=(mode == "timed")
        )
    log("DONE - no hang")


if __name__ == "__main__":
    asyncio.run(main())
