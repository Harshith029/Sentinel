"""Standalone reproduction of the "teardown wedge": mcp, uvicorn and sse-starlette only.

See ``docs/mcp-streamable-http-teardown.md``. While a uvicorn server runs it owns
the process's SIGTERM handler. sse-starlette's shutdown watcher takes that
server's ``should_exit`` for process shutdown and sets the process-wide
``AppStatus.should_exit``, after which every SSE response ends before it starts,
so no later MCP handshake in the process can complete.

Usage::

    python docs/mcp_repro_standalone.py latch   # wait one watcher poll: the next handshake fails
    python docs/mcp_repro_standalone.py fast    # no wait: usually passes, hence "intermittent"
    python docs/mcp_repro_standalone.py fixed   # servers leave signal handlers alone: passes

It exits 1 when the second handshake gets no answer. It uses the same pre-bound
listener and the same explicit HTTP-client ownership as the test harness.
"""
from __future__ import annotations

import asyncio
import contextlib
import faulthandler
import socket
import sys
import time

import httpx
import uvicorn
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.server.fastmcp import FastMCP
from sse_starlette.sse import AppStatus
from starlette.applications import Starlette

_HANDSHAKE_SECONDS = 5.0  # a healthy handshake takes well under a second
_WATCHER_POLL_SECONDS = 0.5  # sse_starlette.sse._shutdown_watcher
_START = time.monotonic()


def log(message: str) -> None:
    print(f"[{time.monotonic() - _START:6.2f}] {message}", flush=True)


def build_app() -> Starlette:
    server = FastMCP("repro")

    @server.tool()
    def ping() -> str:
        return "pong"

    return server.streamable_http_app()


class Server:
    """uvicorn on a pre-bound listening socket."""

    def __init__(self, *, capture_signals: bool) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(128)
        self.port: int = self._sock.getsockname()[1]
        config = uvicorn.Config(
            build_app(),
            host="127.0.0.1",
            port=self.port,
            log_level="error",
            lifespan="on",
            ws="none",
        )
        self._server = uvicorn.Server(config)
        if not capture_signals:  # the fix the test harness uses
            self._server.capture_signals = contextlib.nullcontext  # type: ignore[method-assign]
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


async def handshake(url: str, tag: str) -> bool:
    """Open a session and initialize it, bounded. True if it completed."""
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(None, connect=10.0, pool=10.0),
        follow_redirects=True,  # /mcp answers the MCP POST with a 307 to /mcp/
    ) as client:
        async with streamable_http_client(url, http_client=client) as (read, write, _sid):
            async with ClientSession(read, write) as session:
                try:
                    await asyncio.wait_for(session.initialize(), _HANDSHAKE_SECONDS)
                except TimeoutError:
                    log(f"{tag}: no answer to initialize within {_HANDSHAKE_SECONDS}s")
                    return False
    log(f"{tag}: initialize OK")
    return True


async def main(mode: str) -> int:
    capture = mode != "fixed"
    async with Server(capture_signals=capture) as first:
        await handshake(first.url, "FIRST")
    log(f"first server stopped, AppStatus.should_exit={AppStatus.should_exit}")
    if mode != "fast":
        await asyncio.sleep(2 * _WATCHER_POLL_SECONDS)
        log(f"after a watcher poll, AppStatus.should_exit={AppStatus.should_exit}")

    async with Server(capture_signals=capture) as second:
        ok = await handshake(second.url, "SECOND")
    log("no hang" if ok else "REPRODUCED: the second handshake got no answer")
    return 0 if ok else 1


if __name__ == "__main__":
    faulthandler.dump_traceback_later(60, exit=True)  # never hang the terminal
    chosen = sys.argv[1] if len(sys.argv) > 1 else "latch"
    if chosen not in ("latch", "fast", "fixed"):
        sys.exit(f"unknown mode {chosen!r}; use latch, fast or fixed")
    sys.exit(asyncio.run(main(chosen)))
