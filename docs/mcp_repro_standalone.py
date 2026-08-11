"""Standalone: mcp + uvicorn only. No SENTINEL code.

Open and close ONE streamable-HTTP MCP client session, then open a second one
against a DIFFERENT server. The second initialize() never returns.
Usage: python upstream_repro.py [first|skip]
"""
import asyncio, os, socket, sys, time
import httpx
import uvicorn
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.server.fastmcp import FastMCP

T0 = time.monotonic()
def log(m): print(f"[{time.monotonic()-T0:6.2f}] {m}", flush=True)

def make_app():
    m = FastMCP("repro")
    @m.tool()
    def ping() -> str:
        return "pong"
    return m.streamable_http_app()

class Server:
    def __init__(self, app):
        s = socket.socket(); s.bind(("127.0.0.1", 0)); self.port = s.getsockname()[1]; s.close()
        cfg = uvicorn.Config(app, host="127.0.0.1", port=self.port, log_level="error",
                             lifespan="on", ws="none")
        self.srv = uvicorn.Server(cfg); self.srv.install_signal_handlers = lambda: None
    async def __aenter__(self):
        self.task = asyncio.create_task(self.srv.serve())
        while not self.srv.started: await asyncio.sleep(0.02)
        return self
    async def __aexit__(self, *e):
        self.srv.should_exit = True; await self.task
    @property
    def url(self): return f"http://127.0.0.1:{self.port}/mcp"

async def session(url, tag, *, terminate=True, timed=False):
    log(f"{tag}: connecting (terminate_on_close={terminate}, timed={timed})")
    client = httpx.AsyncClient(timeout=httpx.Timeout(5.0)) if timed else None
    async with streamable_http_client(url, http_client=client,
                                      terminate_on_close=terminate) as (r, w, _):
        log(f"{tag}: transport entered")
        async with ClientSession(r, w) as cs:
            log(f"{tag}: session entered -> initialize()")
            await cs.initialize()
            log(f"{tag}: initialize OK")

async def watchdog(n):
    await asyncio.sleep(n); log(f"TIMEOUT: {len(asyncio.all_tasks())} tasks pending"); os._exit(3)

async def main():
    asyncio.create_task(watchdog(25))
    mode = sys.argv[1] if sys.argv[1:] else "skip"
    if mode != "skip":
        async with Server(make_app()) as a:
            await session(a.url, "FIRST", terminate=(mode != "noterm"))
        log("first server torn down")
    async with Server(make_app()) as b:
        await session(b.url, "SECOND", timed=(mode == "timed"))
    log("DONE - no hang")

asyncio.run(main())
