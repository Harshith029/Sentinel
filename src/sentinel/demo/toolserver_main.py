"""Standalone tool-server entrypoint (BUILD_SPEC §Phase 8 deploy).

Runs ONE mock tool server over streamable HTTP, selected by the
``SENTINEL_TOOL_SERVER`` env var (``web`` / ``email`` / ``records``). In the
Azure Container Apps deployment each of these runs as a SEPARATE container app
with INTERNAL ingress only — no external endpoint — so the only thing that can
reach them is SENTINEL (the topology that enforces the thesis). Locally, the
in-memory transport is used instead, so this entrypoint is exercised only in the
containerized/deployed path.

Run: ``SENTINEL_TOOL_SERVER=web PORT=8000 python -m sentinel.demo.toolserver_main``
"""
from __future__ import annotations

import os

from sentinel.demo.tool_servers import ToolServerState, build_downstream


def main() -> None:
    which = os.environ.get("SENTINEL_TOOL_SERVER", "web")
    servers = build_downstream(ToolServerState())
    if which not in servers:
        raise SystemExit(
            f"unknown SENTINEL_TOOL_SERVER={which!r}; expected one of {sorted(servers)}"
        )
    server = servers[which]
    server.settings.host = "0.0.0.0"  # noqa: S104 - bound inside the isolated ACA env only
    server.settings.port = int(os.environ.get("PORT", "8000"))
    # Streamable HTTP transport so SENTINEL connects as an MCP-over-HTTP client.
    server.run(transport="streamable-http")


if __name__ == "__main__":
    main()
