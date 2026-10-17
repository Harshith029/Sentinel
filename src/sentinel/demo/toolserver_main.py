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

from mcp.server.transport_security import TransportSecuritySettings

from sentinel.demo.tool_servers import ToolServerState, build_downstream

_LOCAL_MCP_HOSTS = ["127.0.0.1:*", "localhost:*", "[::1]:*"]


def _transport_security(internal_host: str | None) -> TransportSecuritySettings:
    """Keep DNS-rebinding protection while allowing ACA's internal hostname.

    FastMCP captures localhost-only allowed hosts when the mock server is
    constructed. Changing its bind address later does not update that list, so
    ACA's ``<app>/mcp`` requests otherwise receive HTTP 421. The Bicep template
    supplies the exact internal app hostname; local execution retains only the
    loopback patterns.
    """
    allowed_hosts = list(_LOCAL_MCP_HOSTS)
    if internal_host:
        host = internal_host.strip().lower()
        if not host or ":" in host or "/" in host:
            raise ValueError("SENTINEL_MCP_ALLOWED_HOST must be a bare hostname")
        allowed_hosts.extend((host, f"{host}:*"))
    return TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=allowed_hosts,
    )


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
    server.settings.transport_security = _transport_security(
        os.environ.get("SENTINEL_MCP_ALLOWED_HOST")
    )
    # Streamable HTTP transport so SENTINEL connects as an MCP-over-HTTP client.
    server.run(transport="streamable-http")


if __name__ == "__main__":
    main()
