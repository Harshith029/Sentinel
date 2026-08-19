"""Real-cloud Foundry wiring (BUILD_SPEC §6, §Phase 8) — AZURE MODE only.

This is the seam where a LIVE Microsoft Foundry agent plugs into the same
pipeline. In real-cloud mode the topology is::

    Foundry Agent Service  --MCP/HTTP-->  SENTINEL (only reachable endpoint)
                                              --MCP-->  isolated tool servers

i.e. the agent reaches every tool ONLY through SENTINEL, registered as the
agent's MCP tool server. :func:`build_sentinel_mcp_tool` produces that
registration using the ``MCPTool`` surface confirmed in Phase 0
(``azure.ai.projects.models.MCPTool``; ``require_approval`` on the tool;
``allowed_tools`` enumerated EXPLICITLY rather than relying on empty-list
semantics, per §6).

HONESTY (per the spec's fail-loudly rule): the registration construction here is
correct against the installed ``azure-ai-projects==2.0.0`` (verified by building
the object). What is NOT exercised in this offline build is the END-TO-END live
run — it requires (a) SENTINEL's MCP server exposed over a real HTTP transport at
``SENTINEL_MCP_URL`` and (b) a live Foundry project + credentials. The stage demo
therefore stays on DEMO MODE (the deterministic :class:`ScriptedAgentDriver`),
which runs the IDENTICAL provenance/authorization/trust/forensic pipeline — only
the agent driver differs. Do not read this module as "tested against live
Foundry"; it is the SDK-correct wiring ready for that environment.
"""
from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from azure.ai.projects.models import MCPTool

# The tools SENTINEL proxies. Enumerated explicitly at registration (§6): we do
# NOT rely on allowed_tools=[] meaning "all" — empty may mean deny-all on some
# surfaces, so we always pass the concrete list.
PROXIED_TOOLS: tuple[str, ...] = (
    "web_fetch",
    "send_email",
    "get_customer_record",
    "delete_record",
    "transfer_funds",
)


def build_sentinel_mcp_tool(
    *,
    server_url: str,
    allowed_tools: Sequence[str] = PROXIED_TOOLS,
    require_approval: str = "never",
    server_label: str = "sentinel",
) -> MCPTool:
    """Build the ``MCPTool`` registration that points a Foundry agent at SENTINEL.

    ``require_approval="never"`` because UI approvals do not persist in automated
    runs (§6). ``allowed_tools`` is always an explicit non-empty list. Lazy import
    keeps DEMO MODE free of the Azure dependency at call sites that never deploy.
    """
    from azure.ai.projects.models import MCPTool

    tool = MCPTool(
        server_label=server_label,
        server_url=server_url,
        allowed_tools=list(allowed_tools),
    )
    # require_approval lives on the tool itself (confirmed in Phase 0).
    tool.require_approval = require_approval  # type: ignore[assignment]
    return tool


def foundry_registration_summary(*, server_url: str) -> dict[str, Any]:
    """Inspectable description of how SENTINEL is registered with Foundry.

    Used by the control plane / README to SHOW the real-cloud wiring without
    requiring a live project. Construction is exercised against the installed SDK
    when available; otherwise the static shape is returned (offline-safe).
    """
    summary: dict[str, Any] = {
        "server_label": "sentinel",
        "server_url": server_url,
        "require_approval": "never",
        "allowed_tools": list(PROXIED_TOOLS),
        "note": (
            "Agent reaches every tool ONLY through SENTINEL; tool servers have no "
            "external ingress. SDK: azure.ai.projects.models.MCPTool."
        ),
    }
    try:
        tool = build_sentinel_mcp_tool(server_url=server_url)
        summary["sdk_constructed"] = True
        summary["server_label"] = tool.server_label
    except Exception:  # noqa: BLE001 - offline / SDK absent → return the static shape
        summary["sdk_constructed"] = False
    return summary
