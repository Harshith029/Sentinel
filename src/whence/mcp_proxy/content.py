"""Shared helpers for shaping MCP tool results and errors.

Kept in one place so the thin skeleton (Phase 1) and the real proxy core
(Phase 4) summarize results and signal blocks identically.
"""
from __future__ import annotations

from typing import Final

import mcp.types as mcp_types

_SUMMARY_LIMIT: Final[int] = 500


def summarize_result(result: mcp_types.CallToolResult) -> str:
    """Flatten a CallToolResult's text content into a short forensic summary."""
    # isinstance narrows the ContentBlock union to the one member with `.text`.
    texts = [
        block.text for block in result.content if isinstance(block, mcp_types.TextContent)
    ]
    summary = (
        " ".join(texts)
        if texts
        else f"<non-text result: {len(result.content)} block(s)>"
    )
    if result.isError:
        summary = f"[error] {summary}"
    if len(summary) > _SUMMARY_LIMIT:
        summary = summary[:_SUMMARY_LIMIT] + "…"
    return summary


def result_text(result: mcp_types.CallToolResult) -> str:
    """The full (untruncated) text of a result — used for shield inspection."""
    return "\n".join(
        block.text for block in result.content if isinstance(block, mcp_types.TextContent)
    )


def mcp_error(message: str) -> mcp_types.CallToolResult:
    """A clean MCP tool error (``isError=True``) carrying a human-readable reason.

    This is how Whence signals a block to the agent at the MCP message boundary:
    a normal tool *result* flagged as an error, not a transport exception. The
    agent's ``ClientSession.call_tool`` returns it with ``isError=True``.
    """
    return mcp_types.CallToolResult(
        content=[mcp_types.TextContent(type="text", text=message)],
        isError=True,
    )
