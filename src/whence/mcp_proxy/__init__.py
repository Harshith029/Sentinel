"""Whence's MCP interception layer.

Named ``mcp_proxy`` (not ``mcp``) so it never shadows the installed official
``mcp`` SDK. Phase 1 ships only the *thin skeleton* (:mod:`skeleton`): a no-op
proxy that forwards a tool call and emits ``ToolCallProposed`` + ``ToolExecuted``
spans. Its purpose is to pin Phase 2's provenance/authorization work to REAL MCP
message shapes (``Tool``, ``CallToolResult``, ...) rather than an invented
abstraction. The full security-bearing proxy core lands in Phase 4.
"""
from __future__ import annotations
