"""Real (non-mock) tool-server implementations.

The demo tool servers in :mod:`whence.demo.tool_servers` simulate the world
(canned pages, an in-memory outbox, one synthetic record) so the security demo is
reproducible and safe. This package holds the REAL implementations that operate on
arbitrary inputs — a ``web_fetch`` that actually fetches URLs, a records service
backed by a real (synthetic-data) store, and a persistent, guarded email sink.

Both sets satisfy the SAME MCP tool contract, so either can sit behind the proxy's
:class:`~whence.mcp_proxy.router.DownstreamConnection`; selection is by
configuration. The security pipeline (provenance / authorization / trust /
forensics) is unchanged and general either way — these modules only change what
lives *downstream* of it.
"""
from __future__ import annotations
