"""Real (non-mock) tool-server implementations.

The demo tool servers in :mod:`sentinel.demo.tool_servers` simulate the world
(canned pages, an in-memory outbox, one synthetic record) so the security demo is
reproducible and safe. This package holds the REAL implementations that operate on
arbitrary inputs. So far that is one: a ``web_fetch`` that actually fetches URLs
(:mod:`.web_fetch`). The records and email tools exist only as demo mocks.

Both sets satisfy the SAME MCP tool contract, so either can sit behind the proxy's
:class:`~sentinel.mcp_proxy.router.DownstreamConnection`; selection is by
configuration. The security pipeline (provenance / authorization / trust /
forensics) is unchanged and general either way — these modules only change what
lives *downstream* of it.
"""
from __future__ import annotations
