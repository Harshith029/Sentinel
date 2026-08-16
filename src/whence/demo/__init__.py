"""The hero demonstration (BUILD_SPEC §Phase 5).

A protected agent (a deterministic scripted driver in DEMO MODE; a live Foundry
driver in real-cloud mode) is MCP-connected to Whence only. Three isolated,
MOCK-transport tool servers sit behind the proxy. The scenarios run the three
attacks — hero exfiltration (obvious + evasion variants), privilege violation,
and trust collapse — through the IDENTICAL production pipeline.

Public surface:
* :mod:`tool_servers` — the mock web_fetch / send_email / records servers, the
  poisoned pages, and the synthetic customer record.
* :mod:`driver`       — the AgentDriver protocol + the deterministic drivers.
* :mod:`preflight`    — downstream health-check + tool-schema cache.
* :mod:`scenario`     — the one pipeline orchestrator + the three attack runs.
"""
from __future__ import annotations
