"""Control plane (BUILD_SPEC §Phase 6) — the FastAPI surface the dashboard reads.

This layer is entirely SEPARATE from the MCP interception bus. It does NOT route
tool calls; the proxy intercepts those at the MCP boundary (Phase 4). The control
plane only starts/inspects runs and streams the forensic spans they emit:

* :mod:`events`  — an in-process EventBus + a BroadcastStore that tees every span
  write to it (the source of the live monitor and its gap-free back-fill).
* :mod:`manager` — RunManager: shared pipeline deps, background runs, isolation.
* :mod:`app`     — the FastAPI app: REST endpoints + robust SSE + polling fallback.
"""
from __future__ import annotations
