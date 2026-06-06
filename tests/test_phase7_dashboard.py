"""Phase 7 backend smoke tests — the dashboard's served page + data endpoints.

The dashboard itself is verified in a real browser; these guard the BACKEND
routes it depends on (the served HTML, the real-sanitizer demo endpoint) so they
cannot regress.
"""
from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx

from sentinel.control.app import create_app
from sentinel.control.manager import RunManager


@asynccontextmanager
async def _client() -> AsyncIterator[tuple[httpx.AsyncClient, RunManager]]:
    manager = RunManager()
    transport = httpx.ASGITransport(app=create_app(manager))
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        try:
            yield client, manager
        finally:
            await manager.aclose()


async def test_dashboard_is_served() -> None:
    async with _client() as (client, _):
        resp = await client.get("/")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        # Load-bearing IA must be present in the markup. Match case-insensitively
        # so a visual-craft restyle (e.g. sentence-case headings) cannot break it.
        body = resp.text.lower()
        assert "sentinel" in body
        assert "launch attack" in body
        assert "never persisted" in body
        assert "view full lineage (dag)" in body
        assert "does not protect against" in body


async def test_sanitization_demo_runs_the_real_extractor() -> None:
    async with _client() as (client, _):
        data = (await client.get("/demo/sanitization")).json()
        # Accepted: free-text decimal becomes a SYSTEM-trust typed value.
        assert data["accepted"]["extracted_value"] == "999999"
        assert data["accepted"]["output_label"] == "SYSTEM"
        assert data["accepted"]["cleared_from"] == "poisoned-page"
        # Rejected: free text is refused (None), taint persists.
        assert "None" in data["rejected"]["result"]


async def test_healthz_reports_demo_mode() -> None:
    async with _client() as (client, _):
        data = (await client.get("/healthz")).json()
        assert data["status"] == "ok"
        assert data["mode"] == "DEMO MODE"
