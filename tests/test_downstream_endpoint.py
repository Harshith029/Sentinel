"""The /downstream endpoint: what Whence is actually protecting, made visible.

The product's strongest properties (which servers are connected, which tools were
discovered, which catalogue defenses are active) were previously invisible to an
operator. These tests lock the operator-facing view.
"""
from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from whence.control.app import create_app
from whence.control.manager import RunManager
from whence.control.mcp_gateway import WhenceGateway
from whence.forensics.store import InMemoryForensicStore


def _manager() -> RunManager:
    return RunManager(store=InMemoryForensicStore())


async def test_reports_not_connected_when_gateway_disabled() -> None:
    app = create_app(_manager())
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://t"
    ) as client:
        body = (await client.get("/downstream")).json()
    assert body["mode"] == "not-connected"
    assert body["servers"] == [] and body["tool_count"] == 0
    assert "make serve" in body["detail"]  # tells the operator how to fix it


async def test_dashboard_renders_the_downstream_panel() -> None:
    """The posture must be VISIBLE, so the panel + its loader ship in the page."""
    app = create_app(_manager())
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://t"
    ) as client:
        body = (await client.get("/")).text
    assert 'id="downstream"' in body            # the panel exists
    assert "loadDownstream" in body             # and is populated on load
    assert "catalogue defenses" in body


async def test_describes_connected_downstream_and_active_defenses() -> None:
    manager = _manager()
    try:
        async with WhenceGateway(manager) as gateway:
            described = gateway.describe()
    finally:
        await manager.aclose()

    # bundled example topology (no WHENCE_MCP_SERVERS declared in tests)
    assert described["mode"] == "memory"
    assert described["declared"] is False
    assert described["tool_count"] >= 4
    tools = {t for server in described["servers"] for t in server["tools"]}
    assert {"web_fetch", "send_email", "get_customer_record"} <= tools

    # the catalogue defenses are reported, not merely implied
    checks = described["checks"]
    assert "fails closed" in checks["cross_server_shadowing"]
    assert checks["tool_poisoning"].startswith("strict")  # secure default
    assert "default-denied" in checks["unknown_tools"]


async def test_poisoning_mode_reflects_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from whence.config import reset_settings_cache

    monkeypatch.setenv("WHENCE_CATALOGUE_STRICT", "0")
    reset_settings_cache()
    manager = _manager()
    try:
        async with WhenceGateway(manager) as gateway:
            assert gateway.describe()["checks"]["tool_poisoning"] == "flag-only"
    finally:
        await manager.aclose()
        reset_settings_cache()
