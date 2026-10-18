"""An unauthenticated deployment refuses forged browser requests (review GW-16).

With no credential configured, nothing told SENTINEL's own dashboard apart from
any other page the operator had open: a page anywhere could POST to a local
anonymous instance, or rebind its DNS name to 127.0.0.1 and drive ``/mcp``.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx
import pytest

from sentinel.config import reset_settings_cache
from sentinel.control.app import create_app
from sentinel.control.manager import RunManager


@asynccontextmanager
async def _client(base_url: str = "http://localhost:8765") -> AsyncIterator[httpx.AsyncClient]:
    manager = RunManager()
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=create_app(manager, enable_mcp_gateway=True)),
            base_url=base_url,
        ) as client:
            yield client
    finally:
        await manager.aclose()


async def test_a_rebound_host_name_is_refused() -> None:
    """A DNS-rebinding page reaches 127.0.0.1 but still sends its own Host."""
    async with _client("http://evil.example") as client:
        assert (await client.get("/runs")).status_code == 421
        rebound = await client.post("/mcp/", json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
        assert rebound.status_code == 421


async def test_a_cross_site_post_is_refused_and_a_same_site_one_is_not() -> None:
    async with _client() as client:
        forged = await client.post(
            "/agents/agent-x/reset", headers={"origin": "https://evil.example"}
        )
        assert forged.status_code == 403
        sandboxed = await client.post("/agents/agent-x/reset", headers={"origin": "null"})
        assert sandboxed.status_code == 403
        own = await client.post(
            "/agents/agent-x/reset", headers={"origin": "http://localhost:8765"}
        )
        assert own.status_code != 403
        no_origin = await client.post("/agents/agent-x/reset")  # curl, an MCP client
        assert no_origin.status_code != 403


async def test_health_checks_answer_under_any_host() -> None:
    async with _client("http://10.0.0.7:10000") as client:
        assert (await client.get("/healthz")).status_code == 200


async def test_declared_hosts_are_served(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTINEL_ALLOWED_HOSTS", "demo.example.org")
    reset_settings_cache()
    try:
        async with _client("https://demo.example.org") as client:
            assert (await client.get("/runs")).status_code == 200
    finally:
        reset_settings_cache()


async def test_an_authenticated_deployment_is_left_to_its_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A page cannot supply the bearer token, so the Host is not checked."""
    monkeypatch.setenv("SENTINEL_API_TOKEN", "tok")
    reset_settings_cache()
    try:
        async with _client("http://evil.example") as client:
            assert (await client.get("/runs")).status_code == 401
            ok = await client.get("/runs", headers={"authorization": "Bearer tok"})
            assert ok.status_code == 200
    finally:
        reset_settings_cache()
