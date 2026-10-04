"""The demo surface is off unless asked for (review F13).

`dashboard: false` used to change only a startup message. Every deployment,
production included, served the scenario-run and attack endpoints (any tenant
could start runs; with an LLM configured, on a paid model with arbitrary text),
and served WITHOUT a credential the dashboard and an OpenAPI document listing
all 21 routes. Off, each of these now answers 404, as a missing route does.
"""
from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx
import pytest

from sentinel.cli import serve_dashboard
from sentinel.config import reset_settings_cache
from sentinel.control.app import create_app
from sentinel.control.manager import RunManager
from sentinel.forensics.store import InMemoryForensicStore

TOKEN = {"Authorization": "Bearer s3cret"}

DEMO_POSTS = (
    ("/runs", {"scenario": "hero-obvious"}),
    ("/runs/custom", {"user_input": "hi", "page": "hello"}),
    ("/runs/custom/baseline", {"user_input": "hi", "page": "hello"}),
    ("/attack/hero-obvious", None),
    ("/attack/hero-obvious/baseline", None),
    ("/auth/session", None),
    ("/auth/logout", None),
)
PUBLIC_DEMO_GETS = ("/", "/assets/index.html", "/docs", "/redoc", "/openapi.json")


@asynccontextmanager
async def _production(
    monkeypatch: pytest.MonkeyPatch, *, dashboard: str
) -> AsyncIterator[httpx.AsyncClient]:
    monkeypatch.setenv("SENTINEL_DASHBOARD", dashboard)
    monkeypatch.setenv("SENTINEL_API_TOKEN", "s3cret")
    monkeypatch.setenv("SENTINEL_ALLOW_ANONYMOUS", "0")
    reset_settings_cache()
    manager = RunManager(store=InMemoryForensicStore())
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=create_app(manager)),
            base_url="http://sentinel",
        ) as client:
            yield client
    finally:
        await manager.aclose()


async def test_by_default_the_demo_surface_does_not_exist(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async with _production(monkeypatch, dashboard="0") as client:
        for path in PUBLIC_DEMO_GETS:
            assert (await client.get(path)).status_code == 404, f"{path} is served"
        # Even WITH a valid credential: these are not the operator API.
        for path, body in DEMO_POSTS:
            response = await client.post(path, headers=TOKEN, json=body)
            assert response.status_code == 404, f"POST {path} -> {response.status_code}"
        assert (
            await client.get("/demo/sanitization", headers=TOKEN)
        ).status_code == 404


async def test_the_operator_api_is_unaffected(monkeypatch: pytest.MonkeyPatch) -> None:
    async with _production(monkeypatch, dashboard="0") as client:
        assert (await client.get("/healthz")).status_code == 200
        for path in ("/runs", "/capabilities", "/downstream", "/events"):
            assert (await client.get(path, headers=TOKEN)).status_code == 200, path
        # ...and still requires its credential.
        assert (await client.get("/runs")).status_code == 401


async def test_a_demo_can_turn_it_on(monkeypatch: pytest.MonkeyPatch) -> None:
    async with _production(monkeypatch, dashboard="1") as client:
        assert (await client.get("/")).status_code == 200
        assert (await client.get("/openapi.json")).status_code == 200
        started = await client.post(
            "/runs", headers=TOKEN, json={"scenario": "hero-obvious"}
        )
        assert started.status_code == 200


def test_serve_takes_the_flag_then_the_environment_then_the_file(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("SENTINEL_DASHBOARD", raising=False)
    assert serve_dashboard({}, False) is False
    assert serve_dashboard({"dashboard": True}, False) is True
    assert serve_dashboard({}, True) is True

    monkeypatch.setenv("SENTINEL_DASHBOARD", "0")
    assert serve_dashboard({"dashboard": True}, False) is False  # env beats the file
    assert serve_dashboard({"dashboard": False}, True) is True   # the flag beats both

    monkeypatch.setenv("SENTINEL_DASHBOARD", "maybe")
    with pytest.raises(ValueError, match="SENTINEL_DASHBOARD"):
        serve_dashboard({}, False)
