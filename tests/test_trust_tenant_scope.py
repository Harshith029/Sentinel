"""Trust is kept per (tenant, agent), not per agent id (review F15).

Agent ids are not secrets: callers choose them for scenario runs, and they
appear in logs and exports. Keyed by agent id alone, two tenants that used the
same id shared one trust score. Reproduced before the fix: after acme ran
`agent-x` (score 20), globex started its own runs as `agent-x`, which made
acme's agent "visible" to globex (200) and drove acme's score to 0, below the
quarantine threshold. With enforcement on, that is quarantining another
tenant's agent.
"""
from __future__ import annotations

import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import httpx
import pytest

from sentinel.config import reset_settings_cache
from sentinel.control.app import create_app
from sentinel.control.manager import RunManager
from sentinel.forensics.emitter import SpanEmitter
from sentinel.forensics.store import InMemoryForensicStore
from sentinel.trust.config import load_default_trust_config
from sentinel.trust.scorer import TrustScorer

ACME = {"Authorization": "Bearer tok-acme"}
GLOBEX = {"Authorization": "Bearer tok-globex"}
ADMIN = {"Authorization": "Bearer tok-admin"}


@asynccontextmanager
async def _tenants(
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[tuple[httpx.AsyncClient, RunManager]]:
    monkeypatch.setenv(
        "SENTINEL_API_TOKENS", json.dumps({"acme": "tok-acme", "globex": "tok-globex"})
    )
    monkeypatch.setenv("SENTINEL_ADMIN_TOKEN", "tok-admin")
    reset_settings_cache()
    manager = RunManager(store=InMemoryForensicStore())
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=create_app(manager)), base_url="http://t"
        ) as client:
            yield client, manager
    finally:
        await manager.aclose()


async def _run(client: httpx.AsyncClient, manager: RunManager, headers: dict[str, str],
               scenario: str, agent_id: str) -> None:
    body = {"scenario": scenario, "agent_id": agent_id}
    started: dict[str, Any] = (await client.post("/runs", headers=headers, json=body)).json()
    await manager.join(started["run_id"])


async def test_another_tenant_using_the_same_agent_id_cannot_move_its_score(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async with _tenants(monkeypatch) as (client, manager):
        await _run(client, manager, ACME, "hero-obvious", "agent-x")
        before = (await client.get("/agents/agent-x/trust", headers=ACME)).json()["score"]

        for _ in range(3):
            await _run(client, manager, GLOBEX, "trust-collapse", "agent-x")

        after = (await client.get("/agents/agent-x/trust", headers=ACME)).json()
        assert after["score"] == before, "another tenant's runs moved this agent's score"
        assert after["tenant"] == "acme"

        # What globex sees under that id is its own agent, not acme's.
        theirs = (await client.get("/agents/agent-x/trust", headers=GLOBEX)).json()
        assert theirs["tenant"] == "globex"
        assert theirs["score"] != before


async def test_a_tenant_cannot_name_another_tenant_for_trust(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async with _tenants(monkeypatch) as (client, manager):
        await _run(client, manager, ACME, "hero-obvious", "agent-x")
        asked = await client.get(
            "/agents/agent-x/trust", params={"tenant": "acme"}, headers=GLOBEX
        )
        assert asked.status_code == 403


async def test_the_operator_resets_one_tenants_agent_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async with _tenants(monkeypatch) as (client, manager):
        await _run(client, manager, ACME, "hero-obvious", "agent-x")
        await _run(client, manager, GLOBEX, "hero-obvious", "agent-x")

        reset = await client.post(
            "/agents/agent-x/reset", params={"tenant": "acme"}, headers=ADMIN
        )
        assert reset.status_code == 200
        assert reset.json()["score"] == 100
        globex = (await client.get("/agents/agent-x/trust", headers=GLOBEX)).json()
        assert globex["score"] < 100, "resetting acme's agent reset globex's too"


async def test_the_scorer_keeps_tenants_apart() -> None:
    emitter = SpanEmitter(InMemoryForensicStore())
    scorer = TrustScorer(emitter, load_default_trust_config())
    trace = emitter.new_trace_id()
    for _ in range(3):
        await scorer.record_blocked_call(
            "agent-x", "send_email", reason="denied", trace_id=trace, tenant="globex"
        )
    assert scorer.is_quarantined("agent-x", tenant="globex")
    assert not scorer.is_quarantined("agent-x", tenant="acme")
    assert scorer.score("agent-x", tenant="acme") == 100
