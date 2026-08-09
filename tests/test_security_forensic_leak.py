"""F-01: a BLOCKED exfiltration must not leak through the forensic read side.

The attack these tests encode: a prompt-injected page induces the agent to email a
customer record to an attacker. Authorization correctly refuses the ``send_email``
— but the proposal, its arguments, and the retrieved record were already written to
spans, and the forensic read routes were unauthenticated. So the control plane
turned a *blocked* exfiltration into a *successful* one against anyone who could
reach it.

Every test here asserts on the SYNTHETIC secrets the demo record carries
(``SYNTHETIC_SECRET_MARKERS``: the SSN and API key), across every unauthenticated
read surface: ``/runs``, ``/runs/{id}``, replay, ``/events``, the SSE stream and
``/audit``.
"""
from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx
import pytest

from sentinel.control.app import create_app
from sentinel.control.manager import RunManager
from sentinel.demo.tool_servers import SYNTHETIC_SECRET_MARKERS
from sentinel.forensics.store import InMemoryForensicStore

ATTACKER = "attacker@evil-corp.io"


@asynccontextmanager
async def _client(manager: RunManager) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=create_app(manager))
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


async def _run_blocked_exfiltration(manager: RunManager) -> str:
    """Run the hero attack; returns the run id once the exfil has been blocked."""
    record = manager.start_scenario("hero-evasion")
    await manager.join(record.trace_id)
    return record.run_id


def _assert_no_secrets(blob: str, surface: str) -> None:
    for secret in SYNTHETIC_SECRET_MARKERS:
        assert secret not in blob, (
            f"{surface} leaked protected material ({secret!r}) from a BLOCKED call"
        )


@pytest.fixture
async def manager() -> AsyncIterator[RunManager]:
    mgr = RunManager(store=InMemoryForensicStore())
    try:
        yield mgr
    finally:
        await mgr.aclose()


# --- the leak, surface by surface ---------------------------------------------

async def test_replay_does_not_leak_blocked_secrets(manager: RunManager) -> None:
    run_id = await _run_blocked_exfiltration(manager)
    async with _client(manager) as client:
        body = (await client.get(f"/runs/{run_id}/replay")).text
    _assert_no_secrets(body, "GET /runs/{id}/replay")


async def test_events_do_not_leak_blocked_secrets(manager: RunManager) -> None:
    await _run_blocked_exfiltration(manager)
    async with _client(manager) as client:
        body = (await client.get("/events", params={"since": 0})).text
    _assert_no_secrets(body, "GET /events")


async def test_sse_stream_does_not_leak_blocked_secrets(manager: RunManager) -> None:
    await _run_blocked_exfiltration(manager)
    async with _client(manager) as client:
        body = (
            await client.get("/events/stream", params={"since": 0, "follow": False})
        ).text
    _assert_no_secrets(body, "GET /events/stream")


async def test_run_listing_and_detail_do_not_leak(manager: RunManager) -> None:
    run_id = await _run_blocked_exfiltration(manager)
    async with _client(manager) as client:
        _assert_no_secrets((await client.get("/runs")).text, "GET /runs")
        _assert_no_secrets((await client.get(f"/runs/{run_id}")).text, "GET /runs/{id}")


async def test_audit_export_does_not_leak(manager: RunManager) -> None:
    run_id = await _run_blocked_exfiltration(manager)
    async with _client(manager) as client:
        _assert_no_secrets(
            (await client.get(f"/runs/{run_id}/audit")).text, "GET /audit"
        )
        _assert_no_secrets(
            (await client.get(f"/runs/{run_id}/audit", params={"format": "jsonl"})).text,
            "GET /audit?format=jsonl",
        )


async def test_attacker_recipient_is_not_exposed(manager: RunManager) -> None:
    """The attempted destination is attacker-controlled payload too."""
    run_id = await _run_blocked_exfiltration(manager)
    async with _client(manager) as client:
        body = (await client.get(f"/runs/{run_id}/replay")).text
    assert ATTACKER not in body, "replay exposed the attacker recipient"


# --- the block itself must remain observable ----------------------------------

async def test_redaction_preserves_the_security_signal(manager: RunManager) -> None:
    """Redaction must not blind the operator: the decision, rule and taint stay."""
    run_id = await _run_blocked_exfiltration(manager)
    async with _client(manager) as client:
        replay = (await client.get(f"/runs/{run_id}/replay")).json()

    kinds = [s["payload"]["event_type"] for s in replay["ordered"]]
    assert "ToolBlocked" in kinds and "AuthorizationDecided" in kinds

    blocked = [
        s["payload"] for s in replay["ordered"]
        if s["payload"]["event_type"] == "ToolBlocked"
    ]
    assert any(b["tool_name"] == "send_email" for b in blocked)
    assert any(b["matched_rule_id"] == "block-untrusted-origin" for b in blocked)

    decided = [
        s["payload"] for s in replay["ordered"]
        if s["payload"]["event_type"] == "AuthorizationDecided"
    ]
    denied = [d for d in decided if d["decision"] == "DENY"]
    assert denied and denied[0]["is_tainted"] is True
    assert "RETRIEVED_CONTENT" in denied[0]["effective_provenance"]
