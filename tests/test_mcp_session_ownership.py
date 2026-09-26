"""An MCP session belongs to the principal that opened it.

The MCP SDK's streamable-HTTP transport routes a request to a session by its
``Mcp-Session-Id`` alone (PYSEC-2026-3482). SENTINEL authenticates every request
to ``/mcp``, but "holds a valid credential" is not "opened this session". Before
the fix, reproduced against the real transport:

* a ``globex`` credential presenting ``acme``'s session id ran a tool call that
  executed as acme's agent, under acme's tenant, policy and trace;
* the same caller's ``DELETE`` terminated acme's session, so acme's next call
  got ``404 Session has been terminated``.

These drive the real SDK session manager in-process over ASGI (no sockets), so
they are not exposed to the Windows teardown wedge.
"""
from __future__ import annotations

import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import httpx
import pytest

from sentinel.config import reset_settings_cache
from sentinel.control.manager import RunManager
from sentinel.control.mcp_gateway import SentinelGateway
from sentinel.forensics.replay import replay
from sentinel.forensics.store import InMemoryForensicStore

_ACCEPT = "application/json, text/event-stream"
_ACME = {"authorization": "Bearer tok-acme", "accept": _ACCEPT}
_GLOBEX = {"authorization": "Bearer tok-globex", "accept": _ACCEPT}


def _rpc(method: str, params: dict[str, Any], id_: int | None = 1) -> dict[str, Any]:
    message: dict[str, Any] = {"jsonrpc": "2.0", "method": method, "params": params}
    if id_ is not None:
        message["id"] = id_
    return message


def _fetch(url: str, id_: int) -> dict[str, Any]:
    return _rpc("tools/call", {"name": "web_fetch", "arguments": {"url": url}}, id_)


@asynccontextmanager
async def _gateway(
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[tuple[httpx.AsyncClient, SentinelGateway, InMemoryForensicStore]]:
    monkeypatch.setenv(
        "SENTINEL_API_TOKENS", json.dumps({"acme": "tok-acme", "globex": "tok-globex"})
    )
    monkeypatch.setenv("SENTINEL_CATALOGUE_RECHECK_SECONDS", "0")
    reset_settings_cache()
    store = InMemoryForensicStore()
    manager = RunManager(store=store)
    try:
        async with SentinelGateway(manager) as gateway:
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=gateway.handle_asgi),
                base_url="http://sentinel",
            ) as client:
                yield client, gateway, store
    finally:
        await manager.aclose()
        reset_settings_cache()


async def _open_session(client: httpx.AsyncClient, headers: dict[str, str]) -> str:
    opened = await client.post("/", headers=headers, json=_rpc("initialize", {
        "protocolVersion": "2025-06-18", "capabilities": {},
        "clientInfo": {"name": "agent", "version": "1"},
    }))
    assert opened.status_code == 200
    session = opened.headers["mcp-session-id"]
    ready = await client.post(
        "/", headers={**headers, "mcp-session-id": session},
        json=_rpc("notifications/initialized", {}, None),
    )
    assert ready.status_code == 202
    return session


async def _proposed(store: InMemoryForensicStore, gateway: SentinelGateway) -> int:
    """Tool calls recorded across every live trace.

    A count, not the arguments: payloads are redacted before they are stored.
    """
    count = 0
    for tracked in list(gateway._sessions.values()):  # noqa: SLF001
        if tracked.proxy is None:
            continue
        rep = await replay(store, tracked.proxy.trace_id)
        count += sum(1 for s in rep.ordered if s.event_type == "ToolCallProposed")
    return count


async def test_another_principal_cannot_drive_a_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async with _gateway(monkeypatch) as (client, gateway, store):
        session = await _open_session(client, _ACME)
        own = await client.post(
            "/", headers={**_ACME, "mcp-session-id": session},
            json=_fetch("https://corp.example/acme", 2),
        )
        assert own.status_code == 200

        foreign = await client.post(
            "/", headers={**_GLOBEX, "mcp-session-id": session},
            json=_fetch("https://corp.example/globex", 3),
        )
        assert foreign.status_code == 404
        assert foreign.json()["error"]["message"] == "Session not found"
        assert await _proposed(store, gateway) == 1, (
            "the foreign call executed inside the owner's session"
        )


async def test_another_principal_cannot_terminate_a_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async with _gateway(monkeypatch) as (client, _gateway_, _store):
        session = await _open_session(client, _ACME)
        killed = await client.delete("/", headers={**_GLOBEX, "mcp-session-id": session})
        assert killed.status_code == 404

        still_alive = await client.post(
            "/", headers={**_ACME, "mcp-session-id": session},
            json=_fetch("https://corp.example/acme", 2),
        )
        assert still_alive.status_code == 200


async def test_the_owner_can_end_its_own_session(monkeypatch: pytest.MonkeyPatch) -> None:
    async with _gateway(monkeypatch) as (client, gateway, _store):
        session = await _open_session(client, _ACME)
        ended = await client.delete("/", headers={**_ACME, "mcp-session-id": session})
        assert ended.status_code == 200
        assert session not in gateway._session_owners  # noqa: SLF001
        gone = await client.post(
            "/", headers={**_ACME, "mcp-session-id": session},
            json=_fetch("https://corp.example/acme", 2),
        )
        assert gone.status_code == 404


async def test_an_unknown_session_id_is_refused_as_before(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async with _gateway(monkeypatch) as (client, _gateway_, _store):
        made_up = await client.post(
            "/", headers={**_ACME, "mcp-session-id": "0" * 32},
            json=_fetch("https://corp.example/x", 1),
        )
        assert made_up.status_code == 404


async def test_owner_records_are_pruned_only_for_dead_sessions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from sentinel.control import mcp_gateway

    monkeypatch.setattr(mcp_gateway, "_OWNER_PRUNE_THRESHOLD", 2)
    async with _gateway(monkeypatch) as (client, gateway, _store):
        live = [await _open_session(client, _ACME) for _ in range(2)]
        gateway._session_owners["long-gone"] = "p:someone"  # noqa: SLF001
        live.append(await _open_session(client, _ACME))  # crosses the threshold

        owners = gateway._session_owners  # noqa: SLF001
        assert "long-gone" not in owners
        assert all(s in owners for s in live), "a live session lost its owner"
