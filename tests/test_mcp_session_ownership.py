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

import asyncio
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
    monkeypatch: pytest.MonkeyPatch, **gateway_kwargs: Any
) -> AsyncIterator[tuple[httpx.AsyncClient, SentinelGateway, InMemoryForensicStore]]:
    monkeypatch.setenv(
        "SENTINEL_API_TOKENS", json.dumps({"acme": "tok-acme", "globex": "tok-globex"})
    )
    monkeypatch.setenv("SENTINEL_CATALOGUE_RECHECK_SECONDS", "0")
    reset_settings_cache()
    store = InMemoryForensicStore()
    manager = RunManager(store=store)
    try:
        async with SentinelGateway(manager, **gateway_kwargs) as gateway:
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=gateway.handle_asgi),
                base_url="http://sentinel",
            ) as client:
                yield client, gateway, store
    finally:
        await manager.aclose()
        reset_settings_cache()


async def _open_session(client: httpx.AsyncClient, headers: dict[str, str]) -> str:
    opened = await client.post(
        "/",
        headers=headers,
        json=_rpc(
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "agent", "version": "1"},
            },
        ),
    )
    assert opened.status_code == 200
    session = opened.headers["mcp-session-id"]
    ready = await client.post(
        "/",
        headers={**headers, "mcp-session-id": session},
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
            "/",
            headers={**_ACME, "mcp-session-id": session},
            json=_fetch("https://corp.example/acme", 2),
        )
        assert own.status_code == 200

        foreign = await client.post(
            "/",
            headers={**_GLOBEX, "mcp-session-id": session},
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
            "/",
            headers={**_ACME, "mcp-session-id": session},
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
            "/",
            headers={**_ACME, "mcp-session-id": session},
            json=_fetch("https://corp.example/acme", 2),
        )
        assert gone.status_code == 404


async def test_an_unknown_session_id_is_refused_as_before(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async with _gateway(monkeypatch) as (client, _gateway_, _store):
        made_up = await client.post(
            "/",
            headers={**_ACME, "mcp-session-id": "0" * 32},
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


async def test_wire_session_capacity_is_reserved_at_initialize_per_tenant(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Idle initialized sessions count, but one tenant cannot crowd out another."""
    async with _gateway(monkeypatch, max_sessions=1) as (client, gateway, _store):
        acme = await _open_session(client, _ACME)
        assert acme in gateway._transport_sessions  # noqa: SLF001

        # No tools/call was made, yet the SDK transport already exists and must
        # be counted. A second acme initialize is refused before it allocates.
        full = await client.post(
            "/",
            headers=_ACME,
            json=_rpc(
                "initialize",
                {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "agent", "version": "1"},
                },
            ),
        )
        # Refused inside the protocol, so an MCP client raises McpError rather
        # than crashing its transport on an HTTP error status.
        assert full.status_code == 200
        refusal = full.json()
        assert refusal["id"] == 1
        assert refusal["error"]["code"] == -32000
        assert "session limit" in refusal["error"]["message"]
        assert "mcp-session-id" not in full.headers
        assert len(gateway._session_manager._server_instances) == 1  # noqa: SLF001

        # The cap is per tenant: globex gets its own one-slot budget.
        globex = await _open_session(client, _GLOBEX)
        assert globex in gateway._transport_sessions  # noqa: SLF001
        assert len(gateway._session_manager._server_instances) == 2  # noqa: SLF001

        ended = await client.delete("/", headers={**_ACME, "mcp-session-id": acme})
        assert ended.status_code == 200
        assert acme not in gateway._transport_sessions  # noqa: SLF001

        replacement = await _open_session(client, _ACME)
        assert replacement in gateway._transport_sessions  # noqa: SLF001


# --- abandoned sessions are reclaimed -------------------------------------------


async def test_an_abandoned_session_is_reclaimed_after_the_idle_ttl(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A client that goes away without DELETE used to hold its session forever."""
    async with _gateway(monkeypatch, idle_ttl=0.3) as (client, gateway, _store):
        sessions = [await _open_session(client, _ACME) for _ in range(5)]
        live = gateway._session_manager._server_instances  # noqa: SLF001
        assert all(s in live for s in sessions)

        for _ in range(100):
            if not any(s in live for s in sessions):
                break
            await asyncio.sleep(0.02)
        assert not any(s in live for s in sessions), "abandoned sessions were kept"

        gone = await client.post(
            "/",
            headers={**_ACME, "mcp-session-id": sessions[0]},
            json=_fetch("https://corp.example/late", 9),
        )
        assert gone.status_code == 404


async def test_an_active_session_is_not_cut_by_the_idle_ttl(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async with _gateway(monkeypatch, idle_ttl=0.3) as (client, _gateway_, _store):
        session = await _open_session(client, _ACME)
        # Active for well over the TTL, never idle for as long as the TTL.
        for i in range(8):
            await asyncio.sleep(0.1)
            kept = await client.post(
                "/",
                headers={**_ACME, "mcp-session-id": session},
                json=_fetch("https://corp.example/busy", 10 + i),
            )
            assert kept.status_code == 200, f"cut after {0.1 * (i + 1):.1f}s of activity"


# --- the gate comes first, for every connection type ----------------------------


async def test_a_websocket_to_mcp_is_refused_before_the_sdk_sees_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mount("/mcp") routes websockets too, and they used to skip the auth gate.

    The SDK only failed on them because Starlette's Request rejects the scope
    type: an unauthenticated caller reached SDK code, and nothing in SENTINEL
    stood in the way.
    """
    async with _gateway(monkeypatch) as (_client, gateway, _store):
        reached: list[str] = []

        async def spy(scope: Any, receive: Any, send: Any) -> None:
            reached.append(scope["type"])

        monkeypatch.setattr(gateway._session_manager, "handle_request", spy)  # noqa: SLF001
        sent: list[dict[str, Any]] = []

        async def receive() -> dict[str, Any]:
            return {"type": "websocket.connect"}

        async def send(message: dict[str, Any]) -> None:
            sent.append(message)

        await gateway.handle_asgi(
            {"type": "websocket", "path": "/", "headers": [], "query_string": b""},
            receive,
            send,
        )
        assert reached == []
        assert sent and sent[0]["type"] == "websocket.close"


async def test_a_rejected_delete_does_not_orphan_the_owners_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only a DELETE the SDK accepted ends the session.

    The owner record used to be dropped after any DELETE. One the SDK refused
    (here, an unsupported protocol version) left the session alive in the SDK
    but unreachable: every later request from its owner was "unknown session".
    """
    async with _gateway(monkeypatch) as (client, gateway, _store):
        session = await _open_session(client, _ACME)
        refused = await client.delete(
            "/",
            headers={**_ACME, "mcp-session-id": session, "mcp-protocol-version": "1999-01-01"},
        )
        assert refused.status_code >= 400
        assert session in gateway._session_owners  # noqa: SLF001

        listed = await client.post(
            "/",
            headers={**_ACME, "mcp-session-id": session},
            json=_rpc("tools/list", {}, 2),
        )
        assert listed.status_code == 200, listed.text


async def test_unknown_tool_names_do_not_each_recheck_every_downstream(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The SDK re-runs tools/list on a tool-cache miss, and tools/list re-checks.

    So every call naming a tool that does not exist cost a tools/list on every
    downstream server: an agent could multiply its load on them at will.
    """
    async with _gateway(monkeypatch) as (client, gateway, _store):
        session = await _open_session(client, _ACME)
        monitor = gateway._monitor  # noqa: SLF001
        assert monitor is not None
        checks: list[int] = []
        real_check = monitor.check

        async def counting_check(downstream: Any) -> Any:
            checks.append(1)
            return await real_check(downstream)

        monkeypatch.setattr(monitor, "check", counting_check)
        for i in range(5):
            response = await client.post(
                "/",
                headers={**_ACME, "mcp-session-id": session},
                json=_rpc("tools/call", {"name": f"no_such_tool_{i}", "arguments": {}}, 10 + i),
            )
            assert response.status_code == 200
        assert len(checks) <= 1, f"{len(checks)} downstream re-checks for 5 calls"


async def test_a_retired_session_is_told_to_reconnect_not_to_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A retired session used to be told the gateway was at capacity."""

    class _Session:  # weak-referenceable stand-in for the SDK's ServerSession
        pass

    async with _gateway(monkeypatch, idle_ttl=0.2) as (_client, gateway, _store):
        idle, fresh = _Session(), _Session()
        args = {"principal": "p", "tenant": "acme", "transport_reserved": True}
        assert await gateway._proxy_for_session(idle, **args) is not None  # noqa: SLF001
        await asyncio.sleep(0.3)
        # A new session needing room is what retires idle ones.
        assert await gateway._proxy_for_session(fresh, **args) is not None  # noqa: SLF001
        assert await gateway._proxy_for_session(idle, **args) is None  # noqa: SLF001

        message = gateway._no_proxy_message(idle)  # noqa: SLF001
        assert "retired" in message and "new session" in message
        assert "Retry shortly" not in message
        assert "capacity" in gateway._no_proxy_message(_Session())  # noqa: SLF001


def test_the_sdk_still_exposes_the_session_index_the_gateway_reads() -> None:
    """GW-18: owner and reservation release read the SDK's private session index.

    If an SDK upgrade drops it, ended sessions are never released and tenants
    reach their cap for good. This fails first, in CI, instead.
    """
    from mcp.server.lowlevel import Server
    from mcp.server.streamable_http_manager import StreamableHTTPSessionManager

    manager = StreamableHTTPSessionManager(app=Server("probe"))
    assert isinstance(getattr(manager, "_server_instances", None), dict)


async def test_a_missing_session_index_is_logged_not_silent(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    async with _gateway(monkeypatch) as (_client, gateway, _store):
        real = gateway._session_manager  # noqa: SLF001
        gateway._session_manager = object()  # type: ignore[assignment]  # noqa: SLF001
        try:
            with caplog.at_level("ERROR", logger="sentinel.control.mcp_gateway"):
                assert gateway._live_session_ids() is None  # noqa: SLF001
        finally:
            gateway._session_manager = real  # noqa: SLF001
        assert "session index" in caplog.text
