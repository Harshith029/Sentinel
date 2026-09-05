"""Live MCP sessions get a STABLE, authenticated principal (audit F-04b).

Trust and quarantine are keyed by agent id. Live sessions minted a fresh random
id per connection, so both were scoped to a single TCP conversation: an agent
that tripped quarantine only had to reconnect to be handed a clean score of 100.
The enforcement existed but could not hold, which is worse than not having it —
the dashboard reported a quarantine that the next connection silently discarded.

Identity now derives from the credential the request had to present to reach
``/mcp`` at all. Not from anything the client claims about itself: an agent able
to choose its own identity could shed a quarantine by choosing a different one,
which is the same hole wearing a different hat.
"""
from __future__ import annotations

import gc
from typing import Any

from sentinel.control.manager import RunManager
from sentinel.control.mcp_gateway import SentinelGateway, _principal_id
from sentinel.forensics.store import InMemoryForensicStore


class _FakeSession:
    """Stands in for a transport ``ServerSession`` (weak-referenceable, unique)."""


class _FakeRequest:
    """Just the header surface ``_principal_id`` reads."""

    def __init__(self, authorization: str | None = None) -> None:
        self.headers = {"authorization": authorization} if authorization else {}


async def _quarantine(scorer: Any, agent_id: str, trace_id: str) -> None:
    """Three blocked calls: 100 -> 70 -> 40 -> 10, below the threshold of 40."""
    for _ in range(3):
        await scorer.record_blocked_call(
            agent_id, "send_email", reason="denied",
            trace_id=trace_id, parent_span_id=None,
        )


async def test_quarantine_survives_a_reconnect() -> None:
    """The headline case: reconnecting must not clear a quarantine.

    Observed before the fix — session A quarantined at score 10, session B from
    the same caller opened at 100 and unquarantined. Every hard signal the
    scorer had accumulated was discarded by closing a socket.
    """
    manager = RunManager(store=InMemoryForensicStore())
    gateway = SentinelGateway(manager)
    async with gateway:
        scorer = manager._scorer  # noqa: SLF001
        principal = _principal_id(_FakeRequest("Bearer operator-token"))
        assert principal is not None

        first = _FakeSession()
        proxy_a = await gateway._proxy_for_session(first, principal=principal)  # noqa: SLF001
        assert proxy_a is not None
        await _quarantine(scorer, proxy_a._agent_id, proxy_a._trace_id)  # noqa: SLF001
        assert scorer.is_quarantined(proxy_a._agent_id)  # noqa: SLF001

        del first, proxy_a  # the transport drops the session
        gc.collect()

        # The SAME credential reconnects.
        second = _FakeSession()
        proxy_b = await gateway._proxy_for_session(second, principal=principal)  # noqa: SLF001
        assert proxy_b is not None
        assert scorer.is_quarantined(proxy_b._agent_id), (  # noqa: SLF001
            "reconnecting cleared the quarantine"
        )
        assert scorer.score(proxy_b._agent_id) < 40  # noqa: SLF001


async def test_a_different_credential_is_a_different_principal() -> None:
    """One caller's quarantine must not contaminate another's.

    The mirror of the test above: identity has to be stable AND discriminating,
    or the fix would trade a bypass for a denial of service in which any agent
    could quarantine everyone.
    """
    manager = RunManager(store=InMemoryForensicStore())
    gateway = SentinelGateway(manager)
    async with gateway:
        scorer = manager._scorer  # noqa: SLF001
        bad = _principal_id(_FakeRequest("Bearer token-one"))
        good = _principal_id(_FakeRequest("Bearer token-two"))
        assert bad != good

        s1 = _FakeSession()
        p1 = await gateway._proxy_for_session(s1, principal=bad)  # noqa: SLF001
        assert p1 is not None
        await _quarantine(scorer, p1._agent_id, p1._trace_id)  # noqa: SLF001

        s2 = _FakeSession()
        p2 = await gateway._proxy_for_session(s2, principal=good)  # noqa: SLF001
        assert p2 is not None
        assert not scorer.is_quarantined(p2._agent_id)  # noqa: SLF001


def test_principal_comes_from_the_credential_not_a_client_claim() -> None:
    """Only a bearer credential yields a principal, and it never leaks the token.

    ``/mcp`` accepts nothing but a bearer header, so deriving identity from
    anything else would attribute a session to a principal that never
    authenticated to this endpoint.
    """
    token = "operator-token"  # noqa: S105 - a fixed literal is the point here
    first = _principal_id(_FakeRequest(f"Bearer {token}"))
    again = _principal_id(_FakeRequest(f"Bearer {token}"))
    assert first == again, "the same credential must map to the same principal"
    assert first is not None and token not in first
    assert len(first) == 16

    # Nothing else counts as identity.
    assert _principal_id(_FakeRequest()) is None
    assert _principal_id(_FakeRequest("Basic abc")) is None
    assert _principal_id(_FakeRequest("Bearer ")) is None
    assert _principal_id(None) is None


async def test_anonymous_sessions_do_not_share_a_principal() -> None:
    """With no credential there is no caller to attribute trust to.

    Anonymous sessions stay per-connection ON PURPOSE. Collapsing them into one
    shared principal would let any unauthenticated client quarantine every other
    one. Durable trust needs a durable identity; running without authentication
    means not having one, and this records that consequence rather than hiding
    it.
    """
    manager = RunManager(store=InMemoryForensicStore())
    gateway = SentinelGateway(manager)
    async with gateway:
        a = _FakeSession()
        b = _FakeSession()
        pa = await gateway._proxy_for_session(a, principal=None)  # noqa: SLF001
        pb = await gateway._proxy_for_session(b, principal=None)  # noqa: SLF001
        assert pa is not None and pb is not None
        assert pa._agent_id != pb._agent_id  # noqa: SLF001
        assert pa._agent_id.startswith("anon-")  # noqa: SLF001


async def test_a_released_session_marks_its_run_terminal() -> None:
    """A disconnected agent must stop showing as running in the run index.

    Live runs opened ``status="running"`` and never transitioned, so every
    session a deployment had ever served looked permanently in-flight and an
    operator could not tell a live agent from one that left days ago.
    """
    manager = RunManager(store=InMemoryForensicStore())
    gateway = SentinelGateway(manager)
    async with gateway:
        session = _FakeSession()
        proxy = await gateway._proxy_for_session(session, principal=None)  # noqa: SLF001
        assert proxy is not None
        trace_id = proxy.trace_id
        running = next(r for r in manager.list_runs() if r.trace_id == trace_id)
        assert running.status == "running"

        del session, proxy  # the transport is done with it
        gc.collect()

        record = next(r for r in manager.list_runs() if r.trace_id == trace_id)
        assert record.status == "completed", "a released session left its run running"


async def test_finishing_a_run_never_relabels_a_settled_one() -> None:
    """Idempotent, and only ever moves a run OUT of running.

    The finalizer can fire late and from a GC context, so it must not be able to
    resurrect or relabel a run that some other path already settled.
    """
    manager = RunManager(store=InMemoryForensicStore())
    gateway = SentinelGateway(manager)
    async with gateway:
        session = _FakeSession()
        proxy = await gateway._proxy_for_session(session, principal=None)  # noqa: SLF001
        assert proxy is not None
        manager.finish_live_run(proxy.trace_id, status="failed")
        manager.finish_live_run(proxy.trace_id, status="completed")  # late, ignored
        record = next(r for r in manager.list_runs() if r.trace_id == proxy.trace_id)
        assert record.status == "failed"
