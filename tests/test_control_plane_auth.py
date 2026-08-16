"""Authentication on the control plane: fail-closed, reads included, SSE usable.

Three properties, each of which was a real hole:

* **Reads were open.** ``/runs``, replay, ``/audit``, trust, ``/events`` and the
  SSE stream answered anyone. Redaction stopped secrets leaking, but the spans
  still map which tools an agent called and which were blocked.
* **Unconfigured meant open.** With no token set, every endpoint answered — so
  forgetting to configure a token was indistinguishable from choosing to have
  none. A live deployment was found in exactly that state.
* **Browsers could not authenticate.** ``EventSource`` cannot send an
  ``Authorization`` header, so a header-only design leaves the dashboard's live
  feed either broken or exempt from auth.
"""
from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx
import pytest

from whence.config import reset_settings_cache
from whence.control.app import SESSION_COOKIE, create_app
from whence.control.manager import RunManager
from whence.forensics.store import InMemoryForensicStore

# noqa justification: a fixed literal is the point — the tests assert that
# this exact value is required and that anything else is refused.
TOKEN = "test-token-not-a-real-secret"  # noqa: S105

# Every route that serves operator data. /healthz and / stay open on purpose:
# a load balancer must be able to probe liveness, and the dashboard shell has to
# load before it can authenticate.
GUARDED_READS = [
    "/runs",
    "/runs/does-not-exist",
    "/runs/does-not-exist/replay",
    "/runs/does-not-exist/audit",
    "/agents/some-agent/trust",
    "/capabilities",
    "/downstream",
    "/tenants",
    "/events",
    "/demo/sanitization",
]


@asynccontextmanager
async def _client(**env: str) -> AsyncIterator[httpx.AsyncClient]:
    """An app built under a specific auth configuration."""
    import os

    previous = {k: os.environ.get(k) for k in env}
    os.environ.update(env)
    reset_settings_cache()
    try:
        app = create_app(RunManager(store=InMemoryForensicStore()))
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://testserver"
        ) as client:
            yield client
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        reset_settings_cache()


async def test_unconfigured_service_refuses_to_serve() -> None:
    """No token and no explicit anonymous opt-in → refuse, do not serve openly.

    This is the shape of the real incident: a public deployment with
    WHENCE_API_TOKEN simply never set. Answering openly makes forgetting to
    configure auth identical to choosing to have none, and the operator gets no
    signal at all. Refusing is loud, and the message says exactly which switch
    to set.
    """
    async with _client(WHENCE_API_TOKEN="", WHENCE_ALLOW_ANONYMOUS="0") as client:
        for path in GUARDED_READS:
            response = await client.get(path)
            assert response.status_code == 503, f"{path} served while unconfigured"
            assert "WHENCE_API_TOKEN" in response.json()["detail"]

        # Mutations too.
        assert (await client.post("/runs", json={"scenario": "hero-obvious"})).status_code == 503

        # Liveness stays answerable, or the platform cannot tell it is up.
        assert (await client.get("/healthz")).status_code == 200


async def test_explicit_anonymous_mode_still_works_for_the_local_demo() -> None:
    """The offline demo is preserved, but only when asked for by name."""
    async with _client(WHENCE_API_TOKEN="", WHENCE_ALLOW_ANONYMOUS="1") as client:
        assert (await client.get("/runs")).status_code == 200
        assert (await client.get("/capabilities")).status_code == 200


async def test_reads_require_a_credential_when_a_token_is_set() -> None:
    """Every data route refuses an anonymous caller, and accepts a valid token."""
    async with _client(
        WHENCE_API_TOKEN=TOKEN, WHENCE_ALLOW_ANONYMOUS="0"
    ) as client:
        for path in GUARDED_READS:
            anonymous = await client.get(path)
            assert anonymous.status_code == 401, f"{path} answered without a credential"
            assert anonymous.headers.get("www-authenticate") == "Bearer"

        authorized = await client.get(
            "/runs", headers={"Authorization": f"Bearer {TOKEN}"}
        )
        assert authorized.status_code == 200

        # A wrong token is refused, not merely a missing one.
        assert (
            await client.get("/runs", headers={"Authorization": "Bearer wrong"})
        ).status_code == 401


async def test_sse_stream_is_gated_and_reachable_by_a_browser() -> None:
    """The live feed is authenticated, and a browser can still authenticate to it.

    ``EventSource`` cannot set headers, so the cookie issued by
    ``POST /auth/session`` is what keeps the SSE stream both gated and usable.
    Without it the honest options would be an open stream or a broken dashboard.
    """
    async with _client(
        WHENCE_API_TOKEN=TOKEN, WHENCE_ALLOW_ANONYMOUS="0"
    ) as client:
        # No credential: the stream is refused like everything else.
        assert (await client.get("/events/stream")).status_code == 401

        # A browser exchanges the token for a session cookie...
        opened = await client.post(
            "/auth/session", headers={"Authorization": f"Bearer {TOKEN}"}
        )
        assert opened.status_code == 200
        cookie = opened.cookies.get(SESSION_COOKIE)
        assert cookie is not None

        # ...which must not be readable by page scripts, or an injected script
        # could exfiltrate the operator's credential.
        set_cookie = opened.headers["set-cookie"].lower()
        assert "httponly" in set_cookie
        assert "samesite=strict" in set_cookie

        # ...and the cookie alone now authenticates a header-less read, which is
        # exactly what EventSource issues.
        assert (await client.get("/events")).status_code == 200

        # Logging out revokes it.
        assert (await client.post("/auth/logout")).status_code == 200
        assert (await client.get("/events")).status_code == 401


async def test_session_cookie_cannot_be_forged() -> None:
    """A made-up cookie value is refused — the cookie is not a bypass."""
    async with _client(
        WHENCE_API_TOKEN=TOKEN, WHENCE_ALLOW_ANONYMOUS="0"
    ) as client:
        client.cookies.set(SESSION_COOKIE, "not-the-token")
        assert (await client.get("/runs")).status_code == 401


@pytest.mark.parametrize("path", ["/healthz", "/"])
async def test_liveness_and_shell_stay_reachable(path: str) -> None:
    """Deliberately open: the platform probes one, the browser loads the other
    before it has any credential to present."""
    async with _client(
        WHENCE_API_TOKEN=TOKEN, WHENCE_ALLOW_ANONYMOUS="0"
    ) as client:
        assert (await client.get(path)).status_code in (200, 404)
