"""A credential sees — and writes — only its own tenant's data.

Multi-tenancy was decorative. ``RunRecord`` carried a ``tenant``, the policy
registry keyed on it, and nothing bound a CALLER to one. Demonstrated before
this change, with a single credential:

    POST /runs tenant=acme     -> 200
    POST /runs tenant=globex   -> 200
    POST /runs tenant=initech  -> 200
    tenants visible to this ONE credential: ['acme', 'globex', 'initech']

The tenant arrived in the request BODY, so it was a claim by the caller rather
than a fact about them: one credential could write into any tenant's history and
read all of it back.

Isolation needs per-tenant credentials, so ``SENTINEL_API_TOKENS`` maps tenant to
token. ``SENTINEL_API_TOKEN`` stays the single-tenant shorthand.
"""
from __future__ import annotations

import json
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx

from sentinel.config import reset_settings_cache
from sentinel.control.app import create_app
from sentinel.control.manager import RunManager
from sentinel.forensics.store import InMemoryForensicStore

ACME = "acme-token"  # noqa: S105 - fixed literals are the point of these tests
GLOBEX = "globex-token"  # noqa: S105
TOKENS = json.dumps({"acme": ACME, "globex": GLOBEX})


async def _finish_runs(manager: RunManager) -> None:
    """Let every background run complete, then close the manager.

    Completing rather than cancelling matters here. Work killed mid-flight
    along with its event loop is the one lead on the open Windows wedge
    (docs/mcp-streamable-http-teardown.md): the hang rate rose when tests
    abandoned runs and fell when they stopped doing so.
    """
    import asyncio

    await asyncio.gather(
        *(manager.join(r.run_id) for r in manager.list_runs()), return_exceptions=True
    )
    await manager.aclose()


@asynccontextmanager
async def _client(**env: str) -> AsyncIterator[tuple[httpx.AsyncClient, RunManager]]:
    previous = {k: os.environ.get(k) for k in env}
    os.environ.update(env)
    reset_settings_cache()
    manager = RunManager(store=InMemoryForensicStore())
    try:
        app = create_app(manager)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://testserver"
        ) as client:
            yield client, manager
    finally:
        # POST /runs starts each scenario as a BACKGROUND task, and this app has
        # no lifespan to stop them. Abandoning them mid-flight — in-memory MCP
        # servers and all — on an event loop pytest is about to destroy measurably
        # raised the rate of the open Windows wedge. Let them FINISH, then close.
        await _finish_runs(manager)
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        reset_settings_cache()


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _seed(client: httpx.AsyncClient, token: str) -> str:
    """Start a run as the given credential; returns its run id."""
    response = await client.post(
        "/runs", json={"scenario": "hero-obvious"}, headers=_auth(token)
    )
    assert response.status_code == 200, response.text
    return str(response.json()["run_id"])


async def test_each_credential_sees_only_its_own_runs() -> None:
    """The headline property: one tenant's runs are invisible to another."""
    async with _client(
        SENTINEL_API_TOKENS=TOKENS, SENTINEL_API_TOKEN="", SENTINEL_ALLOW_ANONYMOUS="0"
    ) as (client, _):
        await _seed(client, ACME)
        await _seed(client, GLOBEX)

        acme_runs = (await client.get("/runs", headers=_auth(ACME))).json()["runs"]
        globex_runs = (await client.get("/runs", headers=_auth(GLOBEX))).json()["runs"]

        assert {r["tenant"] for r in acme_runs} == {"acme"}
        assert {r["tenant"] for r in globex_runs} == {"globex"}
        assert len(acme_runs) == 1
        assert len(globex_runs) == 1


async def test_a_caller_cannot_write_into_another_tenant() -> None:
    """The body's tenant is a claim, and a claim that contradicts the credential
    is refused rather than quietly rewritten — a client asking for a tenant it is
    not is either misconfigured or probing, and both deserve to be told."""
    async with _client(
        SENTINEL_API_TOKENS=TOKENS, SENTINEL_API_TOKEN="", SENTINEL_ALLOW_ANONYMOUS="0"
    ) as (client, _):
        refused = await client.post(
            "/runs",
            json={"scenario": "hero-obvious", "tenant": "globex"},
            headers=_auth(ACME),
        )
        assert refused.status_code == 403
        assert "acme" in refused.text and "globex" in refused.text

        # And nothing landed.
        globex_runs = (await client.get("/runs", headers=_auth(GLOBEX))).json()["runs"]
        assert globex_runs == []


async def test_another_tenants_run_is_404_not_403() -> None:
    """Reading across tenants must not confirm that the run exists.

    A 403 here would leak existence: one tenant could enumerate another's
    activity from the status code alone, without ever reading a payload.
    """
    async with _client(
        SENTINEL_API_TOKENS=TOKENS, SENTINEL_API_TOKEN="", SENTINEL_ALLOW_ANONYMOUS="0"
    ) as (client, _):
        globex_run = await _seed(client, GLOBEX)

        for path in (
            f"/runs/{globex_run}",
            f"/runs/{globex_run}/replay",
            f"/runs/{globex_run}/audit",
        ):
            response = await client.get(path, headers=_auth(ACME))
            assert response.status_code == 404, f"{path} leaked across tenants"

        # The owner still reads it.
        assert (
            await client.get(f"/runs/{globex_run}", headers=_auth(GLOBEX))
        ).status_code == 200


async def test_one_tenant_cannot_reset_anothers_trust() -> None:
    """Reset is the sharp end: clearing a quarantine you do not own re-enables
    an agent that someone else's policy stopped."""
    async with _client(
        SENTINEL_API_TOKENS=TOKENS, SENTINEL_API_TOKEN="", SENTINEL_ALLOW_ANONYMOUS="0"
    ) as (client, manager):
        globex_run = await _seed(client, GLOBEX)
        agent_id = next(
            r.agent_id for r in manager.list_runs() if r.run_id == globex_run
        )

        assert (
            await client.get(f"/agents/{agent_id}/trust", headers=_auth(ACME))
        ).status_code == 404
        # Reset is operator-only now (test_multitenant_auth_model): a tenant is
        # refused before the agent is even looked up, so the 403 says nothing
        # about whether the agent exists.
        assert (
            await client.post(f"/agents/{agent_id}/reset", headers=_auth(ACME))
        ).status_code == 403

        # Its own tenant still can.
        assert (
            await client.get(f"/agents/{agent_id}/trust", headers=_auth(GLOBEX))
        ).status_code == 200


async def test_tenant_listing_is_scoped_too() -> None:
    """``/tenants`` must not enumerate the deployment's other customers."""
    async with _client(
        SENTINEL_API_TOKENS=TOKENS, SENTINEL_API_TOKEN="", SENTINEL_ALLOW_ANONYMOUS="0"
    ) as (client, _):
        listed = (await client.get("/tenants", headers=_auth(ACME))).json()["tenants"]
        assert all(row["tenant"] == "acme" for row in listed)


async def test_an_unknown_credential_authenticates_as_nothing() -> None:
    """A token matching no tenant is refused, not defaulted to one."""
    async with _client(
        SENTINEL_API_TOKENS=TOKENS, SENTINEL_API_TOKEN="", SENTINEL_ALLOW_ANONYMOUS="0"
    ) as (client, _):
        assert (
            await client.get("/runs", headers=_auth("not-a-real-token"))
        ).status_code == 401
        assert (await client.get("/runs")).status_code == 401


async def test_single_token_deployments_bind_to_the_default_tenant() -> None:
    """``SENTINEL_API_TOKEN`` keeps working, as the one-tenant shorthand."""
    async with _client(
        SENTINEL_API_TOKEN=ACME, SENTINEL_API_TOKENS="", SENTINEL_ALLOW_ANONYMOUS="0"
    ) as (client, _):
        await _seed(client, ACME)
        runs = (await client.get("/runs", headers=_auth(ACME))).json()["runs"]
        assert {r["tenant"] for r in runs} == {"default"}


async def test_anonymous_mode_has_no_isolation_and_says_so() -> None:
    """Without a credential there is no tenant to scope to.

    Recorded rather than hidden: an unauthenticated deployment sees everything,
    which is a property of running without authentication and the reason the
    service refuses to start unauthenticated unless asked explicitly.
    """
    async with _client(
        SENTINEL_API_TOKEN="", SENTINEL_API_TOKENS="", SENTINEL_ALLOW_ANONYMOUS="1"
    ) as (client, _):
        for tenant in ("acme", "globex"):
            posted = await client.post(
                "/runs", json={"scenario": "hero-obvious", "tenant": tenant}
            )
            assert posted.status_code == 200
        runs = (await client.get("/runs")).json()["runs"]
        assert {r["tenant"] for r in runs} == {"acme", "globex"}


async def test_the_event_feed_is_scoped_to_the_callers_tenant() -> None:
    """``/events`` and the SSE stream must not leak other tenants' spans.

    Missed by the first pass of tenant isolation, which scoped runs, replay and
    audit but left the event feed global: any authenticated caller could watch
    every tenant's tool calls, decisions and blocks as they happened. Payloads
    were redacted, but WHICH tools a customer's agents call and what gets
    blocked is itself the operator's confidential activity.
    """
    async with _client(
        SENTINEL_API_TOKENS=TOKENS, SENTINEL_API_TOKEN="", SENTINEL_ALLOW_ANONYMOUS="0"
    ) as (client, manager):
        acme_run = await _seed(client, ACME)
        globex_run = await _seed(client, GLOBEX)
        await manager.join(acme_run)
        await manager.join(globex_run)

        polled = (await client.get("/events", headers=_auth(ACME))).json()["events"]
        assert polled, "acme should see its own run's spans"
        traces = {e["span"]["trace_id"] for e in polled}
        assert traces == {acme_run}, f"event feed leaked across tenants: {traces}"

        # The SSE catch-up path goes through the same filter.
        streamed = await client.get(
            "/events/stream", params={"follow": "false"}, headers=_auth(ACME)
        )
        assert streamed.status_code == 200
        assert globex_run not in streamed.text
        assert acme_run in streamed.text
