"""The multi-tenant authentication model, end to end.

The first tenant-isolation pass (``5e76a24``) was tested at the level of run
RECORDS and turned out to be broken for the deployment it existed to serve:

1. ``/mcp`` only accepted ``SENTINEL_API_TOKEN``, so with per-tenant tokens every
   agent was refused — the gateway's tenant binding was unreachable.
2. Nothing gave a provisioned tenant a policy, so every run in a per-tenant
   deployment failed with "no policy registered".
3. **Any tenant's credential could replace any tenant's policy**, including the
   default one: globex could install an allow-everything policy for acme. And
   because the token an agent holds was the same token that administers, an
   agent could reset its own quarantine or rewrite its own guardrails.
4. The event feed was not scoped (covered in ``test_tenant_isolation.py``).
5. ``/auth/session`` answered "authentication is disabled" to a valid tenant
   token and issued no cookie, so browsers were locked out.

The fix separates two roles. **Tenant** credentials drive the data plane and
read their own tenant. The **operator** credential (``SENTINEL_ADMIN_TOKEN``) is
the only thing that can change policy or clear a quarantine — so the credential
an agent holds can never switch off its own guardrails.
"""
from __future__ import annotations

import json
import os
import textwrap
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import httpx

from sentinel.config import reset_settings_cache
from sentinel.control.app import SESSION_COOKIE, create_app
from sentinel.control.manager import RunManager
from sentinel.control.mcp_gateway import _request_authorized
from sentinel.forensics.store import InMemoryForensicStore

ACME = "acme-token"  # noqa: S105 - fixed literals are the point of these tests
GLOBEX = "globex-token"  # noqa: S105
ADMIN = "operator-token"  # noqa: S105
TOKENS = json.dumps({"acme": ACME, "globex": GLOBEX})

# Allows everything it names: what an attacker would install to switch off a
# victim tenant's guardrails.
PERMISSIVE = "policy_version: 99\ntools:\n  send_email:\n    rules: []\n"


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


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
    base = {
        "SENTINEL_API_TOKEN": "",
        "SENTINEL_API_TOKENS": "",
        "SENTINEL_ADMIN_TOKEN": "",
        "SENTINEL_TENANT_POLICIES": "",
        "SENTINEL_ALLOW_ANONYMOUS": "0",
    }
    base.update(env)
    previous = {k: os.environ.get(k) for k in base}
    os.environ.update(base)
    reset_settings_cache()
    manager = RunManager(store=InMemoryForensicStore())
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=create_app(manager)),
            base_url="http://testserver",
        ) as client:
            yield client, manager
    finally:
        await _finish_runs(manager)
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        reset_settings_cache()


def _scope(token: str | None) -> dict[str, object]:
    headers = [(b"authorization", f"Bearer {token}".encode())] if token else []
    return {"type": "http", "headers": headers}


# --- 1. /mcp accepts per-tenant credentials -----------------------------------


async def test_mcp_accepts_per_tenant_tokens_and_nothing_else() -> None:
    async with _client(SENTINEL_API_TOKENS=TOKENS, SENTINEL_ADMIN_TOKEN=ADMIN):
        assert _request_authorized(_scope(ACME))
        assert _request_authorized(_scope(GLOBEX))
        assert not _request_authorized(_scope("not-a-token"))
        assert not _request_authorized(_scope(None))
        # The operator credential administers; it is not an agent credential.
        # Keeping the two apart is what stops an agent from administering.
        assert not _request_authorized(_scope(ADMIN))


# --- 2. provisioned tenants can actually run ----------------------------------


async def test_a_provisioned_tenant_can_run() -> None:
    """A tenant with a credential gets the deployment policy unless told otherwise."""
    async with _client(SENTINEL_API_TOKENS=TOKENS) as (client, manager):
        posted = await client.post(
            "/runs", json={"scenario": "hero-obvious"}, headers=_auth(ACME)
        )
        assert posted.status_code == 200, posted.text
        run_id = posted.json()["run_id"]
        await manager.join(run_id)
        record = manager.get_run(run_id)
        assert record is not None
        assert record.status == "completed", record.error


async def test_a_tenant_can_be_given_its_own_policy(tmp_path: Path) -> None:
    policy = tmp_path / "acme.yaml"
    policy.write_text(
        textwrap.dedent(
            """
            policy_version: 77
            tools:
              send_email:
                rules: []
            """
        ).strip(),
        encoding="utf-8",
    )
    async with _client(
        SENTINEL_API_TOKENS=TOKENS,
        SENTINEL_TENANT_POLICIES=json.dumps({"acme": str(policy)}),
    ) as (client, _):
        acme = (await client.get("/tenants", headers=_auth(ACME))).json()["tenants"]
        globex = (await client.get("/tenants", headers=_auth(GLOBEX))).json()["tenants"]
        assert [t["policy_version"] for t in acme] == [77]
        assert [t["policy_version"] for t in globex] != [77]


# --- 3. only the operator administers -----------------------------------------


async def test_a_tenant_cannot_replace_another_tenants_policy() -> None:
    """The critical one: globex installing an allow-everything policy for acme."""
    async with _client(SENTINEL_API_TOKENS=TOKENS, SENTINEL_ADMIN_TOKEN=ADMIN) as (
        client,
        manager,
    ):
        before = manager.registry.version("acme")
        for target in ("acme", "default"):
            refused = await client.post(
                f"/tenants/{target}/policy", json={"policy": PERMISSIVE},
                headers=_auth(GLOBEX),
            )
            assert refused.status_code == 403, f"globex replaced {target}'s policy"
        assert manager.registry.version("acme") == before


async def test_a_tenant_cannot_rewrite_even_its_own_policy() -> None:
    """The token an agent holds must not be able to switch off its own guardrails."""
    async with _client(SENTINEL_API_TOKENS=TOKENS, SENTINEL_ADMIN_TOKEN=ADMIN) as (
        client,
        _,
    ):
        refused = await client.post(
            "/tenants/acme/policy", json={"policy": PERMISSIVE}, headers=_auth(ACME)
        )
        assert refused.status_code == 403


async def test_the_operator_can_change_any_tenants_policy() -> None:
    async with _client(SENTINEL_API_TOKENS=TOKENS, SENTINEL_ADMIN_TOKEN=ADMIN) as (
        client,
        manager,
    ):
        ok = await client.post(
            "/tenants/acme/policy", json={"policy": PERMISSIVE}, headers=_auth(ADMIN)
        )
        assert ok.status_code == 200, ok.text
        assert manager.registry.version("acme") == 99


async def test_an_agent_cannot_clear_its_own_quarantine() -> None:
    """Otherwise the quarantine fixed in F-04b is one HTTP call from undone."""
    async with _client(SENTINEL_API_TOKENS=TOKENS, SENTINEL_ADMIN_TOKEN=ADMIN) as (
        client,
        manager,
    ):
        posted = await client.post(
            "/runs", json={"scenario": "hero-obvious"}, headers=_auth(ACME)
        )
        run_id = posted.json()["run_id"]
        await manager.join(run_id)
        agent = manager.get_run(run_id).agent_id  # type: ignore[union-attr]

        refused = await client.post(f"/agents/{agent}/reset", headers=_auth(ACME))
        assert refused.status_code == 403
        allowed = await client.post(f"/agents/{agent}/reset", headers=_auth(ADMIN))
        assert allowed.status_code == 200


async def test_with_no_operator_credential_nobody_administers() -> None:
    """Per-tenant deployment, no SENTINEL_ADMIN_TOKEN: administration is closed.

    Falling back to "any tenant may administer" is the hole this replaces.
    """
    async with _client(SENTINEL_API_TOKENS=TOKENS) as (client, _):
        refused = await client.post(
            "/tenants/acme/policy", json={"policy": PERMISSIVE}, headers=_auth(ACME)
        )
        assert refused.status_code == 403
        assert "SENTINEL_ADMIN_TOKEN" in refused.text


async def test_a_single_token_deployment_is_its_own_operator() -> None:
    """One token, one tenant: that token is the operator's, as it always was."""
    async with _client(SENTINEL_API_TOKEN=ACME) as (client, manager):
        ok = await client.post(
            "/tenants/default/policy", json={"policy": PERMISSIVE}, headers=_auth(ACME)
        )
        assert ok.status_code == 200, ok.text
        assert manager.registry.version("default") == 99


# --- 5. browsers can sign in with a tenant credential -------------------------


async def test_a_browser_session_works_with_a_tenant_credential() -> None:
    async with _client(SENTINEL_API_TOKENS=TOKENS) as (client, _):
        opened = await client.post("/auth/session", headers=_auth(ACME))
        assert opened.status_code == 200
        assert opened.json()["status"] == "ok", opened.text
        assert opened.cookies.get(SESSION_COOKIE)

        # The cookie authenticates as THAT tenant, not as some other one.
        runs = await client.get("/runs")
        assert runs.status_code == 200
        tenants = (await client.get("/tenants")).json()["tenants"]
        assert {t["tenant"] for t in tenants} <= {"acme"}
