"""A policy replaced through the API survives a restart, and every attempt is on record.

``POST /tenants/{tenant}/policy`` used to swap the compiled policy in memory
only: a restart silently put the configured file back, and nothing recorded
that the policy had changed or that anyone had tried (review F21).
"""
from __future__ import annotations

import asyncio
import json
import os
import time
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
import pytest

import sentinel.control.manager as manager_module
from sentinel.authorization.engine import ToolCall
from sentinel.authorization.policy import PolicyLoadError
from sentinel.config import reset_settings_cache
from sentinel.control.app import create_app
from sentinel.control.manager import RunManager, saved_policy_dir
from sentinel.forensics.events import PolicyChanged
from sentinel.forensics.store import InMemoryForensicStore

ACME = "acme-token"  # noqa: S105 - fixed literals are the point of these tests
GLOBEX = "globex-token"  # noqa: S105
ADMIN = "operator-token"  # noqa: S105


def _policy(version: int, *, stop: bool = False) -> str:
    """A policy for web_fetch: allowed, or (``stop``) always denied."""
    rules = "\n      - id: emergency-stop\n        deny_always: true" if stop else " []"
    return f"policy_version: {version}\ntools:\n  web_fetch:\n    rules:{rules}\n"


def _decision(manager: RunManager, tenant: str) -> str:
    engine = manager.registry.engine_for(tenant)
    assert engine is not None
    return engine.authorize(ToolCall(name="web_fetch")).decision


@pytest.fixture(autouse=True)
def _fresh_settings() -> Iterator[None]:
    reset_settings_cache()
    yield
    reset_settings_cache()


def _env(monkeypatch: pytest.MonkeyPatch, **values: str) -> None:
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    reset_settings_cache()


async def _policy_changes(manager: RunManager, tenant: str) -> list[PolicyChanged]:
    """The PolicyChanged records in ``tenant``'s history, oldest first."""
    found: list[PolicyChanged] = []
    for record in manager.list_runs():
        if record.scenario != "policy-change" or record.tenant != tenant:
            continue
        for span in (await manager.replay(record.trace_id)).ordered:
            assert isinstance(span.payload, PolicyChanged)
            found.append(span.payload)
    return found


async def test_an_applied_reload_survives_a_restart() -> None:
    first = RunManager(store=InMemoryForensicStore())
    await first.reload_policy("acme", _policy(5, stop=True))
    assert _decision(first, "acme") == "DENY"
    await first.aclose()

    restarted = RunManager(store=InMemoryForensicStore())
    assert restarted.registry.version("acme") == 5
    assert _decision(restarted, "acme") == "DENY"
    await restarted.aclose()


async def test_a_configured_file_with_a_higher_version_beats_the_saved_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configured = tmp_path / "acme.yaml"
    configured.write_text(_policy(3), encoding="utf-8")
    _env(monkeypatch, SENTINEL_TENANT_POLICIES=json.dumps({"acme": str(configured)}))

    first = RunManager(store=InMemoryForensicStore())
    await first.reload_policy("acme", _policy(5, stop=True))
    await first.aclose()
    assert RunManager(store=InMemoryForensicStore()).registry.version("acme") == 5

    # The operator bumps the file past the saved copy: the file wins again.
    configured.write_text(_policy(7), encoding="utf-8")
    restarted = RunManager(store=InMemoryForensicStore())
    assert restarted.registry.version("acme") == 7
    assert _decision(restarted, "acme") == "ALLOW"
    await restarted.aclose()


async def test_every_attempt_is_recorded() -> None:
    manager = RunManager(store=InMemoryForensicStore())
    await manager.reload_policy("acme", _policy(2))
    await manager.reload_policy("acme", _policy(1))  # not newer
    with pytest.raises(PolicyLoadError):
        await manager.reload_policy("acme", "policy_version: 3\ntools: [not, a, mapping]\n")

    changes = await _policy_changes(manager, "acme")
    assert [c.outcome for c in changes] == ["applied", "ignored", "rejected"]
    assert [(c.previous_version, c.version) for c in changes] == [(None, 2), (2, 1), (2, None)]
    assert all(len(c.policy_sha256) == 64 for c in changes)
    assert manager.registry.version("acme") == 2
    await manager.aclose()


@asynccontextmanager
async def _client(monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[httpx.AsyncClient]:
    _env(
        monkeypatch,
        SENTINEL_API_TOKEN="",
        SENTINEL_API_TOKENS=json.dumps({"acme": ACME, "globex": GLOBEX}),
        SENTINEL_ADMIN_TOKEN=ADMIN,
        SENTINEL_ALLOW_ANONYMOUS="0",
    )
    manager = RunManager(store=InMemoryForensicStore())
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=create_app(manager)),
            base_url="http://testserver",
        ) as client:
            yield client
    finally:
        await manager.aclose()


async def test_the_record_belongs_to_the_tenant_whose_policy_changed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async with _client(monkeypatch) as client:
        admin = {"Authorization": f"Bearer {ADMIN}"}
        # Newer than the bundled policy acme starts with (its credential gives
        # it the deployment policy).
        reply = await client.post(
            "/tenants/acme/policy", json={"policy": _policy(10)}, headers=admin
        )
        assert reply.status_code == 200
        assert reply.json()["reloaded"] is True

        acme = (await client.get("/runs", headers={"Authorization": f"Bearer {ACME}"})).json()
        mine = [r for r in acme["runs"] if r["scenario"] == "policy-change"]
        assert len(mine) == 1
        globex = (await client.get("/runs", headers={"Authorization": f"Bearer {GLOBEX}"})).json()
        assert [r for r in globex["runs"] if r["scenario"] == "policy-change"] == []

        audit = (
            await client.get(
                f"/runs/{mine[0]['run_id']}/audit",
                headers={"Authorization": f"Bearer {ACME}"},
            )
        ).json()
        [alert] = audit["alerts"]
        assert alert["alert_type"] == "PolicyChanged"
        assert (alert["outcome"], alert["policy_version"], alert["severity"]) == (
            "applied", 10, "medium",
        )


async def test_any_tenant_name_is_saved_inside_the_directory_without_collisions() -> None:
    manager = RunManager(store=InMemoryForensicStore())
    names = {"../escape": 2, "acme": 3, "ACME": 4, "Acme Corp/EU": 5}
    for tenant, version in names.items():
        await manager.reload_policy(tenant, _policy(version))
    await manager.aclose()

    directory = saved_policy_dir().resolve()
    saved = sorted(directory.iterdir())
    assert len(saved) == len(names)  # one file each: no name reached another's
    assert all(path.parent == directory for path in saved)
    assert not (directory.parent / "escape.json").exists()

    restarted = RunManager(store=InMemoryForensicStore())
    assert {t: restarted.registry.version(t) for t in names} == names
    await restarted.aclose()


async def test_a_failed_save_changes_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    manager = RunManager(store=InMemoryForensicStore())
    await manager.reload_policy("acme", _policy(1))

    def full_disk(tenant: str, text: str, version: int) -> None:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(manager_module, "_save_policy", full_disk)
    with pytest.raises(OSError, match="No space left"):
        await manager.reload_policy("acme", _policy(2, stop=True))

    assert manager.registry.version("acme") == 1
    assert _decision(manager, "acme") == "ALLOW"
    assert [c.outcome for c in await _policy_changes(manager, "acme")] == ["applied", "failed"]
    await manager.aclose()


async def test_the_api_reports_a_failed_save(monkeypatch: pytest.MonkeyPatch) -> None:
    def full_disk(tenant: str, text: str, version: int) -> None:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(manager_module, "_save_policy", full_disk)
    async with _client(monkeypatch) as client:
        reply = await client.post(
            "/tenants/acme/policy",
            json={"policy": _policy(9, stop=True)},
            headers={"Authorization": f"Bearer {ADMIN}"},
        )
    assert reply.status_code == 500
    assert "not applied" in reply.json()["detail"]


async def test_concurrent_reloads_save_the_policy_that_is_enforced(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Interleaved, a slow save of v2 could land after v3's and win the restart."""
    real_save = manager_module._save_policy  # noqa: SLF001

    def slow_for_v2(tenant: str, text: str, version: int) -> None:
        if version == 2:
            time.sleep(0.3)
        real_save(tenant, text, version)

    monkeypatch.setattr(manager_module, "_save_policy", slow_for_v2)
    manager = RunManager(store=InMemoryForensicStore())
    await asyncio.gather(
        manager.reload_policy("acme", _policy(2)),
        manager.reload_policy("acme", _policy(3, stop=True)),
    )
    assert manager.registry.version("acme") == 3
    await manager.aclose()

    restarted = RunManager(store=InMemoryForensicStore())
    assert restarted.registry.version("acme") == 3
    assert _decision(restarted, "acme") == "DENY"
    await restarted.aclose()


def test_a_saved_policy_that_cannot_be_read_stops_startup() -> None:
    directory = saved_policy_dir()
    directory.mkdir(parents=True)
    broken = directory / ("0" * 64 + ".json")
    broken.write_text("{not json", encoding="utf-8")
    with pytest.raises(ValueError, match="repair or delete it") as raised:
        RunManager(store=InMemoryForensicStore())
    assert os.fspath(broken) in str(raised.value)
