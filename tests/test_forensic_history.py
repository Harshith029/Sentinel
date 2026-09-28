"""Historic forensic data: ownership across restarts, retention, clean shutdown.

Before this, reproduced against the SQLite store with a real restart:

* every restored run was attributed to the DEFAULT tenant. ``acme`` saw none of
  its own history after a restart (its run: 404), while a caller resolving to
  the default tenant listed acme's run and replayed its trace (200);
* nothing ever deleted a trace, so the store grew for the life of the data
  directory;
* shutdown never closed the store, so the newest writes could sit in the WAL
  file, which a backup of the database file alone would miss.
"""
from __future__ import annotations

import json
import sqlite3
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest

from sentinel.config import reset_settings_cache
from sentinel.control.app import create_app
from sentinel.control.manager import RunManager
from sentinel.forensics.store import SqliteForensicStore

_ACME = {"Authorization": "Bearer tok-acme"}
_DEFAULT = {"Authorization": "Bearer tok-default"}
_ADMIN = {"Authorization": "Bearer tok-admin"}


@pytest.fixture(autouse=True)
def _tenants(monkeypatch: pytest.MonkeyPatch) -> None:
    """acme has its own token; the single-tenant token resolves to `default`."""
    monkeypatch.setenv("SENTINEL_API_TOKENS", json.dumps({"acme": "tok-acme"}))
    monkeypatch.setenv("SENTINEL_API_TOKEN", "tok-default")
    monkeypatch.setenv("SENTINEL_ADMIN_TOKEN", "tok-admin")
    reset_settings_cache()


@asynccontextmanager
async def _process() -> AsyncIterator[tuple[httpx.AsyncClient, RunManager]]:
    """One SENTINEL 'process': a manager on the default SQLite store, then shutdown."""
    manager = RunManager()
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=create_app(manager)),
            base_url="http://sentinel",
        ) as client:
            yield client, manager
    finally:
        await manager.aclose()


def _db_path(manager: RunManager) -> Path:
    store = manager._inner_store  # noqa: SLF001
    assert isinstance(store, SqliteForensicStore)
    return store._path  # noqa: SLF001


async def _acme_run() -> tuple[str, Path]:
    async with _process() as (client, manager):
        posted = await client.post("/runs", headers=_ACME, json={"scenario": "hero-obvious"})
        run_id = posted.json()["run_id"]
        await manager.join(run_id)
        return run_id, _db_path(manager)


# --- ownership survives a restart ----------------------------------------------


async def test_a_restart_keeps_each_run_with_its_tenant() -> None:
    run_id, _ = await _acme_run()

    async with _process() as (client, _manager):
        acme = (await client.get("/runs", headers=_ACME)).json()["runs"]
        assert [r["run_id"] for r in acme] == [run_id], "acme lost its own history"
        assert acme[0]["tenant"] == "acme"
        assert (await client.get(f"/runs/{run_id}", headers=_ACME)).status_code == 200

        default = (await client.get("/runs", headers=_DEFAULT)).json()["runs"]
        assert default == [], "another tenant was shown acme's history"
        replay = await client.get(f"/runs/{run_id}/replay", headers=_DEFAULT)
        assert replay.status_code == 404


async def test_a_trace_with_no_recorded_owner_is_nobodys() -> None:
    """History written before ownership was recorded must not be guessed at."""
    run_id, db = await _acme_run()
    with sqlite3.connect(db) as conn:  # as if written by the previous version
        conn.execute("DELETE FROM runs")

    async with _process() as (client, _manager):
        assert (await client.get("/runs", headers=_ACME)).json()["runs"] == []
        assert (await client.get("/runs", headers=_DEFAULT)).json()["runs"] == []
        assert (await client.get(f"/runs/{run_id}/replay", headers=_DEFAULT)).status_code == 404

        # The operator still sees it: history is hidden from tenants, not lost.
        admin = (await client.get("/runs", headers=_ADMIN)).json()["runs"]
        assert [(r["run_id"], r["tenant"]) for r in admin] == [(run_id, None)]


# --- retention -----------------------------------------------------------------


def _age(db: Path, trace_id: str, days: float) -> None:
    """Backdate every span of a trace, as if it had been written ``days`` ago."""
    stamp = (datetime.now(UTC) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    with sqlite3.connect(db) as conn:
        conn.execute(
            "UPDATE spans SET body = json_set(body, '$.timestamp', ?) WHERE trace_id = ?",
            (stamp, trace_id),
        )


async def _spans(db: Path, trace_id: str) -> int:
    with sqlite3.connect(db) as conn:
        row = conn.execute("SELECT COUNT(*) FROM spans WHERE trace_id = ?", (trace_id,))
        return int(row.fetchone()[0])


async def test_traces_past_retention_are_deleted_whole_and_newer_ones_kept(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SENTINEL_FORENSIC_RETENTION_DAYS", "30")
    reset_settings_cache()
    old, db = await _acme_run()
    recent, _ = await _acme_run()
    _age(db, old, days=31)
    _age(db, recent, days=29)

    async with _process() as (client, manager):
        listed = (await client.get("/runs", headers=_ACME)).json()["runs"]
        assert [r["run_id"] for r in listed] == [recent]
        assert manager.get_run(old) is None, "the run index kept a purged trace"
    assert await _spans(db, old) == 0, "an expired trace was left (or left partly)"
    assert await _spans(db, recent) > 0
    with sqlite3.connect(db) as conn:
        owners = {r[0] for r in conn.execute("SELECT trace_id FROM runs")}
    assert owners == {recent}, "the ownership record outlived its trace"


async def test_a_run_in_flight_is_never_purged(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTINEL_FORENSIC_RETENTION_DAYS", "1")
    reset_settings_cache()
    run_id, db = await _acme_run()
    _age(db, run_id, days=5)

    async with _process() as (_client, manager):
        store = manager._inner_store  # noqa: SLF001
        assert isinstance(store, SqliteForensicStore)
        cutoff = datetime.now(UTC) - timedelta(days=1)
        assert await store.purge_older_than(cutoff, keep=frozenset({run_id})) == []
        assert await _spans(db, run_id) > 0


async def test_retention_zero_keeps_everything(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTINEL_FORENSIC_RETENTION_DAYS", "0")
    reset_settings_cache()
    run_id, db = await _acme_run()
    _age(db, run_id, days=3650)

    async with _process() as (client, _manager):
        listed = (await client.get("/runs", headers=_ACME)).json()["runs"]
        assert [r["run_id"] for r in listed] == [run_id]


# --- shutdown ------------------------------------------------------------------


async def test_shutdown_leaves_a_self_contained_database_file(tmp_path: Path) -> None:
    """After a clean shutdown the .db file alone holds everything written.

    That is what makes copying the file a valid backup of a stopped service.
    """
    run_id, db = await _acme_run()
    wal = db.with_name(db.name + "-wal")
    assert not wal.exists() or wal.stat().st_size == 0, "writes left in the WAL"

    copy = tmp_path / "backup.db"
    copy.write_bytes(db.read_bytes())  # the database file ONLY
    with sqlite3.connect(copy) as conn:
        spans = conn.execute("SELECT COUNT(*) FROM spans WHERE trace_id = ?", (run_id,))
        assert spans.fetchone()[0] > 0
        owner = conn.execute("SELECT tenant FROM runs WHERE trace_id = ?", (run_id,))
        assert owner.fetchone() == ("acme",)


async def test_a_store_passed_in_is_left_open_for_its_owner(tmp_path: Path) -> None:
    store = SqliteForensicStore(tmp_path / "mine.db")
    manager = RunManager(store=store)
    await manager.aclose()
    assert await store.list_trace_ids() == []  # still usable: not ours to close
    store.close()
