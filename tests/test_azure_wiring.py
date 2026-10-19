"""AZURE-mode wiring selection (verifiable offline; the live calls are not).

These guard the *plumbing* a senior review flagged as overclaimed: that with
Azure configured, the control plane actually selects the Cosmos store and builds
the shield with the Content-Safety endpoint — not that the live Azure services
respond (that needs a subscription and is out of scope here).
"""
from __future__ import annotations

import pytest

from sentinel.config import Settings
from sentinel.control import manager as mgr
from sentinel.forensics.store import CosmosForensicStore, SqliteForensicStore
from sentinel.shield import InputShield


def test_default_store_selects_cosmos_when_azure_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Stub the live container build so no real CosmosClient/credential is created.
    monkeypatch.setattr(mgr, "_build_cosmos_container", lambda _s: object())
    azure = Settings(
        demo_mode=False,
        azure_cosmos_endpoint="https://acct.documents.azure.com:443/",
    )
    assert isinstance(mgr._default_store(azure), CosmosForensicStore)


def test_default_store_uses_sqlite_without_cosmos(
    monkeypatch: pytest.MonkeyPatch, tmp_path: object
) -> None:
    monkeypatch.setenv("SENTINEL_DATA_DIR", str(tmp_path))
    demo = Settings(demo_mode=True)  # no AZURE_COSMOS_ENDPOINT
    assert isinstance(mgr._default_store(demo), SqliteForensicStore)


def test_shield_from_settings_carries_azure_content_safety() -> None:
    azure = Settings(
        demo_mode=False,
        azure_content_safety_endpoint="https://cs.example",
        azure_content_safety_key="k",
    )
    shield = InputShield.from_settings(azure)
    # AZURE MODE shield is actually configured (the prior bug left it unwired).
    assert shield._demo_mode is False  # noqa: SLF001 - wiring assertion
    assert shield._endpoint == "https://cs.example"  # noqa: SLF001


def test_shield_from_settings_is_demo_when_unconfigured() -> None:
    shield = InputShield.from_settings(Settings(demo_mode=True))
    assert shield._demo_mode is True  # noqa: SLF001


def test_an_explicit_azure_shield_is_not_downgraded_by_demo_mode() -> None:
    """Demo mode (the default) used to turn SENTINEL_SHIELD=azure into the local regexes."""
    import pytest

    configured = Settings(
        demo_mode=True,
        shield_backend="azure",
        azure_content_safety_endpoint="https://cs.example",
        azure_content_safety_key="k",
    )
    assert InputShield.from_settings(configured).backend == "azure"
    with pytest.raises(ValueError, match="SENTINEL_SHIELD=azure"):
        InputShield.from_settings(Settings(demo_mode=True, shield_backend="azure"))
    # "auto" in demo mode still picks the free local backend.
    auto = Settings(
        demo_mode=True,
        azure_content_safety_endpoint="https://cs.example",
        azure_content_safety_key="k",
    )
    assert InputShield.from_settings(auto).backend == "local"


def test_cosmos_without_aiohttp_fails_with_the_fix_named(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """It failed at startup with a bare "aiohttp package is not installed"."""
    import importlib.util

    import pytest

    from sentinel.control.manager import _build_cosmos_container

    real_find_spec = importlib.util.find_spec

    def no_aiohttp(name: str, *args: object) -> object:
        return None if name == "aiohttp" else real_find_spec(name, *args)  # type: ignore[arg-type]

    monkeypatch.setattr(importlib.util, "find_spec", no_aiohttp)
    with pytest.raises(RuntimeError, match=r"sentinel-prox\[cosmos\]"):
        _build_cosmos_container(Settings(demo_mode=False, azure_cosmos_endpoint="https://x.example"))
