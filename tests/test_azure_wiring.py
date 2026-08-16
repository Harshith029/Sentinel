"""AZURE-mode wiring selection (verifiable offline; the live calls are not).

These guard the *plumbing* a senior review flagged as overclaimed: that with
Azure configured, the control plane actually selects the Cosmos store and builds
the shield with the Content-Safety endpoint — not that the live Azure services
respond (that needs a subscription and is out of scope here).
"""
from __future__ import annotations

import pytest

from whence.config import Settings
from whence.control import manager as mgr
from whence.forensics.store import CosmosForensicStore, SqliteForensicStore
from whence.shield import InputShield


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
    monkeypatch.setenv("WHENCE_DATA_DIR", str(tmp_path))
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
