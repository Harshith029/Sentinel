"""Phase 8 — enterprise hardening: classifier, multi-tenant, capabilities, audit."""
from __future__ import annotations

import textwrap
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx
import pytest

from whence.authorization.policy import PolicyLoadError
from whence.authorization.registry import DEFAULT_TENANT, PolicyRegistry
from whence.classifier.attack_classifier import AttackClassifier, BlockedAttempt
from whence.config import Settings
from whence.control.app import create_app
from whence.control.capabilities import mode_summary
from whence.control.manager import RunManager
from whence.demo.foundry import (
    PROXIED_TOOLS,
    build_whence_mcp_tool,
    foundry_registration_summary,
)

_V3 = "policy_version: 3\ntools: {web_fetch: {rules: []}}\n"
_V5 = "policy_version: 5\ntools: {web_fetch: {rules: []}}\n"
_BAD = "policy_version: 9\ntools: {x: {rules: [{id: r, deny_if: 'amount > max'}]}}\n"


@asynccontextmanager
async def _client() -> AsyncIterator[tuple[httpx.AsyncClient, RunManager]]:
    manager = RunManager()
    transport = httpx.ASGITransport(app=create_app(manager))
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        try:
            yield client, manager
        finally:
            await manager.aclose()


# --- semantic classifier: ONE job, consistent labels -------------------------

async def test_classifier_labels_action_not_vector() -> None:
    c = AttackClassifier(demo_mode=True)
    # The SAME blocked send_email is 'exfiltration' whether or not Layer 1 caught
    # the injection — the label describes the ACTION, not whether the shield fired.
    obvious = await c.classify(
        BlockedAttempt("send_email", "block-untrusted-origin", "authorization",
                       "denied", is_tainted=True, injection_detected=True)
    )
    evasion = await c.classify(
        BlockedAttempt("send_email", "block-untrusted-origin", "authorization",
                       "denied", is_tainted=True, injection_detected=False)
    )
    assert obvious.attack_class == evasion.attack_class == "exfiltration"
    assert obvious.classifier == "rule_based"

    priv = await c.classify(
        BlockedAttempt("delete_record", "never", "authorization", "denied")
    )
    assert priv.attack_class == "privilege_escalation"


# --- multi-tenant policy registry: version-gated hot-reload ------------------

def test_registry_hot_reload_on_version_bump() -> None:
    reg = PolicyRegistry()
    r1 = reg.reload_if_newer("acme", _V3)
    assert r1.reloaded and r1.version == 3 and r1.previous_version is None

    r2 = reg.reload_if_newer("acme", _V3)  # same version → ignored
    assert not r2.reloaded and reg.version("acme") == 3

    r3 = reg.reload_if_newer("acme", _V5)  # bump → hot-reload
    assert r3.reloaded and r3.version == 5 and r3.previous_version == 3

    r4 = reg.reload_if_newer("acme", _V3)  # downgrade → ignored
    assert not r4.reloaded and reg.version("acme") == 5

    with pytest.raises(PolicyLoadError):  # malformed rejected at load…
        reg.reload_if_newer("acme", _BAD)
    assert reg.version("acme") == 5  # …and never becomes active


def test_registry_with_default_seeds_canonical_policy() -> None:
    reg = PolicyRegistry.with_default()
    assert reg.get(DEFAULT_TENANT) is not None
    assert reg.engine_for(DEFAULT_TENANT) is not None
    assert reg.engine_for("nonexistent") is None


# --- DEMO vs AZURE capability matrix -----------------------------------------

def test_capability_matrix_flips_with_mode() -> None:
    demo = mode_summary(Settings(demo_mode=True))
    assert demo["mode"] == "DEMO MODE"
    assert demo["degraded"]  # non-empty: things are degraded without Azure
    keys = {c["key"] for c in demo["capabilities"]}  # type: ignore[union-attr]
    assert {"prompt_shields", "classifier", "persistence", "agent_driver"} <= keys

    azure = mode_summary(Settings(demo_mode=False))
    assert azure["mode"] == "AZURE MODE"
    assert azure["degraded"] == []  # everything lit up


# --- audit endpoint: blocked attempts carry a classifier label ---------------

async def test_audit_endpoint_classifies_blocked_attempts() -> None:
    async with _client() as (client, manager):
        started = (await client.post("/attack/hero-obvious", json={})).json()
        await manager.join(started["trace_id"])
        audit = (await client.get(f"/runs/{started['trace_id']}/audit")).json()

        blocked = [a for a in audit["alerts"] if a["alert_type"] == "ToolBlocked"]
        assert blocked
        assert all("attack_class" in a for a in blocked)
        assert any(a["attack_class"] == "exfiltration" for a in blocked)
        assert all(a["classifier"] == "rule_based" for a in blocked)  # DEMO MODE
        # The classifier did NOT leak into severity (computed independently).
        assert all(a["severity"] == "high" for a in blocked)


async def test_capabilities_and_tenant_endpoints() -> None:
    async with _client() as (client, _):
        caps = (await client.get("/capabilities")).json()
        assert caps["mode"] == "DEMO MODE"

        # default tenant present
        tenants = (await client.get("/tenants")).json()["tenants"]
        assert any(t["tenant"] == "default" for t in tenants)

        # hot-reload via the API
        r1 = (await client.post("/tenants/acme/policy", json={"policy": _V3})).json()
        assert r1["reloaded"] and r1["version"] == 3
        r2 = (await client.post("/tenants/acme/policy", json={"policy": _V5})).json()
        assert r2["reloaded"] and r2["version"] == 5
        bad = await client.post("/tenants/acme/policy", json={"policy": _BAD})
        assert bad.status_code == 400


# --- generic-MCP-proxy claim surfaced as enterprise story --------------------

async def test_generality_surfaced_in_dashboard() -> None:
    async with _client() as (client, _):
        body = (await client.get("/")).text.lower()
        assert "generic mcp security proxy" in body
        assert "any mcp client" in body
        assert "no agent-code modification" in body


# --- Foundry registration is SDK-correct (verified against azure-ai-projects) -

def test_foundry_mcp_tool_registration_constructs() -> None:
    tool = build_whence_mcp_tool(server_url="https://whence.example/mcp")
    assert tool.server_label == "whence"
    assert "web_fetch" in PROXIED_TOOLS and "send_email" in PROXIED_TOOLS

    summary = foundry_registration_summary(server_url="https://whence.example/mcp")
    assert summary["sdk_constructed"] is True
    assert summary["require_approval"] == "never"


def test_phase4_policy_still_loads() -> None:
    # sanity: the inline Phase-4-style extended policy still compiles via load_policy
    from whence.authorization.policy import load_policy

    policy = load_policy(
        textwrap.dedent(
            """
            policy_version: 4
            tools:
              web_fetch: {rules: []}
              send_email:
                rules:
                  - id: block-untrusted-origin
                    deny_if: "RETRIEVED_CONTENT in effective_provenance"
            """
        )
    )
    assert policy.rules_for("web_fetch") == ()
