"""Phase 0 smoke tests.

These are intentionally small — Phase 0 only proves the foundation is real:
* DEMO_MODE flag round-trips from env.
* OTel tracer initializes and produces SPEC-COMPLIANT hex IDs (not UUIDs).
* `versions.lock` and `SDK_VERIFICATION.md` exist and are non-empty.
* The SDK facts recorded in `SDK_VERIFICATION.md` still hold against the
  installed packages (the "fail loudly on drift" rule from Phase 0 item 4).
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
from pydantic import ValidationError

from whence.config import Settings, get_settings, reset_settings_cache
from whence.tracing import (
    get_tracer,
    init_tracing,
    new_span_id_hex,
    new_trace_id_hex,
    reset_tracing_for_tests,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


# --- DEMO_MODE flag ---------------------------------------------------------


def test_demo_mode_default_true_when_env_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("WHENCE_DEMO_MODE", raising=False)
    reset_settings_cache()
    s = get_settings()
    assert s.demo_mode is True


@pytest.mark.parametrize("raw", ["0", "false", "FALSE", "no", "off"])
def test_demo_mode_false_values(monkeypatch: pytest.MonkeyPatch, raw: str) -> None:
    monkeypatch.setenv("WHENCE_DEMO_MODE", raw)
    reset_settings_cache()
    assert get_settings().demo_mode is False


@pytest.mark.parametrize("raw", ["1", "true", "TRUE", "yes", "on"])
def test_demo_mode_true_values(monkeypatch: pytest.MonkeyPatch, raw: str) -> None:
    monkeypatch.setenv("WHENCE_DEMO_MODE", raw)
    reset_settings_cache()
    assert get_settings().demo_mode is True


def test_demo_mode_bad_value_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WHENCE_DEMO_MODE", "maybe")
    reset_settings_cache()
    with pytest.raises(ValueError, match="WHENCE_DEMO_MODE"):
        get_settings()


def test_settings_is_frozen() -> None:
    reset_settings_cache()
    s = get_settings()
    assert isinstance(s, Settings)
    with pytest.raises(ValidationError):  # frozen model rejects mutation
        s.demo_mode = False  # type: ignore[misc]


# --- OTel tracer + ID shape -------------------------------------------------


def test_tracer_initializes_and_produces_span() -> None:
    reset_tracing_for_tests()
    init_tracing()
    tracer = get_tracer("whence.tests")
    with tracer.start_as_current_span("smoke") as span:
        ctx = span.get_span_context()
        assert ctx.trace_id != 0
        assert ctx.span_id != 0
        # 128-bit trace id, 64-bit span id (W3C Trace Context).
        assert ctx.trace_id < 2**128
        assert ctx.span_id < 2**64


_TRACE_HEX_RE = re.compile(r"^[0-9a-f]{32}$")
_SPAN_HEX_RE = re.compile(r"^[0-9a-f]{16}$")


def test_new_trace_id_hex_shape() -> None:
    for _ in range(20):
        tid = new_trace_id_hex()
        assert _TRACE_HEX_RE.match(tid), tid


def test_new_span_id_hex_shape() -> None:
    for _ in range(20):
        sid = new_span_id_hex()
        assert _SPAN_HEX_RE.match(sid), sid


def test_trace_ids_are_unique() -> None:
    ids = {new_trace_id_hex() for _ in range(500)}
    # The OTel ID generator is random; 500 draws colliding would mean it's
    # broken or hand-rolled. Asserting a high lower bound rather than ==500
    # lets a freakishly-unlucky CI run pass.
    assert len(ids) > 495


def test_init_tracing_is_idempotent() -> None:
    reset_tracing_for_tests()
    init_tracing()
    init_tracing()  # must not raise
    init_tracing()


# --- Phase 0 artifacts present and non-empty --------------------------------


def test_versions_lock_has_real_pins() -> None:
    lock = REPO_ROOT / "versions.lock"
    assert lock.is_file(), "versions.lock must exist after Phase 0"
    lines = [
        line.strip()
        for line in lock.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]
    assert len(lines) >= 15, "expected the full installed dep set in versions.lock"
    required_exact_pins = {
        "azure-ai-projects==2.0.0",  # spec §3: exact
        "mcp",
        "openai",
        "azure-identity",
        "azure-cosmos",
        "azure-monitor-opentelemetry",
        "opentelemetry-api",
        "opentelemetry-sdk",
        "fastapi",
        "uvicorn",
        "sse-starlette",
        "pyyaml",
        "pytest",
        "pytest-asyncio",
        "httpx",
    }
    # Every required package must be present with an EXACT `==` pin (spec §3:
    # "ALL exact-pinned"). For azure-ai-projects we also assert the exact version.
    for required in required_exact_pins:
        if "==" in required:
            assert required in lines, f"missing exact pin: {required}"
        else:
            matches = [
                line for line in lines if line.split("==", 1)[0].lower() == required.lower()
            ]
            assert matches, f"missing pin for {required!r}"
            assert "==" in matches[0], f"non-exact pin in versions.lock: {matches[0]}"
    # Pydantic must be a 2.x exact pin (spec §3: "pydantic==<resolve, 2.x>").
    pyd = [line for line in lines if line.lower().startswith("pydantic==")]
    assert pyd, "missing pydantic pin"
    assert pyd[0].startswith("pydantic==2."), f"pydantic must be 2.x, got {pyd[0]}"


def test_sdk_verification_records_confirmed_facts() -> None:
    sv = REPO_ROOT / "SDK_VERIFICATION.md"
    assert sv.is_file(), "SDK_VERIFICATION.md must exist after Phase 0"
    text = sv.read_text(encoding="utf-8")
    # Three Phase-0 verification items per the kickoff:
    assert "MCPTool" in text, "must record the actual MCPTool spelling"
    assert "require_approval" in text
    assert "allowed_tools" in text


def test_mcp_tool_import_path_holds_as_documented() -> None:
    """The SDK_VERIFICATION.md file claims MCPTool lives at
    `azure.ai.projects.models.MCPTool`. If a future dep bump breaks that, fail
    loudly here rather than letting Phase 4 hit it at runtime."""
    from azure.ai.projects.models import MCPTool, MCPToolFilter, MCPToolRequireApproval

    public = {n for n in dir(MCPTool) if not n.startswith("_")}
    # The fields BUILD_SPEC §6 names must all exist on the installed class.
    for required_field in (
        "server_label",
        "server_url",
        "allowed_tools",
        "require_approval",
    ):
        assert required_field in public, (
            f"installed MCPTool missing field {required_field!r} — spec §6 "
            f"depends on it. Update SDK_VERIFICATION.md and code if the SDK "
            f"changed."
        )
    # MCPToolFilter / MCPToolRequireApproval are the structured forms.
    assert "tool_names" in dir(MCPToolFilter)
    assert "never" in dir(MCPToolRequireApproval)
    assert "always" in dir(MCPToolRequireApproval)
