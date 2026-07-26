"""The default agent path is a real LLM when a key is set, scripted otherwise.

Offline & deterministic: no network. The "key present" case only *constructs* the
live client (no completion call), and the end-to-end case drives the loop with the
built-in SusceptibleStubModel — the same discipline test_phase10 uses.
"""
from __future__ import annotations

import pytest

from sentinel.demo.driver import ScriptedAgentDriver, ToolInvocation
from sentinel.demo.llm_driver import (
    LLMAgentDriver,
    SusceptibleStubModel,
    build_live_model,
    default_agent_driver,
)
from sentinel.demo.scenario import run_demo_session
from sentinel.demo.tool_servers import EVASION_URL

CFG = {"allowed_domains": ["corp.example"], "max_amount": 1000}


def _scripted() -> ScriptedAgentDriver:
    return ScriptedAgentDriver([ToolInvocation("web_fetch", {"url": "https://x.test/"})])


def test_default_falls_back_to_scripted_without_credentials() -> None:
    # conftest clears OPENAI_API_KEY / Azure vars, so no credential is present.
    driver = default_agent_driver(task="do the task", scripted_fallback=_scripted())
    assert isinstance(driver, ScriptedAgentDriver)


def test_default_is_the_llm_when_openai_key_present(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-not-a-real-key")
    driver = default_agent_driver(task="do the task", scripted_fallback=_scripted())
    assert isinstance(driver, LLMAgentDriver)  # real-LLM path selected (constructed only)


def test_local_openai_compatible_endpoint_needs_no_paid_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A local runtime (Ollama/LM Studio/vLLM) or a free-tier provider: base URL
    # only, NO api key. The live path must be selected and pointed at that host.
    monkeypatch.setenv("OPENAI_BASE_URL", "http://localhost:11434/v1")
    monkeypatch.setenv("OPENAI_MODEL", "llama3.2")
    driver = default_agent_driver(task="do the task", scripted_fallback=_scripted())
    assert isinstance(driver, LLMAgentDriver)

    model = build_live_model()
    assert model._model == "llama3.2"
    assert "localhost:11434" in str(model._client.base_url)


async def test_llm_path_blocks_induced_exfiltration_offline() -> None:
    # Drive the REAL agent loop with the offline stand-in: it reads the poisoned
    # page and is induced to send_email — which SENTINEL must block.
    driver = LLMAgentDriver(
        SusceptibleStubModel(poisoned_url=EVASION_URL), task="research the promo page"
    )
    res = await run_demo_session(
        driver, user_input="research the promo page and summarize", authorization_config=CFG
    )
    blocked = [s.payload for s in res.replay.ordered if s.event_type == "ToolBlocked"]
    assert any(b.tool_name == "send_email" for b in blocked)  # type: ignore[attr-defined]
    assert res.outbox == []
