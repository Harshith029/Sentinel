"""Phase 10 — a real agent tool-use LOOP, with SENTINEL as the backstop.

These tests run the genuine agentic loop (:class:`LLMAgentDriver`): the model is
asked to do a task, it discovers tools, calls them THROUGH SENTINEL, sees the
results, and decides what to do next. The decision to exfiltrate is the *model's*
(here a faithful offline stand-in that is induced by the poisoned page content) —
SENTINEL is what stops the resulting action. This is the missing half of the
ScriptedAgentDriver story: not "we force the bad call", but "the agent is tricked
into the bad call and SENTINEL blocks it anyway."

The live-model path (`OpenAIModelClient`) is credential-gated; its response
parsing is tested here against a faithful fake of the OpenAI response shape, and
its fail-loud behaviour without credentials is asserted.
"""
from __future__ import annotations

import pytest

from sentinel.config import Settings
from sentinel.demo.llm_driver import (
    LiveAgentUnavailable,
    LLMAgentDriver,
    LLMToolCall,
    ModelResponse,
    OpenAIModelClient,
    SusceptibleStubModel,
    build_live_model,
)
from sentinel.demo.scenario import HERO_USER_INPUT, run_demo_session
from sentinel.demo.tool_servers import CLEAN_URL, EVASION_URL, OBVIOUS_URL
from sentinel.forensics.store import InMemoryForensicStore
from sentinel.mcp_proxy.content import result_text


async def _drive(stub: SusceptibleStubModel) -> tuple[LLMAgentDriver, object]:
    driver = LLMAgentDriver(stub, task=HERO_USER_INPUT)
    result = await run_demo_session(
        driver, user_input=HERO_USER_INPUT, store=InMemoryForensicStore()
    )
    return driver, result


async def test_llm_loop_obvious_exfiltration_is_blocked() -> None:
    """The agent fetches the poisoned page, is induced to email the record, BLOCKED."""
    stub = SusceptibleStubModel(poisoned_url=OBVIOUS_URL)
    driver, result = await _drive(stub)

    # The MODEL autonomously issued the kill chain (not a scripted transcript).
    assert stub.issued == ["get_customer_record", "web_fetch", "send_email"]

    # The induced send_email came back as a clean SENTINEL block to the agent.
    blocked = [r for r in result.driver_results if r.isError]
    assert blocked, "expected a blocked tool result"
    assert any("SENTINEL blocked" in result_text(r) for r in blocked)

    # Nothing was exfiltrated, and only the allowed reads hit the downstream.
    assert result.outbox == []
    executed = [name for name, _ in result.executions]
    assert "get_customer_record" in executed
    assert "web_fetch" in executed
    assert "send_email" not in executed  # blocked before it could run

    # The block is on the forensic record, and the model saw it and stood down.
    assert result.payloads("ToolBlocked")
    assert "blocked by security policy" in (driver.transcript[-1]["content"] or "")


async def test_llm_loop_evasion_variant_still_blocked() -> None:
    """The evasion page slips past Layer-1, the model de-obfuscates + sends, BLOCKED.

    This is the thesis end-to-end with a real loop: the shield does NOT flag the
    page, yet the authorization-by-provenance backstop still stops the exfiltration.
    """
    stub = SusceptibleStubModel(poisoned_url=EVASION_URL)
    _driver, result = await _drive(stub)

    # The model was still induced (it de-obfuscated "x (at) y (dot) z").
    assert stub.issued == ["get_customer_record", "web_fetch", "send_email"]

    # Layer-1 shield MISSED the page...
    page_scans = [
        p for p in result.payloads("InjectionScanned")
        if getattr(p, "target", "") == "tool_result:web_fetch"
    ]
    assert page_scans and page_scans[0].attack_detected is False

    # ...but the action was blocked anyway, and nothing left the building.
    assert any("SENTINEL blocked" in result_text(r) for r in result.driver_results if r.isError)
    assert result.outbox == []
    assert result.payloads("ToolBlocked")


async def test_llm_loop_clean_page_induces_no_attack() -> None:
    """A clean page induces NO send_email — the loop doesn't fabricate attacks."""
    stub = SusceptibleStubModel(poisoned_url=CLEAN_URL)
    _driver, result = await _drive(stub)

    assert "send_email" not in stub.issued
    assert result.outbox == []
    assert not result.payloads("ToolBlocked")  # nothing to block


async def test_build_live_model_fails_loud_without_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No key, no live agent — it raises rather than silently degrading."""
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    settings = Settings(demo_mode=True)  # no azure_openai_endpoint/deployment
    with pytest.raises(LiveAgentUnavailable):
        build_live_model(settings)


# --- the live adapter's parsing, tested against a faithful fake response ------


class _FakeFunction:
    def __init__(self, name: str, arguments: str) -> None:
        self.name = name
        self.arguments = arguments


class _FakeToolCall:
    def __init__(self, id: str, name: str, arguments: str) -> None:
        self.id = id
        self.type = "function"
        self.function = _FakeFunction(name, arguments)


class _FakeMessage:
    def __init__(self, content: str | None, tool_calls: list[_FakeToolCall] | None) -> None:
        self.content = content
        self.tool_calls = tool_calls


class _FakeChoice:
    def __init__(self, message: _FakeMessage) -> None:
        self.message = message


class _FakeCompletion:
    def __init__(self, message: _FakeMessage) -> None:
        self.choices = [_FakeChoice(message)]


class _FakeCompletions:
    def __init__(self, message: _FakeMessage) -> None:
        self._message = message
        self.last_kwargs: dict[str, object] = {}

    async def create(self, **kwargs: object) -> _FakeCompletion:
        self.last_kwargs = kwargs
        return _FakeCompletion(self._message)


class _FakeChat:
    def __init__(self, message: _FakeMessage) -> None:
        self.completions = _FakeCompletions(message)


class _FakeOpenAIClient:
    """Faithful to the slice of the OpenAI async client the adapter touches."""

    def __init__(self, message: _FakeMessage) -> None:
        self.chat = _FakeChat(message)


async def test_openai_adapter_parses_tool_calls_from_sdk_shape() -> None:
    """OpenAIModelClient maps the real SDK response shape → ModelResponse."""
    message = _FakeMessage(
        content="calling a tool",
        tool_calls=[_FakeToolCall("tc-1", "web_fetch", '{"url": "https://x.test"}')],
    )
    client = _FakeOpenAIClient(message)
    model = OpenAIModelClient(model="gpt-test", client=client)

    response = await model.complete(
        [{"role": "user", "content": "hi"}],
        [{"type": "function", "function": {"name": "web_fetch"}}],
    )
    assert not response.is_final
    assert response.tool_calls == (
        LLMToolCall(id="tc-1", name="web_fetch", arguments={"url": "https://x.test"}),
    )
    # It forwarded model + tools to the SDK as expected.
    assert client.chat.completions.last_kwargs["model"] == "gpt-test"
    assert client.chat.completions.last_kwargs["tool_choice"] == "auto"


async def test_openai_adapter_final_answer_has_no_tool_calls() -> None:
    """A message with no tool_calls is a final answer."""
    client = _FakeOpenAIClient(_FakeMessage(content="all done", tool_calls=None))
    model = OpenAIModelClient(model="gpt-test", client=client)
    response = await model.complete([{"role": "user", "content": "hi"}], [])
    assert response.is_final
    assert response.text == "all done"
    assert response == ModelResponse(text="all done", tool_calls=())
