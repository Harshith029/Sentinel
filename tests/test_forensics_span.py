"""Phase 1: the Span envelope — OTel id shape enforcement and invariants."""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from sentinel.forensics.events import ToolCallProposed
from sentinel.forensics.span import Span

VALID_TRACE = "a" * 32
VALID_SPAN = "b" * 16
PAYLOAD = ToolCallProposed(tool_name="x", arguments={})


def _span(**overrides: object) -> Span:
    kwargs: dict[str, object] = {
        "trace_id": VALID_TRACE,
        "span_id": VALID_SPAN,
        "seq": 0,
        "payload": PAYLOAD,
    }
    kwargs.update(overrides)
    return Span(**kwargs)  # type: ignore[arg-type]


def test_valid_span_constructs() -> None:
    span = _span(parent_span_id="c" * 16)
    assert span.trace_id == VALID_TRACE
    assert span.event_type == "ToolCallProposed"
    assert span.is_root is False


def test_root_span_has_no_parent() -> None:
    assert _span().is_root is True


@pytest.mark.parametrize(
    "bad_trace",
    [
        "a" * 31,        # too short
        "a" * 33,        # too long
        "A" * 32,        # uppercase (W3C is lowercase)
        "g" * 32,        # non-hex
        "0" * 32,        # all-zero sentinel
        "",
    ],
)
def test_bad_trace_id_rejected(bad_trace: str) -> None:
    with pytest.raises(ValidationError):
        _span(trace_id=bad_trace)


@pytest.mark.parametrize(
    "bad_span",
    [
        "b" * 15,        # too short
        "b" * 17,        # too long
        "B" * 16,        # uppercase
        "z" * 16,        # non-hex
        "0" * 16,        # all-zero sentinel
    ],
)
def test_bad_span_id_rejected(bad_span: str) -> None:
    with pytest.raises(ValidationError):
        _span(span_id=bad_span)


def test_all_zero_ids_rejected_for_both_trace_and_span() -> None:
    # Explicit, self-documenting case: the W3C all-zero sentinel is the "no
    # trace / no span" marker and must be rejected for BOTH id fields.
    with pytest.raises(ValidationError):
        _span(trace_id="0" * 32)
    with pytest.raises(ValidationError):
        _span(span_id="0" * 16)


def test_bad_parent_span_id_rejected() -> None:
    with pytest.raises(ValidationError):
        _span(parent_span_id="0" * 16)
    with pytest.raises(ValidationError):
        _span(parent_span_id="nothex" + "0" * 10)


def test_negative_seq_rejected() -> None:
    with pytest.raises(ValidationError):
        _span(seq=-1)


def test_span_is_frozen() -> None:
    span = _span()
    with pytest.raises(ValidationError):
        span.seq = 5  # type: ignore[misc]


def test_timestamp_is_timezone_aware() -> None:
    span = _span()
    assert span.timestamp.tzinfo is not None
