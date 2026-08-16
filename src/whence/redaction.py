"""Redaction of sensitive payload material *before* it is persisted.

Whence exists to stop sensitive data leaving via a tool call. If it then wrote
that same data into a forensic span, a **blocked** exfiltration would become a
**successful** one through the read side — the operator's own audit trail. That is
not a theoretical concern: proposals are recorded before authorization runs, so
the payload of a refused call is exactly what lands in storage.

The rule here is therefore: **raw payload material never reaches the store.**
Redaction happens at span creation (:class:`~whence.forensics.emitter.SpanEmitter`),
not at response time, so there is no unredacted copy at rest to leak later through
a new endpoint, a database dump, or a backup.

What survives redaction is deliberately chosen so the record stays forensically
useful:

* **Argument names** — the shape of the call (``to`` / ``subject`` / ``body``) is
  what an investigator reasons about; the values are what must not escape.
* **Type and length** — distinguishes an empty string from a 4 KB document.
* **A short fingerprint** — a truncated SHA-256, so the *same* secret can be
  correlated across calls and traces without disclosing it. Fingerprints are
  salted per process so they cannot be brute-forced back to a known plaintext by
  someone holding the log.

Decision-relevant metadata (tool name, decision, matched rule, provenance labels,
taint flag) is never redacted: that is the security signal, and blinding the
operator would trade one failure for another.
"""
from __future__ import annotations

import hashlib
import os
from typing import Final

from pydantic import JsonValue

from whence.forensics.events import (
    EventPayload,
    InputReceived,
    ToolCallProposed,
    ToolExecuted,
)

# Per-process salt: fingerprints stay comparable within a deployment's lifetime
# but cannot be matched against a precomputed table of known values.
_SALT: Final[bytes] = os.urandom(16)
_FINGERPRINT_CHARS: Final[int] = 8


def fingerprint(value: str) -> str:
    """Short salted digest — correlate repeats without revealing the content."""
    digest = hashlib.sha256(_SALT + value.encode("utf-8", "replace")).hexdigest()
    return digest[:_FINGERPRINT_CHARS]


def redact_text(value: str) -> str:
    """Replace free text with a descriptor of what was there."""
    return f"<redacted:str:{len(value)}:{fingerprint(value)}>"


def redact_value(value: JsonValue) -> JsonValue:
    """Redact one argument value, preserving enough shape to be useful.

    ``None`` and booleans carry no secret and are kept as-is — they are frequently
    the difference between two policy outcomes. Everything else (strings, numbers,
    and nested structures) is replaced: numbers are redacted too because account
    numbers, amounts and identifiers are exactly the sensitive fields policy
    reasons about.
    """
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, (int, float)):
        return f"<redacted:{type(value).__name__}:{fingerprint(str(value))}>"
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    if isinstance(value, dict):
        return {str(k): redact_value(v) for k, v in value.items()}
    return "<redacted>"  # pragma: no cover - JsonValue admits nothing else


def redact_arguments(arguments: dict[str, JsonValue]) -> dict[str, JsonValue]:
    """Keep the argument NAMES, redact every value."""
    return {name: redact_value(value) for name, value in arguments.items()}


def redact_payload(payload: EventPayload) -> EventPayload:
    """Return ``payload`` with sensitive material replaced.

    Only the three payload types that carry caller/tool data are touched. The
    others are decision metadata and must survive intact — redacting them would
    destroy the audit trail this system exists to produce.
    """
    if isinstance(payload, InputReceived):
        return payload.model_copy(update={"content": redact_text(payload.content)})
    if isinstance(payload, ToolCallProposed):
        return payload.model_copy(
            update={"arguments": redact_arguments(payload.arguments)}
        )
    if isinstance(payload, ToolExecuted):
        return payload.model_copy(
            update={
                "arguments": redact_arguments(payload.arguments),
                "result_summary": redact_text(payload.result_summary),
            }
        )
    return payload
