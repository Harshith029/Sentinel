"""Operator-facing logging for security decisions.

Forensic spans are the durable record, but they live behind an API. An operator
running ``sentinel serve`` needs to see enforcement happen in the place they are
actually looking: stdout, journald, Docker logs, their aggregator. A security
proxy that blocks silently is undebuggable in production.

What gets logged, and at what level, follows what an operator needs to act on:

* ``WARNING`` — a call was **blocked**, or an agent was **quarantined**. These are
  the lines that should page someone or show up in a filter.
* ``INFO``    — a call was allowed. One line per action, so the audit trail is
  legible without being noisy.
* ``DEBUG``   — detail for diagnosing policy, off by default.

**Payloads are never logged.** This is the load-bearing rule of this module: the
arguments SENTINEL inspects are exactly the sensitive material it exists to
protect — customer records, keys, message bodies. Writing them to a log would
move the secret from a blocked tool call into a plaintext file that is shipped
off-box, i.e. it would perform the exfiltration the proxy just prevented. We log
the *decision* (tool, rule, provenance labels, trace id) and never the data.

Nor does the forensic store hold the payload: spans are redacted at the emitter
before persistence (:mod:`sentinel.redaction`), so what survives there is an
opaque field token, types, lengths and a salted fingerprint — enough to
correlate a call without preserving caller-chosen field names or values.
SENTINEL deliberately keeps no copy of the caller's data anywhere. An earlier
version of this note claimed the store held
"the full payload under access control", which was wrong on both counts: nothing
holds the full payload, and the read endpoints were unauthenticated when it was
written.
"""

from __future__ import annotations

import json
import logging
import re
import sys
from typing import IO, Any, Final, Literal

LogFormat = Literal["text", "json"]

SECURITY_LOGGER: Final[str] = "sentinel.security"
_LOG_CONTROL_CHARS: Final[re.Pattern[str]] = re.compile(r"[\x00-\x1f\x7f-\x9f]")

# Fields the JSON formatter always emits; anything else comes from `extra`.
_STANDARD: Final[frozenset[str]] = frozenset(
    {
        "args",
        "asctime",
        "created",
        "exc_info",
        "exc_text",
        "filename",
        "funcName",
        "levelname",
        "levelno",
        "lineno",
        "module",
        "msecs",
        "message",
        "msg",
        "name",
        "pathname",
        "process",
        "processName",
        "relativeCreated",
        "stack_info",
        "taskName",
        "thread",
        "threadName",
    }
)


class JsonFormatter(logging.Formatter):
    """One JSON object per line — what a log aggregator wants to ingest."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        # Structured fields passed via `extra=` (tool, decision, rule, trace_id…).
        for key, value in record.__dict__.items():
            if key not in _STANDARD and not key.startswith("_"):
                payload[key] = value
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


class TextFormatter(logging.Formatter):
    """Compact, human-scannable lines for a terminal."""

    def format(self, record: logging.LogRecord) -> str:
        stamp = self.formatTime(record, "%H:%M:%S")
        base = f"{stamp} {record.levelname:<7} {record.getMessage()}"
        trace = getattr(record, "trace_id", None)
        if trace:
            base = f"{base}  [trace {str(trace)[:12]}]"
        tenant = getattr(record, "tenant", None)
        if tenant:
            base = f"{base}  [tenant {tenant}]"
        if record.exc_info:
            base = f"{base}\n{self.formatException(record.exc_info)}"
        return base


def configure_logging(
    *, level: str = "INFO", fmt: LogFormat = "text", stream: IO[str] | None = None
) -> None:
    """Install a single handler on the ``sentinel`` logger tree.

    Idempotent: re-configuring replaces the handler rather than stacking another,
    so a repeated call cannot produce duplicated lines. Logging goes to stderr by
    default, leaving stdout clean for commands whose output is piped
    (``sentinel scaffold > policy.yaml``).
    """
    logger = logging.getLogger("sentinel")
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()

    handler = logging.StreamHandler(stream if stream is not None else sys.stderr)
    handler.setFormatter(JsonFormatter() if fmt == "json" else TextFormatter())
    logger.addHandler(handler)
    logger.setLevel(level.upper())
    # Ours is the only handler that should render these records.
    logger.propagate = False

    # The MCP SDK logs a line per request ("Processing request of type ...") at
    # INFO, which buries the security decisions an operator is actually watching
    # for. Quiet it unless they explicitly asked for DEBUG.
    if level.upper() != "DEBUG":
        for noisy in ("mcp", "mcp.server", "sse_starlette"):
            logging.getLogger(noisy).setLevel(logging.WARNING)


def security_logger() -> logging.Logger:
    """The logger every enforcement decision is written to."""
    return logging.getLogger(SECURITY_LOGGER)


def _tenant_field(tenant: str | None) -> dict[str, str]:
    """The tenant a security event belongs to, when there is one.

    These lines carried no tenant, so an operator of a multi-tenant deployment
    could not tell whose block or quarantine a line was.
    """
    return {} if tenant is None else {"tenant": _safe_log_value(tenant)}


def _safe_log_value(value: object) -> str:
    """Keep attacker-controlled identifiers to one terminal/log line."""
    return _LOG_CONTROL_CHARS.sub(lambda match: f"\\x{ord(match.group()):02x}", str(value))


def log_allowed(
    tool: str,
    *,
    trace_id: str,
    agent_id: str,
    provenance: tuple[str, ...],
    tenant: str | None = None,
) -> None:
    """One line per permitted action — the routine half of the audit trail."""
    safe_tool = _safe_log_value(tool)
    security_logger().info(
        "ALLOW  %s",
        safe_tool,
        extra={
            "event": "tool_allowed",
            "tool": safe_tool,
            "decision": "ALLOW",
            "trace_id": _safe_log_value(trace_id),
            "agent_id": _safe_log_value(agent_id),
            "provenance": list(provenance),
            **_tenant_field(tenant),
        },
    )


def log_blocked(
    tool: str,
    *,
    reason: str,
    rule: str | None,
    trace_id: str,
    agent_id: str,
    provenance: tuple[str, ...],
    tenant: str | None = None,
) -> None:
    """A refused action. WARNING because this is what an operator filters for."""
    safe_tool = _safe_log_value(tool)
    safe_rule = _safe_log_value(rule) if rule is not None else "-"
    safe_reason = _safe_log_value(reason)
    security_logger().warning(
        "BLOCK  %s  rule=%s  %s",
        safe_tool,
        safe_rule,
        safe_reason,
        extra={
            "event": "tool_blocked",
            "tool": safe_tool,
            "decision": "DENY",
            "rule": safe_rule,
            "reason": safe_reason,
            "trace_id": _safe_log_value(trace_id),
            "agent_id": _safe_log_value(agent_id),
            "provenance": list(provenance),
            **_tenant_field(tenant),
        },
    )


def log_quarantined(
    agent_id: str,
    *,
    trace_id: str,
    score: float,
    enforced: bool = True,
    tenant: str | None = None,
) -> None:
    """The trust score crossed the quarantine threshold, enforced or not."""
    consequence = "further tool calls refused" if enforced else "NOT enforced; calls continue"
    security_logger().warning(
        "QUARANTINE  agent=%s  score=%.1f  %s",
        _safe_log_value(agent_id),
        score,
        consequence,
        extra={
            "event": "agent_quarantined",
            "agent_id": _safe_log_value(agent_id),
            "trace_id": _safe_log_value(trace_id),
            "score": score,
            "enforced": enforced,
            **_tenant_field(tenant),
        },
    )


def log_policy_change(
    tenant: str,
    *,
    outcome: str,
    version: int | None,
    previous: int | None,
    trace_id: str,
) -> None:
    """The operator submitted a tenant's policy: applied, ignored, rejected or failed."""
    security_logger().warning(
        "POLICY  %s  v%s -> v%s",
        outcome.upper(),
        previous,
        version,
        extra={
            "event": "policy_change",
            "outcome": outcome,
            "version": version,
            "previous_version": previous,
            "trace_id": _safe_log_value(trace_id),
            **_tenant_field(tenant),
        },
    )


def log_injection_flagged(
    target: str, *, trace_id: str, shield: str, tenant: str | None = None
) -> None:
    """Layer-1 flagged content. Informational: the shield flags, it does not block."""
    security_logger().info(
        "FLAG   injection markers in %s (%s)",
        _safe_log_value(target),
        _safe_log_value(shield),
        extra={
            "event": "injection_flagged",
            "target": _safe_log_value(target),
            "shield": _safe_log_value(shield),
            "trace_id": _safe_log_value(trace_id),
            **_tenant_field(tenant),
        },
    )
