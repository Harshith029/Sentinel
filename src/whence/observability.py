"""Operator-facing logging for security decisions.

Forensic spans are the durable record, but they live behind an API. An operator
running ``whence serve`` needs to see enforcement happen in the place they are
actually looking: stdout, journald, Docker logs, their aggregator. A security
proxy that blocks silently is undebuggable in production.

What gets logged, and at what level, follows what an operator needs to act on:

* ``WARNING`` — a call was **blocked**, or an agent was **quarantined**. These are
  the lines that should page someone or show up in a filter.
* ``INFO``    — a call was allowed. One line per action, so the audit trail is
  legible without being noisy.
* ``DEBUG``   — detail for diagnosing policy, off by default.

**Payloads are never logged.** This is the load-bearing rule of this module: the
arguments Whence inspects are exactly the sensitive material it exists to
protect — customer records, keys, message bodies. Writing them to a log would
move the secret from a blocked tool call into a plaintext file that is shipped
off-box, i.e. it would perform the exfiltration the proxy just prevented. We log
the *decision* (tool, rule, provenance labels, trace id) and never the data. The
forensic store already holds the full payload under access control for anyone
who genuinely needs it.
"""
from __future__ import annotations

import json
import logging
import sys
from typing import IO, Any, Final, Literal

LogFormat = Literal["text", "json"]

SECURITY_LOGGER: Final[str] = "whence.security"

# Fields the JSON formatter always emits; anything else comes from `extra`.
_STANDARD: Final[frozenset[str]] = frozenset(
    {
        "args", "asctime", "created", "exc_info", "exc_text", "filename",
        "funcName", "levelname", "levelno", "lineno", "module", "msecs",
        "message", "msg", "name", "pathname", "process", "processName",
        "relativeCreated", "stack_info", "taskName", "thread", "threadName",
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
        if record.exc_info:
            base = f"{base}\n{self.formatException(record.exc_info)}"
        return base


def configure_logging(
    *, level: str = "INFO", fmt: LogFormat = "text", stream: IO[str] | None = None
) -> None:
    """Install a single handler on the ``whence`` logger tree.

    Idempotent: re-configuring replaces the handler rather than stacking another,
    so a repeated call cannot produce duplicated lines. Logging goes to stderr by
    default, leaving stdout clean for commands whose output is piped
    (``whence scaffold > policy.yaml``).
    """
    logger = logging.getLogger("whence")
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


def log_allowed(
    tool: str, *, trace_id: str, agent_id: str, provenance: tuple[str, ...]
) -> None:
    """One line per permitted action — the routine half of the audit trail."""
    security_logger().info(
        "ALLOW  %s", tool,
        extra={
            "event": "tool_allowed", "tool": tool, "decision": "ALLOW",
            "trace_id": trace_id, "agent_id": agent_id,
            "provenance": list(provenance),
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
) -> None:
    """A refused action. WARNING because this is what an operator filters for."""
    security_logger().warning(
        "BLOCK  %s  rule=%s  %s", tool, rule or "-", reason,
        extra={
            "event": "tool_blocked", "tool": tool, "decision": "DENY",
            "rule": rule, "reason": reason, "trace_id": trace_id,
            "agent_id": agent_id, "provenance": list(provenance),
        },
    )


def log_quarantined(agent_id: str, *, trace_id: str, score: float) -> None:
    """Containment kicked in — the agent is cut off until reset."""
    security_logger().warning(
        "QUARANTINE  agent=%s  score=%.1f  further tool calls refused",
        agent_id, score,
        extra={
            "event": "agent_quarantined", "agent_id": agent_id,
            "trace_id": trace_id, "score": score,
        },
    )


def log_injection_flagged(target: str, *, trace_id: str, shield: str) -> None:
    """Layer-1 flagged content. Informational: the shield flags, it does not block."""
    security_logger().info(
        "FLAG   injection markers in %s (%s)", target, shield,
        extra={
            "event": "injection_flagged", "target": target,
            "shield": shield, "trace_id": trace_id,
        },
    )
