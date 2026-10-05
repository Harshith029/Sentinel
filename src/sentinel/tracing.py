"""Trace and span IDs for SENTINEL's forensic record, in OpenTelemetry format.

BUILD_SPEC §1 / §2: ``trace_id`` and ``span_id`` come from the OTel SDK's ID
generator (W3C Trace Context hex), never hand-rolled UUIDs. The per-trace
monotonic ``seq`` is a separate field, assigned in :mod:`sentinel.forensics`.

That is all this module does. SENTINEL does not export OpenTelemetry traces:
the forensic spans are its own records, stored by its own stores. This module
used to also define ``init_tracing``/``get_tracer`` with an Azure Monitor
exporter, but nothing in the service ever called them, while ``/capabilities``
reported Application Insights as active whenever its connection string was set.
They were removed rather than left to suggest an integration that does not run.
"""
from __future__ import annotations

from typing import Final

from opentelemetry.sdk.trace.id_generator import RandomIdGenerator

_ID_GENERATOR: Final[RandomIdGenerator] = RandomIdGenerator()


def new_trace_id_hex() -> str:
    """A fresh 128-bit trace id from the OTel SDK ID generator, as 32 hex chars.

    Every run's trace id is minted here (via the span emitter).
    """
    return _format_trace_id(_ID_GENERATOR.generate_trace_id())


def new_span_id_hex() -> str:
    """A fresh 64-bit span id from the OTel SDK ID generator, as 16 hex chars."""
    return _format_span_id(_ID_GENERATOR.generate_span_id())


def _format_trace_id(value: int) -> str:
    """Zero-padded 32-char (128-bit) lowercase hex, matching W3C Trace Context."""
    return f"{value:032x}"


def _format_span_id(value: int) -> str:
    """Zero-padded 16-char (64-bit) lowercase hex, matching W3C Trace Context."""
    return f"{value:016x}"
