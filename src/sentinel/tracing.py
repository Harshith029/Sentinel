"""Trace and span IDs for SENTINEL's forensic record, in OpenTelemetry format.

BUILD_SPEC §1 / §2: ``trace_id`` and ``span_id`` use the operating system's
cryptographically secure random source and are formatted as W3C Trace Context
hex. The per-trace monotonic ``seq`` is a separate field, assigned in
:mod:`sentinel.forensics`.

That is all this module does. SENTINEL does not export OpenTelemetry traces:
the forensic spans are its own records, stored by its own stores. This module
used to also define ``init_tracing``/``get_tracer`` with an Azure Monitor
exporter, but nothing in the service ever called them, while ``/capabilities``
reported Application Insights as active whenever its connection string was set.
They were removed rather than left to suggest an integration that does not run.
"""

from __future__ import annotations

import secrets


def _new_nonzero_hex(byte_count: int) -> str:
    """Generate a non-zero W3C identifier from a cryptographic RNG."""
    # All-zero is the W3C invalid sentinel. It is extraordinarily unlikely, but
    # explicitly retrying makes this module uphold the invariant deterministically.
    while True:
        value = secrets.token_hex(byte_count)
        if value != "0" * (byte_count * 2):
            return value


def new_trace_id_hex() -> str:
    """A fresh cryptographically-random 128-bit trace id, as 32 hex chars.

    Every run's trace id is minted here (via the span emitter).
    """
    return _new_nonzero_hex(16)


def new_span_id_hex() -> str:
    """A fresh cryptographically-random 64-bit span id, as 16 hex chars."""
    return _new_nonzero_hex(8)
