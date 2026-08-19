"""Forensic span spine (BUILD_SPEC §2, Phase 1).

Every security decision SENTINEL makes is written here as a typed, immutable
:class:`~sentinel.forensics.span.Span` carrying OpenTelemetry identity
(``trace_id`` / ``span_id`` / ``parent_span_id``) plus a per-trace monotonic
``seq`` assigned at the single serialization point (the emitter). Replay orders
strictly by ``(trace_id, seq)`` and reconstructs the branching causality DAG —
never a flat write-ordered log.

Public surface:
* :mod:`events`   — the 8 typed event payloads (discriminated union).
* :mod:`span`     — the Span envelope wrapping a payload with OTel IDs + seq.
* :mod:`store`    — ForensicStore interface + in-memory and Cosmos impls.
* :mod:`emitter`  — SpanEmitter: assigns seq under a lock, then writes.
* :mod:`replay`   — replay(trace_id) -> walkable span DAG.
"""
from __future__ import annotations
