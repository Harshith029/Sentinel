"""Authorization engine (BUILD_SPEC §2B) — the policy backstop behind provenance.

Predicates are parsed into a TYPED condition AST (:mod:`ast`) by a hand-written
tokenizer/parser (:mod:`parser`) — never ``eval``. Policy is declarative,
versioned YAML validated at LOAD time (:mod:`policy`). The engine
(:mod:`engine`) resolves a proposed call against the policy with DENY-OVERRIDES
precedence (any matching deny short-circuits; unknown tools default-deny) and
emits a complete :class:`~whence.forensics.events.AuthorizationDecided`
decision trace.
"""
from __future__ import annotations
