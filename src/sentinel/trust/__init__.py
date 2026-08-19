"""Trust Scorer (BUILD_SPEC §Phase 3) — defense-in-depth TIER 2.

Deliberately SUBORDINATE to the Authorization Engine (§2B is the thesis). Trust
is anomaly telemetry + quarantine escalation + operational containment, NOT
primary prevention. It catches novel patterns policy cannot pre-specify, using
the simplest principled mechanism: per-agent tool-transition counts over a
sliding window with Laplace (add-one) smoothing. No baseline learning, no model
training, no adaptive statistics.

Public surface:
* :mod:`config` — :class:`TrustConfig`: the ONE file holding every weight.
* :mod:`scorer` — :class:`TrustScorer`: smoothed scoring, per-agent serialized
  updates, quarantine + visible post-quarantine denials.
"""
from __future__ import annotations
