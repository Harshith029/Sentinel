"""Semantic attack classifier (BUILD_SPEC §Phase 8) — ONE job, ONE panel.

Labels each BLOCKED attempt as ``exfiltration`` / ``privilege_escalation`` /
``instruction_override`` for the SOC export panel. It is DELIBERATELY scoped: it
never feeds severity, policy, trust, or replay. Authorization already decided to
block; this only *names the category* of the blocked attempt for analysts.

DEMO MODE uses a deterministic rule-based labeller; AZURE MODE uses Azure OpenAI.
"""
from __future__ import annotations

from sentinel.classifier.attack_classifier import (
    ATTACK_CLASSES,
    AttackClass,
    AttackClassifier,
    AttackLabel,
)

__all__ = ["ATTACK_CLASSES", "AttackClass", "AttackClassifier", "AttackLabel"]
