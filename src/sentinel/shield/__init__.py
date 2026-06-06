"""Layer-1 input shielding (BUILD_SPEC §5).

A thin wrapper over Azure AI Content Safety **Prompt Shields**. It is LAYER 1
and is EXPECTED to miss obfuscated attacks by design — that is the entire reason
the Authorization Engine (§2B) exists as the backstop. The shield FLAGS
(emitting telemetry + feeding the trust scorer); it does not enforce.
"""
from __future__ import annotations

from sentinel.shield.input_shield import InputShield, ShieldVerdict

__all__ = ["InputShield", "ShieldVerdict"]
