"""Trust-scorer configuration (BUILD_SPEC §Phase 3) — all weights in ONE place.

Every number the scorer uses is a field here, loaded from ``config.yaml``. The
scoring code references ``config.<weight>`` only; there are no inline constants,
so the policy of "no magic numbers / all weights in one declarative file" holds.
"""
from __future__ import annotations

from importlib.resources import files
from pathlib import Path
from typing import Any, Final

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

# The score DOMAIN is fixed by the spec at [0, 100]; these are definitional
# bounds (not tunable weights), named so they are never bare literals in logic.
MIN_SCORE: Final[float] = 0.0
MAX_SCORE: Final[float] = 100.0


class TrustConfigError(ValueError):
    """Raised when the trust configuration is malformed."""


class TrustConfig(BaseModel):
    """Immutable trust-scorer configuration."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    window_size: int = Field(ge=1, description="N: recent transitions defining normal")
    starting_score: float = Field(ge=MIN_SCORE, le=MAX_SCORE)
    quarantine_threshold: float = Field(ge=MIN_SCORE, le=MAX_SCORE)
    max_transition_penalty: float = Field(ge=0.0)
    blocked_call_penalty: float = Field(ge=0.0)
    injection_detected_penalty: float = Field(ge=0.0)


def load_trust_config(text: str) -> TrustConfig:
    """Parse + validate a trust config from YAML text (raises on malformed)."""
    try:
        data: Any = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise TrustConfigError(f"invalid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise TrustConfigError("trust config must be a YAML mapping at the top level")
    try:
        return TrustConfig.model_validate(data)
    except ValidationError as exc:
        raise TrustConfigError(f"invalid trust config: {exc}") from exc


def default_trust_config_path() -> Path:
    return Path(str(files("sentinel.trust").joinpath("config.yaml")))


def load_default_trust_config() -> TrustConfig:
    """Load the canonical trust config shipped with the package."""
    return load_trust_config(default_trust_config_path().read_text(encoding="utf-8"))
