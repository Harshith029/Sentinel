"""Safety checks for the custom-attack command-line example."""

from __future__ import annotations

import runpy
from pathlib import Path

import pytest

_EXAMPLE = runpy.run_path(
    Path(__file__).resolve().parents[1] / "examples" / "run_custom_attack.py"
)
_control_url = _EXAMPLE["_control_url"]


def test_custom_attack_example_accepts_an_http_control_origin() -> None:
    assert _control_url("http://127.0.0.1:8765", "/runs/custom") == (
        "http://127.0.0.1:8765/runs/custom"
    )


@pytest.mark.parametrize(
    "base",
    [
        "file:///tmp/control-plane",
        "ftp://example.test",
        "https://user@example.test",
        "https://example.test/not-an-origin",
    ],
)
def test_custom_attack_example_rejects_non_origin_or_non_http_base(base: str) -> None:
    with pytest.raises(ValueError):
        _control_url(base, "/runs/custom")
