"""Static security invariants for the bundled dashboard."""

from __future__ import annotations

from pathlib import Path

_DASHBOARD = (
    Path(__file__).resolve().parents[1] / "src" / "sentinel" / "control" / "static" / "index.html"
)


def test_soc_export_renders_audit_json_as_text_not_markup() -> None:
    source = _DASHBOARD.read_text(encoding="utf-8")
    assert "$('soc').textContent=d.alerts.map(a=>JSON.stringify(a))" in source
    assert "$('soc').innerHTML=d.alerts.map" not in source
