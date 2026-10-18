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


def test_a_refused_or_failed_run_is_shown_not_spun_forever() -> None:
    """launch() ignored the HTTP status, and a failed run never cleared the spinner.

    Checked in a browser against `sentinel serve --dashboard`: an unknown
    scenario shows REFUSED with the server's reason; a run reported failed shows
    its error. This pins the code paths, since CI has no browser.
    """
    source = _DASHBOARD.read_text(encoding="utf-8")
    assert "if(!resp.ok || !j.trace_id)" in source
    assert "async function watchRun(trace)" in source
    assert "if(state.refused)" in source


def test_autoplay_runs_once_and_only_on_a_fresh_dashboard() -> None:
    """It launched a run and a baseline on every page load."""
    source = _DASHBOARD.read_text(encoding="utf-8")
    assert "sessionStorage.getItem('sentinel-autoplayed')" in source
    assert "if(d.runs && d.runs.length) return;" in source
