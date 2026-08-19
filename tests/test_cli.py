"""The CLI is the product surface — it must behave like a real tool.

Covers config precedence, actionable failure modes, and the fact that the demo
dashboard is OPT-IN rather than the front door.
"""
from __future__ import annotations

import os
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest
import yaml

from sentinel.cli import (
    DEFAULT_CONFIG,
    ConfigError,
    apply_config,
    build_parser,
    load_config,
    main,
)
from sentinel.config import reset_settings_cache

_CLI_VARS = (
    "SENTINEL_MCP_SERVERS", "SENTINEL_POLICY_FILE",
    "SENTINEL_CATALOGUE_STRICT", "SENTINEL_REAL_WEB_FETCH", "SENTINEL_API_TOKEN",
)


@pytest.fixture(autouse=True)
def _isolated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Scratch cwd + a clean SENTINEL_* environment, restored afterwards.

    ``apply_config`` writes ``os.environ`` directly (that is its whole job), and
    monkeypatch cannot undo writes it did not make — so without an explicit
    teardown these leak into every later test and, e.g., point the policy loader
    at a file that does not exist.
    """
    monkeypatch.chdir(tmp_path)
    for var in _CLI_VARS:
        monkeypatch.delenv(var, raising=False)
    yield
    for var in _CLI_VARS:
        os.environ.pop(var, None)
    reset_settings_cache()  # the settings cache may hold values from this test


# --- init ---------------------------------------------------------------------

def test_init_writes_a_usable_config(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["init"]) == 0
    written = Path(DEFAULT_CONFIG)
    assert written.is_file()
    parsed = yaml.safe_load(written.read_text(encoding="utf-8"))
    # the starter file must itself be valid and carry the product-shaped keys
    assert {"policy", "host", "port", "dashboard", "catalogue_strict"} <= parsed.keys()
    assert parsed["dashboard"] is False  # demo UI is opt-in, not the default
    assert "next:" in capsys.readouterr().out


def test_init_refuses_to_clobber_without_force() -> None:
    Path(DEFAULT_CONFIG).write_text("servers: []", encoding="utf-8")
    assert main(["init"]) == 1
    assert Path(DEFAULT_CONFIG).read_text(encoding="utf-8") == "servers: []"
    assert main(["init", "--force"]) == 0
    assert "SENTINEL configuration" in Path(DEFAULT_CONFIG).read_text(encoding="utf-8")


# --- config loading & precedence ----------------------------------------------

def test_missing_default_config_is_not_an_error() -> None:
    assert load_config(None) == {}


def test_missing_explicit_config_is_an_error() -> None:
    with pytest.raises(ConfigError, match="not found"):
        load_config("nope.yaml")


def test_malformed_config_is_reported(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("servers: [unclosed", encoding="utf-8")
    with pytest.raises(ConfigError, match="invalid YAML"):
        load_config(bad)
    scalar = tmp_path / "scalar.yaml"
    scalar.write_text("just-a-string", encoding="utf-8")
    with pytest.raises(ConfigError, match="must be a mapping"):
        load_config(scalar)


def test_config_populates_environment() -> None:
    apply_config(
        {
            "servers": [{"name": "gh", "url": "https://a.test"}],
            "policy": "./policy.yaml",
            "catalogue_strict": False,
        }
    )
    assert '"name": "gh"' in os.environ["SENTINEL_MCP_SERVERS"]
    assert os.environ["SENTINEL_POLICY_FILE"] == "./policy.yaml"
    assert os.environ["SENTINEL_CATALOGUE_STRICT"] == "0"


def test_explicit_environment_beats_the_config_file(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Containers must be able to override a checked-in file without editing it."""
    monkeypatch.setenv("SENTINEL_POLICY_FILE", "/etc/from-env.yaml")
    apply_config({"policy": "./from-file.yaml"})
    assert os.environ["SENTINEL_POLICY_FILE"] == "/etc/from-env.yaml"


# --- check: actionable failures -----------------------------------------------

def test_check_fails_clearly_when_policy_is_missing(
    capsys: pytest.CaptureFixture[str],
) -> None:
    Path(DEFAULT_CONFIG).write_text("policy: ./nope.yaml\n", encoding="utf-8")
    assert main(["check"]) == 1
    captured = capsys.readouterr()
    assert "MISSING" in captured.out
    assert "sentinel scaffold" in captured.err  # tells the operator what to do


def test_check_fails_clearly_when_no_servers_declared(
    capsys: pytest.CaptureFixture[str],
) -> None:
    Path(DEFAULT_CONFIG).write_text("servers: []\n", encoding="utf-8")
    assert main(["check"]) == 1
    assert "none declared" in capsys.readouterr().err


# --- parser -------------------------------------------------------------------

def test_every_command_is_registered() -> None:
    parser = build_parser()
    for command in ("init", "check", "scaffold", "serve"):
        assert parser.parse_args([command]).command == command


def test_serve_dashboard_is_opt_in() -> None:
    parser = build_parser()
    assert parser.parse_args(["serve"]).dashboard is False
    assert parser.parse_args(["serve", "--dashboard"]).dashboard is True


def test_init_warns_when_the_config_could_be_committed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """F-13: sentinel.yaml accepts an api_token, so a committed copy leaks it.

    `sentinel init` writes the file straight into the operator's working tree.
    Nothing there tells them it is credential-bearing, and nothing ignores it —
    so the natural next step (commit the new config) publishes a bearer token
    that grants access to the security proxy itself. The starter file now says
    secrets belong in the environment, and init warns when git would take it.
    """
    subprocess.run(  # noqa: S603
        ["git", "init", "-q"],  # noqa: S607
        cwd=tmp_path, check=True, capture_output=True,
    )
    target = tmp_path / "sentinel.yaml"

    assert main(["--config", str(target), "init"]) == 0
    err = capsys.readouterr().err
    assert "not ignored" in err and "SENTINEL_API_TOKEN" in err
    assert "SECRETS DO NOT BELONG IN THIS FILE" in target.read_text(encoding="utf-8")

    # Once git ignores it there is nothing to warn about.
    (tmp_path / ".gitignore").write_text("sentinel.yaml\n", encoding="utf-8")
    assert main(["--config", str(target), "init", "--force"]) == 0
    assert "not ignored" not in capsys.readouterr().err
