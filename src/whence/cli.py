"""``whence`` — the command-line interface.

This is the product surface. Whence is infrastructure you point at your own MCP
servers, so the primary interaction is a CLI and a config file, not a web page.
The bundled dashboard is a demo of the security pipeline and is **opt-in**.

Commands::

    whence init                 write a starter whence.yaml
    whence check                validate config, connect, vet catalogues (no serving)
    whence scaffold             print a starter policy for your discovered tools
    whence serve                run the proxy

Configuration precedence is the usual one: **CLI flag > environment variable >
config file > default**, so a container can override a checked-in file without
editing it.

The config file (default ``whence.yaml``)::

    servers:
      - name: github
        url: https://mcp.example/gh
    policy: ./policy.yaml     # your rules; generate with `whence scaffold`
    host: 127.0.0.1
    port: 8765
    dashboard: false          # opt-in demo UI
    catalogue_strict: true    # refuse catalogues with injection markers
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, TypeVar, cast

import yaml

T = TypeVar("T")

DEFAULT_CONFIG = "whence.yaml"

STARTER_CONFIG = """\
# Whence configuration. Point it at YOUR MCP servers.
#
# Whence ships no tools of its own: it sits between your agent and your
# servers, tracks where every byte came from, and refuses actions whose data
# originated in untrusted content.

servers:
  # - name: github
  #   url: https://mcp.example/gh

# Your authorization policy. Every tool is DENIED until a rule permits it, so
# generate a starting point once your servers are declared:
#   whence scaffold > policy.yaml
policy: ./policy.yaml

host: 127.0.0.1
port: 8765

# The bundled dashboard is a DEMO of the security pipeline, not the product.
# Leave false for real deployments.
dashboard: false

# Refuse to serve a downstream catalogue whose tool definitions contain
# prompt-injection markers (tool poisoning). Cross-server tool-name shadowing
# always fails closed regardless.
catalogue_strict: true

# SECRETS DO NOT BELONG IN THIS FILE. `api_token` is a valid key here, but this
# file lives in your repository and is easy to commit by accident. Set it in the
# environment instead, where your platform's secret store can deliver it:
#   WHENCE_API_TOKEN=...
# The environment wins over this file, so a deployment can override anything set
# here without editing it.
"""

# config key -> (env var, serializer)
_ENV_MAP: dict[str, tuple[str, Any]] = {
    "servers": ("WHENCE_MCP_SERVERS", json.dumps),
    "policy": ("WHENCE_POLICY_FILE", str),
    "catalogue_strict": ("WHENCE_CATALOGUE_STRICT", lambda v: "1" if v else "0"),
    "real_web_fetch": ("WHENCE_REAL_WEB_FETCH", lambda v: "1" if v else "0"),
    "api_token": ("WHENCE_API_TOKEN", str),
}


class ConfigError(RuntimeError):
    """Raised when the config file is missing or malformed."""


def load_config(path: str | os.PathLike[str] | None) -> dict[str, Any]:
    """Read a config file. A missing DEFAULT path is fine; an explicit one is not."""
    explicit = path is not None
    target = Path(path or DEFAULT_CONFIG)
    if not target.is_file():
        if explicit:
            raise ConfigError(f"config file not found: {target}")
        return {}
    try:
        data = yaml.safe_load(target.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"{target}: invalid YAML: {exc}") from exc
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ConfigError(f"{target}: top level must be a mapping")
    return data


def apply_config(config: dict[str, Any]) -> None:
    """Export config values as env vars, WITHOUT clobbering explicit env.

    Settings are read from the environment, so this is the seam that lets a file
    drive them while keeping env-wins precedence for containers/secrets.
    """
    for key, (env_var, serialize) in _ENV_MAP.items():
        value = config.get(key)
        # An empty list/string means "not declared yet" (the state straight after
        # `whence init`), not "explicitly declare nothing" — exporting it would
        # turn a fresh config into a hard downstream error.
        if value is None or value == [] or value == "":
            continue
        if env_var not in os.environ:
            os.environ[env_var] = serialize(value)


def _fail(message: str) -> None:
    """Write an error AFTER flushing stdout, so ordering reads correctly."""
    sys.stdout.flush()
    print(message, file=sys.stderr)


def _resolve(config: dict[str, Any], key: str, cli_value: T | None, default: T) -> T:
    """CLI flag > config file > default (env is handled by :func:`apply_config`)."""
    if cli_value is not None:
        return cli_value
    value = config.get(key)
    if value is not None:
        return cast(T, value)
    return default


# --- commands -----------------------------------------------------------------


def cmd_init(args: argparse.Namespace) -> int:
    target = Path(args.config or DEFAULT_CONFIG)
    if target.exists() and not args.force:
        _fail(f"{target} already exists (use --force to overwrite)")
        return 1
    target.write_text(STARTER_CONFIG, encoding="utf-8")
    print(f"wrote {target}")
    if _is_committable(target):
        print(
            f"warning: {target} is inside a git repository and is not ignored. "
            "It accepts an api_token; keep secrets in the environment "
            "(WHENCE_API_TOKEN) or add this file to .gitignore.",
            file=sys.stderr,
        )
    print("next: declare your servers, then run `whence check`")
    return 0


def _is_committable(target: Path) -> bool:
    """True when ``target`` sits in a git repo and git is not ignoring it.

    The config accepts an ``api_token``, so a committed copy publishes a
    credential. Asking git directly is what makes this accurate: it honours
    global excludes and nested .gitignore files, which reading one file cannot.
    Any failure (git missing, not a repo) answers False — the warning is a
    convenience, and guessing wrong would train operators to ignore it.
    """
    try:
        # noqa justification: fixed argv (never a shell), and `--` stops a
        # path that looks like a flag from being read as one. `git` is resolved
        # from PATH on purpose — that is the git the operator actually uses.
        proc = subprocess.run(  # noqa: S603
            ["git", "check-ignore", "-q", "--", str(target)],  # noqa: S607
            cwd=target.parent if target.parent.exists() else None,
            capture_output=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    if proc.returncode == 0:  # git ignores it → safe
        return False
    inside = subprocess.run(  # noqa: S603
        ["git", "rev-parse", "--is-inside-work-tree"],  # noqa: S607
        cwd=target.parent if target.parent.exists() else None,
        capture_output=True,
        text=True,
        timeout=5,
    )
    return inside.returncode == 0 and inside.stdout.strip() == "true"


def cmd_check(args: argparse.Namespace) -> int:
    """Validate config and connectivity WITHOUT serving — the pre-flight command."""
    import asyncio
    from contextlib import AsyncExitStack

    config = load_config(args.config)
    apply_config(config)

    from whence.config import get_settings, reset_settings_cache
    from whence.downstream import connect_downstream, parse_servers

    reset_settings_cache()
    settings = get_settings()

    print(f"config          : {args.config or DEFAULT_CONFIG}")
    policy = settings.policy_file
    if policy:
        ok = Path(policy).is_file()
        print(f"policy          : {policy} {'(found)' if ok else '(MISSING)'}")
        if not ok:
            _fail("  -> run `whence scaffold > policy.yaml` to generate one")
            return 1
    else:
        print("policy          : (bundled example policy - your tools will be denied)")

    try:
        servers = parse_servers(settings.mcp_servers)
    except Exception as exc:  # noqa: BLE001 - a config mistake must read as guidance
        _fail(f"servers         : invalid declaration - {exc}")
        return 1
    if not servers:
        _fail("servers         : none declared - add them under `servers:`")
        return 1
    print(f"servers         : {len(servers)} declared")

    async def probe() -> int:
        async with AsyncExitStack() as stack:
            topology = await connect_downstream(servers, stack)
            for name, tools in sorted(topology.catalogues.items()):
                names = ", ".join(sorted(t.name for t in tools))
                print(f"  {name:<16} {len(tools)} tool(s): {names}")
            print(f"catalogue       : OK - no shadowing, {len(topology.tool_names)} tool(s) total")
        return 0

    try:
        return asyncio.run(probe())
    except Exception as exc:  # noqa: BLE001 - report any connect/vetting failure
        _fail(f"FAILED: {exc}")
        return 1


def cmd_scaffold(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    apply_config(config)
    from whence.config import reset_settings_cache

    reset_settings_cache()
    from whence.scaffold import _main as scaffold_main

    return scaffold_main()


def cmd_serve(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    apply_config(config)

    host = _resolve(config, "host", args.host, "127.0.0.1")
    port = int(_resolve(config, "port", args.port, 8765))
    dashboard = bool(_resolve(config, "dashboard", args.dashboard or None, False))

    # Enforcement must be visible where the operator is looking, not only in the
    # forensic store. Blocks log at WARNING; payloads are never written.
    from whence.observability import configure_logging

    configure_logging(
        level=str(_resolve(config, "log_level", args.log_level, "INFO")),
        fmt=str(_resolve(config, "log_format", args.log_format, "text")),  # type: ignore[arg-type]
    )

    os.environ.setdefault("WHENCE_ENABLE_MCP_GATEWAY", "1")

    from whence.config import reset_settings_cache

    reset_settings_cache()

    import uvicorn

    from whence.control.app import create_app

    app = create_app(enable_mcp_gateway=True)
    print(f"Whence proxy on http://{host}:{port}/mcp")
    suffix = "" if dashboard else " (dashboard disabled)"
    print(f"  point your agent's MCP endpoint at that URL{suffix}")
    if dashboard:
        print(f"  dashboard: http://{host}:{port}/")
    uvicorn.run(app, host=host, port=port, log_level="info")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="whence",
        description="Provenance-aware security proxy for AI agents (MCP).",
    )
    parser.add_argument("-c", "--config", help=f"config file (default: {DEFAULT_CONFIG})")
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="write a starter whence.yaml")
    p_init.add_argument("--force", action="store_true", help="overwrite an existing file")
    p_init.set_defaults(func=cmd_init)

    sub.add_parser(
        "check", help="validate config, connect to servers, vet catalogues"
    ).set_defaults(func=cmd_check)

    sub.add_parser(
        "scaffold", help="print a starter policy for your discovered tools"
    ).set_defaults(func=cmd_scaffold)

    p_serve = sub.add_parser("serve", help="run the proxy")
    p_serve.add_argument("--host")
    p_serve.add_argument("--port", type=int)
    p_serve.add_argument(
        "--dashboard", action="store_true", help="also serve the demo dashboard"
    )
    p_serve.add_argument(
        "--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="verbosity of security decision logging (default: INFO)",
    )
    p_serve.add_argument(
        "--log-format", choices=["text", "json"],
        help="'text' for a terminal, 'json' for a log aggregator (default: text)",
    )
    p_serve.set_defaults(func=cmd_serve)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        result: int = args.func(args)
        return result
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
