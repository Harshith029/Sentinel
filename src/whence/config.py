"""Runtime configuration for Whence.

Reads environment variables only — no direct file IO, no Azure calls.
This keeps Phase 0 trivially testable and lets the higher-level wiring decide
whether to pull secrets from Key Vault (Azure mode) or from a local .env file
(demo / dev mode).

BUILD_SPEC §10 calls the on-stage mode "DEMO MODE", deliberately NOT "mock":
the security pipeline is LIVE in both modes — only the agent driver differs.
The env-var name therefore uses `DEMO_MODE`.
"""
from __future__ import annotations

import os
from functools import lru_cache
from typing import Final

from pydantic import BaseModel, Field

_TRUE_VALUES: Final[frozenset[str]] = frozenset({"1", "true", "yes", "on"})
_FALSE_VALUES: Final[frozenset[str]] = frozenset({"0", "false", "no", "off"})


def _parse_bool_env(name: str, *, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    normalized = raw.strip().lower()
    if normalized in _TRUE_VALUES:
        return True
    if normalized in _FALSE_VALUES:
        return False
    raise ValueError(
        f"Environment variable {name!r}={raw!r} is not a recognized boolean "
        f"(expected one of {sorted(_TRUE_VALUES | _FALSE_VALUES)})."
    )


class Settings(BaseModel):
    """Immutable view of Whence's runtime configuration.

    Construct via :func:`get_settings` — that path caches and re-reads the
    environment, which is what tests and the proxy both want.
    """

    model_config = {"frozen": True}

    demo_mode: bool = Field(
        description=(
            "Spec §10: True iff Whence is running in DEMO MODE (deterministic "
            "attack orchestration; no real Azure dependencies). The security "
            "pipeline itself is IDENTICAL in both modes."
        ),
    )

    azure_ai_project_endpoint: str | None = None
    azure_cosmos_endpoint: str | None = None
    azure_cosmos_database: str = "whence"
    azure_cosmos_container: str = "spans"

    azure_content_safety_endpoint: str | None = None
    azure_content_safety_key: str | None = None

    azure_openai_endpoint: str | None = None
    azure_openai_deployment: str | None = None
    azure_openai_api_version: str | None = None

    applicationinsights_connection_string: str | None = None

    whence_mcp_url: str = "http://localhost:8765/mcp"

    # Remote downstream tool servers (the ACA deploy sets these). When ALL three
    # are set, the gateway connects to them over MCP-over-HTTP instead of the
    # in-memory mock servers. When unset (the DEMO default), in-memory mocks.
    whence_tools_web_url: str | None = None
    whence_tools_email_url: str | None = None
    whence_tools_records_url: str | None = None

    enable_mcp_gateway: bool = Field(
        default=False,
        description=(
            "When True, the control plane also exposes Whence's proxy as a real "
            "streamable-HTTP MCP server at /mcp, so an EXTERNAL MCP client can "
            "connect over the wire and be secured by the same pipeline. Off by "
            "default (the REST-driven demo doesn't need it); the `serve` "
            "entrypoint / WHENCE_ENABLE_MCP_GATEWAY=1 turns it on."
        ),
    )

    api_token: str | None = Field(
        default=None,
        description=(
            "Bearer token required on EVERY control-plane endpoint, reads "
            "included, and on the /mcp wire endpoint. Browsers exchange it for a "
            "session cookie via POST /auth/session. When unset the service "
            "refuses to serve unless allow_anonymous is explicitly set."
        ),
    )

    policy_file: str | None = Field(
        default=None,
        description=(
            "Path to YOUR authorization policy (YAML). This is how an operator "
            "governs their own tools; without it Whence loads the bundled example "
            "policy, which only knows the example tools and therefore default-denies "
            "everything else. Generate a starting point with `whence scaffold`."
        ),
    )

    mcp_servers: str | None = Field(
        default=None,
        description=(
            "JSON declaring the operator's OWN downstream MCP servers, e.g. "
            '[{"name":"github","url":"https://mcp.example/gh"}] (an object mapping '
            "name->url also works). When set, Whence connects to these, DISCOVERS "
            "their tools, and builds routing from discovery — the product path. When "
            "unset it falls back to the bundled example servers. Discovery never "
            "grants permission: a discovered tool with no policy entry is "
            "default-denied until the operator writes a rule for it."
        ),
    )

    catalogue_strict: bool = Field(
        default=True,
        description=(
            "When True (the secure default), Whence REFUSES to serve a downstream "
            "tool catalogue whose definitions carry prompt-injection markers (tool "
            "poisoning) — a supply-chain compromise provenance alone cannot catch. "
            "Set False to downgrade to flag-only triage. Cross-server tool-name "
            "shadowing always fails closed regardless of this setting."
        ),
    )

    allow_anonymous: bool = Field(
        default=False,
        description=(
            "Run with NO authentication at all. Off by default so an operator "
            "cannot expose a Whence deployment simply by forgetting to set a "
            "token: with neither this nor api_token set, the service refuses to "
            "serve rather than serving openly. Intended for a local offline demo "
            "and never for anything reachable from a network."
        ),
    )

    real_web_fetch: bool = Field(
        default=False,
        description=(
            "When True, the in-process `web` tool performs a REAL, SSRF-guarded "
            "HTTP fetch of the requested URL (whence.toolservers.web_fetch) instead "
            "of returning canned demo pages. The security pipeline is unchanged; only "
            "the downstream `web_fetch` implementation differs. Off by default so the "
            "scripted demo stays reproducible offline."
        ),
    )

    def tool_server_urls(self) -> dict[str, str]:
        """Server-key → URL for any configured REMOTE downstream tool servers.

        Keys match ``TOOL_TO_SERVER`` values (``web`` / ``email`` / ``records``).
        Empty ⇒ the gateway uses the in-memory mock tool servers.
        """
        configured = {
            "web": self.whence_tools_web_url,
            "email": self.whence_tools_email_url,
            "records": self.whence_tools_records_url,
        }
        return {key: url for key, url in configured.items() if url}


def _read_settings_from_env() -> Settings:
    return Settings(
        demo_mode=_parse_bool_env("WHENCE_DEMO_MODE", default=True),
        azure_ai_project_endpoint=os.environ.get("AZURE_AI_PROJECT_ENDPOINT") or None,
        azure_cosmos_endpoint=os.environ.get("AZURE_COSMOS_ENDPOINT") or None,
        azure_cosmos_database=os.environ.get("AZURE_COSMOS_DATABASE", "whence"),
        azure_cosmos_container=os.environ.get("AZURE_COSMOS_CONTAINER", "spans"),
        azure_content_safety_endpoint=os.environ.get("AZURE_CONTENT_SAFETY_ENDPOINT") or None,
        azure_content_safety_key=os.environ.get("AZURE_CONTENT_SAFETY_KEY") or None,
        azure_openai_endpoint=os.environ.get("AZURE_OPENAI_ENDPOINT") or None,
        azure_openai_deployment=os.environ.get("AZURE_OPENAI_DEPLOYMENT") or None,
        azure_openai_api_version=os.environ.get("AZURE_OPENAI_API_VERSION") or None,
        applicationinsights_connection_string=(
            os.environ.get("APPLICATIONINSIGHTS_CONNECTION_STRING") or None
        ),
        whence_mcp_url=os.environ.get("WHENCE_MCP_URL", "http://localhost:8765/mcp"),
        whence_tools_web_url=os.environ.get("WHENCE_TOOLS_WEB_URL") or None,
        whence_tools_email_url=os.environ.get("WHENCE_TOOLS_EMAIL_URL") or None,
        whence_tools_records_url=os.environ.get("WHENCE_TOOLS_RECORDS_URL") or None,
        enable_mcp_gateway=_parse_bool_env("WHENCE_ENABLE_MCP_GATEWAY", default=False),
        api_token=os.environ.get("WHENCE_API_TOKEN") or None,
        allow_anonymous=_parse_bool_env("WHENCE_ALLOW_ANONYMOUS", default=False),
        real_web_fetch=_parse_bool_env("WHENCE_REAL_WEB_FETCH", default=False),
        catalogue_strict=_parse_bool_env("WHENCE_CATALOGUE_STRICT", default=True),
        mcp_servers=os.environ.get("WHENCE_MCP_SERVERS") or None,
        policy_file=os.environ.get("WHENCE_POLICY_FILE") or None,
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings.

    Cached because env vars are stable for the lifetime of a process. Tests
    that mutate the environment must call :func:`reset_settings_cache`
    afterwards (the `_force_demo_mode` autouse fixture in `tests/conftest.py`
    sets the env BEFORE settings are first read, so most tests do not need to
    reset).
    """
    return _read_settings_from_env()


def reset_settings_cache() -> None:
    """Drop the cached settings so the next :func:`get_settings` re-reads env.

    Strictly for tests / interactive use. Production code should never call
    this — the process should be restarted instead.
    """
    get_settings.cache_clear()
