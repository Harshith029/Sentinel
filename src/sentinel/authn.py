"""Credential → tenant resolution, shared by the control plane and ``/mcp``.

Both entry points authenticate the same callers against the same credentials, so
the mapping lives here rather than in either one. Keeping it in ``control.app``
would have forced the gateway to import the app it is mounted into, and — worse
— invited the two surfaces to drift into disagreeing about who a caller is.

Two shapes are supported:

``SENTINEL_API_TOKEN``
    The single-tenant shorthand. One secret, bound to the default tenant.

``SENTINEL_API_TOKENS``
    A JSON object mapping tenant to token, for a deployment serving more than
    one. Each token authenticates as its tenant and sees only that tenant's data.

A caller's tenant is therefore a property of the secret they proved they hold,
never of anything they assert about themselves. That distinction is the whole
of the isolation: a tenant named in a request body is a claim, and a claim is
not a credential.
"""
from __future__ import annotations

import json
import logging
from hmac import compare_digest
from typing import Final

from sentinel.authorization.registry import DEFAULT_TENANT
from sentinel.config import get_settings

_LOG: Final[logging.Logger] = logging.getLogger("sentinel.authn")


def tenant_credentials() -> dict[str, str]:
    """Tenant → bearer token, from ``SENTINEL_API_TOKENS``.

    Malformed configuration yields NOTHING rather than a partial map. A
    half-parsed credential table would authenticate some tenants and silently
    lock out others, which is a confusing failure to debug and a dangerous one
    to half-succeed at; callers treat an empty map as "no credentials
    configured", which is fail-closed.
    """
    raw = get_settings().api_tokens
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        _LOG.error("SENTINEL_API_TOKENS is not valid JSON; no tenants authenticated")
        return {}
    if not isinstance(parsed, dict):
        _LOG.error("SENTINEL_API_TOKENS must be a JSON object of tenant -> token")
        return {}
    return {str(tenant): str(token) for tenant, token in parsed.items() if token}


def auth_configured() -> bool:
    """Whether ANY credential is configured: single-tenant, per-tenant or operator."""
    settings = get_settings()
    return (
        settings.api_token is not None
        or settings.admin_token is not None
        or bool(tenant_credentials())
    )


def is_admin(presented: str) -> bool:
    """Whether a credential is the OPERATOR's — the one that may administer.

    Administration means replacing a policy or clearing a quarantine. It is kept
    apart from tenant credentials on purpose: tenant tokens are what agents
    hold, and an agent whose credential could administer could rewrite its own
    policy or lift its own quarantine — the guardrail and the thing it guards
    would share a key.

    * ``SENTINEL_ADMIN_TOKEN`` set: that credential, and only that one.
    * Single-token deployment, no admin token: the one token is the operator's,
      because there is nobody else it could belong to.
    * Per-tenant tokens, no admin token: NOBODY administers. Falling back to
      "any tenant may" is precisely the hole this closes.
    """
    if not presented:
        return False
    settings = get_settings()
    if settings.admin_token is not None:
        return compare_digest(presented, settings.admin_token)
    if settings.api_token is not None and not tenant_credentials():
        return compare_digest(presented, settings.api_token)
    return False


def tenant_policy_paths() -> dict[str, str]:
    """Tenant → policy file, from ``SENTINEL_TENANT_POLICIES``.

    Malformed configuration is an ERROR rather than an empty map: unlike
    credentials, silently dropping a tenant's policy would leave that tenant
    running the deployment policy while its operator believes their own is in
    force.
    """
    raw = get_settings().tenant_policies
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"SENTINEL_TENANT_POLICIES is not valid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ValueError("SENTINEL_TENANT_POLICIES must be a JSON object of tenant -> path")
    return {str(tenant): str(path) for tenant, path in parsed.items()}


def resolve_tenant(presented: str) -> str | None:
    """The tenant a credential authenticates as, or ``None`` if it matches none.

    Compared with :func:`hmac.compare_digest` against every configured
    credential, and deliberately WITHOUT returning early on a match, so the time
    taken does not reveal which tenant's token was supplied — or how far down the
    table a near-miss got.
    """
    if not presented:
        return None
    matched: str | None = None
    for tenant, token in tenant_credentials().items():
        if compare_digest(presented, token):
            matched = tenant
    single = get_settings().api_token
    if single is not None and compare_digest(presented, single):
        matched = DEFAULT_TENANT
    return matched


def bearer_credential(headers: object) -> str:
    """The bearer token in a header mapping, or ``""``.

    Takes the mapping rather than a request so both a Starlette ``Request`` and
    a raw ASGI scope can be handed to it.
    """
    get = getattr(headers, "get", None)
    if get is None:
        return ""
    raw = get("authorization", "") or ""
    if not raw.lower().startswith("bearer "):
        return ""
    return str(raw[7:]).strip()
