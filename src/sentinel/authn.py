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
from typing import Final, cast

from sentinel.authorization.registry import DEFAULT_TENANT
from sentinel.config import get_settings

_LOG: Final[logging.Logger] = logging.getLogger("sentinel.authn")
# The browser credential carrier (issued by ``POST /auth/session``). Defined
# here, not in the app, because the rate limiter reads it too.
SESSION_COOKIE: Final[str] = "sentinel_session"


def _credentials_match(presented: str, expected: str) -> bool:
    """Constant-time credential comparison that is defined for all Unicode input.

    ``hmac.compare_digest`` accepts ``str`` only when both strings are ASCII.
    Request headers are attacker-controlled, so a non-ASCII bearer must simply
    fail authentication—not turn the rate-limit middleware into an HTTP 500.
    """
    return compare_digest(
        presented.encode("utf-8", "surrogatepass"), expected.encode("utf-8", "surrogatepass")
    )


def tenant_credentials() -> dict[str, str]:
    """Tenant → bearer token, from ``SENTINEL_API_TOKENS``.

    Malformed or ambiguous configuration yields NOTHING rather than a partial
    map. A half-parsed credential table would authenticate some tenants and
    silently lock out others. Its *presence* still puts the deployment in
    multi-tenant mode, so it cannot fall back to a single-token operator.
    """
    raw = get_settings().api_tokens
    if not raw:
        return {}

    def reject_duplicate_keys(pairs: list[tuple[object, object]]) -> dict[object, object]:
        table: dict[object, object] = {}
        for tenant, token in pairs:
            if tenant in table:
                raise ValueError(f"duplicate tenant {tenant!r}")
            table[tenant] = token
        return table

    try:
        parsed = json.loads(raw, object_pairs_hook=reject_duplicate_keys)
    except (json.JSONDecodeError, ValueError) as exc:
        _LOG.error("SENTINEL_API_TOKENS is invalid; no tenants authenticated: %s", exc)
        return {}
    if not isinstance(parsed, dict):
        _LOG.error("SENTINEL_API_TOKENS must be a JSON object of tenant -> token")
        return {}
    if (
        not parsed
        or any(
            not isinstance(tenant, str)
            or not tenant.strip()
            or not isinstance(token, str)
            or not token
            for tenant, token in parsed.items()
        )
    ):
        _LOG.error("SENTINEL_API_TOKENS must map non-empty tenant names to string tokens")
        return {}
    tokens = dict(parsed)
    if len(set(tokens.values())) != len(tokens):
        _LOG.error("SENTINEL_API_TOKENS must not assign one token to multiple tenants")
        return {}
    return cast(dict[str, str], tokens)


def _multi_tenant_configured() -> bool:
    """Whether a multi-tenant table was supplied, valid or not.

    A malformed table is a deployment error, not permission to downgrade into
    the single-token mode. Authentication remains configured and every caller
    is refused until the operator repairs the table.
    """
    raw = get_settings().api_tokens
    return raw is not None and bool(raw.strip())


def auth_configured() -> bool:
    """Whether ANY credential is configured: single-tenant, per-tenant or operator."""
    settings = get_settings()
    return (
        settings.api_token is not None
        or settings.admin_token is not None
        or _multi_tenant_configured()
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
        return _credentials_match(presented, settings.admin_token)
    if settings.api_token is not None and not _multi_tenant_configured():
        return _credentials_match(presented, settings.api_token)
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
    tenants = tenant_credentials()
    for tenant, token in tenants.items():
        if _credentials_match(presented, token):
            matched = tenant
    # SENTINEL_API_TOKEN authenticates the default tenant on its own AND
    # alongside a valid per-tenant table (a supported combination). Only a
    # table that is present but unusable disables it: that deployment is
    # misconfigured and fails closed for every credential until it is fixed,
    # rather than quietly falling back to the single token.
    single = get_settings().api_token
    single_usable = not _multi_tenant_configured() or bool(tenants)
    if single_usable and single is not None and _credentials_match(presented, single):
        matched = DEFAULT_TENANT
    return matched


def bearer_credential(headers: object) -> str:
    """The bearer token in a header mapping, or ``""``.

    Takes the mapping rather than a request so both a Starlette ``Request`` and
    a raw ASGI scope can be handed to it.
    """
    # ASGI permits repeated header fields. Do not let one part of the gateway
    # read a different Authorization value than another: ambiguity is not a
    # credential and must fail closed. Starlette's Headers exposes getlist;
    # plain mappings (used by programmatic callers) retain their single value.
    getlist = getattr(headers, "getlist", None)
    if callable(getlist):
        values = getlist("authorization")
        if len(values) != 1:
            return ""
        raw = values[0] or ""
    else:
        get = getattr(headers, "get", None)
        if get is None:
            return ""
        raw = get("authorization", "") or ""
    if not raw.lower().startswith("bearer "):
        return ""
    return str(raw[7:]).strip()
