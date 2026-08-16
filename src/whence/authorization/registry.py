"""Multi-tenant policy registry (BUILD_SPEC §Phase 8).

Policies are namespaced per tenant/agent and hot-reloaded ON VERSION BUMP: a
re-submitted policy replaces the active one only when its ``policy_version`` is
greater than the currently-loaded version. A same-or-older version is ignored,
so a stale or accidental re-push can never silently downgrade a tenant's policy.
Malformed policy is rejected at load time (it never becomes active).
"""
from __future__ import annotations

from dataclasses import dataclass

from whence.authorization.engine import AuthorizationEngine
from whence.authorization.policy import CompiledPolicy, load_default_policy, load_policy

DEFAULT_TENANT = "default"


@dataclass(frozen=True)
class ReloadResult:
    """Outcome of a hot-reload attempt."""

    tenant: str
    reloaded: bool
    version: int
    previous_version: int | None
    detail: str


class PolicyRegistry:
    """Per-tenant compiled policies with version-gated hot-reload."""

    def __init__(self) -> None:
        self._policies: dict[str, CompiledPolicy] = {}

    @classmethod
    def with_default(cls) -> PolicyRegistry:
        """A registry seeded with the canonical policy under the default tenant."""
        registry = cls()
        registry.register(DEFAULT_TENANT, load_default_policy())
        return registry

    def register(self, tenant: str, policy: CompiledPolicy) -> None:
        self._policies[tenant] = policy

    def get(self, tenant: str) -> CompiledPolicy | None:
        return self._policies.get(tenant)

    def version(self, tenant: str) -> int | None:
        policy = self._policies.get(tenant)
        return policy.policy_version if policy is not None else None

    def engine_for(self, tenant: str) -> AuthorizationEngine | None:
        """The engine a given tenant's calls are authorized against."""
        policy = self._policies.get(tenant)
        return AuthorizationEngine(policy) if policy is not None else None

    def tenants(self) -> list[str]:
        return sorted(self._policies)

    def reload_if_newer(self, tenant: str, text: str) -> ReloadResult:
        """Compile ``text`` and swap it in for ``tenant`` only if it is newer.

        Raises ``PolicyLoadError`` (from :func:`load_policy`) on malformed input,
        BEFORE touching the active policy — a bad push cannot take a tenant down.
        """
        candidate = load_policy(text)
        current = self._policies.get(tenant)
        if current is None:
            self._policies[tenant] = candidate
            return ReloadResult(
                tenant=tenant, reloaded=True, version=candidate.policy_version,
                previous_version=None, detail="initial load",
            )
        if candidate.policy_version > current.policy_version:
            self._policies[tenant] = candidate
            return ReloadResult(
                tenant=tenant, reloaded=True, version=candidate.policy_version,
                previous_version=current.policy_version,
                detail=f"hot-reloaded v{current.policy_version} → v{candidate.policy_version}",
            )
        return ReloadResult(
            tenant=tenant, reloaded=False, version=current.policy_version,
            previous_version=current.policy_version,
            detail=(
                f"ignored: submitted v{candidate.policy_version} is not newer than "
                f"active v{current.policy_version}"
            ),
        )
