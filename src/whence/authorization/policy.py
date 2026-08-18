"""Versioned, declarative policy (BUILD_SPEC §2B) — validated at LOAD time.

A policy is YAML::

    policy_version: 3
    tools:
      send_email:
        rules:
          - id: block-untrusted-origin
            deny_if: "RETRIEVED_CONTENT in effective_provenance"
          - id: domain-allowlist
            deny_if: "recipient_domain not in allowed_domains"
      delete_record:
        rules:
          - id: never
            deny_always: true

Loading is strict and total: structure is validated by Pydantic (unknown keys
rejected), each rule must declare EXACTLY one of ``deny_if`` / ``deny_always``,
and every ``deny_if`` predicate is parsed into a typed AST immediately. Any
problem raises :class:`PolicyLoadError` at load time — never at evaluation time.
The compiled form (:class:`CompiledPolicy`) carries the parsed AST so the engine
never re-parses or sees raw strings.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from importlib.resources import files
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from whence.authorization.ast import Predicate
from whence.authorization.parser import PolicyParseError, parse_condition
from whence.provenance.sanitizer import schema_names


class PolicyLoadError(ValueError):
    """Raised for any malformed policy — bad structure, shape, or predicate."""


class _RuleDoc(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    deny_if: str | None = None
    deny_always: bool | None = None

    @model_validator(mode="after")
    def _exactly_one_effect(self) -> _RuleDoc:
        has_if = self.deny_if is not None
        has_always = self.deny_always is not None
        if has_if == has_always:
            raise ValueError(
                f"rule {self.id!r} must declare exactly one of "
                "'deny_if' or 'deny_always'"
            )
        if has_always and self.deny_always is not True:
            raise ValueError(
                f"rule {self.id!r}: 'deny_always' must be true if present "
                "(a false deny_always is meaningless)"
            )
        return self


class _DeclassifyDoc(BaseModel):
    """Opt-in declassification for ONE tool's output.

    Naming a schema here says: this tool's result may cross the trust boundary
    IF it validates as that schema, and only as the typed value the schema
    extracts. It is deliberately per-tool and deliberately explicit — a global
    or implicit rule would turn taint-clearing into laundering.
    """

    model_config = ConfigDict(extra="forbid")

    schema_name: str = Field(alias="schema")

    @model_validator(mode="after")
    def _schema_is_known(self) -> _DeclassifyDoc:
        if self.schema_name not in schema_names():
            raise ValueError(
                f"unknown declassification schema {self.schema_name!r}; "
                f"available: {', '.join(schema_names())}"
            )
        return self


class _ToolDoc(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rules: list[_RuleDoc]
    declassify: _DeclassifyDoc | None = None


class _PolicyDoc(BaseModel):
    model_config = ConfigDict(extra="forbid")

    policy_version: int
    tools: dict[str, _ToolDoc]


@dataclass(frozen=True)
class CompiledRule:
    """A rule with its predicate already parsed to a typed AST.

    ``deny_always`` rules carry no condition. ``deny_if`` rules carry a parsed
    :class:`Predicate` (either a leaf :class:`Comparison` or a Boolean
    combination via ``and`` / ``or`` / ``not``). Every rule's effect is DENY
    (the policy is deny-only; allow is the absence of a matching deny — see
    the engine).
    """

    id: str
    deny_always: bool
    condition: Predicate | None


@dataclass(frozen=True)
class CompiledPolicy:
    policy_version: int
    tools: dict[str, tuple[CompiledRule, ...]]
    # tool name -> declassification schema name. Absent means this tool's output
    # can never clear taint, which is the default for every tool.
    declassifiers: dict[str, str] = field(default_factory=dict)

    def declassifier_for(self, tool_name: str) -> str | None:
        """The schema a tool's output may be declassified by, if policy allows it."""
        return self.declassifiers.get(tool_name)

    def rules_for(self, tool_name: str) -> tuple[CompiledRule, ...] | None:
        """Rules for ``tool_name``, or ``None`` if the tool is unknown (→ default-deny)."""
        return self.tools.get(tool_name)


def _compile(doc: _PolicyDoc) -> CompiledPolicy:
    tools: dict[str, tuple[CompiledRule, ...]] = {}
    declassifiers: dict[str, str] = {
        name: tool_doc.declassify.schema_name
        for name, tool_doc in doc.tools.items()
        if tool_doc.declassify is not None
    }
    for tool_name, tool_doc in doc.tools.items():
        compiled: list[CompiledRule] = []
        for rule in tool_doc.rules:
            if rule.deny_always:
                compiled.append(
                    CompiledRule(id=rule.id, deny_always=True, condition=None)
                )
            else:
                assert rule.deny_if is not None  # guaranteed by _RuleDoc validator
                try:
                    condition = parse_condition(rule.deny_if)
                except PolicyParseError as exc:
                    raise PolicyLoadError(
                        f"tool {tool_name!r} rule {rule.id!r}: {exc}"
                    ) from exc
                compiled.append(
                    CompiledRule(id=rule.id, deny_always=False, condition=condition)
                )
        tools[tool_name] = tuple(compiled)
    return CompiledPolicy(
        policy_version=doc.policy_version, tools=tools, declassifiers=declassifiers
    )


def load_policy(text: str) -> CompiledPolicy:
    """Parse + validate + compile a policy from YAML text (raises on malformed)."""
    try:
        data: Any = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise PolicyLoadError(f"invalid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise PolicyLoadError("policy must be a YAML mapping at the top level")
    try:
        doc = _PolicyDoc.model_validate(data)
    except ValidationError as exc:
        raise PolicyLoadError(f"invalid policy structure: {exc}") from exc
    return _compile(doc)


def load_policy_file(path: str | Path) -> CompiledPolicy:
    return load_policy(Path(path).read_text(encoding="utf-8"))


def default_policy_path() -> Path:
    """Filesystem path to the bundled canonical policy."""
    return Path(str(files("whence.authorization").joinpath("policies/default.yaml")))


def load_default_policy() -> CompiledPolicy:
    """Load the canonical §2B policy shipped with the package."""
    return load_policy_file(default_policy_path())
