"""The ProvenanceNode (BUILD_SPEC §4.3).

```python
class ProvenanceNode(BaseModel):
    span_id: str
    label: Literal["SYSTEM", "USER", "AGENT", "RETRIEVED_CONTENT"]
    derived_from: list[str] = []      # parent span_ids
    cleared_from: str | None = None   # set by a Sanitizer (see §4.4); auditable
```

Two fields carry the entire taint semantics:

* ``derived_from`` is the ONLY edge the provenance walk follows. A node's
  effective provenance is the union of labels over everything reachable through
  ``derived_from``.
* ``cleared_from`` is set by a sanitizer and is NEVER traversed — it exists for
  audit only. A sanitized node has an empty ``derived_from`` (its tainted source
  is recorded in ``cleared_from`` instead), which is precisely how taint is cut.

``derived_from`` is stored as a tuple so a frozen node is genuinely immutable
(the spec writes ``list[str]``; an immutable tuple is the faithful, safe
rendering). ``span_id`` is a plain string per the spec — these reference forensic
span ids but are not re-validated here.
"""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator

from sentinel.labels import Label


class ProvenanceNode(BaseModel):
    """One node in the provenance DAG: a span_id, its own trust label, and edges."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    span_id: str
    label: Label
    derived_from: tuple[str, ...] = Field(default_factory=tuple)
    cleared_from: str | None = None

    @field_validator("span_id")
    @classmethod
    def _non_empty_span_id(cls, value: str) -> str:
        if not value:
            raise ValueError("span_id must be a non-empty string")
        return value
