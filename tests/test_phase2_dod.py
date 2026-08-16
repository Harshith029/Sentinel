"""Phase 2 Definition of Done — all 18 cases (BUILD_SPEC §2B DoD).

These exercise provenance + authorization TOGETHER, end-to-end, the way the
proxy will. Provenance verdicts here come from real transitive graph walks
(not hard-coded flags); policy verdicts come from the typed-AST engine with
deny-overrides + default-deny.
"""
from __future__ import annotations

import itertools
import textwrap
from decimal import Decimal

import pytest

from whence.authorization.engine import AuthorizationEngine, ToolCall
from whence.authorization.policy import (
    PolicyLoadError,
    load_default_policy,
    load_policy,
)
from whence.forensics.emitter import SpanEmitter
from whence.forensics.events import AuthorizationDecided
from whence.forensics.replay import replay
from whence.forensics.store import InMemoryForensicStore
from whence.labels import Label
from whence.provenance.graph import ProvenanceGraph
from whence.provenance.model import ProvenanceNode
from whence.provenance.sanitizer import DecimalAmountSchema, StructuredExtractor

CONFIG: dict[str, object] = {
    "allowed_domains": ["corp.example"],
    "max_amount": Decimal("1000"),
}
# Byte-identical send_email arguments reused across DoD 1 & 2.
SEND_ARGS: dict[str, object] = {"recipient_domain": "corp.example", "subject": "status"}


def _engine() -> AuthorizationEngine:
    return AuthorizationEngine(load_default_policy())


def _node(span_id: str, label: Label, *parents: str) -> ProvenanceNode:
    return ProvenanceNode(span_id=span_id, label=label, derived_from=tuple(parents))


def _ep(graph: ProvenanceGraph, span_id: str) -> frozenset[Label]:
    result = graph.effective_provenance(span_id)
    assert not result.anomalous, f"unexpected anomaly: {result}"
    return result.labels


def _extractor() -> StructuredExtractor:
    ids = itertools.count(1)
    return StructuredExtractor(id_factory=lambda: f"clean-{next(ids)}")


# --- DoD 1 / 2: same call, provenance decides --------------------------------

def test_dod01_user_originated_send_email_allowed() -> None:
    g = ProvenanceGraph([_node("u", "USER"), _node("compose", "AGENT", "u")])
    result = _engine().authorize(
        ToolCall(name="send_email", arguments=SEND_ARGS, provenance=_ep(g, "compose"),
                 config=CONFIG)
    )
    assert result.allowed is True


def test_dod02_byte_identical_call_with_retrieved_ancestor_blocked() -> None:
    g = ProvenanceGraph(
        [
            _node("u", "USER"),
            _node("doc", "RETRIEVED_CONTENT", "u"),
            _node("compose", "AGENT", "u", "doc"),
        ]
    )
    result = _engine().authorize(
        ToolCall(name="send_email", arguments=SEND_ARGS, provenance=_ep(g, "compose"),
                 config=CONFIG)
    )
    assert result.allowed is False
    assert result.matched_rule_id == "block-untrusted-origin"


# --- DoD 3: summarize fetched doc then email → summary stays tainted ----------

def test_dod03_summarize_then_email_stays_tainted() -> None:
    g = ProvenanceGraph(
        [
            _node("u", "USER"),
            _node("fetch", "RETRIEVED_CONTENT", "u"),
            _node("summary", "AGENT", "fetch"),   # agent summarizes the fetched doc
            _node("email", "AGENT", "summary"),   # then composes an email from it
        ]
    )
    # The taint survives summarization because the walk unions the ancestor's
    # RETRIEVED_CONTENT — not because any flag was propagated.
    assert "RETRIEVED_CONTENT" in _ep(g, "summary")
    assert "RETRIEVED_CONTENT" in _ep(g, "email")
    result = _engine().authorize(
        ToolCall(name="send_email", arguments=SEND_ARGS, provenance=_ep(g, "email"),
                 config=CONFIG)
    )
    assert result.allowed is False
    assert result.matched_rule_id == "block-untrusted-origin"


# --- DoD 4 / 5: two docs, mixed trust; sanitize EVERY contributor or stay tainted

def test_dod04_mixed_ancestry_one_unsanitized_is_tainted() -> None:
    doc1 = _node("doc1", "RETRIEVED_CONTENT")
    doc2 = _node("doc2", "RETRIEVED_CONTENT")
    g = ProvenanceGraph([doc1, doc2])
    s1 = _extractor().sanitize(doc1, DecimalAmountSchema(), content="10")
    assert s1 is not None
    g.add(s1.node)
    # doc2 was NOT sanitized → it remains an ancestor of the email.
    g.add(_node("email", "AGENT", s1.node.span_id, "doc2"))
    result = _engine().authorize(
        ToolCall(name="send_email", arguments=SEND_ARGS, provenance=_ep(g, "email"),
                 config=CONFIG)
    )
    assert result.allowed is False
    assert result.matched_rule_id == "block-untrusted-origin"


def test_dod05_mixed_ancestry_all_sanitized_is_allowed() -> None:
    doc1 = _node("doc1", "RETRIEVED_CONTENT")
    doc2 = _node("doc2", "RETRIEVED_CONTENT")
    g = ProvenanceGraph([doc1, doc2])
    ext = _extractor()
    s1 = ext.sanitize(doc1, DecimalAmountSchema(), content="10")
    s2 = ext.sanitize(doc2, DecimalAmountSchema(), content="20")
    assert s1 is not None and s2 is not None
    g.add(s1.node)
    g.add(s2.node)
    g.add(_node("email", "AGENT", s1.node.span_id, s2.node.span_id))
    prov = _ep(g, "email")
    assert "RETRIEVED_CONTENT" not in prov  # every untrusted contributor cleared
    result = _engine().authorize(
        ToolCall(name="send_email", arguments=SEND_ARGS, provenance=prov, config=CONFIG)
    )
    assert result.allowed is True


# --- DoD 6 / 7: the sanitizer clears on match, fails on mismatch --------------

def test_dod06_structured_extractor_clears_on_schema_match() -> None:
    tainted = _node("page", "RETRIEVED_CONTENT")
    out = _extractor().sanitize(tainted, DecimalAmountSchema(), content="999999")
    assert out is not None
    assert out.value == Decimal("999999")
    g = ProvenanceGraph([tainted, out.node])
    assert g.is_tainted(out.node.span_id) is False


def test_dod07_structured_extractor_fails_on_mismatch_taint_persists() -> None:
    tainted = _node("page", "RETRIEVED_CONTENT")
    out = _extractor().sanitize(
        tainted, DecimalAmountSchema(), content="totally not a number"
    )
    assert out is None
    assert ProvenanceGraph([tainted]).is_tainted("page") is True


# --- DoD 8: recombination regression — a sanitized value cannot launder -------

def test_dod08_recombination_regression_taint_reappears() -> None:
    page = _node("page", "RETRIEVED_CONTENT")
    free_text = _node("free_text", "RETRIEVED_CONTENT")
    g = ProvenanceGraph([page, free_text])
    clean = _extractor().sanitize(page, DecimalAmountSchema(), content="42")
    assert clean is not None
    g.add(clean.node)
    assert g.is_tainted(clean.node.span_id) is False  # the extracted value alone

    g.add(_node("recombined", "AGENT", clean.node.span_id, "free_text"))
    assert g.is_tainted("recombined") is True  # tainted sibling re-taints


# --- DoD 9: delete_record is always denied ------------------------------------

def test_dod09_delete_record_always_denied() -> None:
    result = _engine().authorize(
        ToolCall(name="delete_record", arguments={"id": 1}, provenance=frozenset({"USER"}))
    )
    assert result.allowed is False
    assert result.matched_rule_id == "never"


# --- DoD 10 / 11 / 12: transfer cap boundary and user-only provenance ---------

def test_dod10_transfer_at_cap_boundary_is_denied() -> None:
    result = _engine().authorize(
        ToolCall(name="transfer_funds", arguments={"amount": Decimal("1000")},
                 provenance=frozenset({"USER"}), config=CONFIG)
    )
    assert result.allowed is False
    assert result.matched_rule_id == "cap"  # amount >= max_amount at the boundary


def test_dod11_transfer_below_cap_is_allowed() -> None:
    result = _engine().authorize(
        ToolCall(name="transfer_funds", arguments={"amount": Decimal("999.99")},
                 provenance=frozenset({"USER"}), config=CONFIG)
    )
    assert result.allowed is True


def test_dod12_transfer_requires_exactly_user_provenance() -> None:
    # Below the cap, but agent-tainted provenance ({USER, AGENT}) ≠ {USER}.
    result = _engine().authorize(
        ToolCall(name="transfer_funds", arguments={"amount": Decimal("1")},
                 provenance=frozenset({"USER", "AGENT"}), config=CONFIG)
    )
    assert result.allowed is False
    assert result.matched_rule_id == "user-only"
    # Short-circuit: 'cap' is never reached.
    assert [r.rule_id for r in result.rules_considered] == ["user-only"]


# --- DoD 13: deny-overrides short-circuits a later would-allow ----------------

def test_dod13_deny_overrides_short_circuits_later_would_allow() -> None:
    policy = load_policy(
        textwrap.dedent(
            """
            policy_version: 1
            tools:
              pay:
                rules:
                  - id: early-deny
                    deny_if: "amount >= max_amount"
                  - id: later-would-allow
                    deny_if: "recipient_domain not in allowed_domains"
            """
        )
    )
    result = AuthorizationEngine(policy).authorize(
        ToolCall(
            name="pay",
            # early-deny matches; later rule would NOT deny (domain is allowed).
            arguments={"amount": Decimal("1000"), "recipient_domain": "corp.example"},
            config=CONFIG,
        )
    )
    assert result.allowed is False
    assert result.matched_rule_id == "early-deny"
    assert [r.rule_id for r in result.rules_considered] == ["early-deny"]


# --- DoD 14: unknown tool → default-deny --------------------------------------

def test_dod14_unknown_tool_default_deny() -> None:
    result = _engine().authorize(ToolCall(name="launch_missiles"))
    assert result.allowed is False
    assert result.matched_rule_id is None
    assert result.rules_considered == ()
    assert "default-deny" in result.reason


# --- DoD 15: malformed policy rejected at load --------------------------------

_MALFORMED: dict[str, str] = {
    "unsupported_op": (
        'policy_version: 1\ntools:\n  x:\n    rules:\n      - id: r\n'
        '        deny_if: "amount > max_amount"\n'
    ),
    "both_effects": (
        'policy_version: 1\ntools:\n  x:\n    rules:\n      - id: r\n'
        '        deny_if: "amount >= max_amount"\n        deny_always: true\n'
    ),
    "neither_effect": "policy_version: 1\ntools:\n  x:\n    rules:\n      - id: r\n",
    "version_not_int": "policy_version: three\ntools: {}\n",
}


@pytest.mark.parametrize("name", sorted(_MALFORMED))
def test_dod15_malformed_policy_rejected_at_load(name: str) -> None:
    with pytest.raises(PolicyLoadError):
        load_policy(_MALFORMED[name])


# --- DoD 16: every decision yields a complete decision-trace span -------------

async def test_dod16_every_decision_yields_complete_decision_span() -> None:
    engine = _engine()
    call = ToolCall(
        name="send_email",
        arguments=SEND_ARGS,
        provenance=frozenset({"USER", "RETRIEVED_CONTENT"}),
        config=CONFIG,
    )
    payload = engine.decision_payload(call)

    # Completeness of the decision trace.
    assert isinstance(payload, AuthorizationDecided)
    assert payload.tool_name == "send_email"
    assert payload.decision == "DENY"
    assert payload.policy_version == "3"
    assert payload.is_tainted is True
    assert "RETRIEVED_CONTENT" in payload.effective_provenance
    assert payload.matched_rule_id == "block-untrusted-origin"
    assert payload.reason
    assert len(payload.rules_considered) >= 1

    # It is a real forensic span: it persists and replays via the Phase 1 spine.
    store = InMemoryForensicStore()
    emitter = SpanEmitter(store)
    tid = emitter.new_trace_id()
    await emitter.emit(payload, trace_id=tid)
    rep = await replay(store, tid)
    (restored,) = rep.ordered
    assert restored.payload == payload


# --- DoD 17: provenance traversal is cycle-safe -------------------------------

def test_dod17_provenance_traversal_is_cycle_safe() -> None:
    g = ProvenanceGraph(
        [_node("a", "AGENT", "b"), _node("b", "USER", "a")]  # a <-> b cycle
    )
    result = g.effective_provenance("a")  # must terminate, not recurse forever
    assert result.malformed is True
    assert g.is_tainted("a") is True  # fail-closed


# --- DoD 18: domain allowlist blocks an untrusted recipient -------------------

def test_dod18_domain_allowlist_blocks_untrusted_recipient() -> None:
    # Clean provenance (block-untrusted-origin does NOT match), but the recipient
    # domain is not allowlisted → the SECOND rule denies.
    result = _engine().authorize(
        ToolCall(
            name="send_email",
            arguments={"recipient_domain": "exfil.evil", "subject": "x"},
            provenance=frozenset({"USER"}),
            config=CONFIG,
        )
    )
    assert result.allowed is False
    assert result.matched_rule_id == "domain-allowlist"
    assert [r.rule_id for r in result.rules_considered] == [
        "block-untrusted-origin",
        "domain-allowlist",
    ]
