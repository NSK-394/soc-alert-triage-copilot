"""Tests for citation_validator.py: valid/invalid ids in cited_log_ids, and ids
embedded in attack_chain steps."""
from __future__ import annotations

from citation_validator import validate_citations
from providers import Brief


def _brief(cited_log_ids, attack_chain=None) -> Brief:
    return Brief(
        summary="s",
        attack_chain=attack_chain or [],
        mitre_techniques=[],
        recommended_actions=[],
        open_questions=[],
        cited_log_ids=cited_log_ids,
        tokens_in=1,
        tokens_out=1,
        cost_usd=0.0,
    )


def test_validate_citations_all_valid():
    context = [{"log_line_id": "a"}, {"log_line_id": "b"}]
    brief = _brief(["a", "b"])

    valid, invalid = validate_citations(brief, context)

    assert valid is True
    assert invalid == []


def test_validate_citations_invalid_id_in_cited_log_ids():
    context = [{"log_line_id": "a"}]
    brief = _brief(["a", "ghost"])

    valid, invalid = validate_citations(brief, context)

    assert valid is False
    assert invalid == ["ghost"]


def test_validate_citations_invalid_id_embedded_in_attack_chain_step():
    context = [{"log_line_id": "a"}]
    brief = _brief(["a"], attack_chain=[{"step": "did a thing", "log_line_id": "fake-id"}])

    valid, invalid = validate_citations(brief, context)

    assert valid is False
    assert invalid == ["fake-id"]


def test_validate_citations_valid_attack_chain_id_not_in_cited_log_ids_still_checked():
    # A step citing a real id that the model forgot to also list in
    # cited_log_ids should still pass -- attack_chain ids are checked
    # independently, not merely as a subset check of cited_log_ids.
    context = [{"log_line_id": "a"}]
    brief = _brief([], attack_chain=[{"step": "did a thing", "log_line_id": "a"}])

    valid, invalid = validate_citations(brief, context)

    assert valid is True
    assert invalid == []


def test_validate_citations_dedupes_and_sorts_invalid_ids():
    context: list[dict] = []
    brief = _brief(["z", "a"], attack_chain=[{"step": "x", "log_line_id": "a"}])

    valid, invalid = validate_citations(brief, context)

    assert valid is False
    assert invalid == ["a", "z"]


def test_validate_citations_empty_citations_against_empty_context_is_valid():
    brief = _brief([])

    valid, invalid = validate_citations(brief, [])

    assert valid is True
    assert invalid == []


def test_validate_citations_attack_chain_step_with_no_log_line_id_is_ignored():
    # A step that omits log_line_id shouldn't be treated as an invalid citation
    # of "None" -- it simply contributes nothing to the cited-id set.
    context = [{"log_line_id": "a"}]
    brief = _brief(["a"], attack_chain=[{"step": "no citation here"}])

    valid, invalid = validate_citations(brief, context)

    assert valid is True
    assert invalid == []
