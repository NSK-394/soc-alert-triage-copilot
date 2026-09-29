"""Margin/entropy computation correctness on hand-constructed probability arrays
(docs/architecture.md §5: compute margin/entropy from the FULL probabilities array, never trust a
single bundled confidence value)."""

from __future__ import annotations

import math

import pytest

from client import compute_margin_and_entropy


def test_confident_two_way_choice() -> None:
    # A clear winner: margin should be large, entropy low.
    margin, entropy = compute_margin_and_entropy({"true_positive": 0.95, "false_positive": 0.05})
    assert margin == pytest.approx(0.90)
    expected_entropy = -(0.95 * math.log(0.95) + 0.05 * math.log(0.05))
    assert entropy == pytest.approx(expected_entropy)


def test_ambiguous_two_way_choice_near_zero_margin() -> None:
    # Two options nearly tied: this is exactly the case §5 warns a bundled confidence value would
    # hide -- top1 alone could still read "51% confident" while the real signal is "coin flip."
    margin, entropy = compute_margin_and_entropy({"true_positive": 0.51, "false_positive": 0.49})
    assert margin == pytest.approx(0.02)
    # Entropy for a near-50/50 split should be close to the max possible for 2 outcomes (ln 2).
    assert entropy == pytest.approx(math.log(2), abs=0.01)


def test_uniform_distribution_is_max_entropy_zero_margin() -> None:
    probabilities = {"a": 0.25, "b": 0.25, "c": 0.25, "d": 0.25}
    margin, entropy = compute_margin_and_entropy(probabilities)
    assert margin == pytest.approx(0.0)
    assert entropy == pytest.approx(math.log(4))


def test_single_certain_outcome_is_zero_entropy_full_margin() -> None:
    probabilities = {"critical": 1.0, "high": 0.0, "low": 0.0, "informational": 0.0}
    margin, entropy = compute_margin_and_entropy(probabilities)
    assert margin == pytest.approx(1.0)
    assert entropy == pytest.approx(0.0)


def test_zero_probabilities_are_skipped_not_logged() -> None:
    # log(0) is undefined; entries with p == 0 must be excluded from the entropy sum rather than
    # raising or contributing -inf.
    margin, entropy = compute_margin_and_entropy({"x": 1.0, "y": 0.0, "z": 0.0})
    assert margin == pytest.approx(1.0)
    assert entropy == pytest.approx(0.0)


def test_single_option_distribution() -> None:
    margin, entropy = compute_margin_and_entropy({"only_option": 1.0})
    assert margin == pytest.approx(1.0)  # top2 defaults to 0.0 when there is no second option
    assert entropy == pytest.approx(0.0)


def test_empty_distribution_returns_zeros() -> None:
    assert compute_margin_and_entropy({}) == (0.0, 0.0)


def test_four_way_score_distribution_matches_hand_calculation() -> None:
    # severity: informational / low / high / critical
    probabilities = {"informational": 0.05, "low": 0.10, "high": 0.60, "critical": 0.25}
    margin, entropy = compute_margin_and_entropy(probabilities)
    assert margin == pytest.approx(0.60 - 0.25)
    expected_entropy = -sum(p * math.log(p) for p in probabilities.values())
    assert entropy == pytest.approx(expected_entropy)
