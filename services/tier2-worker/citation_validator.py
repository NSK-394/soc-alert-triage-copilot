"""Validates that every log_line_id a Tier-2 brief cites actually exists in the
context window it was generated from (docs/architecture.md §6: the worker
"rejects and retries once if a brief cites a log_line_id that doesn't exist in
the context it was given"). This is the hard backstop behind the prompt-level
injection defense in prompt.py -- even a manipulated brief can't fabricate a
citation that passes this check.
"""
from __future__ import annotations

from providers import Brief


def validate_citations(brief: Brief, context: list[dict]) -> tuple[bool, list[str]]:
    """Checks every id in `brief.cited_log_ids`, AND every `log_line_id` embedded
    in an `attack_chain` step (each step is required, per prompt.py's schema, to
    carry its own log_line_id), against the real `log_line_id`s present in
    `context`.

    Returns (valid, invalid_ids): `valid` is True only if every citation from
    both sources exists in context; `invalid_ids` is the sorted, de-duplicated
    list of every citation that doesn't.
    """
    known_ids = {item["log_line_id"] for item in context if item.get("log_line_id") is not None}

    cited: set[str] = set(brief.cited_log_ids)

    for step in brief.attack_chain:
        if isinstance(step, dict):
            step_id = step.get("log_line_id")
            if step_id is not None:
                cited.add(step_id)

    invalid_ids = sorted(cid for cid in cited if cid not in known_ids)
    return (len(invalid_ids) == 0, invalid_ids)
