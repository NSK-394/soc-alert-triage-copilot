"""Orchestrates a single Tier-2 brief generation end to end (docs/architecture.md
§6): check budget -> resolve provider -> build context -> generate -> validate
citations -> retry generation exactly once if citations are invalid -> raise if
still invalid.

The RQ job-queue wiring that will call this off `queued_with_tier2_brief` alerts
is a later integration phase (not this task) -- this module is the self-contained
library that phase will call directly.
"""
from __future__ import annotations

import asyncpg

from budget_guard import check_budget
from citation_validator import validate_citations
from context_builder import build_context
from providers import Brief, resolve_provider


class BudgetExceededError(RuntimeError):
    """Raised when today's Tier-2 budget (brief count or USD ceiling) is already
    spent, instead of returning None. A None return is too easy for a caller to
    accidentally ignore; a specific exception forces the caller to handle it (and,
    per spec, log a `budget_exceeded` event and skip generation) rather than
    silently proceeding as if a brief were generated.
    """


class InvalidCitationError(RuntimeError):
    """Raised when a brief still cites a log_line_id that doesn't exist in its
    context after one retry. Carries the still-invalid ids for logging/debugging.
    """

    def __init__(self, message: str, invalid_ids: list[str]):
        super().__init__(message)
        self.invalid_ids = invalid_ids


async def generate_brief_for_alert(
    pool: asyncpg.Pool,
    alert: dict,
    provider_override: str | None = None,
    daily_brief_cap: int = 300,
    daily_usd_ceiling: float = 10.00,
) -> Brief:
    """Generates a citation-validated Brief for `alert`.

    Raises:
        BudgetExceededError: today's Tier-2 budget is already spent.
        InvalidCitationError: the brief still cites a nonexistent log_line_id
            after one retry.

    Note: `Tier2Provider.generate_brief` is a synchronous call (it wraps the
    synchronous `openai` client, per the Protocol in providers.py/docs/
    architecture.md §6) invoked here from inside an async function. That's a
    blocking call on the event loop; acceptable for this phase since the
    Protocol's signature is fixed by the architecture spec, and this function
    itself is only ever invoked from a worker context (the future RQ
    integration), not from request-handling code. Moving it off-thread (e.g.
    `asyncio.to_thread`) is a reasonable follow-up for that integration phase,
    not a correctness issue for this library.
    """
    status = await check_budget(pool, daily_brief_cap, daily_usd_ceiling)
    if not status.allowed:
        raise BudgetExceededError(status.reason or "Tier-2 daily budget exceeded")

    provider = await resolve_provider(provider_override, pool=pool)
    context = await build_context(pool, alert)

    brief = provider.generate_brief(alert, context)
    valid, invalid_ids = validate_citations(brief, context)

    if not valid:
        # Reject and retry exactly once, per docs/architecture.md §6.
        brief = provider.generate_brief(alert, context)
        valid, invalid_ids = validate_citations(brief, context)
        if not valid:
            raise InvalidCitationError(
                f"Brief cited nonexistent log_line_id(s) after retry: {invalid_ids}",
                invalid_ids,
            )

    return brief
