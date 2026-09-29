"""Answers "is Tier-2 allowed to generate another brief right now?" against the
daily brief-count cap and USD ceiling from docs/architecture.md §6 ("hard daily
cap on brief count (default 300/day), and the worker refuses to fire once the
day's costs cross a configured USD ceiling").

This module only answers the question -- it does NOT log a `budget_exceeded`
event and does not itself block generation. Per the spec, the caller (worker.py
here; the later RQ integration layer eventually) is responsible for logging that
event and skipping Tier-2 generation when `allowed` is False.
"""
from __future__ import annotations

import asyncpg
from pydantic import BaseModel


class BudgetStatus(BaseModel):
    allowed: bool
    reason: str | None
    briefs_today: int
    cost_today: float


async def check_budget(
    pool: asyncpg.Pool, daily_brief_cap: int, daily_usd_ceiling: float
) -> BudgetStatus:
    """Sums today's Tier-2 spend and counts today's Tier-2 briefs from `costs`
    (`call_type = 'tier2'`, `created_at::date = CURRENT_DATE`) and compares
    against both caps. The count cap is checked first; either cap being crossed
    is sufficient to disallow.
    """
    row = await pool.fetchrow(
        """
        SELECT COUNT(*) AS briefs_today, COALESCE(SUM(cost_usd), 0) AS cost_today
        FROM costs
        WHERE call_type = 'tier2'
          AND created_at::date = CURRENT_DATE
        """
    )
    briefs_today = int(row["briefs_today"])
    cost_today = float(row["cost_today"])

    if briefs_today >= daily_brief_cap:
        return BudgetStatus(
            allowed=False,
            reason=f"daily Tier-2 brief cap reached ({briefs_today}/{daily_brief_cap})",
            briefs_today=briefs_today,
            cost_today=cost_today,
        )

    if cost_today >= daily_usd_ceiling:
        return BudgetStatus(
            allowed=False,
            reason=(
                f"daily Tier-2 USD ceiling reached "
                f"(${cost_today:.4f}/${daily_usd_ceiling:.2f})"
            ),
            briefs_today=briefs_today,
            cost_today=cost_today,
        )

    return BudgetStatus(
        allowed=True, reason=None, briefs_today=briefs_today, cost_today=cost_today
    )
