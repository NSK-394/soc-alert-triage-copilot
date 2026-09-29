"""Tests for budget_guard.py: under/over both the daily brief-count cap and the
daily USD ceiling, against a mocked DB pool."""
from __future__ import annotations

from budget_guard import check_budget


class FakePool:
    """Minimal asyncpg.Pool stand-in: returns a fixed aggregate row for the
    check_budget() query regardless of its actual SQL/args."""

    def __init__(self, briefs_today: int, cost_today: float):
        self._row = {"briefs_today": briefs_today, "cost_today": cost_today}

    async def fetchrow(self, query, *args):
        return self._row


async def test_check_budget_allowed_when_under_both_caps():
    pool = FakePool(briefs_today=5, cost_today=1.0)

    status = await check_budget(pool, daily_brief_cap=300, daily_usd_ceiling=10.0)

    assert status.allowed is True
    assert status.reason is None
    assert status.briefs_today == 5
    assert status.cost_today == 1.0


async def test_check_budget_blocked_when_over_count_cap():
    pool = FakePool(briefs_today=301, cost_today=1.0)

    status = await check_budget(pool, daily_brief_cap=300, daily_usd_ceiling=10.0)

    assert status.allowed is False
    assert "brief cap" in status.reason


async def test_check_budget_blocked_when_over_usd_ceiling():
    pool = FakePool(briefs_today=5, cost_today=10.50)

    status = await check_budget(pool, daily_brief_cap=300, daily_usd_ceiling=10.0)

    assert status.allowed is False
    assert "USD ceiling" in status.reason


async def test_check_budget_blocked_exactly_at_count_cap():
    # >= semantics: hitting the cap exactly blocks the NEXT brief, it doesn't
    # allow one more over it.
    pool = FakePool(briefs_today=300, cost_today=0.0)

    status = await check_budget(pool, daily_brief_cap=300, daily_usd_ceiling=10.0)

    assert status.allowed is False


async def test_check_budget_blocked_exactly_at_usd_ceiling():
    pool = FakePool(briefs_today=1, cost_today=10.0)

    status = await check_budget(pool, daily_brief_cap=300, daily_usd_ceiling=10.0)

    assert status.allowed is False


async def test_check_budget_allowed_just_under_both_caps():
    pool = FakePool(briefs_today=299, cost_today=9.9999)

    status = await check_budget(pool, daily_brief_cap=300, daily_usd_ceiling=10.0)

    assert status.allowed is True
