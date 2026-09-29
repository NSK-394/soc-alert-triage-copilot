"""Tests for worker.py: the retry-once-on-bad-citation flow, budget enforcement,
and the happy path -- all against monkeypatched collaborators (no real DB, no
real OpenAI calls)."""
from __future__ import annotations

import pytest

import worker
from budget_guard import BudgetStatus
from providers import Brief


def _brief(cited_log_ids) -> Brief:
    return Brief(
        summary="s",
        attack_chain=[],
        mitre_techniques=[],
        recommended_actions=[],
        open_questions=[],
        cited_log_ids=cited_log_ids,
        tokens_in=1,
        tokens_out=1,
        cost_usd=0.0,
    )


class FakeProvider:
    """Returns each brief in `briefs` in order, one per generate_brief() call."""

    def __init__(self, briefs):
        self._briefs = list(briefs)
        self.calls = 0

    def generate_brief(self, alert, context):
        self.calls += 1
        return self._briefs.pop(0)


def _patch_collaborators(monkeypatch, provider, context, budget_status=None):
    if budget_status is None:
        budget_status = BudgetStatus(allowed=True, reason=None, briefs_today=0, cost_today=0.0)

    async def fake_check_budget(pool, cap, ceiling):
        return budget_status

    async def fake_resolve_provider(override, pool=None):
        return provider

    async def fake_build_context(pool, alert):
        return context

    monkeypatch.setattr(worker, "check_budget", fake_check_budget)
    monkeypatch.setattr(worker, "resolve_provider", fake_resolve_provider)
    monkeypatch.setattr(worker, "build_context", fake_build_context)


async def test_generate_brief_for_alert_succeeds_on_first_try(monkeypatch):
    context = [{"log_line_id": "a"}]
    provider = FakeProvider([_brief(["a"])])
    _patch_collaborators(monkeypatch, provider, context)

    brief = await worker.generate_brief_for_alert(pool=object(), alert={"id": "x"})

    assert brief.cited_log_ids == ["a"]
    assert provider.calls == 1


async def test_generate_brief_for_alert_retries_once_then_succeeds(monkeypatch):
    context = [{"log_line_id": "a"}]
    # First brief cites a nonexistent id; second (the retry) cites a real one.
    provider = FakeProvider([_brief(["ghost"]), _brief(["a"])])
    _patch_collaborators(monkeypatch, provider, context)

    brief = await worker.generate_brief_for_alert(pool=object(), alert={"id": "x"})

    assert brief.cited_log_ids == ["a"]
    assert provider.calls == 2


async def test_generate_brief_for_alert_raises_invalid_citation_after_second_failure(monkeypatch):
    context = [{"log_line_id": "a"}]
    provider = FakeProvider([_brief(["ghost1"]), _brief(["ghost2"])])
    _patch_collaborators(monkeypatch, provider, context)

    with pytest.raises(worker.InvalidCitationError) as excinfo:
        await worker.generate_brief_for_alert(pool=object(), alert={"id": "x"})

    assert excinfo.value.invalid_ids == ["ghost2"]
    assert provider.calls == 2  # exactly one retry, never a third attempt


async def test_generate_brief_for_alert_raises_budget_exceeded_and_never_calls_provider(monkeypatch):
    provider = FakeProvider([_brief(["a"])])
    blocked_status = BudgetStatus(
        allowed=False,
        reason="daily Tier-2 brief cap reached (300/300)",
        briefs_today=300,
        cost_today=1.0,
    )
    _patch_collaborators(monkeypatch, provider, context=[], budget_status=blocked_status)

    with pytest.raises(worker.BudgetExceededError, match="brief cap reached"):
        await worker.generate_brief_for_alert(pool=object(), alert={"id": "x"})

    assert provider.calls == 0
