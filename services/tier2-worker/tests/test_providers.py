"""Tests for providers.py: cost computation from real token usage (never the
model's self-reported cost), and provider-resolution precedence. The OpenAI
client is always mocked -- no real API calls happen in this suite.
"""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from providers import DEFAULT_MODEL_KEY, PRICING, OpenAIProvider, compute_cost_usd, resolve_provider


class FakeSettingsPool:
    """Minimal asyncpg.Pool stand-in exposing only the async fetchrow() this
    module's DB read needs."""

    def __init__(self, settings_value: str | None):
        self._settings_value = settings_value
        self.calls = 0

    async def fetchrow(self, query, *args):
        self.calls += 1
        if self._settings_value is None:
            return None
        return {"value": self._settings_value}


def _fake_openai_response(content_dict: dict, tokens_in: int, tokens_out: int):
    return SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=json.dumps(content_dict)))],
        usage=SimpleNamespace(prompt_tokens=tokens_in, completion_tokens=tokens_out),
    )


class FakeOpenAIClient:
    def __init__(self, response):
        self._response = response
        self.last_kwargs: dict | None = None
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **kwargs):
        self.last_kwargs = kwargs
        return self._response


# --- cost computation -------------------------------------------------------


@pytest.mark.parametrize(
    "key,tokens_in,tokens_out",
    [
        ("luna", 20_000, 5_000),
        ("sol", 12_345, 6_789),
        ("astra", 1_000, 1_000),
        ("luna", 0, 0),
    ],
)
def test_compute_cost_usd_matches_pricing_table(key, tokens_in, tokens_out):
    price_in, price_out = PRICING[key]
    expected = (tokens_in / 1_000_000) * price_in + (tokens_out / 1_000_000) * price_out
    assert compute_cost_usd(key, tokens_in, tokens_out) == pytest.approx(expected)


def test_compute_cost_usd_luna_matches_architecture_spec_example():
    # docs/architecture.md §6: Luna, ~20k-in/5k-out brief -> ~$0.0045.
    cost = compute_cost_usd("luna", tokens_in=20_000, tokens_out=5_000)
    assert cost == pytest.approx(0.0045, rel=1e-6)


def test_generate_brief_computes_cost_from_usage_not_model_output():
    # The model's JSON includes a bogus self-reported cost; it must be ignored
    # entirely -- cost_usd is computed only from usage tokens x PRICING.
    content = {
        "summary": "test summary",
        "attack_chain": [],
        "mitre_techniques": [],
        "recommended_actions": [],
        "open_questions": [],
        "cited_log_ids": [],
        "cost_usd": 999.0,
        "tokens_in": 1,
        "tokens_out": 1,
    }
    response = _fake_openai_response(content, tokens_in=1000, tokens_out=500)
    client = FakeOpenAIClient(response)
    provider = OpenAIProvider(model="gpt-6-luna", provider_key="luna", client=client)

    brief = provider.generate_brief(alert={"id": "a1"}, context=[])

    assert brief.tokens_in == 1000
    assert brief.tokens_out == 500
    assert brief.cost_usd == pytest.approx(compute_cost_usd("luna", 1000, 500))
    assert brief.cost_usd != pytest.approx(999.0)


def test_generate_brief_handles_missing_usage_gracefully():
    content = {
        "summary": "s",
        "attack_chain": [],
        "mitre_techniques": [],
        "recommended_actions": [],
        "open_questions": [],
        "cited_log_ids": [],
    }
    response = SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=json.dumps(content)))],
        usage=None,
    )
    client = FakeOpenAIClient(response)
    provider = OpenAIProvider(model="gpt-6-luna", provider_key="luna", client=client)

    brief = provider.generate_brief(alert={"id": "a1"}, context=[])

    assert brief.tokens_in == 0
    assert brief.tokens_out == 0
    assert brief.cost_usd == 0.0


# --- provider resolution precedence -----------------------------------------


async def test_resolve_provider_explicit_override_wins_over_everything(monkeypatch):
    monkeypatch.setenv("TIER2_MODEL", "sol")
    pool = FakeSettingsPool(settings_value="astra")

    provider = await resolve_provider("luna", pool=pool)

    assert provider.provider_key == "luna"
    assert pool.calls == 0  # settings table never even queried once override given


async def test_resolve_provider_settings_table_wins_over_env_var(monkeypatch):
    monkeypatch.setenv("TIER2_MODEL", "sol")
    pool = FakeSettingsPool(settings_value="astra")

    provider = await resolve_provider(None, pool=pool)

    assert provider.provider_key == "astra"


async def test_resolve_provider_env_var_wins_over_default(monkeypatch):
    monkeypatch.setenv("TIER2_MODEL", "sol")
    pool = FakeSettingsPool(settings_value=None)

    provider = await resolve_provider(None, pool=pool)

    assert provider.provider_key == "sol"


async def test_resolve_provider_env_var_used_when_no_pool_given(monkeypatch):
    monkeypatch.setenv("TIER2_MODEL", "astra")

    provider = await resolve_provider(None, pool=None)

    assert provider.provider_key == "astra"


async def test_resolve_provider_defaults_to_luna_when_nothing_set(monkeypatch):
    monkeypatch.delenv("TIER2_MODEL", raising=False)

    provider = await resolve_provider(None, pool=None)

    assert provider.provider_key == DEFAULT_MODEL_KEY == "luna"


async def test_resolve_provider_unknown_key_raises_value_error(monkeypatch):
    monkeypatch.delenv("TIER2_MODEL", raising=False)

    with pytest.raises(ValueError):
        await resolve_provider("nonexistent-model", pool=None)
