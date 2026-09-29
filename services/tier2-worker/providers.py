"""The Tier-2 provider abstraction (docs/architecture.md §6): one interface, three
interchangeable OpenAI-compatible models. Default is Luna for cost; Sol and Astra
are drop-in swaps selected via the `TIER2_MODEL` env var (or a `settings.tier2_model`
DB override) -- no other code change required.
"""
from __future__ import annotations

import os
from typing import Protocol

from pydantic import BaseModel

from prompt import SYSTEM_PROMPT, build_user_message, parse_brief_response

# $ per 1,000,000 tokens, as (price_in, price_out) -- docs/architecture.md §6's
# pricing table. This is OUR OWN pricing reference, used to compute cost_usd from
# the API response's actual usage.prompt_tokens/usage.completion_tokens. The model
# is never trusted to report its own cost.
PRICING: dict[str, tuple[float, float]] = {
    "luna": (0.10, 0.50),
    "sol": (2.0, 10.0),
    "astra": (10.0, 50.0),
}

DEFAULT_MODEL_KEY = "luna"

# Provider key -> the actual model name passed to the OpenAI-compatible API.
_MODEL_NAMES: dict[str, str] = {
    "luna": "gpt-6-luna",
    "sol": "gpt-6-sol",
    "astra": "gpt-6-astra",
}


class Brief(BaseModel):
    summary: str
    attack_chain: list[dict]
    mitre_techniques: list[str]
    recommended_actions: list[str]
    open_questions: list[str]
    cited_log_ids: list[str]
    tokens_in: int
    tokens_out: int
    cost_usd: float


class Tier2Provider(Protocol):
    def generate_brief(self, alert: dict, context: list[dict]) -> Brief: ...


def compute_cost_usd(provider_key: str, tokens_in: int, tokens_out: int) -> float:
    """Computes cost from real token counts against PRICING -- the one place cost
    is ever calculated. Never derived from anything the model itself reports."""
    price_in, price_out = PRICING[provider_key]
    return (tokens_in / 1_000_000) * price_in + (tokens_out / 1_000_000) * price_out


def _infer_provider_key(model: str) -> str:
    for key, name in _MODEL_NAMES.items():
        if name == model:
            return key
    raise ValueError(f"Unknown model {model!r}; can't determine its PRICING tier")


class OpenAIProvider:
    """Tier2Provider backed by the official `openai` SDK, parameterized by model
    name. One instance per provider key (see PROVIDERS below); the client is
    created lazily so importing this module never requires OPENAI_API_KEY to be
    set, and tests can inject a mock client directly.
    """

    def __init__(self, model: str, provider_key: str | None = None, client=None):
        self.model = model
        self.provider_key = provider_key or _infer_provider_key(model)
        self._client = client

    @property
    def client(self):
        if self._client is None:
            from openai import OpenAI

            # Reads OPENAI_API_KEY from the environment (loaded via python-dotenv
            # by whatever entrypoint imports this module -- see worker.py).
            self._client = OpenAI()
        return self._client

    def generate_brief(self, alert: dict, context: list[dict]) -> Brief:
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": build_user_message(alert, context)},
            ],
            # JSON mode rather than strict `json_schema` structured outputs: Luna/
            # Sol/Astra are this project's own custom model names (not standard
            # OpenAI models), so there is no way to confirm ahead of time that the
            # backend serving them supports strict schema-constrained decoding. A
            # provider that doesn't recognize `response_format: json_schema` may
            # reject the request outright, which would break every call. JSON mode
            # (`type: json_object`) is the widely-supported, safer baseline; the
            # detailed schema in SYSTEM_PROMPT plus parse_brief_response()'s
            # defensive parsing (raising a clear BriefParseError on malformed or
            # incomplete JSON, never crashing silently) is the fallback path the
            # architecture spec calls for when schema-mode support is uncertain.
            response_format={"type": "json_object"},
        )

        choice = response.choices[0]
        parsed = parse_brief_response(choice.message.content)

        usage = response.usage
        tokens_in = usage.prompt_tokens if usage is not None else 0
        tokens_out = usage.completion_tokens if usage is not None else 0
        cost_usd = compute_cost_usd(self.provider_key, tokens_in, tokens_out)

        return Brief(
            **parsed,
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            cost_usd=cost_usd,
        )


PROVIDERS: dict[str, Tier2Provider] = {
    key: OpenAIProvider(model=name, provider_key=key) for key, name in _MODEL_NAMES.items()
}


async def resolve_provider(override: str | None = None, pool=None) -> Tier2Provider:
    """Resolves which provider to use, in precedence order:
    1. `override` (explicit function argument) wins outright.
    2. Else, if `pool` is given, the `settings.tier2_model` row in the DB (the
       dashboard's global override, per docs/architecture.md §9/§4).
    3. Else, the `TIER2_MODEL` env var.
    4. Else, the default ("luna").

    `pool` is optional and, when given, is expected to be an asyncpg Pool (or
    anything exposing an async `.fetchrow(query, *args)` like asyncpg.Pool does) --
    this function is async specifically so it can await that DB read; callers with
    no pool (or no DB access at that point) can omit it and still get the env var
    / default behavior.
    """
    key: str | None = None

    if override:
        key = override
    elif pool is not None:
        row = await pool.fetchrow("SELECT value FROM settings WHERE key = 'tier2_model'")
        if row and row["value"]:
            key = row["value"]

    if not key:
        key = os.environ.get("TIER2_MODEL")

    if not key:
        key = DEFAULT_MODEL_KEY

    key = key.strip().lower()
    if key not in PROVIDERS:
        raise ValueError(f"Unknown TIER2 provider {key!r}; choices: {sorted(PROVIDERS)}")

    return PROVIDERS[key]
