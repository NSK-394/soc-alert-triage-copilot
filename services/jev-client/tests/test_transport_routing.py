"""Tests for client.py's _resolve_transport (JEV_ROUTE=openrouter fallback routing).

See client.py's module-level comment near _ROUTE_ENV for the full rationale: this
exists because api.typesafe.ai's real 401 (waitlist not cleared) means the repo's
.env currently routes through OpenRouter's System One endpoint instead, using a
separate OPENROUTER_API_KEY credential.
"""
from __future__ import annotations

from client import _resolve_transport


def test_explicit_api_key_wins_untouched(monkeypatch):
    monkeypatch.setenv("JEV_ROUTE", "openrouter")
    monkeypatch.setenv("OPENROUTER_API_KEY", "or-key")
    api_key, base_url = _resolve_transport("explicit-key", None)
    assert api_key == "explicit-key"
    assert base_url is None


def test_explicit_base_url_wins_untouched(monkeypatch):
    monkeypatch.setenv("JEV_ROUTE", "openrouter")
    api_key, base_url = _resolve_transport(None, "https://explicit.example")
    assert api_key is None
    assert base_url == "https://explicit.example"


def test_direct_route_default_pins_api_key_none_and_direct_base_url(monkeypatch):
    """api_key stays None (SDK's own TYPESAFE_API_KEY env resolution applies), but
    base_url is explicitly pinned to api.typesafe.ai -- NOT left None. A live test
    caught why: this repo's .env also sets TYPESAFE_BASE_URL (for the openrouter
    branch), which typesafe_sdk reads itself regardless of this wrapper -- leaving
    base_url=None here would silently redirect "direct" calls to OpenRouter's host
    while still sending the real TypeSafe API key (wrong host/key pairing)."""
    monkeypatch.delenv("JEV_ROUTE", raising=False)
    monkeypatch.setenv("TYPESAFE_BASE_URL", "https://openrouter.ai/api/v1/system-one")
    api_key, base_url = _resolve_transport(None, None)
    assert api_key is None
    assert base_url == "https://api.typesafe.ai"


def test_direct_route_pinned_even_without_typesafe_base_url_set(monkeypatch):
    monkeypatch.delenv("JEV_ROUTE", raising=False)
    monkeypatch.delenv("TYPESAFE_BASE_URL", raising=False)
    api_key, base_url = _resolve_transport(None, None)
    assert api_key is None
    assert base_url == "https://api.typesafe.ai"


def test_openrouter_route_resolves_from_env(monkeypatch):
    monkeypatch.setenv("JEV_ROUTE", "openrouter")
    monkeypatch.setenv("OPENROUTER_API_KEY", "or-key-123")
    monkeypatch.setenv("TYPESAFE_BASE_URL", "https://openrouter.ai/api/v1/system-one")
    api_key, base_url = _resolve_transport(None, None)
    assert api_key == "or-key-123"
    assert base_url == "https://openrouter.ai/api/v1/system-one"


def test_openrouter_route_falls_back_to_default_base_url(monkeypatch):
    monkeypatch.setenv("JEV_ROUTE", "openrouter")
    monkeypatch.setenv("OPENROUTER_API_KEY", "or-key-123")
    monkeypatch.delenv("TYPESAFE_BASE_URL", raising=False)
    api_key, base_url = _resolve_transport(None, None)
    assert api_key == "or-key-123"
    assert base_url == "https://openrouter.ai/api/v1/system-one"


def test_route_value_is_case_insensitive(monkeypatch):
    monkeypatch.setenv("JEV_ROUTE", "OpenRouter")
    monkeypatch.setenv("OPENROUTER_API_KEY", "or-key-123")
    api_key, _ = _resolve_transport(None, None)
    assert api_key == "or-key-123"
