"""Ensures the jev-client package root is importable regardless of the directory pytest is
invoked from (jev-client's directory name contains a hyphen, so it can't be reached via a normal
dotted `import`)."""

import os
import sys

import pytest

_PACKAGE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PACKAGE_ROOT not in sys.path:
    sys.path.insert(0, _PACKAGE_ROOT)

# Tests must be deterministic regardless of what the real repo-root .env happens to
# set (client.py calls load_dotenv() at import time). This previously worked by
# accident -- TYPESAFE_BASE_URL/JEV_ROUTE/OPENROUTER_API_KEY were never actually set
# in .env, so the SDK's own env-var fallback resolution never kicked in during
# tests. Now that .env legitimately sets these (routing through OpenRouter while
# api.typesafe.ai's waitlist is gated), tests need explicit isolation from them so
# a real ops config change can never silently change what these tests exercise.
_ENV_VARS_TO_CLEAR = ("TYPESAFE_BASE_URL", "JEV_ROUTE", "OPENROUTER_API_KEY", "TYPESAFE_API_KEY")


@pytest.fixture(autouse=True)
def _isolate_transport_env(monkeypatch):
    for var in _ENV_VARS_TO_CLEAR:
        monkeypatch.delenv(var, raising=False)
