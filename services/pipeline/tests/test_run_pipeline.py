"""Unit tests for services/pipeline/run_pipeline.py.

Everything that talks to the outside world -- the DB pool, JevClient, the policy
evaluator, both notifier functions, and tier2-worker's generate_brief_for_alert/
resolve_provider -- is faked or monkeypatched. No real Postgres, Redis, Jev, Slack,
PagerDuty, or OpenAI call happens anywhere in this file.
"""
from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest

import run_pipeline
from client import JevUnavailableError
from evaluator import PolicyOutcome
from providers import Brief

_SCENARIOS_DIR = Path(__file__).resolve().parents[3] / "infra" / "wazuh" / "scenarios"


def _load_scenario(name: str) -> dict:
    with (_SCENARIOS_DIR / f"{name}.json").open("r", encoding="utf-8") as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# build_state_object_from_wazuh: field mapping
# ---------------------------------------------------------------------------


def test_build_state_object_maps_ssh_brute_force_fields():
    raw = _load_scenario("ssh_brute_force")
    state = run_pipeline.build_state_object_from_wazuh(raw)

    assert state["alert"]["source"] == "wazuh"
    assert state["alert"]["rule_id"] == "5712"
    assert state["alert"]["rule_description"] == "SSHD brute force trying to get access"
    assert state["alert"]["rule_level"] == 10
    assert state["alert"]["mitre_hint"] == ["T1110"]
    assert state["alert"]["timestamp_utc"] == raw["timestamp"]

    assert state["entities"]["src_ip"] == "203.0.113.7"
    assert state["entities"]["user"] == "svc-backup"
    assert state["entities"]["host"] == "db-prod-02"

    assert state["untrusted_evidence"]["raw_log_excerpt"] == raw["full_log"]

    # Only off_hours is genuinely computed; everything else is the documented MVP default.
    derived = state["derived"]
    assert isinstance(derived["off_hours"], bool)
    assert derived["failed_auth_10m"] == 0
    assert derived["successful_auth_after_failures"] is False
    assert derived["src_ip_first_seen_days"] == 0
    assert derived["src_ip_reputation"] == "unknown"
    assert derived["host_criticality"] == "unknown"
    assert derived["rule_historical_fp_rate"] == 0.0
    assert derived["similar_alerts_24h"] == 0


def test_build_state_object_falls_back_when_no_srcuser():
    # new_listening_service.json has neither data.srcuser nor data.dstuser.
    raw = _load_scenario("new_listening_service")
    state = run_pipeline.build_state_object_from_wazuh(raw)

    assert state["entities"]["user"] is None
    assert state["entities"]["src_ip"] is None
    assert state["entities"]["host"] == "db-prod-02"
    # Real MITRE id from rule.mitre.id, not fabricated from rule.groups tags.
    assert state["alert"]["mitre_hint"] == ["T1571"]


def test_build_state_object_sudo_abuse_uses_srcuser_not_dstuser():
    raw = _load_scenario("sudo_abuse")
    state = run_pipeline.build_state_object_from_wazuh(raw)
    assert state["entities"]["user"] == "jenkins"  # srcuser wins over dstuser="root"


def test_build_state_object_no_mitre_hint_stays_empty_not_fabricated():
    raw = _load_scenario("ssh_brute_force")
    del raw["rule"]["mitre"]
    state = run_pipeline.build_state_object_from_wazuh(raw)
    assert state["alert"]["mitre_hint"] == []


def test_build_state_object_missing_timestamp_raises():
    raw = _load_scenario("ssh_brute_force")
    del raw["timestamp"]
    with pytest.raises(ValueError):
        run_pipeline.build_state_object_from_wazuh(raw)


# ---------------------------------------------------------------------------
# run_pipeline(): action-branching logic, everything else mocked
# ---------------------------------------------------------------------------


class FakePool:
    def __init__(self, alert_row: dict):
        self.alert_row = alert_row
        self.executed: list[tuple[str, tuple]] = []

    async def fetchrow(self, query: str, *args):
        return dict(self.alert_row)

    async def fetchval(self, query: str, *args):
        # Only real caller today is _jev_daily_call_count's COUNT(*) query --
        # 0 keeps every existing test scenario safely under any cap.
        return 0

    async def execute(self, query: str, *args):
        self.executed.append((query, args))
        return "OK"

    def executed_tables(self) -> list[str]:
        tables = []
        for query, _ in self.executed:
            first_line = " ".join(query.split())
            tables.append(first_line)
        return tables


class FakeDecision:
    def __init__(self, **overrides):
        defaults = dict(
            triage_verdict="true_positive",
            is_false_positive_prob=0.1,
            severity="critical",
            attack_category="credential_access",
            needs_more_context_prob=0.2,
            business_impact_if_true="high",
            confidence_margin=0.9,
            raw_response={"usage": {"input_tokens": 111, "output_tokens": 22}},
            latency_ms=123,
        )
        defaults.update(overrides)
        self.__dict__.update(defaults)


class FakeJevClient:
    """Stands in for JevClient -- construction takes no args (matches
    run_pipeline.py's `JevClient()` call), and the class itself (not an instance)
    is monkeypatched in so each call to `JevClient()` returns a fresh instance
    configured with whichever decision/error the test wants.
    """

    decision: FakeDecision | None = None
    error: Exception | None = None
    closed_count = 0

    def __init__(self):
        self.closed = False

    def score_alert(self, state):
        if type(self).error is not None:
            raise type(self).error
        return type(self).decision

    def close(self):
        self.closed = True
        type(self).closed_count += 1


def _alert_row(raw: dict, normalized: dict | None = None) -> dict:
    return {
        "id": uuid.uuid4(),
        "source": "wazuh",
        "external_id": raw.get("id"),
        "incident_id": None,
        "raw": raw,
        "normalized": normalized or {},
        "ground_truth_label": None,
        "ingested_at": None,
    }


def _fake_provider(provider_key="luna", model="gpt-6-luna"):
    class _Provider:
        pass

    p = _Provider()
    p.provider_key = provider_key
    p.model = model
    return p


def _fake_brief() -> Brief:
    return Brief(
        summary="s",
        attack_chain=[{"step": "x", "log_line_id": "a"}],
        mitre_techniques=["T1110"],
        recommended_actions=["do it"],
        open_questions=[],
        cited_log_ids=["a"],
        tokens_in=100,
        tokens_out=50,
        cost_usd=0.001,
    )


@pytest.fixture(autouse=True)
def _reset_fake_jev_client():
    FakeJevClient.decision = None
    FakeJevClient.error = None
    FakeJevClient.closed_count = 0
    yield


@pytest.fixture(autouse=True)
def _patch_policy(monkeypatch):
    # Real policy YAML content is irrelevant here -- evaluate() itself is
    # monkeypatched per-test, so _get_policy() just needs to not touch disk.
    monkeypatch.setattr(run_pipeline, "_get_policy", lambda: {})


@pytest.fixture(autouse=True)
def _patch_jev_client(monkeypatch):
    monkeypatch.setattr(run_pipeline, "JevClient", FakeJevClient)


async def test_run_pipeline_auto_close_writes_no_brief_or_notification(monkeypatch):
    raw = _load_scenario("ssh_brute_force")
    pool = FakePool(_alert_row(raw))
    FakeJevClient.decision = FakeDecision(severity="informational", triage_verdict="false_positive")

    monkeypatch.setattr(
        run_pipeline,
        "evaluate",
        lambda *a, **k: PolicyOutcome(
            action="auto_close", rule_version="v1", reason="test", shadow_mode=False
        ),
    )

    def _boom(*a, **k):
        raise AssertionError("should not be called on the auto_close path")

    monkeypatch.setattr(run_pipeline, "send_slack_notification", _boom)
    monkeypatch.setattr(run_pipeline, "page_pagerduty", _boom)
    monkeypatch.setattr(run_pipeline, "generate_brief_for_alert", _boom)

    await run_pipeline.run_pipeline(pool, str(pool.alert_row["id"]))

    tables = pool.executed_tables()
    assert any("UPDATE alerts SET normalized" in q for q in tables)
    assert any("INSERT INTO jev_decisions" in q for q in tables)
    assert any("INSERT INTO policy_outcomes" in q for q in tables)
    assert not any("INSERT INTO briefs" in q for q in tables)
    assert FakeJevClient.closed_count == 1


async def test_run_pipeline_auto_escalate_calls_both_notifiers(monkeypatch):
    raw = _load_scenario("ssh_brute_force")
    pool = FakePool(_alert_row(raw))
    FakeJevClient.decision = FakeDecision(severity="critical", triage_verdict="true_positive")

    monkeypatch.setattr(
        run_pipeline,
        "evaluate",
        lambda *a, **k: PolicyOutcome(
            action="auto_escalate",
            rule_version="v1",
            reason="test",
            shadow_mode=False,
            notify_actions=["notify_slack", "page_pagerduty"],
        ),
    )

    slack_calls = []
    pd_calls = []
    monkeypatch.setattr(
        run_pipeline,
        "send_slack_notification",
        lambda alert_id, summary, severity, verdict: slack_calls.append((alert_id, summary, severity, verdict)),
    )
    monkeypatch.setattr(
        run_pipeline,
        "page_pagerduty",
        lambda alert_id, summary, severity, jev_verdict=None: pd_calls.append(
            (alert_id, summary, severity, jev_verdict)
        ),
    )

    async def _boom(*a, **k):
        raise AssertionError("generate_brief_for_alert should not be called on the auto_escalate path")

    monkeypatch.setattr(run_pipeline, "generate_brief_for_alert", _boom)

    alert_id = str(pool.alert_row["id"])
    await run_pipeline.run_pipeline(pool, alert_id)

    assert len(slack_calls) == 1
    assert slack_calls[0][0] == alert_id
    assert "SSHD brute force" in slack_calls[0][1]
    assert slack_calls[0][2] == "critical"
    assert len(pd_calls) == 1


async def test_run_pipeline_jev_failure_fails_safe_to_queued(monkeypatch):
    raw = _load_scenario("ssh_brute_force")
    pool = FakePool(_alert_row(raw))
    FakeJevClient.error = JevUnavailableError("boom")

    captured_kwargs = {}

    def _fake_evaluate(policy, **kwargs):
        captured_kwargs.update(kwargs)
        return PolicyOutcome(action="queued", rule_version="v1", reason="jev failed", shadow_mode=False)

    monkeypatch.setattr(run_pipeline, "evaluate", _fake_evaluate)
    monkeypatch.setattr(run_pipeline, "resolve_provider", _async_return(_fake_provider()))
    monkeypatch.setattr(run_pipeline, "generate_brief_for_alert", _async_return(_fake_brief()))

    await run_pipeline.run_pipeline(pool, str(pool.alert_row["id"]))

    assert captured_kwargs["jev_failed"] is True
    tables = pool.executed_tables()
    # No jev_decisions row on a Jev failure (per the fail-safe contract).
    assert not any("INSERT INTO jev_decisions" in q for q in tables)
    assert any("INSERT INTO policy_outcomes" in q for q in tables)
    assert any("INSERT INTO briefs" in q for q in tables)
    assert any("INSERT INTO costs" in q and "'tier2'" in q for q in tables)


async def test_run_pipeline_queued_generates_and_stores_brief(monkeypatch):
    raw = _load_scenario("ssh_brute_force")
    pool = FakePool(_alert_row(raw))
    FakeJevClient.decision = FakeDecision(triage_verdict="true_positive", severity="high")

    monkeypatch.setattr(
        run_pipeline,
        "evaluate",
        lambda *a, **k: PolicyOutcome(action="queued", rule_version="v1", reason="default", shadow_mode=False),
    )
    monkeypatch.setattr(run_pipeline, "resolve_provider", _async_return(_fake_provider("sol", "gpt-6-sol")))
    monkeypatch.setattr(run_pipeline, "generate_brief_for_alert", _async_return(_fake_brief()))

    await run_pipeline.run_pipeline(pool, str(pool.alert_row["id"]))

    tables = pool.executed_tables()
    assert any("INSERT INTO jev_decisions" in q for q in tables)
    assert any("INSERT INTO briefs" in q for q in tables)
    assert any("INSERT INTO costs" in q and "'tier2'" in q for q in tables)
    assert any("INSERT INTO costs" in q and "'jev'" in q for q in tables)

    # provider_model / model were taken from resolve_provider's result.
    briefs_call = next(a for q, a in pool.executed if "INSERT INTO briefs" in " ".join(q.split()))
    assert briefs_call[1] == "sol"


async def test_run_pipeline_budget_exceeded_skips_without_crashing(monkeypatch):
    raw = _load_scenario("ssh_brute_force")
    pool = FakePool(_alert_row(raw))
    FakeJevClient.decision = FakeDecision()

    monkeypatch.setattr(
        run_pipeline,
        "evaluate",
        lambda *a, **k: PolicyOutcome(action="queued", rule_version="v1", reason="default", shadow_mode=False),
    )
    monkeypatch.setattr(run_pipeline, "resolve_provider", _async_return(_fake_provider()))

    async def _raise_budget(*a, **k):
        raise run_pipeline.BudgetExceededError("daily cap reached")

    monkeypatch.setattr(run_pipeline, "generate_brief_for_alert", _raise_budget)

    await run_pipeline.run_pipeline(pool, str(pool.alert_row["id"]))  # must not raise

    tables = pool.executed_tables()
    assert not any("INSERT INTO briefs" in q for q in tables)


async def test_run_pipeline_invalid_citation_skips_without_crashing(monkeypatch):
    raw = _load_scenario("ssh_brute_force")
    pool = FakePool(_alert_row(raw))
    FakeJevClient.decision = FakeDecision()

    monkeypatch.setattr(
        run_pipeline,
        "evaluate",
        lambda *a, **k: PolicyOutcome(action="queued", rule_version="v1", reason="default", shadow_mode=False),
    )
    monkeypatch.setattr(run_pipeline, "resolve_provider", _async_return(_fake_provider()))

    async def _raise_citation(*a, **k):
        raise run_pipeline.InvalidCitationError("bad citation", ["ghost"])

    monkeypatch.setattr(run_pipeline, "generate_brief_for_alert", _raise_citation)

    await run_pipeline.run_pipeline(pool, str(pool.alert_row["id"]))  # must not raise

    tables = pool.executed_tables()
    assert not any("INSERT INTO briefs" in q for q in tables)


async def test_run_pipeline_skips_renormalization_when_already_normalized(monkeypatch):
    raw = _load_scenario("ssh_brute_force")
    existing_state = {
        "alert": {"rule_id": "5712"},
        "entities": {},
        "derived": {"host_criticality": "unknown"},
        "untrusted_evidence": {"raw_log_excerpt": ""},
    }
    pool = FakePool(_alert_row(raw, normalized=existing_state))
    FakeJevClient.decision = FakeDecision()

    def _boom(raw):
        raise AssertionError("build_state_object_from_wazuh should not be called when normalized already exists")

    monkeypatch.setattr(run_pipeline, "build_state_object_from_wazuh", _boom)
    monkeypatch.setattr(
        run_pipeline,
        "evaluate",
        lambda *a, **k: PolicyOutcome(action="auto_close", rule_version="v1", reason="x", shadow_mode=False),
    )

    await run_pipeline.run_pipeline(pool, str(pool.alert_row["id"]))

    tables = pool.executed_tables()
    assert not any("UPDATE alerts SET normalized" in q for q in tables)


async def test_run_pipeline_never_raises_on_unexpected_error():
    class ExplodingPool:
        async def fetchrow(self, *a, **k):
            raise RuntimeError("db exploded")

    # Must not raise -- a bug processing one alert must never crash the worker.
    await run_pipeline.run_pipeline(ExplodingPool(), str(uuid.uuid4()))


def _async_return(value):
    async def _inner(*args, **kwargs):
        return value

    return _inner
