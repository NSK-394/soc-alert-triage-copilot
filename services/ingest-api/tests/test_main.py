"""Tests for ingest-api.

These exercise the real Postgres-backed behavior (upsert idempotency, jsonb
round-tripping) end to end via FastAPI's TestClient, rather than mocking the DB --
that's the behavior most worth protecting here.

They require a reachable DATABASE_URL (e.g. `docker compose up postgres`, or any
Postgres with infra/migrations/001_init.sql applied). If DATABASE_URL is unset, or
set but Postgres isn't actually reachable, the whole module is skipped rather than
failing -- CI/local runs won't always have Postgres up, and a skipped suite is more
honest than a suite that silently passes zero assertions.
"""
from __future__ import annotations

import asyncio
import os
import uuid

import asyncpg
import pytest
from fastapi.testclient import TestClient

DATABASE_URL = os.environ.get("DATABASE_URL")


def _postgres_reachable(dsn: str) -> bool:
    async def _check() -> bool:
        try:
            conn = await asyncpg.connect(dsn=dsn, timeout=2)
        except Exception:
            return False
        await conn.close()
        return True

    return asyncio.run(_check())


if not DATABASE_URL or not _postgres_reachable(DATABASE_URL):
    pytest.skip(
        "DATABASE_URL not set or Postgres unreachable -- skipping ingest-api "
        "integration tests (run `docker compose up postgres` to enable them)",
        allow_module_level=True,
    )

import main  # noqa: E402  (import deferred until after the skip check above)


@pytest.fixture()
def client():
    # `with` triggers FastAPI's lifespan (pool creation/teardown) around the test.
    with TestClient(main.app) as test_client:
        yield test_client


def test_healthz(client: TestClient) -> None:
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_replay_happy_path(client: TestClient) -> None:
    body = {
        "source": "guide_replay",
        "external_id": f"test-{uuid.uuid4()}",
        "incident_id": "inc-1",
        "raw": {"foo": "bar"},
        "normalized": {"derived": {"off_hours": True}},
        "ground_truth_label": "true_positive",
    }
    resp = client.post("/replay", json=body)
    assert resp.status_code == 201
    alert_id = resp.json()["id"]
    uuid.UUID(alert_id)  # raises if not a valid uuid

    get_resp = client.get(f"/alerts/{alert_id}")
    assert get_resp.status_code == 200
    data = get_resp.json()
    assert data["id"] == alert_id
    assert data["source"] == "guide_replay"
    assert data["external_id"] == body["external_id"]
    assert data["incident_id"] == "inc-1"
    assert data["raw"] == {"foo": "bar"}
    assert data["normalized"] == {"derived": {"off_hours": True}}
    assert data["ground_truth_label"] == "true_positive"


def test_replay_idempotency(client: TestClient) -> None:
    body = {
        "source": "guide_replay",
        "external_id": f"idempotent-{uuid.uuid4()}",
        "raw": {"n": 1},
    }
    first = client.post("/replay", json=body)
    assert first.status_code == 201
    first_id = first.json()["id"]

    second = client.post("/replay", json=body)
    assert second.status_code == 200
    assert second.json()["id"] == first_id

    # No duplicate row: fetching by id still returns the original payload.
    get_resp = client.get(f"/alerts/{first_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["raw"] == {"n": 1}


def test_webhook_wazuh_happy_path(client: TestClient) -> None:
    payload = {
        "id": f"wazuh-{uuid.uuid4()}",
        "rule": {"id": "5712", "level": 10, "description": "SSHD brute force"},
        "data": {"srcip": "203.0.113.7"},
    }
    resp = client.post("/webhook/wazuh", json=payload)
    assert resp.status_code == 201
    alert_id = resp.json()["id"]

    get_resp = client.get(f"/alerts/{alert_id}")
    assert get_resp.status_code == 200
    data = get_resp.json()
    assert data["source"] == "wazuh"
    assert data["external_id"] == payload["id"]
    assert data["raw"] == payload
    assert data["normalized"] == {}


def test_webhook_wazuh_rejects_empty_body(client: TestClient) -> None:
    resp = client.post("/webhook/wazuh", json={})
    assert resp.status_code == 422


def test_webhook_wazuh_unauthenticated_when_secret_unset(client: TestClient, monkeypatch) -> None:
    """.env's actual default (WAZUH_WEBHOOK_SECRET unset) -- a security audit flagged
    this endpoint as unauthenticated, and this IS the documented, logged-loudly
    unauthenticated state, not a bug. See main.py's _check_webhook_secret."""
    monkeypatch.delenv("WAZUH_WEBHOOK_SECRET", raising=False)
    payload = {"id": f"wazuh-{uuid.uuid4()}", "rule": {"id": "1"}}
    resp = client.post("/webhook/wazuh", json=payload)
    assert resp.status_code == 201


def test_webhook_wazuh_rejects_missing_secret_when_configured(client: TestClient, monkeypatch) -> None:
    monkeypatch.setenv("WAZUH_WEBHOOK_SECRET", "correct-secret")
    payload = {"id": f"wazuh-{uuid.uuid4()}", "rule": {"id": "1"}}
    resp = client.post("/webhook/wazuh", json=payload)
    assert resp.status_code == 401


def test_webhook_wazuh_rejects_wrong_secret_when_configured(client: TestClient, monkeypatch) -> None:
    monkeypatch.setenv("WAZUH_WEBHOOK_SECRET", "correct-secret")
    payload = {"id": f"wazuh-{uuid.uuid4()}", "rule": {"id": "1"}}
    resp = client.post(
        "/webhook/wazuh", json=payload, headers={"X-Webhook-Secret": "wrong-secret"}
    )
    assert resp.status_code == 401


def test_webhook_wazuh_accepts_correct_secret_when_configured(client: TestClient, monkeypatch) -> None:
    monkeypatch.setenv("WAZUH_WEBHOOK_SECRET", "correct-secret")
    payload = {"id": f"wazuh-{uuid.uuid4()}", "rule": {"id": "1"}}
    resp = client.post(
        "/webhook/wazuh", json=payload, headers={"X-Webhook-Secret": "correct-secret"}
    )
    assert resp.status_code == 201


def test_get_alert_not_found(client: TestClient) -> None:
    resp = client.get(f"/alerts/{uuid.uuid4()}")
    assert resp.status_code == 404


def test_webhook_wazuh_enqueues_pipeline_job_on_fresh_insert(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A brand-new /webhook/wazuh alert must enqueue exactly one pipeline job for
    its own id (docs/architecture.md §12, Phase C task 3). The real Redis/RQ queue
    is mocked out here -- this test is only about main.py's wiring, not RQ itself.
    """
    enqueued: list[str] = []
    monkeypatch.setattr(main, "enqueue_pipeline", lambda alert_id: enqueued.append(alert_id))

    payload = {
        "id": f"wazuh-{uuid.uuid4()}",
        "rule": {"id": "5712", "level": 10, "description": "SSHD brute force"},
        "data": {"srcip": "203.0.113.7"},
    }
    resp = client.post("/webhook/wazuh", json=payload)
    assert resp.status_code == 201
    alert_id = resp.json()["id"]

    assert enqueued == [alert_id]


def test_webhook_wazuh_duplicate_does_not_reenqueue(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A redelivered webhook for the same (source, external_id) hits the existing
    idempotency index (created=False) and must NOT enqueue a second pipeline job --
    otherwise a flaky Wazuh integration retrying delivery would fire duplicate
    Jev/Slack/PagerDuty/Tier-2 calls for what is really one alert.
    """
    enqueued: list[str] = []
    monkeypatch.setattr(main, "enqueue_pipeline", lambda alert_id: enqueued.append(alert_id))

    payload = {
        "id": f"wazuh-dup-{uuid.uuid4()}",
        "rule": {"id": "5712", "level": 10, "description": "SSHD brute force"},
        "data": {"srcip": "203.0.113.7"},
    }
    first = client.post("/webhook/wazuh", json=payload)
    assert first.status_code == 201
    second = client.post("/webhook/wazuh", json=payload)
    assert second.status_code == 200

    # Only the first (fresh) delivery enqueued -- the redelivery did not.
    assert enqueued == [first.json()["id"]]


def test_replay_never_enqueues_pipeline_job(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """/replay must NEVER trigger the live pipeline (docs/architecture.md §12,
    Phase C task 3's safety-critical constraint) -- it's used to push large labeled
    benchmark volumes, and enqueueing a live Jev/notifier/Tier-2 job per replayed
    alert would be a serious cost and operational-safety bug.
    """
    enqueued: list[str] = []
    monkeypatch.setattr(main, "enqueue_pipeline", lambda alert_id: enqueued.append(alert_id))

    body = {
        "source": "guide_replay",
        "external_id": f"test-{uuid.uuid4()}",
        "raw": {"foo": "bar"},
    }
    resp = client.post("/replay", json=body)
    assert resp.status_code == 201
    assert enqueued == []
