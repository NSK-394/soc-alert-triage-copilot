"""ingest-api: FastAPI skeleton for the SOC alert triage copilot (docs/architecture.md §12,
Phase A task 2).

Receives alerts from the replay harness (`/replay`) or a Wazuh webhook (`/webhook/wazuh`)
and writes them to the `alerts` table (infra/migrations/001_init.sql). Feature-builder
wiring (populating `normalized`) happens in a later phase -- alerts are stored with
`normalized={}` here.
"""
from __future__ import annotations

import hmac
import logging
import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any

import asyncpg
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from starlette.responses import JSONResponse

from db import close_pool, create_pool
from job_queue import enqueue_pipeline

load_dotenv()

logger = logging.getLogger(__name__)

# Enforced by counting actual bytes as they stream in (see _limited_receive below),
# not just by trusting the declared Content-Length header. A security audit flagged
# that the original Content-Length-only check could be bypassed by a client that
# lies about the header or uses chunked transfer-encoding -- this version can't be
# bypassed that way since it aborts the moment real bytes exceed the cap, regardless
# of what any header claimed.
MAX_BODY_BYTES = 5 * 1024 * 1024  # 5 MB


class BodyTooLargeError(Exception):
    pass


class BodySizeLimitMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        seen = 0

        async def limited_receive():
            nonlocal seen
            message = await receive()
            if message["type"] == "http.request":
                seen += len(message.get("body", b""))
                if seen > MAX_BODY_BYTES:
                    raise BodyTooLargeError()
            return message

        try:
            await self.app(scope, limited_receive, send)
        except BodyTooLargeError:
            response = JSONResponse(
                {"detail": "request body exceeds the 5MB limit"},
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            )
            await response(scope, receive, send)


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.pool = await create_pool()
    try:
        yield
    finally:
        await close_pool(app.state.pool)


app = FastAPI(title="ingest-api", lifespan=lifespan)

app.add_middleware(BodySizeLimitMiddleware)

# Wildcard CORS is a deliberate dev-mode choice (the dashboard runs on a different
# port and there's no dashboard-facing auth yet), but a security audit flagged that
# nothing previously stopped this from also shipping wide-open in a non-local
# deployment -- now explicitly gated on ENV, defaulting to a closed allow-list
# unless ENV=development. Set CORS_ALLOWED_ORIGINS (comma-separated) for a real
# deployment instead of flipping ENV back to development.
_env = os.environ.get("ENV", "development")
if _env == "development":
    _cors_origins = ["*"]
else:
    _cors_origins = [o.strip() for o in os.environ.get("CORS_ALLOWED_ORIGINS", "").split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_pool(request: Request) -> asyncpg.Pool:
    """FastAPI dependency exposing the pool stored on app.state -- handlers never
    touch a module-level global."""
    return request.app.state.pool


class ReplayAlert(BaseModel):
    source: str
    external_id: str | None = None
    incident_id: str | None = None
    raw: dict[str, Any]
    normalized: dict[str, Any] = Field(default_factory=dict)
    ground_truth_label: str | None = None


class AlertOut(BaseModel):
    id: uuid.UUID


class AlertDetail(BaseModel):
    id: uuid.UUID
    source: str
    external_id: str | None
    incident_id: str | None
    raw: dict[str, Any]
    normalized: dict[str, Any]
    ground_truth_label: str | None
    ingested_at: datetime


async def upsert_alert(
    pool: asyncpg.Pool,
    *,
    source: str,
    external_id: str | None,
    incident_id: str | None,
    raw: dict[str, Any],
    normalized: dict[str, Any],
    ground_truth_label: str | None,
) -> tuple[uuid.UUID, bool]:
    """Insert an alert, honoring the partial unique index on (source, external_id).

    Returns (id, created). created is False when a row with the same
    (source, external_id) already existed and this call was a no-op (idempotent
    replay/webhook redelivery) -- the existing row's id is returned instead.
    A NULL external_id is never subject to the unique index, so those always insert.
    """
    async with pool.acquire() as conn:
        inserted_id = await conn.fetchval(
            """
            INSERT INTO alerts (source, external_id, incident_id, raw, normalized, ground_truth_label)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (source, external_id) WHERE external_id IS NOT NULL DO NOTHING
            RETURNING id
            """,
            source,
            external_id,
            incident_id,
            raw,
            normalized,
            ground_truth_label,
        )
        if inserted_id is not None:
            return inserted_id, True

        existing_id = await conn.fetchval(
            "SELECT id FROM alerts WHERE source = $1 AND external_id = $2",
            source,
            external_id,
        )
        if existing_id is None:
            # Should be unreachable: DO NOTHING only fires on a real (source,
            # external_id) collision, so the row must exist. Fail loudly rather
            # than silently returning a bogus id.
            raise HTTPException(status_code=500, detail="failed to insert or locate alert")
        return existing_id, False


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    """Liveness check -- no DB dependency."""
    return {"status": "ok"}


@app.post("/replay", response_model=AlertOut)
async def replay(
    alert: ReplayAlert,
    response: Response,
    pool: asyncpg.Pool = Depends(get_pool),
) -> AlertOut:
    alert_id, created = await upsert_alert(
        pool,
        source=alert.source,
        external_id=alert.external_id,
        incident_id=alert.incident_id,
        raw=alert.raw,
        normalized=alert.normalized,
        ground_truth_label=alert.ground_truth_label,
    )
    response.status_code = status.HTTP_201_CREATED if created else status.HTTP_200_OK
    return AlertOut(id=alert_id)


def _check_webhook_secret(request: Request) -> None:
    """Require a matching X-Webhook-Secret header when WAZUH_WEBHOOK_SECRET is set.

    A security audit flagged this endpoint as unauthenticated: anyone who could
    reach it could trigger real Jev/Tier-2/Slack/PagerDuty calls (cost + paging-noise
    abuse) and write unbounded attacker-controlled rows. WAZUH_WEBHOOK_SECRET is
    unset by default (matches this repo's existing pattern for optional secrets,
    e.g. services/notifier's SLACK_WEBHOOK_URL/PAGERDUTY_API_KEY) so local dev via
    infra/wazuh/simulate.py keeps working with zero setup -- but that means this
    endpoint is genuinely open unless the secret is configured. It MUST be set
    before exposing ingest-api past localhost.
    """
    expected = os.environ.get("WAZUH_WEBHOOK_SECRET")
    if not expected:
        logger.warning(
            "WAZUH_WEBHOOK_SECRET is not set -- /webhook/wazuh is accepting unauthenticated "
            "requests. Fine for local dev, unsafe for any non-local deployment."
        )
        return
    provided = request.headers.get("x-webhook-secret", "")
    if not hmac.compare_digest(provided, expected):
        raise HTTPException(status_code=401, detail="missing or invalid X-Webhook-Secret")


@app.post("/webhook/wazuh", response_model=AlertOut)
async def webhook_wazuh(
    payload: dict[str, Any],
    request: Request,
    response: Response,
    pool: asyncpg.Pool = Depends(get_pool),
) -> AlertOut:
    """Ingest a raw Wazuh alert. Wazuh's schema varies by rule, so the body is only
    validated as a non-empty JSON object -- nothing more specific.

    `normalized` is stored empty here, same as before -- feature-builder
    normalization now happens asynchronously in the live pipeline
    (services/pipeline/run_pipeline.py), triggered by the enqueue below, not
    synchronously in this handler. Only a fresh insert (created=True) enqueues it;
    see the comment at the enqueue call for why.
    """
    _check_webhook_secret(request)

    if not payload:
        raise HTTPException(status_code=422, detail="wazuh payload must be a non-empty JSON object")

    # Wazuh alerts typically carry a stable `id` field; use it for idempotent
    # redelivery via the same (source, external_id) unique index as /replay. Not
    # every rule guarantees one, so fall back to NULL (always inserts) when absent.
    external_id = payload.get("id")
    if external_id is not None:
        external_id = str(external_id)

    alert_id, created = await upsert_alert(
        pool,
        source="wazuh",
        external_id=external_id,
        incident_id=None,
        raw=payload,
        normalized={},
        ground_truth_label=None,
    )

    # Only a FRESH insert enqueues the live pipeline (docs/architecture.md §12,
    # Phase C task 3) -- a redelivered/duplicate webhook (created=False, caught by
    # the (source, external_id) unique index in upsert_alert) must NOT re-enqueue,
    # or a flaky Wazuh integration retrying the same alert would fire duplicate
    # Jev/Slack/PagerDuty/Tier-2 calls for it. Enqueueing failure (e.g. Redis
    # briefly unreachable) is logged but never turned into a 500 here: the alert
    # is already safely committed to Postgres, which is this endpoint's actual
    # contract -- losing the live-pipeline trigger for one alert is recoverable,
    # failing the whole webhook because Redis hiccuped is not.
    if created:
        try:
            enqueue_pipeline(str(alert_id))
        except Exception:
            logger.exception(
                "failed to enqueue pipeline job for alert %s (alert is still stored)",
                alert_id,
            )

    response.status_code = status.HTTP_201_CREATED if created else status.HTTP_200_OK
    return AlertOut(id=alert_id)


@app.get("/alerts/{alert_id}", response_model=AlertDetail)
async def get_alert(alert_id: uuid.UUID, pool: asyncpg.Pool = Depends(get_pool)) -> AlertDetail:
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT id, source, external_id, incident_id, raw, normalized,
                   ground_truth_label, ingested_at
            FROM alerts
            WHERE id = $1
            """,
            alert_id,
        )
    if row is None:
        raise HTTPException(status_code=404, detail="alert not found")
    return AlertDetail(**dict(row))
