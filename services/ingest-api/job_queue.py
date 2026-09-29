"""RQ helper for enqueuing the live pipeline job after a fresh Wazuh webhook insert.

See docs/architecture.md §2 and §12 (Phase C task 3): `/webhook/wazuh` is the ONLY
endpoint that triggers the live ingest -> features -> Jev -> policy -> notifier (and,
per Phase D, Tier-2) pipeline. `/replay` must NEVER trigger it (see main.py's
`replay()` handler, untouched by this module) -- replay pushes tens/hundreds of
thousands of GUIDE alerts for benchmarking, and firing real Jev/Slack/PagerDuty/OpenAI
calls at that volume would be a serious cost and operational-safety bug.

Named `job_queue.py`, NOT `queue.py`, deliberately: a module literally named
`queue.py` living in this directory (which is on `sys.path` as soon as `main.py` is
imported -- see how `main.py` already does `from db import ...`) would shadow the
Python standard library's own `queue` module for every other import in this process.
uvicorn/starlette/asyncio all use `queue` internally; shadowing it would be a subtle,
hard-to-diagnose way to break the whole service. `job_queue` avoids the collision
entirely while still being an obvious, discoverable name.
"""
from __future__ import annotations

import os
from typing import Optional

import redis
from rq import Queue
from rq.serializers import JSONSerializer

# The RQ worker entrypoint (services/tier2-worker/rq_worker.py) listens on this exact
# queue name -- see that module's docstring. This is duplicated as a plain string
# (not a shared import) on purpose: ingest-api and tier2-worker are separate
# services/containers with no shared package between them (per-service dependency
# isolation is this repo's convention -- see every service's own requirements.txt),
# so the queue name is the one small piece of coordination that has to be
# documented on both sides instead of imported.
QUEUE_NAME = "ingest-api"

# RQ job target, given as a STRING, not a function reference. That's deliberate:
# ingest-api never imports anything from services/pipeline or services/tier2-worker
# (services it has no other dependency on) -- RQ's worker resolves this string via
# `importlib.import_module` inside ITS OWN process when the job actually runs (see
# rq_worker.py, which defines a module-level `process_alert` function so this exact
# string resolves there).
_JOB_TARGET = "rq_worker.process_alert"

_queue: Optional[Queue] = None


def get_queue() -> Queue:
    """Return an RQ Queue connected to REDIS_URL, connecting lazily on first use --
    never at import time, so importing this module never requires Redis to be up
    (e.g. tests that monkeypatch `enqueue_pipeline` directly never call this at all).

    Raises KeyError if REDIS_URL isn't set, matching db.py's create_pool() convention
    for DATABASE_URL: fail loudly at first real use rather than silently limping
    along unconfigured.
    """
    global _queue
    if _queue is None:
        redis_url = os.environ["REDIS_URL"]
        connection = redis.from_url(redis_url)
        # JSONSerializer, not RQ's pickle default: a security audit flagged that an
        # unauthenticated (or compromised) Redis would otherwise let anyone push a
        # raw job payload that the worker's pickle.loads() would deserialize and
        # execute. Job args here are always plain strings (an alert id), so JSON
        # loses nothing. rq_worker.py's Queue/Worker MUST use the same serializer.
        _queue = Queue(QUEUE_NAME, connection=connection, serializer=JSONSerializer)
    return _queue


def enqueue_pipeline(alert_id: str) -> None:
    """Enqueue one alert id for the live pipeline (services/pipeline's
    run_pipeline(), invoked by rq_worker.py's `process_alert`).

    Fire-and-forget: `Queue.enqueue` is a fast, synchronous push onto Redis -- it
    does not wait for or block on the pipeline actually running, so callers (e.g.
    main.py's webhook_wazuh handler) stay fast per docs/architecture.md §12's
    "Keep the HTTP response fast" requirement.
    """
    get_queue().enqueue(_JOB_TARGET, str(alert_id))
