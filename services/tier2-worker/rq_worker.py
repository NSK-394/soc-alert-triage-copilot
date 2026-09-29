"""RQ worker entrypoint for the live pipeline (docs/architecture.md §12 Phase C task 3,
Phase D task 2). Connects to REDIS_URL, listens on the same queue name
`services/ingest-api/job_queue.py` enqueues to, and runs
`services/pipeline/run_pipeline.run_pipeline(pool, alert_id)` for each job.

Replaces the placeholder `CMD` in this service's Dockerfile (which just kept the
container alive with `time.sleep`) -- see the Dockerfile for the one-line change.

Import setup for hyphenated/sibling service directories
-----------------------------------------------------------
This process needs two things a normal dotted import can't reach from
`services/tier2-worker/`:
  - `services/pipeline` (no hyphen, but still imported the flat/sys.path way used
    everywhere else in this repo, for consistency -- see run_pipeline.py's docstring)
  - `services/ingest-api` (hyphenated), purely to reuse `db.py`'s
    `create_pool()`/`close_pool()` pair rather than re-implementing the same ~10
    lines here. This worker process needs its own asyncpg pool, independent of
    ingest-api's -- it's a separate process/container.
Both follow this repo's established `sys.path.insert(0, "<dir>"); import <module>`
convention for hyphenated directories (see e.g. data/converters/guide_to_state.py
or any service's tests/conftest.py).

Why this always uses SimpleWorker, never the forking Worker
----------------------------------------------------------------
RQ's default `Worker` forks a child process per job via `os.fork()`. This script
creates ONE asyncpg pool and ONE event loop in `main()`, reused for every job (see
"Event loop note" below) -- and asyncpg connections are not fork-safe: a forked
child inherits the parent's already-open connections/sockets, and when the parent
and child (or two children in quick succession) both touch what the OS still sees
as the same underlying connection, Postgres's prepared-statement protocol gets
confused between them. This was caught live, not theoretically: firing several
real alerts in quick succession produced a real
`asyncpg.exceptions.DuplicatePreparedStatementError` from exactly this race. Since
`os.fork()` doesn't exist on Windows either (this repo's local dev/verification
environment), the fix converges on the same answer both platforms needed anyway:
always use `rq.worker.SimpleWorker` (runs each job in-process, no fork), never the
forking `Worker`. For this project's single-worker-replica demo scale, sequential
in-process job processing is correct, not a limitation -- Jev/Tier-2 calls are
already externally rate-limited, and `run_pipeline()` already catches every
exception per-job so one bad job can't take down the process.

Event loop note
------------------
RQ jobs are plain sync callables. `process_alert` (the job function --
`job_queue.py`'s `_JOB_TARGET = "rq_worker.process_alert"` names it explicitly)
bridges into async `run_pipeline()` via `loop.run_until_complete(...)` on a SINGLE
event loop created once in `main()` and reused for every job. asyncpg pools are bound
to the event loop they were created on; calling `asyncio.run()` fresh per job would
create a new loop each time and break the pool created under the first one.
"""
from __future__ import annotations

import asyncio
import logging
import os
import sys
from pathlib import Path

import redis
from rq import Queue
from rq.serializers import JSONSerializer
from rq.worker import SimpleWorker

_THIS_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _THIS_DIR.parents[1]
_PIPELINE_DIR = _REPO_ROOT / "services" / "pipeline"
_INGEST_API_DIR = _REPO_ROOT / "services" / "ingest-api"
for _dir in (_PIPELINE_DIR, _INGEST_API_DIR):
    if str(_dir) not in sys.path:
        sys.path.insert(0, str(_dir))

from run_pipeline import run_pipeline  # noqa: E402  (services/pipeline)
from db import close_pool, create_pool  # noqa: E402  (services/ingest-api)

# This script is run directly (`python rq_worker.py`, per the Dockerfile's CMD),
# which Python loads as module `__main__`, NOT as a module named `rq_worker`. But
# job_queue.py enqueues jobs by the string "rq_worker.process_alert", and RQ resolves
# job-target strings via `importlib.import_module("rq_worker")` *inside this same
# process* when a job actually runs. Without the line below, that import would create
# a SECOND, entirely separate `rq_worker` module object (re-running every top-level
# statement in this file again) whose own `_pool`/`_loop` globals were never set by
# main() -- `process_alert` would then always see them as None, no matter how long
# the worker had been running. Aliasing `sys.modules["rq_worker"]` to the `__main__`
# module object that's actually executing solves it: later imports of "rq_worker"
# just return this exact running module, `_pool`/`_loop` and all. This is a no-op
# (and unnecessary, but harmless) if this file is ever imported normally as
# `rq_worker` instead of run as a script.
if __name__ == "__main__":
    sys.modules.setdefault("rq_worker", sys.modules["__main__"])

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
logger = logging.getLogger(__name__)

# Must match services/ingest-api/job_queue.py's QUEUE_NAME exactly.
QUEUE_NAME = "ingest-api"

# Module-level state set once by main() before the worker loop starts, and read by
# process_alert() on every job. See the module docstring for why the pool and the
# event loop are both created once and reused, not per-job.
_pool = None
_loop: asyncio.AbstractEventLoop | None = None


def process_alert(alert_id: str) -> None:
    """RQ job entrypoint -- the exact target `job_queue.py` enqueues by string
    (`"rq_worker.process_alert"`). Runs the async pipeline on this process's
    single long-lived event loop against its single long-lived asyncpg pool.
    """
    if _pool is None or _loop is None:
        raise RuntimeError(
            "rq_worker.process_alert called before main() initialized the pool/event loop"
        )
    _loop.run_until_complete(run_pipeline(_pool, alert_id))


def main() -> None:
    global _pool, _loop

    redis_url = os.environ["REDIS_URL"]

    _loop = asyncio.new_event_loop()
    asyncio.set_event_loop(_loop)
    _pool = _loop.run_until_complete(create_pool())
    logger.info("rq_worker: asyncpg pool created")

    connection = redis.from_url(redis_url)
    # JSONSerializer, matching services/ingest-api/job_queue.py's Queue exactly --
    # RQ requires both enqueue and worker sides to agree on serializer. See that
    # module's comment for why (mitigates a pickle-deserialization RCE finding
    # from a security audit; job args here are always plain strings, so nothing
    # is lost by not using pickle).
    queue = Queue(QUEUE_NAME, connection=connection, serializer=JSONSerializer)

    # Always SimpleWorker (never the forking Worker) -- see the module docstring's
    # "Why this always uses SimpleWorker" section for the real bug this avoids.
    logger.info("rq_worker: starting SimpleWorker on queue %r (redis=%s)", QUEUE_NAME, redis_url)
    worker = SimpleWorker([queue], connection=connection, serializer=JSONSerializer)

    try:
        worker.work()
    finally:
        _loop.run_until_complete(close_pool(_pool))
        _loop.close()


if __name__ == "__main__":
    main()
