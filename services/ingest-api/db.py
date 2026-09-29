"""Connection pool setup/teardown for the ingest-api Postgres database.

Kept separate from main.py's route handlers so the pool lifecycle can be exercised
(or swapped) independently of HTTP routing.
"""
from __future__ import annotations

import json
import os

import asyncpg

# Registered on every pooled connection so `jsonb`/`json` columns round-trip as
# plain Python dicts (asyncpg does not do this automatically) -- callers pass and
# receive dicts for `raw`/`normalized` without any manual json.dumps/json.loads.
async def _init_connection(conn: asyncpg.Connection) -> None:
    await conn.set_type_codec(
        "jsonb",
        schema="pg_catalog",
        encoder=json.dumps,
        decoder=json.loads,
        format="text",
    )
    await conn.set_type_codec(
        "json",
        schema="pg_catalog",
        encoder=json.dumps,
        decoder=json.loads,
        format="text",
    )


async def create_pool() -> asyncpg.Pool:
    """Create the asyncpg connection pool from the DATABASE_URL env var.

    Raises KeyError if DATABASE_URL isn't set -- fail loudly at startup rather than
    limping along with no database.
    """
    database_url = os.environ["DATABASE_URL"]
    return await asyncpg.create_pool(
        dsn=database_url,
        min_size=1,
        max_size=10,
        init=_init_connection,
    )


async def close_pool(pool: asyncpg.Pool) -> None:
    await pool.close()
