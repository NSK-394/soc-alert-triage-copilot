"""Builds the curated ±30-minute correlated-event context window for a Tier-2
brief (docs/architecture.md §6: "the triggering alert plus ±30 minutes of events
for the same entities (src_ip, user, host) -- keeps every tier within 10k-40k
tokens regardless of provider").
"""
from __future__ import annotations

from datetime import timedelta

import asyncpg

CONTEXT_WINDOW = timedelta(minutes=30)

# Hard cap on context rows returned. Each row is a full alert (raw + normalized
# JSONB), so even a modest per-row size can add up on a noisy shared entity (e.g.
# a busy NAT gateway IP). 50 rows is a generous ceiling that still keeps total
# tokens well inside the 10k-40k target from the architecture spec across all
# three providers; if noisier environments prove this too high in practice,
# lower this constant rather than adding per-provider logic here -- the token
# budget is a property of the context builder, not of which model consumes it.
MAX_CONTEXT_ITEMS = 50


async def build_context(pool: asyncpg.Pool, alert: dict) -> list[dict]:
    """Queries `alerts` for other rows sharing at least one entity (src_ip, user,
    or host, from `normalized->entities`) with the triggering alert, within ±30
    minutes of its `ingested_at`, ordered oldest-first and capped at
    MAX_CONTEXT_ITEMS rows.

    Each returned item carries a stable `log_line_id`: the row's own `alerts.id`
    UUID, as a string. One alert row is treated as one citable "log line" -- the
    granularity citation_validator.py checks brief citations against. (A finer,
    per-field synthetic id like f"{alert_id}:{field}" would let a brief cite a
    specific field within one alert's raw payload; that wasn't needed for this
    phase's context shape, and can be introduced later by changing this
    function's log_line_id construction without touching validator/worker
    contracts, which only assume "some stable string id per context item.")

    Returns [] if the triggering alert has no entities to correlate on, or no
    ingested_at timestamp to center the window on -- rather than querying with
    an unbounded/undefined window.
    """
    entities = (alert.get("normalized") or {}).get("entities") or {}
    src_ip = entities.get("src_ip")
    user = entities.get("user")
    host = entities.get("host")

    if not any([src_ip, user, host]):
        return []

    timestamp = alert.get("ingested_at")
    if timestamp is None:
        return []

    window_start = timestamp - CONTEXT_WINDOW
    window_end = timestamp + CONTEXT_WINDOW

    params: list = [alert.get("id"), window_start, window_end]
    entity_conditions: list[str] = []

    for value, field in ((src_ip, "src_ip"), (user, "user"), (host, "host")):
        if value:
            params.append(value)
            entity_conditions.append(f"normalized->'entities'->>'{field}' = ${len(params)}")

    params.append(MAX_CONTEXT_ITEMS)

    query = f"""
        SELECT id, source, external_id, incident_id, raw, normalized, ingested_at
        FROM alerts
        WHERE id != $1
          AND ingested_at BETWEEN $2 AND $3
          AND ({" OR ".join(entity_conditions)})
        ORDER BY ingested_at ASC
        LIMIT ${len(params)}
    """

    rows = await pool.fetch(query, *params)

    return [
        {
            "log_line_id": str(row["id"]),
            "source": row["source"],
            "external_id": row["external_id"],
            "incident_id": row["incident_id"],
            "ingested_at": row["ingested_at"].isoformat() if row["ingested_at"] else None,
            "normalized": row["normalized"],
        }
        for row in rows
    ]
