"""Pure functions that compute the `derived` sub-object of the Jev state object.

See docs/architecture.md §4 for the authoritative schema. Every function here is
pure: no file/network/DB access, no `datetime.now()`, no reads of global or
process state. All "current time" is passed in explicitly as `reference_time` so
results are fully deterministic and unit-testable.

Counting and date/time arithmetic are computed here, in code, and never left for
Jev to infer from raw text (architecture.md §5, "known failure modes").

Entity scoping (important): several functions below take an `events` list but no
explicit entity identifier (src_ip / user / host). That is intentional — this
module does not know how to match "the same entity" across arbitrary event
shapes, and doing that filtering here would smuggle a policy decision into a
supposedly dumb counting function. Instead, the CALLER is responsible for
pre-filtering `events` down to the entity relevant to the alert (e.g. only auth
events for the alert's src_ip/user) before calling these functions. Functions
that need to match on something intrinsic to the events themselves (e.g. rule_id
for `similar_alerts_24h`) take that as an explicit parameter instead.

Event dict shape (shared across all functions that take `events`):

    {
        "event_type": str,        # e.g. "auth_failure", "auth_success"
                                   # (or "alert" for the alert-history events
                                   # consumed by similar_alerts_24h)
        "timestamp": datetime,    # timezone-naive or timezone-aware, but must be
                                   # consistent with `reference_time`'s awareness
                                   # (mixing naive and aware datetimes raises
                                   # TypeError, by design -- callers must
                                   # normalize upstream)
        "rule_id": str,           # optional; only read by similar_alerts_24h
        ...                       # other keys are ignored by this module
    }

Only the keys a given function actually reads are required to be present; the
shape above is documented once here so every function can share it.
"""

from __future__ import annotations

from datetime import datetime, timedelta

# ---------------------------------------------------------------------------
# Individual derived-field computations
# ---------------------------------------------------------------------------


def failed_auth_10m(events: list[dict], reference_time: datetime) -> int:
    """Count failed-auth events in the 10 minutes before `reference_time`.

    `events` is expected to already be scoped to a single entity by the caller
    (see module docstring). The window is inclusive on both ends:
    `[reference_time - 10m, reference_time]`, so an event exactly on either
    boundary counts.
    """
    window_start = reference_time - timedelta(minutes=10)
    return sum(
        1
        for event in events
        if event.get("event_type") == "auth_failure"
        and window_start <= event["timestamp"] <= reference_time
    )


def successful_auth_after_failures(
    events: list[dict],
    reference_time: datetime,
    lookback_minutes: int = 10,
) -> bool:
    """True if a successful auth follows one or more failed auths, same entity.

    "Follows" means chronologically later within the lookback window
    `[reference_time - lookback_minutes, reference_time]` (inclusive both ends).
    `events` is expected to already be scoped to a single entity by the caller.
    Events outside the window are ignored entirely, including for ordering.
    """
    window_start = reference_time - timedelta(minutes=lookback_minutes)
    windowed = [
        event
        for event in events
        if window_start <= event["timestamp"] <= reference_time
        and event.get("event_type") in ("auth_failure", "auth_success")
    ]
    windowed.sort(key=lambda event: event["timestamp"])

    saw_failure = False
    for event in windowed:
        if event["event_type"] == "auth_failure":
            saw_failure = True
        elif event["event_type"] == "auth_success" and saw_failure:
            return True
    return False


def off_hours(
    timestamp: datetime,
    business_hours_start: int = 8,
    business_hours_end: int = 18,
    business_days: set[int] | None = None,
) -> bool:
    """True if `timestamp` falls outside business hours.

    Assumption: `timestamp` is already expressed in whatever local time zone is
    relevant for "business hours" (e.g. the org's HQ time, or per-site local
    time already resolved upstream). This function does no time zone
    conversion or guessing -- it just reads `.hour` and `.weekday()` off the
    value it's given.

    `business_days` uses Python's `datetime.weekday()` convention: Monday=0 ...
    Sunday=6. Defaults to Monday-Friday ({0,1,2,3,4}). Deliberately not given a
    mutable default value in the signature (a `set` default literal would be
    shared across calls); `None` is used as the sentinel and the default set is
    built fresh inside the function.

    Boundary convention: business hours are `[business_hours_start,
    business_hours_end)` -- start-of-hour inclusive, end-of-hour exclusive. So
    with the defaults, 08:00:00 is business hours and 18:00:00 is already
    off-hours.
    """
    if business_days is None:
        business_days = {0, 1, 2, 3, 4}

    is_business_day = timestamp.weekday() in business_days
    is_business_hour = business_hours_start <= timestamp.hour < business_hours_end
    return not (is_business_day and is_business_hour)


def src_ip_first_seen_days(
    ip: str,
    first_seen_lookup: dict[str, datetime],
    reference_time: datetime,
) -> int:
    """Days since `ip` was first observed, per `first_seen_lookup`.

    If `ip` is missing from the lookup, it is treated as first-seen right now
    (0 days) -- i.e. "unknown" is treated as "brand new," the conservative
    choice for a security signal (an IP we have no history for should not look
    established). If the lookup's first-seen timestamp is somehow after
    `reference_time` (bad/stale data), the result is clamped to 0 rather than
    returned negative, since this feeds a security decision and should never
    hand a policy/model a nonsensical value.
    """
    first_seen = first_seen_lookup.get(ip)
    if first_seen is None:
        return 0
    days = (reference_time - first_seen).days
    return max(0, days)


def src_ip_reputation(ip: str, reputation_lookup: dict[str, str]) -> str:
    """Reputation category for `ip` (e.g. "malicious"/"suspicious"/"clean").

    Defaults to "unknown" if `ip` is missing from the lookup.
    """
    return reputation_lookup.get(ip, "unknown")


def host_criticality(host: str, criticality_lookup: dict[str, str]) -> str:
    """Criticality tier for `host` (e.g. "crown_jewel").

    Defaults to "unknown" if `host` is missing from the lookup.
    """
    return criticality_lookup.get(host, "unknown")


def rule_historical_fp_rate(rule_id: str, fp_rate_lookup: dict[str, float]) -> float:
    """Historical false-positive rate for `rule_id`, clamped to [0.0, 1.0].

    Defaults to 0.0 if `rule_id` is missing. The lookup is external input (it
    may be populated by a different, less-trusted process than this module),
    and this value feeds a security decision, so the result is defensively
    clamped even when the stored value is out of range, non-numeric, or NaN --
    any such bad value is treated as 0.0 rather than propagated.
    """
    raw_value = fp_rate_lookup.get(rule_id, 0.0)
    try:
        value = float(raw_value)
    except (TypeError, ValueError):
        return 0.0
    if value != value:  # NaN never equals itself
        return 0.0
    return max(0.0, min(1.0, value))


def similar_alerts_24h(
    events: list[dict],
    rule_id: str,
    reference_time: datetime,
) -> int:
    """Count alert-history events with the same `rule_id` in the last 24h.

    Window is inclusive on both ends: `[reference_time - 24h, reference_time]`.
    `events` here is alert history (each event expected to carry a "rule_id"
    key), not auth events -- pass in whatever historical alerts are available
    for the relevant scope (e.g. same host, or org-wide, per the caller's
    choice). The triggering alert itself should NOT be included in `events`;
    this function only counts what's handed to it.
    """
    window_start = reference_time - timedelta(hours=24)
    return sum(
        1
        for event in events
        if event.get("rule_id") == rule_id
        and window_start <= event["timestamp"] <= reference_time
    )


# ---------------------------------------------------------------------------
# Top-level assembly
# ---------------------------------------------------------------------------


def build_derived(
    alert: dict,
    entities: dict,
    events: list[dict],
    lookups: dict,
    reference_time: datetime,
) -> dict:
    """Compute the full `derived` sub-object for the Jev state object.

    Parameters
    ----------
    alert:
        The state object's `alert` section (only `rule_id` is read here).
    entities:
        The state object's `entities` section (`src_ip`, `host` are read
        here; `user` is accepted by the schema but not needed by any current
        derived field).
    events:
        A single event list used both as the auth-event history for
        `failed_auth_10m`/`successful_auth_after_failures` and as the
        alert-history for `similar_alerts_24h`. Callers should ensure this
        list is scoped appropriately (pre-filtered to the alert's entity for
        auth events; not including the triggering alert itself for the alert
        history) -- see the module docstring and `similar_alerts_24h` for
        details. Passing separately-scoped lists is fine too, since each
        function only reads the keys it needs and ignores events of an
        irrelevant `event_type`.
    lookups:
        Bundle of reputation/asset/rule lookup tables, keyed as:
          - "ip_reputation": dict[str, str]        (src_ip_reputation)
          - "host_criticality": dict[str, str]      (host_criticality)
          - "rule_fp_rate": dict[str, float]        (rule_historical_fp_rate)
          - "ip_first_seen": dict[str, datetime]    (src_ip_first_seen_days)
        Any missing sub-key is treated as an empty dict (all lookups then
        fall back to that field's documented default).
    reference_time:
        The anchor "now" for every time-windowed computation, and the
        timestamp used for the `off_hours` calculation -- in practice, the
        alert's own timestamp (already in the relevant local time; see
        `off_hours`'s docstring for that assumption).

    Returns
    -------
    dict matching the `derived` section of the schema in docs/architecture.md
    §4 exactly: same keys, same types.
    """
    src_ip = entities.get("src_ip")
    host = entities.get("host")
    rule_id = alert.get("rule_id")

    ip_reputation_lookup = lookups.get("ip_reputation", {})
    host_criticality_lookup = lookups.get("host_criticality", {})
    rule_fp_rate_lookup = lookups.get("rule_fp_rate", {})
    ip_first_seen_lookup = lookups.get("ip_first_seen", {})

    return {
        "failed_auth_10m": failed_auth_10m(events, reference_time),
        "successful_auth_after_failures": successful_auth_after_failures(
            events, reference_time
        ),
        "off_hours": off_hours(reference_time),
        "src_ip_first_seen_days": (
            src_ip_first_seen_days(src_ip, ip_first_seen_lookup, reference_time)
            if src_ip is not None
            else 0
        ),
        "src_ip_reputation": (
            src_ip_reputation(src_ip, ip_reputation_lookup)
            if src_ip is not None
            else "unknown"
        ),
        "host_criticality": (
            host_criticality(host, host_criticality_lookup)
            if host is not None
            else "unknown"
        ),
        "rule_historical_fp_rate": (
            rule_historical_fp_rate(rule_id, rule_fp_rate_lookup)
            if rule_id is not None
            else 0.0
        ),
        "similar_alerts_24h": (
            similar_alerts_24h(events, rule_id, reference_time)
            if rule_id is not None
            else 0
        ),
    }
