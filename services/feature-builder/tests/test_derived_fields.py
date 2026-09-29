"""Unit tests for services/feature-builder/derived_fields.py.

Synthetic fixtures only -- no real GUIDE/log data (that's the converter's job).
"""

from datetime import datetime, timedelta

from derived_fields import (
    build_derived,
    failed_auth_10m,
    host_criticality,
    off_hours,
    rule_historical_fp_rate,
    similar_alerts_24h,
    src_ip_first_seen_days,
    src_ip_reputation,
    successful_auth_after_failures,
)

REF = datetime(2026, 9, 20, 3, 12, 44)  # a Sunday, 03:12:44


def auth_event(event_type: str, minutes_before_ref: float) -> dict:
    return {
        "event_type": event_type,
        "timestamp": REF - timedelta(minutes=minutes_before_ref),
    }


def alert_event(rule_id: str, hours_before_ref: float) -> dict:
    return {
        "event_type": "alert",
        "rule_id": rule_id,
        "timestamp": REF - timedelta(hours=hours_before_ref),
    }


# ---------------------------------------------------------------------------
# failed_auth_10m
# ---------------------------------------------------------------------------


class TestFailedAuth10m:
    def test_empty_events(self):
        assert failed_auth_10m([], REF) == 0

    def test_counts_only_failures_in_window(self):
        events = [
            auth_event("auth_failure", 1),
            auth_event("auth_failure", 5),
            auth_event("auth_failure", 9.5),
            auth_event("auth_success", 2),  # wrong type, ignored
            auth_event("auth_failure", 15),  # outside window
        ]
        assert failed_auth_10m(events, REF) == 3

    def test_boundary_exactly_10_minutes_before_counts(self):
        events = [auth_event("auth_failure", 10)]
        assert failed_auth_10m(events, REF) == 1

    def test_boundary_just_over_10_minutes_excluded(self):
        events = [auth_event("auth_failure", 10.001)]
        assert failed_auth_10m(events, REF) == 0

    def test_event_at_reference_time_counts(self):
        events = [auth_event("auth_failure", 0)]
        assert failed_auth_10m(events, REF) == 1

    def test_large_count(self):
        # 212 failures spread across ~8.4 of the 10-minute window
        events = [auth_event("auth_failure", i / 25) for i in range(212)]
        assert failed_auth_10m(events, REF) == 212


# ---------------------------------------------------------------------------
# successful_auth_after_failures
# ---------------------------------------------------------------------------


class TestSuccessfulAuthAfterFailures:
    def test_empty_events(self):
        assert successful_auth_after_failures([], REF) is False

    def test_failure_then_success_is_true(self):
        events = [auth_event("auth_failure", 5), auth_event("auth_success", 2)]
        assert successful_auth_after_failures(events, REF) is True

    def test_success_then_failure_is_false(self):
        # success happens first, failure after it -- no success *follows* a failure
        events = [auth_event("auth_success", 8), auth_event("auth_failure", 3)]
        assert successful_auth_after_failures(events, REF) is False

    def test_only_failures_is_false(self):
        events = [auth_event("auth_failure", 5), auth_event("auth_failure", 1)]
        assert successful_auth_after_failures(events, REF) is False

    def test_only_success_is_false(self):
        events = [auth_event("auth_success", 5)]
        assert successful_auth_after_failures(events, REF) is False

    def test_outside_lookback_window_ignored(self):
        events = [
            auth_event("auth_failure", 20),  # outside default 10m window
            auth_event("auth_success", 15),  # also outside
        ]
        assert successful_auth_after_failures(events, REF) is False

    def test_custom_lookback_minutes(self):
        events = [auth_event("auth_failure", 25), auth_event("auth_success", 20)]
        assert successful_auth_after_failures(events, REF, lookback_minutes=10) is False
        assert successful_auth_after_failures(events, REF, lookback_minutes=30) is True

    def test_unordered_input_is_sorted_internally(self):
        events = [auth_event("auth_success", 1), auth_event("auth_failure", 5)]
        assert successful_auth_after_failures(events, REF) is True


# ---------------------------------------------------------------------------
# off_hours
# ---------------------------------------------------------------------------


class TestOffHours:
    def test_middle_of_business_day(self):
        # Monday 2026-09-21, 14:00
        ts = datetime(2026, 9, 21, 14, 0, 0)
        assert off_hours(ts) is False

    def test_weekend_is_off_hours(self):
        # Sunday
        ts = datetime(2026, 9, 20, 14, 0, 0)
        assert off_hours(ts) is True

    def test_early_morning_weekday_is_off_hours(self):
        ts = datetime(2026, 9, 21, 3, 0, 0)
        assert off_hours(ts) is True

    def test_boundary_start_of_business_hours_is_in_hours(self):
        ts = datetime(2026, 9, 21, 8, 0, 0)
        assert off_hours(ts) is False

    def test_boundary_one_minute_before_start_is_off_hours(self):
        ts = datetime(2026, 9, 21, 7, 59, 0)
        assert off_hours(ts) is True

    def test_boundary_end_of_business_hours_is_off_hours(self):
        # end is exclusive: 18:00:00 itself is already off-hours
        ts = datetime(2026, 9, 21, 18, 0, 0)
        assert off_hours(ts) is True

    def test_boundary_one_minute_before_end_is_in_hours(self):
        ts = datetime(2026, 9, 21, 17, 59, 0)
        assert off_hours(ts) is False

    def test_custom_business_hours(self):
        ts = datetime(2026, 9, 21, 20, 0, 0)
        assert off_hours(ts, business_hours_start=6, business_hours_end=22) is False

    def test_custom_business_days_includes_saturday(self):
        ts = datetime(2026, 9, 19, 10, 0, 0)  # Saturday
        assert off_hours(ts, business_days={5, 6}) is False

    def test_default_business_days_not_mutated_across_calls(self):
        # guards against a shared-mutable-default regression
        ts_weekday = datetime(2026, 9, 21, 10, 0, 0)
        off_hours(ts_weekday, business_days={5, 6})
        assert off_hours(ts_weekday) is False  # still Mon-Fri by default


# ---------------------------------------------------------------------------
# src_ip_first_seen_days
# ---------------------------------------------------------------------------


class TestSrcIpFirstSeenDays:
    def test_missing_ip_is_zero(self):
        assert src_ip_first_seen_days("203.0.113.7", {}, REF) == 0

    def test_seen_five_days_ago(self):
        lookup = {"203.0.113.7": REF - timedelta(days=5)}
        assert src_ip_first_seen_days("203.0.113.7", lookup, REF) == 5

    def test_seen_right_now_is_zero(self):
        lookup = {"203.0.113.7": REF}
        assert src_ip_first_seen_days("203.0.113.7", lookup, REF) == 0

    def test_future_first_seen_is_clamped_to_zero(self):
        lookup = {"203.0.113.7": REF + timedelta(days=3)}
        assert src_ip_first_seen_days("203.0.113.7", lookup, REF) == 0

    def test_partial_day_floors_down(self):
        lookup = {"203.0.113.7": REF - timedelta(days=1, hours=23)}
        assert src_ip_first_seen_days("203.0.113.7", lookup, REF) == 1


# ---------------------------------------------------------------------------
# src_ip_reputation
# ---------------------------------------------------------------------------


class TestSrcIpReputation:
    def test_known_ip(self):
        lookup = {"203.0.113.7": "malicious"}
        assert src_ip_reputation("203.0.113.7", lookup) == "malicious"

    def test_missing_ip_defaults_unknown(self):
        assert src_ip_reputation("203.0.113.7", {}) == "unknown"


# ---------------------------------------------------------------------------
# host_criticality
# ---------------------------------------------------------------------------


class TestHostCriticality:
    def test_known_host(self):
        lookup = {"db-prod-02": "crown_jewel"}
        assert host_criticality("db-prod-02", lookup) == "crown_jewel"

    def test_missing_host_defaults_unknown(self):
        assert host_criticality("db-prod-02", {}) == "unknown"


# ---------------------------------------------------------------------------
# rule_historical_fp_rate
# ---------------------------------------------------------------------------


class TestRuleHistoricalFpRate:
    def test_known_rule(self):
        lookup = {"5712": 0.62}
        assert rule_historical_fp_rate("5712", lookup) == 0.62

    def test_missing_rule_defaults_zero(self):
        assert rule_historical_fp_rate("5712", {}) == 0.0

    def test_value_above_one_is_clamped(self):
        lookup = {"5712": 1.5}
        assert rule_historical_fp_rate("5712", lookup) == 1.0

    def test_negative_value_is_clamped(self):
        lookup = {"5712": -0.2}
        assert rule_historical_fp_rate("5712", lookup) == 0.0

    def test_non_numeric_value_defaults_zero(self):
        lookup = {"5712": "not-a-number"}
        assert rule_historical_fp_rate("5712", lookup) == 0.0

    def test_nan_value_defaults_zero(self):
        lookup = {"5712": float("nan")}
        assert rule_historical_fp_rate("5712", lookup) == 0.0

    def test_none_value_defaults_zero(self):
        lookup = {"5712": None}
        assert rule_historical_fp_rate("5712", lookup) == 0.0


# ---------------------------------------------------------------------------
# similar_alerts_24h
# ---------------------------------------------------------------------------


class TestSimilarAlerts24h:
    def test_empty_events(self):
        assert similar_alerts_24h([], "5712", REF) == 0

    def test_zero_similar_alerts_different_rule(self):
        events = [alert_event("9999", 1)]
        assert similar_alerts_24h(events, "5712", REF) == 0

    def test_counts_matching_rule_within_window(self):
        events = [
            alert_event("5712", 1),
            alert_event("5712", 10),
            alert_event("5712", 23.9),
            alert_event("9999", 2),  # different rule
            alert_event("5712", 25),  # outside window
        ]
        assert similar_alerts_24h(events, "5712", REF) == 3

    def test_boundary_exactly_24h_before_counts(self):
        events = [alert_event("5712", 24)]
        assert similar_alerts_24h(events, "5712", REF) == 1

    def test_boundary_just_over_24h_excluded(self):
        events = [alert_event("5712", 24.001)]
        assert similar_alerts_24h(events, "5712", REF) == 0


# ---------------------------------------------------------------------------
# build_derived
# ---------------------------------------------------------------------------


class TestBuildDerived:
    def _lookups(self):
        return {
            "ip_reputation": {"203.0.113.7": "malicious"},
            "host_criticality": {"db-prod-02": "crown_jewel"},
            "rule_fp_rate": {"5712": 0.62},
            "ip_first_seen": {"203.0.113.7": REF},
        }

    def test_matches_schema_keys_and_types(self):
        alert = {"rule_id": "5712"}
        entities = {"src_ip": "203.0.113.7", "user": "svc-backup", "host": "db-prod-02"}
        events = [
            auth_event("auth_failure", 5),
            auth_event("auth_success", 2),
            alert_event("5712", 1),
            alert_event("5712", 2),
        ]

        derived = build_derived(alert, entities, events, self._lookups(), REF)

        assert set(derived.keys()) == {
            "failed_auth_10m",
            "successful_auth_after_failures",
            "off_hours",
            "src_ip_first_seen_days",
            "src_ip_reputation",
            "host_criticality",
            "rule_historical_fp_rate",
            "similar_alerts_24h",
        }
        assert isinstance(derived["failed_auth_10m"], int)
        assert isinstance(derived["successful_auth_after_failures"], bool)
        assert isinstance(derived["off_hours"], bool)
        assert isinstance(derived["src_ip_first_seen_days"], int)
        assert isinstance(derived["src_ip_reputation"], str)
        assert isinstance(derived["host_criticality"], str)
        assert isinstance(derived["rule_historical_fp_rate"], float)
        assert isinstance(derived["similar_alerts_24h"], int)

        assert derived["failed_auth_10m"] == 1
        assert derived["successful_auth_after_failures"] is True
        assert derived["src_ip_first_seen_days"] == 0
        assert derived["src_ip_reputation"] == "malicious"
        assert derived["host_criticality"] == "crown_jewel"
        assert derived["rule_historical_fp_rate"] == 0.62
        assert derived["similar_alerts_24h"] == 2

    def test_missing_entities_and_empty_lookups_default_safely(self):
        alert = {}
        entities = {}
        derived = build_derived(alert, entities, [], {}, REF)

        assert derived["failed_auth_10m"] == 0
        assert derived["successful_auth_after_failures"] is False
        assert derived["src_ip_first_seen_days"] == 0
        assert derived["src_ip_reputation"] == "unknown"
        assert derived["host_criticality"] == "unknown"
        assert derived["rule_historical_fp_rate"] == 0.0
        assert derived["similar_alerts_24h"] == 0

    def test_example_from_architecture_doc_shape(self):
        # Sanity check against the worked example in docs/architecture.md §4:
        # a Sunday 03:12:44 SSH brute-force alert should read as off_hours.
        alert = {"rule_id": "5712", "rule_description": "SSHD brute force"}
        entities = {"src_ip": "203.0.113.7", "user": "svc-backup", "host": "db-prod-02"}
        derived = build_derived(alert, entities, [], self._lookups(), REF)
        assert derived["off_hours"] is True
