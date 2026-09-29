"""Rate limiter bucket math -- fake clock only, never a real `time.sleep` (docs/architecture.md
§5: token-bucket limiter respecting 1,200 req/min AND 250k tokens/sec, two independent buckets)."""

from __future__ import annotations

import pytest

from rate_limiter import JevRateLimiter, TokenBucket


class FakeClock:
    """A controllable clock: `advance()` moves it forward, calling it returns the current time."""

    def __init__(self, start: float = 0.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def _fail_sleep(seconds: float) -> None:
    raise AssertionError(f"sleep() should not have been called (requested {seconds}s)")


class TestTokenBucket:
    def test_starts_full_no_wait_needed(self) -> None:
        clock = FakeClock()
        bucket = TokenBucket(capacity=10, refill_rate=1, clock=clock)
        assert bucket.wait_time(10) == 0.0
        bucket.consume(10, sleep=_fail_sleep)  # must not raise

    def test_wait_time_when_insufficient(self) -> None:
        clock = FakeClock()
        bucket = TokenBucket(capacity=10, refill_rate=2, clock=clock)  # 2 tokens/sec
        bucket.consume(10, sleep=_fail_sleep)  # drain to empty
        # Refill rate is 2/sec; needing 4 more tokens takes 2.0s.
        assert bucket.wait_time(4) == pytest.approx(2.0)

    def test_consume_blocks_via_injected_sleep_and_advances_fake_clock(self) -> None:
        clock = FakeClock()
        bucket = TokenBucket(capacity=5, refill_rate=1, clock=clock)  # 1 token/sec
        bucket.consume(5, sleep=_fail_sleep)  # drain to empty

        recorded: list[float] = []

        def recording_sleep(seconds: float) -> None:
            recorded.append(seconds)
            clock.advance(seconds)

        bucket.consume(3, sleep=recording_sleep)
        assert recorded == [pytest.approx(3.0)]

    def test_refill_is_capped_at_capacity(self) -> None:
        clock = FakeClock()
        bucket = TokenBucket(capacity=5, refill_rate=100, clock=clock)
        clock.advance(1000)  # would overflow far past capacity without the cap
        assert bucket.wait_time(5) == 0.0

    def test_amount_exceeding_capacity_never_deadlocks(self) -> None:
        clock = FakeClock()
        bucket = TokenBucket(capacity=10, refill_rate=1, clock=clock)
        # Asking for more than the bucket could ever hold must not wait forever.
        assert bucket.wait_time(1_000_000) == 0.0

    def test_rejects_non_positive_capacity_or_rate(self) -> None:
        with pytest.raises(ValueError):
            TokenBucket(capacity=0, refill_rate=1, clock=FakeClock())
        with pytest.raises(ValueError):
            TokenBucket(capacity=1, refill_rate=0, clock=FakeClock())


class TestJevRateLimiter:
    def test_default_limits_match_spec(self) -> None:
        assert JevRateLimiter.REQUESTS_PER_MINUTE == 1_200
        assert JevRateLimiter.TOKENS_PER_SECOND == 250_000

    def test_acquire_within_budget_never_sleeps(self) -> None:
        clock = FakeClock()
        limiter = JevRateLimiter(clock=clock)
        limiter.acquire(estimated_tokens=500, sleep=_fail_sleep)

    def test_request_bucket_forces_a_wait_once_exhausted(self) -> None:
        clock = FakeClock()
        limiter = JevRateLimiter(clock=clock)
        # Drain the 1,200-request bucket completely (tiny token cost so the token bucket never binds).
        for _ in range(1_200):
            limiter.acquire(estimated_tokens=1, sleep=_fail_sleep)

        recorded: list[float] = []

        def recording_sleep(seconds: float) -> None:
            recorded.append(seconds)
            clock.advance(seconds)

        limiter.acquire(estimated_tokens=1, sleep=recording_sleep)
        # Request bucket refills at 1200/60 = 20/sec, so one more token takes 1/20 = 0.05s.
        assert recorded == [pytest.approx(0.05, abs=1e-6)]

    def test_token_bucket_forces_a_wait_once_exhausted(self) -> None:
        clock = FakeClock()
        limiter = JevRateLimiter(clock=clock)
        # A single oversized request drains the 250k token bucket without touching the request bucket.
        limiter.acquire(estimated_tokens=250_000, sleep=_fail_sleep)

        recorded: list[float] = []

        def recording_sleep(seconds: float) -> None:
            recorded.append(seconds)
            clock.advance(seconds)

        limiter.acquire(estimated_tokens=25_000, sleep=recording_sleep)
        # Token bucket refills at 250k/sec, so 25k more tokens takes 0.1s.
        assert recorded == [pytest.approx(0.1, abs=1e-6)]
