"""Token-bucket rate limiting for Jev calls (docs/architecture.md §5: "Rate limit is 1,200
req/min and 250k tokens/sec -- the replay harness needs a token-bucket limiter in front of it").

Two independent buckets, combined in `JevRateLimiter`:
  - a request bucket: capacity 1200, refilling at 1200/60 = 20 tokens/sec
  - a token bucket:    capacity 250_000, refilling at 250_000/sec

Both are plain `TokenBucket` instances; `JevRateLimiter.acquire()` blocks on whichever bucket is
more depleted. The clock and sleep function are both injectable so tests never call `time.sleep`
or depend on wall-clock time (see tests/test_rate_limiter.py).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable

Clock = Callable[[], float]
Sleep = Callable[[float], None]


@dataclass
class TokenBucket:
    """A single token bucket: `capacity` tokens max, refilling continuously at `refill_rate`
    tokens/sec. Not thread-safe by design -- callers needing cross-thread/process limiting should
    put a lock around `acquire`/`wait_time`, same as any other in-process rate limiter.
    """

    capacity: float
    refill_rate: float
    clock: Clock = field(default=lambda: 0.0)
    _tokens: float = field(init=False, repr=False)
    _last_refill: float = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if self.capacity <= 0:
            raise ValueError("capacity must be positive")
        if self.refill_rate <= 0:
            raise ValueError("refill_rate must be positive")
        self._tokens = self.capacity
        self._last_refill = self.clock()

    def _refill(self) -> None:
        now = self.clock()
        elapsed = now - self._last_refill
        if elapsed > 0:
            self._tokens = min(self.capacity, self._tokens + elapsed * self.refill_rate)
            self._last_refill = now

    def wait_time(self, amount: float) -> float:
        """Seconds until `amount` tokens would be available, without consuming anything. 0.0 if
        already available (including when `amount` exceeds `capacity`, which would otherwise wait
        forever -- callers asking for more than the bucket can ever hold get charged immediately
        and go negative instead of deadlocking)."""
        self._refill()
        if amount >= self.capacity or self._tokens >= amount:
            return 0.0
        return (amount - self._tokens) / self.refill_rate

    def consume(self, amount: float, sleep: Sleep = lambda seconds: None) -> None:
        """Block (via `sleep`) until `amount` tokens are available, then deduct them."""
        wait = self.wait_time(amount)
        if wait > 0:
            sleep(wait)
            self._refill()
        self._tokens -= amount


class JevRateLimiter:
    """Combines the request-count and token-count buckets required by docs/architecture.md §5."""

    REQUESTS_PER_MINUTE = 1_200
    TOKENS_PER_SECOND = 250_000

    def __init__(self, clock: Clock | None = None) -> None:
        clock = clock or time.monotonic
        self._request_bucket = TokenBucket(
            capacity=self.REQUESTS_PER_MINUTE,
            refill_rate=self.REQUESTS_PER_MINUTE / 60.0,
            clock=clock,
        )
        self._token_bucket = TokenBucket(
            capacity=self.TOKENS_PER_SECOND,
            refill_rate=float(self.TOKENS_PER_SECOND),
            clock=clock,
        )

    def acquire(self, estimated_tokens: int, sleep: Sleep = lambda seconds: None) -> None:
        """Block until both buckets can afford one request of `estimated_tokens` tokens, then
        deduct from both. Checks/waits for the request bucket first, then the token bucket, so a
        single `acquire()` call never over- or under-charges either bucket."""
        self._request_bucket.consume(1, sleep=sleep)
        self._token_bucket.consume(max(0, estimated_tokens), sleep=sleep)
