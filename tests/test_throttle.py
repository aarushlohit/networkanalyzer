import time

from vulnsync.utils.throttle import RateLimiter


class TestRateLimiter:
    def test_no_limit(self):
        limiter = RateLimiter(max_rate=0)
        t0 = time.monotonic()
        for _ in range(100):
            limiter.wait()
        elapsed = time.monotonic() - t0
        assert elapsed < 0.5

    def test_rate_limit(self):
        limiter = RateLimiter(max_rate=100)
        t0 = time.monotonic()
        for _ in range(100):
            limiter.wait()
        elapsed = time.monotonic() - t0
        assert elapsed >= 0.8

    def test_empty_limiter(self):
        limiter = RateLimiter()
        t0 = time.monotonic()
        for _ in range(10):
            limiter.wait()
        elapsed = time.monotonic() - t0
        assert elapsed < 0.1
