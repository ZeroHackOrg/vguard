import pytest

from vguard.rate_limiter import RateLimitExceeded, RateLimiter


def test_within_limit():
    limiter = RateLimiter(rpm=10, budget=100)
    assert limiter.allow("tenant-a")


def test_rpm_exhausted():
    limiter = RateLimiter(rpm=3, budget=100)
    for _ in range(3):
        limiter.allow("tenant-a")
    with pytest.raises(RateLimitExceeded, match="Rate limit"):
        limiter.allow("tenant-a")


def test_budget_exhausted():
    limiter = RateLimiter(rpm=1000, budget=5)
    for _ in range(5):
        limiter.allow("tenant-b", cost=1.0)
    with pytest.raises(RateLimitExceeded, match="budget"):
        limiter.allow("tenant-b", cost=1.0)


def test_independent_keys():
    limiter = RateLimiter(rpm=1, budget=100)
    limiter.allow("tenant-a")
    assert limiter.allow("tenant-b")


def test_remaining_budget():
    limiter = RateLimiter(rpm=100, budget=10)
    limiter.allow("tenant-a", cost=4)
    assert limiter.remaining("tenant-a") == 6.0