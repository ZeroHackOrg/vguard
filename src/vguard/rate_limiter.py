# src/vguard/rate_limiter.py
import threading
import time
from dataclasses import dataclass, field
from typing import Dict


class RateLimitExceeded(Exception):
    pass


@dataclass
class TokenBucket:
    capacity: float
    refill_rate: float
    tokens: float = field(init=False)

    def __post_init__(self):
        self.tokens = self.capacity
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def consume(self, cost: float = 1.0) -> bool:
        with self._lock:
            now = time.monotonic()
            self.tokens = min(self.capacity, self.tokens + (now - self._last) * self.refill_rate)
            self._last = now
            if self.tokens < cost:
                return False
            self.tokens -= cost
            return True


class RateLimiter:
    def __init__(self, rpm: int = 60, budget: float = 1_000_000.0):
        self.rpm = int(rpm)
        self.budget = float(budget)
        self._buckets: Dict[str, TokenBucket] = {}
        self._spend: Dict[str, float] = {}
        self._lock = threading.Lock()

    def bucket_for(self, key: str) -> TokenBucket:
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = TokenBucket(capacity=self.rpm, refill_rate=self.rpm / 60.0)
                self._buckets[key] = bucket
            return bucket

    def allow(self, key: str, cost: float = 1.0) -> bool:
        if not self.bucket_for(key).consume(cost):
            raise RateLimitExceeded(f"Rate limit exceeded for key '{key}' (limit {self.rpm} rpm).")
        with self._lock:
            spent = self._spend.get(key, 0.0)
            if spent + cost > self.budget:
                raise RateLimitExceeded(f"Compute budget exhausted for key '{key}' (budget {self.budget}).")
            self._spend[key] = spent + cost
        return True

    def remaining(self, key: str) -> float:
        return max(0.0, self.budget - self._spend.get(key, 0.0))