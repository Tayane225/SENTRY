"""Thread-safe token-bucket rate limiter for third-party APIs."""

from __future__ import annotations

import threading
import time


class RateLimiter:
    def __init__(self, rate_per_minute: float, burst: int | None = None):
        self.rate = rate_per_minute / 60.0
        self.capacity = burst or max(1, int(rate_per_minute))
        self.tokens = float(self.capacity)
        self.updated = time.monotonic()
        self.lock = threading.Lock()

    def acquire(self, timeout: float = 120) -> bool:
        deadline = time.monotonic() + timeout
        while True:
            with self.lock:
                now = time.monotonic()
                self.tokens = min(self.capacity, self.tokens + (now - self.updated) * self.rate)
                self.updated = now
                if self.tokens >= 1:
                    self.tokens -= 1
                    return True
                wait = (1 - self.tokens) / self.rate
            if time.monotonic() + wait > deadline:
                return False
            time.sleep(min(wait, 5))
