from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass
from threading import Lock


@dataclass
class RateLimitState:
    count: int = 0
    last_request_at: float = 0.0


class SlidingWindowRateLimiter:
    def __init__(self, limit: int, window_seconds: float) -> None:
        self.limit = limit
        self.window_seconds = window_seconds
        self._states: dict[str, RateLimitState] = defaultdict(RateLimitState)
        self._lock = Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            state = self._states[key]
            if now - state.last_request_at > self.window_seconds:
                state.count = 0
            if state.count >= self.limit:
                state.last_request_at = now
                return False
            state.count += 1
            state.last_request_at = now
            return True
