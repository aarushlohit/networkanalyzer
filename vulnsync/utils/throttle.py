from __future__ import annotations

import random
import time
from threading import Lock


class RateLimiter:
    def __init__(self, max_rate: float = 0, jitter_ms: float = 0):
        self.max_rate = max_rate
        self.jitter = jitter_ms / 1000.0
        self._lock = Lock()
        self._last_tick = 0.0
        self._interval = 1.0 / max_rate if max_rate > 0 else 0

    def wait(self):
        if self.max_rate <= 0 and self.jitter <= 0:
            return
        with self._lock:
            now = time.monotonic()
            if self._interval > 0:
                sleep = max(0, self._last_tick + self._interval - now)
                if sleep > 0:
                    time.sleep(sleep)
            if self.jitter > 0:
                time.sleep(random.uniform(0, self.jitter))
            self._last_tick = time.monotonic()
