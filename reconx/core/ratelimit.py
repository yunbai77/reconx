import threading
import time


class RateLimiter:
    def __init__(self, rate_per_sec: float, burst: int = 1):
        self.rate = float(rate_per_sec)
        self.capacity = max(1, int(burst))
        self.tokens = float(self.capacity)
        self.last = time.monotonic()
        self.lock = threading.Lock()

    def acquire(self, tokens: float = 1.0) -> None:
        if self.rate <= 0:
            return
        while True:
            with self.lock:
                now = time.monotonic()
                self.tokens = min(
                    self.capacity,
                    self.tokens + (now - self.last) * self.rate,
                )
                self.last = now
                if self.tokens >= tokens:
                    self.tokens -= tokens
                    return
                wait = (tokens - self.tokens) / self.rate
            time.sleep(wait)
