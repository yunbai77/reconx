import random
import threading
import time

import httpx

from reconx.core.logger import get_logger
from reconx.core.ratelimit import RateLimiter

log = get_logger()

DEFAULT_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Connection": "keep-alive",
}


class StealthSession:
    def __init__(self, net_cfg, http_cfg):
        self.net = net_cfg
        self.http = http_cfg
        self.limiter = RateLimiter(net_cfg.rate_limit)
        self._clients = {}
        self._proxy_idx = 0
        self._lock = threading.Lock()

    def _pick_proxy(self):
        proxies = list(self.net.proxies or [])
        if not proxies:
            return None
        if self.net.proxy_rotate:
            with self._lock:
                proxy = proxies[self._proxy_idx % len(proxies)]
                self._proxy_idx += 1
            return proxy
        return proxies[0]

    def _build_client(self, proxy):
        return httpx.Client(
            timeout=self.net.timeout,
            proxy=proxy,
            follow_redirects=self.http.follow_redirects,
            verify=self.http.verify_tls,
            headers=dict(DEFAULT_HEADERS),
        )

    def _client(self, proxy):
        if proxy not in self._clients:
            self._clients[proxy] = self._build_client(proxy)
        return self._clients[proxy]

    def request(self, method, url, **kwargs):
        self.limiter.acquire()
        if self.net.delay_max > 0:
            time.sleep(random.uniform(self.net.delay_min, self.net.delay_max))

        headers = dict(kwargs.pop("headers", {}) or {})
        if self.net.user_agents:
            headers.setdefault("User-Agent", random.choice(self.net.user_agents))

        last_exc = None
        for attempt in range(self.net.retries + 1):
            proxy = self._pick_proxy()
            client = self._client(proxy)
            try:
                return client.request(method, url, headers=headers, **kwargs)
            except httpx.HTTPError as e:
                last_exc = e
                log.debug("请求失败(%s/%s) %s: %s",
                          attempt + 1, self.net.retries + 1, url, e)
                time.sleep(1.5 * (attempt + 1))
        raise last_exc

    def get(self, url, **kwargs):
        return self.request("GET", url, **kwargs)

    def close(self):
        for c in self._clients.values():
            c.close()
        self._clients.clear()
