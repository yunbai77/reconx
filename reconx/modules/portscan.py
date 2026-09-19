from __future__ import annotations

import random
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from reconx.core.logger import get_logger
from reconx.core.ratelimit import RateLimiter

log = get_logger()

COMMON_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios",
    143: "imap", 443: "https", 445: "smb", 993: "imaps", 995: "pop3s",
    1433: "mssql", 1521: "oracle", 3306: "mysql", 3389: "rdp",
    5432: "postgres", 5900: "vnc", 6379: "redis", 8000: "http-alt",
    8080: "http-proxy", 8443: "https-alt", 11211: "memcached", 27017: "mongodb",
}


@dataclass
class PortResult:
    host: str
    ip: str
    open_ports: list[int] = field(default_factory=list)

    @property
    def services(self) -> list[str]:
        return [f"{p}/{COMMON_PORTS.get(p, 'unknown')}" for p in self.open_ports]


class PortScanner:
    def __init__(self, limiter=None, timeout: float = 1.5,
                 delay_min: float = 0.0, delay_max: float = 0.0,
                 max_workers: int = 20):
        self.limiter = limiter or RateLimiter(50.0, burst=5)
        self.timeout = timeout
        self.delay_min = delay_min
        self.delay_max = delay_max
        self.max_workers = max_workers

    def _probe(self, ip: str, port: int) -> bool:
        self.limiter.acquire()
        if self.delay_max > 0:
            time.sleep(random.uniform(self.delay_min, self.delay_max))
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(self.timeout)
            try:
                return sock.connect_ex((ip, port)) == 0
            except OSError as exc:
                log.debug("probe %s:%s failed: %s", ip, port, exc)
                return False

    @staticmethod
    def resolve_ipv4(host: str) -> str:
        infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
        return infos[0][4][0]

    def scan(self, host: str, ports=None) -> PortResult:
        ip = self.resolve_ipv4(host)
        port_list = list(ports or COMMON_PORTS)
        random.shuffle(port_list)
        open_ports: list[int] = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {pool.submit(self._probe, ip, p): p for p in port_list}
            for fut in as_completed(futures):
                if fut.result():
                    open_ports.append(futures[fut])
        return PortResult(host=host, ip=ip, open_ports=sorted(open_ports))


def parse_ports(spec: str) -> list[int]:
    spec = (spec or "").strip().lower()
    if not spec or spec == "common":
        return list(COMMON_PORTS)
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            ports.update(range(int(lo), int(hi) + 1))
        else:
            ports.add(int(part))
    return sorted(p for p in ports if 0 < p < 65536)
