from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

import dns.exception
import dns.resolver

DEFAULT_NAMESERVERS = ["1.1.1.1", "8.8.8.8"]
HOST_TYPES = ("A", "AAAA", "CNAME")
DOMAIN_TYPES = ("NS", "MX", "TXT")
DEFAULT_TYPES = HOST_TYPES + DOMAIN_TYPES


@dataclass
class DNSRecord:
    name: str
    record_type: str
    values: list[str] = field(default_factory=list)


@dataclass
class DNSResult:
    name: str
    records: list[DNSRecord] = field(default_factory=list)
    error: str | None = None

    @property
    def addresses(self) -> list[str]:
        return [v for r in self.records if r.record_type in ("A", "AAAA") for v in r.values]


def make_resolver(nameservers=None, timeout: float = 3.0, lifetime: float = 8.0) -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = list(nameservers or DEFAULT_NAMESERVERS)
    resolver.timeout = timeout
    resolver.lifetime = lifetime
    return resolver


def resolve(name: str, record_types=DEFAULT_TYPES, resolver=None, nameservers=None) -> DNSResult:
    resolver = resolver or make_resolver(nameservers)
    result = DNSResult(name=name)
    for rtype in record_types:
        try:
            answers = resolver.resolve(name, rtype)
        except dns.resolver.NoAnswer:
            continue
        except dns.resolver.NXDOMAIN:
            result.error = "NXDOMAIN"
            break
        except dns.exception.Timeout:
            result.error = "timeout"
            continue
        except dns.resolver.NoNameservers as exc:
            result.error = f"no nameservers: {exc}"
            continue
        except Exception as exc:
            result.error = str(exc)
            continue
        result.records.append(DNSRecord(name, rtype, [r.to_text() for r in answers]))
    return result


def resolve_many(names, record_types=DEFAULT_TYPES, workers: int = 20, nameservers=None) -> list[DNSResult]:
    results: list[DNSResult] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(resolve, n, record_types, None, nameservers) for n in names]
        for fut in as_completed(futures):
            results.append(fut.result())
    return results
