from __future__ import annotations

from dataclasses import dataclass, field

import httpx

CRT_SH_URL = "https://crt.sh/"
CERTSPOTTER_URL = "https://api.certspotter.com/v1/issuances"
DEFAULT_HEADERS = {"User-Agent": "reconx/0.1 (security recon; authorized use only)"}


@dataclass
class SubdomainResult:
    domain: str
    source: str = "none"
    subdomains: list[str] = field(default_factory=list)
    error: str | None = None


def _normalize(domain: str) -> str:
    return domain.strip().lower().strip(".")


def _collect(names, domain: str) -> set[str]:
    out: set[str] = set()
    suffix = "." + domain
    for raw in names:
        for name in str(raw).splitlines():
            name = name.strip().lower().rstrip(".").lstrip("*.")
            if name and (name == domain or name.endswith(suffix)):
                out.add(name)
    return out


def query_crtsh(domain: str, timeout: float = 90.0) -> set[str]:
    params = {"q": f"%.{domain}", "output": "json"}
    with httpx.Client(timeout=timeout, trust_env=False, headers=DEFAULT_HEADERS) as client:
        resp = client.get(CRT_SH_URL, params=params)
        resp.raise_for_status()
        records = resp.json()
    names: set[str] = set()
    for rec in records:
        names |= _collect([rec.get("name_value", "")], domain)
    return names


def query_certspotter(domain: str, timeout: float = 60.0) -> set[str]:
    params = {"domain": domain, "include_subdomains": "true", "expand": "dns_names"}
    with httpx.Client(timeout=timeout, trust_env=False, headers=DEFAULT_HEADERS) as client:
        resp = client.get(CERTSPOTTER_URL, params=params)
        resp.raise_for_status()
        records = resp.json()
    names: set[str] = set()
    for rec in records:
        names |= _collect(rec.get("dns_names", []), domain)
    return names


def enumerate_subdomains(domain: str) -> SubdomainResult:
    domain = _normalize(domain)
    errors: list[str] = []
    for source, fn in (("crt.sh", query_crtsh), ("certspotter", query_certspotter)):
        try:
            names = fn(domain)
        except Exception as exc:
            errors.append(f"{source}: {exc}")
            continue
        if names:
            return SubdomainResult(domain=domain, source=source, subdomains=sorted(names))
        errors.append(f"{source}: empty")
    return SubdomainResult(domain=domain, error="; ".join(errors))
