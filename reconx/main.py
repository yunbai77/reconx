from __future__ import annotations

import argparse
import sys

from reconx.config import load_config
from reconx.core.export import HostRecord, write_results
from reconx.core.logger import get_logger, setup_logger
from reconx.core.ratelimit import RateLimiter
from reconx.core.session import StealthSession
from reconx.modules.dns import HOST_TYPES, resolve_many
from reconx.modules.httpprobe import probe
from reconx.modules.portscan import PortScanner, parse_ports
from reconx.modules.subdomain import enumerate_subdomains

log = get_logger()


def run_scan(domain: str, cfg, do_http: bool = True, do_ports: bool = True) -> list:
    log.info("enumerating subdomains for %s", domain)
    subs = enumerate_subdomains(domain)
    log.info("subdomains: %d (source=%s)", len(subs.subdomains), subs.source)
    if not subs.subdomains:
        log.warning("no subdomains found")
        return []

    results = resolve_many(
        subs.subdomains, record_types=HOST_TYPES, workers=cfg.network.concurrency
    )
    records = []
    for r in results:
        rec = HostRecord(host=r.name, addresses=r.addresses)
        rec.cname = next(
            (v for x in r.records if x.record_type == "CNAME" for v in x.values), ""
        )
        records.append(rec)
    record_map = {rec.host: rec for rec in records}
    alive = [r for r in results if r.addresses]
    log.info("alive: %d/%d", len(alive), len(results))

    if do_http and cfg.modules.httpprobe and alive:
        session = StealthSession(cfg.network, cfg.http)
        try:
            for r in alive:
                info = probe(session, r.name)
                rec = record_map[r.name]
                rec.status = info.status
                rec.server = info.server
                rec.title = info.title
                log.info("http  %-40s %s %s", r.name, info.status, info.title or info.error or "")
        finally:
            session.close()

    if do_ports and cfg.modules.portscan and alive:
        limiter = RateLimiter(cfg.network.rate_limit, burst=max(1, cfg.network.concurrency))
        scanner = PortScanner(
            limiter=limiter,
            timeout=min(2.0, cfg.network.timeout),
            delay_min=cfg.network.delay_min,
            delay_max=cfg.network.delay_max,
            max_workers=max(1, cfg.network.concurrency),
        )
        ports = parse_ports(cfg.portscan.ports)
        for r in alive:
            res = scanner.scan(r.name, ports)
            record_map[r.name].open_ports = res.open_ports
            log.info("ports %-40s %s", r.name, ", ".join(res.services) or "-")

    for path in write_results(domain, records, cfg.general.output_dir):
        log.info("wrote %s", path)
    return records


def cmd_scan(args) -> None:
    cfg = load_config(args.config) if args.config else load_config()
    setup_logger(cfg.general.log_file, cfg.general.log_level)
    run_scan(args.domain, cfg, do_http=not args.no_http, do_ports=not args.no_ports)


def cmd_tui(args) -> None:
    from reconx.ui.tui import run

    run()


def cmd_env(args) -> None:
    cfg = load_config(args.config) if args.config else load_config()
    print(cfg)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reconx", description="Stealthy recon: subdomains, DNS, ports, HTTP"
    )
    parser.add_argument("-c", "--config", help="path to config.yaml")
    sub = parser.add_subparsers(dest="command")

    p_scan = sub.add_parser("scan", help="run a full recon scan")
    p_scan.add_argument("domain")
    p_scan.add_argument("--no-http", action="store_true", help="skip HTTP probing")
    p_scan.add_argument("--no-ports", action="store_true", help="skip port scanning")
    p_scan.set_defaults(func=cmd_scan)

    p_tui = sub.add_parser("tui", help="launch the terminal UI")
    p_tui.set_defaults(func=cmd_tui)

    p_env = sub.add_parser("env", help="print resolved configuration")
    p_env.set_defaults(func=cmd_env)
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 1
    try:
        args.func(args)
    except KeyboardInterrupt:
        log.warning("interrupted by user")
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
