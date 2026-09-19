from __future__ import annotations

from pathlib import Path

from textual import work
from textual.app import App, ComposeResult
from textual.containers import Horizontal
from textual.widgets import Button, DataTable, Footer, Header, Input, RichLog

from reconx.config import load_config
from reconx.core.export import HostRecord, write_results
from reconx.core.ratelimit import RateLimiter
from reconx.core.session import StealthSession
from reconx.modules.dns import HOST_TYPES, resolve_many
from reconx.modules.httpprobe import probe
from reconx.modules.portscan import PortScanner, parse_ports
from reconx.modules.subdomain import enumerate_subdomains

CONFIG_PATH = Path(__file__).resolve().parents[2] / "config.yaml"


class ReconxApp(App):
    CSS = """
    #toolbar { height: 3; }
    #target  { width: 1fr; }
    #run     { width: 12; }
    #ports   { width: 12; }
    #export  { width: 12; }
    #results { height: 1fr; }
    #log     { height: 10; }
    """

    BINDINGS = [("q", "quit", "Quit"), ("ctrl+r", "run", "Run"), ("ctrl+e", "export", "Export")]

    def __init__(self) -> None:
        super().__init__()
        self.config = load_config(CONFIG_PATH)
        self.targets: list[str] = []
        self.records: dict[str, HostRecord] = {}
        self.current_domain = ""

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="toolbar"):
            yield Input(placeholder="domain e.g. nmap.org", id="target")
            yield Button("Scan", id="run", variant="primary")
            yield Button("Ports", id="ports", variant="warning")
            yield Button("Export", id="export", variant="success")
        yield DataTable(id="results")
        yield RichLog(id="log", markup=True)
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#results", DataTable)
        for key, label in (
            ("host", "Subdomain"),
            ("addr", "Addresses"),
            ("ports", "Ports"),
            ("status", "Status"),
            ("server", "Server"),
            ("title", "Title"),
        ):
            table.add_column(label, key=key)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "run":
            self.action_run()
        elif event.button.id == "ports":
            self.action_ports()
        elif event.button.id == "export":
            self.action_export()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self.action_run()

    def action_run(self) -> None:
        domain = self.query_one("#target", Input).value.strip()
        log = self.query_one("#log", RichLog)
        if not domain:
            log.write("[red]please input a domain[/red]")
            return
        self.run_scan(domain)

    def action_ports(self) -> None:
        log = self.query_one("#log", RichLog)
        if not self.targets:
            log.write("[red]run Scan first[/red]")
            return
        self.run_ports(list(self.targets))

    def action_export(self) -> None:
        log = self.query_one("#log", RichLog)
        if not self.records:
            log.write("[red]nothing to export, run Scan first[/red]")
            return
        self.run_export()

    @work(thread=True, exclusive=True)
    def run_scan(self, domain: str) -> None:
        log = self.query_one("#log", RichLog)
        table = self.query_one("#results", DataTable)
        self.current_domain = domain
        self.records = {}

        self.call_from_thread(log.write, f"[cyan]1/3 enumerating {domain} ...[/cyan]")
        subs = enumerate_subdomains(domain)
        if subs.error:
            self.call_from_thread(log.write, f"[yellow]{subs.error}[/yellow]")
        if not subs.subdomains:
            self.call_from_thread(log.write, "[red]no subdomains found[/red]")
            return
        self.call_from_thread(table.clear)
        for name in subs.subdomains:
            self.call_from_thread(table.add_row, name, "", "", "", "", "", key=name)
        self.call_from_thread(
            log.write, f"[green]{len(subs.subdomains)} subdomains via {subs.source}[/green]"
        )

        self.call_from_thread(log.write, "[cyan]2/3 resolving ...[/cyan]")
        results = resolve_many(
            subs.subdomains,
            record_types=HOST_TYPES,
            workers=self.config.network.concurrency,
        )
        alive = [r for r in results if r.addresses]
        self.targets = [r.name for r in alive]
        for r in results:
            rec = HostRecord(host=r.name, addresses=r.addresses)
            rec.cname = next(
                (v for x in r.records if x.record_type == "CNAME" for v in x.values), ""
            )
            self.records[r.name] = rec
            self.call_from_thread(table.update_cell, r.name, "addr", " ".join(r.addresses))
        self.call_from_thread(log.write, f"[green]alive: {len(alive)}/{len(results)}[/green]")

        if not self.config.modules.httpprobe or not alive:
            return

        self.call_from_thread(log.write, "[cyan]3/3 http probe ...[/cyan]")
        session = StealthSession(self.config.network, self.config.http)
        try:
            for r in alive:
                info = probe(session, r.name)
                rec = self.records[r.name]
                rec.status = info.status
                rec.server = info.server
                rec.title = info.title
                self.call_from_thread(table.update_cell, r.name, "status", str(info.status or "-"))
                self.call_from_thread(table.update_cell, r.name, "server", info.server)
                self.call_from_thread(
                    table.update_cell, r.name, "title", info.title or (info.error or "")
                )
        finally:
            session.close()
        self.call_from_thread(log.write, "[green]done[/green]")

    @work(thread=True, exclusive=True)
    def run_ports(self, hosts: list[str]) -> None:
        log = self.query_one("#log", RichLog)
        table = self.query_one("#results", DataTable)
        cfg = self.config
        ports = parse_ports(cfg.portscan.ports)
        limiter = RateLimiter(cfg.network.rate_limit, burst=max(1, cfg.network.concurrency))
        scanner = PortScanner(
            limiter=limiter,
            timeout=min(2.0, cfg.network.timeout),
            delay_min=cfg.network.delay_min,
            delay_max=cfg.network.delay_max,
            max_workers=max(1, cfg.network.concurrency),
        )
        self.call_from_thread(
            log.write, f"[cyan]port scan {len(ports)} ports on {len(hosts)} hosts ...[/cyan]"
        )
        for host in hosts:
            result = scanner.scan(host, ports)
            if host in self.records:
                self.records[host].open_ports = result.open_ports
            text = ", ".join(result.services) or "-"
            self.call_from_thread(table.update_cell, host, "ports", text)
            self.call_from_thread(log.write, f"[green]{host}: {text}[/green]")
        self.call_from_thread(log.write, "[green]port scan done[/green]")

    @work(thread=True, exclusive=True)
    def run_export(self) -> None:
        log = self.query_one("#log", RichLog)
        paths = write_results(
            self.current_domain,
            list(self.records.values()),
            self.config.general.output_dir,
        )
        for path in paths:
            self.call_from_thread(log.write, f"[green]wrote {path}[/green]")


def run() -> None:
    ReconxApp().run()


if __name__ == "__main__":
    run()
