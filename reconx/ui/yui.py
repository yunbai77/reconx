from __future__ import annotations

from pathlib import Path

from textual import work
from textual.app import App, ComposeResult
from textual.containers import Horizontal
from textual.widgets import Button, DataTable, Footer, Header, Input, RichLog

from reconx.config import load_config
from reconx.core.session import StealthSession
from reconx.modules.dns import HOST_TYPES, resolve_many
from reconx.modules.httpprobe import probe
from reconx.modules.subdomain import enumerate_subdomains

CONFIG_PATH = Path(__file__).resolve().parents[2] / "config.yaml"


class ReconxApp(App):
    CSS = """
    #toolbar { height: 3; }
    #target  { width: 1fr; }
    #run     { width: 16; }
    #results { height: 1fr; }
    #log     { height: 10; }
    """

    BINDINGS = [("q", "quit", "Quit"), ("ctrl+r", "run", "Run")]

    def __init__(self) -> None:
        super().__init__()
        self.config = load_config(CONFIG_PATH)

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="toolbar"):
            yield Input(placeholder="domain e.g. nmap.org", id="target")
            yield Button("Scan", id="run", variant="primary")
        yield DataTable(id="results")
        yield RichLog(id="log", markup=True)
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#results", DataTable)
        for key, label in (
            ("host", "Subdomain"),
            ("addr", "Addresses"),
            ("status", "Status"),
            ("server", "Server"),
            ("title", "Title"),
        ):
            table.add_column(label, key=key)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "run":
            self.action_run()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self.action_run()

    def action_run(self) -> None:
        domain = self.query_one("#target", Input).value.strip()
        log = self.query_one("#log", RichLog)
        if not domain:
            log.write("[red]please input a domain[/red]")
            return
        self.run_scan(domain)

    @work(thread=True, exclusive=True)
    def run_scan(self, domain: str) -> None:
        log = self.query_one("#log", RichLog)
        table = self.query_one("#results", DataTable)

        self.call_from_thread(log.write, f"[cyan]1/3 enumerating {domain} ...[/cyan]")
        subs = enumerate_subdomains(domain)
        if subs.error:
            self.call_from_thread(log.write, f"[yellow]{subs.error}[/yellow]")
        if not subs.subdomains:
            self.call_from_thread(log.write, "[red]no subdomains found[/red]")
            return
        self.call_from_thread(table.clear)
        for name in subs.subdomains:
            self.call_from_thread(table.add_row, name, "", "", "", "", key=name)
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
        for r in results:
            self.call_from_thread(table.update_cell, r.name, "addr", " ".join(r.addresses))
        self.call_from_thread(log.write, f"[green]alive: {len(alive)}/{len(results)}[/green]")

        if not self.config.modules.httpprobe or not alive:
            return

        self.call_from_thread(log.write, "[cyan]3/3 http probe ...[/cyan]")
        session = StealthSession(self.config.network, self.config.http)
        try:
            for r in alive:
                info = probe(session, r.name)
                self.call_from_thread(table.update_cell, r.name, "status", str(info.status or "-"))
                self.call_from_thread(table.update_cell, r.name, "server", info.server)
                self.call_from_thread(
                    table.update_cell, r.name, "title", info.title or (info.error or "")
                )
        finally:
            session.close()
        self.call_from_thread(log.write, "[green]done[/green]")


def run() -> None:
    ReconxApp().run()


if __name__ == "__main__":
    run()
