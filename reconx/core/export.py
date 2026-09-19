from __future__ import annotations

import csv
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class HostRecord:
    host: str
    addresses: list[str] = field(default_factory=list)
    cname: str = ""
    open_ports: list[int] = field(default_factory=list)
    status: int | None = None
    server: str = ""
    title: str = ""


def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


def write_results(target: str, records: list[HostRecord], out_dir: str | Path = "results") -> list[Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    stamp = _timestamp()
    base = f"{target.replace('/', '_')}_{stamp}"

    json_path = out / f"{base}.json"
    payload = {
        "target": target,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "count": len(records),
        "hosts": [asdict(r) for r in records],
    }
    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    csv_path = out / f"{base}.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["host", "addresses", "cname", "open_ports", "status", "server", "title"])
        for r in records:
            writer.writerow([
                r.host,
                " ".join(r.addresses),
                r.cname,
                " ".join(str(p) for p in r.open_ports),
                r.status if r.status is not None else "",
                r.server,
                r.title,
            ])
    return [json_path, csv_path]
