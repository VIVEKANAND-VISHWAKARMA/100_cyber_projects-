from __future__ import annotations

import csv
import io
import json

from .core import ScanResult


def render_txt(results: list[ScanResult], show_all: bool = False) -> str:
    lines: list[str] = []
    by_host: dict[str, list[ScanResult]] = {}
    for result in results:
        by_host.setdefault(result.host, []).append(result)
    for host in sorted(by_host):
        host_results = sorted(by_host[host], key=lambda r: r.port)
        open_ports = [r for r in host_results if r.state == "open"]
        lines.append(f"scan results for {host}")
        lines.append(f"  open ports ({len(open_ports)}):")
        if not open_ports:
            lines.append("    none found")
        for result in open_ports:
            line = f"    {result.port:<6}{result.service:<20}{result.state}"
            if result.banner:
                line += f"\n      banner: {result.banner}"
            lines.append(line)
        if show_all:
            counts: dict[str, int] = {}
            for result in host_results:
                counts[result.state] = counts.get(result.state, 0) + 1
            summary = ", ".join(f"{state}: {count}" for state, count in counts.items())
            lines.append(f"  totals ({summary})")
        lines.append("")
    return "\n".join(lines).rstrip()


def render_json(results: list[ScanResult], meta: dict | None = None) -> str:
    payload = {
        "scanner": "port-scanner",
        "results": [result.as_dict() for result in results],
    }
    if meta:
        payload.update(meta)
    return json.dumps(payload, indent=2)


def render_csv(results: list[ScanResult]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["host", "port", "protocol", "state", "service", "banner", "rtt_ms"])
    for result in results:
        writer.writerow(
            [
                result.host,
                result.port,
                result.protocol,
                result.state,
                result.service,
                result.banner,
                f"{result.rtt_ms:.3f}",
            ]
        )
    return buffer.getvalue().rstrip()


def write_output(content: str, path: str | None = None) -> None:
    if path:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)
    else:
        print(content)
