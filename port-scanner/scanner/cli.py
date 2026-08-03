from __future__ import annotations

import argparse
import sys
import time

from . import __version__
from .core import (
    PortScanner,
    ScannerError,
    expand_targets,
    host_is_up,
    parse_ports,
)
from .output import render_csv, render_json, render_txt, write_output
from .services import TOP_PORTS


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="port-scanner",
        description="Multi-threaded TCP / SYN / UDP port scanner built on Python sockets.",
        epilog=(
            "examples:\n"
            "  python main.py 127.0.0.1\n"
            "  python main.py 192.168.1.10 -p 22,80,443 --banner\n"
            "  python main.py 192.168.1.0/24 -p 1-1024 -T 200 -v\n"
            "  python main.py scanme.example.com --top-ports 100 -f json -o report.json\n"
            "  python main.py 192.168.1.0/28 --host-discovery -P udp --top-ports 50"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("targets", nargs="+", help="hostname, IP address or CIDR range")
    parser.add_argument(
        "-p",
        "--ports",
        metavar="PORTS",
        help="ports to scan, e.g. 22,80,443 or 1-1024 or a mix",
    )
    parser.add_argument(
        "--top-ports",
        type=int,
        metavar="N",
        help=f"scan the N most common ports (default {len(TOP_PORTS)})",
    )
    parser.add_argument(
        "-P",
        "--protocol",
        choices=["tcp", "syn", "udp"],
        default="tcp",
        help="scan technique (default: tcp)",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=1.0,
        help="per-port timeout in seconds (default: 1.0)",
    )
    parser.add_argument(
        "-T",
        "--threads",
        type=int,
        default=100,
        help="number of concurrent worker threads (default: 100)",
    )
    parser.add_argument(
        "-b",
        "--banner",
        action="store_true",
        help="grab application banners from open ports",
    )
    parser.add_argument(
        "--no-service",
        action="store_true",
        help="skip service-name lookup for scanned ports",
    )
    parser.add_argument(
        "--randomize",
        action="store_true",
        help="scan ports in random order to avoid detection",
    )
    parser.add_argument(
        "--host-discovery",
        action="store_true",
        help="probe each host before scanning and skip unreachable ones",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=["txt", "json", "csv"],
        default="txt",
        help="output format (default: txt)",
    )
    parser.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        help="write results to FILE instead of stdout",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="show totals for closed/filtered ports and live progress",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.ports is not None and not args.ports.strip():
            parser.error("--ports must not be empty")
        if args.ports and args.top_ports is not None:
            parser.error("--ports and --top-ports are mutually exclusive")
        if args.top_ports is not None and args.top_ports < 1:
            parser.error("--top-ports must be at least 1")

        if args.ports:
            ports = parse_ports(args.ports)
        elif args.top_ports is not None:
            ports = TOP_PORTS[: args.top_ports]
        else:
            ports = TOP_PORTS

        seen: set[str] = set()
        hosts: list[str] = []
        explicit: dict[str, bool] = {}
        for target in args.targets:
            is_range = "/" in target
            for host in expand_targets(target):
                if host not in seen:
                    seen.add(host)
                    hosts.append(host)
                    explicit[host] = not is_range

        if args.host_discovery:
            print(f"[*] host discovery: probing {len(hosts)} target(s)...", file=sys.stderr)
            alive: list[str] = []
            for host in hosts:
                if host_is_up(host, min(args.timeout, 2.0)):
                    alive.append(host)
                elif explicit[host]:
                    print(
                        f"    {host}: no response, scanning anyway (explicit target)",
                        file=sys.stderr,
                    )
                    alive.append(host)
                else:
                    print(f"    {host}: unreachable, skipping", file=sys.stderr)
            hosts = alive
            if not hosts:
                print("[!] no live hosts found", file=sys.stderr)
                return 1
            print(f"[*] {len(hosts)} host(s) alive", file=sys.stderr)

        scanner = PortScanner(
            protocol=args.protocol,
            timeout=args.timeout,
            threads=args.threads,
            grab_banners=args.banner,
            resolve_services=not args.no_service,
            randomize=args.randomize,
            on_result=_progress if args.verbose else None,
        )
    except (ScannerError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    started = time.perf_counter()
    print(
        f"[*] scanning {len(hosts)} host(s), {len(ports)} port(s) "
        f"via {args.protocol.upper()} ({args.threads} threads, {args.timeout}s timeout)...",
        file=sys.stderr,
    )
    try:
        results = scanner.scan(hosts, ports)
    except KeyboardInterrupt:
        print("\n[!] interrupted by user", file=sys.stderr)
        return 130

    elapsed = time.perf_counter() - started
    meta = {
        "targets": hosts,
        "ports": len(ports),
        "protocol": args.protocol,
        "duration_s": round(elapsed, 3),
    }

    if args.format == "json":
        content = render_json(results, meta=meta)
    elif args.format == "csv":
        content = render_csv(results)
    else:
        content = render_txt(results, show_all=args.verbose)

    write_output(content, args.output)

    open_count = sum(1 for r in results if r.state == "open")
    print(
        f"[*] done in {elapsed:.2f}s: {len(hosts)} host(s), "
        f"{len(ports)} port(s), {open_count} open",
        file=sys.stderr,
    )
    if args.output:
        print(f"[*] results written to {args.output}", file=sys.stderr)
    return 0


def _progress(result) -> None:
    print(
        f"    {result.host}:{result.port} {result.state}"
        + (f" ({result.service})" if result.state == "open" else ""),
        file=sys.stderr,
    )
