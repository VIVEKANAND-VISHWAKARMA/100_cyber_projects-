# Port Scanner

A multi-threaded network port scanner written in pure Python using **sockets**.
Supports TCP connect scanning, half-open SYN scanning (raw sockets), and UDP
scanning, with banner grabbing, service detection, CIDR ranges, host discovery
and multiple output formats. No third-party dependencies.

## Features

- **Three scan techniques**
  - `tcp` — full three-way-handshake TCP connect scan (no privileges needed)
  - `syn` — half-open SYN scan over raw sockets (requires `root`), classifies
    ports as `open`, `closed`, or `filtered`
  - `udp` — UDP datagram probe that detects open ports from responses and
    closed ports from ICMP "port unreachable" replies
- **Blazing fast** — `ThreadPoolExecutor` with configurable worker count
- **Flexible targets** — hostnames, IP addresses, and CIDR ranges
  (`192.168.1.0/24`)
- **Flexible port selection** — single, comma-separated, ranges, or the N most
  common ports
- **Banner grabbing** — identifies the application behind an open port
- **Service detection** — ~1500 well-known ports resolved via a built-in
  database plus `/etc/services`
- **Host discovery** — optional ICMP ping (with TCP fallback) to skip
  unreachable hosts in large ranges
- **Output formats** — human-readable text, JSON, and CSV; write to a file or
  stdout
- **Stealth options** — randomized scan order, verbose progress reporting

## Requirements

- Python 3.9 or newer
- Linux/Unix (SYN scan and ICMP ping additionally require `root`)

Everything is built on the Python standard library — **no third-party
packages are needed**, so there is no `requirements.txt` file. Just copy the
project and run it:

```bash
python main.py 127.0.0.1
```

## Quick start

```bash
python main.py 127.0.0.1                        # scan top common ports
python main.py scanme.example.com -p 22,80,443  # specific ports
python main.py 192.168.1.10 -p 1-1024           # a range
python main.py 192.168.1.0/24 --top-ports 100   # a subnet
python main.py 10.0.0.5 -P syn                  # half-open SYN scan (root)
python main.py 10.0.0.5 -P udp --top-ports 50   # UDP scan
```

## Usage

```
usage: port-scanner [-h] [-p PORTS] [--top-ports N] [-P {tcp,syn,udp}]
                    [-t TIMEOUT] [-T THREADS] [-b] [--no-service]
                    [--randomize] [--host-discovery] [-f {txt,json,csv}]
                    [-o FILE] [-v] [--version]
                    targets [targets ...]
```

### Options

| Option                | Description                                                  |
| --------------------- | ------------------------------------------------------------ |
| `targets`             | One or more hostnames, IP addresses, or CIDR ranges          |
| `-p, --ports`         | Ports to scan, e.g. `22,80,443` or `1-1024` or `1-100,8080`  |
| `--top-ports N`       | Scan the N most common ports (default: all curated ports)    |
| `-P, --protocol`      | Scan technique: `tcp` (default), `syn`, or `udp`             |
| `-t, --timeout`       | Per-port timeout in seconds (default: `1.0`)                 |
| `-T, --threads`       | Concurrent worker threads (default: `100`)                   |
| `-b, --banner`        | Grab application banners from open ports                     |
| `--no-service`        | Skip service-name lookup for scanned ports                   |
| `--randomize`         | Scan ports in random order to evade detection                |
| `--host-discovery`    | Ping hosts first; skip unreachable hosts in CIDR ranges      |
| `-f, --format`        | Output format: `txt`, `json`, or `csv` (default: `txt`)      |
| `-o, --output FILE`   | Write results to a file instead of stdout                    |
| `-v, --verbose`       | Show totals and live per-port progress                       |

## Examples

Scan the first 1000 ports on a host with 200 threads:

```bash
python main.py 192.168.1.50 -p 1-1000 -T 200
```

Grab banners and write a JSON report:

```bash
python main.py scanme.example.com --top-ports 100 --banner -f json -o report.json
```

Half-open SYN scan of a subnet (requires root):

```bash
sudo python main.py 192.168.1.0/24 -P syn -p 22,80,443,8080
```

Discover live hosts in a subnet first, then scan them via UDP:

```bash
python main.py 10.0.0.0/24 --host-discovery -P udp --top-ports 50
```

### Example output

```
$ python main.py 127.0.0.1 -p 22,80,443 --banner
[*] scanning 1 host(s), 3 port(s) via TCP (100 threads, 1.0s timeout)...
scan results for 127.0.0.1
  open ports (2):
    22     ssh                  open
      banner: SSH-2.0-OpenSSH_9.2
    80     http                 open
      banner: HTTP/1.0 200 OK..Server: SimpleHTTP/0.6 Python/3.13.12..
[*] done in 1.00s: 1 host(s), 3 port(s), 2 open
```

JSON:

```json
{
  "scanner": "port-scanner",
  "results": [
    {
      "host": "127.0.0.1",
      "port": 22,
      "protocol": "tcp",
      "state": "open",
      "service": "ssh",
      "banner": "SSH-2.0-OpenSSH_9.2",
      "rtt_ms": 0.812
    }
  ],
  "targets": ["127.0.0.1"],
  "ports": 3,
  "protocol": "tcp",
  "duration_s": 1.0
}
```

## How it works

### TCP connect scan

The scanner opens a real TCP connection with `socket.connect_ex()` and considers
the port `open` if the three-way handshake completes, `closed` if the host
answers with a RST, and `filtered` on timeout. Each port is probed concurrently
by worker threads drawn from a `ThreadPoolExecutor`.

### SYN scan (requires root)

Instead of completing the handshake, a crafted IP + TCP packet with the `SYN`
flag set is transmitted over a raw socket. The scanner classifies the port by
the reply:

- `SYN-ACK` → `open`
- `RST` → `closed`
- no reply → `filtered`

Packet headers (IP and TCP) and their checksums are built by hand — see
`scanner/core.py`. This technique is faster and less conspicuous than a full
TCP connect, but never completes a connection.

### UDP scan

An empty datagram is sent to the target port. A response marks the port `open`,
an ICMP "port unreachable" message marks it `closed`, and silence after the
timeout leaves it `open|filtered` (UDP scanning can rarely be conclusive).

### Banner grabbing

For each open port the scanner sends a probe — an HTTP request for web ports,
an empty packet for protocols that greet the client — and captures the reply,
which typically reveals the server software and version.

### Host discovery

By default every explicit target is scanned. With `--host-discovery`, hosts in
CIDR ranges are first probed with an ICMP echo request (or a TCP connect to
common ports when ICMP is unavailable) and unreachable hosts are skipped.

## Project structure

```
port-scanner/
├── main.py                 # entry point
├── README.md
└── scanner/
    ├── __init__.py         # public API exports
    ├── cli.py              # argument parsing and orchestration
    ├── core.py             # scanning engine (PortScanner, probes)
    ├── output.py           # text / JSON / CSV renderers
    └── services.py         # well-known port database + top-ports list
```

## Library usage

The scanner can be used as a library:

```python
from scanner import PortScanner

scanner = PortScanner(protocol="tcp", timeout=0.5, threads=50)
results = scanner.scan(["192.168.1.10"], [22, 80, 443])

for result in results:
    print(result.port, result.state, result.service)
```

## Tests

```bash
python -m pytest tests/ -v
```

The suite covers port/range parsing, CIDR expansion, IP checksums, service
lookups, real TCP/UDP scanning over loopback, banner grabbing, and all output
renderers.

## Limitations

- SYN and ICMP-ping features require root for raw sockets; TCP/UDP scanning
  works as an unprivileged user.
- UDP scanning cannot reliably distinguish `open` from `filtered` ports.
- Firewalls, rate limiting, and NAT may cause hosts to appear filtered.

## Legal notice

Port scanning can be considered intrusive or illegal without permission. Only
scan systems you own or are explicitly authorized to test. You are responsible
for complying with all applicable laws.

## License

Open source — released under the MIT License. You are free to use, modify, and
distribute this project for any purpose, including commercial use.
