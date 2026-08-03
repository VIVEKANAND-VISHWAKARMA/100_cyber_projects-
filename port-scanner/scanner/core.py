from __future__ import annotations

import ipaddress
import os
import random
import select
import socket
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

from .services import TOP_PORTS, lookup_service

PORT_ALL = 65535

STATE_OPEN = "open"
STATE_CLOSED = "closed"
STATE_FILTERED = "filtered"
STATE_OPEN_OR_FILTERED = "open|filtered"

ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0
ICMP_UNREACHABLE = 3
ICMP_PORT_UNREACHABLE = 3

HTTP_GET_PROBE = b"GET / HTTP/1.0\r\n\r\n"


class ScannerError(RuntimeError):
    pass


@dataclass
class ScanResult:
    host: str
    port: int
    protocol: str
    state: str
    service: str
    banner: str = ""
    rtt_ms: float = 0.0

    def as_dict(self) -> dict:
        return {
            "host": self.host,
            "port": self.port,
            "protocol": self.protocol,
            "state": self.state,
            "service": self.service,
            "banner": self.banner,
            "rtt_ms": round(self.rtt_ms, 3),
        }


def parse_ports(spec: str) -> list[int]:
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            bounds = part.split("-")
            if len(bounds) != 2:
                raise ValueError(f"invalid port range: {part!r}")
            start, end = bounds
            try:
                start, end = int(start), int(end)
            except ValueError as exc:
                raise ValueError(f"invalid port range: {part!r}") from exc
            if not 1 <= start <= 65535 or not 1 <= end <= 65535:
                raise ValueError(f"port out of range (1-65535): {part!r}")
            if start > end:
                raise ValueError(f"range start is greater than end: {part!r}")
            ports.update(range(start, end + 1))
        else:
            try:
                port = int(part)
            except ValueError as exc:
                raise ValueError(f"invalid port: {part!r}") from exc
            if not 1 <= port <= 65535:
                raise ValueError(f"port out of range (1-65535): {part!r}")
            ports.add(port)
    if not ports:
        raise ValueError("empty port specification")
    return sorted(ports)


def expand_targets(target: str) -> list[str]:
    target = target.strip()
    if not target:
        raise ValueError("empty target")
    if "/" in target:
        try:
            network = ipaddress.ip_network(target, strict=False)
        except ValueError as exc:
            raise ValueError(f"invalid CIDR range: {target!r}") from exc
        if network.num_addresses <= 2:
            return [str(ip) for ip in network]
        return [str(ip) for ip in network.hosts()]
    if "/" not in target:
        try:
            ipaddress.ip_address(target)
            return [target]
        except ValueError:
            pass
    try:
        resolved = socket.gethostbyname(target)
    except socket.gaierror as exc:
        raise ValueError(f"could not resolve target: {target!r}") from exc
    return [resolved]


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def local_ip() -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        sock.close()


def icmp_ping(host: str, timeout: float = 1.0) -> bool | None:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        return None
    except OSError:
        return None
    with sock:
        sock.settimeout(timeout)
        try:
            target_ip = socket.gethostbyname(host)
        except OSError:
            target_ip = host
        ident = os.getpid() & 0xFFFF
        payload = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, 0, ident, 1) + b"\x00" * 32
        packet = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, checksum(payload), ident, 1) + b"\x00" * 32
        try:
            sock.sendto(packet, (target_ip, 1))
        except OSError:
            return False
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                data, addr = sock.recvfrom(2048)
            except socket.timeout:
                return False
            if addr[0] != target_ip:
                continue
            ip_header_len = (data[0] & 0x0F) * 4
            if ip_header_len + 8 > len(data):
                continue
            icmp_type = data[ip_header_len]
            reply_ident = struct.unpack("!H", data[ip_header_len + 4 : ip_header_len + 6])[0]
            if icmp_type == ICMP_ECHO_REPLY and reply_ident == ident:
                return True
        return False


def tcp_ping(host: str, timeout: float = 1.0, ports: tuple[int, ...] = (80, 443, 22)) -> bool:
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                if sock.connect_ex((host, port)) == 0:
                    return True
        except OSError:
            continue
    return False


def host_is_up(
    host: str, timeout: float = 1.0, ports: tuple[int, ...] = (80, 443, 22)
) -> bool:
    alive = icmp_ping(host, timeout)
    if alive is not None:
        return alive
    return tcp_ping(host, timeout, ports)


class PortScanner:
    def __init__(
        self,
        protocol: str = "tcp",
        timeout: float = 1.0,
        threads: int = 100,
        grab_banners: bool = False,
        resolve_services: bool = True,
        randomize: bool = False,
        on_result=None,
    ) -> None:
        if protocol not in ("tcp", "syn", "udp"):
            raise ScannerError(f"unknown protocol: {protocol!r}")
        if timeout <= 0:
            raise ScannerError("timeout must be positive")
        if threads < 1:
            raise ScannerError("threads must be at least 1")
        self.protocol = protocol
        self.timeout = timeout
        self.threads = min(threads, 4096)
        self.grab_banners = grab_banners
        self.resolve_services = resolve_services
        self.randomize = randomize
        self.on_result = on_result
        if protocol == "syn" and not self._syn_capable():
            raise ScannerError(
                "SYN scanning requires raw sockets (run as root); "
                "use --protocol tcp instead"
            )

    def _syn_capable(self) -> bool:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW):
                with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP):
                    return True
        except (PermissionError, OSError):
            return False

    def scan(self, hosts: list[str], ports: list[int] | None = None) -> list[ScanResult]:
        results: list[ScanResult] = []
        for host in hosts:
            results.extend(self.scan_host(host, ports or TOP_PORTS))
        return results

    def scan_host(self, host: str, ports: list[int]) -> list[ScanResult]:
        work = list(ports)
        if self.randomize:
            random.shuffle(work)
        results: list[ScanResult] = []
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self._scan_port, host, port): port for port in work
            }
            for future in as_completed(futures):
                result = future.result()
                results.append(result)
                if self.on_result is not None:
                    self.on_result(result)
        results.sort(key=lambda r: r.port)
        return results

    def _scan_port(self, host: str, port: int) -> ScanResult:
        if self.protocol == "tcp":
            state, banner, rtt = self._tcp_probe(host, port)
        elif self.protocol == "udp":
            state, banner, rtt = self._udp_probe(host, port)
        else:
            state, banner, rtt = self._syn_probe(host, port)
        service = lookup_service(port) if self.resolve_services else "unknown"
        return ScanResult(
            host=host,
            port=port,
            protocol=self.protocol,
            state=state,
            service=service,
            banner=banner,
            rtt_ms=rtt,
        )

    def _tcp_probe(self, host: str, port: int) -> tuple[str, str, float]:
        start = time.perf_counter()
        state = STATE_CLOSED
        banner = ""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(self.timeout)
            if sock.connect_ex((host, port)) == 0:
                state = STATE_OPEN
                if self.grab_banners:
                    banner = self._grab_banner(sock, port)
        rtt = (time.perf_counter() - start) * 1000.0
        return state, banner, rtt

    def _grab_banner(self, sock: socket.socket, port: int) -> str:
        sock.settimeout(min(self.timeout, 1.0))
        for probe in self._banner_probes(port):
            try:
                if probe:
                    sock.sendall(probe)
                data = sock.recv(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            if data:
                return self._clean_banner(data)
        return ""

    @staticmethod
    def _banner_probes(port: int) -> tuple[bytes, bytes]:
        service = lookup_service(port).lower()
        if "http" in service or port in (80, 443, 8080, 8443) or 8000 <= port <= 8999:
            return (HTTP_GET_PROBE, b"")
        return (b"", HTTP_GET_PROBE)

    @staticmethod
    def _clean_banner(data: bytes) -> str:
        text = data.decode("utf-8", errors="replace")
        cleaned = "".join(ch if ch.isprintable() else "." for ch in text)
        return cleaned.strip()[:200]

    def _udp_probe(self, host: str, port: int) -> tuple[str, str, float]:
        start = time.perf_counter()
        state = STATE_OPEN_OR_FILTERED
        banner = ""
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        icmp = None
        try:
            icmp = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        except (PermissionError, OSError):
            icmp = None
        try:
            udp.sendto(b"", (host, port))
            deadline = time.monotonic() + self.timeout
            while time.monotonic() < deadline:
                remaining = deadline - time.monotonic()
                sockets = [udp] + ([icmp] if icmp is not None else [])
                try:
                    ready, _, _ = select.select(sockets, [], [], max(remaining, 0))
                except OSError:
                    break
                if not ready:
                    break
                for sock in ready:
                    if sock is udp:
                        try:
                            data = sock.recv(1024)
                        except OSError:
                            continue
                        state = STATE_OPEN
                        if data:
                            banner = self._clean_banner(data)
                        rtt = (time.perf_counter() - start) * 1000.0
                        return state, banner, rtt
                    else:
                        try:
                            packet = sock.recv(2048)
                        except OSError:
                            continue
                        if self._is_icmp_port_unreachable(packet, port):
                            state = STATE_CLOSED
                            rtt = (time.perf_counter() - start) * 1000.0
                            return state, banner, rtt
        finally:
            udp.close()
            if icmp is not None:
                icmp.close()
        rtt = (time.perf_counter() - start) * 1000.0
        return state, banner, rtt

    @staticmethod
    def _is_icmp_port_unreachable(packet: bytes, port: int) -> bool:
        if len(packet) < 28:
            return False
        ip_header_len = (packet[0] & 0x0F) * 4
        if ip_header_len + 8 > len(packet):
            return False
        icmp_type = packet[ip_header_len]
        icmp_code = packet[ip_header_len + 1]
        if icmp_type != ICMP_UNREACHABLE or icmp_code != ICMP_PORT_UNREACHABLE:
            return False
        embedded_offset = ip_header_len + 8
        if embedded_offset + 20 > len(packet):
            return False
        embedded_ip_len = (packet[embedded_offset] & 0x0F) * 4
        udp_offset = embedded_offset + embedded_ip_len
        if udp_offset + 4 > len(packet):
            return False
        dest_port = struct.unpack("!H", packet[udp_offset + 2 : udp_offset + 4])[0]
        return dest_port == port

    def _syn_probe(self, host: str, port: int) -> tuple[str, str, float]:
        start = time.perf_counter()
        try:
            target_ip = socket.gethostbyname(host)
        except OSError:
            target_ip = host
        send_sock, recv_sock = _thread_raw_sockets()
        src_port = random.randint(1024, 65535)
        seq = random.getrandbits(32)
        self._send_syn(send_sock, target_ip, port, src_port, seq)
        state = self._wait_syn_reply(recv_sock, target_ip, port, src_port)
        rtt = (time.perf_counter() - start) * 1000.0
        return state, "", rtt

    def _send_syn(
        self, send_sock: socket.socket, dst_ip: str, dst_port: int, src_port: int, seq: int
    ) -> None:
        tcp_header = struct.pack(
            "!HHIIBBHHH",
            src_port,
            dst_port,
            seq,
            0,
            5 << 4,
            0x02,
            65535,
            0,
            0,
        )
        pseudo_header = struct.pack(
            "!4s4sBBH",
            socket.inet_aton(local_ip()),
            socket.inet_aton(dst_ip),
            0,
            socket.IPPROTO_TCP,
            len(tcp_header),
        )
        tcp_sum = checksum(pseudo_header + tcp_header)
        tcp_header = struct.pack(
            "!HHIIBBHHH",
            src_port,
            dst_port,
            seq,
            0,
            5 << 4,
            0x02,
            65535,
            tcp_sum,
            0,
        )
        ip_header = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            20 + len(tcp_header),
            0,
            0,
            64,
            socket.IPPROTO_TCP,
            0,
            socket.inet_aton(local_ip()),
            socket.inet_aton(dst_ip),
        )
        ip_sum = checksum(ip_header)
        ip_header = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            20 + len(tcp_header),
            0,
            0,
            64,
            socket.IPPROTO_TCP,
            ip_sum,
            socket.inet_aton(local_ip()),
            socket.inet_aton(dst_ip),
        )
        send_sock.sendto(ip_header + tcp_header, (dst_ip, 0))

    def _wait_syn_reply(
        self, recv_sock: socket.socket, dst_ip: str, dst_port: int, src_port: int
    ) -> str:
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            try:
                ready, _, _ = select.select([recv_sock], [], [], max(remaining, 0))
            except OSError:
                return STATE_FILTERED
            if not ready:
                return STATE_FILTERED
            try:
                packet, _ = recv_sock.recvfrom(65535)
            except OSError:
                return STATE_FILTERED
            if len(packet) < 40:
                continue
            ip_header_len = (packet[0] & 0x0F) * 4
            if packet[9] != socket.IPPROTO_TCP or ip_header_len + 20 > len(packet):
                continue
            tcp_offset = ip_header_len
            reply_src, reply_dst = struct.unpack("!HH", packet[tcp_offset : tcp_offset + 4])
            flags = packet[tcp_offset + 13]
            if reply_src != dst_port or reply_dst != src_port:
                continue
            if flags & 0x12:
                return STATE_OPEN
            if flags & 0x04:
                return STATE_CLOSED
        return STATE_FILTERED


_syn_local = threading.local()


def _thread_raw_sockets() -> tuple[socket.socket, socket.socket]:
    if not hasattr(_syn_local, "send_sock"):
        send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        try:
            send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        except OSError:
            pass
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        _syn_local.send_sock = send_sock
        _syn_local.recv_sock = recv_sock
    return _syn_local.send_sock, _syn_local.recv_sock
