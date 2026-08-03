from __future__ import annotations

import json
import socket
import struct
import threading

import pytest

from scanner.core import ScanResult, PortScanner, checksum, expand_targets, parse_ports
from scanner.output import render_csv, render_json, render_txt
from scanner.services import TOP_PORTS, lookup_service


class TestParsePorts:
    def test_single_port(self):
        assert parse_ports("22") == [22]

    def test_multiple_ports(self):
        assert parse_ports("22,80,443") == [22, 80, 443]

    def test_range(self):
        assert parse_ports("1-5") == [1, 2, 3, 4, 5]

    def test_mixed(self):
        assert parse_ports("1-3,7,9-10") == [1, 2, 3, 7, 9, 10]

    def test_deduped_and_sorted(self):
        assert parse_ports("443,22,22,1-2") == [1, 2, 22, 443]

    def test_whitespace(self):
        assert parse_ports(" 22 , 80 ") == [22, 80]

    def test_invalid_range_reversed(self):
        with pytest.raises(ValueError):
            parse_ports("10-5")

    def test_invalid_port(self):
        with pytest.raises(ValueError):
            parse_ports("abc")

    def test_out_of_range(self):
        with pytest.raises(ValueError):
            parse_ports("70000")

    def test_empty(self):
        with pytest.raises(ValueError):
            parse_ports("")


class TestExpandTargets:
    def test_ip(self):
        assert expand_targets("127.0.0.1") == ["127.0.0.1"]

    def test_cidr(self):
        assert expand_targets("127.0.0.0/30") == ["127.0.0.1", "127.0.0.2"]

    def test_hostname(self):
        assert expand_targets("localhost") == ["127.0.0.1"]

    def test_invalid(self):
        with pytest.raises(ValueError):
            expand_targets("999.999.999.999")


class TestChecksum:
    def test_roundtrip_is_zero(self):
        header = bytearray(
            b"\x45\x00\x00\x3c\x1c\x46\x40\x00\x40\x06\x00\x00"
            b"\xac\xd9\x17\xfe\x0a\x00\x00\x02"
        )
        computed = checksum(bytes(header))
        header[10:12] = struct.pack("!H", computed)
        assert checksum(bytes(header)) == 0


class TestServices:
    def test_well_known(self):
        assert lookup_service(22) == "ssh"
        assert lookup_service(80) == "http"
        assert lookup_service(443) == "https"

    def test_top_ports(self):
        assert 22 in TOP_PORTS
        assert 80 in TOP_PORTS
        assert 443 in TOP_PORTS
        assert all(1 <= p <= 65535 for p in TOP_PORTS)


@pytest.fixture
def tcp_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    def _handler():
        conn, _ = server.accept()
        conn.settimeout(2.0)
        try:
            conn.recv(1024)
            conn.sendall(b"220 test banner ready\r\n")
        except OSError:
            pass
        conn.close()
        server.close()

    thread = threading.Thread(target=_handler, daemon=True)
    thread.start()
    yield port


def _free_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


class TestTcpScan:
    def test_open_and_closed(self, tcp_server):
        open_port = tcp_server
        closed_port = _free_port()
        scanner = PortScanner(protocol="tcp", timeout=1.0, threads=16)
        results = scanner.scan_host("127.0.0.1", [open_port, closed_port])
        states = {r.port: r.state for r in results}
        assert states[closed_port] == "closed"
        assert states[open_port] == "open"

    def test_banner_grabbing(self, tcp_server):
        open_port = tcp_server
        scanner = PortScanner(protocol="tcp", timeout=1.0, threads=8, grab_banners=True)
        results = scanner.scan_host("127.0.0.1", [open_port])
        assert results[0].state == "open"
        assert "test banner" in results[0].banner


class TestUdpScan:
    @staticmethod
    def _icmp_unreachable(dst_port: int) -> bytes:
        outer_ip = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            28 + 8 + 20 + 8,
            0,
            0,
            64,
            1,
            0,
            socket.inet_aton("127.0.0.1"),
            socket.inet_aton("127.0.0.1"),
        )
        icmp = struct.pack("!BBHI", 3, 3, 0, 0)
        inner_ip = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            28,
            0,
            0,
            64,
            17,
            0,
            socket.inet_aton("127.0.0.1"),
            socket.inet_aton("127.0.0.1"),
        )
        udp = struct.pack("!HHHH", 12345, dst_port, 8, 0)
        return outer_ip + icmp + inner_ip + udp

    def test_icmp_unreachable_parser(self):
        scanner = PortScanner(protocol="udp")
        packet = self._icmp_unreachable(9999)
        assert scanner._is_icmp_port_unreachable(packet, 9999)
        assert not scanner._is_icmp_port_unreachable(packet, 8888)
        assert not scanner._is_icmp_port_unreachable(b"", 9999)

    def test_udp_open_via_response(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind(("127.0.0.1", 0))
        port = server.getsockname()[1]

        def _loop():
            while True:
                data, addr = server.recvfrom(4096)
                if data == b"STOP":
                    break
                server.sendto(b"pong", addr)

        thread = threading.Thread(target=_loop, daemon=True)
        thread.start()
        try:
            scanner = PortScanner(protocol="udp", timeout=1.0, threads=8)
            results = scanner.scan_host("127.0.0.1", [port])
            assert results[0].state == "open"
            assert results[0].banner == "pong"
        finally:
            server.sendto(b"STOP", ("127.0.0.1", port))
            server.close()


class TestRenderers:
    def test_txt(self):
        results = [
            ScanResult("127.0.0.1", 22, "tcp", "open", "ssh"),
            ScanResult("127.0.0.1", 80, "tcp", "closed", "http"),
        ]
        text = render_txt(results)
        assert "127.0.0.1" in text
        assert "ssh" in text
        assert "closed" not in text

    def test_json(self):
        results = [ScanResult("127.0.0.1", 22, "tcp", "open", "ssh")]
        payload = json.loads(render_json(results, meta={"duration_s": 0.1}))
        assert payload["results"][0]["port"] == 22
        assert payload["duration_s"] == 0.1

    def test_csv(self):
        results = [
            ScanResult("127.0.0.1", 22, "tcp", "open", "ssh", banner="hi")
        ]
        rows = render_csv(results).splitlines()
        assert rows[0].startswith("host,port,protocol")
        assert "127.0.0.1,22,tcp,open,ssh" in rows[1]
