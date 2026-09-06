from __future__ import annotations

import re
import socket
import os
import threading
import time
from urllib.request import Request, urlopen
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait

from PyQt6.QtCore import QThread, pyqtSignal

from .constants import ICMP_PING_TIMEOUT_MS
from .models import Node
from .subprocess_utils import CREATE_NO_WINDOW, result_output_text, run_text_pumped


_MAX_PING_WORKERS = 16

_ICMP_TIME_RE = re.compile(r"[=<]\s*(\d+(?:[.,]\d+)?)\s*ms", re.IGNORECASE)


def tcp_ping(host: str, port: int, timeout: float = 2.0) -> int | None:
    if not host or not port:
        return None
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            elapsed = (time.perf_counter() - start) * 1000.0
            return int(elapsed)
    except OSError:
        return None


def udp_ping(host: str, port: int, timeout: float = 2.0) -> int | None:
    """Measure a UDP endpoint without assuming a TCP listener.

    Hysteria/Hysteria2 use QUIC over UDP.  A tiny datagram is enough to make
    the OS perform the endpoint reachability check; when the peer answers (or
    reports an ICMP error) we return the elapsed time.  Some servers silently
    drop unknown datagrams, in which case the caller can use ICMP as fallback.
    """
    if not host or not port:
        return None
    start = time.perf_counter()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.connect((host, port))
            sock.send(b"\x00")
            try:
                sock.recv(1)
            except socket.timeout:
                return None
        return int((time.perf_counter() - start) * 1000.0)
    except OSError:
        return None


def hysteria_ping(host: str, port: int, timeout: float = 2.0) -> int | None:
    """Ping a Hysteria endpoint using its UDP transport.

    UDP probes are intentionally followed by ICMP: Hysteria servers commonly
    ignore non-QUIC datagrams, while ICMP still provides a useful endpoint
    latency measurement without starting sing-box or a proxy session.
    """
    measured = udp_ping(host, port, timeout)
    if measured is not None:
        return measured
    return icmp_ping(host, int(timeout * 1000))


def http_get_ping(host: str, port: int, timeout: float = 3.0) -> int | None:
    """Measure an endpoint with a direct HTTP(S) GET, without a proxy core."""
    if not host or not port:
        return None
    for scheme in ("https", "http"):
        started = time.perf_counter()
        try:
            request = Request(f"{scheme}://{host}:{int(port)}/", method="GET")
            with urlopen(request, timeout=timeout) as response:
                response.read(1)
            return int((time.perf_counter() - started) * 1000.0)
        except Exception:
            continue
    return None


def endpoint_ping(host: str, port: int, protocol: str, method: str, timeout: float) -> int | None:
    """Best-effort transport ping for protocols without an Xray test adapter."""
    if method == "icmp":
        return icmp_ping(host, int(timeout * 1000))
    if method == "http":
        return http_get_ping(host, port, timeout) or icmp_ping(host, int(timeout * 1000))
    if protocol in {"hysteria", "hysteria2", "hy", "hy2", "tuic", "awg", "wireguard", "warp", "masque"}:
        return hysteria_ping(host, port, timeout)
    return tcp_ping(host, port, timeout)


def icmp_ping(host: str, timeout_ms: int = ICMP_PING_TIMEOUT_MS) -> int | None:
    """Системный ICMP ping (один пакет). Возвращает задержку в мс или None."""
    host = str(host or "").strip()
    if not host:
        return None
    timeout_ms = max(200, int(timeout_ms or ICMP_PING_TIMEOUT_MS))
    if os.name == "nt":
        command = ["ping", "-n", "1", "-w", str(timeout_ms), host]
    else:
        timeout_sec = max(1, int(round(timeout_ms / 1000.0)))
        command = ["ping", "-c", "1", "-W", str(timeout_sec), host]
    try:
        result = run_text_pumped(
            command,
            timeout=max(2.0, timeout_ms / 1000.0 + 1.0),
            creationflags=CREATE_NO_WINDOW,
        )
    except Exception:
        return None
    if result.returncode != 0:
        return None
    text = result_output_text(result)
    match = _ICMP_TIME_RE.search(text)
    if not match:
        return None
    try:
        return int(round(float(match.group(1).replace(",", "."))))
    except ValueError:
        return None


def _is_ipv4_address(value: str) -> bool:
    try:
        socket.inet_aton(value)
    except OSError:
        return False
    return value.count(".") == 3


def _resolve_ipv4(host: str) -> str:
    if _is_ipv4_address(host):
        return host
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
    except OSError:
        return ""
    for info in infos:
        sockaddr = info[4]
        if sockaddr:
            ip = str(sockaddr[0])
            if _is_ipv4_address(ip):
                return ip
    return ""


def _detect_direct_gateway() -> str:
    if os.name != "nt":
        return ""
    script = (
        "$routes = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue "
        "| Where-Object { $_.NextHop -and $_.NextHop -ne '0.0.0.0' } "
        "| Sort-Object RouteMetric, InterfaceMetric; "
        "$route = $routes | Where-Object { "
        "$alias = [string]$_.InterfaceAlias; "
        "$alias -notmatch '(?i)lumen|xftun|wintun|tun' "
        "} | Select-Object -First 1; "
        "if (-not $route) { $route = $routes | Select-Object -First 1 }; "
        "if (-not $route) { exit 1 }; "
        "$route.NextHop"
    )
    try:
        result = run_text_pumped(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            timeout=6,
            creationflags=CREATE_NO_WINDOW,
        )
    except Exception:
        return ""
    if result.returncode != 0:
        return ""
    gateway = result_output_text(result).strip().splitlines()
    return gateway[0].strip() if gateway else ""


def _looks_like_tun_gateway(gateway: str) -> bool:
    return gateway.startswith(("172.18.", "172.19.", "198.18.", "198.19."))


def _has_direct_host_route(ip: str, gateway: str) -> bool:
    if os.name != "nt" or not ip or not gateway:
        return False
    script = (
        f"$routes = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '{ip}/32' -ErrorAction SilentlyContinue; "
        f"$route = $routes | Where-Object {{ $_.NextHop -eq '{gateway}' }} | Select-Object -First 1; "
        "if ($route) { exit 0 } else { exit 1 }"
    )
    try:
        result = run_text_pumped(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            timeout=3,
            creationflags=CREATE_NO_WINDOW,
        )
    except Exception:
        return False
    return result.returncode == 0


_DIRECT_DNS_SERVERS = ("8.8.8.8", "1.1.1.1", "9.9.9.9")


def _looks_like_fake_ip(ip: str) -> bool:
    # sing-box fake-ip pool (198.18.0.0/15) and the TUN subnet must never be
    # used as a real ping target or host route destination.
    return ip.startswith(("198.18.", "198.19.", "172.18.", "172.19."))


def _skip_dns_name(data: bytes, idx: int) -> int:
    while True:
        length = data[idx]
        if length == 0:
            return idx + 1
        if length & 0xC0 == 0xC0:
            return idx + 2
        idx += length + 1


def _direct_dns_resolve_a(domain: str, dns_server: str, timeout: float = 3.0) -> str:
    """Resolve an A record by querying dns_server directly over UDP.

    While the TUN is up, this is paired with a temporary host route to
    dns_server via the physical gateway, so the query bypasses sing-box DNS
    hijacking / fake-ip and returns the real public IP.
    """
    import struct

    try:
        header = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        qname = b"".join(
            bytes([len(label)]) + label.encode("ascii")
            for label in domain.rstrip(".").split(".")
            if label
        ) + b"\x00"
        packet = header + qname + struct.pack(">HH", 1, 1)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(packet, (dns_server, 53))
            data, _ = sock.recvfrom(2048)
    except Exception:
        return ""
    try:
        ancount = struct.unpack(">H", data[6:8])[0]
        if ancount <= 0:
            return ""
        idx = _skip_dns_name(data, 12) + 4  # question name + qtype/qclass
        for _ in range(ancount):
            idx = _skip_dns_name(data, idx)
            rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", data[idx:idx + 10])
            idx += 10
            if rtype == 1 and rdlen == 4:
                return ".".join(str(b) for b in data[idx:idx + 4])
            idx += rdlen
    except Exception:
        return ""
    return ""


# A ping run and a speed test can hold a bypass at the same time, so temporary
# host routes are refcounted process-wide: an IP is only deleted once the last
# holder releases it.
_ROUTE_REFS_LOCK = threading.Lock()
_ROUTE_REFS: dict[tuple[str, str], int] = {}


class _WindowsPingBypass:
    def __init__(self, nodes: list[Node], enabled: bool):
        self._nodes = nodes
        self._enabled = bool(enabled and os.name == "nt")
        self._gateway = ""
        self._added_ips: set[str] = set()
        self._dns_routes: set[str] = set()
        self._covered_ips: set[str] = set()
        self._host_ips: dict[str, str] = {}

    def _route_add(self, ip: str) -> bool:
        try:
            result = run_text_pumped(
                ["route", "add", ip, "mask", "255.255.255.255", self._gateway, "metric", "1"],
                timeout=4,
                creationflags=CREATE_NO_WINDOW,
            )
        except Exception:
            return False
        if result.returncode == 0:
            return True
        return _has_direct_host_route(ip, self._gateway)

    def _acquire_route(self, ip: str) -> bool:
        key = (self._gateway, ip)
        with _ROUTE_REFS_LOCK:
            refs = _ROUTE_REFS.get(key, 0)
            if refs <= 0:
                if not self._route_add(ip):
                    return False
                _ROUTE_REFS[key] = 1
                return True
            _ROUTE_REFS[key] = refs + 1
            return True

    def _release_route(self, ip: str) -> None:
        key = (self._gateway, ip)
        with _ROUTE_REFS_LOCK:
            refs = _ROUTE_REFS.get(key, 0)
            if refs > 1:
                _ROUTE_REFS[key] = refs - 1
                return
            _ROUTE_REFS.pop(key, None)
            self._route_delete(ip)

    def _route_delete(self, ip: str) -> None:
        try:
            run_text_pumped(
                ["route", "delete", ip, "mask", "255.255.255.255", self._gateway],
                timeout=4,
                creationflags=CREATE_NO_WINDOW,
            )
        except Exception:
            pass

    def _resolve_real_ip(self, host: str) -> str:
        if _is_ipv4_address(host):
            return host
        for dns_server in _DIRECT_DNS_SERVERS:
            if dns_server not in self._dns_routes:
                continue
            ip = _direct_dns_resolve_a(host, dns_server)
            if ip and _is_ipv4_address(ip) and not _looks_like_fake_ip(ip):
                return ip
        # Fallback: system resolver (may be hijacked to a fake-ip while TUN is up).
        ip = _resolve_ipv4(host)
        if ip and not _looks_like_fake_ip(ip):
            return ip
        return ""

    def __enter__(self):
        if not self._enabled:
            return self
        self._gateway = _detect_direct_gateway()
        if not self._gateway or _looks_like_tun_gateway(self._gateway):
            return self

        # Route the public resolvers directly so DNS lookups bypass the TUN
        # (and sing-box fake-ip) while we resolve the real server addresses.
        for dns_server in _DIRECT_DNS_SERVERS:
            if self._acquire_route(dns_server):
                self._added_ips.add(dns_server)
                self._dns_routes.add(dns_server)

        ips: set[str] = set()
        for node in self._nodes:
            host = str(node.server or "").strip()
            if not host or host in self._host_ips:
                continue
            ip = self._resolve_real_ip(host)
            if ip and not ip.startswith(("127.", "0.", "169.254.")):
                self._host_ips[host] = ip
                ips.add(ip)

        for ip in ips:
            if ip in self._added_ips or ip in self._covered_ips:
                self._covered_ips.add(ip)
                continue
            if self._acquire_route(ip):
                self._added_ips.add(ip)
                self._covered_ips.add(ip)
        return self

    def direct_ip(self, host: str) -> str:
        host = str(host or "").strip()
        if not self._enabled:
            return host
        return self._host_ips.get(host, "")

    def can_ping_direct(self, host: str) -> bool:
        if not self._enabled:
            return True
        ip = self._host_ips.get(str(host or "").strip())
        return bool(ip and ip in self._covered_ips)

    def __exit__(self, *_exc) -> None:
        for ip in self._added_ips:
            self._release_route(ip)
        self._added_ips.clear()
        self._dns_routes.clear()
        self._covered_ips.clear()
        self._host_ips.clear()


class PingWorker(QThread):
    result = pyqtSignal(str, object)
    progress = pyqtSignal(int, int)  # current, total
    completed = pyqtSignal()

    def __init__(
        self,
        nodes: list[Node],
        timeout: float = 2.0,
        *,
        bypass_tun: bool = False,
        method: str = "tcping",
    ):
        super().__init__()
        self.setObjectName("lumen-ping-worker")
        self._nodes = nodes
        self._timeout = timeout
        self._bypass_tun = bypass_tun
        self._method = method if method in ("tcping", "icmp", "http", "real") else "tcping"
        self._cancelled = False

    def _measure(self, node: Node) -> int | None:
        target = node.server
        bypass = getattr(self, "_bypass", None)
        if bypass is not None:
            direct = bypass.direct_ip(node.server)
            if direct:
                target = direct
        if self._method == "icmp":
            return icmp_ping(target, int(self._timeout * 1000))
        outbound = node.outbound if isinstance(node.outbound, dict) else {}
        protocol = str(
            outbound.get("protocol")
            or outbound.get("type")
            or node.scheme
            or ""
        ).strip().lower()
        if protocol in {"hysteria", "hysteria2", "hy", "hy2"}:
            return hysteria_ping(target, node.port, self._timeout)
        if self._method in {"http", "real"}:
            return endpoint_ping(target, node.port, protocol, self._method, self._timeout)
        return tcp_ping(target, node.port, self._timeout)

    def cancel(self) -> None:
        self._cancelled = True

    def run(self) -> None:
        total = len(self._nodes)
        if total == 0:
            self.completed.emit()
            return

        max_workers = min(_MAX_PING_WORKERS, total)
        executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="ping")
        pending: dict[Future[int | None], str] = {}
        iterator = iter(self._nodes)
        exhausted = False
        completed = 0

        bypass = _WindowsPingBypass(self._nodes, self._bypass_tun)
        self._bypass = bypass

        def submit_node(node: Node) -> None:
            nonlocal completed
            if not bypass.can_ping_direct(node.server):
                completed += 1
                self.result.emit(node.id, None)
                self.progress.emit(completed, total)
                return
            future = executor.submit(self._measure, node)
            pending[future] = node.id

        def fill_pending_slots() -> None:
            nonlocal exhausted
            while len(pending) < max_workers and not exhausted and not self._cancelled:
                node = next(iterator, None)
                if node is None:
                    exhausted = True
                    break
                submit_node(node)

        try:
            bypass.__enter__()
            fill_pending_slots()

            while (pending or not exhausted) and not self._cancelled:
                if not pending:
                    fill_pending_slots()
                    if not pending:
                        break
                done, _ = wait(tuple(pending), timeout=0.1, return_when=FIRST_COMPLETED)
                if not done:
                    continue

                for future in done:
                    node_id = pending.pop(future)
                    try:
                        ms = future.result()
                    except Exception:
                        ms = None

                    completed += 1
                    self.result.emit(node_id, ms)
                    self.progress.emit(completed, total)

                    if self._cancelled:
                        break

                    fill_pending_slots()

            if self._cancelled:
                for future in pending:
                    future.cancel()
        finally:
            # No measurement may outlive its direct host route.
            executor.shutdown(wait=True, cancel_futures=True)
            bypass.__exit__(None, None, None)

        self.completed.emit()
