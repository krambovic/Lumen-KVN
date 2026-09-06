"""Worker for v2rayN-style speed testing through temporary xray cores."""

from __future__ import annotations

from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from copy import deepcopy
from dataclasses import dataclass
import json
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from urllib.request import ProxyHandler, Request

from PyQt6.QtCore import QThread, pyqtSignal

from .constants import (
    PROXY_HOST,
    SPEED_TEST_DEFAULT_URL,
    SPEED_TEST_DOWNLOAD_IDLE_TIMEOUT,
    SPEED_TEST_MAX_PING_MS,
    SPEED_TEST_MIN_BYTES_AFTER_GRACE,
    SPEED_TEST_MIN_MBPS_AFTER_GRACE,
    SPEED_TEST_MIXED_CONCURRENCY,
    SPEED_TEST_PING_URL,
    SPEED_TEST_PING_TIMEOUT,
    SPEED_TEST_SLOW_GRACE_SECONDS,
    SPEED_TEST_STARTUP_TIMEOUT,
    SPEED_TEST_TIMEOUT,
)
from .http_utils import build_opener
from .models import Node, RoutingSettings
from .ping_worker import _WindowsPingBypass, endpoint_ping
from .xray_fragments import apply_xray_final_fragment


@dataclass(frozen=True)
class _SpeedTestTarget:
    node: Node
    http_port: int


def _resolve_speed_test_concurrency(node_count: int, configured: int) -> int:
    total = max(1, int(node_count or 0))
    requested = int(configured or 0)
    if requested > 0:
        return min(requested, total)
    return min(max(1, SPEED_TEST_MIXED_CONCURRENCY), total)


class SpeedTestWorker(QThread):
    """Tests nodes like v2rayN Mixedtest: ping first, then one speed download."""

    result = pyqtSignal(str, object, bool)   # node_id, speed_mbps (float|None), is_alive
    ping_result = pyqtSignal(str, object)    # node_id, delay_ms (int|None) - режим ping
    progress = pyqtSignal(int, int)          # current, total
    node_progress = pyqtSignal(str, int)     # node_id, percent 0..100
    completed = pyqtSignal()

    def __init__(
        self,
        nodes: list[Node],
        xray_path: str,
        routing: RoutingSettings | None = None,
        timeout: float = SPEED_TEST_TIMEOUT,
        *,
        mode: str = "speed",
        test_url: str = "",
        concurrency: int = 0,
        bypass_tun: bool = False,
    ):
        super().__init__()
        self.setObjectName("lumen-speed-test" if mode == "speed" else "lumen-real-ping")
        self._nodes = list(nodes)
        self._xray_path = xray_path
        self._routing = routing or RoutingSettings()
        self._timeout = timeout
        self._mode = mode if mode in ("speed", "ping") else "speed"
        self._test_url = (test_url or "").strip() or SPEED_TEST_DEFAULT_URL
        self._concurrency = int(concurrency or 0)
        self._bypass_tun = bool(bypass_tun)
        self._cancelled = False
        self._completed_nodes = 0
        self._processes: set[subprocess.Popen] = set()
        self._process_lock = threading.Lock()
        self._responses: list[object] = []
        self._response_lock = threading.Lock()

    def cancel(self) -> None:
        # Called from the GUI thread: only signal and release, never wait —
        # run()'s finally does the kill escalation on the worker thread.
        self._cancelled = True
        with self._response_lock:
            responses = list(self._responses)
        for response in responses:
            try:
                response.close()
            except Exception:
                pass
        self._terminate_all_processes(wait=False)

    def _terminate_all_processes(self, *, wait: bool = True) -> None:
        with self._process_lock:
            processes = list(self._processes)
        for proc in processes:
            if proc.poll() is None:
                try:
                    proc.terminate()
                except Exception:
                    pass
        if not wait:
            return
        deadline = time.monotonic() + 1.0
        while time.monotonic() < deadline and any(proc.poll() is None for proc in processes):
            time.sleep(0.05)
        for proc in processes:
            if proc.poll() is None:
                try:
                    proc.kill()
                except Exception:
                    pass

    @property
    def completed_nodes(self) -> int:
        return self._completed_nodes

    @property
    def was_cancelled(self) -> bool:
        return self._cancelled

    def run(self) -> None:
        total = len(self._nodes)
        self._completed_nodes = 0
        try:
            needs_core = any(not self._uses_direct_ping_fallback(node) for node in self._nodes)
            if needs_core and not Path(self._xray_path).is_file():
                for node in self._nodes:
                    if self._cancelled:
                        break
                    self._emit_node_result(node, None, False, total)
                return

            for node in self._nodes:
                self.node_progress.emit(node.id, 0)

            max_workers = _resolve_speed_test_concurrency(len(self._nodes), self._concurrency)
            with _WindowsPingBypass(self._bypass_targets(), self._bypass_tun) as bypass:
                self._bypass = bypass
                executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="speed-test")
                pending: set[Future[tuple[Node, float | None, bool]]] = set()
                iterator = iter(self._nodes)
                exhausted = False

                def fill_pending_slots() -> None:
                    nonlocal exhausted
                    while len(pending) < max_workers and not exhausted and not self._cancelled:
                        node = next(iterator, None)
                        if node is None:
                            exhausted = True
                            break
                        pending.add(executor.submit(self._test_node, node))

                try:
                    fill_pending_slots()
                    while (pending or not exhausted) and not self._cancelled:
                        if not pending:
                            fill_pending_slots()
                            if not pending:
                                break
                        done, _ = wait(pending, timeout=0.2, return_when=FIRST_COMPLETED)
                        if not done:
                            continue
                        for future in done:
                            pending.discard(future)
                            if self._cancelled:
                                break
                            try:
                                node, speed, alive = future.result()
                            except Exception:
                                continue
                            self._emit_node_result(node, speed, alive, total)
                            fill_pending_slots()
                finally:
                    if self._cancelled:
                        for future in pending:
                            future.cancel()
                    executor.shutdown(wait=True, cancel_futures=True)
        finally:
            self._terminate_all_processes()
            self.completed.emit()

    def _emit_node_result(self, node: Node, value: float | None, alive: bool, total: int) -> None:
        self._completed_nodes += 1
        self.node_progress.emit(node.id, 100)
        if self._mode == "ping":
            delay = int(value) if (value is not None and value > 0) else None
            self.ping_result.emit(node.id, delay)
        else:
            self.result.emit(node.id, value, alive)
        self.progress.emit(self._completed_nodes, total)

    def _bypass_targets(self) -> list[Node]:
        targets = list(self._nodes)
        for node in self._nodes:
            outbound = node.outbound if isinstance(node.outbound, dict) else {}
            full_config = outbound.get("xray_config")
            if str(outbound.get("protocol") or "").strip().lower() != "xray_config" or not isinstance(full_config, dict):
                continue
            for candidate in full_config.get("outbounds", []):
                if not isinstance(candidate, dict):
                    continue
                host = self._xray_outbound_host(candidate)
                if not host:
                    continue
                target = deepcopy(node)
                target.server = host
                targets.append(target)
        return targets

    def _test_node(self, node: Node) -> tuple[Node, float | None, bool]:
        if self._mode == "ping" and self._uses_direct_ping_fallback(node):
            protocol = self._node_protocol(node)
            target = node.server
            bypass = getattr(self, "_bypass", None)
            if bypass is not None:
                direct = bypass.direct_ip(node.server)
                if direct:
                    target = direct
            method = "http" if protocol not in {"hysteria", "hysteria2", "hy", "hy2"} else "real"
            delay = endpoint_ping(target, node.port, protocol, method, self._timeout)
            return node, float(delay or 0), delay is not None

        reservation: socket.socket | None = None
        tmp = None
        proc = None

        try:
            port, reservation = self._reserve_port()
            target = _SpeedTestTarget(node=node, http_port=port)
            config = self._build_config(target)
            tmp = tempfile.NamedTemporaryFile(
                mode="w",
                suffix=".json",
                prefix="xray_speed_",
                delete=False,
                encoding="utf-8",
            )
            json.dump(config, tmp, ensure_ascii=True)
            tmp.close()

            self._close_reserved_ports([reservation])
            reservation = None

            proc = subprocess.Popen(
                [self._xray_path, "run", "-c", tmp.name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=0x08000000,  # CREATE_NO_WINDOW
            )
            self._register_process(proc)

            if not self._wait_for_ready(proc, target):
                return node, None, False

            delay_ms = self._real_ping(target)
            if self._cancelled:
                return node, None, False
            if delay_ms <= 0:
                return node, None, False

            if self._mode == "ping":
                # Режим реальной задержки: только ping, без загрузки.
                return node, float(delay_ms), True

            self.node_progress.emit(node.id, 35)
            speed = self._measure_speed(target)
            return node, speed, bool(speed and speed > 0)

        except Exception:
            return node, None, False

        finally:
            if reservation is not None:
                self._close_reserved_ports([reservation])
            if proc is not None:
                # Keep the PID visible as Lumen-owned until the temporary core
                # has really exited. Otherwise conflict scanning can briefly
                # report our own test process as a foreign Xray instance.
                try:
                    self._stop_process(proc)
                finally:
                    self._unregister_process(proc)
            if tmp:
                try:
                    Path(tmp.name).unlink(missing_ok=True)
                except Exception:
                    pass

    @staticmethod
    def _node_protocol(node: Node) -> str:
        outbound = node.outbound if isinstance(node.outbound, dict) else {}
        return str(outbound.get("protocol") or outbound.get("type") or node.scheme or "").strip().lower()

    @classmethod
    def _uses_direct_ping_fallback(cls, node: Node) -> bool:
        return cls._node_protocol(node) in {
            "awg", "wireguard", "warp", "hysteria", "hysteria2", "hy", "hy2",
            "tuic", "masque", "openvpn", "mieru", "naive", "anytls", "snell",
            "singbox_config",
        }

    def _apply_direct_ip_to_outbound(self, outbound: dict, host: str) -> None:
        # While TUN is up, point the temp xray outbound at the server's real
        # IP (resolved directly, bypassing fake-ip) so its connection follows
        # the temporary direct host route instead of being tunneled. TLS SNI /
        # host live in streamSettings and are left untouched.
        bypass = getattr(self, "_bypass", None)
        if bypass is None:
            return
        host = str(host or "").strip()
        ip = bypass.direct_ip(host)
        if not ip or ip == host:
            return
        settings = outbound.get("settings")
        if not isinstance(settings, dict):
            return
        for key in ("vnext", "servers"):
            entries = settings.get(key)
            if not isinstance(entries, list):
                continue
            for entry in entries:
                if isinstance(entry, dict) and entry.get("address"):
                    entry["address"] = ip

    def _build_config(self, target: _SpeedTestTarget) -> dict:
        inbound_tag = "speed-http"
        outbound_tag = "speed-proxy"
        stored_outbound = target.node.outbound if isinstance(target.node.outbound, dict) else {}
        full_config = stored_outbound.get("xray_config")
        if str(stored_outbound.get("protocol") or "").strip().lower() == "xray_config" and isinstance(full_config, dict):
            return self._build_auto_config(target, full_config, inbound_tag)
        proxy_outbound = deepcopy(target.node.outbound)
        proxy_outbound["tag"] = outbound_tag
        self._apply_direct_ip_to_outbound(proxy_outbound, target.node.server)

        config = {
            "log": {"loglevel": "none"},
            "inbounds": [
                {
                    "tag": inbound_tag,
                    "listen": PROXY_HOST,
                    "port": int(target.http_port),
                    "protocol": "http",
                    "settings": {},
                    "sniffing": {
                        "enabled": True,
                        "destOverride": ["http", "tls"],
                        "routeOnly": False,
                    },
                }
            ],
            "outbounds": [
                proxy_outbound,
                {"tag": "direct", "protocol": "freedom", "settings": {}},
                {"tag": "block", "protocol": "blackhole", "settings": {}},
            ],
            "routing": {
                "domainStrategy": "AsIs",
                "rules": [
                    {
                        "type": "field",
                        "inboundTag": [inbound_tag],
                        "outboundTag": outbound_tag,
                    }
                ],
            },
        }
        apply_xray_final_fragment(config, tag_prefix=outbound_tag)
        return config

    def _build_auto_config(self, target: _SpeedTestTarget, full_config: dict, inbound_tag: str) -> dict:
        """Build a temporary HTTP inbound while preserving AUTO balancer/observer."""
        config = deepcopy(full_config)
        config["log"] = {"loglevel": "none"}
        config["inbounds"] = [
            {
                "tag": inbound_tag,
                "listen": PROXY_HOST,
                "port": int(target.http_port),
                "protocol": "http",
                "settings": {},
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls"],
                    "routeOnly": False,
                },
            }
        ]
        config.pop("api", None)
        config.pop("stats", None)
        config.pop("policy", None)

        routing = config.get("routing")
        if not isinstance(routing, dict):
            routing = {}
            config["routing"] = routing
        balancer_tag = ""
        rules = routing.get("rules") if isinstance(routing.get("rules"), list) else []
        for rule in rules:
            if isinstance(rule, dict) and str(rule.get("balancerTag") or "").strip():
                balancer_tag = str(rule["balancerTag"]).strip()
                break
        if not balancer_tag:
            balancers = routing.get("balancers") if isinstance(routing.get("balancers"), list) else []
            for balancer in balancers:
                if isinstance(balancer, dict) and str(balancer.get("tag") or "").strip():
                    balancer_tag = str(balancer["tag"]).strip()
                    break
        if not balancer_tag:
            raise ValueError("AUTO profile has no balancer tag")
        routing["rules"] = [
            {
                "type": "field",
                "inboundTag": [inbound_tag],
                "balancerTag": balancer_tag,
            }
        ]

        outbounds = config.get("outbounds") if isinstance(config.get("outbounds"), list) else []
        for outbound in outbounds:
            if not isinstance(outbound, dict):
                continue
            host = self._xray_outbound_host(outbound)
            self._apply_direct_ip_to_outbound(outbound, host)
        return config

    @staticmethod
    def _xray_outbound_host(outbound: dict) -> str:
        settings = outbound.get("settings") if isinstance(outbound.get("settings"), dict) else {}
        for key in ("vnext", "servers"):
            entries = settings.get(key)
            if isinstance(entries, list) and entries and isinstance(entries[0], dict):
                return str(entries[0].get("address") or entries[0].get("server") or "").strip()
        return str(settings.get("address") or settings.get("server") or outbound.get("address") or "").strip()

    def _real_ping(self, target: _SpeedTestTarget) -> int:
        if self._cancelled:
            return -1
        opener = self._build_proxy_opener(target.http_port)
        req = Request(SPEED_TEST_PING_URL, headers={"User-Agent": "Lumen/SpeedTest"})
        self.node_progress.emit(target.node.id, 20)
        started = time.perf_counter()
        try:
            with opener.open(req, timeout=min(self._timeout, SPEED_TEST_PING_TIMEOUT)) as resp:
                self._register_response(resp)
                try:
                    resp.read(16)
                finally:
                    self._unregister_response(resp)
            elapsed_ms = int((time.perf_counter() - started) * 1000)
            if elapsed_ms > SPEED_TEST_MAX_PING_MS:
                return -1
            self.node_progress.emit(target.node.id, 30)
            return max(1, elapsed_ms)
        except Exception:
            return -1

    def _measure_speed(self, target: _SpeedTestTarget) -> float | None:
        opener = self._build_proxy_opener(target.http_port)
        req = Request(self._test_url, headers={"User-Agent": "Lumen/SpeedTest"})

        try:
            started = time.perf_counter()
            last_update = started
            total_bytes = 0
            window_bytes = 0
            max_speed = 0.0

            idle_timeout = min(self._timeout, SPEED_TEST_DOWNLOAD_IDLE_TIMEOUT)
            with opener.open(req, timeout=idle_timeout) as resp:
                self._register_response(resp)
                try:
                    while not self._cancelled:
                        chunk = resp.read(64 * 1024)
                        now = time.perf_counter()
                        if not chunk:
                            break

                        total_bytes += len(chunk)
                        window_bytes += len(chunk)
                        elapsed = now - started
                        if elapsed >= self._timeout:
                            break
                        if (
                            elapsed >= SPEED_TEST_SLOW_GRACE_SECONDS
                            and total_bytes < SPEED_TEST_MIN_BYTES_AFTER_GRACE
                        ):
                            return None

                        window_elapsed = now - last_update
                        if window_elapsed >= 1.0:
                            speed = (window_bytes / (1000 * 1000)) / max(window_elapsed, 0.001)
                            max_speed = max(max_speed, speed)
                            if (
                                elapsed >= SPEED_TEST_SLOW_GRACE_SECONDS
                                and max_speed < SPEED_TEST_MIN_MBPS_AFTER_GRACE
                            ):
                                return None
                            window_bytes = 0
                            last_update = now
                            percent = 35 + int(60 * min(1.0, elapsed / max(self._timeout, 0.1)))
                            self.node_progress.emit(target.node.id, max(35, min(95, percent)))
                finally:
                    self._unregister_response(resp)

            elapsed_total = time.perf_counter() - started
            if window_bytes > 0:
                speed = (window_bytes / (1000 * 1000)) / max(time.perf_counter() - last_update, 0.001)
                max_speed = max(max_speed, speed)

            if total_bytes <= 0 or elapsed_total <= 0:
                return None

            if max_speed <= 0:
                max_speed = (total_bytes / (1000 * 1000)) / elapsed_total

            self.node_progress.emit(target.node.id, 95)
            return round(max_speed, 1)

        except Exception:
            return None

    def _wait_for_ready(self, proc: subprocess.Popen, target: _SpeedTestTarget) -> bool:
        deadline = time.perf_counter() + SPEED_TEST_STARTUP_TIMEOUT
        while time.perf_counter() < deadline:
            if self._cancelled:
                return False
            if proc.poll() is not None:
                return False
            if self._is_port_ready(target.http_port):
                self.node_progress.emit(target.node.id, 10)
                return True
            time.sleep(0.05)
        return False

    @staticmethod
    def _build_proxy_opener(http_port: int):
        proxy_url = f"http://{PROXY_HOST}:{http_port}"
        return build_opener(ProxyHandler({"http": proxy_url, "https": proxy_url}))

    def _register_process(self, proc: subprocess.Popen) -> None:
        with self._process_lock:
            self._processes.add(proc)

    def _unregister_process(self, proc: subprocess.Popen) -> None:
        with self._process_lock:
            self._processes.discard(proc)

    def _register_response(self, response: object) -> None:
        with self._response_lock:
            self._responses.append(response)

    def _unregister_response(self, response: object) -> None:
        with self._response_lock:
            self._responses = [item for item in self._responses if item is not response]

    @staticmethod
    def _stop_process(proc: subprocess.Popen) -> None:
        if proc.poll() is not None:
            return
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            try:
                proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass

    def _reserve_port(self) -> tuple[int, socket.socket]:
        sockets: list[socket.socket] = []
        try:
            ports, sockets = self._reserve_ports(1)
            return ports[0], sockets[0]
        except Exception:
            self._close_reserved_ports(sockets)
            raise

    def _reserve_ports(self, count: int) -> tuple[list[int], list[socket.socket]]:
        sockets: list[socket.socket] = []
        ports: list[int] = []
        try:
            for _ in range(count):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.bind((PROXY_HOST, 0))
                sockets.append(sock)
                ports.append(int(sock.getsockname()[1]))
        except Exception:
            self._close_reserved_ports(sockets)
            raise
        return ports, sockets

    @staticmethod
    def _close_reserved_ports(sockets: list[socket.socket]) -> None:
        while sockets:
            sock = sockets.pop()
            try:
                sock.close()
            except Exception:
                pass

    @staticmethod
    def _is_port_ready(port: int) -> bool:
        try:
            with socket.create_connection((PROXY_HOST, port), timeout=0.1):
                return True
        except OSError:
            return False
