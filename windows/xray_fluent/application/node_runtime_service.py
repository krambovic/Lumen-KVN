from __future__ import annotations

from typing import TYPE_CHECKING

from ..country_flags import CountryResolver, detect_country
from ..link_parser import normalize_node_outbound, repair_node_outbound_from_link, validate_node_outbound
from ..qthread_utils import bind_thread_reference

if TYPE_CHECKING:
    from ..app_controller import AppController
    from ..models import Node


def detect_countries_sync(controller: AppController) -> bool:
    changed = False
    for node in controller.state.nodes:
        if not node.country_code:
            code = detect_country(node.name, node.server)
            if code:
                node.country_code = code
                changed = True
    if changed:
        controller.schedule_save()
    return changed


def start_country_ip_resolution(controller: AppController) -> None:
    needs = [(node.id, node.server) for node in controller.state.nodes if not node.country_code]
    if not needs:
        return
    current = controller._country_resolver
    if current is not None and current.isRunning():
        return
    worker = CountryResolver(needs)
    controller._country_resolver = worker
    bind_thread_reference(controller, "_country_resolver", worker)
    worker.resolved.connect(controller._on_countries_resolved)
    worker.start()


def on_countries_resolved(controller: AppController, results: dict[str, str]) -> None:
    if not results:
        return
    for node in controller.state.nodes:
        if node.id in results:
            node.country_code = results[node.id]
    controller.save()
    controller.nodes_changed.emit(controller.state.nodes)


def get_node_by_id(controller: AppController, node_id: str | None) -> Node | None:
    if not node_id:
        return None
    for node in controller.state.nodes:
        if node.id == node_id:
            return node
    return None


def is_native_singbox_only_node(node: Node | None) -> bool:
    outbound = node.outbound if node is not None else None
    if not isinstance(outbound, dict):
        return False
    protocol = str(outbound.get("protocol") or node.scheme or "").strip().lower()
    if protocol in {"warp", "wireguard", "awg", "hysteria", "hysteria2", "tuic", "mieru", "masque", "openvpn", "naive", "singbox_config"}:
        return True
    return isinstance(outbound.get("singbox"), dict) and protocol not in {
        "vless",
        "vmess",
        "trojan",
        "shadowsocks",
        "socks",
        "http",
    }


def is_xray_exclusive_node(node: Node | None) -> bool:
    """Return True only for nodes that require the Xray runtime."""
    outbound = node.outbound if node is not None else None
    if not isinstance(outbound, dict):
        return False

    protocol = str(outbound.get("protocol") or node.scheme or "").strip().lower()
    if protocol == "xray_config":
        return True

    stream_settings = outbound.get("streamSettings")
    if not isinstance(stream_settings, dict):
        return False

    # Never silently discard Xray-only semantics.  These options have no
    # equivalent in the exact bundled sing-box-extended schema.  Running such
    # a node as an approximate native outbound is worse than using the Xray
    # core/sidecar because the config starts successfully but cannot connect.
    if "finalmask" in stream_settings:
        return True

    network = str(stream_settings.get("network") or "tcp").strip().lower()
    security = str(stream_settings.get("security") or "none").strip().lower()
    if network not in {
        "tcp", "raw", "ws", "http", "h2", "grpc", "xhttp",
        "httpupgrade", "quic", "kcp", "mkcp",
    }:
        return True
    if protocol in {"shadowsocks", "socks"} and (
        network not in {"tcp", "raw"} or security in {"tls", "reality"}
    ):
        return True
    if protocol == "http" and network not in {"tcp", "raw"}:
        return True
    if network == "quic":
        return True

    if network == "grpc":
        grpc = stream_settings.get("grpcSettings")
        if isinstance(grpc, dict) and (
            str(grpc.get("authority") or "").strip()
            or bool(grpc.get("multiMode", grpc.get("multi_mode", False)))
        ):
            return True

    if network == "httpupgrade":
        settings = stream_settings.get("httpupgradeSettings")
        if isinstance(settings, dict):
            path = str(settings.get("path") or "").lower()
            if str(settings.get("ed") or "").strip() or "?ed=" in path:
                return True

    tls = stream_settings.get("tlsSettings")
    if isinstance(tls, dict):
        if str(tls.get("verifyPeerCertByName") or "").strip():
            return True
        if not _singbox_utls_fingerprint_supported(tls.get("fingerprint")):
            return True

    reality = stream_settings.get("realitySettings")
    if isinstance(reality, dict):
        if not _singbox_utls_fingerprint_supported(reality.get("fingerprint")):
            return True
        if str(
            reality.get("mldsa65Verify")
            or reality.get("mldsa65_verify")
            or ""
        ).strip():
            return True
        spider_x = str(
            reality.get("spiderX") or reality.get("spider_x") or ""
        ).strip()
        if spider_x and spider_x != "/":
            return True

    return False


def _singbox_utls_fingerprint_supported(value: object) -> bool:
    compact = str(value or "").strip().lower().replace("_", "-")
    if not compact:
        return True
    if compact in {
        "chrome-psk", "chrome-psk-shuffle", "chrome-padding-psk-shuffle",
        "chrome-pq", "chrome-pq-psk",
    }:
        return True
    if compact.startswith(
        ("chrome", "firefox", "edge", "safari", "ios", "android", "qq", "360", "random")
    ):
        return True
    return False


def proxy_core_for_node(node: Node | None) -> str:
    """Use sing-box for hot-switchable proxy sessions and Xray only when required."""
    # With no selected node, system-proxy mode can still run an active raw Xray
    # document.  Every representable node stays on sing-box so the Clash
    # selector can switch it without restarting the core in proxy and TUN mode.
    if node is None or is_xray_exclusive_node(node):
        return "xray"
    return "singbox"


def native_singbox_only_message(node: Node | None = None) -> str:
    name = (node.name or node.server) if node is not None else "Этот сервер"
    return (
        f"{name} не поддерживается ядром Xray. "
        "Используйте автоматический выбор ядра: Lumen запустит этот сервер через sing-box extended "
        "как в системном прокси, так и в TUN."
    )


def prepare_node_for_runtime(controller: AppController, node: Node | None) -> str | None:
    if node is None:
        return None
    changed = repair_node_outbound_from_link(node)
    changed = normalize_node_outbound(node) or changed
    if changed:
        controller.schedule_save()
    return validate_node_outbound(node)


def get_fastest_alive_node(controller: AppController) -> Node | None:
    alive_nodes = [node for node in controller.state.nodes if node.is_alive is True]
    if not alive_nodes:
        alive_nodes = [node for node in controller.state.nodes if node.ping_ms is not None]
    if not alive_nodes:
        return controller.selected_node
    with_speed = [node for node in alive_nodes if node.speed_mbps is not None and node.speed_mbps > 0]
    if with_speed:
        return max(with_speed, key=lambda node: node.speed_mbps)
    return min(alive_nodes, key=lambda node: node.ping_ms if node.ping_ms is not None else float("inf"))
