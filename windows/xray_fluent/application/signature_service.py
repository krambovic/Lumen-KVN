from __future__ import annotations

import json
from typing import TYPE_CHECKING

from ..constants import DEFAULT_HTTP_PORT, DEFAULT_SOCKS_PORT
from ..engines.singbox import classify_node_for_singbox
from .node_runtime_service import proxy_core_for_node

if TYPE_CHECKING:
    from ..app_controller import AppController
    from ..models import AppSettings, Node, RoutingSettings


def signature(payload: object) -> str:
    return json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def routing_signature(controller: AppController, routing: RoutingSettings | None = None) -> str:
    routing = routing or controller.state.routing
    return signature(routing.to_dict())


def system_proxy_bypass_lan(controller: AppController, settings: AppSettings | None = None) -> bool:
    settings = settings or controller.state.settings
    return bool(settings.system_proxy_bypass_lan)


def _singbox_tun_runtime_signature(settings: AppSettings) -> dict[str, object]:
    """Return settings that change the sing-box TUN runtime contract."""
    proxy_auth_enabled = bool(getattr(settings, "proxy_auth_enabled", False))
    return {
        "enable_final_fragment": bool(getattr(settings, "enable_final_fragment", False)),
        "fragment_packets": str(getattr(settings, "fragment_packets", "tlshello")),
        "fragment_length": str(getattr(settings, "fragment_length", "50-100")),
        "fragment_delay": str(getattr(settings, "fragment_delay", "10-20")),
        "tail_fragment_enabled": bool(getattr(settings, "tail_fragment_enabled", False)),
        "multiplex_enabled": bool(getattr(settings, "multiplex_enabled", False)),
        "multiplex_concurrency": int(getattr(settings, "multiplex_concurrency", 8)),
        "tun_strict_route": bool(getattr(settings, "tun_strict_route", False)),
        "tun_stack": str(getattr(settings, "tun_stack", "mixed")),
        "tun_mtu": int(getattr(settings, "tun_mtu", 9000)),
        "tun_endpoint_independent_nat": bool(
            getattr(settings, "tun_endpoint_independent_nat", False)
        ),
        "tun_block_quic": bool(getattr(settings, "tun_block_quic", True)),
        "local_socks_port": int(getattr(settings, "local_socks_port", DEFAULT_SOCKS_PORT)),
        "local_http_port": int(getattr(settings, "local_http_port", DEFAULT_HTTP_PORT)),
        "proxy_auth_enabled": proxy_auth_enabled,
        "proxy_auth_username": str(getattr(settings, "proxy_auth_username", "")) if proxy_auth_enabled else "",
        "proxy_auth_password": str(getattr(settings, "proxy_auth_password", "")) if proxy_auth_enabled else "",
    }


def transition_signature(
    controller: AppController,
    node: Node | None = None,
    settings: AppSettings | None = None,
    routing: RoutingSettings | None = None,
    *,
    include_node: bool = True,
) -> str:
    settings = settings or controller.state.settings
    routing = routing or controller.state.routing
    node = (node or controller.selected_node) if include_node else None
    if not settings.tun_mode and proxy_core_for_node(node) == "singbox":
        source_path, config_hash, has_proxy_outbound = controller._inspect_active_singbox_config()
        return signature(
            {
                "mode": "singbox-proxy",
                "singbox_path": str(settings.singbox_path),
                "config_file": str(source_path.name),
                "config_hash": config_hash,
                "has_proxy_outbound": has_proxy_outbound,
                "node_id": node.id if node else None,
                "node_outbound": node.outbound if node else None,
                "proxy_enabled": bool(settings.enable_system_proxy),
                "proxy_bypass_lan": system_proxy_bypass_lan(controller, settings),
                "firefox_proxy_integration": bool(getattr(settings, "firefox_proxy_integration", False)),
                "socks_port": int(getattr(settings, "local_socks_port", DEFAULT_SOCKS_PORT)),
                "http_port": int(getattr(settings, "local_http_port", DEFAULT_HTTP_PORT)),
                "routing": routing.to_dict(),
                "regional_preset": str(getattr(settings, "regional_preset", "russia")),
                "discord_proxy_enabled": bool(settings.discord_proxy_enabled),
                "prefer_ipv6": bool(getattr(settings, "prefer_ipv6", False)),
            }
        )
    if controller.is_singbox_editor_mode(settings):
        source_path, config_hash, has_proxy_outbound = controller._inspect_active_singbox_config()
        planner_outcome = "native_singbox"
        if has_proxy_outbound and node is not None:
            planner_outcome = classify_node_for_singbox(node)
        signature_payload = {
            "mode": "singbox-editor",
            "singbox_path": str(settings.singbox_path),
            "config_file": str(source_path.name),
            "config_hash": config_hash,
            "has_proxy_outbound": has_proxy_outbound,
            "planner_outcome": planner_outcome,
            "node_id": node.id if has_proxy_outbound and node else None,
            "node_outbound": node.outbound if has_proxy_outbound and node else None,
            "routing": routing.to_dict(),
            "regional_preset": str(getattr(settings, "regional_preset", "russia")),
            "discord_proxy_enabled": bool(settings.discord_proxy_enabled),
            "prefer_ipv6": bool(getattr(settings, "prefer_ipv6", False)),
            "tun_runtime": _singbox_tun_runtime_signature(settings),
        }
        if planner_outcome == "hybrid_xray_sidecar":
            signature_payload["xray_path"] = str(settings.xray_path)
        return signature(signature_payload)
    if controller.uses_xray_raw_config(settings):
        source_path, config_hash, has_proxy_outbound, socks_port, http_port, api_port = controller._inspect_active_xray_config()
        signature_payload = {
            "mode": "xray-direct",
            "xray_path": str(settings.xray_path),
            "config_file": str(source_path.name),
            "config_hash": config_hash,
            "has_proxy_outbound": has_proxy_outbound,
            "node_id": node.id if has_proxy_outbound and node else None,
            "node_outbound": node.outbound if has_proxy_outbound and node else None,
            "api_port": int(api_port),
            "proxy_allow_lan": bool(getattr(settings, "proxy_allow_lan", False)),
            "sniff_route_only": bool(getattr(settings, "sniff_route_only", False)),
            "routing": routing.to_dict(),
            "regional_preset": str(getattr(settings, "regional_preset", "russia")),
            "discord_proxy_enabled": bool(settings.discord_proxy_enabled),
            "prefer_ipv6": bool(getattr(settings, "prefer_ipv6", False)),
        }
        signature_payload.update(
            {
                "proxy_enabled": bool(settings.enable_system_proxy),
                "proxy_bypass_lan": system_proxy_bypass_lan(controller, settings),
                "firefox_proxy_integration": bool(getattr(settings, "firefox_proxy_integration", False)),
                "socks_port": int(socks_port),
                "http_port": int(http_port),
            }
        )
        return signature(signature_payload)
    return signature(
        {
            "node_id": node.id if node else None,
            "tun_mode": bool(settings.tun_mode),
            "proxy_enabled": bool(settings.enable_system_proxy),
            "proxy_bypass_lan": bool(routing.bypass_lan),
            "firefox_proxy_integration": bool(getattr(settings, "firefox_proxy_integration", False)),
            "proxy_allow_lan": bool(getattr(settings, "proxy_allow_lan", False)),
            "sniff_route_only": bool(getattr(settings, "sniff_route_only", False)),
            "tun_settings": [
                bool(settings.tun_strict_route),
                str(settings.tun_stack),
                int(settings.tun_mtu),
                bool(getattr(settings, "tun_endpoint_independent_nat", False)),
                bool(getattr(settings, "tun_block_quic", True)),
            ],
            "socks_port": int(getattr(settings, "local_socks_port", DEFAULT_SOCKS_PORT)),
            "http_port": int(getattr(settings, "local_http_port", DEFAULT_HTTP_PORT)),
            "xray_path": str(settings.xray_path),
            "singbox_path": str(settings.singbox_path),
            "routing": routing.to_dict(),
            "regional_preset": str(getattr(settings, "regional_preset", "russia")),
            "discord_proxy_enabled": bool(settings.discord_proxy_enabled),
            "prefer_ipv6": bool(getattr(settings, "prefer_ipv6", False)),
        }
    )


def xray_layer_signature(
    controller: AppController,
    node: Node | None = None,
    settings: AppSettings | None = None,
    routing: RoutingSettings | None = None,
) -> str:
    settings = settings or controller.state.settings
    routing = routing or controller.state.routing
    node = node or controller.selected_node
    if not settings.tun_mode and proxy_core_for_node(node) == "singbox":
        return ""
    if controller.uses_xray_raw_config(settings):
        source_path, config_hash, has_proxy_outbound, socks_port, http_port, api_port = controller._inspect_active_xray_config()
        signature_payload = {
            "mode": "xray-direct",
            "xray_path": str(settings.xray_path),
            "config_file": str(source_path.name),
            "config_hash": config_hash,
            "has_proxy_outbound": has_proxy_outbound,
            "node_id": node.id if has_proxy_outbound and node else None,
            "node_outbound": node.outbound if has_proxy_outbound and node else None,
            "socks_port": int(socks_port),
            "http_port": int(http_port),
            "api_port": int(api_port),
            "proxy_allow_lan": bool(getattr(settings, "proxy_allow_lan", False)),
            "sniff_route_only": bool(getattr(settings, "sniff_route_only", False)),
            "routing": routing.to_dict(),
            "discord_proxy_enabled": bool(settings.discord_proxy_enabled),
            "prefer_ipv6": bool(getattr(settings, "prefer_ipv6", False)),
        }
        return signature(signature_payload)
    return signature(
        {
            "node_id": node.id if node else None,
            "tun_mode": bool(settings.tun_mode),
            "socks_port": int(getattr(settings, "local_socks_port", DEFAULT_SOCKS_PORT)),
            "http_port": int(getattr(settings, "local_http_port", DEFAULT_HTTP_PORT)),
            "xray_path": str(settings.xray_path),
            "routing": routing.to_dict(),
            "discord_proxy_enabled": bool(settings.discord_proxy_enabled),
            "prefer_ipv6": bool(getattr(settings, "prefer_ipv6", False)),
        }
    )


def tun_layer_signature(
    controller: AppController,
    node: Node | None = None,
    settings: AppSettings | None = None,
    routing: RoutingSettings | None = None,
) -> str:
    settings = settings or controller.state.settings
    routing = routing or controller.state.routing
    node = node or controller.selected_node
    if not settings.tun_mode:
        return ""
    if controller.is_singbox_editor_mode(settings):
        return transition_signature(
            controller,
            settings=settings,
            routing=routing,
            include_node=False,
        )
    return signature(
        {
            "mode": "singbox-native",
            "routing": routing.to_dict(),
            "xray_path": str(settings.xray_path),
            "singbox_path": str(settings.singbox_path),
            "discord_proxy_enabled": bool(settings.discord_proxy_enabled),
            "prefer_ipv6": bool(getattr(settings, "prefer_ipv6", False)),
        }
    )
