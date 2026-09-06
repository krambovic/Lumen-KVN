from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
import json

from xray_fluent.application.signature_service import transition_signature, tun_layer_signature
from xray_fluent.application.transition_engine import can_tun_hot_swap
from xray_fluent.engines.singbox.runtime_planner import parse_singbox_document, plan_singbox_runtime
from xray_fluent.models import AppSettings, Node, RoutingSettings


def _controller(node: Node) -> SimpleNamespace:
    return SimpleNamespace(
        selected_node=node,
        is_singbox_editor_mode=lambda _settings: True,
        uses_xray_raw_config=lambda _settings: False,
        _inspect_active_singbox_config=lambda: (Path("default.json"), "config-hash", True),
    )


def _node(node_id: str) -> Node:
    server = f"{node_id}.example"
    return Node(
        id=node_id,
        name=node_id,
        server=server,
        port=443,
        scheme="vless",
        outbound={
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": server,
                    "port": 443,
                    "users": [{"id": "00000000-0000-0000-0000-000000000000"}],
                }]
            },
            "streamSettings": {"security": "tls"},
        },
    )


def test_singbox_tun_signature_changes_when_tun_runtime_setting_changes() -> None:
    node = _node("node-a")
    controller = _controller(node)
    routing = RoutingSettings(mode="global")
    base = AppSettings(tun_mode=True, tun_mtu=9000)
    changed = AppSettings(tun_mode=True, tun_mtu=1400)

    assert transition_signature(controller, node, base, routing) != transition_signature(
        controller, node, changed, routing
    )
    assert tun_layer_signature(controller, node, base, routing) != tun_layer_signature(
        controller, node, changed, routing
    )


def test_singbox_tun_layer_signature_ignores_only_selected_node() -> None:
    node_a = _node("node-a")
    node_b = _node("node-b")
    controller = _controller(node_a)
    settings = AppSettings(tun_mode=True)
    routing = RoutingSettings(mode="global")

    assert tun_layer_signature(controller, node_a, settings, routing) == tun_layer_signature(
        controller, node_b, settings, routing
    )


def test_tun_hot_swap_requires_a_selected_node() -> None:
    session = SimpleNamespace(
        active_core="singbox",
        tun_mode=True,
        clash_api_selector="proxy",
        tun_layer_signature="same",
    )

    assert not can_tun_hot_swap(
        session=session,
        settings_tun_mode=True,
        has_selected_node=False,
        current_tun_layer_signature="same",
    )


def test_selector_is_not_added_to_a_proxy_runtime() -> None:
    payload = {
        "inbounds": [],
        "outbounds": [
            {"type": "direct", "tag": "proxy"},
            {"type": "direct", "tag": "direct"},
        ],
        "route": {"rules": [], "final": "proxy"},
    }
    document = parse_singbox_document(Path("default.json"), json.dumps(payload))

    plan = plan_singbox_runtime(
        document,
        _node("node-a"),
        routing=RoutingSettings(mode="global"),
        tun_mode=False,
        enable_hot_switch=True,
        hot_switch_nodes=(_node("node-a"), _node("node-b")),
    )

    assert plan.clash_api_selector == ""
    assert not any(item.get("type") == "selector" and item.get("tag") == "proxy" for item in plan.singbox_config["outbounds"])
