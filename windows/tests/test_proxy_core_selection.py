from __future__ import annotations

from types import SimpleNamespace

import pytest

from xray_fluent.app_controller import AppController
from xray_fluent.application.node_runtime_service import proxy_core_for_node
from xray_fluent.models import Node


def _node(protocol: str) -> Node:
    return Node(
        scheme=protocol,
        server="example.com",
        port=443,
        outbound={"protocol": protocol},
    )


@pytest.mark.parametrize(
    "protocol",
    ["hysteria", "hysteria2", "tuic", "awg", "warp", "wireguard", "mieru", "masque", "singbox_config"],
)
def test_native_singbox_protocols_select_singbox_proxy_core(protocol: str) -> None:
    assert proxy_core_for_node(_node(protocol)) == "singbox"


@pytest.mark.parametrize(
    "protocol",
    ["vless", "vmess", "trojan", "shadowsocks", "socks", "http"],
)
def test_hot_switchable_protocols_select_singbox_proxy_core(protocol: str) -> None:
    assert proxy_core_for_node(_node(protocol)) == "singbox"


def test_insecure_tls_node_selects_singbox_proxy_core() -> None:
    node = _node("trojan")
    node.outbound["streamSettings"] = {
        "security": "tls",
        "tlsSettings": {"serverName": "example.com", "allowInsecure": True},
    }

    assert proxy_core_for_node(node) == "singbox"


def test_unknown_utls_fingerprint_keeps_xray_semantics() -> None:
    node = _node("vless")
    node.outbound["streamSettings"] = {
        "security": "reality",
        "realitySettings": {"fingerprint": "future-browser-profile"},
    }

    assert proxy_core_for_node(node) == "xray"


def test_default_reality_spider_path_remains_native_singbox() -> None:
    node = _node("vless")
    node.outbound["streamSettings"] = {
        "security": "reality",
        "realitySettings": {"spiderX": "/", "fingerprint": "chrome"},
    }

    assert proxy_core_for_node(node) == "singbox"


def test_finalmask_vless_node_keeps_xray_proxy_core() -> None:
    node = _node("vless")
    node.outbound["streamSettings"] = {
        "network": "raw",
        "finalmask": {"tcp": [{"type": "fragment", "settings": {}}]},
    }

    assert proxy_core_for_node(node) == "xray"


@pytest.mark.parametrize(
    ("network", "settings_key", "settings"),
    [
        ("grpc", "grpcSettings", {"authority": "cdn.example.com"}),
        ("grpc", "grpcSettings", {"multiMode": True}),
        ("httpupgrade", "httpupgradeSettings", {"ed": "2048"}),
        ("quic", "quicSettings", {"security": "none"}),
    ],
)
def test_xray_only_transport_semantics_keep_xray_core(
    network: str,
    settings_key: str,
    settings: dict,
) -> None:
    node = _node("vless")
    node.outbound["streamSettings"] = {
        "network": network,
        settings_key: settings,
    }

    assert proxy_core_for_node(node) == "xray"


@pytest.mark.parametrize(
    ("security", "settings_key", "settings"),
    [
        ("tls", "tlsSettings", {"verifyPeerCertByName": "one.example.com"}),
        ("reality", "realitySettings", {"mldsa65Verify": "post-quantum-key"}),
        ("reality", "realitySettings", {"spiderX": "/custom-spider"}),
    ],
)
def test_xray_only_tls_semantics_keep_xray_core(
    security: str,
    settings_key: str,
    settings: dict,
) -> None:
    node = _node("vless")
    node.outbound["streamSettings"] = {
        "network": "tcp",
        "security": security,
        settings_key: settings,
    }

    assert proxy_core_for_node(node) == "xray"


def test_xray_proxy_hot_swap_is_rejected_when_selected_node_requires_singbox() -> None:
    controller = SimpleNamespace(
        selected_node=_node("hysteria2"),
        state=SimpleNamespace(settings=SimpleNamespace(tun_mode=False)),
        _inspect_active_xray_config=lambda: (_ for _ in ()).throw(
            AssertionError("Xray config must not be inspected for a sing-box target")
        ),
    )

    assert AppController._can_proxy_hot_swap(controller, SimpleNamespace()) is False
