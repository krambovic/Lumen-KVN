from __future__ import annotations

import json
from pathlib import Path

from xray_fluent.engines.singbox.config_builder import build_singbox_outbound
from xray_fluent.link_parser import parse_links_text, parse_single
from xray_fluent.node_transport import node_transport
from xray_fluent.qml_app.bridge.node_edit_helpers import (
    MANUAL_NODE_PROTOCOLS,
    build_node_updates,
    load_node_edit_fields,
)


QML_DIR = Path(__file__).parents[1] / "xray_fluent" / "qml_app" / "qml"
ROOT = Path(__file__).parents[1]
REPO_ROOT = Path(__file__).parents[2]


def test_explicit_naive_uri_builds_native_extended_outbound() -> None:
    node = parse_single(
        "naive://user:p%40ss@example.com:443?"
        "sni=front.example&udp_over_tcp=true#Naive"
    )

    outbound = build_singbox_outbound(node)

    assert node.scheme == "naive"
    assert outbound["type"] == "naive"
    assert outbound["username"] == "user"
    assert outbound["password"] == "p@ss"
    assert outbound["udp_over_tcp"] is True
    assert outbound["tls"]["server_name"] == "front.example"
    assert node_transport(node) == "H2"


def test_naive_quic_and_official_config_json_are_supported() -> None:
    quic = parse_single("naive+quic://user:pass@example.com#QUIC")
    assert build_singbox_outbound(quic)["quic"] is True
    assert node_transport(quic) == "QUIC"

    official_quic = parse_single("quic://user:pass@example.com#Official-QUIC")
    assert build_singbox_outbound(official_quic)["quic"] is True

    nodes, errors = parse_links_text(
        json.dumps(
            {
                "listen": "socks://127.0.0.1:1080",
                "proxy": "https://user:pass@example.com",
            }
        )
    )
    assert errors == []
    assert build_singbox_outbound(nodes[0])["type"] == "naive"


def test_clash_and_native_naive_payloads_are_supported() -> None:
    clash = """proxies:
  - name: Naive Clash
    type: naive
    server: example.com
    port: 443
    username: user
    password: pass
    sni: front.example
"""
    clash_nodes, clash_errors = parse_links_text(clash)
    assert clash_errors == []
    assert build_singbox_outbound(clash_nodes[0])["type"] == "naive"

    native_nodes, native_errors = parse_links_text(
        json.dumps(
            {
                "type": "naive",
                "tag": "native-naive",
                "server": "example.com",
                "server_port": 443,
                "username": "user",
                "password": "pass",
                "tls": {"enabled": True, "server_name": "example.com"},
            }
        )
    )
    assert native_errors == []
    assert build_singbox_outbound(native_nodes[0])["type"] == "naive"


def test_https_proxy_is_not_misdetected_as_naive() -> None:
    node = parse_single("https://user:pass@example.com")
    assert node.outbound["protocol"] == "http"
    assert "singbox" not in node.outbound


def test_naive_is_editable_and_keeps_native_fields() -> None:
    node = parse_single("naive://user:pass@example.com")
    assert "naive" in MANUAL_NODE_PROTOCOLS
    field_keys = {item["key"] for item in load_node_edit_fields(node)["protocolFields"]}
    assert {
        "username",
        "password",
        "extraHeaders",
        "udpOverTcpEnabled",
        "naiveQuic",
        "sni",
    } <= field_keys

    updates = build_node_updates(
        node,
        {
            "name": "Edited",
            "group": "Default",
            "server": "new.example.com",
            "port": "8443",
            "username": "new-user",
            "password": "new-pass",
            "extraHeaders": '{"Host":"front.example"}',
            "udpOverTcpEnabled": True,
            "naiveQuic": True,
            "sni": "front.example",
        },
    )
    outbound = updates["outbound"]["singbox"]
    assert outbound["server"] == "new.example.com"
    assert outbound["server_port"] == 8443
    assert outbound["extra_headers"] == {"Host": "front.example"}
    assert outbound["udp_over_tcp"] is True
    assert outbound["quic"] is True
    assert outbound["tls"] == {"enabled": True, "server_name": "front.example"}


def test_editor_uses_styled_scroll_and_context_menu_consumes_repeat_clicks() -> None:
    editor = (QML_DIR / "NodeEditDialog.qml").read_text(encoding="utf-8")
    context_menu = (QML_DIR / "TextEditContextMenu.qml").read_text(encoding="utf-8")

    assert "ScrollBar.vertical: FluentScrollBar" in editor
    assert "Flickable.StopAtBounds" in editor
    assert "Universal.accent: Theme.accent" in editor
    assert "modal: false" in context_menu
    assert "Popup.CloseOnPressOutside | Popup.CloseOnEscape" in context_menu
    assert "Overlay.modal: MouseArea" not in context_menu
    assert "onReleased: (mouse) => {" in context_menu
    assert "root.openAt(mouse.x, mouse.y)" in context_menu
    pressed_handler = context_menu.split("onPressed: (mouse) => {", 1)[1].split("}", 1)[0]
    assert "root.openAt(" not in pressed_handler


def test_release_build_bundles_naive_cronet_companion() -> None:
    build_script = (ROOT / "scripts" / "build_singbox_extended.ps1").read_text(
        encoding="utf-8"
    )
    stable_workflow = (REPO_ROOT / ".github" / "workflows" / "build.yml").read_text(
        encoding="utf-8"
    )
    prerelease_workflow = (
        REPO_ROOT / ".github" / "workflows" / "prerelease.yml"
    ).read_text(encoding="utf-8")

    assert "windows-amd64-purego.zip" in build_script
    assert "libcronet.dll" in build_script
    assert "naive-v1" in stable_workflow
    assert "naive-v1" in prerelease_workflow


def test_singbox_build_defaults_to_the_awg31_compatible_outbound_release() -> None:
    build_script = (ROOT / "scripts" / "build_singbox_extended.ps1").read_text(
        encoding="utf-8"
    )

    assert 'Ref = "v1.14.0-extended-2.7.1"' in build_script
    assert "apply --unidiff-zero" in build_script
    assert '"tunnel_address"' in (ROOT / "xray_fluent" / "link_parser.py").read_text(
        encoding="utf-8"
    )
