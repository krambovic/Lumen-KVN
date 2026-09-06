from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from xray_fluent.application.xray_runtime_service import build_runtime_xray_config
from xray_fluent.engines.singbox.runtime_planner import (
    parse_singbox_document,
    plan_singbox_runtime,
)
from xray_fluent.link_parser import parse_links_text, repair_node_outbound_from_link


def _xray_auto_payload() -> dict:
    outbounds = [
        {
            "tag": tag,
            "protocol": "vless",
            "settings": {
                "vnext": [
                    {
                        "address": f"{tag}.example",
                        "port": 443,
                        "users": [{"id": f"uuid-{tag}", "encryption": "none"}],
                    }
                ]
            },
            "streamSettings": {"network": "tcp", "security": "none"},
        }
        for tag in ("wifi-1", "wifi-2")
    ]
    outbounds.extend(
        [
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole"},
        ]
    )
    return {
        "remarks": "Авто | WiFi",
        "inbounds": [
            {"tag": "socks", "protocol": "socks", "listen": "127.0.0.1", "port": 10808},
            {"tag": "http", "protocol": "http", "listen": "127.0.0.1", "port": 10809},
        ],
        "outbounds": outbounds,
        "observatory": {
            "subjectSelector": ["wifi-1", "wifi-2"],
            "probeURL": "https://www.gstatic.com/generate_204",
            "probeInterval": "30s",
            "enableConcurrency": True,
        },
        "routing": {
            "balancers": [
                {
                    "tag": "auto",
                    "selector": ["wifi-1", "wifi-2"],
                    "strategy": {"type": "leastPing"},
                    "fallbackTag": "wifi-1",
                }
            ],
            "rules": [
                {"type": "field", "network": "tcp,udp", "balancerTag": "auto"},
            ],
        },
    }


def _singbox_base_document():
    payload = {
        "inbounds": [{"type": "tun", "tag": "tun-in", "interface_name": "tun0"}],
        "outbounds": [
            {"type": "direct", "tag": "proxy"},
            {"type": "direct", "tag": "direct"},
            {"type": "block", "tag": "block"},
        ],
        "route": {"rules": [], "final": "direct"},
        "dns": {
            "servers": [
                {"tag": "bootstrap-dns", "type": "udp", "server": "1.1.1.1"},
                {"tag": "proxy-dns", "type": "https", "server": "dns.google"},
            ],
            "final": "bootstrap-dns",
        },
    }
    return parse_singbox_document(Path("default.json"), json.dumps(payload))


def test_clash_masque_yaml_accepts_generator_trailing_tabs() -> None:
    text = """
proxies:
  - name: MASQUE
    type: masque
    private-key: private
    public-key: public
    ip: 172.16.0.2
    ipv6: 2606:4700:110::1
    dns: [1.1.1.1, 1.0.0.1]
    server: 162.159.198.2
    port: 443
    sni: example.com
  - name: MASQUE h2
    type: masque
    private-key: private
    public-key: public
    ip: 172.16.0.2
    server: 162.159.198.2
    port: 443
    network: h2
proxy-groups:
  - name: WARP
    type: select
    proxies:
      - MASQUE
      - "MASQUE h2"\t\t
rules:
  - MATCH,WARP
"""

    nodes, errors = parse_links_text(text)

    assert errors == []
    assert [(node.name, node.scheme, node.server, node.port) for node in nodes] == [
        ("MASQUE", "masque", "162.159.198.2", 443),
        ("MASQUE h2", "masque", "162.159.198.2", 443),
    ]
    assert nodes[0].outbound["singbox"]["profile"] == {"detour": "direct"}
    assert nodes[0].outbound["singbox"]["server"] == "162.159.198.2"
    assert nodes[0].outbound["singbox"]["server_port"] == 443
    assert nodes[0].outbound["singbox"]["private_key"] == "private"
    assert nodes[0].outbound["singbox"]["public_key"] == "public"
    assert nodes[0].outbound["singbox"]["tunnel_address"] == [
        "172.16.0.2/32",
        "2606:4700:110::1/128",
    ]
    assert nodes[0].outbound["_dns"] == ["1.1.1.1", "1.0.0.1"]
    assert nodes[0].outbound["singbox"]["udp_keepalive_period"] == "30s"
    assert nodes[0].outbound["singbox"]["reconnect_delay"] == "5s"
    assert nodes[0].outbound["singbox"]["congestion_controller"] == "bbr"
    assert nodes[0].outbound["singbox"]["use_http2"] is False
    assert nodes[1].outbound["singbox"]["use_http2"] is True


def test_legacy_clash_masque_node_restores_direct_profile_before_runtime() -> None:
    payload = {
        "name": "Legacy MASQUE",
        "type": "masque",
        "private-key": "wireguard-private-key",
        "public-key": "wireguard-public-key",
        "ip": "172.16.0.2",
        "dns": ["1.1.1.1", "1.0.0.1"],
        "server": "162.159.198.2",
        "port": 443,
        "sni": "example.com",
    }
    nodes, errors = parse_links_text("proxies:\n  - " + json.dumps(payload))
    assert errors == []
    node = nodes[0]
    node.link = json.dumps(payload)
    node.outbound["singbox"]["profile"]["private_key"] = payload["private-key"]
    node.outbound.pop("_dns")

    assert repair_node_outbound_from_link(node) is True

    assert node.outbound["singbox"]["profile"] == {"detour": "direct"}
    assert node.outbound["singbox"]["private_key"] == "wireguard-private-key"
    assert node.outbound["singbox"]["public_key"] == "wireguard-public-key"
    assert node.outbound["singbox"]["tunnel_address"] == ["172.16.0.2/32"]
    assert node.outbound["_dns"] == ["1.1.1.1", "1.0.0.1"]


def test_saved_legacy_masque_shape_repairs_without_original_clash_payload() -> None:
    payload = {
        "name": "Saved MASQUE",
        "type": "masque",
        "private-key": "wireguard-private-key",
        "public-key": "wireguard-public-key",
        "ip": "172.16.0.2",
        "server": "162.159.198.2",
        "port": 443,
    }
    node = parse_links_text("proxies:\n  - " + json.dumps(payload))[0][0]
    native = node.outbound["singbox"]
    native["profile"]["private_key"] = native.pop("private_key")
    # Early builds persisted this normalized object instead of the original
    # Clash entry, so the repair must use fields already stored on the node.
    node.link = json.dumps(node.outbound)

    assert repair_node_outbound_from_link(node) is True

    assert node.outbound["singbox"]["private_key"] == "wireguard-private-key"
    assert node.outbound["singbox"]["profile"] == {"detour": "direct"}
    assert node.outbound["singbox"]["server"] == "162.159.198.2"
    assert node.outbound["singbox"]["server_port"] == 443


def test_xray_least_ping_profile_imports_as_one_auto_node() -> None:
    payload = _xray_auto_payload()

    nodes, errors = parse_links_text(json.dumps(payload, ensure_ascii=False))

    assert errors == []
    assert len(nodes) == 1
    node = nodes[0]
    assert (node.name, node.scheme, node.server, node.port) == (
        "Авто | WiFi",
        "auto",
        "wifi-1.example",
        443,
    )
    assert node.outbound["protocol"] == "xray_config"
    stored = node.outbound["xray_config"]
    assert stored["routing"]["balancers"][0]["strategy"]["type"] == "leastPing"
    assert stored["observatory"]["subjectSelector"] == ["wifi-1", "wifi-2"]


def test_xray_auto_profile_is_preserved_for_proxy_runtime() -> None:
    node = parse_links_text(json.dumps(_xray_auto_payload(), ensure_ascii=False))[0][0]
    settings = SimpleNamespace(
        sniff_route_only=False,
        local_socks_port=10808,
        local_http_port=10809,
        enable_xray_fragment=True,
        enable_final_fragment=True,
    )
    controller = SimpleNamespace(
        load_active_xray_config_text=lambda: (Path("default.json"), "{}"),
        state=SimpleNamespace(settings=settings),
        _format_json_error_message=lambda _text, exc: str(exc),
        _ensure_xray_metrics_contract=lambda _payload, allocate_port: (19000, ("socks", "http")),
        _log=lambda _message: None,
        _infer_xray_ping_target=lambda _payload, selected: (selected.server, selected.port),
    )

    runtime = build_runtime_xray_config(controller, node)

    assert runtime.used_selected_node is True
    assert runtime.config["observatory"]["probeInterval"] == "30s"
    assert runtime.config["routing"]["rules"][-1]["balancerTag"] == "auto"
    assert runtime.config["routing"]["balancers"][0]["strategy"]["type"] == "leastPing"


def test_xray_auto_profile_uses_full_balancer_in_tun_sidecar() -> None:
    node = parse_links_text(json.dumps(_xray_auto_payload(), ensure_ascii=False))[0][0]

    plan = plan_singbox_runtime(
        _singbox_base_document(),
        node,
        routing=None,
        tun_mode=True,
    )

    assert plan.outcome == "hybrid_xray_sidecar"
    assert plan.xray_sidecar is not None
    sidecar = plan.xray_sidecar.config
    assert sidecar["observatory"]["subjectSelector"] == ["wifi-1", "wifi-2"]
    assert sidecar["routing"]["balancers"][0]["strategy"]["type"] == "leastPing"
    candidates = [
        outbound
        for outbound in sidecar["outbounds"]
        if str(outbound.get("tag") or "").startswith("wifi-")
    ]
    assert len(candidates) == 2
    assert all(
        outbound["streamSettings"]["sockopt"]["dialerProxy"] == "__app_hybrid_protect_out"
        for outbound in candidates
    )
