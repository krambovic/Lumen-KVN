from __future__ import annotations

import base64
import json
from pathlib import Path
import subprocess
from urllib.parse import quote

import pytest

from xray_fluent.engines.singbox.config_builder import build_singbox_outbound
from xray_fluent.engines.singbox.runtime_planner import parse_singbox_document, plan_singbox_runtime
from xray_fluent.application.node_service import _maybe_base64_decode
from xray_fluent.link_parser import (
    parse_links_text,
    parse_single,
    repair_node_outbound_from_link,
    validate_node_outbound,
)
from xray_fluent.models import Node, RoutingSettings


def _base_config() -> dict:
    return {
        "inbounds": [{"type": "tun", "tag": "tun-in"}],
        "outbounds": [
            {"type": "direct", "tag": "proxy"},
            {"type": "direct", "tag": "direct"},
            {"type": "block", "tag": "block"},
        ],
        "route": {"rules": [], "final": "direct"},
        "dns": {"servers": [{"tag": "bootstrap-dns", "type": "udp", "server": "1.1.1.1"}]},
    }


def test_vmess_base64_with_legacy_non_utf8_remark_still_imports() -> None:
    payload = {
        "v": "2",
        "ps": "Сервер Ы",
        "add": "example.com",
        "port": "443",
        "id": "00000000-0000-0000-0000-000000000000",
        "aid": "0",
        "net": "tcp",
        "type": "none",
        "tls": "tls",
    }
    encoded = base64.urlsafe_b64encode(
        json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("cp1251")
    ).decode("ascii")

    nodes, errors = parse_links_text(f"vmess://{encoded}")

    assert errors == []
    assert nodes[0].server == "example.com"
    assert nodes[0].name == "Сервер Ы"


def test_base64_subscription_with_legacy_non_utf8_text_is_unwrapped() -> None:
    raw = "vless://00000000-0000-0000-0000-000000000000@example.com:443#Сервер Ы".encode(
        "cp1251"
    )
    encoded = base64.urlsafe_b64encode(raw).decode("ascii")

    assert _maybe_base64_decode(encoded) == raw.decode("cp1251")


def test_mkcp_transport_is_converted_for_singbox_extended() -> None:
    nodes, errors = parse_links_text(
        "vless://00000000-0000-0000-0000-000000000000@example.com:443"
        "?type=kcp&headerType=wireguard&seed=secret&congestion=false&mtu=1350#mkcp"
    )

    assert errors == []
    outbound = build_singbox_outbound(nodes[0], tag="proxy")

    assert outbound["transport"]["type"] == "mkcp"
    assert outbound["transport"]["header_type"] == "wireguard"
    assert outbound["transport"]["seed"] == "secret"
    assert outbound["transport"]["congestion"] is False
    assert outbound["transport"]["mtu"] == 1350


def test_mieru_native_json_import_is_tun_only_singbox_outbound() -> None:
    nodes, errors = parse_links_text(
        json.dumps(
            {
                "type": "mieru",
                "tag": "proxy",
                "server": "example.com",
                "server_port": 27017,
                "transport": "TCP",
                "username": "user",
                "password": "pass",
            }
        )
    )

    assert errors == []
    assert nodes[0].scheme == "mieru"
    assert build_singbox_outbound(nodes[0], tag="proxy")["type"] == "mieru"


def test_mierus_link_imports_as_mieru_extended_outbound() -> None:
    nodes, errors = parse_links_text(
        "mierus://user:pass@example.com:27017?transport=TCP&multiplexing=MULTIPLEXING_LOW#secure-mieru"
    )

    assert errors == []
    assert nodes[0].scheme == "mieru"
    outbound = build_singbox_outbound(nodes[0], tag="proxy")
    assert outbound["type"] == "mieru"
    assert outbound["server"] == "example.com"
    assert outbound["server_port"] == 27017
    assert outbound["transport"] == "TCP"
    assert outbound["username"] == "user"
    assert outbound["password"] == "pass"
    assert outbound["multiplexing"] == "MULTIPLEXING_LOW"


def test_clash_yaml_imports_wireguard_and_amnezia_warp(tmp_path) -> None:
    config_path = tmp_path / "warp.yaml"
    config_path.write_text(
        ("# long generated header\n" * 300) + """
warp-common: &warp-common
  type: wireguard
  ip: 172.16.0.2/32
  ipv6: '2606:4700:110::2/128'
  private-key: private-key=
  public-key: public-key=
  allowed-ips: [0.0.0.0/0, '::/0']
  reserved: [14, 84, 156]
  persistent-keepalive: 25
  mtu: 1280

proxies:
  - name: WARP WG
    <<: *warp-common
    server: engage.cloudflareclient.com
    port: 2408
  - name: WARP AWG
    <<: *warp-common
    server: 162.159.192.1
    port: 500
    amnezia-wg-option:
      jc: 4
      jmin: 64
      jmax: 256
      h1: 1
      h2: 2
      h3: 3
      h4: 4
      i1: '<b 0x01020304>'
""".strip(),
        encoding="utf-8",
    )

    nodes, errors = parse_links_text(str(config_path), allow_file_reference=True)

    assert errors == []
    assert [node.scheme for node in nodes] == ["warp", "awg"]
    assert all("WARP" in node.tags for node in nodes)
    plain = build_singbox_outbound(nodes[0], tag="proxy")
    assert plain["type"] == "warp"
    assert plain["profile"]["private_key"] == "private-key="
    # sing-box-extended 2.5.1+ rejects an explicit `reserved` on WARP endpoints.
    assert "reserved" not in plain
    assert plain["persistent_keepalive_interval"] == 25
    amnezia = build_singbox_outbound(nodes[1], tag="proxy")["amnezia"]
    assert amnezia["jc"] == 4
    assert amnezia["i1"] == "<b 0x01020304>"

    document = parse_singbox_document(Path("default.json"), json.dumps(_base_config()))
    runtime = plan_singbox_runtime(
        document,
        nodes[1],
        routing=RoutingSettings(mode="global", tun_default_outbound="proxy"),
    ).singbox_config
    endpoint = runtime["endpoints"][0]
    assert "ip" not in endpoint
    assert "server" not in endpoint
    assert endpoint["type"] == "warp"
    assert runtime["experimental"]["cache_file"]["store_warp_config"] is True


def test_legacy_clash_wireguard_link_is_migrated_before_runtime() -> None:
    legacy_payload = {
        "name": "Legacy WARP",
        "type": "wireguard",
        "server": "engage.cloudflareclient.com",
        "port": 2408,
        "ip": "172.16.0.2/32",
        "private-key": "private-key=",
        "public-key": "public-key=",
        "allowed-ips": ["0.0.0.0/0", "::/0"],
        "reserved": [14, 84, 156],
    }
    nodes, errors = parse_links_text("proxies:\n  - " + json.dumps(legacy_payload))
    assert errors == []
    node = nodes[0]
    node.link = json.dumps(legacy_payload)
    node.outbound = {"protocol": "wireguard", "singbox": dict(legacy_payload)}

    assert repair_node_outbound_from_link(node) is True

    outbound = build_singbox_outbound(node, tag="proxy")
    assert node.scheme == "warp"
    assert "ip" not in outbound
    assert "server" not in outbound
    assert outbound["type"] == "warp"
    assert outbound["profile"]["private_key"] == "private-key="
    assert "reserved" not in outbound


def test_warp_link_reserved_parameter_is_not_emitted_on_the_endpoint() -> None:
    nodes, errors = parse_links_text("warp://?private_key=private-key%3D&reserved=DlSc#WARP")

    assert errors == []
    outbound = build_singbox_outbound(nodes[0], tag="proxy")
    assert outbound["type"] == "warp"
    assert "reserved" not in outbound


def test_clash_wireguard_reserved_on_non_cloudflare_server_is_rejected() -> None:
    payload = {
        "name": "NonWarpWG",
        "type": "wireguard",
        "server": "203.0.113.9",
        "port": 51820,
        "private-key": "private-key=",
        "public-key": "public-key=",
        "ip": "10.7.0.2",
        "reserved": [12, 34, 56],
    }
    nodes, errors = parse_links_text("proxies:\n  - " + json.dumps(payload))

    assert nodes == []
    assert errors and "Cloudflare WARP" in errors[0]


def test_newline_delimited_clash_awg_json_uses_native_wireguard_endpoints() -> None:
    def awg_payload(name: str, kind: str, server: str, address: str) -> dict:
        return {
            "name": name,
            "type": kind,
            "server": server,
            "port": 44303,
            "ip": address,
            "private-key": "private-key=",
            "public-key": "public-key=",
            "allowed-ips": ["0.0.0.0/0", "::/0"],
            "dns": ["1.1.1.1", "1.0.0.1"],
            "mtu": 1420,
            "persistent-keepalive": 25,
            "udp-timeout": "4m",
            "workers": 3,
            "preallocated-buffers-per-pool": 96,
            "disable-pauses": True,
            "remote-dns-resolve": True,
            "amnezia-wg-option": {
                "jc": 4,
                "jmin": 64,
                "jmax": 160,
                "s1": 44,
                "s2": 63,
                "s3": 12,
                "s4": 8,
                "h1": "819296636-819296655",
                "h2": "2094251746-2094251766",
                "h3": "688450779-688450798",
                "h4": "1775783192-1775783212",
                "i1": "<b 0x01020304>",
                "i5": "<b 0x05060708>",
            },
        }

    first = awg_payload("AWG 2.0 one", "wireguard", "203.0.113.10", "10.8.0.64/32")
    second = awg_payload("AWG 2.0 two", "amneziawg", "198.51.100.20", "10.8.0.100/32")
    nodes, errors = parse_links_text(
        json.dumps(first, ensure_ascii=False) + "\n" + json.dumps(second, ensure_ascii=False)
    )

    assert errors == []
    assert [node.scheme for node in nodes] == ["awg", "awg"]
    assert [node.server for node in nodes] == ["203.0.113.10", "198.51.100.20"]
    for node, expected_address in zip(nodes, ("10.8.0.64/32", "10.8.0.100/32")):
        endpoint = build_singbox_outbound(node, tag="proxy")
        peer = endpoint["peers"][0]
        assert endpoint["type"] == "wireguard"
        assert endpoint["address"] == [expected_address]
        assert endpoint["mtu"] == 1420
        assert endpoint["udp_timeout"] == "4m"
        assert endpoint["workers"] == 3
        assert endpoint["preallocated_buffers_per_pool"] == 96
        assert endpoint["disable_pauses"] is True
        assert peer["allowed_ips"] == ["0.0.0.0/0", "::/0"]
        assert peer["persistent_keepalive_interval"] == 25
        assert endpoint["amnezia"]["h1"] == "819296636-819296655"
        assert endpoint["amnezia"]["i1"] == "<b 0x01020304>"
        assert node.outbound["_dns"] == ["1.1.1.1", "1.0.0.1"]
        assert validate_node_outbound(node) is None


def test_native_singbox_wireguard_json_is_not_reclassified_as_clash() -> None:
    payload = {
        "type": "wireguard",
        "tag": "native-wg",
        "address": ["10.0.0.2/32"],
        "private_key": "private-key=",
        "peers": [
            {
                "address": "203.0.113.10",
                "port": 51820,
                "public_key": "public-key=",
                "allowed_ips": ["0.0.0.0/0"],
            }
        ],
    }

    nodes, errors = parse_links_text(json.dumps(payload))

    assert errors == []
    assert len(nodes) == 1
    assert nodes[0].scheme == "wireguard"
    assert nodes[0].server == "203.0.113.10"
    assert build_singbox_outbound(nodes[0], tag="proxy")["peers"] == payload["peers"]


def test_awg_wgquick_config_normalizes_bare_addresses_and_awg20_fields() -> None:
    nodes, errors = parse_links_text(
        """
        [Interface]
        PrivateKey = QGg8AFRn6qKfTB7cT3FWH1WGx3np+OKzlNuQUrqIBmI=
        Address = 172.16.0.2, 2606:4700:110:80b2::2
        DNS = 1.1.1.1, 1.0.0.1
        MTU = 1280
        Jc = 4
        Jmin = 40
        Jmax = 70
        S1 = 0
        S2 = 0
        S3 = 0
        S4 = 0
        H1 = 1
        H2 = 2
        H3 = 3
        H4 = 4
        I1 = <b 0x01020304>
        I5 = <b 0x05060708>
        J3 = <b 0x090a0b0c>
        Itime = 50
        Id = www.pochta.ru
        Ip = quic
        Ib = curl

        [Peer]
        PublicKey = 3nk7jdnkcL95Fc/z+GCiH7jOovEKhFkLIGPT+U/uLEQ=
        AllowedIPs = 0.0.0.0/0, ::/0
        Endpoint = 162.159.192.1:8886
        PersistentKeepalive = 25
        """
    )

    assert errors == []
    outbound = build_singbox_outbound(nodes[0], tag="proxy")
    assert nodes[0].scheme == "awg"
    assert outbound["type"] == "wireguard"
    assert outbound["address"] == ["172.16.0.2/32", "2606:4700:110:80b2::2/128"]
    assert "listen_port" not in outbound
    assert outbound["peers"][0]["persistent_keepalive_interval"] == 25
    assert outbound["amnezia"]["i1"] == "<b 0x01020304>"
    assert outbound["amnezia"]["i5"] == "<b 0x05060708>"
    assert outbound["amnezia"]["j3"] == "<b 0x090a0b0c>"
    assert outbound["amnezia"]["itime"] == 50
    assert nodes[0].outbound["_dns"] == ["1.1.1.1", "1.0.0.1"]
    assert nodes[0].outbound["_protocol_masking"] == {
        "id": "www.pochta.ru",
        "ip": "quic",
        "ib": "curl",
    }


def test_awg3_wgquick_config_preserves_header_protection_and_timers() -> None:
    header_key = base64.b64encode(bytes(range(32))).decode("ascii")
    source = f"""
        [Interface]
        PrivateKey = {base64.b64encode(bytes([1] * 32)).decode("ascii")}
        Address = 10.9.0.120/32
        DNS = 1.1.1.1, 1.0.0.1
        MTU = 1420
        Jc = 8
        Jmin = 82
        Jmax = 289
        S1 = 59
        S2 = 25
        S3 = 19
        S4 = 14
        H1 = 100016672-100016772
        H2 = 600002096-600002196
        H3 = 1100030931-1100031031
        H4 = 1600001288-1600001388
        I1 = <b 0x01020304>
        HeaderProtectionKey = {header_key}
        ContentPaddingAddition = 0-110
        RekeyAfterTime = 120
        RekeyTimeout = 5-8
        RejectAfterTime = 180
        KeepaliveTimeout = 10
        MaxHandshakeAttempts = 18

        [Peer]
        PublicKey = {base64.b64encode(bytes([2] * 32)).decode("ascii")}
        Endpoint = 203.0.113.10:44553
        AllowedIPs = 0.0.0.0/0
        PersistentKeepalive = 25
    """

    nodes, errors = parse_links_text(source)

    assert errors == []
    assert len(nodes) == 1
    node = nodes[0]
    outbound = build_singbox_outbound(node, tag="proxy")
    amnezia = outbound["amnezia"]
    assert node.scheme == "awg"
    assert amnezia["header_protection_key"] == header_key
    assert amnezia["content_padding_addition"] == "0-110"
    assert amnezia["rekey_after_time"] == 120
    assert amnezia["rekey_timeout"] == "5-8"
    assert amnezia["reject_after_time"] == 180
    assert amnezia["keepalive_timeout"] == 10
    assert amnezia["max_handshake_attempts"] == 18
    assert validate_node_outbound(node) is None


def test_awg31_wgquick_config_preserves_the_extended_transport_fields() -> None:
    header_key = base64.b64encode(bytes(range(32))).decode("ascii")
    source = f"""
        [Interface]
        PrivateKey = {base64.b64encode(bytes([1] * 32)).decode("ascii")}
        Address = 10.9.0.121/32
        MTU = 1280
        Jc = 6
        Jmin = 10
        Jmax = 50
        S1 = 95
        S2 = 86
        S3 = 33
        S4 = 12
        H1 = 134567-245678
        H2 = 3456789-4567890
        H3 = 56789012-67890123
        H4 = 456789012-567890123
        I1 = <b 0x01020304>
        I2 = <b 0x05060708>
        I3 = <b 0x090a0b0c>
        I4 = <b 0x0d0e0f10>
        I5 = <b 0x11121314>
        HeaderProtectionKey = {header_key}
        ContentPaddingAddition = 10-100
        RekeyAfterTime = 100-120
        RekeyTimeout = 5-8
        RejectAfterTime = 180-200
        KeepaliveTimeout = 10-15
        MaxHandshakeAttempts = 5-8

        [Peer]
        PublicKey = {base64.b64encode(bytes([2] * 32)).decode("ascii")}
        Endpoint = 198.51.100.10:51820
        AllowedIPs = 0.0.0.0/0, ::/0
        PersistentKeepalive = 25
    """

    nodes, errors = parse_links_text(source)

    assert errors == []
    assert len(nodes) == 1
    amnezia = build_singbox_outbound(nodes[0], tag="proxy")["amnezia"]
    assert nodes[0].scheme == "awg"
    assert amnezia["i2"] == "<b 0x05060708>"
    assert amnezia["i5"] == "<b 0x11121314>"
    assert amnezia["header_protection_key"] == header_key
    assert amnezia["content_padding_addition"] == "10-100"
    assert amnezia["rekey_after_time"] == "100-120"
    assert amnezia["rekey_timeout"] == "5-8"
    assert amnezia["reject_after_time"] == "180-200"
    assert amnezia["keepalive_timeout"] == "10-15"
    assert amnezia["max_handshake_attempts"] == "5-8"
    assert validate_node_outbound(nodes[0]) is None


def test_awg3_runtime_config_is_accepted_by_delivered_singbox_core(tmp_path) -> None:
    core = Path(__file__).parents[1] / "core" / "sing-box.exe"
    if not core.is_file():
        pytest.skip("delivered sing-box core is not present")

    header_key = base64.b64encode(bytes(range(32))).decode("ascii")
    source = f"""
        [Interface]
        PrivateKey = {base64.b64encode(bytes([1] * 32)).decode("ascii")}
        Address = 10.9.0.120/32
        MTU = 1420
        Jc = 8
        Jmin = 82
        Jmax = 289
        S1 = 59
        S2 = 25
        S3 = 19
        S4 = 14
        H1 = 100016672-100016772
        H2 = 600002096-600002196
        H3 = 1100030931-1100031031
        H4 = 1600001288-1600001388
        HeaderProtectionKey = {header_key}
        ContentPaddingAddition = 0-110

        [Peer]
        PublicKey = {base64.b64encode(bytes([2] * 32)).decode("ascii")}
        Endpoint = 203.0.113.10:44553
        AllowedIPs = 0.0.0.0/0
    """
    nodes, errors = parse_links_text(source)
    assert errors == []

    template_path = Path(__file__).parents[1] / "data" / "templates" / "sing-box" / "default.json"
    document = parse_singbox_document(template_path, template_path.read_text(encoding="utf-8"))
    plan = plan_singbox_runtime(
        document,
        nodes[0],
        routing=RoutingSettings(mode="global", tun_default_outbound="proxy"),
        tun_mode=True,
    )
    config_path = tmp_path / "awg3-runtime.json"
    config_path.write_text(json.dumps(plan.singbox_config), encoding="utf-8")
    result = subprocess.run(
        [str(core), "check", "-c", str(config_path), "-D", str(core.parent)],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr


def test_legacy_awg_wgquick_node_is_migrated_before_runtime() -> None:
    source = """
        [Interface]
        PrivateKey = private-key=
        Address = 172.16.0.2
        DNS = 1.1.1.1, 1.0.0.1
        MTU = 1280
        Jc = 4
        Jmin = 40
        Jmax = 70
        H1 = 1
        H2 = 2
        H3 = 3
        H4 = 4

        [Peer]
        PublicKey = public-key=
        AllowedIPs = 0.0.0.0/0, ::/0
        Endpoint = 8.47.69.2:1074
        """
    nodes, errors = parse_links_text(source)
    assert errors == []
    node = nodes[0]
    native = node.outbound["singbox"]
    native["listen_port"] = 10000
    node.outbound.pop("_dns")

    assert repair_node_outbound_from_link(node) is True

    assert "listen_port" not in node.outbound["singbox"]
    assert node.outbound["_dns"] == ["1.1.1.1", "1.0.0.1"]


def test_awg_runtime_keeps_configured_doh_for_public_profile_dns() -> None:
    nodes, errors = parse_links_text(
        """
        [Interface]
        PrivateKey = private-key=
        Address = 172.16.0.2, 2606:4700:110::2
        DNS = 1.1.1.1, 1.0.0.1
        MTU = 1280
        Jc = 4
        Jmin = 40
        Jmax = 70
        S1 = 0
        S2 = 0
        S3 = 0
        S4 = 0
        H1 = 1
        H2 = 2
        H3 = 3
        H4 = 4

        [Peer]
        PublicKey = public-key=
        AllowedIPs = 0.0.0.0/0, ::/0
        Endpoint = 8.47.69.2:1074
        """
    )

    assert errors == []
    document = parse_singbox_document(Path("default.json"), json.dumps(_base_config()))
    runtime = plan_singbox_runtime(
        document,
        nodes[0],
        routing=RoutingSettings(mode="global", tun_default_outbound="proxy"),
    ).singbox_config

    tun = next(item for item in runtime["inbounds"] if item.get("type") == "tun")
    proxy_dns = next(item for item in runtime["dns"]["servers"] if item.get("tag") == "proxy-dns")
    endpoint = next(item for item in runtime["endpoints"] if item.get("tag") == "proxy")
    assert tun["mtu"] == 1280
    assert proxy_dns["type"] == "https"
    assert proxy_dns["server"] == "cloudflare-dns.com"
    assert proxy_dns["detour"] == "proxy"
    assert next(
        item for item in runtime["dns"]["servers"] if item.get("tag") == "proxy-dns-2"
    )["server"] == "dns.google"
    assert endpoint["peers"][0]["address"] == "8.47.69.2"


def test_awg_runtime_prefers_private_profile_dns() -> None:
    nodes, errors = parse_links_text(
        """
        [Interface]
        PrivateKey = private-key=
        Address = 10.8.0.2/32
        DNS = 1.1.1.1, 10.8.0.1
        Jc = 4
        Jmin = 40
        Jmax = 70

        [Peer]
        PublicKey = public-key=
        AllowedIPs = 0.0.0.0/0
        Endpoint = 203.0.113.10:51820
        """
    )

    assert errors == []
    document = parse_singbox_document(Path("default.json"), json.dumps(_base_config()))
    runtime = plan_singbox_runtime(
        document,
        nodes[0],
        routing=RoutingSettings(mode="global", tun_default_outbound="proxy"),
    ).singbox_config

    proxy_dns = next(item for item in runtime["dns"]["servers"] if item.get("tag") == "proxy-dns")
    assert proxy_dns["server"] == "10.8.0.1"


def test_awg_runtime_keeps_configured_doh_when_profile_has_no_dns() -> None:
    nodes, errors = parse_links_text(
        """
        [Interface]
        PrivateKey = private-key=
        Address = 10.8.0.2/32
        Jc = 4
        Jmin = 40
        Jmax = 70

        [Peer]
        PublicKey = public-key=
        AllowedIPs = 0.0.0.0/0
        Endpoint = 203.0.113.10:51820
        """
    )

    assert errors == []
    document = parse_singbox_document(Path("default.json"), json.dumps(_base_config()))
    runtime = plan_singbox_runtime(
        document,
        nodes[0],
        routing=RoutingSettings(mode="global", tun_default_outbound="proxy"),
    ).singbox_config

    proxy_dns = next(item for item in runtime["dns"]["servers"] if item.get("tag") == "proxy-dns")
    assert proxy_dns["server"] == "cloudflare-dns.com"
    assert proxy_dns["type"] == "https"


def test_plain_wireguard_runtime_keeps_configured_doh_for_public_profile_dns() -> None:
    nodes, errors = parse_links_text(
        """
        [Interface]
        PrivateKey = private-key=
        Address = 10.8.0.2/32
        DNS = 9.9.9.9, 1.1.1.1

        [Peer]
        PublicKey = public-key=
        AllowedIPs = 0.0.0.0/0
        Endpoint = 203.0.113.10:51820
        """
    )

    assert errors == []
    document = parse_singbox_document(Path("default.json"), json.dumps(_base_config()))
    runtime = plan_singbox_runtime(
        document,
        nodes[0],
        routing=RoutingSettings(mode="global", tun_default_outbound="proxy"),
    ).singbox_config

    proxy_dns = [
        item
        for item in runtime["dns"]["servers"]
        if str(item.get("tag") or "").startswith("proxy-dns")
    ]
    assert [item["server"] for item in proxy_dns] == ["cloudflare-dns.com", "dns.google"]


def test_custom_proxy_dns_wins_over_private_awg_profile_dns() -> None:
    nodes, errors = parse_links_text(
        """
        [Interface]
        PrivateKey = private-key=
        Address = 10.8.0.2/32
        DNS = 10.8.0.1
        Jc = 4
        Jmin = 40
        Jmax = 70

        [Peer]
        PublicKey = public-key=
        AllowedIPs = 0.0.0.0/0
        Endpoint = 203.0.113.10:51820
        """
    )

    assert errors == []
    document = parse_singbox_document(Path("default.json"), json.dumps(_base_config()))
    runtime = plan_singbox_runtime(
        document,
        nodes[0],
        routing=RoutingSettings(
            mode="global",
            tun_default_outbound="proxy",
            dns_proxy_server="dns.quad9.net",
            dns_proxy_servers=["dns.quad9.net"],
            dns_proxy_type="https",
        ),
    ).singbox_config

    proxy_dns = next(item for item in runtime["dns"]["servers"] if item.get("tag") == "proxy-dns")
    assert proxy_dns["server"] == "dns.quad9.net"
    assert proxy_dns["type"] == "https"


def test_awg_validation_rejects_runtime_only_amnezia_errors() -> None:
    nodes, errors = parse_links_text(
        """
        [Interface]
        PrivateKey = private-key=
        Address = 10.8.0.2/32
        Jc = invalid
        Jmin = 70
        Jmax = 40
        I1 = <b 0xabc>

        [Peer]
        PublicKey = public-key=
        AllowedIPs = 0.0.0.0/0
        Endpoint = 203.0.113.10:51820
        """
    )

    assert errors == []
    assert "`jc`" in str(validate_node_outbound(nodes[0]))

    endpoint = nodes[0].outbound["singbox"]
    endpoint["amnezia"]["jc"] = 4
    assert "I1" in str(validate_node_outbound(nodes[0]))

    endpoint["amnezia"]["i1"] = "<b 0xabcd>"
    assert "jmin" in str(validate_node_outbound(nodes[0]))

    endpoint["amnezia"]["jmin"] = 40
    endpoint["amnezia"]["h1"] = "100-200"
    assert validate_node_outbound(nodes[0]) is None

    endpoint["amnezia"]["h1"] = "invalid"
    assert "`h1`" in str(validate_node_outbound(nodes[0]))


def test_wireguard_config_supports_multiple_peers() -> None:
    nodes, errors = parse_links_text(
        """
        [Interface]
        PrivateKey = private-key=
        Address = 10.0.0.2
        ListenPort = 51821
        UDPTimeout = 4m
        Workers = 2
        PreallocatedBuffersPerPool = 64
        DisablePauses = true

        [Peer]
        PublicKey = first-public-key=
        AllowedIPs = 10.1.0.0/16
        Endpoint = first.example.com:51820

        [Peer]
        PublicKey = second-public-key=
        PresharedKey = shared-key=
        AllowedIPs = 10.2.0.1
        Endpoint = [2001:db8::1]:51822
        """
    )

    assert errors == []
    outbound = build_singbox_outbound(nodes[0], tag="proxy")
    assert outbound["listen_port"] == 51821
    assert outbound["address"] == ["10.0.0.2/32"]
    assert outbound["udp_timeout"] == "4m"
    assert outbound["workers"] == 2
    assert outbound["preallocated_buffers_per_pool"] == 64
    assert outbound["disable_pauses"] is True
    assert len(outbound["peers"]) == 2
    assert outbound["peers"][1]["address"] == "2001:db8::1"
    assert outbound["peers"][1]["allowed_ips"] == ["10.2.0.1/32"]
    assert outbound["peers"][1]["pre_shared_key"] == "shared-key="


def test_wireguard_uri_imports_singbox_extended_userspace_options() -> None:
    nodes, errors = parse_links_text(
        "wireguard://private-key%3D@wg.example.com:51820"
        "?public_key=public-key%3D&address=10.0.0.2%2F32"
        "&udp_timeout=3m&workers=4&preallocated_buffers_per_pool=128"
        "&disable_pauses=true#Extended-WG"
    )

    assert errors == []
    endpoint = build_singbox_outbound(nodes[0], tag="proxy")
    assert endpoint["type"] == "wireguard"
    assert endpoint["system"] is False
    assert endpoint["udp_timeout"] == "3m"
    assert endpoint["workers"] == 4
    assert endpoint["preallocated_buffers_per_pool"] == 128
    assert endpoint["disable_pauses"] is True


def test_cloudflare_wireguard_reserved_config_uses_native_warp_endpoint() -> None:
    nodes, errors = parse_links_text(
        """
        [Interface]
        PrivateKey = private-key=
        Address = 172.16.0.2
        Reserved = DlSc

        [Peer]
        PublicKey = public-key=
        AllowedIPs = 0.0.0.0/0, ::/0
        Endpoint = engage.cloudflareclient.com:2408
        PersistentKeepalive = 25
        """
    )

    assert errors == []
    outbound = build_singbox_outbound(nodes[0], tag="proxy")
    assert nodes[0].scheme == "warp"
    assert outbound["type"] == "warp"
    assert "reserved" not in outbound
    assert outbound["persistent_keepalive_interval"] == 25
    assert outbound["profile"]["private_key"] == "private-key="


def test_legacy_wireguard_outbound_json_is_migrated_to_the_endpoint_schema() -> None:
    nodes, errors = parse_links_text(
        json.dumps(
            {
                "type": "wireguard",
                "tag": "proxy",
                "server": "203.0.113.9",
                "server_port": 51820,
                "private_key": "private-key=",
                "peer_public_key": "public-key=",
                "local_address": ["10.7.0.2/32"],
                "mtu": 1408,
            }
        )
    )

    assert errors == []
    assert validate_node_outbound(nodes[0]) is None
    endpoint = nodes[0].outbound["singbox"]
    assert endpoint["address"] == ["10.7.0.2/32"]
    assert endpoint["peers"][0]["address"] == "203.0.113.9"
    assert endpoint["peers"][0]["public_key"] == "public-key="
    assert "server" not in endpoint


def test_warp_outbound_is_migrated_into_the_endpoints_section() -> None:
    nodes, errors = parse_links_text(
        json.dumps(
            {
                "protocol": "singbox_config",
                "singbox_config": {
                    "outbounds": [
                        {
                            "type": "warp",
                            "tag": "proxy",
                            "profile": {"detour": "direct", "private_key": "private-key="},
                        },
                        {"type": "direct", "tag": "direct"},
                    ]
                },
            }
        )
    )

    assert errors == []
    config = nodes[0].outbound["singbox_config"]
    assert [item["type"] for item in config["outbounds"]] == ["direct"]
    assert config["endpoints"][0]["type"] == "warp"


def test_wireguard_config_with_bracketless_ipv6_endpoint_still_imports() -> None:
    nodes, errors = parse_links_text(
        """
        [Interface]
        PrivateKey = private-key=
        Address = 172.16.0.2

        [Peer]
        PublicKey = public-key=
        AllowedIPs = 0.0.0.0/0, ::/0
        Endpoint = 2606:4700:d0::a
        """
    )

    assert errors == []
    endpoint = build_singbox_outbound(nodes[0], tag="proxy")
    assert endpoint["peers"][0]["address"] == "2606:4700:d0::a"
    assert endpoint["peers"][0]["port"] == 51820


def test_saved_wireguard_endpoint_is_normalized_again_before_runtime() -> None:
    nodes, errors = parse_links_text(
        json.dumps(
            {
                "type": "wireguard",
                "address": ["172.16.0.2", "2606:4700:110::2"],
                "private_key": "private-key=",
                "peers": [
                    {
                        "address": "162.159.192.1",
                        "port": 2408,
                        "public_key": "public-key=",
                        "allowed_ips": ["0.0.0.0", "::"],
                    }
                ],
            }
        )
    )

    assert errors == []
    outbound = build_singbox_outbound(nodes[0], tag="proxy")
    assert outbound["address"] == ["172.16.0.2/32", "2606:4700:110::2/128"]
    assert outbound["peers"][0]["allowed_ips"] == ["0.0.0.0/32", "::/128"]


def test_tuic_builds_native_proxy_runtime_without_xray_sidecar() -> None:
    nodes, errors = parse_links_text(
        "tuic://00000000-0000-0000-0000-000000000000:password@example.com:443"
        "?allow_insecure=1#tuic-proxy"
    )
    assert errors == []

    document = parse_singbox_document(Path("default.json"), json.dumps(_base_config()))
    plan = plan_singbox_runtime(
        document,
        nodes[0],
        routing=RoutingSettings(mode="global", tun_default_outbound="proxy"),
        tun_mode=False,
    )

    assert plan.xray_sidecar is None
    assert not any(inbound.get("type") == "tun" for inbound in plan.singbox_config["inbounds"])
    proxy = next(outbound for outbound in plan.singbox_config["outbounds"] if outbound.get("tag") == "proxy")
    assert proxy["type"] == "tuic"


def test_insecure_trojan_builds_native_proxy_runtime_without_xray_sidecar() -> None:
    nodes, errors = parse_links_text(
        "trojan://password@example.com:443?security=tls&sni=example.com&allowInsecure=1#trojan-proxy"
    )
    assert errors == []

    document = parse_singbox_document(Path("default.json"), json.dumps(_base_config()))
    plan = plan_singbox_runtime(
        document,
        nodes[0],
        routing=RoutingSettings(mode="global", tun_default_outbound="proxy"),
        tun_mode=False,
    )

    assert plan.xray_sidecar is None
    proxy = next(outbound for outbound in plan.singbox_config["outbounds"] if outbound.get("tag") == "proxy")
    assert proxy["type"] == "trojan"
    assert proxy["tls"]["insecure"] is True


def test_xray_verify_peer_names_remain_a_comma_separated_string() -> None:
    nodes, errors = parse_links_text(
        "trojan://password@example.com:443?security=tls&vcn=one.example.com,two.example.com#trojan-vcn"
    )

    assert errors == []
    tls = nodes[0].outbound["streamSettings"]["tlsSettings"]
    assert tls["verifyPeerCertByName"] == "one.example.com,two.example.com"


def test_full_provider_config_is_preserved_for_tun_runtime() -> None:
    provider_config = {
        "inbounds": [{"type": "mixed", "tag": "mixed-in", "listen_port": 7897}],
        "outbounds": [
            {"type": "direct", "tag": "direct"},
            {"type": "urltest", "tag": "auto", "outbounds": ["direct"], "use_all_providers": True},
        ],
        "providers": [
            {
                "type": "remote",
                "tag": "sub",
                "url": "https://example.com/sub.txt",
                "user_agent": "sing-box",
            }
        ],
        "route": {"final": "auto"},
        "dns": {"servers": [{"tag": "bootstrap-dns", "type": "udp", "server": "1.1.1.1"}]},
    }
    nodes, errors = parse_links_text(json.dumps(provider_config))
    assert errors == []
    assert nodes[0].scheme == "singbox_config"

    document = parse_singbox_document(Path("default.json"), json.dumps(_base_config()))
    planned = plan_singbox_runtime(
        document,
        nodes[0],
        routing=RoutingSettings(mode="global", tun_default_outbound="proxy"),
    ).singbox_config

    assert planned["providers"] == provider_config["providers"]
    assert any(outbound.get("tag") == "proxy" for outbound in planned["outbounds"])


def test_full_wireguard_urltest_config_is_imported_as_one_auto_profile() -> None:
    profile = {
        "remarks": "AUTO WireGuard",
        "endpoints": [
            {
                "type": "wireguard",
                "tag": "wg-one",
                "system": True,
                "address": ["10.0.0.2"],
                "private_key": "private-one=",
                "peers": [
                    {
                        "address": "one.example.com",
                        "port": 51820,
                        "public_key": "public-one=",
                        "allowed_ips": ["0.0.0.0/0", "::/0"],
                    }
                ],
            },
            {
                "type": "wireguard",
                "tag": "wg-two",
                "address": ["10.0.1.2/32"],
                "private_key": "private-two=",
                "peers": [
                    {
                        "address": "198.51.100.20",
                        "port": 51821,
                        "public_key": "public-two=",
                        "allowed_ips": ["0.0.0.0/0"],
                    }
                ],
            },
        ],
        "outbounds": [
            {
                "type": "urltest",
                "tag": "auto-wg",
                "outbounds": ["wg-one", "wg-two"],
                "url": "https://www.gstatic.com/generate_204",
                "interval": "30s",
                "tolerance": 50,
            },
            {"type": "direct", "tag": "direct"},
        ],
        "route": {"final": "auto-wg"},
    }

    nodes, errors = parse_links_text(json.dumps(profile))

    assert errors == []
    assert len(nodes) == 1
    node = nodes[0]
    assert node.scheme == "auto"
    assert node.name == "AUTO WireGuard"
    assert node.server == "one.example.com"
    assert node.description == "Автовыбор лучших серверов"
    stored = node.outbound["singbox_config"]
    assert "remarks" not in stored
    assert [endpoint["tag"] for endpoint in stored["endpoints"]] == ["wg-one", "wg-two"]
    assert all(endpoint["system"] is False for endpoint in stored["endpoints"])

    document = parse_singbox_document(Path("default.json"), json.dumps(_base_config()))
    planned = plan_singbox_runtime(
        document,
        node,
        routing=RoutingSettings(mode="global", tun_default_outbound="proxy"),
    ).singbox_config
    auto = next(item for item in planned["outbounds"] if item.get("tag") == "auto-wg")
    assert auto["outbounds"] == ["wg-one", "wg-two"]
    assert next(item for item in planned["outbounds"] if item.get("tag") == "proxy")["outbounds"] == ["auto-wg"]
    assert planned["route"]["final"] == "proxy"
    assert all(endpoint["domain_resolver"] == "bootstrap-dns" for endpoint in planned["endpoints"])


def test_legacy_wireguard_outbounds_are_migrated_without_breaking_urltest_tags() -> None:
    profile = {
        "outbounds": [
            {
                "type": "wireguard",
                "tag": "legacy-one",
                "server": "192.0.2.10",
                "server_port": 51820,
                "local_address": ["10.20.0.2"],
                "private_key": "private-one=",
                "peer_public_key": "public-one=",
            },
            {
                "type": "wireguard",
                "tag": "legacy-two",
                "server": "192.0.2.20",
                "server_port": 51821,
                "local_address": ["10.21.0.2/32"],
                "private_key": "private-two=",
                "peer_public_key": "public-two=",
            },
            {
                "type": "urltest",
                "tag": "auto",
                "outbounds": ["legacy-one", "legacy-two"],
            },
        ],
        "route": {"final": "auto"},
    }

    nodes, errors = parse_links_text(json.dumps(profile))

    assert errors == []
    assert len(nodes) == 1
    assert nodes[0].scheme == "auto"
    config = nodes[0].outbound["singbox_config"]
    assert [endpoint["tag"] for endpoint in config["endpoints"]] == ["legacy-one", "legacy-two"]
    assert not any(item.get("type") == "wireguard" for item in config["outbounds"])
    auto = next(item for item in config["outbounds"] if item.get("tag") == "auto")
    assert auto["outbounds"] == ["legacy-one", "legacy-two"]
    assert config["endpoints"][0]["address"] == ["10.20.0.2/32"]
    assert config["endpoints"][0]["peers"][0]["address"] == "192.0.2.10"


def test_clash_wireguard_urltest_group_adds_auto_profile() -> None:
    nodes, errors = parse_links_text(
        """
proxies:
  - name: WG One
    type: wireguard
    server: 192.0.2.10
    port: 51820
    ip: 10.0.0.2/32
    private-key: private-one=
    public-key: public-one=
    allowed-ips: [0.0.0.0/0]
  - name: WG Two
    type: wireguard
    server: 192.0.2.20
    port: 51821
    ip: 10.0.1.2/32
    private-key: private-two=
    public-key: public-two=
    allowed-ips: [0.0.0.0/0]
proxy-groups:
  - name: Best WG
    type: url-test
    proxies: [WG One, WG Two]
    url: https://www.gstatic.com/generate_204
    interval: 60
"""
    )

    assert errors == []
    assert [node.scheme for node in nodes] == ["wireguard", "wireguard", "auto"]
    auto_node = nodes[-1]
    assert auto_node.name == "Best WG"
    config = auto_node.outbound["singbox_config"]
    assert len(config["endpoints"]) == 2
    urltest = next(item for item in config["outbounds"] if item.get("type") == "urltest")
    assert urltest["outbounds"] == ["wg-auto-1-1", "wg-auto-1-2"]
    assert urltest["interval"] == "60s"


def test_runtime_omits_deprecated_independent_dns_cache_option() -> None:
    node = parse_single(
        "vless://00000000-0000-0000-0000-000000000000@example.com:443#latest-core"
    )
    document = parse_singbox_document(Path("default.json"), json.dumps(_base_config()))

    runtime = plan_singbox_runtime(
        document,
        node,
        routing=RoutingSettings(mode="global", tun_default_outbound="proxy"),
    ).singbox_config

    assert "independent_cache" not in runtime["dns"]


def test_grpc_authority_without_tls_is_not_silently_discarded() -> None:
    nodes, errors = parse_links_text(
        "vless://00000000-0000-0000-0000-000000000000@example.com:443"
        "?type=grpc&serviceName=lumen&authority=legacy.example.com#grpc"
    )

    assert errors == []
    with pytest.raises(ValueError, match="authority"):
        build_singbox_outbound(nodes[0], tag="proxy")


def test_vless_native_outbound_states_xudp_packet_encoding() -> None:
    node = parse_single(
        "vless://00000000-0000-0000-0000-000000000000@example.com:443?type=tcp"
    )

    assert build_singbox_outbound(node)["packet_encoding"] == "xudp"


def test_reality_without_fingerprint_uses_interoperable_utls_default() -> None:
    node = parse_single(
        "vless://00000000-0000-0000-0000-000000000000@example.com:443"
        "?type=tcp&security=reality&sni=www.example.com"
        "&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=0123456789abcdef"
    )

    assert build_singbox_outbound(node)["tls"]["utls"] == {
        "enabled": True,
        "fingerprint": "chrome",
    }


def test_tls_certificate_pin_alias_is_preserved_and_normalized() -> None:
    node = parse_single(
        "vless://00000000-0000-0000-0000-000000000000@example.com:443"
        f"?type=tcp&security=tls&pcs={'ab' * 32}"
    )

    assert build_singbox_outbound(node)["tls"]["certificate_public_key_sha256"] == [
        base64.b64encode(bytes.fromhex("ab" * 32)).decode("ascii")
    ]


def test_ws_early_data_query_is_preserved() -> None:
    node = parse_single(
        "vless://00000000-0000-0000-0000-000000000000@example.com:443"
        "?type=ws&security=tls&path=%2Fws&ed=2048&eh=Sec-WebSocket-Protocol"
    )

    assert build_singbox_outbound(node)["transport"] == {
        "type": "ws",
        "path": "/ws",
        "max_early_data": 2048,
        "early_data_header_name": "Sec-WebSocket-Protocol",
    }


def test_ws_early_data_embedded_in_path_is_normalized() -> None:
    node = parse_single(
        "vless://00000000-0000-0000-0000-000000000000@example.com:443"
        "?type=ws&security=tls&path=%2Fproxy%3Fed%3D3072"
    )

    assert build_singbox_outbound(node)["transport"] == {
        "type": "ws",
        "path": "/proxy",
        "max_early_data": 3072,
        "early_data_header_name": "Sec-WebSocket-Protocol",
    }


def test_https_proxy_keeps_tls_when_converted_to_singbox() -> None:
    outbound = build_singbox_outbound(parse_single("https://user:pass@example.com:8443"))

    assert outbound["type"] == "http"
    assert outbound["username"] == "user"
    assert outbound["tls"] == {"enabled": True, "server_name": "example.com"}


def test_sip003_shadowsocks_plugin_is_split_from_options() -> None:
    credentials = base64.urlsafe_b64encode(b"aes-256-gcm:secret").decode("ascii").rstrip("=")
    node = parse_single(
        f"ss://{credentials}@example.com:8388?plugin=v2ray-plugin%3Btls%3Bhost%3Dcdn.example.com"
    )
    outbound = build_singbox_outbound(node)

    assert outbound["plugin"] == "v2ray-plugin"
    assert outbound["plugin_opts"] == "tls;host=cdn.example.com"


def test_xhttp_download_settings_use_exact_extended_core_schema() -> None:
    node = parse_single(
        "vless://00000000-0000-0000-0000-000000000000@example.com:443"
        "?type=xhttp&security=tls&path=%2Fupload&extra="
        + quote(
            json.dumps(
                {
                    "noSSEHeader": True,
                    "sessionIDLength": "12-18",
                    "downloadSettings": {
                        "address": "download.example.com",
                        "port": 8443,
                        "streamSettings": {
                            "security": "tls",
                            "tlsSettings": {"serverName": "cdn.example.com"},
                            "xhttpSettings": {"path": "/download", "xPaddingBytes": "50-100"},
                        },
                    },
                },
                separators=(",", ":"),
            ),
            safe="",
        )
    )
    transport = build_singbox_outbound(node)["transport"]

    assert "download_settings" not in transport
    assert transport["no_sse_header"] is True
    assert transport["session_id_length"] == "12-18"
    assert transport["download"]["server"] == "download.example.com"
    assert transport["download"]["server_port"] == 8443
    assert transport["download"]["path"] == "/download"
    assert transport["download"]["tls"]["server_name"] == "cdn.example.com"


def test_unknown_xray_transport_fails_instead_of_becoming_raw_tcp() -> None:
    node = Node(
        scheme="vless",
        outbound={
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": "example.com",
                    "port": 443,
                    "users": [{"id": "00000000-0000-0000-0000-000000000000"}],
                }]
            },
            "streamSettings": {"network": "future-transport", "security": "none"},
        },
    )

    with pytest.raises(ValueError, match="future-transport"):
        build_singbox_outbound(node)


def test_vless_vision_is_kept_for_grpc_reality_outbound() -> None:
    nodes, errors = parse_links_text(
        "vless://00000000-0000-0000-0000-000000000000@example.com:443"
        "?type=grpc&security=reality&flow=xtls-rprx-vision&sni=example.com"
        "&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=0123456789abcdef#grpc-vision"
    )

    assert errors == []
    outbound = build_singbox_outbound(nodes[0], tag="proxy")

    assert outbound["transport"]["type"] == "grpc"
    assert outbound["tls"]["reality"]["enabled"] is True
    assert outbound["flow"] == "xtls-rprx-vision"


def test_vless_encryption_keeps_vision_on_framed_transport() -> None:
    nodes, errors = parse_links_text(
        "vless://00000000-0000-0000-0000-000000000000@example.com:443"
        "?type=grpc&security=reality&flow=xtls-rprx-vision"
        "&encryption=mlkem768x25519plus.native.0rtt.key&sni=example.com"
        "&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=0123456789abcdef"
    )

    assert errors == []
    assert build_singbox_outbound(nodes[0])["flow"] == "xtls-rprx-vision"


@pytest.mark.parametrize("tun_mode", [False, True])
def test_vless_vision_is_kept_for_xhttp_reality_runtime(tun_mode: bool) -> None:
    nodes, errors = parse_links_text(
        "vless://00000000-0000-0000-0000-000000000000@example.com:443"
        "?type=xhttp&security=reality&flow=xtls-rprx-vision&sni=example.com"
        "&path=%2Flumen&mode=auto&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "&sid=0123456789abcdef#xhttp-vision"
    )

    assert errors == []
    document = parse_singbox_document(Path("default.json"), json.dumps(_base_config()))
    runtime = plan_singbox_runtime(
        document,
        nodes[0],
        routing=RoutingSettings(mode="global"),
        tun_mode=tun_mode,
    ).singbox_config
    outbound = next(
        item for item in runtime["outbounds"] if item.get("tag") == "proxy"
    )

    assert outbound["flow"] == "xtls-rprx-vision"
    assert outbound["transport"]["type"] == "xhttp"
    assert outbound["tls"]["reality"]["enabled"] is True


def test_vless_vision_is_kept_for_raw_reality_outbound() -> None:
    nodes, errors = parse_links_text(
        "vless://00000000-0000-0000-0000-000000000000@example.com:443"
        "?type=tcp&security=reality&flow=xtls-rprx-vision&sni=example.com"
        "&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=0123456789abcdef#tcp-vision"
    )

    assert errors == []
    outbound = build_singbox_outbound(nodes[0], tag="proxy")

    assert outbound["flow"] == "xtls-rprx-vision"
    assert "transport" not in outbound
    assert outbound["tls"]["reality"]["enabled"] is True


def test_vless_encryption_is_preserved_for_singbox_outbound() -> None:
    encryption = "mlkem768x25519plus.native.0rtt.test_key-with.dots"
    nodes, errors = parse_links_text(
        "vless://00000000-0000-0000-0000-000000000000@example.com:8443"
        f"?encryption={encryption}&type=tcp&flow=xtls-rprx-vision"
        "&security=reality&sni=www.bing.com&fp=edge"
        "&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=0123456789abcdef#encrypted-vision"
    )

    assert errors == []
    outbound = build_singbox_outbound(nodes[0], tag="proxy")

    assert outbound["encryption"] == encryption
    assert outbound["flow"] == "xtls-rprx-vision"
    assert outbound["tls"]["reality"]["enabled"] is True


def test_vless_vision_without_tls_or_encryption_is_removed() -> None:
    nodes, errors = parse_links_text(
        "vless://00000000-0000-0000-0000-000000000000@example.com:443"
        "?type=tcp&security=none&flow=xtls-rprx-vision#plain-vision"
    )

    assert errors == []
    outbound = build_singbox_outbound(nodes[0], tag="proxy")

    assert "flow" not in outbound
    assert "tls" not in outbound


def test_imported_singbox_config_keeps_transport_vless_vision_with_tls() -> None:
    payload = _base_config()
    payload["outbounds"][0] = {
        "type": "vless",
        "tag": "proxy",
        "server": "example.com",
        "server_port": 443,
        "uuid": "00000000-0000-0000-0000-000000000000",
        "flow": "xtls-rprx-vision",
        "tls": {"enabled": True},
        "transport": {"type": "grpc", "service_name": "lumen"},
    }
    node = Node(
        scheme="singbox_config",
        outbound={"protocol": "singbox_config", "singbox_config": payload},
    )

    document = parse_singbox_document(Path("vision.json"), json.dumps(payload))
    plan = plan_singbox_runtime(document, node, tun_mode=False)
    proxy = next(item for item in plan.singbox_config["outbounds"] if item.get("tag") == "proxy")

    assert proxy["flow"] == "xtls-rprx-vision"


def test_imported_singbox_grpc_authority_is_mapped_without_losing_semantics() -> None:
    payload = _base_config()
    payload["outbounds"][0] = {
        "type": "vless",
        "tag": "proxy",
        "server": "example.com",
        "server_port": 443,
        "uuid": "00000000-0000-0000-0000-000000000000",
        "tls": {"enabled": True},
        "transport": {
        "type": "grpc",
        "service_name": "lumen",
        "authority": "legacy.example.com",
        },
    }
    node = Node(
        scheme="singbox_config",
        outbound={
            "protocol": "singbox_config",
            "singbox_config": payload,
        },
    )

    document = parse_singbox_document(Path("authority.json"), json.dumps(payload))
    plan = plan_singbox_runtime(
        document,
        node,
        tun_mode=False,
    )

    proxy = next(
        item for item in plan.singbox_config["outbounds"] if item.get("tag") == "proxy"
    )
    assert "authority" not in proxy["transport"]
    assert proxy["tls"]["server_name"] == "legacy.example.com"


@pytest.mark.parametrize(
    ("transport", "message"),
    [
        ({"type": "grpc", "multi_mode": True}, "multi-mode"),
        ({"type": "httpupgrade", "path": "/up?ed=2048"}, "early-data"),
        ({"type": "quic", "security": "aes-128-gcm"}, "QUIC"),
    ],
)
def test_native_transport_semantics_are_rejected_instead_of_silently_removed(
    transport: dict,
    message: str,
) -> None:
    node = Node(
        scheme="vless",
        server="example.com",
        port=443,
        outbound={
            "protocol": "vless",
            "singbox": {
                "type": "vless",
                "server": "example.com",
                "server_port": 443,
                "uuid": "00000000-0000-0000-0000-000000000000",
                "transport": transport,
            },
        },
    )

    with pytest.raises(ValueError, match=message):
        build_singbox_outbound(node)


def test_native_reality_extension_is_not_silently_removed() -> None:
    node = Node(
        scheme="vless",
        server="example.com",
        port=443,
        outbound={
            "protocol": "vless",
            "singbox": {
                "type": "vless",
                "server": "example.com",
                "server_port": 443,
                "uuid": "00000000-0000-0000-0000-000000000000",
                "tls": {
                    "enabled": True,
                    "reality": {
                        "enabled": True,
                        "mldsa65Verify": "post-quantum-key",
                    },
                },
            },
        },
    )

    with pytest.raises(ValueError, match="ML-DSA"):
        build_singbox_outbound(node)


def test_xhttp_download_detour_is_migrated_to_download_block() -> None:
    node = Node(
        scheme="vless",
        server="example.com",
        port=443,
        outbound={
            "protocol": "vless",
            "singbox": {
                "type": "vless",
                "server": "example.com",
                "server_port": 443,
                "uuid": "00000000-0000-0000-0000-000000000000",
                "transport": {
                    "type": "xhttp",
                    "download_detour": "download-direct",
                    "download": {
                        "server": "download.example.com",
                        "server_port": 443,
                    },
                },
            },
        },
    )

    transport = build_singbox_outbound(node)["transport"]

    assert "download_detour" not in transport
    assert transport["download"]["detour"] == "download-direct"


def test_saved_native_aliases_are_migrated_without_reimport() -> None:
    node = Node(
        scheme="vless",
        server="example.com",
        port=443,
        outbound={
            "protocol": "vless",
            "singbox": {
                "type": "vless",
                "server": "example.com",
                "server_port": 443,
                "uuid": "00000000-0000-0000-0000-000000000000",
                "tls": {
                    "enabled": True,
                    "serverName": "cdn.example.com",
                    "pinnedPeerCertSha256": "cd" * 32,
                },
                "transport": {
                    "type": "ws",
                    "path": "/proxy?ed=4096",
                    "maxEarlyData": "4096",
                    "earlyDataHeaderName": "Sec-WebSocket-Protocol",
                },
            },
        },
    )

    outbound = build_singbox_outbound(node)
    assert outbound["tls"]["server_name"] == "cdn.example.com"
    assert "serverName" not in outbound["tls"]
    assert outbound["tls"]["certificate_public_key_sha256"] == [
        base64.b64encode(bytes.fromhex("cd" * 32)).decode("ascii")
    ]
    assert outbound["transport"]["path"] == "/proxy"
    assert outbound["transport"]["max_early_data"] == 4096
    assert "maxEarlyData" not in outbound["transport"]


def test_saved_legacy_xhttp_download_key_is_migrated() -> None:
    node = Node(
        scheme="vless",
        server="example.com",
        port=443,
        outbound={
            "protocol": "vless",
            "singbox": {
                "type": "vless",
                "server": "example.com",
                "server_port": 443,
                "uuid": "00000000-0000-0000-0000-000000000000",
                "transport": {
                    "type": "xhttp",
                    "x_padding_bytes": "100-1000",
                    "download_settings": {
                        "server": "download.example.com",
                        "server_port": 8443,
                        "path": "/download",
                        "x_padding_bytes": "50-100",
                    },
                },
            },
        },
    )

    transport = build_singbox_outbound(node)["transport"]
    assert "download_settings" not in transport
    assert transport["download"]["server"] == "download.example.com"
    assert transport["download"]["server_port"] == 8443
