from __future__ import annotations

import json

import pytest

from xray_fluent.engines.singbox.config_builder import build_singbox_outbound
from xray_fluent.link_parser import parse_links_text, parse_single
from xray_fluent.models import Node
from xray_fluent.qml_app.bridge.node_edit_helpers import (
    build_node_updates,
    load_node_edit_fields,
    new_node_edit_fields,
    normalized_node_export_link,
)


def test_awg_editor_hides_xray_fields_and_updates_native_endpoint() -> None:
    node = Node(
        name="WARP",
        scheme="awg",
        server="engage.cloudflareclient.com",
        port=2408,
        outbound={
            "protocol": "awg",
            "singbox": {
                "type": "wireguard",
                "peers": [{"server": "engage.cloudflareclient.com", "server_port": 2408}],
                "amnezia": {"jc": 4},
            },
        },
    )

    fields = load_node_edit_fields(node)

    assert fields["capabilities"]["nativeSingbox"] is True
    assert fields["capabilities"]["xrayAdvanced"] is False
    assert fields["capabilities"]["identity"] is False
    assert fields["capabilities"]["endpoint"] is True

    updates = build_node_updates(
        node,
        {
            "name": "WARP new",
            "group": "Native",
            "server": "162.159.192.1",
            "port": "2408",
            "uuid": "must-not-be-used",
            "network": "xhttp",
            "security": "reality",
        },
    )

    assert updates["name"] == "WARP new"
    assert updates["server"] == "162.159.192.1"
    assert "settings" not in updates["outbound"]
    assert "streamSettings" not in updates["outbound"]
    peer = updates["outbound"]["singbox"]["peers"][0]
    assert peer["address"] == "162.159.192.1"
    assert peer["port"] == 2408
    assert "server" not in peer
    assert "server_port" not in peer


def test_singbox_config_editor_is_metadata_only() -> None:
    node = Node(
        name="Full config",
        scheme="singbox_config",
        server="",
        port=0,
        outbound={"protocol": "singbox_config", "singbox": {"outbounds": []}},
    )

    fields = load_node_edit_fields(node)
    updates = build_node_updates(node, {"name": "Renamed", "group": "Configs", "server": "bad", "port": "443"})

    assert fields["capabilities"]["readOnlyConfig"] is True
    assert fields["capabilities"]["endpoint"] is False
    assert "tags" not in fields
    assert updates == {
        "name": "Renamed",
        "group": "Configs",
        "outbound": {"protocol": "singbox_config", "singbox": {"outbounds": []}},
    }


def test_vless_editor_keeps_advanced_fields() -> None:
    node = Node(
        name="VLESS",
        scheme="vless",
        server="old.example",
        port=443,
        outbound={
            "protocol": "vless",
            "settings": {"vnext": [{"address": "old.example", "port": 443, "users": [{"id": "old"}]}]},
            "streamSettings": {"network": "tcp", "security": "none"},
        },
    )

    fields = load_node_edit_fields(node)

    assert fields["capabilities"]["xrayAdvanced"] is True
    assert fields["capabilities"]["identity"] is True

    updates = build_node_updates(
        node,
        {
            "name": "VLESS new",
            "group": "Default",
            "server": "new.example",
            "port": "8443",
            "uuid": "new-id",
            "encryption": "none",
            "flow": "",
            "network": "xhttp",
            "security": "tls",
            "sni": "front.example",
            "fingerprint": "edge",
        },
    )

    outbound = updates["outbound"]
    user = outbound["settings"]["vnext"][0]["users"][0]
    assert updates["server"] == "new.example"
    assert updates["port"] == 8443
    assert user["id"] == "new-id"
    assert outbound["streamSettings"]["network"] == "xhttp"
    assert outbound["streamSettings"]["tlsSettings"]["serverName"] == "front.example"


def test_vless_ws_transport_and_tls_survive_link_reparse() -> None:
    node = parse_single("vless://old-id@old.example:443?encryption=none&type=tcp#VLESS")

    updates = build_node_updates(
        node,
        {
            "name": "VLESS WS",
            "server": "new.example",
            "port": "8443",
            "uuid": "new-id",
            "encryption": "none",
            "network": "ws",
            "transportPath": "/socket",
            "transportHost": "cdn.example",
            "security": "tls",
            "sni": "front.example",
            "fingerprint": "chrome",
            "alpn": "h2, http/1.1",
            "allowInsecure": True,
        },
    )

    reparsed = parse_single(updates["link"])
    assert reparsed.outbound == updates["outbound"]


def test_vless_editor_validates_tls_certificate_pin() -> None:
    node = Node(
        name="VLESS",
        scheme="vless",
        server="example.com",
        port=443,
        outbound={
            "protocol": "vless",
            "settings": {"vnext": [{"address": "example.com", "port": 443, "users": [{"id": "id"}]}]},
            "streamSettings": {"network": "tcp", "security": "tls"},
        },
    )

    with pytest.raises(ValueError, match="64 hex"):
        build_node_updates(node, {"pinnedPeerCertSha256": "not-a-digest"})

    updates = build_node_updates(node, {"pinnedPeerCertSha256": "A" * 64, "security": "tls"})
    assert updates["outbound"]["streamSettings"]["tlsSettings"][
        "pinnedPeerCertSha256"
    ] == "a" * 64


@pytest.mark.parametrize(
    ("link", "required", "forbidden"),
    [
        (
            "trojan://secret@example.com:443?security=tls&sni=front.example#Trojan",
            {"server", "port", "password", "network", "security", "sni"},
            {"uuid", "method", "auth", "privateKey"},
        ),
        (
            "ss://aes-128-gcm:secret@example.com:8388#SS",
            {"server", "port", "method", "password", "plugin"},
            {"uuid", "network", "security", "username"},
        ),
        (
            "socks://user:secret@example.com:1080#SOCKS",
            {"server", "port", "username", "password"},
            {"uuid", "method", "network", "security"},
        ),
        (
            "http://user:secret@example.com:8080#HTTP",
            {"server", "port", "username", "password"},
            {"uuid", "method", "network", "security"},
        ),
        (
            "hysteria://auth@example.com:443?upmbps=50&downmbps=200&sni=front.example#HY",
            {"server", "port", "auth", "upMbps", "downMbps", "sni", "allowInsecure", "alpn"},
            {"uuid", "method", "network", "privateKey"},
        ),
        (
            "hy2://secret@example.com:443?obfs=salamander&obfs-password=mask&sni=front.example#HY2",
            {"server", "port", "password", "obfsType", "obfsPassword", "sni"},
            {"uuid", "method", "network", "privateKey"},
        ),
        (
            "tuic://00000000-0000-0000-0000-000000000000:secret@example.com:443?sni=front.example#TUIC",
            {"server", "port", "uuid", "password", "congestionControl", "udpRelayMode", "zeroRtt", "sni"},
            {"method", "network", "privateKey"},
        ),
        (
            "mierus://user:secret@example.com:27017?transport=TCP&multiplexing=MULTIPLEXING_LOW#Mieru",
            {"server", "port", "serverPorts", "username", "password", "nativeTransport", "multiplexing", "trafficPattern"},
            {"uuid", "method", "security", "privateKey"},
        ),
    ],
)
def test_protocol_editor_exposes_only_supported_fields(
    link: str,
    required: set[str],
    forbidden: set[str],
) -> None:
    node = parse_single(link)
    fields = load_node_edit_fields(node)
    keys = {item["key"] for item in fields["protocolFields"]}

    assert required <= keys
    assert keys.isdisjoint(forbidden)
    assert all(item.get("secret") is not True for item in fields["protocolFields"])


def test_vmess_editor_updates_vmess_only_fields_and_transport() -> None:
    node = Node(
        name="VMess",
        scheme="vmess",
        server="old.example",
        port=443,
        outbound={
            "protocol": "vmess",
            "settings": {
                "vnext": [
                    {
                        "address": "old.example",
                        "port": 443,
                        "users": [{"id": "old-id", "alterId": 0, "security": "auto"}],
                    }
                ]
            },
            "streamSettings": {"network": "tcp", "security": "none"},
        },
    )

    fields = load_node_edit_fields(node)
    keys = {item["key"] for item in fields["protocolFields"]}
    assert {"uuid", "alterId", "vmessSecurity", "network"} <= keys
    assert "flow" not in keys
    assert "encryption" not in keys

    updates = build_node_updates(
        node,
        {
            "server": "new.example",
            "port": "8443",
            "uuid": "new-id",
            "alterId": "4",
            "vmessSecurity": "aes-128-gcm",
            "network": "ws",
            "transportPath": "/vmess",
            "transportHost": "cdn.example",
            "security": "tls",
            "sni": "front.example",
        },
    )

    user = updates["outbound"]["settings"]["vnext"][0]["users"][0]
    stream = updates["outbound"]["streamSettings"]
    assert user == {"id": "new-id", "alterId": 4, "security": "aes-128-gcm"}
    assert stream["wsSettings"] == {"path": "/vmess", "headers": {"Host": "cdn.example"}}
    assert stream["tlsSettings"]["serverName"] == "front.example"


def test_trojan_editor_updates_password_transport_and_persists_share_uri() -> None:
    node = parse_single("trojan://old@example.com:443?security=tls&sni=old.example#Trojan")

    updates = build_node_updates(
        node,
        {
            "name": "Trojan new",
            "server": "new.example",
            "port": "8443",
            "password": "new-secret",
            "network": "grpc",
            "grpcServiceName": "trojan-grpc",
            "security": "tls",
            "sni": "front.example",
        },
    )

    server = updates["outbound"]["settings"]["servers"][0]
    assert server == {"address": "new.example", "port": 8443, "password": "new-secret"}
    assert updates["outbound"]["streamSettings"]["grpcSettings"]["serviceName"] == "trojan-grpc"
    assert updates["link"].startswith("trojan://new-secret@new.example:8443?")
    reparsed = parse_single(updates["link"])
    assert reparsed.outbound == updates["outbound"]
    assert reparsed.name == "Trojan new"


@pytest.mark.parametrize(
    ("link", "changes", "prefix"),
    [
        (
            "trojan://old@example.com:443#Trojan",
            {"password": "p@ss word", "security": "none"},
            "trojan://p%40ss%20word@new.example:8443?",
        ),
        (
            "ss://aes-128-gcm:old@example.com:8388#SS",
            {"method": "chacha20-ietf-poly1305", "password": "new"},
            "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpuZXc@new.example:8443",
        ),
        (
            "socks://old:old@example.com:1080#SOCKS",
            {"username": "new-user", "password": "new-pass"},
            "socks://new-user:new-pass@new.example:8443",
        ),
        (
            "hy2://old@example.com:443?sni=old.example#HY2",
            {"password": "new", "sni": "front.example", "obfsType": "salamander", "obfsPassword": "mask"},
            "hysteria2://new@new.example:8443?",
        ),
        (
            "tuic://00000000-0000-0000-0000-000000000000:old@example.com:443?sni=old.example#TUIC",
            {"password": "new", "sni": "front.example", "zeroRtt": True},
            "tuic://00000000-0000-0000-0000-000000000000:new@new.example:8443?",
        ),
    ],
)
def test_editor_emits_portable_share_uri_not_json(
    link: str,
    changes: dict,
    prefix: str,
) -> None:
    node = parse_single(link)
    updates = build_node_updates(node, {"name": "Shared", "server": "new.example", "port": "8443", **changes})

    assert not updates["link"].startswith("{")
    assert updates["link"].startswith(prefix)
    reparsed = parse_single(updates["link"])
    assert reparsed.outbound == updates["outbound"]
    assert reparsed.name == "Shared"


def test_vmess_editor_emits_vmess_share_uri() -> None:
    node = Node(
        name="VMess",
        scheme="vmess",
        server="old.example",
        port=443,
        outbound={
            "protocol": "vmess",
            "settings": {
                "vnext": [
                    {
                        "address": "old.example",
                        "port": 443,
                        "users": [{"id": "old-id", "alterId": 0, "security": "auto"}],
                    }
                ]
            },
            "streamSettings": {"network": "tcp", "security": "none"},
        },
    )

    updates = build_node_updates(
        node,
        {
            "name": "VMess new",
            "server": "new.example",
            "port": "8443",
            "uuid": "new-id",
            "alterId": "4",
            "vmessSecurity": "aes-128-gcm",
            "network": "ws",
            "transportPath": "/vmess",
            "transportHost": "cdn.example",
            "security": "tls",
            "sni": "front.example",
        },
    )

    assert updates["link"].startswith("vmess://")
    reparsed = parse_single(updates["link"])
    assert reparsed.name == "VMess new"
    assert reparsed.server == "new.example"
    assert reparsed.port == 8443
    assert reparsed.outbound["settings"]["vnext"][0]["users"][0] == {
        "id": "new-id",
        "alterId": 4,
        "security": "aes-128-gcm",
    }
    stream = reparsed.outbound["streamSettings"]
    assert stream["network"] == "ws"
    assert stream["security"] == "tls"
    assert stream["wsSettings"] == {"path": "/vmess", "headers": {"Host": "cdn.example"}}
    assert stream["tlsSettings"]["serverName"] == "front.example"


def test_native_only_protocols_keep_canonical_json_link() -> None:
    node = Node(
        name="MASQUE",
        scheme="masque",
        server="masque.example",
        port=443,
        outbound={
            "protocol": "masque",
            "singbox": {
                "type": "masque",
                "server": "masque.example",
                "server_port": 443,
                "profile": {"detour": "direct"},
            },
        },
    )

    updates = build_node_updates(node, {"name": "MASQUE new", "server": "new.example", "port": "8443"})

    assert updates["link"].startswith("{")
    assert parse_single(updates["link"]).outbound == updates["outbound"]


def test_export_normalizes_json_vless_to_share_uri() -> None:
    payload = {
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": "example.com",
                "port": 443,
                "users": [{"id": "json-id", "encryption": "none"}],
            }],
        },
        "streamSettings": {
            "network": "ws",
            "security": "tls",
            "tlsSettings": {"serverName": "front.example"},
            "wsSettings": {"path": "/socket", "headers": {"Host": "cdn.example"}},
        },
    }
    node = Node(
        name="Imported JSON",
        scheme="vless",
        server="example.com",
        port=443,
        link=json.dumps(payload),
        outbound=payload,
    )

    exported = normalized_node_export_link(node)

    assert exported.startswith("vless://json-id@example.com:443?")
    assert not exported.startswith("{")
    reparsed = parse_single(exported)
    assert reparsed.outbound == payload


@pytest.mark.parametrize(
    ("protocol", "native", "prefix"),
    [
        ("hysteria", {"type": "hysteria", "server": "example.com", "server_port": 443, "auth_str": "auth"}, "hysteria://"),
        ("mieru", {"type": "mieru", "server": "example.com", "server_port": 443, "username": "u", "password": "p"}, "mieru://"),
        ("naive", {"type": "naive", "server": "example.com", "server_port": 443, "username": "u", "password": "p"}, "naive://"),
        ("anytls", {"type": "anytls", "server": "example.com", "server_port": 443, "password": "p"}, "anytls://"),
    ],
)
def test_export_normalizes_native_json_protocols(protocol: str, native: dict, prefix: str) -> None:
    node = Node(
        name="Native JSON",
        scheme=protocol,
        server="example.com",
        port=443,
        link=json.dumps(native),
        outbound={"protocol": protocol, "singbox": native},
    )

    exported = normalized_node_export_link(node)

    assert exported.startswith(prefix)
    assert parse_single(exported).scheme == protocol


def test_export_keeps_full_config_as_compact_json() -> None:
    payload = {"inbounds": [], "outbounds": [{"type": "direct", "tag": "direct"}]}
    node = Node(
        name="Full config",
        scheme="singbox_config",
        link="{\n  \"outbounds\": [{\"type\": \"direct\", \"tag\": \"direct\"}],\n  \"inbounds\": []\n}",
        outbound={"protocol": "singbox_config", "singbox_config": payload},
    )

    exported = normalized_node_export_link(node)

    assert exported == json.dumps({"outbounds": payload["outbounds"], "inbounds": []}, separators=(",", ":"))


@pytest.mark.parametrize(
    ("link", "changes", "expected"),
    [
        (
            "ss://aes-128-gcm:old@example.com:8388#SS",
            {"method": "chacha20-ietf-poly1305", "password": "new", "plugin": "obfs-local"},
            {"method": "chacha20-ietf-poly1305", "password": "new", "plugin": "obfs-local"},
        ),
        (
            "socks://old:old@example.com:1080#SOCKS",
            {"username": "new-user", "password": "new-pass"},
            {"users": [{"user": "new-user", "pass": "new-pass"}]},
        ),
        (
            "http://old:old@example.com:8080#HTTP",
            {"username": "new-user", "password": "new-pass"},
            {"users": [{"user": "new-user", "pass": "new-pass"}]},
        ),
    ],
)
def test_simple_proxy_editors_update_only_their_credentials(
    link: str,
    changes: dict,
    expected: dict,
) -> None:
    node = parse_single(link)
    updates = build_node_updates(node, {"server": "new.example", "port": "9443", **changes})
    server = updates["outbound"]["settings"]["servers"][0]

    assert server["address"] == "new.example"
    assert server["port"] == 9443
    for key, value in expected.items():
        assert server[key] == value
    assert parse_single(updates["link"]).outbound == updates["outbound"]


@pytest.mark.parametrize(
    ("link", "changes", "checks"),
    [
        (
            "hysteria://old@example.com:443?upmbps=10&downmbps=20&sni=old.example#HY",
            {"auth": "new", "upMbps": "50", "downMbps": "200", "obfsPassword": "mask", "sni": "front.example"},
            {"auth_str": "new", "up_mbps": 50, "down_mbps": 200, "obfs": "mask"},
        ),
        (
            "hy2://old@example.com:443?sni=old.example#HY2",
            {"password": "new", "obfsType": "salamander", "obfsPassword": "mask", "sni": "front.example"},
            {"password": "new", "obfs": {"type": "salamander", "password": "mask"}},
        ),
        (
            "tuic://00000000-0000-0000-0000-000000000000:old@example.com:443?sni=old.example#TUIC",
            {"uuid": "11111111-1111-1111-1111-111111111111", "password": "new", "congestionControl": "bbr", "udpRelayMode": "quic", "zeroRtt": True},
            {"uuid": "11111111-1111-1111-1111-111111111111", "password": "new", "congestion_control": "bbr", "udp_relay_mode": "quic", "zero_rtt_handshake": True},
        ),
        (
            "mierus://old:old@example.com:27017?transport=TCP#Mieru",
            {"username": "new", "password": "new-pass", "serverPorts": "20000-30000, 40000", "multiplexing": "MULTIPLEXING_LOW"},
            {"username": "new", "password": "new-pass", "server_ports": ["20000-30000", "40000"], "multiplexing": "MULTIPLEXING_LOW"},
        ),
    ],
)
def test_native_protocol_editors_rebuild_supported_fields(
    link: str,
    changes: dict,
    checks: dict,
) -> None:
    node = parse_single(link)
    updates = build_node_updates(node, {"server": "new.example", "port": "8443", **changes})
    native = updates["outbound"]["singbox"]

    assert native["server"] == "new.example"
    assert native["server_port"] == 8443
    for key, value in checks.items():
        assert native[key] == value
    assert build_singbox_outbound(Node(outbound=updates["outbound"]))["type"] == native["type"]
    assert parse_single(updates["link"]).outbound == updates["outbound"]


def test_wireguard_awg_editor_exposes_and_updates_all_endpoint_fields() -> None:
    nodes, errors = parse_links_text(
        """
        [Interface]
        PrivateKey = private-key=
        Address = 10.8.0.2/32
        DNS = 1.1.1.1
        MTU = 1420
        Jc = 4
        Jmin = 64
        Jmax = 160
        S1 = 44
        S2 = 63
        H1 = 1-2
        I1 = <b 0x01020304>

        [Peer]
        PublicKey = public-key=
        PresharedKey = psk=
        AllowedIPs = 0.0.0.0/0, ::/0
        Endpoint = 203.0.113.10:44303
        PersistentKeepalive = 25
        """
    )
    assert errors == []
    node = nodes[0]
    fields = load_node_edit_fields(node)
    keys = {item["key"] for item in fields["protocolFields"]}
    assert {
        "server", "port", "interfaceAddresses", "privateKey", "wgPublicKey",
        "preSharedKey", "allowedIps", "mtu", "listenPort", "keepalive", "dns",
        "peersJson", "udpTimeout", "workers", "preallocatedBuffers", "disablePauses",
        "awg_jc", "awg_h1", "awg_i1",
    } <= keys
    assert {"uuid", "password", "network", "security"}.isdisjoint(keys)
    private_key_field = next(item for item in fields["protocolFields"] if item["key"] == "privateKey")
    assert private_key_field.get("secret") is not True

    updates = build_node_updates(
        node,
        {
            "server": "198.51.100.20",
            "port": "51820",
            "interfaceAddresses": "10.9.0.2/32, fd00::2/128",
            "privateKey": "new-private=",
            "wgPublicKey": "new-public=",
            "preSharedKey": "new-psk=",
            "allowedIps": "0.0.0.0/0, ::/0",
            "mtu": "1380",
            "listenPort": "12345",
            "keepalive": "30",
            "udpTimeout": "4m",
            "workers": "4",
            "preallocatedBuffers": "128",
            "disablePauses": True,
            "dns": "10.9.0.1, 1.1.1.1",
            "awg_jc": "5",
            "awg_h1": "10-20",
            "awg_i1": "<b 0x05060708>",
        },
    )
    endpoint = updates["outbound"]["singbox"]
    peer = endpoint["peers"][0]
    assert endpoint["address"] == ["10.9.0.2/32", "fd00::2/128"]
    assert endpoint["private_key"] == "new-private="
    assert endpoint["mtu"] == 1380
    assert endpoint["listen_port"] == 12345
    assert endpoint["system"] is False
    assert endpoint["udp_timeout"] == "4m"
    assert endpoint["workers"] == 4
    assert endpoint["preallocated_buffers_per_pool"] == 128
    assert endpoint["disable_pauses"] is True
    assert peer == {
        "address": "198.51.100.20",
        "port": 51820,
        "public_key": "new-public=",
        "allowed_ips": ["0.0.0.0/0", "::/0"],
        "pre_shared_key": "new-psk=",
        "persistent_keepalive_interval": 30,
    }
    assert endpoint["amnezia"]["jc"] == 5
    assert endpoint["amnezia"]["h1"] == "10-20"
    assert endpoint["amnezia"]["i1"] == "<b 0x05060708>"
    assert updates["outbound"]["_dns"] == ["10.9.0.1", "1.1.1.1"]


def test_wireguard_editor_can_enable_amnezia_compatibility() -> None:
    node = Node(
        name="WG",
        scheme="wireguard",
        server="203.0.113.10",
        port=51820,
        outbound={
            "protocol": "wireguard",
            "singbox": {
                "type": "wireguard",
                "address": ["10.0.0.2/32"],
                "private_key": "private=",
                "peers": [{
                    "address": "203.0.113.10",
                    "port": 51820,
                    "public_key": "public=",
                    "allowed_ips": ["0.0.0.0/0"],
                }],
            },
        },
    )

    fields = load_node_edit_fields(node)
    specs = {item["key"]: item for item in fields["protocolFields"]}
    assert fields["amneziaEnabled"] is False
    assert specs["amneziaEnabled"]["kind"] == "bool"
    assert specs["awg_jc"]["whenKey"] == "amneziaEnabled"

    updates = build_node_updates(
        node,
        {"amneziaEnabled": True},
    )
    assert updates["scheme"] == "awg"
    assert updates["outbound"]["protocol"] == "awg"
    assert updates["outbound"]["singbox"]["amnezia"] == {
        "jc": 4,
        "jmin": 40,
        "jmax": 70,
        "s1": 0,
        "s2": 0,
        "s3": 0,
        "s4": 0,
        "h1": "1",
        "h2": "2",
        "h3": "3",
        "h4": "4",
    }

    custom = build_node_updates(
        node,
        {"amneziaEnabled": True, "awg_jc": "7", "awg_h1": "99"},
    )
    custom_amnezia = custom["outbound"]["singbox"]["amnezia"]
    assert custom_amnezia["jc"] == 7
    assert custom_amnezia["h1"] == "99"
    assert custom_amnezia["jmin"] == 40

    reverted = build_node_updates(
        Node(**{**node.to_dict(), "scheme": "awg", "outbound": updates["outbound"]}),
        {"amneziaEnabled": False},
    )
    assert reverted["scheme"] == "wireguard"
    assert reverted["outbound"]["protocol"] == "wireguard"
    assert "amnezia" not in reverted["outbound"]["singbox"]


def test_manual_node_schema_changes_with_selected_protocol() -> None:
    vless = new_node_edit_fields("vless", "Manual")
    wireguard = new_node_edit_fields("wireguard", "Manual")

    assert vless["protocolKey"] == "vless"
    assert wireguard["protocolKey"] == "wireguard"
    assert vless["group"] == wireguard["group"] == "Manual"
    assert "uuid" in {item["key"] for item in vless["protocolFields"]}
    assert "privateKey" in {item["key"] for item in wireguard["protocolFields"]}


def test_warp_and_masque_editors_have_separate_supported_fields() -> None:
    warp = Node(
        name="WARP",
        scheme="warp",
        outbound={
            "protocol": "warp",
            "singbox": {
                "type": "warp",
                "profile": {"detour": "direct", "private_key": "old="},
                "reserved": [1, 2, 3],
                "amnezia": {"jc": 4},
            },
        },
    )
    warp_fields = load_node_edit_fields(warp)
    warp_keys = {item["key"] for item in warp_fields["protocolFields"]}
    assert {"profileId", "profilePrivateKey", "authToken", "reserved", "awg_jc"} <= warp_keys
    assert {"server", "port", "wgPublicKey", "allowedIps"}.isdisjoint(warp_keys)

    warp_updates = build_node_updates(
        warp,
        {
            "profileId": "profile-id",
            "profilePrivateKey": "new-private=",
            "authToken": "token",
            "reserved": "4, 5, 6",
            "keepalive": "25",
            "awg_jc": "5",
        },
    )
    warp_native = warp_updates["outbound"]["singbox"]
    assert warp_native["profile"] == {
        "detour": "direct",
        "id": "profile-id",
        "private_key": "new-private=",
        "auth_token": "token",
    }
    assert warp_native["reserved"] == [4, 5, 6]
    assert warp_native["persistent_keepalive_interval"] == 25
    assert warp_native["amnezia"]["jc"] == 5

    masque = Node(
        name="MASQUE",
        scheme="masque",
        server="masque.example",
        port=443,
        outbound={
            "protocol": "masque",
            "singbox": {
                "type": "masque",
                "server": "masque.example",
                "server_port": 443,
                "address": ["172.16.0.2/32"],
                "private_key": "private",
                "public_key": "public",
                "profile": {"detour": "direct"},
            },
        },
    )
    masque_fields = load_node_edit_fields(masque)
    masque_keys = {item["key"] for item in masque_fields["protocolFields"]}
    assert {"server", "port", "interfaceName", "useHttp2", "privateKey", "wgPublicKey", "profileId", "udpTimeout"} <= masque_keys
    assert {"uuid", "method", "network", "awg_jc"}.isdisjoint(masque_keys)

    masque_updates = build_node_updates(
        masque,
        {
            "server": "new-masque.example",
            "port": "8443",
            "interfaceName": "masque1",
            "useHttp2": True,
            "useIpv6": True,
            "interfaceAddresses": "172.20.0.2/32",
            "privateKey": "new-private",
            "wgPublicKey": "new-public",
            "profileId": "profile",
            "authToken": "token",
            "udpTimeout": "10m",
            "sni": "front.example",
        },
    )
    masque_native = masque_updates["outbound"]["singbox"]
    assert masque_native["server"] == "new-masque.example"
    assert masque_native["server_port"] == 8443
    assert masque_native["name"] == "masque1"
    assert masque_native["use_http2"] is True
    assert masque_native["use_ipv6"] is True
    assert masque_native["profile"]["id"] == "profile"
    assert masque_native["tls"]["server_name"] == "front.example"
