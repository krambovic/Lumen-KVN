from __future__ import annotations

import json
import socket
import time
from pathlib import Path

import pytest

from xray_fluent.engines.singbox import operations
from xray_fluent.engines.singbox.config_builder import build_singbox_outbound
from xray_fluent.engines.singbox.runtime_planner import (
    classify_node_for_singbox,
    parse_singbox_document,
    plan_singbox_runtime,
    singbox_node_source_signature,
    singbox_node_tag,
)
from xray_fluent.models import Node, RoutingSettings


def _base_config() -> dict:
    return {
        "inbounds": [
            {
                "type": "tun",
                "tag": "tun-in",
                "interface_name": "xftun",
            }
        ],
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
                {"tag": "fake-dns", "type": "fakeip", "inet4_range": "198.18.0.0/15"},
            ],
            "final": "bootstrap-dns",
        },
    }


def _node() -> Node:
    return Node(
        scheme="vless",
        server="203.0.113.1",
        outbound={
            "protocol": "vless",
            "settings": {
                "vnext": [
                    {
                        "address": "203.0.113.1",
                        "port": 443,
                        "users": [{"id": "00000000-0000-0000-0000-000000000000"}],
                    }
                ]
            },
            "streamSettings": {"security": "tls"},
        },
    )


def _node_with_server(server: str) -> Node:
    node = _node()
    node.server = server
    node.outbound["settings"]["vnext"][0]["address"] = server
    return node


def _wireguard_node(server: str) -> Node:
    return Node(
        scheme="wireguard",
        server=server,
        outbound={
            "protocol": "wireguard",
            "singbox": {
                "type": "wireguard",
                "tag": "proxy",
                "address": ["10.0.0.2/32"],
                "private_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                "peers": [
                    {
                        "address": server,
                        "port": 51820,
                        "public_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
                        "allowed_ips": ["0.0.0.0/0"],
                    }
                ],
            },
        },
    )


def _hysteria_node(**bandwidth) -> Node:
    return Node(
        scheme="hysteria",
        server="srv.example.com",
        outbound={
            "protocol": "hysteria",
            "singbox": {
                "type": "hysteria",
                "server": "srv.example.com",
                "server_port": 443,
                "auth_str": "auth",
                **bandwidth,
            },
        },
    )


def _endpoint_document(server: str) -> dict:
    config = _base_config()
    config["outbounds"] = [
        {"type": "selector", "tag": "SELECT", "outbounds": ["direct"], "default": "direct"},
        {"type": "direct", "tag": "direct"},
        {"type": "block", "tag": "block"},
    ]
    config["endpoints"] = [
        {
            "type": "wireguard",
            "tag": "wg-out",
            "address": ["10.0.0.2/32"],
            "private_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "peers": [
                {
                    "address": server,
                    "port": 51820,
                    "public_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
                    "allowed_ips": ["0.0.0.0/0"],
                }
            ],
        }
    ]
    return config


def _full_config_node(config: dict) -> Node:
    return Node(
        scheme="singbox_config",
        server="",
        outbound={"protocol": "singbox_config", "singbox_config": config},
    )


def _xhttp_node(protocol: str) -> Node:
    user = {
        "id": "00000000-0000-0000-0000-000000000000",
        "encryption": "none",
    }
    if protocol == "vmess":
        user = {"id": user["id"], "alterId": 0, "security": "auto"}
    return Node(
        scheme=protocol,
        server="203.0.113.1",
        port=443,
        outbound={
            "protocol": protocol,
            "settings": {
                "vnext": [
                    {
                        "address": "203.0.113.1",
                        "port": 443,
                        "users": [user],
                    }
                ]
            },
            "streamSettings": {
                "network": "xhttp",
                "security": "tls",
                "tlsSettings": {"serverName": "server.example.com"},
                "xhttpSettings": {"path": "/", "mode": "auto"},
            },
        },
    )


def _plan(routing: RoutingSettings, node: Node | None = None, **kwargs) -> dict:
    text = json.dumps(_base_config())
    document = parse_singbox_document(Path("test.json"), text)
    return plan_singbox_runtime(document, node or _node(), routing=routing, **kwargs).singbox_config


def _dns_servers(config: dict) -> dict[str, dict]:
    return {
        str(server.get("tag")): server
        for server in config["dns"]["servers"]
        if isinstance(server, dict)
    }


def _tun_inbound(config: dict) -> dict:
    return next(inbound for inbound in config["inbounds"] if inbound.get("type") == "tun")


def _tun_dns_hijack_rule() -> dict:
    return {
        "type": "logical",
        "mode": "or",
        "rules": [{"port": 53}, {"protocol": "dns"}],
        "action": "hijack-dns",
    }


def _tun_sniff_rule() -> dict:
    return {
        "action": "sniff",
        "timeout": "1s",
    }


def test_runtime_plan_propagates_its_rotating_clash_api_secret() -> None:
    document = parse_singbox_document(Path("test.json"), json.dumps(_base_config()))

    first_plan = plan_singbox_runtime(document, _node(), routing=RoutingSettings(mode="global"))
    second_plan = plan_singbox_runtime(document, _node(), routing=RoutingSettings(mode="global"))

    assert first_plan.clash_api_secret
    assert first_plan.clash_api_secret != second_plan.clash_api_secret
    assert (
        first_plan.singbox_config["experimental"]["clash_api"]["secret"]
        == first_plan.clash_api_secret
    )
    assert first_plan.singbox_config["experimental"]["clash_api"]["external_controller"] == "127.0.0.1:19090"


def test_tun_runtime_uses_stable_low_mtu_v2rayn_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    import xray_fluent.engines.singbox.runtime_planner as planner

    monkeypatch.setattr(planner, "_local_ipv4_addresses", lambda: set())
    monkeypatch.setattr(planner, "_ipv4_gateway_in_use", lambda _gateway: False)
    config = _plan(
        RoutingSettings(mode="global", tun_default_outbound="proxy"),
        tun_mtu=1280,
        tun_stack="gvisor",
    )
    inbound = _tun_inbound(config)

    assert inbound["interface_name"] == "tun0"
    assert inbound["address"] == ["172.18.0.1/30", "fdfe:dcba:9876::1/126"]
    assert inbound["mtu"] == 1280
    assert inbound["stack"] == "gvisor"
    assert inbound["auto_route"] is True
    assert "route_address" not in inbound
    assert inbound["strict_route"] is False
    assert config["route"]["rules"][0] == _tun_sniff_rule()
    assert any(
        rule.get("inbound") == ["tun-in"]
        and rule.get("protocol") == "quic"
        and rule.get("action") == "reject"
        for rule in config["route"]["rules"]
    )


def test_tun_runtime_keeps_v2rayn_style_local_proxy_inbounds() -> None:
    config = _plan(RoutingSettings(mode="global", tun_default_outbound="proxy"))

    inbounds = {inbound.get("tag"): inbound for inbound in config["inbounds"]}
    rules = config["route"]["rules"]

    assert inbounds["socks-in"] == {
        "type": "mixed",
        "tag": "socks-in",
        "listen": "127.0.0.1",
        "listen_port": 10808,
    }
    assert inbounds["http-in"] == {
        "type": "http",
        "tag": "http-in",
        "listen": "127.0.0.1",
        "listen_port": 10809,
    }
    assert any(
        rule.get("inbound") == ["socks-in", "http-in"]
        and rule.get("outbound") == "proxy"
        and rule.get("action") == "route"
        for rule in rules
    )


def test_proxy_runtime_removes_tun_and_keeps_local_proxy_inbounds() -> None:
    config = _plan(
        RoutingSettings(mode="global", tun_default_outbound="proxy"),
        node=_wireguard_node("198.51.100.10"),
        tun_mode=False,
        local_socks_port=12080,
        local_http_port=12081,
    )

    assert not any(inbound.get("type") == "tun" for inbound in config["inbounds"])
    inbounds = {inbound.get("tag"): inbound for inbound in config["inbounds"]}
    assert inbounds["socks-in"]["listen_port"] == 12080
    assert inbounds["http-in"]["listen_port"] == 12081
    assert any(
        rule.get("inbound") == ["socks-in", "http-in"]
        and rule.get("outbound") == "proxy"
        for rule in config["route"]["rules"]
    )


@pytest.mark.parametrize(
    "legacy_routing",
    [
        {"mode": "global", "preset_id": "blocked"},
        {"mode": "global", "proxy_domains": ["geosite:ru-blocked"]},
    ],
)
def test_awg_proxy_runtime_keeps_blocked_preset_direct_fallback_after_legacy_state(
    legacy_routing: dict,
) -> None:
    routing = RoutingSettings.from_dict(legacy_routing)

    assert routing.mode == "rule"
    config = _plan(
        routing,
        node=_wireguard_node("198.51.100.10"),
        tun_mode=False,
        enable_final_fragment=False,
    )

    assert config["route"]["final"] == "direct"
    assert any(
        rule.get("outbound") == "proxy"
        and "geosite-ru-blocked" in rule.get("rule_set", [])
        for rule in config["route"]["rules"]
    )


def test_disabled_tls_fragment_is_not_added_to_tun_rules() -> None:
    text = json.dumps(_base_config())
    document = parse_singbox_document(Path("test.json"), text)
    config = plan_singbox_runtime(
        document,
        _node(),
        routing=RoutingSettings(mode="global", tun_default_outbound="proxy"),
        enable_final_fragment=False,
    ).singbox_config

    assert not any(rule.get("tls_record_fragment") or rule.get("tls_fragment") for rule in config["route"]["rules"])


def test_tun_runtime_uses_extended_tls_fragment_rule() -> None:
    config = _plan(RoutingSettings(mode="global", tun_default_outbound="proxy"))

    fragment_rules = [
        rule
        for rule in config["route"]["rules"]
        if rule.get("action") == "route-options" and rule.get("protocol") == ["tls"]
    ]

    assert fragment_rules == [
        {
            "protocol": ["tls"],
            "action": "route-options",
            "tls_fragment": True,
            "tls_fragment_fallback_delay": "500ms",
        }
    ]


def test_tun_runtime_rejects_browser_doh_before_dns_hijack() -> None:
    config = _plan(RoutingSettings(mode="global", tun_default_outbound="proxy"))
    rules = config["route"]["rules"]

    doh_rule = next(
        rule
        for rule in rules
        if rule.get("action") == "reject"
        and rule.get("inbound") == ["tun-in"]
        and "cloudflare-dns.com" in rule.get("domain_suffix", [])
        and "dns.google" in rule.get("domain_suffix", [])
    )

    assert rules.index(_tun_sniff_rule()) < rules.index(doh_rule) < rules.index(_tun_dns_hijack_rule())


def test_tun_runtime_rejects_browser_doh_dns_before_fakeip() -> None:
    config = _plan(
        RoutingSettings(mode="global", dns_fake_enabled=True, tun_default_outbound="proxy")
    )
    dns_rules = config["dns"]["rules"]

    https_index = next(index for index, rule in enumerate(dns_rules) if rule.get("query_type") == ["HTTPS", "SVCB"])
    doh_index = next(
        index
        for index, rule in enumerate(dns_rules)
        if rule.get("action") == "reject"
        and "dns.google" in [str(item) for item in rule.get("domain_suffix") or []]
    )
    fake_index = next(index for index, rule in enumerate(dns_rules) if rule.get("server") == "fake-dns")

    assert https_index < doh_index < fake_index


def test_vmess_xhttp_uses_xray_sidecar_but_vless_xhttp_stays_native() -> None:
    assert classify_node_for_singbox(_xhttp_node("vmess")) == "hybrid_xray_sidecar"
    assert classify_node_for_singbox(_xhttp_node("vless")) == "native_singbox"


def test_vmess_xhttp_hybrid_plan_preserves_original_xray_outbound() -> None:
    text = json.dumps(_base_config())
    document = parse_singbox_document(Path("test.json"), text)
    plan = plan_singbox_runtime(
        document,
        _xhttp_node("vmess"),
        routing=RoutingSettings(mode="global", tun_default_outbound="proxy"),
        enable_final_fragment=False,
    )

    assert plan.is_hybrid
    assert plan.xray_sidecar is not None
    proxy = next(outbound for outbound in plan.singbox_config["outbounds"] if outbound.get("tag") == "proxy")
    xray_proxy = next(outbound for outbound in plan.xray_sidecar.config["outbounds"] if outbound.get("tag") == "proxy")
    assert proxy["type"] == "socks"
    assert xray_proxy["protocol"] == "vmess"
    assert xray_proxy["streamSettings"]["network"] == "xhttp"


def test_system_dns_mode_uses_physical_adapter_dns_without_local_recursion() -> None:
    text = json.dumps(_base_config())
    document = parse_singbox_document(Path("test.json"), text)
    config = plan_singbox_runtime(
        document,
        _node(),
        routing=RoutingSettings(
            mode="global",
            dns_mode="system",
            dns_hijack_enabled=True,
            dns_fake_enabled=True,
            tun_default_outbound="proxy",
        ),
        system_dns_servers=("192.0.2.53",),
    ).singbox_config

    rules = config["route"]["rules"]
    servers = _dns_servers(config)

    assert [rule for rule in rules if rule.get("action") == "hijack-dns"] == [_tun_dns_hijack_rule()]
    for tag in ("bootstrap-dns", "direct-dns"):
        assert servers[tag]["type"] == "udp"
        assert servers[tag]["server"] == "192.0.2.53"
        assert servers[tag]["detour"] == "direct"
        assert "domain_resolver" not in servers[tag]
    assert servers["proxy-dns"]["type"] == "https"
    assert servers["proxy-dns"]["server"] == "cloudflare-dns.com"
    assert servers["proxy-dns"]["detour"] == "proxy"
    assert servers["proxy-dns"]["domain_resolver"] == "bootstrap-dns"
    assert config["dns"]["final"] == "proxy-dns"
    assert config["dns"]["strategy"] == "ipv4_only"
    assert config["dns"]["reverse_mapping"] is True
    assert config["route"]["default_domain_resolver"]["server"] == "proxy-dns"
    assert config["route"]["default_domain_resolver"]["strategy"] == "ipv4_only"
    # FakeIP is now enabled regardless of system/built-in DNS mode so ECH sites
    # stay reachable; it adds no upstream recursion.
    assert servers["fake-dns"]["type"] == "fakeip"
    assert servers["fake-dns"]["inet4_range"] == "198.18.0.0/15"


def test_tun_runtime_disables_fake_dns_when_setting_off() -> None:
    config = _plan(
        RoutingSettings(
            mode="global",
            dns_mode="system",
            dns_fake_enabled=False,
            tun_default_outbound="proxy",
        )
    )

    servers = _dns_servers(config)
    dns_rules = config["dns"]["rules"]
    route_rules = config["route"]["rules"]

    assert "fake-dns" not in servers
    assert not any(rule.get("server") == "fake-dns" for rule in dns_rules)
    assert not any(
        rule.get("ip_cidr") == ["198.18.0.0/15", "fc00::/18"] for rule in route_rules
    )


def test_default_system_dns_keeps_proxied_domain_dns_on_proxy_resolver() -> None:
    config = _plan(
        RoutingSettings(
            mode="rule",
            dns_mode="system",
            proxy_domains=["chatgpt.com"],
            tun_default_outbound="direct",
        )
    )

    servers = _dns_servers(config)
    dns_rules = config["dns"]["rules"]

    assert servers["bootstrap-dns"]["type"] == "udp"
    assert servers["bootstrap-dns"]["server"] == "1.1.1.1"
    assert servers["direct-dns"]["type"] == "udp"
    assert servers["direct-dns"]["server"] == "1.1.1.1"
    assert servers["proxy-dns"]["type"] == "https"
    assert servers["proxy-dns"]["server"] == "cloudflare-dns.com"
    assert servers["proxy-dns"]["detour"] == "proxy"
    assert config["dns"]["strategy"] == "ipv4_only"
    assert config["dns"]["reverse_mapping"] is True
    assert any(
        rule.get("server") == "proxy-dns"
        and "chatgpt.com" in rule.get("domain_suffix", [])
        for rule in dns_rules
    )


def test_tun_dns_can_prefer_ipv6_without_disabling_ipv4() -> None:
    config = _plan(
        RoutingSettings(
            mode="global",
            dns_mode="system",
            dns_bootstrap_strategy="prefer_ipv6",
            dns_proxy_strategy="prefer_ipv6",
            tun_default_outbound="proxy",
        )
    )

    assert config["dns"]["strategy"] == "prefer_ipv6"
    assert config["route"]["default_domain_resolver"]["strategy"] == "prefer_ipv6"


def test_system_dns_mode_falls_back_to_explicit_bootstrap_server() -> None:
    config = _plan(
        RoutingSettings(
            mode="global",
            dns_mode="system",
            dns_bootstrap_server="1.1.1.1",
            dns_bootstrap_type="udp",
            tun_default_outbound="proxy",
        )
    )

    servers = _dns_servers(config)

    assert servers["bootstrap-dns"]["type"] == "udp"
    assert servers["bootstrap-dns"]["server"] == "1.1.1.1"
    assert servers["bootstrap-dns"]["detour"] == "direct"
    assert servers["proxy-dns"]["type"] == "https"
    assert servers["proxy-dns"]["server"] == "cloudflare-dns.com"
    assert servers["proxy-dns"]["detour"] == "proxy"
    assert servers["proxy-dns"]["domain_resolver"] == "bootstrap-dns"


def test_builtin_dns_mode_keeps_tun_dns_hijack_contract() -> None:
    config = _plan(
        RoutingSettings(
            mode="global",
            dns_mode="builtin",
            dns_hijack_enabled=True,
            dns_fake_enabled=True,
            tun_default_outbound="proxy",
        )
    )

    rules = config["route"]["rules"]
    servers = _dns_servers(config)

    assert any(rule.get("action") == "hijack-dns" for rule in rules)
    assert rules.index(_tun_dns_hijack_rule()) < next(
        index
        for index, rule in enumerate(rules)
        if rule.get("action") == "reject" and rule.get("port") == [135, 137, 138, 139, 5353, 5355]
    )
    assert servers["bootstrap-dns"]["type"] == "udp"
    assert servers["bootstrap-dns"]["server"] == "1.1.1.1"
    assert servers["bootstrap-dns"]["detour"] == "direct"
    assert servers["direct-dns"]["detour"] == "direct"
    assert servers["proxy-dns"]["detour"] == "proxy"
    assert servers["fake-dns"]["type"] == "fakeip"
    assert config["dns"]["final"] == "proxy-dns"
    assert any(
        rule.get("server") == "fake-dns"
        and rule.get("query_type") == ["A", "AAAA"]
        for rule in config["dns"]["rules"]
    )
    assert config["log"]["level"] == "info"


def test_fake_dns_runtime_persists_fakeip_cache() -> None:
    config = _plan(
        RoutingSettings(
            mode="global",
            dns_mode="builtin",
            dns_fake_enabled=True,
            tun_default_outbound="proxy",
        )
    )

    cache_file = config["experimental"]["cache_file"]

    assert cache_file["enabled"] is True
    assert cache_file["store_fakeip"] is True
    assert str(cache_file["path"]).endswith("sing-box-cache.db")


def test_builtin_dns_always_hijacks_the_tun_dns_peer() -> None:
    config = _plan(
        RoutingSettings(
            mode="global",
            dns_mode="builtin",
            dns_hijack_enabled=False,
            tun_default_outbound="proxy",
        )
    )

    hijack_rules = [rule for rule in config["route"]["rules"] if rule.get("action") == "hijack-dns"]

    assert hijack_rules == [_tun_dns_hijack_rule()]


def test_builtin_fake_dns_keeps_proxied_dns_final_for_direct_default() -> None:
    config = _plan(
        RoutingSettings(
            mode="direct",
            dns_mode="builtin",
            dns_hijack_enabled=True,
            dns_fake_enabled=True,
            tun_default_outbound="direct",
        )
    )

    assert config["route"]["final"] == "direct"
    assert config["dns"]["final"] == "proxy-dns"
    assert any(rule.get("server") == "fake-dns" for rule in config["dns"]["rules"])


def test_builtin_fake_dns_keeps_service_dns_rules_ahead_of_fakeip() -> None:
    config = _plan(
        RoutingSettings(
            mode="global",
            service_routes={"youtube": "direct"},
            dns_mode="builtin",
            dns_fake_enabled=True,
            tun_default_outbound="proxy",
        )
    )

    rules = config["dns"]["rules"]
    service_index = next(
        index
        for index, rule in enumerate(rules)
        if rule.get("server") == "bootstrap-dns"
        and "youtube.com" in rule.get("domain_suffix", [])
    )
    fake_index = next(index for index, rule in enumerate(rules) if rule.get("server") == "fake-dns")

    assert service_index < fake_index


@pytest.mark.parametrize("dns_type", ["udp", "tcp", "tls", "https"])
def test_builtin_dns_uses_independent_resolver_for_dns_server_hostnames(dns_type: str) -> None:
    text = json.dumps(_base_config())
    document = parse_singbox_document(Path("test.json"), text)
    config = plan_singbox_runtime(
        document,
        _node(),
        routing=RoutingSettings(
            mode="global",
            dns_mode="builtin",
            dns_bootstrap_server="resolver.example.com",
            dns_bootstrap_type=dns_type,
            dns_proxy_server="proxied-resolver.example.com",
            dns_proxy_type=dns_type,
            tun_default_outbound="proxy",
        ),
        system_dns_servers=("192.0.2.53",),
    ).singbox_config

    servers = _dns_servers(config)

    assert servers["system-dns"]["type"] == "udp"
    assert servers["system-dns"]["server"] == "192.0.2.53"
    assert servers["system-dns"]["detour"] == "direct"
    assert servers["bootstrap-dns"]["detour"] == "direct"
    assert servers["bootstrap-dns"]["domain_resolver"] == "system-dns"
    assert servers["direct-dns"]["detour"] == "direct"
    assert servers["direct-dns"]["domain_resolver"] == "system-dns"
    assert servers["proxy-dns"]["detour"] == "proxy"
    assert servers["proxy-dns"]["domain_resolver"] == "bootstrap-dns"


@pytest.mark.parametrize("dns_type", ["udp", "tcp", "tls", "https"])
def test_builtin_dns_does_not_add_resolver_for_ip_dns_servers(dns_type: str) -> None:
    config = _plan(
        RoutingSettings(
            mode="global",
            dns_mode="builtin",
            dns_bootstrap_server="1.1.1.1",
            dns_bootstrap_type=dns_type,
            dns_proxy_server="8.8.8.8",
            dns_proxy_type=dns_type,
            tun_default_outbound="proxy",
        )
    )

    servers = _dns_servers(config)

    assert servers["bootstrap-dns"]["detour"] == "direct"
    assert "domain_resolver" not in servers["bootstrap-dns"]
    assert servers["direct-dns"]["detour"] == "direct"
    assert "domain_resolver" not in servers["direct-dns"]
    assert servers["proxy-dns"]["detour"] == "proxy"
    if dns_type in {"tls", "https"}:
        assert servers["proxy-dns"]["server"] == "dns.google"
        assert servers["proxy-dns"]["type"] == dns_type
        assert servers["proxy-dns"]["domain_resolver"] == "bootstrap-dns"
    else:
        assert servers["proxy-dns"]["server"] == "8.8.8.8"
        assert "domain_resolver" not in servers["proxy-dns"]


@pytest.mark.parametrize(
    ("server", "cidr"),
    [
        ("95.128.157.251", "95.128.157.251/32"),
        ("2001:db8::2208", "2001:db8::2208/128"),
    ],
)
def test_native_tun_excludes_ip_proxy_endpoint_from_tun_routes(server: str, cidr: str) -> None:
    config = _plan(
        RoutingSettings(mode="global", dns_mode="builtin", tun_default_outbound="proxy"),
        _node_with_server(server),
    )

    rules = config["route"]["rules"]
    route_excludes = _tun_inbound(config)["route_exclude_address"]

    assert cidr in route_excludes
    assert any(rule.get("outbound") == "direct" and cidr in rule.get("ip_cidr", []) for rule in rules)


def test_native_tun_preserves_user_route_excludes_when_adding_endpoint_exclude() -> None:
    config = _plan(
        RoutingSettings(
            mode="global",
            dns_mode="builtin",
            tun_default_outbound="proxy",
            tun_route_exclude_address=["192.168.0.0/16"],
        ),
        _node_with_server("95.128.157.251"),
    )

    route_excludes = _tun_inbound(config)["route_exclude_address"]

    assert "192.168.0.0/16" in route_excludes
    assert "95.128.157.251/32" in route_excludes


def test_native_tun_excludes_resolved_domain_proxy_endpoint_from_tun_routes(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_getaddrinfo(host: str, *_args, **_kwargs):
        if host != "vpn.example.com":
            return []
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("203.0.113.10", 0)),
            (socket.AF_INET6, socket.SOCK_STREAM, 0, "", ("2001:db8::10", 0, 0, 0)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    config = _plan(
        RoutingSettings(mode="global", dns_mode="builtin", tun_default_outbound="proxy"),
        _node_with_server("vpn.example.com"),
    )

    rules = config["route"]["rules"]
    inbound = _tun_inbound(config)
    proxy = next(outbound for outbound in config["outbounds"] if outbound.get("tag") == "proxy")

    assert "203.0.113.10/32" in inbound["route_exclude_address"]
    assert "2001:db8::10/128" in inbound["route_exclude_address"]
    assert proxy["server"] == "vpn.example.com"
    assert proxy.get("domain_resolver") == "bootstrap-dns"
    assert proxy["tls"]["server_name"] == "vpn.example.com"
    assert any(rule.get("outbound") == "direct" and "203.0.113.10/32" in rule.get("ip_cidr", []) for rule in rules)
    assert any(
        rule.get("outbound") == "direct"
        and "vpn.example.com" in rule.get("domain", [])
        for rule in rules
    )


def test_endpoint_resolution_is_reused_within_cache_ttl(monkeypatch: pytest.MonkeyPatch) -> None:
    import xray_fluent.engines.singbox.runtime_planner as planner

    calls = 0

    def fake_getaddrinfo(host: str, *_args, **_kwargs):
        nonlocal calls
        calls += 1
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("203.0.113.25", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    with planner._endpoint_dns_cache_lock:
        planner._endpoint_dns_cache.clear()

    assert planner._resolve_endpoint_addresses("cache.example.com") == ["203.0.113.25"]
    assert planner._resolve_endpoint_addresses("cache.example.com") == ["203.0.113.25"]
    assert calls == 1


def test_tun_runtime_rejects_https_svcb_dns_in_system_mode() -> None:
    config = _plan(
        RoutingSettings(
            mode="global",
            dns_mode="system",
            dns_fake_enabled=True,
            tun_default_outbound="proxy",
        )
    )

    dns_rules = config["dns"]["rules"]
    https_rejects = [
        rule
        for rule in dns_rules
        if rule.get("action") == "reject"
        and {str(item).upper() for item in rule.get("query_type", [])} == {"HTTPS", "SVCB"}
    ]
    assert len(https_rejects) == 1
    # The reject must sit ahead of the A/AAAA -> fake-dns rule so ECH/h3 hints
    # are never answered for routed domains.
    fake_index = next(
        index
        for index, rule in enumerate(dns_rules)
        if rule.get("server") == "fake-dns"
    )
    reject_index = next(
        index
        for index, rule in enumerate(dns_rules)
        if rule.get("action") == "reject"
        and {str(item).upper() for item in rule.get("query_type", [])} == {"HTTPS", "SVCB"}
    )
    assert reject_index < fake_index

    servers = _dns_servers(config)
    assert servers["fake-dns"]["type"] == "fakeip"


def test_tun_runtime_does_not_reject_quic_globally() -> None:
    config = _plan(
        RoutingSettings(
            mode="rule",
            dns_mode="system",
            direct_domains=["2ip.ru"],
            tun_default_outbound="direct",
        ),
        _node_with_server("vpn.example.com"),
    )

    rules = config["route"]["rules"]
    assert any(
        rule.get("outbound") == "direct" and "2ip.ru" in rule.get("domain_suffix", [])
        for rule in rules
    )
    assert not any(
        rule.get("action") == "reject" and rule.get("network") == "udp" and rule.get("port") == 443
        for rule in rules
    )


def test_native_tun_keeps_domain_proxy_endpoint_route_when_resolution_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_getaddrinfo(*_args, **_kwargs):
        raise socket.gaierror()

    monkeypatch.setattr(socket, "getaddrinfo", fail_getaddrinfo)

    config = _plan(
        RoutingSettings(mode="global", dns_mode="builtin", tun_default_outbound="proxy"),
        _node_with_server("vpn.example.com"),
    )

    rules = config["route"]["rules"]
    inbound = _tun_inbound(config)
    proxy = next(outbound for outbound in config["outbounds"] if outbound.get("tag") == "proxy")

    assert "route_exclude_address" not in inbound
    assert proxy["server"] == "vpn.example.com"
    assert proxy["domain_resolver"] == "bootstrap-dns"
    assert any(
        rule.get("outbound") == "direct"
        and "vpn.example.com" in rule.get("domain", [])
        for rule in rules
    )


def test_native_tun_does_not_block_startup_on_slow_endpoint_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    import xray_fluent.engines.singbox.runtime_planner as planner

    def slow_getaddrinfo(*_args, **_kwargs):
        time.sleep(5)
        return []

    monkeypatch.setattr(planner, "_local_ipv4_addresses", lambda: set())
    monkeypatch.setattr(socket, "getaddrinfo", slow_getaddrinfo)
    started = time.monotonic()

    config = _plan(
        RoutingSettings(mode="global", dns_mode="builtin", tun_default_outbound="proxy"),
        _node_with_server("vpn.example.com"),
    )

    assert time.monotonic() - started < 2
    proxy = next(outbound for outbound in config["outbounds"] if outbound.get("tag") == "proxy")
    assert proxy["server"] == "vpn.example.com"
    assert proxy["domain_resolver"] == "bootstrap-dns"


def test_endpoint_tun_excludes_ip_peer_from_tun_routes() -> None:
    config = _plan(
        RoutingSettings(mode="global", dns_mode="builtin", tun_default_outbound="proxy"),
        _wireguard_node("46.17.101.82"),
    )

    rules = config["route"]["rules"]
    route_excludes = _tun_inbound(config)["route_exclude_address"]

    assert "46.17.101.82/32" in route_excludes
    assert any(
        rule.get("outbound") == "direct"
        and "46.17.101.82/32" in rule.get("ip_cidr", [])
        for rule in rules
    )


def test_endpoint_tun_excludes_resolved_domain_peer_from_tun_routes(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_getaddrinfo(host: str, *_args, **_kwargs):
        if host != "wg.example.com":
            return []
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("198.51.100.20", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    config = _plan(
        RoutingSettings(mode="global", dns_mode="builtin", tun_default_outbound="proxy"),
        _wireguard_node("wg.example.com"),
    )

    rules = config["route"]["rules"]
    route_excludes = _tun_inbound(config)["route_exclude_address"]

    assert "198.51.100.20/32" in route_excludes
    assert any(
        rule.get("outbound") == "direct"
        and "198.51.100.20/32" in rule.get("ip_cidr", [])
        for rule in rules
    )
    assert any(
        rule.get("outbound") == "direct"
        and "wg.example.com" in rule.get("domain", [])
        for rule in rules
    )


def test_builtin_dns_adds_multiple_servers_and_hosts_without_unsupported_optimistic_field() -> None:
    config = _plan(
        RoutingSettings(
            mode="global",
            dns_mode="builtin",
            dns_bootstrap_servers=["1.1.1.1", "8.8.8.8"],
            dns_bootstrap_type="udp",
            dns_proxy_servers=["dns.google", "9.9.9.9"],
            dns_proxy_type="https",
            dns_optimistic_cache=True,
            dns_hosts={"local.test": ["127.0.0.1", "::1"]},
            tun_default_outbound="proxy",
        )
    )

    servers = _dns_servers(config)

    assert servers["direct-dns-2"]["server"] == "8.8.8.8"
    assert servers["proxy-dns-2"]["server"] == "dns.quad9.net"
    assert servers["hosts-dns"] == {
        "tag": "hosts-dns",
        "type": "hosts",
        "predefined": {"local.test": ["127.0.0.1", "::1"]},
    }
    assert config["dns"].get("optimistic") is None
    assert any(
        rule.get("ip_accept_any") is True and rule.get("server") == "hosts-dns"
        for rule in config["dns"]["rules"]
    )


def test_hysteria_without_bandwidth_gets_singbox_speed_defaults() -> None:
    outbound = build_singbox_outbound(_hysteria_node(), tag="proxy")

    assert outbound["up_mbps"] == 50
    assert outbound["down_mbps"] == 200


def test_hysteria_keeps_bandwidth_declared_by_the_link() -> None:
    outbound = build_singbox_outbound(_hysteria_node(up_mbps=10, down_mbps=20), tag="proxy")

    assert outbound["up_mbps"] == 10
    assert outbound["down_mbps"] == 20


def test_full_config_node_keeps_endpoint_bootstrap_route_after_gui_routing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_getaddrinfo(*_args, **_kwargs):
        raise socket.gaierror()

    monkeypatch.setattr(socket, "getaddrinfo", fail_getaddrinfo)

    document = parse_singbox_document(Path("test.json"), json.dumps(_base_config()))
    config = plan_singbox_runtime(
        document,
        _full_config_node(_endpoint_document("wg.example.com")),
        routing=RoutingSettings(mode="global", dns_mode="builtin", tun_default_outbound="proxy"),
    ).singbox_config

    assert any(
        rule.get("outbound") == "direct" and "wg.example.com" in rule.get("domain", [])
        for rule in config["route"]["rules"]
    )


def test_document_without_proxy_outbound_keeps_endpoint_bootstrap_route(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_getaddrinfo(*_args, **_kwargs):
        raise socket.gaierror()

    monkeypatch.setattr(socket, "getaddrinfo", fail_getaddrinfo)

    document = parse_singbox_document(
        Path("test.json"), json.dumps(_endpoint_document("wg.example.com"))
    )
    plan = plan_singbox_runtime(
        document,
        None,
        routing=RoutingSettings(mode="global", dns_mode="builtin", tun_default_outbound="proxy"),
    )

    assert plan.has_proxy_outbound is False
    assert any(
        rule.get("outbound") == "direct" and "wg.example.com" in rule.get("domain", [])
        for rule in plan.singbox_config["route"]["rules"]
    )


def test_document_with_foreign_proxy_tag_gets_a_proxy_alias() -> None:
    document = parse_singbox_document(
        Path("test.json"), json.dumps(_endpoint_document("198.51.100.7"))
    )
    plan = plan_singbox_runtime(
        document,
        None,
        routing=RoutingSettings(mode="global", dns_mode="builtin", tun_default_outbound="proxy"),
    )
    config = plan.singbox_config

    alias = next(outbound for outbound in config["outbounds"] if outbound.get("tag") == "proxy")

    assert plan.has_proxy_outbound is False
    assert alias["type"] == "selector"
    assert alias["default"] == "SELECT"
    assert config["route"]["final"] == "proxy"
    assert any(
        rule.get("inbound") == ["socks-in", "http-in"] and rule.get("outbound") == "proxy"
        for rule in config["route"]["rules"]
    )


def test_imported_tun_inbound_tag_is_normalized_for_the_scoped_reject_rules() -> None:
    payload = _base_config()
    payload["inbounds"][0]["tag"] = "tun"
    payload["route"]["rules"] = [{"inbound": ["tun"], "action": "route", "outbound": "direct"}]
    document = parse_singbox_document(Path("test.json"), json.dumps(payload))
    config = plan_singbox_runtime(
        document,
        _node(),
        routing=RoutingSettings(mode="global", tun_default_outbound="proxy"),
    ).singbox_config

    rules = config["route"]["rules"]

    assert _tun_inbound(config)["tag"] == "tun-in"
    assert any(
        rule.get("inbound") == ["tun-in"]
        and rule.get("protocol") == "quic"
        and rule.get("action") == "reject"
        for rule in rules
    )
    assert not any("tun" in (rule.get("inbound") or []) for rule in rules)


def test_tls_fragment_rule_precedes_terminal_gui_route_rules() -> None:
    config = _plan(
        RoutingSettings(
            mode="rule",
            proxy_domains=["example.com"],
            tun_default_outbound="proxy",
        )
    )
    rules = config["route"]["rules"]

    fragment_index = next(
        index for index, rule in enumerate(rules) if rule.get("action") == "route-options"
    )
    gui_index = next(
        index
        for index, rule in enumerate(rules)
        if rule.get("outbound") == "proxy" and "example.com" in rule.get("domain_suffix", [])
    )
    local_proxy_index = next(
        index
        for index, rule in enumerate(rules)
        if rule.get("inbound") == ["socks-in", "http-in"]
    )

    assert fragment_index < gui_index
    assert fragment_index < local_proxy_index


def test_dns_hosts_override_precedes_the_fakeip_rule() -> None:
    config = _plan(
        RoutingSettings(
            mode="global",
            dns_mode="builtin",
            dns_fake_enabled=True,
            dns_hosts={"my.internal": ["10.1.2.3"]},
            tun_default_outbound="proxy",
        )
    )
    dns_rules = config["dns"]["rules"]

    https_index = next(
        index for index, rule in enumerate(dns_rules) if rule.get("query_type") == ["HTTPS", "SVCB"]
    )
    hosts_index = next(
        index for index, rule in enumerate(dns_rules) if rule.get("server") == "hosts-dns"
    )
    fake_index = next(
        index for index, rule in enumerate(dns_rules) if rule.get("server") == "fake-dns"
    )

    assert https_index < hosts_index < fake_index


def test_planner_runtime_error_is_reported_as_a_connection_error() -> None:
    statuses: list[tuple[str, str]] = []

    class FakeController:
        _active_core = "xray"

        def _plan_runtime_singbox(self, node, *, tun_mode):
            raise RuntimeError("Не найден региональный rule-set geosite:ru-blocked.")

        def _set_connection_status(self, status, message, *, level):
            statuses.append((status, message))

    controller = FakeController()

    assert operations.start_runtime(controller, None, prev_active_core="xray", tun_mode=True) is None
    assert controller._active_core == "xray"
    assert statuses == [("error", "Не найден региональный rule-set geosite:ru-blocked.")]


def test_hot_switch_selector_contains_native_nodes_and_skips_hybrid_nodes() -> None:
    first = _node_with_server("first.example.com")
    first.id = "first-node"
    second = _node_with_server("second.example.com")
    second.id = "second-node"
    hybrid = Node(
        id="hybrid-node",
        name="Hybrid",
        scheme="vmess",
        server="hybrid.example.com",
        port=443,
        outbound={
            "protocol": "vmess",
            "settings": {"vnext": [{"address": "hybrid.example.com", "port": 443}]},
            "streamSettings": {"network": "xhttp"},
        },
    )

    document = parse_singbox_document(Path("test.json"), json.dumps(_base_config()))
    plan = plan_singbox_runtime(
        document,
        first,
        routing=RoutingSettings(mode="global", tun_default_outbound="proxy"),
        enable_hot_switch=True,
        hot_switch_nodes=(first, second, hybrid),
    )

    assert plan.clash_api_selector == "proxy"
    selector = next(item for item in plan.singbox_config["outbounds"] if item.get("tag") == "proxy")
    assert selector["type"] == "selector"
    assert selector["default"] in selector["outbounds"]
    assert len(selector["outbounds"]) == 2
    assert singbox_node_tag(hybrid.id) not in selector["outbounds"]
    assert dict(plan.clash_api_node_signatures) == {
        first.id: singbox_node_source_signature(first),
        second.id: singbox_node_source_signature(second),
    }
    assert not any(item.get("tag") == "proxy" and item.get("type") != "selector" for item in plan.singbox_config["outbounds"])
