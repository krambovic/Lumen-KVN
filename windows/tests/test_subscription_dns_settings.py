from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from xray_fluent.app_controller import AppController, apply_dns_defaults_update_once
from xray_fluent.application import node_service
from xray_fluent.application.node_service import (
    _filter_subscription_nodes,
    _subscription_converter_target,
)
from xray_fluent.models import AppSettings, AppState, Node, RoutingSettings
from xray_fluent.storage import StateStorage


def test_subscription_and_dns_settings_round_trip() -> None:
    settings = AppSettings(
        subscription_include_regex="NL|DE",
        subscription_exclude_regex="expired",
        subscription_user_agent="Lumen-Test/1.0",
        subscription_use_real_hwid=False,
        subscription_hwid="device-id-for-panel",
        subscription_use_proxy_tun=True,
        subscription_converter_enabled=True,
        subscription_converter_url="https://converter.test/sub?url={url}",
        node_sort_key="speed",
        node_sort_ascending=False,
        node_filter_group="Work",
        selected_subscription_id="subscription-1",
        node_table_layout={"manual": True, "name": 360.0, "ping": 120.0},
    )
    routing = RoutingSettings(
        dns_bootstrap_servers=["1.1.1.1", "8.8.8.8"],
        dns_proxy_servers=["dns.google", "cloudflare-dns.com"],
        dns_parallel_query=True,
        dns_optimistic_cache=True,
        dns_geo_check=True,
        dns_hosts={"Example.COM.": ["127.0.0.1", "::1"]},
    )

    restored_settings = AppSettings.from_dict(settings.to_dict())
    restored_routing = RoutingSettings.from_dict(routing.to_dict())

    assert restored_settings.subscription_include_regex == "NL|DE"
    assert restored_settings.subscription_use_real_hwid is False
    assert restored_settings.subscription_hwid == "device-id-for-panel"
    assert restored_settings.subscription_use_proxy_tun is True
    assert restored_settings.subscription_converter_enabled is True
    assert restored_settings.node_sort_key == "speed"
    assert restored_settings.node_sort_ascending is False
    assert restored_settings.node_filter_group == "Work"
    assert restored_settings.selected_subscription_id == "subscription-1"
    assert restored_settings.node_table_layout == {
        "manual": True,
        "name": 360.0,
        "ping": 120.0,
    }
    assert restored_routing.dns_bootstrap_servers == ["1.1.1.1", "8.8.8.8"]
    assert restored_routing.dns_proxy_server == "dns.google"
    assert restored_routing.dns_parallel_query is True
    assert restored_routing.dns_optimistic_cache is True
    assert restored_routing.dns_geo_check is True
    assert restored_routing.dns_hosts == {"example.com": ["127.0.0.1", "::1"]}


def test_real_subscription_hwid_is_enabled_by_default() -> None:
    assert AppSettings.from_dict({}).subscription_use_real_hwid is True


def test_subscription_proxy_tun_is_disabled_by_default() -> None:
    assert AppSettings.from_dict({}).subscription_use_proxy_tun is False


def test_without_a_custom_user_agent_lumen_asks_as_itself() -> None:
    assert AppSettings.from_dict({}).subscription_user_agent == ""
    assert node_service._SUBSCRIPTION_CLIENT_PROFILES[0][0] == "Lumen"


def test_custom_subscription_user_agent_still_wins_over_lumen(monkeypatch) -> None:
    settings = AppSettings(subscription_user_agent="CustomClient/2.0")
    calls = []

    def fake_fetch(url: str, profile: str, headers: dict, *, direct: bool = True):
        calls.append((profile, headers["User-Agent"]))
        return (
            "vless://00000000-0000-0000-0000-000000000001@one.example:443"
            "?encryption=none&type=tcp&security=none#one",
            {"clientProfile": profile},
        )

    monkeypatch.setattr(node_service, "_fetch_subscription_with_headers", fake_fetch)

    _text, info, errors = node_service.fetch_subscription_payload(
        "https://sub.example/sub",
        user_agent=settings.subscription_user_agent,
        use_real_hwid=False,
    )

    assert errors == []
    assert info["clientProfile"] == "Custom"
    assert calls == [("Custom", "CustomClient/2.0")]


def test_real_subscription_hwid_hides_manual_field() -> None:
    settings_qml = (
        Path(__file__).parents[1] / "xray_fluent" / "qml_app" / "qml" / "SettingsPage.qml"
    ).read_text(encoding="utf-8")

    assert "Switch { id: subscriptionUseRealHwid; checked: App.subscriptionUseRealHwid }" in settings_qml
    assert "visible: !subscriptionUseRealHwid.checked" in settings_qml


def test_subscription_proxy_tun_setting_is_exposed() -> None:
    settings_qml = (
        Path(__file__).parents[1] / "xray_fluent" / "qml_app" / "qml" / "SettingsPage.qml"
    ).read_text(encoding="utf-8")

    assert "App.subscriptionUseProxyTun" in settings_qml
    assert "App.setSubscriptionUseProxyTun(checked)" in settings_qml


def test_dns_defaults_use_builtin_split_resolvers() -> None:
    routing = RoutingSettings.from_dict({})

    assert routing.dns_mode == "builtin"
    assert routing.dns_bootstrap_servers == ["1.1.1.1", "8.8.8.8"]
    assert routing.dns_bootstrap_type == "udp"
    assert routing.dns_bootstrap_strategy == "ipv4_only"
    assert routing.dns_proxy_servers == ["cloudflare-dns.com", "dns.google"]
    assert routing.dns_proxy_type == "https"
    assert routing.dns_proxy_strategy == "ipv4_only"
    assert routing.dns_fake_enabled is False
    assert routing.dns_hijack_enabled is True
    assert routing.dns_parallel_query is False
    assert routing.dns_optimistic_cache is False
    assert routing.dns_geo_check is True


def test_dns_defaults_update_is_applied_once_without_touching_servers() -> None:
    node = Node(name="Keep me", server="server.example")
    state = AppState(
        nodes=[node],
        subscriptions=[{"id": "sub-1", "url": "https://example.test/sub"}],
        routing=RoutingSettings(
            dns_mode="system",
            dns_bootstrap_server="9.9.9.9",
            dns_bootstrap_servers=["9.9.9.9"],
            dns_proxy_server="dns.quad9.net",
            dns_proxy_servers=["dns.quad9.net"],
            dns_fake_enabled=True,
            dns_hijack_enabled=False,
            dns_parallel_query=True,
            dns_optimistic_cache=True,
            dns_geo_check=False,
            dns_hosts={"old.test": ["127.0.0.1"]},
        ),
    )

    assert apply_dns_defaults_update_once(state) is True
    assert state.nodes == [node]
    assert state.subscriptions == [{"id": "sub-1", "url": "https://example.test/sub"}]
    assert state.routing.dns_mode == "builtin"
    assert state.routing.dns_bootstrap_servers == ["1.1.1.1", "8.8.8.8"]
    assert state.routing.dns_proxy_servers == ["cloudflare-dns.com", "dns.google"]
    assert state.routing.dns_bootstrap_type == "udp"
    assert state.routing.dns_bootstrap_strategy == "ipv4_only"
    assert state.routing.dns_proxy_type == "https"
    assert state.routing.dns_proxy_strategy == "ipv4_only"
    assert state.routing.dns_fake_enabled is False
    assert state.routing.dns_hijack_enabled is True
    assert state.routing.dns_parallel_query is False
    assert state.routing.dns_optimistic_cache is False
    assert state.routing.dns_geo_check is True
    assert state.routing.dns_hosts == {}

    state.routing.dns_bootstrap_servers = ["9.9.9.9"]
    assert apply_dns_defaults_update_once(state) is False
    assert state.routing.dns_bootstrap_servers == ["9.9.9.9"]


def test_dns_defaults_update_persists_across_restart(tmp_path) -> None:
    storage = StateStorage(tmp_path / "state.json")
    original = AppState(
        nodes=[Node(name="Keep me", server="server.example")],
        subscriptions=[{"id": "sub-1", "url": "https://example.test/sub"}],
        routing=RoutingSettings(
            dns_mode="system",
            dns_bootstrap_server="9.9.9.9",
            dns_bootstrap_servers=["9.9.9.9"],
            dns_bootstrap_type="tls",
            dns_bootstrap_strategy="prefer_ipv6",
            dns_proxy_server="dns.quad9.net",
            dns_proxy_servers=["dns.quad9.net"],
            dns_proxy_type="tls",
            dns_proxy_strategy="prefer_ipv6",
            dns_fake_enabled=True,
            dns_hijack_enabled=False,
            dns_parallel_query=True,
            dns_optimistic_cache=True,
            dns_geo_check=False,
            dns_hosts={"old.test": ["127.0.0.1"]},
        ),
    )
    storage.save(original)

    upgraded = storage.load()
    assert apply_dns_defaults_update_once(upgraded) is True
    storage.save(upgraded)

    restarted = storage.load()
    assert restarted.nodes[0].name == "Keep me"
    assert restarted.subscriptions == [{"id": "sub-1", "url": "https://example.test/sub"}]
    assert restarted.routing.dns_mode == "builtin"
    assert restarted.routing.dns_bootstrap_servers == ["1.1.1.1", "8.8.8.8"]
    assert restarted.routing.dns_bootstrap_type == "udp"
    assert restarted.routing.dns_bootstrap_strategy == "ipv4_only"
    assert restarted.routing.dns_proxy_servers == ["cloudflare-dns.com", "dns.google"]
    assert restarted.routing.dns_proxy_type == "https"
    assert restarted.routing.dns_proxy_strategy == "ipv4_only"
    assert restarted.routing.dns_parallel_query is False
    assert restarted.routing.dns_optimistic_cache is False
    assert restarted.routing.dns_geo_check is True
    assert restarted.routing.dns_hijack_enabled is True
    assert restarted.routing.dns_fake_enabled is False
    assert restarted.routing.dns_hosts == {}
    assert apply_dns_defaults_update_once(restarted) is False


def test_reset_settings_preserves_servers_and_subscriptions(tmp_path) -> None:
    node = Node(name="Keep me", server="server.example")
    state = AppState(
        nodes=[node],
        subscriptions=[{"id": "sub-1", "url": "https://example.test/sub"}],
        settings=AppSettings(theme="dark", local_socks_port=12080),
        routing=RoutingSettings(mode="global", dns_mode="system"),
    )
    controller = SimpleNamespace(state=state, storage=StateStorage(tmp_path / "state.json"))
    controller.update_settings = lambda value: setattr(controller.state, "settings", value)
    controller.update_routing = lambda value: setattr(controller.state, "routing", value)

    AppController.reset_settings_to_defaults(controller)

    assert state.nodes == [node]
    assert state.subscriptions == [{"id": "sub-1", "url": "https://example.test/sub"}]
    assert state.settings.theme == "system"
    assert state.settings.local_socks_port == 10808
    assert state.settings.xray_path
    assert state.settings.singbox_path
    assert state.routing.preset_id == "blocked"
    assert state.routing.dns_mode == "builtin"


def test_subscription_converter_encodes_source_url() -> None:
    target = _subscription_converter_target(
        "https://converter.test/sub?target={url}",
        "https://source.test/sub?id=1&name=test",
    )

    assert target == (
        "https://converter.test/sub?target="
        "https%3A%2F%2Fsource.test%2Fsub%3Fid%3D1%26name%3Dtest"
    )


def test_subscription_regex_filters_include_then_exclude() -> None:
    settings = AppSettings(
        subscription_include_regex="NL|Reality",
        subscription_exclude_regex="expired",
    )
    controller = SimpleNamespace(state=SimpleNamespace(settings=settings))
    nodes = [
        Node(name="NL Reality", server="nl.example", scheme="vless", link="vless://nl"),
        Node(name="NL expired", server="old.example", scheme="vless", link="vless://old"),
        Node(name="DE regular", server="de.example", scheme="trojan", link="trojan://de"),
    ]

    filtered, errors = _filter_subscription_nodes(controller, nodes)

    assert errors == []
    assert [node.name for node in filtered] == ["NL Reality"]


def test_invalid_subscription_regex_is_reported() -> None:
    settings = AppSettings(subscription_include_regex="[")
    controller = SimpleNamespace(state=SimpleNamespace(settings=settings))

    filtered, errors = _filter_subscription_nodes(controller, [Node(name="test")])

    assert filtered == []
    assert errors and "Include regex" in errors[0]
