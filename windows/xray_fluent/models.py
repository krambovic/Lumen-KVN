from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import locale
import math
from typing import Any
import uuid

from .constants import ROUTING_RULE, STATE_SCHEMA_VERSION


DEFAULT_WINDOW_WIDTH = 1280
DEFAULT_WINDOW_HEIGHT = 720
DEFAULT_SUBSCRIPTION_HWID = "00000000-0000-4000-8000-000000000000"
_LEGACY_WINDOW_DEFAULT = (1024, 768)


def _normalize_window_size(width: Any, height: Any) -> tuple[int, int]:
    try:
        w = int(width or DEFAULT_WINDOW_WIDTH)
    except (TypeError, ValueError):
        w = DEFAULT_WINDOW_WIDTH
    try:
        h = int(height or DEFAULT_WINDOW_HEIGHT)
    except (TypeError, ValueError):
        h = DEFAULT_WINDOW_HEIGHT
    if (w, h) == _LEGACY_WINDOW_DEFAULT or w < 640 or h < 360:
        return DEFAULT_WINDOW_WIDTH, DEFAULT_WINDOW_HEIGHT
    return w, h


def _normalize_string_list(values: Any, *, fallback: str = "") -> list[str]:
    if isinstance(values, str):
        values = values.replace(";", "\n").replace(",", "\n").splitlines()
    if not isinstance(values, (list, tuple, set)):
        values = []
    result: list[str] = []
    for item in values:
        value = str(item or "").strip()
        if value and value not in result:
            result.append(value)
    if not result and fallback:
        result.append(fallback)
    return result


def _normalize_dns_hosts(values: Any) -> dict[str, list[str]]:
    if not isinstance(values, dict):
        return {}
    result: dict[str, list[str]] = {}
    for raw_domain, raw_addresses in values.items():
        domain = str(raw_domain or "").strip().lower().rstrip(".")
        if not domain:
            continue
        addresses = _normalize_string_list(raw_addresses)
        if addresses:
            result[domain] = addresses
    return result


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(slots=True)
class Node:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    scheme: str = ""
    server: str = ""
    port: int = 0
    link: str = ""
    outbound: dict[str, Any] = field(default_factory=dict)
    group: str = "Default"
    tags: list[str] = field(default_factory=list)
    ping_ms: int | None = None
    last_used_at: str | None = None
    created_at: str = field(default_factory=utc_now_iso)
    country_code: str = ""
    speed_mbps: float | None = None
    is_alive: bool | None = None
    ping_history: list[tuple[str, int | None]] = field(default_factory=list)
    speed_history: list[tuple[str, float | None]] = field(default_factory=list)
    sort_order: int = 0
    subscription_id: str = ""
    description: str = ""
    # Stable identity of a subscription entry.  Unlike the provider display
    # name or list position this survives harmless formatting/name changes and
    # lets reconcile preserve ping/speed history and local ordering.
    source_key: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "scheme": self.scheme,
            "server": self.server,
            "port": self.port,
            "link": self.link,
            "outbound": self.outbound,
            "group": self.group,
            "tags": list(self.tags),
            "ping_ms": self.ping_ms,
            "last_used_at": self.last_used_at,
            "created_at": self.created_at,
            "country_code": self.country_code,
            "speed_mbps": self.speed_mbps,
            "is_alive": self.is_alive,
            "ping_history": self.ping_history,
            "speed_history": self.speed_history,
            "sort_order": self.sort_order,
            "subscription_id": self.subscription_id,
            "description": self.description,
            "source_key": self.source_key,
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "Node":
        return Node(
            id=str(data.get("id") or uuid.uuid4()),
            name=str(data.get("name") or ""),
            scheme=str(data.get("scheme") or ""),
            server=str(data.get("server") or ""),
            port=int(data.get("port") or 0),
            link=str(data.get("link") or ""),
            outbound=dict(data.get("outbound") or {}),
            group=str(data.get("group") or "Default"),
            tags=list(data.get("tags") or []),
            ping_ms=data.get("ping_ms"),
            last_used_at=data.get("last_used_at"),
            created_at=str(data.get("created_at") or utc_now_iso()),
            country_code=str(data.get("country_code") or ""),
            speed_mbps=data.get("speed_mbps"),
            is_alive=data.get("is_alive"),
            ping_history=data.get("ping_history", []),
            speed_history=data.get("speed_history", []),
            sort_order=int(data.get("sort_order", 0)),
            subscription_id=str(data.get("subscription_id") or ""),
            description=str(data.get("description") or ""),
            source_key=str(data.get("source_key") or ""),
        )


@dataclass(slots=True)
class RoutingSettings:
    mode: str = ROUTING_RULE
    preset_id: str = "blocked"  # global | blocked | except_ru | custom
    bypass_lan: bool = True
    direct_domains: list[str] = field(default_factory=list)
    proxy_domains: list[str] = field(default_factory=list)
    block_domains: list[str] = field(default_factory=list)
    dns_mode: str = "builtin"  # system | builtin
    dns_bootstrap_server: str = "1.1.1.1"  # DNS for direct traffic
    dns_bootstrap_servers: list[str] = field(default_factory=list)
    dns_bootstrap_type: str = "udp"        # udp | tcp | tls | https
    dns_bootstrap_strategy: str = "ipv4_only"
    dns_proxy_server: str = "cloudflare-dns.com"  # DNS for proxy traffic
    dns_proxy_servers: list[str] = field(default_factory=list)
    dns_proxy_type: str = "https"          # tcp | tls | https
    dns_proxy_strategy: str = "ipv4_only"
    dns_fake_enabled: bool = False
    dns_hijack_enabled: bool = True
    dns_parallel_query: bool = False
    dns_optimistic_cache: bool = False
    dns_geo_check: bool = True
    dns_hosts: dict[str, list[str]] = field(default_factory=dict)
    tun_route_exclude_address: list[str] = field(default_factory=list)
    process_rules: list[dict[str, str]] = field(default_factory=list)  # [{"process": "chrome.exe", "action": "direct|proxy|block"}]
    process_preset_routes: dict[str, str] = field(default_factory=dict)  # {"telegram": "proxy", "windows_system": "direct"}
    service_routes: dict[str, str] = field(default_factory=dict)  # {"youtube": "proxy", "steam": "direct", ...}
    # Kept in persisted data for compatibility with older presets. The runtime
    # now derives the fallback from the active preset and otherwise uses proxy.
    tun_default_outbound: str = "proxy"  # "proxy" | "direct"

    def __post_init__(self) -> None:
        bootstrap_defaults = ["1.1.1.1", "8.8.8.8"] if self.dns_bootstrap_server == "1.1.1.1" else [self.dns_bootstrap_server]
        proxy_defaults = ["cloudflare-dns.com", "dns.google"] if self.dns_proxy_server == "cloudflare-dns.com" else [self.dns_proxy_server]
        # An explicitly empty direct-DNS list is meaningful: DNS still goes
        # through the proxied resolver, including names whose traffic route is
        # direct.  Fresh/legacy settings keep the historical defaults.
        self.dns_bootstrap_servers = _normalize_string_list(
            self.dns_bootstrap_servers or bootstrap_defaults,
            fallback="",
        )
        self.dns_proxy_servers = _normalize_string_list(
            self.dns_proxy_servers or proxy_defaults,
            fallback="cloudflare-dns.com",
        )
        self.dns_bootstrap_server = self.dns_bootstrap_servers[0] if self.dns_bootstrap_servers else ""
        self.dns_proxy_server = self.dns_proxy_servers[0]
        self.dns_hosts = _normalize_dns_hosts(self.dns_hosts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "preset_id": self.preset_id,
            "bypass_lan": self.bypass_lan,
            "direct_domains": list(self.direct_domains),
            "proxy_domains": list(self.proxy_domains),
            "block_domains": list(self.block_domains),
            "dns_mode": self.dns_mode,
            "dns_bootstrap_server": self.dns_bootstrap_server,
            "dns_bootstrap_servers": list(self.dns_bootstrap_servers),
            "dns_bootstrap_type": self.dns_bootstrap_type,
            "dns_bootstrap_strategy": self.dns_bootstrap_strategy,
            "dns_proxy_server": self.dns_proxy_server,
            "dns_proxy_servers": list(self.dns_proxy_servers),
            "dns_proxy_type": self.dns_proxy_type,
            "dns_proxy_strategy": self.dns_proxy_strategy,
            "dns_fake_enabled": self.dns_fake_enabled,
            "dns_hijack_enabled": self.dns_hijack_enabled,
            "dns_parallel_query": self.dns_parallel_query,
            "dns_optimistic_cache": self.dns_optimistic_cache,
            "dns_geo_check": self.dns_geo_check,
            "dns_hosts": {key: list(values) for key, values in self.dns_hosts.items()},
            "tun_route_exclude_address": list(self.tun_route_exclude_address),
            "process_rules": list(self.process_rules),
            "process_preset_routes": dict(self.process_preset_routes),
            "service_routes": dict(self.service_routes),
            "tun_default_outbound": self.tun_default_outbound,
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "RoutingSettings":
        preset_id = str(data.get("preset_id") or "").strip().lower()
        if not preset_id:
            direct = {str(item).strip().lower() for item in (data.get("direct_domains") or [])}
            proxy = {str(item).strip().lower() for item in (data.get("proxy_domains") or [])}
            if {"geosite:category-ru", "geoip:ru"} & direct:
                preset_id = "except_ru"
            elif {
                "geosite:ru-blocked",
                "geosite:category-media-ru-blocked",
                "geoip:ru-blocked",
                "geoip:ru-blocked-community",
            } & proxy:
                preset_id = "blocked"
            elif str(data.get("mode") or ROUTING_RULE) == "global":
                preset_id = "global"
            else:
                preset_id = "custom"
        mode = str(data.get("mode") or ROUTING_RULE)
        if mode.strip().lower() == "global" and preset_id in {"blocked", "blocked_cn"}:
            # Older persisted states could infer the blocked-only preset from
            # its domain rules while retaining the old global mode.  That
            # combination makes native sing-box proxy runtime full-tunnel.
            mode = ROUTING_RULE
        raw_bootstrap_servers = data.get("dns_bootstrap_servers")
        if raw_bootstrap_servers is None:
            bootstrap_server = str(data.get("dns_bootstrap_server") or "1.1.1.1")
            bootstrap_servers: list[str] = []
        else:
            bootstrap_servers = [
                str(item).strip()
                for item in (raw_bootstrap_servers if isinstance(raw_bootstrap_servers, list) else [])
                if str(item).strip()
            ]
            bootstrap_server = bootstrap_servers[0] if bootstrap_servers else ""
        return RoutingSettings(
            mode=mode,
            preset_id=preset_id,
            bypass_lan=bool(data.get("bypass_lan", True)),
            direct_domains=list(data.get("direct_domains") or []),
            proxy_domains=list(data.get("proxy_domains") or []),
            block_domains=list(data.get("block_domains") or []),
            dns_mode=str(data.get("dns_mode") or "builtin"),
            dns_bootstrap_server=bootstrap_server,
            dns_bootstrap_servers=bootstrap_servers,
            dns_bootstrap_type=str(data.get("dns_bootstrap_type") or "udp"),
            dns_bootstrap_strategy=str(data.get("dns_bootstrap_strategy") or "ipv4_only"),
            dns_proxy_server=str(data.get("dns_proxy_server") or "cloudflare-dns.com"),
            dns_proxy_servers=list(data.get("dns_proxy_servers") or []),
            dns_proxy_type=str(data.get("dns_proxy_type") or "https"),
            dns_proxy_strategy=str(data.get("dns_proxy_strategy") or "ipv4_only"),
            dns_fake_enabled=bool(data.get("dns_fake_enabled", False)),
            dns_hijack_enabled=bool(data.get("dns_hijack_enabled", True)),
            dns_parallel_query=bool(data.get("dns_parallel_query", False)),
            dns_optimistic_cache=bool(data.get("dns_optimistic_cache", False)),
            dns_geo_check=bool(data.get("dns_geo_check", True)),
            dns_hosts=dict(data.get("dns_hosts") or {}),
            tun_route_exclude_address=[
                str(item).strip()
                for item in (data.get("tun_route_exclude_address") or [])
                if str(item).strip()
            ],
            process_rules=list(data.get("process_rules") or []),
            process_preset_routes=dict(data.get("process_preset_routes") or {}),
            service_routes=dict(data.get("service_routes") or {}),
            tun_default_outbound=str(data.get("tun_default_outbound") or "proxy"),
        )


@dataclass(slots=True)
class SecuritySettings:
    enabled: bool = False
    password_hash: str = ""
    salt: str = ""
    auto_lock_minutes: int = 15

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "password_hash": self.password_hash,
            "salt": self.salt,
            "auto_lock_minutes": self.auto_lock_minutes,
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "SecuritySettings":
        return SecuritySettings(
            enabled=bool(data.get("enabled", False)),
            password_hash=str(data.get("password_hash") or ""),
            salt=str(data.get("salt") or ""),
            auto_lock_minutes=int(data.get("auto_lock_minutes") or 15),
        )


@dataclass(slots=True)
class AppSettings:
    theme: str = "system"  # system | light | dark
    language: str = field(default_factory=lambda: _detect_system_language())  # ru | en | fa | zh
    accent_color: str = "#0078D4"
    interface_mode: str = "full"  # compact | full
    auto_connect_last: bool = True
    start_minimized: bool = False
    enable_system_proxy: bool = True
    system_proxy_bypass_lan: bool = True
    firefox_proxy_integration: bool = False
    launch_on_startup: bool = False
    launch_in_tray_on_startup: bool = True
    always_run_as_admin: bool = False
    # Block connecting when another VPN/proxy client is detected.
    block_vpn_conflicts: bool = True
    reconnect_on_network_change: bool = True
    reconnect_after_sleep: bool = True
    regional_preset: str = "russia"  # russia | china | iran
    prefer_ipv6: bool = False
    # Kill-switch: при неожиданном обрыве VPN не выпускать трафик напрямую (fail-closed).
    kill_switch: bool = False
    # Проверять обновления ядер и geoip/geosite при запуске и уведомлять.
    resource_update_check: bool = False
    xray_path: str = ""
    log_level: str = "warning"
    check_updates: bool = True
    allow_updates: bool = True
    app_auto_update: bool = False
    release_channel: str = "stable"  # stable | beta | nightly
    update_feed_url: str = ""
    xray_release_channel: str = "beta"  # stable | beta | nightly
    xray_update_feed_url: str = ""
    xray_auto_update: bool = False
    enable_xray_fragment: bool = False
    enable_final_fragment: bool = False
    fragment_packets: str = "tlshello"
    fragment_length: str = "50-100"
    fragment_delay: str = "10-20"
    tail_fragment_enabled: bool = False
    multiplex_enabled: bool = False
    multiplex_concurrency: int = 8
    discord_proxy_enabled: bool = False
    tun_mode: bool = False
    xray_config_file: str = ""
    xray_template_file: str = ""
    singbox_path: str = ""
    singbox_config_file: str = ""
    singbox_template_file: str = ""
    window_width: int = DEFAULT_WINDOW_WIDTH
    window_height: int = DEFAULT_WINDOW_HEIGHT
    window_x: int = -1
    window_y: int = -1
    zapret_preset: str = ""
    zapret_autostart: bool = False
    auto_switch_enabled: bool = False
    auto_switch_threshold_kbps: int = 50
    auto_switch_delay_sec: int = 30
    auto_switch_cooldown_sec: int = 60
    # Не подключаться автоматически к только что импортированному серверу.
    auto_connect_on_import: bool = False
    # Способ измерения ping: "tcping" | "icmp" | "real" (реальная задержка HTTP).
    ping_method: str = "tcping"  # tcping | icmp | http | real
    # Пользовательский URL/размер для теста скорости (пусто = значение по умолчанию).
    speed_test_url: str = ""
    # Число одновременных проверок при тесте (0 = значение по умолчанию).
    speed_test_concurrency: int = 0
    # Интервал авто-обновления подписок в минутах (0 = выключено).
    subscription_auto_update_minutes: int = 240
    subscription_include_regex: str = ""
    subscription_exclude_regex: str = ""
    subscription_user_agent: str = ""
    subscription_use_real_hwid: bool = True
    subscription_hwid: str = DEFAULT_SUBSCRIPTION_HWID
    subscription_use_proxy_tun: bool = False
    subscription_converter_enabled: bool = False
    subscription_converter_url: str = ""
    # ── Внешний вид 2.0 (Appearance Studio) ──
    ui_density: str = "comfortable"      # comfortable | compact | spacious
    ui_corner_radius: int = 8            # базовый радиус скругления, px
    ui_font_family: str = ""             # "" = системный шрифт по умолчанию
    ui_font_scale: int = 100             # масштаб шрифта, %
    ui_backdrop: str = "mica"            # mica | acrylic | solid
    ui_transparency_strength: int = 50   # 0..100, higher = more transparent
    ui_theme_preset: str = "default"     # пресет палитры
    ui_animations: bool = True           # глобальный тумблер анимаций
    ui_base_tint: str = ""               # "" = выкл; иначе #RRGGBB — свой базовый тон окна (финальный, приглушённый)
    ui_base_tint_src: str = ""           # "#RRGGBB|mute" — состояние пикера (база + приглушение)
    ui_wallpaper: str = ""               # путь к файлу обоев; "" = выкл
    ui_wallpaper_opacity: int = 50       # непрозрачность обоев, %
    ui_wallpaper_blur: int = 10          # размытие обоев, 0..100
    ui_wallpaper_brightness: int = 50    # яркость обоев, 0..100 (100 = оригинал)
    diagnostics_upload_enabled: bool = True
    proxy_allow_lan: bool = False
    tun_strict_route: bool = False
    tun_stack: str = "mixed"
    tun_mtu: int = 9000
    tun_endpoint_independent_nat: bool = False
    tun_block_quic: bool = True
    local_socks_port: int = 10808
    local_http_port: int = 10809
    proxy_auth_enabled: bool = False
    proxy_auth_username: str = ""
    proxy_auth_password: str = ""
    sniff_route_only: bool = False
    # Servers page UI state. Keep view choices across page recreation and app
    # restarts without mixing them into subscription/node data.
    node_sort_key: str = "manual"
    node_sort_ascending: bool = True
    node_filter_group: str = ""
    selected_subscription_id: str = ""
    node_table_layout: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        from .routing_presets import normalize_regional_preset
        self.regional_preset = normalize_regional_preset(self.regional_preset)
        self.tun_stack = _normalize_tun_stack(self.tun_stack)
        self.local_socks_port = _normalize_local_port(self.local_socks_port, 10808)
        self.local_http_port = _normalize_local_port(self.local_http_port, 10809)
        if self.local_http_port == self.local_socks_port:
            self.local_http_port = _normalize_local_port(self.local_socks_port + 1, 10809)
        self.tun_mtu = _clamp_tun_mtu(self.tun_mtu)
        self.proxy_auth_username = str(self.proxy_auth_username or "").strip()[:256]
        self.proxy_auth_password = str(self.proxy_auth_password or "")[:256]
        if self.proxy_auth_enabled and not (
            self.proxy_auth_username and self.proxy_auth_password
        ):
            self.proxy_auth_enabled = False
        if self.node_sort_key not in {
            "manual", "name", "group", "scheme", "transport", "ping", "speed", "last"
        }:
            self.node_sort_key = "manual"
        self.node_filter_group = str(self.node_filter_group or "").strip()
        self.selected_subscription_id = str(self.selected_subscription_id or "").strip()
        self.node_table_layout = _normalize_node_table_layout(self.node_table_layout)

    def to_dict(self) -> dict[str, Any]:
        return {
            "theme": self.theme,
            "language": self.language,
            "accent_color": self.accent_color,
            "interface_mode": self.interface_mode,
            "auto_connect_last": self.auto_connect_last,
            "start_minimized": self.start_minimized,
            "enable_system_proxy": self.enable_system_proxy,
            "system_proxy_bypass_lan": self.system_proxy_bypass_lan,
            "firefox_proxy_integration": self.firefox_proxy_integration,
            "launch_on_startup": self.launch_on_startup,
            "launch_in_tray_on_startup": self.launch_in_tray_on_startup,
            "always_run_as_admin": self.always_run_as_admin,
            "block_vpn_conflicts": self.block_vpn_conflicts,
            "reconnect_on_network_change": self.reconnect_on_network_change,
            "reconnect_after_sleep": self.reconnect_after_sleep,
            "regional_preset": self.regional_preset,
            "prefer_ipv6": self.prefer_ipv6,
            "kill_switch": self.kill_switch,
            "resource_update_check": self.resource_update_check,
            "xray_path": self.xray_path,
            "log_level": self.log_level,
            "check_updates": self.check_updates,
            "allow_updates": self.allow_updates,
            "app_auto_update": self.app_auto_update,
            "release_channel": self.release_channel,
            "update_feed_url": self.update_feed_url,
            "xray_release_channel": self.xray_release_channel,
            "xray_update_feed_url": self.xray_update_feed_url,
            "xray_auto_update": self.xray_auto_update,
            "enable_xray_fragment": self.enable_xray_fragment,
            "enable_final_fragment": self.enable_final_fragment,
            "fragment_packets": self.fragment_packets,
            "fragment_length": self.fragment_length,
            "fragment_delay": self.fragment_delay,
            "tail_fragment_enabled": self.tail_fragment_enabled,
            "multiplex_enabled": self.multiplex_enabled,
            "multiplex_concurrency": self.multiplex_concurrency,
            "discord_proxy_enabled": self.discord_proxy_enabled,
            "tun_mode": self.tun_mode,
            "proxy_allow_lan": self.proxy_allow_lan,
            "tun_strict_route": self.tun_strict_route,
            "tun_stack": self.tun_stack,
            "tun_mtu": self.tun_mtu,
            "tun_endpoint_independent_nat": self.tun_endpoint_independent_nat,
            "tun_block_quic": self.tun_block_quic,
            "local_socks_port": self.local_socks_port,
            "local_http_port": self.local_http_port,
            "proxy_auth_enabled": self.proxy_auth_enabled,
            "proxy_auth_username": self.proxy_auth_username,
            "proxy_auth_password": self.proxy_auth_password,
            "sniff_route_only": self.sniff_route_only,
            "node_sort_key": self.node_sort_key,
            "node_sort_ascending": self.node_sort_ascending,
            "node_filter_group": self.node_filter_group,
            "selected_subscription_id": self.selected_subscription_id,
            "node_table_layout": dict(self.node_table_layout),
            "xray_config_file": self.xray_config_file,
            "xray_template_file": self.xray_template_file,
            "singbox_path": self.singbox_path,
            "singbox_config_file": self.singbox_config_file,
            "singbox_template_file": self.singbox_template_file,
            "window_width": self.window_width,
            "window_height": self.window_height,
            "window_x": self.window_x,
            "window_y": self.window_y,
            "zapret_preset": self.zapret_preset,
            "zapret_autostart": self.zapret_autostart,
            "auto_switch_enabled": self.auto_switch_enabled,
            "auto_switch_threshold_kbps": self.auto_switch_threshold_kbps,
            "auto_switch_delay_sec": self.auto_switch_delay_sec,
            "auto_switch_cooldown_sec": self.auto_switch_cooldown_sec,
            "auto_connect_on_import": self.auto_connect_on_import,
            "ping_method": self.ping_method,
            "speed_test_url": self.speed_test_url,
            "speed_test_concurrency": self.speed_test_concurrency,
            "subscription_auto_update_minutes": self.subscription_auto_update_minutes,
            "subscription_include_regex": self.subscription_include_regex,
            "subscription_exclude_regex": self.subscription_exclude_regex,
            "subscription_user_agent": self.subscription_user_agent,
            "subscription_use_real_hwid": self.subscription_use_real_hwid,
            "subscription_hwid": self.subscription_hwid,
            "subscription_use_proxy_tun": self.subscription_use_proxy_tun,
            "subscription_converter_enabled": self.subscription_converter_enabled,
            "subscription_converter_url": self.subscription_converter_url,
            "ui_density": self.ui_density,
            "ui_corner_radius": self.ui_corner_radius,
            "ui_font_family": self.ui_font_family,
            "ui_font_scale": self.ui_font_scale,
            "ui_backdrop": self.ui_backdrop,
            "ui_transparency_strength": self.ui_transparency_strength,
            "ui_theme_preset": self.ui_theme_preset,
            "ui_animations": self.ui_animations,
            "ui_base_tint": self.ui_base_tint,
            "ui_base_tint_src": self.ui_base_tint_src,
            "ui_wallpaper": self.ui_wallpaper,
            "ui_wallpaper_opacity": self.ui_wallpaper_opacity,
            "ui_wallpaper_blur": self.ui_wallpaper_blur,
            "ui_wallpaper_brightness": self.ui_wallpaper_brightness,
            "diagnostics_upload_enabled": self.diagnostics_upload_enabled,
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "AppSettings":
        xray_release_channel = str(data.get("xray_release_channel") or "beta").strip().lower()
        if xray_release_channel not in {"stable", "beta"}:
            xray_release_channel = "beta"
        window_width, window_height = _normalize_window_size(
            data.get("window_width"),
            data.get("window_height"),
        )
        return AppSettings(
            theme=str(data.get("theme") or "system"),
            language=_normalize_language(data.get("language")),
            accent_color=str(data.get("accent_color") or "#0078D4"),
            interface_mode=str(data.get("interface_mode") or "full"),
            auto_connect_last=bool(data.get("auto_connect_last", True)),
            start_minimized=bool(data.get("start_minimized", False)),
            enable_system_proxy=bool(data.get("enable_system_proxy", True)),
            system_proxy_bypass_lan=bool(data.get("system_proxy_bypass_lan", True)),
            firefox_proxy_integration=bool(data.get("firefox_proxy_integration", False)),
            launch_on_startup=bool(data.get("launch_on_startup", False)),
            launch_in_tray_on_startup=bool(data.get("launch_in_tray_on_startup", True)),
            always_run_as_admin=bool(data.get("always_run_as_admin", False)),
            block_vpn_conflicts=bool(data.get("block_vpn_conflicts", True)),
            reconnect_on_network_change=bool(data.get("reconnect_on_network_change", True)),
            reconnect_after_sleep=bool(data.get("reconnect_after_sleep", True)),
            regional_preset=str(data.get("regional_preset") or "russia"),
            prefer_ipv6=bool(data.get("prefer_ipv6", False)),
            kill_switch=bool(data.get("kill_switch", False)),
            resource_update_check=bool(data.get("resource_update_check", False)),
            xray_path=str(data.get("xray_path") or ""),
            log_level=str(data.get("log_level") or "warning"),
            check_updates=bool(data.get("check_updates", True)),
            allow_updates=bool(data.get("allow_updates", True)),
            app_auto_update=bool(data.get("app_auto_update", False)),
            release_channel=str(data.get("release_channel") or "stable"),
            update_feed_url=str(data.get("update_feed_url") or ""),
            xray_release_channel=xray_release_channel,
            xray_update_feed_url=str(data.get("xray_update_feed_url") or ""),
            xray_auto_update=bool(data.get("xray_auto_update", False)),
            enable_xray_fragment=bool(data.get("enable_xray_fragment", False)),
            enable_final_fragment=bool(data.get("enable_final_fragment", False)),
            fragment_packets=str(data.get("fragment_packets") or "tlshello"),
            fragment_length=str(data.get("fragment_length") or "50-100"),
            fragment_delay=str(data.get("fragment_delay") or "10-20"),
            tail_fragment_enabled=bool(data.get("tail_fragment_enabled", False)),
            multiplex_enabled=bool(data.get("multiplex_enabled", False)),
            multiplex_concurrency=int(data.get("multiplex_concurrency") or 8),
            discord_proxy_enabled=bool(data.get("discord_proxy_enabled", False)),
            tun_mode=bool(data.get("tun_mode", False)),
            proxy_allow_lan=bool(data.get("proxy_allow_lan", False)),
            tun_strict_route=bool(data.get("tun_strict_route", False)),
            tun_stack=_normalize_tun_stack(data.get("tun_stack")),
            tun_mtu=_clamp_tun_mtu(data.get("tun_mtu")),
            tun_endpoint_independent_nat=bool(data.get("tun_endpoint_independent_nat", False)),
            tun_block_quic=bool(data.get("tun_block_quic", True)),
            local_socks_port=_normalize_local_port(data.get("local_socks_port", 10808), 10808),
            local_http_port=_normalize_local_port(data.get("local_http_port", 10809), 10809),
            proxy_auth_enabled=bool(data.get("proxy_auth_enabled", False)),
            proxy_auth_username=str(data.get("proxy_auth_username") or ""),
            proxy_auth_password=str(data.get("proxy_auth_password") or ""),
            sniff_route_only=bool(data.get("sniff_route_only", False)),
            node_sort_key=str(data.get("node_sort_key") or "manual"),
            node_sort_ascending=bool(data.get("node_sort_ascending", True)),
            node_filter_group=str(data.get("node_filter_group") or ""),
            selected_subscription_id=str(data.get("selected_subscription_id") or ""),
            node_table_layout=(
                dict(data.get("node_table_layout"))
                if isinstance(data.get("node_table_layout"), dict)
                else {}
            ),
            xray_config_file=str(data.get("xray_config_file") or ""),
            xray_template_file=str(data.get("xray_template_file") or ""),
            singbox_path=str(data.get("singbox_path") or ""),
            singbox_config_file=str(data.get("singbox_config_file") or ""),
            singbox_template_file=str(data.get("singbox_template_file") or ""),
            window_width=window_width,
            window_height=window_height,
            window_x=int(data.get("window_x", -1)),
            window_y=int(data.get("window_y", -1)),
            zapret_preset=str(data.get("zapret_preset") or ""),
            zapret_autostart=bool(data.get("zapret_autostart", False)),
            auto_switch_enabled=bool(data.get("auto_switch_enabled", False)),
            auto_switch_threshold_kbps=int(data.get("auto_switch_threshold_kbps") or 50),
            auto_switch_delay_sec=int(data.get("auto_switch_delay_sec") or 30),
            auto_switch_cooldown_sec=int(data.get("auto_switch_cooldown_sec") or 60),
            auto_connect_on_import=bool(data.get("auto_connect_on_import", False)),
            ping_method=str(data.get("ping_method") or "tcping"),
            speed_test_url=str(data.get("speed_test_url") or ""),
            speed_test_concurrency=int(data.get("speed_test_concurrency") or 0),
            subscription_auto_update_minutes=int(data.get("subscription_auto_update_minutes") if data.get("subscription_auto_update_minutes") is not None else 240),
            subscription_include_regex=str(data.get("subscription_include_regex") or ""),
            subscription_exclude_regex=str(data.get("subscription_exclude_regex") or ""),
            subscription_user_agent=str(data.get("subscription_user_agent") or ""),
            subscription_use_real_hwid=bool(data.get("subscription_use_real_hwid", True)),
            subscription_hwid=str(data.get("subscription_hwid") or DEFAULT_SUBSCRIPTION_HWID),
            subscription_use_proxy_tun=bool(data.get("subscription_use_proxy_tun", False)),
            subscription_converter_enabled=bool(data.get("subscription_converter_enabled", False)),
            subscription_converter_url=str(data.get("subscription_converter_url") or ""),
            ui_density=str(data.get("ui_density") or "comfortable"),
            ui_corner_radius=int(data.get("ui_corner_radius") if data.get("ui_corner_radius") is not None else 8),
            ui_font_family=str(data.get("ui_font_family") or ""),
            ui_font_scale=int(data.get("ui_font_scale") or 100),
            ui_backdrop=str(data.get("ui_backdrop") or "mica"),
            ui_transparency_strength=int(data.get("ui_transparency_strength") if data.get("ui_transparency_strength") is not None else 50),
            ui_theme_preset=str(data.get("ui_theme_preset") or "default"),
            ui_animations=bool(data.get("ui_animations", True)),
            ui_base_tint=str(data.get("ui_base_tint") or ""),
            ui_base_tint_src=str(data.get("ui_base_tint_src") or ""),
            ui_wallpaper=str(data.get("ui_wallpaper") or ""),
            ui_wallpaper_opacity=int(data.get("ui_wallpaper_opacity") if data.get("ui_wallpaper_opacity") is not None else 50),
            ui_wallpaper_blur=int(data.get("ui_wallpaper_blur") if data.get("ui_wallpaper_blur") is not None else 10),
            ui_wallpaper_brightness=int(data.get("ui_wallpaper_brightness") if data.get("ui_wallpaper_brightness") is not None else 50),
            diagnostics_upload_enabled=bool(data.get("diagnostics_upload_enabled", True)),
        )


@dataclass(slots=True)
class AppState:
    schema_version: int = STATE_SCHEMA_VERSION
    selected_node_id: str | None = None
    nodes: list[Node] = field(default_factory=list)
    routing: RoutingSettings = field(default_factory=RoutingSettings)
    settings: AppSettings = field(default_factory=AppSettings)
    security: SecuritySettings = field(default_factory=SecuritySettings)
    # Импортированные подписки: [{"url", "name", "group", "updated_at", "node_count"}].
    subscriptions: list[dict[str, Any]] = field(default_factory=list)
    # Ручные группы без подписки. Нужны, чтобы пустая группа была видна в фильтре.
    manual_groups: list[str] = field(default_factory=list)
    # Кастомные пресеты маршрутизации: [{"id", "name", "routing": {...}}].
    routing_presets: list[dict[str, Any]] = field(default_factory=list)
    applied_migrations: dict[str, bool] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "selected_node_id": self.selected_node_id,
            "nodes": [node.to_dict() for node in self.nodes],
            "routing": self.routing.to_dict(),
            "settings": self.settings.to_dict(),
            "security": self.security.to_dict(),
            "subscriptions": [dict(item) for item in self.subscriptions],
            "manual_groups": list(self.manual_groups),
            "routing_presets": [dict(item) for item in self.routing_presets],
            "applied_migrations": dict(self.applied_migrations),
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "AppState":
        nodes_raw = data.get("nodes") or []
        nodes = [Node.from_dict(item) for item in nodes_raw if isinstance(item, dict)]
        subscriptions = [
            dict(item)
            for item in (data.get("subscriptions") or [])
            if isinstance(item, dict)
        ]
        groups: dict[str, list[str]] = {}
        for subscription in subscriptions:
            subscription_id = str(subscription.get("id") or uuid.uuid4())
            subscription["id"] = subscription_id
            group = str(subscription.get("group") or "").strip()
            if group:
                groups.setdefault(group, []).append(subscription_id)
        for node in nodes:
            if node.subscription_id:
                continue
            matches = groups.get(str(node.group or "Default").strip(), [])
            if len(matches) == 1:
                node.subscription_id = matches[0]
        return AppState(
            schema_version=int(data.get("schema_version") or STATE_SCHEMA_VERSION),
            selected_node_id=data.get("selected_node_id"),
            nodes=nodes,
            routing=RoutingSettings.from_dict(dict(data.get("routing") or {})),
            settings=AppSettings.from_dict(dict(data.get("settings") or {})),
            security=SecuritySettings.from_dict(dict(data.get("security") or {})),
            subscriptions=subscriptions,
            manual_groups=[
                str(item).strip()
                for item in (data.get("manual_groups") or [])
                if str(item).strip()
            ],
            routing_presets=[dict(item) for item in (data.get("routing_presets") or []) if isinstance(item, dict)],
            applied_migrations={
                str(key): bool(value)
                for key, value in dict(data.get("applied_migrations") or {}).items()
            },
        )


def _normalize_tun_stack(value: Any) -> str:
    stack = str(value or "").strip().lower()
    return stack if stack in {"system", "gvisor", "mixed"} else "mixed"


def _normalize_node_table_layout(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    allowed = {
        "manual", "name", "type", "transport", "address", "port",
        "group", "ping", "speed", "status", "last",
    }
    normalized: dict[str, Any] = {}
    for raw_key, raw_value in value.items():
        key = str(raw_key)
        if key not in allowed:
            continue
        if key == "manual":
            normalized[key] = bool(raw_value)
            continue
        try:
            numeric = float(raw_value)
        except (TypeError, ValueError):
            continue
        if not math.isfinite(numeric):
            continue
        normalized[key] = max(48.0, min(numeric, 2000.0))
    return normalized


def _clamp_tun_mtu(value: Any) -> int:
    try:
        mtu = int(value)
    except (TypeError, ValueError):
        return 9000
    return max(1280, min(mtu, 65535))


def _normalize_local_port(value: Any, default: int) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return default
    if port < 1025 or port > 65535 or port == 10818:  # 10818 is reserved for droute Discord Voice
        return default
    return port


def _normalize_language(value: Any) -> str:
    language = str(value or "").strip().lower()
    return language if language in {"ru", "en", "fa", "zh"} else _detect_system_language()


def _detect_system_language() -> str:
    try:
        language = (locale.getlocale()[0] or "").lower()
    except Exception:
        language = ""
    if language.startswith("ru"):
        return "ru"
    if language.startswith("fa"):
        return "fa"
    if language.startswith("zh"):
        return "zh"
    return "en"
