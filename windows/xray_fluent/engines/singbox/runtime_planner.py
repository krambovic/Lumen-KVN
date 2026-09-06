from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import hashlib
from ipaddress import ip_address, ip_network
import json
import secrets
import socket
import threading
import time
from pathlib import Path
from typing import Any, Iterable

from ...application.runtime_security import (
    clamp_singbox_local_inbounds,
    generate_local_proxy_credentials,
    strip_singbox_proxy_inbounds,
)
from ...application.node_runtime_service import is_xray_exclusive_node
from ...constants import (
    DATA_DIR,
    DEFAULT_DISCORD_SOCKS_PORT,
    DEFAULT_HTTP_PORT,
    DEFAULT_SOCKS_PORT,
    PROXY_HOST,
    SINGBOX_CLASH_API_PORT,
    SINGBOX_CLASH_API_SELECTOR,
    SINGBOX_TUN_INTERFACE_NAME,
    SINGBOX_XRAY_RELAY_PORT,
    SS_PROTECT_PORT_END,
    SS_PROTECT_PORT_START,
)
from ...models import Node, RoutingSettings
from ...multiplex import apply_xray_multiplex
from ...routing_runtime import apply_singbox_gui_routing
from ...xray_fragments import apply_xray_final_fragment
from ...wireguard_normalization import normalize_singbox_wireguard_endpoints
from ...openvpn_normalization import normalize_openvpn_outbound
from .config_builder import (
    _normalize_vless_vision,
    _preserve_or_reject_semantic_fields,
    _strip_removed_transport_fields,
    build_singbox_outbound,
)


_SS_PROTECT_METHOD = "chacha20-ietf-poly1305"
_APP_SINGBOX_HYBRID_PROTECT_INBOUND_TAG = "__app_hybrid_protect_in"
_APP_XRAY_SIDECAR_RELAY_INBOUND_TAG = "__app_hybrid_relay_in"
_APP_XRAY_SIDECAR_PROTECT_OUTBOUND_TAG = "__app_hybrid_protect_out"
_APP_DISCORD_PROXY_INBOUND_TAG = "discord-socks-in"
_APP_TUN_INBOUND_TAG = "tun-in"
_APP_TUN_MIXED_INBOUND_TAG = "socks-in"
_APP_TUN_HTTP_INBOUND_TAG = "http-in"
_ENDPOINT_DNS_CACHE_TTL_SECONDS = 300.0
_DEFAULT_DIRECT_DNS_SERVER = "1.1.1.1"
_DEFAULT_DIRECT_DNS_TYPE = "udp"
_DEFAULT_PROXY_DNS_SERVER = "cloudflare-dns.com"
_DEFAULT_PROXY_DNS_TYPE = "https"
_SINGBOX_DHCP_AUTO_DNS = "dhcp://auto"
_KNOWN_DOH_IP_HOSTS = {
    "1.0.0.1": "cloudflare-dns.com",
    "1.1.1.1": "cloudflare-dns.com",
    "8.8.4.4": "dns.google",
    "8.8.8.8": "dns.google",
    "9.9.9.9": "dns.quad9.net",
    "149.112.112.112": "dns.quad9.net",
}
_BROWSER_DOH_DOMAIN_SUFFIXES = [
    "cloudflare-dns.com",
    "dns.adguard.com",
    "dns.alidns.com",
    "dns.cloudflare.com",
    "dns.google",
    "dns.nextdns.io",
    "dns.quad9.net",
    "doh.dns.sb",
    "doh.opendns.com",
    "doh.pub",
    "doh.sb",
    "mozilla.cloudflare-dns.com",
    "one.one.one.one",
]
_endpoint_dns_cache: dict[tuple[str, int], tuple[float, tuple[str, ...]]] = {}
_endpoint_dns_cache_lock = threading.Lock()


@dataclass(slots=True)
class SingboxDocumentState:
    source_path: Path
    text: str
    text_hash: str
    has_proxy_outbound: bool
    file_mtime_ns: int = 0
    file_size: int = 0


@dataclass(slots=True)
class ParsedSingboxDocument:
    source_path: Path
    text: str
    text_hash: str
    payload: dict[str, Any]
    has_proxy_outbound: bool


@dataclass(slots=True)
class SingboxXraySidecarPlan:
    relay_port: int
    relay_username: str
    relay_password: str
    protect_port: int
    protect_password: str
    config: dict[str, Any]


@dataclass(slots=True)
class SingboxRuntimePlan:
    outcome: str  # native_singbox | hybrid_xray_sidecar
    source_path: Path
    text_hash: str
    singbox_config: dict[str, Any]
    has_proxy_outbound: bool
    used_selected_node: bool
    clash_api_secret: str
    xray_sidecar: SingboxXraySidecarPlan | None
    clash_api_selector: str = ""
    clash_api_node_signatures: tuple[tuple[str, str], ...] = ()

    @property
    def is_hybrid(self) -> bool:
        return self.outcome == "hybrid_xray_sidecar"


def inspect_singbox_document_text(source_path: Path, text: str) -> SingboxDocumentState:
    text_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
    has_proxy_outbound = False
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        payload = None
    if isinstance(payload, dict):
        has_proxy_outbound = _config_has_proxy_outbound(payload)
    return SingboxDocumentState(
        source_path=source_path,
        text=text,
        text_hash=text_hash,
        has_proxy_outbound=has_proxy_outbound,
    )


def parse_singbox_document(source_path: Path, text: str) -> ParsedSingboxDocument:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{source_path.name}: {_format_json_error_message(text, exc)}") from exc
    if not isinstance(payload, dict):
        raise ValueError("Корень sing-box config должен быть JSON-объектом.")
    text_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
    has_proxy_outbound = _config_has_proxy_outbound(payload)
    return ParsedSingboxDocument(
        source_path=source_path,
        text=text,
        text_hash=text_hash,
        payload=payload,
        has_proxy_outbound=has_proxy_outbound,
    )


def classify_node_for_singbox(node: Node | None) -> str:
    if node is None:
        return "native_singbox"
    if _node_is_full_singbox_config(node):
        return "native_singbox"
    if _node_should_use_xray_sidecar(node):
        return "hybrid_xray_sidecar"
    try:
        build_singbox_outbound(node, tag="proxy")
    except ValueError:
        return "hybrid_xray_sidecar"
    return "native_singbox"


def plan_singbox_runtime(
    document: ParsedSingboxDocument,
    node: Node | None,
    *,
    routing: RoutingSettings | None = None,
    enable_final_fragment: bool = True,
    fragment_packets: str = "tlshello",
    fragment_length: str = "50-100",
    fragment_delay: str = "10-20",
    tail_fragment_enabled: bool = False,
    multiplex_enabled: bool = False,
    multiplex_concurrency: int = 8,
    discord_proxy_enabled: bool = False,
    tun_strict_route: bool = False,
    tun_stack: str = "mixed",
    tun_mtu: int = 9000,
    tun_endpoint_independent_nat: bool = False,
    tun_block_quic: bool = True,
    local_socks_port: int = DEFAULT_SOCKS_PORT,
    local_http_port: int = DEFAULT_HTTP_PORT,
    proxy_auth_username: str = "",
    proxy_auth_password: str = "",
    preferred_relay_port: int = 0,
    preferred_protect_port: int = 0,
    preferred_protect_password: str = "",
    system_dns_servers: tuple[str, ...] = (),
    tun_mode: bool = True,
    enable_hot_switch: bool = False,
    hot_switch_nodes: Iterable[Node] | None = None,
) -> SingboxRuntimePlan:
    if _node_is_full_singbox_config(node):
        runtime_config = deepcopy((node.outbound or {}).get("singbox_config") or {})
        _preserve_or_reject_semantic_fields(runtime_config)
        _strip_removed_transport_fields(runtime_config)
        _normalize_vless_vision(runtime_config)
        normalize_singbox_wireguard_endpoints(runtime_config)
        # Keep legacy AWG 1.5 imports readable on disk, but never pass their
        # removed members to the strict extended 2.6.x decoder.  Full imported
        # profiles bypass the selected-node path, so sanitize them here too.
        _strip_legacy_awg15_fields(runtime_config)
        _ensure_awg3_windows_bind_workarounds(runtime_config)
        _normalize_openvpn_outbounds(runtime_config)
        strip_singbox_proxy_inbounds(runtime_config)
        _configure_singbox_runtime_inbounds(
            runtime_config,
            tun_mode=tun_mode,
            local_socks_port=local_socks_port,
            local_http_port=local_http_port,
            proxy_auth_username=proxy_auth_username,
            proxy_auth_password=proxy_auth_password,
        )
        clash_api_secret = _ensure_singbox_metrics_contract(runtime_config)
        _ensure_singbox_runtime_contract(
            runtime_config,
            tun_mode=tun_mode,
            routing=routing,
            enable_final_fragment=enable_final_fragment,
            system_dns_servers=system_dns_servers,
            tun_strict_route=tun_strict_route,
            tun_stack=tun_stack,
            tun_mtu=tun_mtu,
            tun_endpoint_independent_nat=tun_endpoint_independent_nat,
            tun_block_quic=tun_block_quic,
            local_socks_port=local_socks_port,
            local_http_port=local_http_port,
            proxy_auth_username=proxy_auth_username,
            proxy_auth_password=proxy_auth_password,
        )
        _ensure_full_config_proxy_alias(runtime_config)
        if routing is not None:
            apply_singbox_gui_routing(runtime_config, routing)
        # Add bootstrap loop protection after GUI rules so it keeps the runtime's
        # reserved priority without being confused with imported user routes.
        _ensure_all_server_bootstrap_contracts(runtime_config)
        _ensure_singbox_discord_proxy_contract(runtime_config, enabled=discord_proxy_enabled)
        clamp_singbox_local_inbounds(runtime_config)
        _validate_runtime_dns_contract(runtime_config)
        return SingboxRuntimePlan(
            outcome="native_singbox",
            source_path=document.source_path,
            text_hash=document.text_hash,
            singbox_config=runtime_config,
            has_proxy_outbound=True,
            used_selected_node=True,
            clash_api_secret=clash_api_secret,
            xray_sidecar=None,
        )

    runtime_config = deepcopy(document.payload)
    _preserve_or_reject_semantic_fields(runtime_config)
    _strip_removed_transport_fields(runtime_config)
    _normalize_vless_vision(runtime_config)
    normalize_singbox_wireguard_endpoints(runtime_config)
    _normalize_openvpn_outbounds(runtime_config)
    strip_singbox_proxy_inbounds(runtime_config)
    _configure_singbox_runtime_inbounds(
        runtime_config,
        tun_mode=tun_mode,
        local_socks_port=local_socks_port,
        local_http_port=local_http_port,
        proxy_auth_username=proxy_auth_username,
        proxy_auth_password=proxy_auth_password,
    )
    clash_api_secret = _ensure_singbox_metrics_contract(runtime_config)
    _ensure_singbox_runtime_contract(
        runtime_config,
        tun_mode=tun_mode,
        routing=routing,
        enable_final_fragment=enable_final_fragment,
        system_dns_servers=system_dns_servers,
        tun_strict_route=tun_strict_route,
        tun_stack=tun_stack,
        tun_mtu=tun_mtu,
        tun_endpoint_independent_nat=tun_endpoint_independent_nat,
        tun_block_quic=tun_block_quic,
        local_socks_port=local_socks_port,
        local_http_port=local_http_port,
        proxy_auth_username=proxy_auth_username,
        proxy_auth_password=proxy_auth_password,
    )
    outbounds = runtime_config.get("outbounds")
    proxy_index = _find_proxy_outbound_index(outbounds)
    if proxy_index is None:
        # The runtime contracts reference outbound `proxy`; a document whose own
        # proxy outbound is tagged differently needs the alias to resolve them.
        _ensure_full_config_proxy_alias(runtime_config)
        _strip_legacy_awg15_fields(runtime_config)
        _ensure_awg3_windows_bind_workarounds(runtime_config)
        if routing is not None:
            apply_singbox_gui_routing(runtime_config, routing)
        _ensure_all_server_bootstrap_contracts(runtime_config)
        _ensure_singbox_discord_proxy_contract(runtime_config, enabled=discord_proxy_enabled)
        clamp_singbox_local_inbounds(runtime_config)
        _validate_runtime_dns_contract(runtime_config)
        return SingboxRuntimePlan(
            outcome="native_singbox",
            source_path=document.source_path,
            text_hash=document.text_hash,
            singbox_config=runtime_config,
            has_proxy_outbound=False,
            used_selected_node=False,
            clash_api_secret=clash_api_secret,
            xray_sidecar=None,
        )

    if node is None:
        raise ValueError("В конфиге есть outbound tag `proxy`. Выберите сервер для запуска sing-box.")

    force_sidecar = _node_should_use_xray_sidecar(node)
    try:
        native_proxy = None if force_sidecar else build_singbox_outbound(
            node,
            tag="proxy",
            multiplex_enabled=multiplex_enabled,
            multiplex_concurrency=multiplex_concurrency,
        )
    except ValueError:
        native_proxy = None

    if native_proxy is None:
        plan = _plan_hybrid_runtime(
            document,
            runtime_config=runtime_config,
            proxy_index=proxy_index,
            node=node,
            enable_final_fragment=enable_final_fragment,
            fragment_packets=fragment_packets,
            fragment_length=fragment_length,
            fragment_delay=fragment_delay,
            tail_fragment_enabled=tail_fragment_enabled,
            multiplex_enabled=multiplex_enabled,
            multiplex_concurrency=multiplex_concurrency,
            preferred_relay_port=preferred_relay_port,
            preferred_protect_port=preferred_protect_port,
            preferred_protect_password=preferred_protect_password,
            clash_api_secret=clash_api_secret,
        )
        if routing is not None:
            apply_singbox_gui_routing(plan.singbox_config, routing)
        _ensure_all_server_bootstrap_contracts(plan.singbox_config)
        _ensure_singbox_discord_proxy_contract(plan.singbox_config, enabled=discord_proxy_enabled)
        clamp_singbox_local_inbounds(plan.singbox_config)
        _validate_runtime_dns_contract(plan.singbox_config)
        return plan

    assert isinstance(outbounds, list)
    native_is_endpoint = _is_singbox_endpoint(native_proxy)
    if native_is_endpoint:
        outbounds.pop(proxy_index)
        _strip_legacy_awg15_fields(native_proxy)
        ensure_awg3_windows_bind_workaround(runtime_config, native_proxy)
        _replace_or_append_tagged(_ensure_list(runtime_config, "endpoints"), "proxy", native_proxy)
    else:
        outbounds[proxy_index] = native_proxy
    clash_api_selector = ""
    clash_api_node_signatures: tuple[tuple[str, str], ...] = ()
    if enable_hot_switch:
        clash_api_selector, clash_api_node_signatures = _ensure_singbox_hot_switch_selector(
            runtime_config,
            selected_node=node,
            candidate_nodes=hot_switch_nodes,
            multiplex_enabled=multiplex_enabled,
            multiplex_concurrency=multiplex_concurrency,
        )
    if routing is not None:
        apply_singbox_gui_routing(runtime_config, routing)
    _ensure_all_server_bootstrap_contracts(runtime_config)
    if native_is_endpoint:
        _ensure_endpoint_server_bootstrap_contract(runtime_config, native_proxy)
    elif str(native_proxy.get("type") or "").strip().lower() == "openvpn":
        _ensure_openvpn_server_bootstrap_contract(runtime_config, native_proxy)
    else:
        _ensure_proxy_server_bootstrap_contract(runtime_config, native_proxy, node.server)
    _apply_imported_proxy_dns(runtime_config, node, routing)
    _clamp_tun_mtu_for_proxy(runtime_config, native_proxy, enabled=tun_mode)
    _ensure_singbox_discord_proxy_contract(runtime_config, enabled=discord_proxy_enabled)
    clamp_singbox_local_inbounds(runtime_config)
    _validate_runtime_dns_contract(runtime_config)
    return SingboxRuntimePlan(
        outcome="native_singbox",
        source_path=document.source_path,
        text_hash=document.text_hash,
        singbox_config=runtime_config,
        has_proxy_outbound=True,
        used_selected_node=True,
        clash_api_secret=clash_api_secret,
        xray_sidecar=None,
        clash_api_selector=clash_api_selector,
        clash_api_node_signatures=clash_api_node_signatures,
    )


def _plan_hybrid_runtime(
    document: ParsedSingboxDocument,
    *,
    runtime_config: dict[str, Any],
    proxy_index: int,
    node: Node,
    enable_final_fragment: bool,
    fragment_packets: str,
    fragment_length: str,
    fragment_delay: str,
    tail_fragment_enabled: bool,
    multiplex_enabled: bool,
    multiplex_concurrency: int,
    preferred_relay_port: int,
    preferred_protect_port: int,
    preferred_protect_password: str,
    clash_api_secret: str,
) -> SingboxRuntimePlan:
    relay_port = preferred_relay_port if preferred_relay_port > 0 else _find_free_port(preferred=SINGBOX_XRAY_RELAY_PORT)
    excluded_ports = {relay_port}
    protect_port = preferred_protect_port if preferred_protect_port > 0 else _find_free_port(
        preferred=SS_PROTECT_PORT_START,
        port_range=range(SS_PROTECT_PORT_START, SS_PROTECT_PORT_END),
        excluded=excluded_ports,
    )
    protect_password = preferred_protect_password or _generate_ss_password()
    relay_username, relay_password = generate_local_proxy_credentials(prefix="sidecar")

    outbounds = runtime_config.setdefault("outbounds", [])
    assert isinstance(outbounds, list)
    outbounds[proxy_index] = {
        "type": "socks",
        "tag": "proxy",
        "server": PROXY_HOST,
        "server_port": relay_port,
        "username": relay_username,
        "password": relay_password,
        # Keep the relay on loopback so sing-box does not bind it to the
        # physical adapter via auto-detect rules.
        "inet4_bind_address": PROXY_HOST,
    }

    _replace_or_append_tagged(
        _ensure_list(runtime_config, "inbounds"),
        _APP_SINGBOX_HYBRID_PROTECT_INBOUND_TAG,
        {
            "type": "shadowsocks",
            "tag": _APP_SINGBOX_HYBRID_PROTECT_INBOUND_TAG,
            "listen": PROXY_HOST,
            "listen_port": protect_port,
            "method": _SS_PROTECT_METHOD,
            "password": protect_password,
        },
    )
    _ensure_hybrid_protect_route(runtime_config)
    _remove_singbox_tls_fragment_rule(runtime_config)
    clamp_singbox_local_inbounds(runtime_config)
    _validate_runtime_dns_contract(runtime_config)

    sidecar = SingboxXraySidecarPlan(
        relay_port=relay_port,
        relay_username=relay_username,
        relay_password=relay_password,
        protect_port=protect_port,
        protect_password=protect_password,
        config=_build_xray_sidecar_config(
            node,
            relay_port=relay_port,
            relay_username=relay_username,
            relay_password=relay_password,
            protect_port=protect_port,
            protect_password=protect_password,
            enable_final_fragment=enable_final_fragment,
            fragment_packets=fragment_packets,
            fragment_length=fragment_length,
            fragment_delay=fragment_delay,
            tail_fragment_enabled=tail_fragment_enabled,
            multiplex_enabled=multiplex_enabled,
            multiplex_concurrency=multiplex_concurrency,
        ),
    )
    return SingboxRuntimePlan(
        outcome="hybrid_xray_sidecar",
        source_path=document.source_path,
        text_hash=document.text_hash,
        singbox_config=runtime_config,
        has_proxy_outbound=True,
        used_selected_node=True,
        clash_api_secret=clash_api_secret,
        xray_sidecar=sidecar,
    )


def _node_should_use_xray_sidecar(node: Node | None) -> bool:
    """Return True only for transports that require the Xray sidecar."""
    return is_xray_exclusive_node(node)


def _node_is_full_singbox_config(node: Node | None) -> bool:
    outbound = node.outbound if node is not None else None
    if not isinstance(outbound, dict):
        return False
    return str(outbound.get("protocol") or node.scheme or "").strip().lower() == "singbox_config" and isinstance(
        outbound.get("singbox_config"),
        dict,
    )


def singbox_node_tag(node_id: str) -> str:
    """Return a stable, opaque outbound tag for a stored Lumen node."""
    digest = hashlib.sha256(str(node_id or "").encode("utf-8")).hexdigest()
    return f"lumen-node-{digest[:20]}"


def singbox_node_source_signature(node: Node) -> str:
    """Return the source data used to build a node's native outbound."""
    payload = {
        "scheme": str(node.scheme or ""),
        "server": str(node.server or ""),
        "port": int(node.port),
        "link": str(node.link or ""),
        "outbound": node.outbound if isinstance(node.outbound, dict) else {},
    }
    text = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _node_has_eager_singbox_runtime(node: Node) -> bool:
    """Return whether merely declaring the node can start background traffic."""
    outbound = node.outbound if isinstance(node.outbound, dict) else {}
    native = outbound.get("singbox") if isinstance(outbound.get("singbox"), dict) else {}
    outbound_type = str(
        native.get("type") or outbound.get("protocol") or node.scheme or ""
    ).strip().lower()
    return outbound_type in {"masque", "wireguard", "awg", "warp", "openvpn"}


def _ensure_singbox_hot_switch_selector(
    config: dict[str, Any],
    *,
    selected_node: Node,
    candidate_nodes: Iterable[Node] | None,
    multiplex_enabled: bool,
    multiplex_concurrency: int,
) -> tuple[str, tuple[tuple[str, str], ...]]:
    """Build a selector containing every node usable by native sing-box.

    The regular runtime still exposes the selected node as ``proxy``.  This
    helper replaces that single outbound only when at least two stored nodes
    can be represented natively, leaving unsupported/hybrid nodes to the
    existing restart fallback.
    """
    outbounds = config.get("outbounds")
    if not isinstance(outbounds, list):
        return "", ()

    candidates: list[Node] = [selected_node]
    seen_ids = {selected_node.id}
    for node in candidate_nodes or ():
        if node.id in seen_ids:
            continue
        seen_ids.add(node.id)
        candidates.append(node)

    native_entries: list[tuple[str, Node, dict[str, Any]]] = []
    for node in candidates:
        if (
            _node_is_full_singbox_config(node)
            or _node_should_use_xray_sidecar(node)
            or _node_has_eager_singbox_runtime(node)
        ):
            continue
        try:
            native = build_singbox_outbound(
                node,
                tag=singbox_node_tag(node.id),
                multiplex_enabled=multiplex_enabled,
                multiplex_concurrency=multiplex_concurrency,
            )
        except (TypeError, ValueError):
            continue
        native_entries.append((singbox_node_tag(node.id), node, native))

    selected_tag = singbox_node_tag(selected_node.id)
    if len(native_entries) < 2 or not any(tag == selected_tag for tag, _, _ in native_entries):
        return "", ()

    endpoints = _ensure_list(config, "endpoints")
    outbounds[:] = [
        item
        for item in outbounds
        if not (isinstance(item, dict) and str(item.get("tag") or "") == SINGBOX_CLASH_API_SELECTOR)
    ]
    endpoints[:] = [
        item
        for item in endpoints
        if not (
            isinstance(item, dict)
            and (
                str(item.get("tag") or "") == SINGBOX_CLASH_API_SELECTOR
                or str(item.get("tag") or "").startswith("lumen-node-")
            )
        )
    ]

    member_tags: list[str] = []
    for tag, node, native in native_entries:
        member_tags.append(tag)
        if _is_singbox_endpoint(native):
            _strip_legacy_awg15_fields(native)
            ensure_awg3_windows_bind_workaround(config, native)
            _replace_or_append_tagged(endpoints, tag, native)
            _ensure_endpoint_server_bootstrap_contract(config, native)
        else:
            outbounds.append(native)
            if str(native.get("type") or "").strip().lower() == "openvpn":
                _ensure_openvpn_server_bootstrap_contract(config, native)
            else:
                _ensure_proxy_server_bootstrap_contract(config, native, node.server)

    outbounds.append(
        {
            "type": "selector",
            "tag": SINGBOX_CLASH_API_SELECTOR,
            "outbounds": member_tags,
            "default": selected_tag,
            "interrupt_exist_connections": True,
        }
    )
    return SINGBOX_CLASH_API_SELECTOR, tuple(
        (node.id, singbox_node_source_signature(node))
        for _, node, _ in native_entries
    )


def _ensure_full_config_proxy_alias(config: dict[str, Any]) -> None:
    outbounds = config.get("outbounds")
    if not isinstance(outbounds, list):
        return
    tags = {
        str(outbound.get("tag") or "")
        for outbound in outbounds
        if isinstance(outbound, dict)
    }
    if "proxy" in tags:
        return
    route = config.get("route") if isinstance(config.get("route"), dict) else {}
    preferred = str(route.get("final") or "").strip()
    ignored = {"", "direct", "block", "dns"}
    if not preferred or preferred in ignored or preferred not in tags:
        for outbound in outbounds:
            if not isinstance(outbound, dict):
                continue
            tag = str(outbound.get("tag") or "").strip()
            outbound_type = str(outbound.get("type") or "").strip().lower()
            if tag and tag not in ignored and outbound_type not in ignored:
                preferred = tag
                break
    if not preferred or preferred in ignored:
        return
    outbounds.append(
        {
            "type": "selector",
            "tag": "proxy",
            "outbounds": [preferred],
            "default": preferred,
            "interrupt_exist_connections": True,
        }
    )


def _ensure_tun_inbound(config: dict[str, Any]) -> None:
    inbounds = _ensure_list(config, "inbounds")
    if any(isinstance(inbound, dict) and str(inbound.get("type") or "").strip().lower() == "tun" for inbound in inbounds):
        return
    inbounds.insert(
        0,
        {
            "type": "tun",
            "tag": _APP_TUN_INBOUND_TAG,
            "interface_name": SINGBOX_TUN_INTERFACE_NAME,
        },
    )


def _rename_singbox_rule_inbound_tags(payload: dict[str, Any], old_tags: set[str], new_tag: str) -> None:
    route = payload.get("route")
    if not isinstance(route, dict):
        return
    for rule in route.get("rules") or []:
        if not isinstance(rule, dict):
            continue
        inbound = rule.get("inbound")
        if isinstance(inbound, str):
            if inbound in old_tags:
                rule["inbound"] = new_tag
        elif isinstance(inbound, list):
            rule["inbound"] = list(
                dict.fromkeys(new_tag if str(item) in old_tags else item for item in inbound)
            )


def _configure_singbox_runtime_inbounds(
    config: dict[str, Any],
    *,
    tun_mode: bool,
    local_socks_port: int,
    local_http_port: int,
    proxy_auth_username: str,
    proxy_auth_password: str,
) -> None:
    inbounds = _ensure_list(config, "inbounds")
    if tun_mode:
        _ensure_tun_inbound(config)
        return
    inbounds[:] = [
        inbound
        for inbound in inbounds
        if not (isinstance(inbound, dict) and str(inbound.get("type") or "").strip().lower() == "tun")
    ]
    _ensure_singbox_tun_local_proxy_contract(
        config,
        socks_port=local_socks_port,
        http_port=local_http_port,
        username=proxy_auth_username,
        password=proxy_auth_password,
    )


def _build_xray_sidecar_config(
    node: Node,
    *,
    relay_port: int,
    relay_username: str,
    relay_password: str,
    protect_port: int,
    protect_password: str,
    enable_final_fragment: bool = True,
    fragment_packets: str = "tlshello",
    fragment_length: str = "50-100",
    fragment_delay: str = "10-20",
    tail_fragment_enabled: bool = False,
    multiplex_enabled: bool = False,
    multiplex_concurrency: int = 8,
) -> dict[str, Any]:
    if not isinstance(node.outbound, dict) or not node.outbound:
        raise ValueError("Выбранный сервер не содержит outbound JSON для xray sidecar.")
    if not str(node.outbound.get("protocol") or "").strip():
        raise ValueError("Выбранный сервер не содержит protocol для xray sidecar.")
    if str(node.outbound.get("protocol") or "").strip().lower() == "xray_config":
        full_config = node.outbound.get("xray_config")
        if not isinstance(full_config, dict):
            raise ValueError("AUTO-профиль Xray повреждён: отсутствует полный JSON-конфиг.")
        config = deepcopy(full_config)
        outbounds = config.get("outbounds")
        if not isinstance(outbounds, list) or not outbounds:
            raise ValueError("AUTO-профиль Xray не содержит список outbounds.")

        config["inbounds"] = [
            {
                "tag": _APP_XRAY_SIDECAR_RELAY_INBOUND_TAG,
                "protocol": "socks",
                "listen": PROXY_HOST,
                "port": relay_port,
                "settings": {
                    "auth": "password",
                    "accounts": [{"user": relay_username, "pass": relay_password}],
                    "udp": True,
                },
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls"],
                    "routeOnly": False,
                },
            }
        ]
        ignored_protocols = {"freedom", "blackhole", "dns"}
        for outbound in outbounds:
            if not isinstance(outbound, dict):
                continue
            protocol = str(outbound.get("protocol") or "").strip().lower()
            if protocol in ignored_protocols:
                continue
            stream = outbound.get("streamSettings")
            if not isinstance(stream, dict):
                stream = {}
                outbound["streamSettings"] = stream
            sockopt = stream.get("sockopt")
            if not isinstance(sockopt, dict):
                sockopt = {}
                stream["sockopt"] = sockopt
            sockopt["dialerProxy"] = _APP_XRAY_SIDECAR_PROTECT_OUTBOUND_TAG
        outbounds.append(
            {
                "tag": _APP_XRAY_SIDECAR_PROTECT_OUTBOUND_TAG,
                "protocol": "shadowsocks",
                "settings": {
                    "servers": [
                        {
                            "address": PROXY_HOST,
                            "port": protect_port,
                            "method": _SS_PROTECT_METHOD,
                            "password": protect_password,
                        }
                    ]
                },
            }
        )
        return config

    proxy_outbound = deepcopy(node.outbound)
    proxy_outbound["tag"] = "proxy"
    apply_xray_multiplex(
        proxy_outbound,
        enabled=multiplex_enabled,
        concurrency=multiplex_concurrency,
    )
    stream_settings = proxy_outbound.get("streamSettings")
    if not isinstance(stream_settings, dict):
        stream_settings = {}
        proxy_outbound["streamSettings"] = stream_settings
    sockopt = stream_settings.get("sockopt")
    if not isinstance(sockopt, dict):
        sockopt = {}
        stream_settings["sockopt"] = sockopt
    sockopt["dialerProxy"] = _APP_XRAY_SIDECAR_PROTECT_OUTBOUND_TAG

    config = {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "tag": _APP_XRAY_SIDECAR_RELAY_INBOUND_TAG,
                "protocol": "socks",
                "listen": PROXY_HOST,
                "port": relay_port,
                "settings": {
                    "auth": "password",
                    "accounts": [{"user": relay_username, "pass": relay_password}],
                    "udp": True,
                },
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls"],
                    "routeOnly": False,
                },
            }
        ],
        "outbounds": [
            proxy_outbound,
            {
                "tag": _APP_XRAY_SIDECAR_PROTECT_OUTBOUND_TAG,
                "protocol": "shadowsocks",
                "settings": {
                    "servers": [
                        {
                            "address": PROXY_HOST,
                            "port": protect_port,
                            "method": _SS_PROTECT_METHOD,
                            "password": protect_password,
                        }
                    ]
                },
            },
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                {
                    "type": "field",
                    "inboundTag": [_APP_XRAY_SIDECAR_RELAY_INBOUND_TAG],
                    "outboundTag": "proxy",
                }
            ],
        },
    }
    if enable_final_fragment:
        apply_xray_final_fragment(
            config,
            packets=fragment_packets,
            length=fragment_length,
            delay=fragment_delay,
            tail_fragment=tail_fragment_enabled,
        )
    return config


def _is_domain_name(value: str) -> bool:
    host = str(value or "").strip()
    if not host:
        return False
    if _is_dhcp_auto_dns(host):
        return False
    try:
        ip_address(host)
    except ValueError:
        return True
    return False


def _is_dhcp_auto_dns(value: str) -> bool:
    return str(value or "").strip().lower() == _SINGBOX_DHCP_AUTO_DNS


def _ensure_proxy_server_bootstrap_contract(
    payload: dict[str, Any],
    proxy_outbound: dict[str, Any],
    preferred_server: str,
) -> None:
    server = str(preferred_server or proxy_outbound.get("server") or "").strip()
    if not server:
        return
    endpoint_cidr = _endpoint_ip_cidr(server)
    if endpoint_cidr:
        _ensure_tun_route_exclude_addresses(payload, [endpoint_cidr])
        _ensure_direct_ip_route(payload, endpoint_cidr)
        return

    # Domain-based proxy servers must resolve through bootstrap-dns, otherwise
    # proxy-dns can recurse into the proxy outbound before the tunnel is ready.
    proxy_outbound["domain_resolver"] = "bootstrap-dns"
    endpoint_addresses = _resolve_endpoint_addresses(server)
    endpoint_cidrs = [_endpoint_ip_cidr(address) for address in endpoint_addresses]
    if endpoint_cidrs:
        # v2rayN parity: keep the domain in the outbound so sing-box re-resolves it on every redial
        _ensure_tun_route_exclude_addresses(payload, endpoint_cidrs)
        for cidr in endpoint_cidrs:
            _ensure_direct_ip_route(payload, cidr)
    _ensure_direct_domain_route(payload, server)


AWG3_DIRECT_DETOUR_TAG = "awg3-direct"


def _strip_legacy_awg15_fields(payload: dict[str, Any]) -> bool:
    """Remove AWG 1.5-only fields before handing data to extended 2.6.x.

    Older imports remain readable/editable (and can still be exported), while
    the current strict sing-box schema never receives the removed J1-J3/Itime
    members.  The operation is deliberately limited to the runtime copy.
    """
    changed = False
    endpoints = payload.get("endpoints") if isinstance(payload.get("endpoints"), list) else None
    candidates = endpoints if endpoints is not None else [payload]
    for endpoint in candidates:
        if not isinstance(endpoint, dict):
            continue
        amnezia = endpoint.get("amnezia")
        if not isinstance(amnezia, dict):
            continue
        for key in ("j1", "j2", "j3", "itime"):
            if key in amnezia:
                amnezia.pop(key, None)
                changed = True
    return changed


def endpoint_needs_windows_bind_workaround(endpoint: dict[str, Any]) -> bool:
    """Return whether an AWG 3.0 endpoint needs a non-default Windows bind."""
    amnezia = endpoint.get("amnezia")
    return isinstance(amnezia, dict) and bool(
        str(amnezia.get("header_protection_key") or "").strip()
    )


def ensure_awg3_windows_bind_workaround(
    runtime_config: dict[str, Any], endpoint: dict[str, Any]
) -> bool:
    """Route AWG 3.0 through a direct detour to avoid the Windows bind bug.

    The extended core's default Windows WireGuard listener rewrites bytes that
    are part of AWG 3.0 header-protection's nonce.  A detour selects the
    userspace ClientBind path and leaves those bytes intact.  Explicit user
    detours are preserved.
    """
    if not endpoint_needs_windows_bind_workaround(endpoint):
        return False
    if str(endpoint.get("detour") or "").strip():
        return False
    outbounds = _ensure_list(runtime_config, "outbounds")
    if not any(
        isinstance(item, dict) and item.get("tag") == AWG3_DIRECT_DETOUR_TAG
        for item in outbounds
    ):
        outbounds.append({"type": "direct", "tag": AWG3_DIRECT_DETOUR_TAG})
    endpoint["detour"] = AWG3_DIRECT_DETOUR_TAG
    return True


def _ensure_awg3_windows_bind_workarounds(runtime_config: dict[str, Any]) -> bool:
    """Apply the AWG 3.0 Windows bind workaround to imported endpoints.

    Selected-node plans call :func:`ensure_awg3_windows_bind_workaround`
    directly.  A full sing-box document can contain several endpoints and does
    not have a selected ``Node`` to pass through that path, so inspect all
    top-level endpoints without changing explicit detours.
    """
    endpoints = runtime_config.get("endpoints")
    if not isinstance(endpoints, list):
        return False
    changed = False
    for endpoint in endpoints:
        if isinstance(endpoint, dict):
            changed = ensure_awg3_windows_bind_workaround(runtime_config, endpoint) or changed
    return changed


def _ensure_endpoint_server_bootstrap_contract(payload: dict[str, Any], endpoint: dict[str, Any]) -> None:
    endpoint_type = str(endpoint.get("type") or "").strip().lower()
    hosts: list[str] = []
    if endpoint_type in {"wireguard", "warp"} and not str(endpoint.get("detour") or "").strip():
        # sing-box on Windows fails to bind the WireGuard endpoint socket when
        # route.auto_detect_interface is enabled and the endpoint has no detour
        # ("unable to update bind: An invalid argument was supplied", see
        # SagerNet/sing-box#2900). The endpoint then reports "connected" but
        # passes no traffic. Pin the endpoint dialer to the direct outbound,
        # mirroring what masque/openvpn outbounds already do.
        endpoint["detour"] = "direct"
    if endpoint_type == "wireguard":
        endpoint["domain_resolver"] = "bootstrap-dns"
        for peer in endpoint.get("peers") or []:
            if isinstance(peer, dict):
                hosts.append(str(peer.get("address") or "").strip())
    elif endpoint_type == "warp":
        endpoint["domain_resolver"] = "bootstrap-dns"
        hosts.append("engage.cloudflareclient.com")

    resolved_by_host: dict[str, list[str]] = {}
    endpoint_cidrs: list[str] = []
    for host in hosts:
        cidr = _endpoint_ip_cidr(host)
        if cidr:
            endpoint_cidrs.append(cidr)
        elif _is_domain_name(host):
            resolved_by_host[host] = _resolve_endpoint_ip_cidrs(host)
            endpoint_cidrs.extend(resolved_by_host[host])
    _ensure_tun_route_exclude_addresses(payload, [cidr for cidr in endpoint_cidrs if cidr])
    for host in hosts:
        endpoint_cidr = _endpoint_ip_cidr(host)
        if endpoint_cidr:
            _ensure_direct_ip_route(payload, endpoint_cidr)
        elif _is_domain_name(host):
            for cidr in resolved_by_host.get(host, []):
                _ensure_direct_ip_route(payload, cidr)
            _ensure_direct_domain_route(payload, host)


def _ensure_all_endpoint_server_bootstrap_contract(payload: dict[str, Any]) -> None:
    endpoints = payload.get("endpoints")
    if not isinstance(endpoints, list):
        return
    for endpoint in endpoints:
        if not isinstance(endpoint, dict):
            continue
        if str(endpoint.get("type") or "").strip().lower() not in {"wireguard", "warp"}:
            continue
        _ensure_endpoint_server_bootstrap_contract(payload, endpoint)


def _ensure_openvpn_server_bootstrap_contract(
    payload: dict[str, Any],
    outbound: dict[str, Any],
) -> None:
    servers = outbound.get("servers")
    if not isinstance(servers, list):
        return
    for server_options in servers:
        if not isinstance(server_options, dict):
            continue
        server = str(server_options.get("server") or "").strip()
        if server:
            _ensure_proxy_server_bootstrap_contract(payload, outbound, server)


def _normalize_openvpn_outbounds(payload: dict[str, Any]) -> None:
    outbounds = payload.get("outbounds")
    if not isinstance(outbounds, list):
        return
    used_names: set[str] = set()
    openvpn_index = 0
    detours: list[dict[str, Any]] = []
    for outbound in outbounds:
        if not isinstance(outbound, dict):
            continue
        if str(outbound.get("type") or "").strip().lower() != "openvpn":
            continue
        normalize_openvpn_outbound(outbound)
        outbound["system"] = False
        requested_name = str(outbound.get("name") or f"openvpn{openvpn_index}").strip()
        name_candidate = requested_name
        suffix = 1
        while name_candidate in used_names:
            name_candidate = f"{requested_name}-{suffix}"
            suffix += 1
        outbound["name"] = name_candidate
        used_names.add(name_candidate)
        proxy = outbound.pop("lumen_proxy", None)
        if isinstance(proxy, dict):
            proxy_type = str(proxy.get("type") or "").strip().lower()
            if proxy_type not in {"http", "socks"}:
                raise ValueError(f"Unsupported OpenVPN proxy type `{proxy_type or 'unknown'}`")
            server = str(proxy.get("server") or "").strip()
            try:
                port = int(proxy.get("server_port") or 0)
            except (TypeError, ValueError):
                port = 0
            if not server or not (1 <= port <= 65535):
                raise ValueError("OpenVPN proxy must contain a valid server and port")
            detour_tag = f"ovpn-proxy-{openvpn_index}"
            outbound["detour"] = detour_tag
            detour: dict[str, Any] = {
                "type": proxy_type,
                "tag": detour_tag,
                "server": server,
                "server_port": port,
            }
            for key in ("username", "password"):
                value = str(proxy.get(key) or "")
                if value:
                    detour[key] = value
            detours.append(detour)
        openvpn_index += 1
    outbounds.extend(detours)


def _ensure_all_openvpn_server_bootstrap_contract(payload: dict[str, Any]) -> None:
    outbounds = payload.get("outbounds")
    if not isinstance(outbounds, list):
        return
    for outbound in outbounds:
        if not isinstance(outbound, dict):
            continue
        if str(outbound.get("type") or "").strip().lower() == "openvpn":
            _ensure_openvpn_server_bootstrap_contract(payload, outbound)


def _ensure_all_server_bootstrap_contracts(payload: dict[str, Any]) -> None:
    _ensure_all_endpoint_server_bootstrap_contract(payload)
    _ensure_all_openvpn_server_bootstrap_contract(payload)


def _endpoint_ip_cidr(value: str) -> str:
    try:
        address = ip_address(str(value or "").strip())
    except ValueError:
        return ""
    return f"{address}/{'128' if address.version == 6 else '32'}"


def _pin_proxy_outbound_to_endpoint_ip(proxy_outbound: dict[str, Any], original_server: str, endpoint_ip: str) -> None:
    if not endpoint_ip:
        return
    proxy_outbound["server"] = endpoint_ip
    proxy_outbound.pop("domain_resolver", None)
    tls = proxy_outbound.get("tls")
    if isinstance(tls, dict) and not str(tls.get("server_name") or "").strip():
        tls["server_name"] = original_server


def _resolve_endpoint_ip_cidrs(host: str) -> list[str]:
    return [_endpoint_ip_cidr(address) for address in _resolve_endpoint_addresses(host)]


def _resolve_endpoint_addresses(host: str) -> list[str]:
    if not _is_domain_name(host):
        return []
    normalized_host = str(host).strip().lower()
    cache_key = (normalized_host, id(socket.getaddrinfo))
    with _endpoint_dns_cache_lock:
        cached = _endpoint_dns_cache.get(cache_key)
        if cached and time.monotonic() - cached[0] < _ENDPOINT_DNS_CACHE_TTL_SECONDS:
            return list(cached[1])
    result: list[Any] = []
    completed = threading.Event()

    def resolve() -> None:
        try:
            result.extend(socket.getaddrinfo(normalized_host, None, 0, socket.SOCK_STREAM))
        except OSError:
            pass
        finally:
            addresses = _resolved_addresses(result)
            if addresses:
                with _endpoint_dns_cache_lock:
                    _endpoint_dns_cache[cache_key] = (time.monotonic(), tuple(addresses))
            completed.set()

    threading.Thread(target=resolve, name="tun-endpoint-resolver", daemon=True).start()
    if not completed.wait(1.2):
        return []

    return _resolved_addresses(result)


def _resolved_addresses(result: list[Any]) -> list[str]:
    addresses: list[str] = []
    for info in result:
        try:
            sockaddr = info[4]
            if not sockaddr:
                continue
            address = ip_address(str(sockaddr[0]))
        except (IndexError, TypeError, ValueError):
            continue
        addresses.append(str(address))
    return sorted(dict.fromkeys(addresses), key=lambda value: (ip_address(value).version, value))


def prime_endpoint_resolution(host: str) -> None:
    """Warm endpoint DNS without delaying application or connection startup."""
    if not _is_domain_name(host):
        return
    threading.Thread(
        target=_resolve_endpoint_addresses,
        args=(host,),
        name="tun-endpoint-prewarm",
        daemon=True,
    ).start()


def _ensure_tun_route_exclude_addresses(payload: dict[str, Any], addresses: list[str]) -> None:
    normalized = _normalize_route_exclude_addresses(addresses)
    if not normalized:
        return
    inbounds = payload.get("inbounds")
    if not isinstance(inbounds, list):
        return
    for inbound in inbounds:
        if not isinstance(inbound, dict):
            continue
        if str(inbound.get("type") or "").strip().lower() != "tun":
            continue
        existing = inbound.get("route_exclude_address")
        values = existing if isinstance(existing, list) else []
        inbound["route_exclude_address"] = _normalize_route_exclude_addresses(
            [str(item) for item in values] + normalized
        )


def _ensure_direct_domain_route(payload: dict[str, Any], server: str) -> None:
    server = str(server or "").strip()
    if not server:
        return

    route = _ensure_dict(payload, "route")
    rules = _ensure_list(route, "rules")
    direct_rule = {"domain": [server], "action": "route", "outbound": "direct"}

    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            continue
        domain_value = rule.get("domain")
        if isinstance(domain_value, list) and server in [str(item) for item in domain_value]:
            rules[index] = direct_rule
            return

    insert_index = 0
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            continue
        if rule.get("action") == "sniff" or rule.get("protocol") == "dns":
            insert_index = index + 1
            continue
        break
    rules.insert(insert_index, direct_rule)


def _ensure_direct_ip_route(payload: dict[str, Any], cidr: str) -> None:
    cidr = str(cidr or "").strip()
    if not cidr:
        return

    route = _ensure_dict(payload, "route")
    rules = _ensure_list(route, "rules")
    direct_rule = {"ip_cidr": [cidr], "action": "route", "outbound": "direct"}

    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            continue
        ip_value = rule.get("ip_cidr")
        if isinstance(ip_value, list) and cidr in [str(item) for item in ip_value]:
            rules[index] = direct_rule
            return

    insert_index = 0
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            continue
        if rule.get("action") == "sniff" or rule.get("protocol") == "dns":
            insert_index = index + 1
            continue
        break
    rules.insert(insert_index, direct_rule)


def _ensure_hybrid_protect_route(payload: dict[str, Any]) -> None:
    route = _ensure_dict(payload, "route")
    rules = _ensure_list(route, "rules")
    protect_rule = {
        "inbound": [_APP_SINGBOX_HYBRID_PROTECT_INBOUND_TAG],
        "action": "route",
        "outbound": "direct",
    }
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            continue
        inbound_value = rule.get("inbound")
        if isinstance(inbound_value, list) and _APP_SINGBOX_HYBRID_PROTECT_INBOUND_TAG in [str(item) for item in inbound_value]:
            rules[index] = protect_rule
            return
    rules.insert(0, protect_rule)


def _ensure_singbox_discord_proxy_contract(payload: dict[str, Any], *, enabled: bool) -> None:
    inbounds = _ensure_list(payload, "inbounds")
    route = _ensure_dict(payload, "route")
    rules = _ensure_list(route, "rules")

    inbounds[:] = [
        inbound
        for inbound in inbounds
        if not (
            isinstance(inbound, dict)
            and str(inbound.get("tag") or "") == _APP_DISCORD_PROXY_INBOUND_TAG
        )
    ]
    rules[:] = [rule for rule in rules if not _is_singbox_discord_proxy_rule(rule)]

    if not enabled:
        return

    for inbound in inbounds:
        if not isinstance(inbound, dict):
            continue
        try:
            port = int(inbound.get("listen_port") or inbound.get("port") or 0)
        except (TypeError, ValueError):
            port = 0
        if port == int(DEFAULT_DISCORD_SOCKS_PORT):
            tag = str(inbound.get("tag") or "").strip() or "<no tag>"
            raise ValueError(
                f"sing-box inbound `{tag}` already uses Discord proxy port {DEFAULT_DISCORD_SOCKS_PORT}."
            )

    inbounds.append(
        {
            "type": "socks",
            "tag": _APP_DISCORD_PROXY_INBOUND_TAG,
            "listen": PROXY_HOST,
            "listen_port": int(DEFAULT_DISCORD_SOCKS_PORT),
        }
    )
    rules.insert(
        _singbox_discord_rule_insert_index(rules),
        {
            "inbound": [_APP_DISCORD_PROXY_INBOUND_TAG],
            "action": "route",
            "outbound": "proxy",
        },
    )


def _ensure_singbox_tun_local_proxy_contract(
    payload: dict[str, Any],
    *,
    socks_port: int = DEFAULT_SOCKS_PORT,
    http_port: int = DEFAULT_HTTP_PORT,
    username: str = "",
    password: str = "",
) -> None:
    """Keep v2rayN-style local proxy ports alive while TUN is running.

    Some browsers, Necko profiles, extensions and helper apps keep using
    127.0.0.1:10808/10809 even after the Windows system proxy is disabled for
    TUN. v2rayN keeps local proxy inbounds available in TUN mode, so do the same
    here instead of letting those requests time out outside sing-box.
    """

    def _safe_port(value: Any, default: int) -> int:
        try:
            port = int(value)
        except (TypeError, ValueError):
            return default
        if port <= 0 or port > 65535 or port == int(DEFAULT_DISCORD_SOCKS_PORT):  # keep droute port free
            return default
        return port

    socks_value = _safe_port(socks_port, int(DEFAULT_SOCKS_PORT))
    http_value = _safe_port(http_port, int(DEFAULT_HTTP_PORT))
    if http_value == socks_value:
        http_value = int(DEFAULT_HTTP_PORT) if socks_value != int(DEFAULT_HTTP_PORT) else int(DEFAULT_HTTP_PORT) + 1
    inbounds = _ensure_list(payload, "inbounds")
    route = _ensure_dict(payload, "route")
    rules = _ensure_list(route, "rules")

    managed_tags = {_APP_TUN_MIXED_INBOUND_TAG, _APP_TUN_HTTP_INBOUND_TAG}
    inbounds[:] = [
        inbound
        for inbound in inbounds
        if not (isinstance(inbound, dict) and str(inbound.get("tag") or "").strip() in managed_tags)
    ]
    rules[:] = [rule for rule in rules if not _is_singbox_tun_local_proxy_rule(rule)]

    auth_users = (
        [{"username": str(username).strip(), "password": str(password)}]
        if str(username).strip() and str(password)
        else []
    )
    mixed_inbound = {
                "type": "mixed",
                "tag": _APP_TUN_MIXED_INBOUND_TAG,
                "listen": PROXY_HOST,
                "listen_port": socks_value,
            }
    http_inbound = {
                "type": "http",
                "tag": _APP_TUN_HTTP_INBOUND_TAG,
                "listen": PROXY_HOST,
                "listen_port": http_value,
            }
    if auth_users:
        mixed_inbound["users"] = list(auth_users)
        http_inbound["users"] = list(auth_users)
    inbounds.extend([mixed_inbound, http_inbound])
    rules.insert(
        _singbox_local_proxy_rule_insert_index(rules),
        {
            "inbound": [_APP_TUN_MIXED_INBOUND_TAG, _APP_TUN_HTTP_INBOUND_TAG],
            "action": "route",
            "outbound": "proxy",
        },
    )


def _is_singbox_tun_local_proxy_rule(rule: Any) -> bool:
    if not isinstance(rule, dict):
        return False
    inbound = rule.get("inbound")
    tags: set[str]
    if isinstance(inbound, str):
        tags = {inbound}
    elif isinstance(inbound, list):
        tags = {str(item) for item in inbound}
    else:
        return False
    return bool(tags & {_APP_TUN_MIXED_INBOUND_TAG, _APP_TUN_HTTP_INBOUND_TAG}) and str(rule.get("outbound") or "") == "proxy"


def _singbox_local_proxy_rule_insert_index(rules: list[Any]) -> int:
    index = 0
    while index < len(rules):
        rule = rules[index]
        if not isinstance(rule, dict):
            break
        inbound = rule.get("inbound")
        if inbound:
            index += 1
            continue
        if rule.get("action") in {"sniff", "route-options"}:
            index += 1
            continue
        break
    return index


def _is_singbox_discord_proxy_rule(rule: Any) -> bool:
    if not isinstance(rule, dict):
        return False
    inbound = rule.get("inbound")
    if isinstance(inbound, str):
        return inbound == _APP_DISCORD_PROXY_INBOUND_TAG
    if isinstance(inbound, list):
        return _APP_DISCORD_PROXY_INBOUND_TAG in [str(item) for item in inbound]
    return False


def _dns_strategy(value: str) -> str:
    strategy = str(value or "").strip().lower().replace("-", "_")
    return strategy if strategy in {"prefer_ipv4", "prefer_ipv6", "ipv4_only", "ipv6_only"} else "prefer_ipv4"


def _is_default_direct_dns(routing: RoutingSettings | None) -> bool:
    if routing is None:
        return True
    return (
        str(routing.dns_bootstrap_server or "").strip().lower() == _DEFAULT_DIRECT_DNS_SERVER
        and str(routing.dns_bootstrap_type or "").strip().lower() == _DEFAULT_DIRECT_DNS_TYPE
    )


def _is_default_proxy_dns(routing: RoutingSettings | None) -> bool:
    if routing is None:
        return True
    return (
        str(routing.dns_proxy_server or "").strip().lower() == _DEFAULT_PROXY_DNS_SERVER
        and str(routing.dns_proxy_type or "").strip().lower() == _DEFAULT_PROXY_DNS_TYPE
    )


def _build_dns_server(tag: str, server: str, server_type: str, strategy: str) -> dict[str, Any]:
    dns_type = str(server_type or "").strip().lower()
    address = str(server or "").strip() or ("8.8.8.8" if tag == "proxy-dns" else "1.1.1.1")
    if _is_dhcp_auto_dns(address):
        return {
            "tag": tag,
            "type": "dhcp",
        }
    if dns_type not in {"udp", "tcp", "tls", "https"}:
        dns_type = "https" if tag == "proxy-dns" else "udp"
    payload: dict[str, Any] = {
        "tag": tag,
        "type": dns_type,
        "server": address,
    }
    if dns_type == "https":
        payload.setdefault("server_port", 443)
        payload.setdefault("path", "/dns-query")
    elif dns_type == "tls":
        payload.setdefault("server_port", 853)
    elif dns_type in {"udp", "tcp"}:
        payload.setdefault("server_port", 53)
    return payload


def _set_dns_server_dial_contract(server: dict[str, Any], *, detour: str, resolver: str = "") -> None:
    server["detour"] = detour
    address = str(server.get("server") or "")
    if _is_domain_name(address):
        server["domain_resolver"] = resolver or "system-dns"
    else:
        server.pop("domain_resolver", None)


def _apply_imported_proxy_dns(
    payload: dict[str, Any],
    node: Node,
    routing: RoutingSettings | None,
) -> None:
    """Use an internal profile DNS without replacing the configured resolver.

    Clash WireGuard/AWG profiles often carry public UDP resolvers such as
    1.1.1.1.  Some providers block UDP/53 inside the tunnel, so replacing the
    user's working DoH resolver with that hint makes the endpoint appear dead
    even after a successful handshake.  Keep the configured proxy resolver;
    only a private profile DNS may override the default resolver, and never a
    resolver explicitly customized by the user.
    """
    node_outbound = node.outbound if isinstance(node.outbound, dict) else {}
    raw_values = node_outbound.get("_dns")
    addresses = (
        [str(item).strip() for item in raw_values if str(item).strip()]
        if isinstance(raw_values, (list, tuple))
        else []
    )
    addresses = list(dict.fromkeys(addresses))
    dns = payload.get("dns")
    if not isinstance(dns, dict):
        return
    servers = dns.get("servers")
    if not isinstance(servers, list):
        return

    configured_proxy_dns = [
        server
        for server in servers
        if isinstance(server, dict)
        and (
            str(server.get("tag") or "") == "proxy-dns"
            or str(server.get("tag") or "").startswith("proxy-dns-")
        )
    ]
    private_dns = ""
    for address in addresses:
        try:
            if ip_address(address).is_private:
                private_dns = address
                break
        except ValueError:
            continue

    if configured_proxy_dns and (
        not private_dns
        or (routing is not None and not _is_default_proxy_dns(routing))
    ):
        return
    selected_dns = private_dns or (addresses[0] if addresses else "")
    if not selected_dns:
        return

    servers[:] = [
        server
        for server in servers
        if not (
            isinstance(server, dict)
            and (
                str(server.get("tag") or "") == "proxy-dns"
                or str(server.get("tag") or "").startswith("proxy-dns-")
            )
        )
    ]
    strategy = _dns_strategy(routing.dns_proxy_strategy if routing is not None else "")
    server = _build_dns_server("proxy-dns", selected_dns, "udp", strategy)
    _set_dns_server_dial_contract(server, detour="proxy", resolver="bootstrap-dns")
    servers.append(server)


def _clamp_tun_mtu_for_proxy(
    payload: dict[str, Any],
    proxy: dict[str, Any],
    *,
    enabled: bool,
) -> None:
    """Do not advertise jumbo TUN packets to MTU-limited VPN endpoints."""
    if not enabled:
        return
    proxy_type = str(proxy.get("type") or "").strip().lower()
    if proxy_type not in {"wireguard", "warp", "masque", "openvpn"}:
        return
    try:
        endpoint_mtu = int(proxy.get("mtu") or (1500 if proxy_type == "openvpn" else 1280))
    except (TypeError, ValueError):
        endpoint_mtu = 1280
    endpoint_mtu = max(576, min(endpoint_mtu, 9000))
    for inbound in payload.get("inbounds") or []:
        if not isinstance(inbound, dict) or str(inbound.get("type") or "").lower() != "tun":
            continue
        try:
            current_mtu = int(inbound.get("mtu") or endpoint_mtu)
        except (TypeError, ValueError):
            current_mtu = endpoint_mtu
        inbound["mtu"] = min(current_mtu, endpoint_mtu)


def _normalize_route_exclude_addresses(values: list[str] | tuple[str, ...]) -> list[str]:
    normalized: list[str] = []
    for raw in values:
        value = str(raw or "").strip()
        if not value:
            continue
        try:
            # sing-box accepts CIDR entries here; plain IPs are normalized to /32 or /128.
            if "/" in value:
                normalized.append(str(ip_network(value, strict=False)))
            else:
                address = ip_address(value)
                normalized.append(f"{address}/{'128' if address.version == 6 else '32'}")
        except ValueError:
            continue
    return sorted(dict.fromkeys(normalized))


def _singbox_discord_rule_insert_index(rules: list[Any]) -> int:
    index = 0
    while index < len(rules):
        rule = rules[index]
        if not isinstance(rule, dict):
            break
        if rule.get("inbound"):
            index += 1
            continue
        if rule.get("action") in {"sniff", "hijack-dns", "route-options"}:
            index += 1
            continue
        break
    return index


def _ensure_singbox_metrics_contract(payload: dict[str, Any]) -> str:
    log = _ensure_dict(payload, "log")
    if str(log.get("level") or "").strip().lower() in {"", "warn", "warning", "error", "fatal", "panic"}:
        log["level"] = "info"
    log.setdefault("timestamp", True)
    experimental = _ensure_dict(payload, "experimental")
    cache_file = _ensure_dict(experimental, "cache_file")
    cache_path = DATA_DIR / "runtime" / "sing-box-cache.db"
    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass
    cache_file["enabled"] = True
    cache_file["path"] = str(cache_path)
    cache_file["store_fakeip"] = True
    cache_file["store_warp_config"] = True
    clash_api_secret = secrets.token_urlsafe(32)
    experimental["clash_api"] = {
        "external_controller": f"127.0.0.1:{SINGBOX_CLASH_API_PORT}",
        "secret": clash_api_secret,
    }
    return clash_api_secret


_SINGBOX_TUN_IPV6_ADDRESS = "fdfe:dcba:9876::1/126"
_SINGBOX_TUN_IPV4_CANDIDATES = (
    "172.18.0.1/30",
    "172.19.0.1/30",
    "198.18.0.1/30",
    "198.19.0.1/30",
    "100.64.0.1/30",
    "10.201.7.1/30",
    "192.0.2.1/30",
)


def _local_ipv4_addresses() -> set[str]:
    found: set[str] = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            addr = info[4][0]
            if addr:
                found.add(addr)
    except OSError:
        pass
    return found


def _ipv4_gateway_in_use(gateway_ip: str) -> bool:
    # A gateway address already assigned to a local adapter can be bound;
    # a free one raises EADDRNOTAVAIL. This detects Docker/WSL/Hyper-V clashes.
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((gateway_ip, 0))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def _pick_singbox_tun_ipv4() -> str:
    known = _local_ipv4_addresses()
    for candidate in _SINGBOX_TUN_IPV4_CANDIDATES:
        gateway = candidate.split("/", 1)[0]
        try:
            network = ip_network(candidate, strict=False)
        except ValueError:
            continue
        if _ipv4_gateway_in_use(gateway):
            continue
        collides = False
        for addr in known:
            try:
                if ip_address(addr) in network:
                    collides = True
                    break
            except ValueError:
                continue
        if not collides:
            return candidate
    return _SINGBOX_TUN_IPV4_CANDIDATES[0]


def _singbox_tun_addresses() -> list[str]:
    return [_pick_singbox_tun_ipv4(), _SINGBOX_TUN_IPV6_ADDRESS]


def _ensure_singbox_tun_runtime_contract(
    payload: dict[str, Any],
    *,
    routing: RoutingSettings | None = None,
    enable_final_fragment: bool = True,
    system_dns_servers: tuple[str, ...] = (),
    tun_strict_route: bool = False,
    tun_stack: str = "mixed",
    tun_mtu: int = 9000,
    tun_endpoint_independent_nat: bool = False,
    tun_block_quic: bool = True,
    local_socks_port: int = DEFAULT_SOCKS_PORT,
    local_http_port: int = DEFAULT_HTTP_PORT,
    proxy_auth_username: str = "",
    proxy_auth_password: str = "",
) -> None:
    """Patch app-owned runtime fields for raw sing-box configs.

    Keep the Windows adapter identity stable so route and DNS registration can
    be reused across reconnects. MTU, stack and strict_route follow user
    settings (v2rayN parity) with safe defaults.
    """
    try:
        mtu_value = int(tun_mtu)
    except (TypeError, ValueError):
        mtu_value = 9000
    mtu_value = max(1280, min(mtu_value, 65535))
    stack_value = str(tun_stack or "").strip().lower()
    if stack_value not in {"system", "gvisor", "mixed"}:
        stack_value = "mixed"
    inbounds = payload.get("inbounds")
    has_tun = False
    renamed_tun_tags: set[str] = set()
    if isinstance(inbounds, list):
        for inbound in inbounds:
            if not isinstance(inbound, dict):
                continue
            if str(inbound.get("type") or "").strip().lower() != "tun":
                continue
            has_tun = True
            previous_tag = str(inbound.get("tag") or "").strip()
            if previous_tag and previous_tag != _APP_TUN_INBOUND_TAG:
                renamed_tun_tags.add(previous_tag)
            inbound["tag"] = _APP_TUN_INBOUND_TAG
            # Preserve an explicit name from the selected template/imported
            # config. Only omitted names receive Lumen's stable default.
            interface_name = str(inbound.get("interface_name") or "").strip()
            inbound["interface_name"] = interface_name or SINGBOX_TUN_INTERFACE_NAME
            inbound["address"] = _singbox_tun_addresses()
            inbound["mtu"] = mtu_value
            inbound["auto_route"] = True
            inbound.pop("route_address", None)
            inbound["strict_route"] = bool(tun_strict_route)  # True breaks Discord voice ICE fallback and WinDivert tools
            inbound["stack"] = stack_value
            if tun_endpoint_independent_nat and stack_value != "system":
                inbound["endpoint_independent_nat"] = True  # full-cone NAT, needs gvisor/mixed UDP stack
            else:
                inbound.pop("endpoint_independent_nat", None)
            excludes = _normalize_route_exclude_addresses(
                routing.tun_route_exclude_address if routing is not None else []
            )
            if excludes:
                inbound["route_exclude_address"] = excludes
            else:
                inbound.pop("route_exclude_address", None)
            inbound.pop("sniff", None)
    if not has_tun:
        return
    if renamed_tun_tags:
        _rename_singbox_rule_inbound_tags(payload, renamed_tun_tags, _APP_TUN_INBOUND_TAG)

    route = _ensure_dict(payload, "route")
    route["auto_detect_interface"] = True
    use_builtin_dns = _singbox_uses_builtin_dns(routing)
    direct_strategy = _dns_strategy(routing.dns_bootstrap_strategy if routing is not None else "")
    route["default_domain_resolver"] = {"server": "bootstrap-dns", "strategy": direct_strategy}
    _ensure_singbox_dns_runtime_contract(
        payload,
        routing=routing,
        system_dns_servers=system_dns_servers,
    )
    rules = _ensure_list(route, "rules")
    _ensure_singbox_tun_base_rules(
        rules,
        enable_final_fragment=enable_final_fragment,
        builtin_dns=use_builtin_dns,
        dns_hijack_all=(routing.dns_hijack_enabled if routing is not None else True),
        block_quic=tun_block_quic,
    )
    _ensure_singbox_tun_local_proxy_contract(
        payload,
        socks_port=local_socks_port,
        http_port=local_http_port,
        username=proxy_auth_username,
        password=proxy_auth_password,
    )


def _ensure_singbox_runtime_contract(
    payload: dict[str, Any],
    *,
    tun_mode: bool,
    routing: RoutingSettings | None,
    enable_final_fragment: bool,
    system_dns_servers: tuple[str, ...],
    tun_strict_route: bool,
    tun_stack: str,
    tun_mtu: int,
    tun_endpoint_independent_nat: bool,
    tun_block_quic: bool,
    local_socks_port: int,
    local_http_port: int,
    proxy_auth_username: str,
    proxy_auth_password: str,
) -> None:
    if tun_mode:
        _ensure_singbox_tun_runtime_contract(
            payload,
            routing=routing,
            enable_final_fragment=enable_final_fragment,
            system_dns_servers=system_dns_servers,
            tun_strict_route=tun_strict_route,
            tun_stack=tun_stack,
            tun_mtu=tun_mtu,
            tun_endpoint_independent_nat=tun_endpoint_independent_nat,
            tun_block_quic=tun_block_quic,
            local_socks_port=local_socks_port,
            local_http_port=local_http_port,
            proxy_auth_username=proxy_auth_username,
            proxy_auth_password=proxy_auth_password,
        )
        return

    route = _ensure_dict(payload, "route")
    route["auto_detect_interface"] = True
    direct_strategy = _dns_strategy(routing.dns_bootstrap_strategy if routing is not None else "")
    route["default_domain_resolver"] = {"server": "bootstrap-dns", "strategy": direct_strategy}
    _ensure_singbox_dns_runtime_contract(
        payload,
        routing=routing,
        system_dns_servers=system_dns_servers,
    )
    _ensure_singbox_tun_local_proxy_contract(
        payload,
        socks_port=local_socks_port,
        http_port=local_http_port,
        username=proxy_auth_username,
        password=proxy_auth_password,
    )


def _ensure_singbox_dns_runtime_contract(
    payload: dict[str, Any],
    *,
    routing: RoutingSettings | None = None,
    system_dns_servers: tuple[str, ...] = (),
) -> None:
    dns = payload.get("dns")
    if not isinstance(dns, dict):
        dns = {}
        payload["dns"] = dns
    # sing-box 1.14 keys DNS cache entries by transport automatically;
    # independent_cache is deprecated and will be removed in 1.16.
    direct_server = routing.dns_bootstrap_server if routing is not None else _DEFAULT_DIRECT_DNS_SERVER
    direct_type = routing.dns_bootstrap_type if routing is not None else _DEFAULT_DIRECT_DNS_TYPE
    direct_strategy = _dns_strategy(routing.dns_bootstrap_strategy if routing is not None else "")
    proxy_server = routing.dns_proxy_server if routing is not None else _DEFAULT_PROXY_DNS_SERVER
    proxy_type = routing.dns_proxy_type if routing is not None else _DEFAULT_PROXY_DNS_TYPE
    proxy_strategy = _dns_strategy(routing.dns_proxy_strategy if routing is not None else "")
    direct_servers = list(routing.dns_bootstrap_servers) if routing is not None else [direct_server]
    proxy_servers = list(routing.dns_proxy_servers) if routing is not None else [proxy_server]
    direct_servers = [str(item).strip() for item in direct_servers if str(item).strip()] or [str(direct_server)]
    proxy_servers = [str(item).strip() for item in proxy_servers if str(item).strip()] or [str(proxy_server)]
    use_builtin_dns = _singbox_uses_builtin_dns(routing)
    # FakeIP follows the user setting (off by default, matching v2rayN). When
    # enabled it keeps ECH sites reachable; when disabled the browser resolves
    # real IPs, avoiding Chrome Local Network Access prompts under TUN.
    fake_enabled = bool(routing.dns_fake_enabled) if routing is not None else False
    proxy_is_default = _is_default_proxy_dns(routing)
    runtime_direct_server = str(direct_server or "").strip()
    runtime_direct_type = str(direct_type or "").strip()
    runtime_proxy_server = str(proxy_server or "").strip()
    runtime_proxy_type = str(proxy_type or "").strip()
    if proxy_is_default:
        runtime_proxy_server = _DEFAULT_PROXY_DNS_SERVER
        runtime_proxy_type = _DEFAULT_PROXY_DNS_TYPE

    dns["strategy"] = direct_strategy
    dns["reverse_mapping"] = True
    servers = dns.setdefault("servers", [])
    if not isinstance(servers, list):
        servers = []
        dns["servers"] = servers
    servers[:] = [
        server
        for server in servers
        if not (
            isinstance(server, dict)
            and (
                str(server.get("tag") or "").startswith("direct-dns-")
                or str(server.get("tag") or "").startswith("proxy-dns-")
                or str(server.get("tag") or "") == "hosts-dns"
            )
        )
    ]
    system_server = next((str(item).strip() for item in system_dns_servers if str(item).strip()), "")
    if not system_server:
        system_server = runtime_direct_server if not _is_domain_name(str(runtime_direct_server)) else _DEFAULT_DIRECT_DNS_SERVER
    system_type = "udp" if system_dns_servers or _is_domain_name(str(runtime_direct_server)) else runtime_direct_type
    if use_builtin_dns:
        system_dns = _build_dns_server("system-dns", system_server, system_type, direct_strategy)
        _set_dns_server_dial_contract(system_dns, detour="direct")
        _replace_or_append_tagged(servers, "system-dns", system_dns)
        bootstrap_dns = _build_dns_server("bootstrap-dns", runtime_direct_server, runtime_direct_type, direct_strategy)
        _set_dns_server_dial_contract(bootstrap_dns, detour="direct")
        direct_dns = _build_dns_server("direct-dns", runtime_direct_server, runtime_direct_type, direct_strategy)
        _set_dns_server_dial_contract(direct_dns, detour="direct")
        _replace_or_append_tagged(servers, "bootstrap-dns", bootstrap_dns)
        _replace_or_append_tagged(servers, "direct-dns", direct_dns)
        proxy_dns = _build_dns_server("proxy-dns", runtime_proxy_server, runtime_proxy_type, proxy_strategy)
        _set_dns_server_dial_contract(proxy_dns, detour="proxy", resolver="bootstrap-dns")
    else:
        # In system mode keep direct/bootstrap DNS pinned to the physical
        # adapter snapshot captured before TUN starts. dhcp://auto can pick the
        # just-created virtual adapter on Windows and recurse into the tunnel.
        bootstrap_dns = _build_dns_server("bootstrap-dns", system_server, system_type, direct_strategy)
        direct_dns = _build_dns_server("direct-dns", system_server, system_type, direct_strategy)
        proxy_dns = _build_dns_server("proxy-dns", runtime_proxy_server, runtime_proxy_type, proxy_strategy)
        _set_dns_server_dial_contract(bootstrap_dns, detour="direct")
        _set_dns_server_dial_contract(direct_dns, detour="direct")
        _set_dns_server_dial_contract(proxy_dns, detour="proxy", resolver="bootstrap-dns")
        _replace_or_append_tagged(servers, "bootstrap-dns", bootstrap_dns)
        _replace_or_append_tagged(servers, "direct-dns", direct_dns)
    _replace_or_append_tagged(servers, "proxy-dns", proxy_dns)
    if use_builtin_dns:
        for index, address in enumerate(direct_servers[1:], start=2):
            extra_direct = _build_dns_server(f"direct-dns-{index}", address, runtime_direct_type, direct_strategy)
            _set_dns_server_dial_contract(extra_direct, detour="direct")
            _replace_or_append_tagged(servers, f"direct-dns-{index}", extra_direct)
    for index, address in enumerate(proxy_servers[1:], start=2):
        extra_proxy = _build_dns_server(f"proxy-dns-{index}", address, runtime_proxy_type, proxy_strategy)
        _set_dns_server_dial_contract(extra_proxy, detour="proxy", resolver="bootstrap-dns")
        _replace_or_append_tagged(servers, f"proxy-dns-{index}", extra_proxy)

    hosts = routing.dns_hosts if routing is not None else {}
    if hosts:
        _replace_or_append_tagged(
            servers,
            "hosts-dns",
            {
                "tag": "hosts-dns",
                "type": "hosts",
                "predefined": {domain: list(addresses) for domain, addresses in hosts.items()},
            },
        )
    if fake_enabled:
        _replace_or_append_tagged(
            servers,
            "fake-dns",
            {
                "tag": "fake-dns",
                "type": "fakeip",
                "inet4_range": "198.18.0.0/15",
                "inet6_range": "fc00::/18",
            },
        )
    else:
        servers[:] = [
            server
            for server in servers
            if not (isinstance(server, dict) and str(server.get("tag") or "") == "fake-dns")
        ]

    for server in servers:
        if not isinstance(server, dict):
            continue
        tag = str(server.get("tag") or "")
        server_type = str(server.get("type") or "").strip().lower()
        address = str(server.get("server") or "").strip().lower()
        if tag.startswith("proxy-dns") and server_type in {"tls", "https"} and address in _KNOWN_DOH_IP_HOSTS:
            # Remote/proxied DNS must use a hostname with a valid TLS identity.
            # DoH/DoT to a bare IP can silently break domains because the TLS
            # handshake has no provider hostname/SNI to present.
            server.clear()
            server.update(
                {
                    "tag": tag,
                    "type": server_type,
                    "server": _KNOWN_DOH_IP_HOSTS[address],
                    "server_port": 443 if server_type == "https" else 853,
                    "domain_resolver": "bootstrap-dns",
                    "detour": "proxy",
                }
            )
            if server_type == "https":
                server["path"] = "/dns-query"
            continue

    _ensure_singbox_https_dns_reject_rule(dns)
    _ensure_singbox_hosts_dns_rule(dns, enabled=bool(hosts))


# DNS query types 64 (SVCB) and 65 (HTTPS) carry ECH config and HTTP/3 hints.
# Answering them lets browsers encrypt the SNI (breaking sniff) and prefer QUIC.
# Rejecting them forces a clean fallback to A/AAAA (FakeIP) and TCP, which is how
# v2rayN-style TUN profiles keep ECH-enabled sites (OpenAI/Anthropic/Google)
# reachable.
_HTTPS_DNS_REJECT_RULE = {"query_type": ["HTTPS", "SVCB"], "action": "reject"}


def _is_https_dns_reject_rule(rule: Any) -> bool:
    if not isinstance(rule, dict):
        return False
    if str(rule.get("action") or "") != "reject":
        return False
    query_type = rule.get("query_type")
    if not isinstance(query_type, list):
        return False
    return {str(item).strip().upper() for item in query_type} == {"HTTPS", "SVCB"}


def _is_browser_doh_dns_reject_rule(rule: Any) -> bool:
    if not isinstance(rule, dict):
        return False
    if str(rule.get("action") or "") != "reject":
        return False
    suffixes = rule.get("domain_suffix")
    if not isinstance(suffixes, list):
        return False
    return [str(item) for item in suffixes] == list(_BROWSER_DOH_DOMAIN_SUFFIXES)


def _ensure_singbox_https_dns_reject_rule(dns: dict[str, Any]) -> None:
    rules = dns.get("rules")
    if not isinstance(rules, list):
        rules = []
        dns["rules"] = rules
    rules[:] = [
        rule
        for rule in rules
        if not _is_https_dns_reject_rule(rule)
        and not _is_browser_doh_dns_reject_rule(rule)
    ]
    rules.insert(
        0,
        {
            "domain_suffix": list(_BROWSER_DOH_DOMAIN_SUFFIXES),
            "action": "reject",
        },
    )
    rules.insert(0, deepcopy(_HTTPS_DNS_REJECT_RULE))


def _is_singbox_hosts_dns_rule(rule: Any) -> bool:
    return (
        isinstance(rule, dict)
        and rule.get("ip_accept_any") is True
        and str(rule.get("server") or "") == "hosts-dns"
    )


def _ensure_singbox_hosts_dns_rule(dns: dict[str, Any], *, enabled: bool) -> None:
    rules = dns.get("rules")
    if not isinstance(rules, list):
        rules = []
        dns["rules"] = rules
    rules[:] = [rule for rule in rules if not _is_singbox_hosts_dns_rule(rule)]
    if enabled:
        rules.insert(0, {"ip_accept_any": True, "server": "hosts-dns"})

def _singbox_uses_builtin_dns(routing: RoutingSettings | None) -> bool:
    return str(routing.dns_mode if routing is not None else "builtin").strip().lower() == "builtin"


def _ensure_singbox_tun_base_rules(
    rules: list[Any],
    *,
    enable_final_fragment: bool = True,
    builtin_dns: bool = True,
    dns_hijack_all: bool = True,
    block_quic: bool = True,
) -> None:
    noisy_local_dns_rejects = [
        {
            "network": "udp",
            "port": [135, 137, 138, 139, 5353, 5355],
            "action": "reject",
        },
        {
            "ip_cidr": ["224.0.0.0/3", "ff00::/8"],
            "action": "reject",
        },
    ]
    # DNS hijack must be early and broad: some Windows/Chromium paths are
    # detected by sing-box as protocol=dns before a plain port rule matches.
    dns_hijack_rule = {
        "type": "logical",
        "mode": "or",
        "rules": [{"port": 53}, {"protocol": "dns"}],
        "action": "hijack-dns",
    }
    sniff_rule = {
        "action": "sniff",
        "timeout": "1s",
    }
    # Drop QUIC/HTTP3 coming from the local TUN so browsers fall back to TCP
    # HTTP/2. Scoped to tun-in only, so proxy UDP endpoints (WARP/AWG/Hysteria2)
    # that dial out from the outbound side are untouched.
    quic_reject_rule = {
        "inbound": [_APP_TUN_INBOUND_TAG],
        "protocol": "quic",
        "action": "reject",
    }
    browser_doh_reject_rule = {
        "inbound": [_APP_TUN_INBOUND_TAG],
        "domain_suffix": _BROWSER_DOH_DOMAIN_SUFFIXES,
        "action": "reject",
    }
    base_rules = [sniff_rule]
    if enable_final_fragment:
        # `route` is terminal, `route-options` is not: the fragment rule has to
        # precede the GUI route rules or only fall-through traffic gets it.
        base_rules.append(
            {
                "protocol": ["tls"],
                "action": "route-options",
                "tls_fragment": True,
                "tls_fragment_fallback_delay": "500ms",
            }
        )
    if block_quic:
        base_rules.append(quic_reject_rule)
    base_rules.extend([browser_doh_reject_rule, dns_hijack_rule, *noisy_local_dns_rejects])
    rules[:] = [rule for rule in rules if not _is_singbox_tun_base_rule(rule)]
    rules[0:0] = base_rules


def _remove_singbox_tls_fragment_rule(payload: dict[str, Any]) -> None:
    route = payload.get("route")
    if not isinstance(route, dict):
        return
    rules = route.get("rules")
    if not isinstance(rules, list):
        return
    rules[:] = [
        rule
        for rule in rules
        if not _is_app_singbox_tls_fragment_rule(rule)
    ]


def _is_singbox_tun_base_rule(rule: Any) -> bool:
    if not isinstance(rule, dict):
        return False
    action = str(rule.get("action") or "")
    if action == "sniff":
        return True
    if action == "hijack-dns":
        return True
    if (
        action == "reject"
        and rule.get("inbound") == [_APP_TUN_INBOUND_TAG]
        and rule.get("protocol") == "quic"
    ):
        return True
    if _is_app_singbox_tls_fragment_rule(rule):
        return True
    if (
        action == "reject"
        and rule.get("inbound") == [_APP_TUN_INBOUND_TAG]
        and rule.get("domain_suffix") == _BROWSER_DOH_DOMAIN_SUFFIXES
    ):
        return True
    if rule.get("protocol") in ("dns", ["dns"]):
        return True
    if rule.get("port") in (53, [53]) and action in {"hijack-dns", ""}:
        return True
    if action == "reject" and rule.get("network") == "udp" and rule.get("port") == 443:
        return True
    if action == "reject" and rule.get("network") == "udp" and rule.get("port") in (
        [135, 137, 138, 139, 5353],
        [135, 137, 138, 139, 5353, 5355],
    ):
        return True
    return action == "reject" and rule.get("ip_cidr") == ["224.0.0.0/3", "ff00::/8"]


def _is_app_singbox_tls_fragment_rule(rule: Any) -> bool:
    if not isinstance(rule, dict):
        return False
    return (
        str(rule.get("action") or "") == "route-options"
        and rule.get("protocol") == ["tls"]
        and (rule.get("tls_record_fragment") is True or rule.get("tls_fragment") is True)
        and set(rule)
        <= {"protocol", "action", "tls_record_fragment", "tls_fragment", "tls_fragment_fallback_delay"}
    )


def _validate_runtime_dns_contract(payload: dict[str, Any]) -> None:
    dns = payload.get("dns")
    server_tags: set[str] = set()
    if isinstance(dns, dict):
        for server in dns.get("servers") or []:
            if not isinstance(server, dict):
                continue
            tag = str(server.get("tag") or "").strip()
            if tag:
                server_tags.add(tag)

    missing_refs: list[str] = []

    def require_dns_tag(tag: str, owner: str) -> None:
        if not tag or tag in server_tags:
            return
        missing_refs.append(f"{owner} -> {tag}")

    route = payload.get("route")
    if isinstance(route, dict):
        require_dns_tag(_extract_dns_server_tag(route.get("default_domain_resolver")), "route.default_domain_resolver")

    if isinstance(dns, dict):
        require_dns_tag(_extract_dns_server_tag(dns.get("final")), "dns.final")
        for index, rule in enumerate(dns.get("rules") or []):
            if not isinstance(rule, dict):
                continue
            require_dns_tag(_extract_dns_server_tag(rule.get("server")), f"dns.rules[{index}].server")

    for index, outbound in enumerate(payload.get("outbounds") or []):
        if not isinstance(outbound, dict):
            continue
        require_dns_tag(
            _extract_dns_server_tag(outbound.get("domain_resolver")),
            f"outbounds[{index}].domain_resolver",
        )

    if not missing_refs:
        return

    details = "; ".join(dict.fromkeys(missing_refs))
    raise ValueError(
        "В sing-box конфиге отсутствует DNS-сервер с нужным tag. "
        f"Проверьте раздел dns.servers: {details}. "
        "Обычно для стандартного шаблона должны существовать теги `bootstrap-dns` и `proxy-dns`."
    )


def _find_proxy_outbound_index(outbounds: Any) -> int | None:
    if not isinstance(outbounds, list):
        return None
    for index, outbound in enumerate(outbounds):
        if isinstance(outbound, dict) and str(outbound.get("tag") or "") == "proxy":
            return index
    return None


def _config_has_proxy_outbound(payload: Any) -> bool:
    return _find_proxy_outbound_index(payload.get("outbounds") if isinstance(payload, dict) else None) is not None


def _replace_or_append_tagged(items: list[Any], tag: str, payload: dict[str, Any]) -> None:
    for index, item in enumerate(items):
        if isinstance(item, dict) and str(item.get("tag") or "") == tag:
            items[index] = payload
            return
    items.append(payload)


def _is_singbox_endpoint(payload: Any) -> bool:
    if not isinstance(payload, dict):
        return False
    return str(payload.get("type") or "").strip().lower() in {"warp", "wireguard"}


def _ensure_dict(parent: dict[str, Any], key: str) -> dict[str, Any]:
    value = parent.get(key)
    if isinstance(value, dict):
        return value
    created: dict[str, Any] = {}
    parent[key] = created
    return created


def _ensure_list(parent: dict[str, Any], key: str) -> list[Any]:
    value = parent.get(key)
    if isinstance(value, list):
        return value
    created: list[Any] = []
    parent[key] = created
    return created


def _extract_dns_server_tag(value: Any) -> str:
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, dict):
        return str(value.get("server") or "").strip()
    return ""


def _find_free_port(
    *,
    preferred: int,
    port_range: range | None = None,
    excluded: set[int] | None = None,
) -> int:
    excluded = excluded or set()
    candidates: list[int] = []
    if preferred > 0:
        candidates.append(preferred)
    if port_range is None:
        port_range = range(preferred, preferred + 100)
    for port in port_range:
        if port not in candidates:
            candidates.append(port)
    for port in candidates:
        if port <= 0 or port in excluded:
            continue
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind((PROXY_HOST, port))
                return port
            except OSError:
                continue
    raise RuntimeError(f"No free TCP port available near {preferred}")


def _generate_ss_password(length: int = 24) -> str:
    _, password = generate_local_proxy_credentials(prefix="protect", password_length=length)
    return password


def _format_json_error_message(text: str, exc: json.JSONDecodeError) -> str:
    lines = text.splitlines()
    line = lines[exc.lineno - 1] if 0 < exc.lineno <= len(lines) else ""
    caret = ""
    if line:
        caret = "\n" + (" " * max(0, exc.colno - 1)) + "^"
    return f"Ошибка синтаксиса JSON: {exc.msg} (строка {exc.lineno}, столбец {exc.colno})\n{line}{caret}".rstrip()
