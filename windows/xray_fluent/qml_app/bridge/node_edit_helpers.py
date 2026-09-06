"""GUI-free port of ``ui/node_edit_dialog.py`` outbound load/build logic"""
from __future__ import annotations

import base64
from copy import deepcopy
import json
import re
from typing import Any
from urllib.parse import quote

# Option lists — identical to ui/node_edit_dialog.py module constants.
FINGERPRINTS = ("", "chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized")
NETWORKS = ("tcp", "ws", "grpc", "http", "h2", "xhttp", "httpupgrade", "kcp")
SECURITY = ("none", "tls", "reality")
FLOWS = ("", "xtls-rprx-vision", "xtls-rprx-vision-udp443")
RAW_HEADERS = ("none", "http")

XRAY_ADVANCED_PROTOCOLS = {"vless", "vmess"}
ENDPOINT_EDITABLE_PROTOCOLS = {
    "vless",
    "vmess",
    "trojan",
    "shadowsocks",
    "ss",
    "socks",
    "http",
    "hysteria",
    "hysteria2",
    "tuic",
    "mieru",
    "wireguard",
    "awg",
    "warp",
    "masque",
    "openvpn",
    "naive",
    "anytls",
    "snell",
}
NATIVE_PROTOCOLS = {
    "wireguard",
    "awg",
    "warp",
    "hysteria",
    "hysteria2",
    "tuic",
    "mieru",
    "masque",
    "openvpn",
    "naive",
    "singbox_config",
    "anytls",
    "snell",
}

MANUAL_NODE_PROTOCOLS = (
    "vless",
    "vmess",
    "trojan",
    "shadowsocks",
    "socks",
    "http",
    "hysteria",
    "hysteria2",
    "tuic",
    "mieru",
    "wireguard",
    "awg",
    "warp",
    "masque",
    "openvpn",
    "naive",
)


def _first_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, list) and value and isinstance(value[0], dict):
        return value[0]
    return {}


def _ensure_first_dict(parent: dict[str, Any], key: str) -> dict[str, Any]:
    value = parent.get(key)
    if not isinstance(value, list):
        value = []
        parent[key] = value
    if not value or not isinstance(value[0], dict):
        value.insert(0, {})
    return value[0]


def _set_or_remove(parent: dict[str, Any], key: str, value: str) -> None:
    if value:
        parent[key] = value
    else:
        parent.pop(key, None)


def _safe_port(value: Any, fallback: int) -> int:
    try:
        port = int(str(value).strip())
    except ValueError:
        return int(fallback or 0)
    return max(0, min(65535, port))


def _set_param(params: dict[str, str], key: str, value: Any) -> None:
    value = str(value or "")
    if value:
        params[key] = value


def _protocol_from_node(node) -> str:
    outbound = node.outbound if isinstance(getattr(node, "outbound", None), dict) else {}
    protocol = str(outbound.get("protocol") or node.scheme or "").strip().lower()
    return {
        "ss": "shadowsocks",
        "socks5": "socks",
        "hy": "hysteria",
        "hy2": "hysteria2",
        "mierus": "mieru",
        "any-tls": "anytls",
        "wg": "wireguard",
    }.get(protocol, protocol)


def _field_capabilities(protocol: str) -> dict[str, bool | str]:
    protocol = (protocol or "").strip().lower()
    xray_advanced = protocol in XRAY_ADVANCED_PROTOCOLS
    tls_editable = protocol in {"vless", "vmess", "trojan"}
    endpoint = protocol in ENDPOINT_EDITABLE_PROTOCOLS
    fixed_endpoint = protocol in {"singbox_config", "xray_config"}
    return {
        "protocol": protocol,
        "xrayAdvanced": xray_advanced,
        "nativeSingbox": protocol in NATIVE_PROTOCOLS,
        "endpoint": endpoint and not fixed_endpoint,
        "identity": xray_advanced,
        "flow": protocol == "vless",
        "encryption": xray_advanced,
        "transport": xray_advanced,
        "rawHeader": xray_advanced,
        "tls": tls_editable,
        "reality": xray_advanced,
        "finalmask": xray_advanced,
        "basicOnly": not xray_advanced,
        "readOnlyConfig": protocol in {"singbox_config", "xray_config"},
    }


def _share_query(params: dict[str, str]) -> str:
    return "&".join(f"{quote(key)}={quote(value, safe='')}" for key, value in params.items() if value != "")


def _share_host(server: Any) -> str:
    """Format a host for URI authority syntax (including IPv6 literals)."""
    value = str(server or "").strip()
    if ":" in value and not value.startswith("["):
        return f"[{value}]"
    return value


def _share_network(stream: dict[str, Any]) -> str:
    network = str(stream.get("network") or "tcp")
    return "tcp" if network.lower() == "raw" else network


def _stream_share_params(stream: dict[str, Any]) -> dict[str, str]:
    params: dict[str, str] = {"type": _share_network(stream)}
    security = str(stream.get("security") or "none").lower()
    _set_param(params, "security", security if security != "none" else "")
    tls = stream.get("tlsSettings") if isinstance(stream.get("tlsSettings"), dict) else {}
    reality = stream.get("realitySettings") if isinstance(stream.get("realitySettings"), dict) else {}
    payload = reality if security == "reality" else tls
    _set_param(params, "sni", str(payload.get("serverName") or ""))
    _set_param(params, "fp", str(payload.get("fingerprint") or ""))
    _set_param(params, "pcs", str(tls.get("pinnedPeerCertSha256") or ""))
    alpn = tls.get("alpn")
    _set_param(params, "alpn", ",".join(str(item) for item in alpn) if isinstance(alpn, list) else str(alpn or ""))
    if "allowInsecure" in tls:
        _set_param(params, "allowInsecure", "1" if tls.get("allowInsecure") is True else "0")
    network = str(stream.get("network") or "tcp").lower()
    if network == "ws":
        ws = stream.get("wsSettings") if isinstance(stream.get("wsSettings"), dict) else {}
        _set_param(params, "path", str(ws.get("path") or ""))
        headers = ws.get("headers") if isinstance(ws.get("headers"), dict) else {}
        _set_param(params, "host", str(headers.get("Host") or headers.get("host") or ""))
    elif network in {"http", "h2"}:
        http = stream.get("httpSettings") if isinstance(stream.get("httpSettings"), dict) else {}
        _set_param(params, "path", str(http.get("path") or ""))
        host = http.get("host")
        _set_param(params, "host", ",".join(str(item) for item in host) if isinstance(host, list) else str(host or ""))
    elif network == "grpc":
        grpc = stream.get("grpcSettings") if isinstance(stream.get("grpcSettings"), dict) else {}
        _set_param(params, "serviceName", str(grpc.get("serviceName") or ""))
    elif network == "xhttp":
        xhttp = stream.get("xhttpSettings") if isinstance(stream.get("xhttpSettings"), dict) else {}
        _set_param(params, "path", str(xhttp.get("path") or ""))
        _set_param(params, "host", str(xhttp.get("host") or ""))
        _set_param(params, "mode", str(xhttp.get("mode") or ""))
        extra = xhttp.get("extra")
        if extra not in (None, ""):
            _set_param(
                params,
                "extra",
                extra if isinstance(extra, str) else json.dumps(extra, ensure_ascii=False, separators=(",", ":")),
            )
    elif network == "httpupgrade":
        httpupgrade = stream.get("httpupgradeSettings") if isinstance(stream.get("httpupgradeSettings"), dict) else {}
        _set_param(params, "path", str(httpupgrade.get("path") or ""))
        _set_param(params, "host", str(httpupgrade.get("host") or ""))
    elif network in {"kcp", "mkcp"}:
        kcp = stream.get("kcpSettings") if isinstance(stream.get("kcpSettings"), dict) else {}
        header = kcp.get("header") if isinstance(kcp.get("header"), dict) else {}
        _set_param(params, "headerType", str(header.get("type") or "none"))
        for key in ("mtu", "tti", "uplinkCapacity", "downlinkCapacity", "readBufferSize", "writeBufferSize", "seed"):
            _set_param(params, key, kcp.get(key))
        if kcp.get("congestion") is True:
            _set_param(params, "congestion", "1")
    if security == "reality":
        _set_param(params, "pbk", str(reality.get("publicKey") or ""))
        _set_param(params, "sid", str(reality.get("shortId") or ""))
        _set_param(params, "spx", str(reality.get("spiderX") or ""))
        _set_param(params, "pqv", str(reality.get("mldsa65Verify") or ""))
    finalmask = stream.get("finalmask")
    if finalmask not in (None, ""):
        _set_param(params, "fm", finalmask if isinstance(finalmask, str) else json.dumps(finalmask, ensure_ascii=False, separators=(",", ":")))
    return params


def _native_share_tls_params(params: dict[str, str], native: dict[str, Any]) -> None:
    tls = native.get("tls") if isinstance(native.get("tls"), dict) else {}
    _set_param(params, "sni", str(tls.get("server_name") or ""))
    alpn = tls.get("alpn")
    _set_param(params, "alpn", ",".join(str(item) for item in alpn) if isinstance(alpn, list) else str(alpn or ""))
    if "insecure" in tls:
        _set_param(params, "insecure", "1" if tls.get("insecure") is True else "0")


def _native_share_transport_params(native: dict[str, Any]) -> dict[str, str]:
    """Convert sing-box transport/TLS fields to the common share URI query."""
    transport = native.get("transport") if isinstance(native.get("transport"), dict) else {}
    transport_type = str(transport.get("type") or "tcp").strip().lower()
    params: dict[str, str] = {"type": "tcp" if transport_type in {"", "raw"} else transport_type}
    path = transport.get("path")
    _set_param(params, "path", path)
    host = transport.get("host")
    if isinstance(host, list):
        _set_param(params, "host", ",".join(str(item) for item in host))
    else:
        _set_param(params, "host", host)
    headers = transport.get("headers") if isinstance(transport.get("headers"), dict) else {}
    _set_param(params, "host", headers.get("Host") or headers.get("host") or params.get("host", ""))
    _set_param(params, "serviceName", transport.get("service_name") or transport.get("serviceName"))
    _set_param(params, "mode", transport.get("mode"))

    tls = native.get("tls") if isinstance(native.get("tls"), dict) else {}
    reality = tls.get("reality") if isinstance(tls.get("reality"), dict) else {}
    if reality.get("enabled") or reality:
        params["security"] = "reality"
        _set_param(params, "pbk", reality.get("public_key") or reality.get("publicKey"))
        _set_param(params, "sid", reality.get("short_id") or reality.get("shortId"))
        _set_param(params, "spx", reality.get("spider_x") or reality.get("spiderX"))
    elif tls.get("enabled") is not False and tls:
        params["security"] = "tls"
    _set_param(params, "sni", tls.get("server_name") or tls.get("serverName"))
    alpn = tls.get("alpn")
    _set_param(params, "alpn", ",".join(str(item) for item in alpn) if isinstance(alpn, list) else alpn)
    if "insecure" in tls:
        _set_param(params, "insecure", "1" if tls.get("insecure") is True else "0")
    return params


def _build_vless_link(name: str, server: str, port: int, outbound: dict[str, Any]) -> str:
    native = _native_payload(outbound)
    if native:
        params = _native_share_transport_params(native)
        _set_param(params, "encryption", str(native.get("encryption") or "none"))
        _set_param(params, "flow", str(native.get("flow") or ""))
        user_id = str(native.get("uuid") or native.get("id") or "")
        fragment = quote(name, safe="")
        return f"vless://{quote(user_id, safe='')}@{_share_host(native.get('server') or server)}:{int(native.get('server_port') or port)}?{_share_query(params)}#{fragment}"
    settings = outbound.get("settings") if isinstance(outbound.get("settings"), dict) else {}
    vnext = _first_dict(settings.get("vnext"))
    user = _first_dict(vnext.get("users"))
    user_id = str(user.get("id") or "")
    stream = outbound.get("streamSettings") if isinstance(outbound.get("streamSettings"), dict) else {}
    params: dict[str, str] = {
        "encryption": str(user.get("encryption") or "none"),
        "type": _share_network(stream),
    }
    _set_param(params, "flow", str(user.get("flow") or ""))
    params.update(_stream_share_params(stream))
    fragment = quote(name, safe="")
    return f"vless://{quote(user_id, safe='')}@{_share_host(server)}:{port}?{_share_query(params)}#{fragment}"


def _build_vmess_link(name: str, server: str, port: int, outbound: dict[str, Any]) -> str:
    native = _native_payload(outbound)
    if native:
        params = _native_share_transport_params(native)
        payload: dict[str, str] = {
            "v": "2",
            "ps": name,
            "add": str(native.get("server") or server),
            "port": str(native.get("server_port") or port),
            "id": str(native.get("uuid") or native.get("id") or ""),
            "aid": str(native.get("alter_id") or native.get("alterId") or 0),
            "scy": str(native.get("security") or "auto"),
            "net": params.get("type", "tcp"),
            "type": params.get("headerType", "none"),
            "host": params.get("host", ""),
            "path": params.get("path", "") or params.get("serviceName", ""),
            "tls": "tls" if params.get("security") in {"tls", "reality"} else "",
            "sni": params.get("sni", ""),
            "alpn": params.get("alpn", ""),
        }
        encoded = base64.b64encode(json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")).decode("ascii")
        return f"vmess://{encoded}"
    settings = outbound.get("settings") if isinstance(outbound.get("settings"), dict) else {}
    vnext = _first_dict(settings.get("vnext"))
    user = _first_dict(vnext.get("users"))
    stream = outbound.get("streamSettings") if isinstance(outbound.get("streamSettings"), dict) else {}
    params = _stream_share_params(stream)
    security = str(stream.get("security") or "none").lower()
    payload: dict[str, str] = {
        "v": "2",
        "ps": name,
        "add": server,
        "port": str(port),
        "id": str(user.get("id") or ""),
        "aid": str(user.get("alterId") or 0),
        "scy": str(user.get("security") or "auto"),
        "net": params.get("type", "tcp"),
        "type": params.get("headerType", "none"),
        "host": params.get("host", ""),
        "path": params.get("path", "") or params.get("serviceName", ""),
        "tls": "tls" if security in {"tls", "reality"} else "",
        "sni": params.get("sni", ""),
        "alpn": params.get("alpn", ""),
        "fp": params.get("fp", ""),
    }
    service_name = params.get("serviceName", "")
    if service_name:
        payload["serviceName"] = service_name
    encoded = base64.b64encode(
        json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")
    return f"vmess://{encoded}"


def _build_trojan_link(name: str, server: str, port: int, outbound: dict[str, Any]) -> str:
    native = _native_payload(outbound)
    if native:
        params = _native_share_transport_params(native)
        # Trojan URI parsers default to TLS; preserve an explicitly disabled
        # native TLS block as ``security=none``.
        params.setdefault("security", "none")
        password = quote(str(native.get("password") or ""), safe="")
        fragment = quote(name, safe="")
        return f"trojan://{password}@{_share_host(native.get('server') or server)}:{int(native.get('server_port') or port)}?{_share_query(params)}#{fragment}"
    settings = outbound.get("settings") if isinstance(outbound.get("settings"), dict) else {}
    server_item = _first_dict(settings.get("servers"))
    stream = outbound.get("streamSettings") if isinstance(outbound.get("streamSettings"), dict) else {}
    params = _stream_share_params(stream)
    # trojan defaults to TLS on import, so an explicit "none" must survive the round trip.
    params.setdefault("security", "none")
    fragment = quote(name, safe="")
    password = quote(str(server_item.get("password") or ""), safe="")
    return f"trojan://{password}@{_share_host(server)}:{port}?{_share_query(params)}#{fragment}"


def _build_shadowsocks_link(name: str, server: str, port: int, outbound: dict[str, Any]) -> str:
    native = _native_payload(outbound)
    if native:
        credentials = f"{native.get('method') or ''}:{native.get('password') or ''}"
        encoded = base64.urlsafe_b64encode(credentials.encode("utf-8")).decode("ascii").rstrip("=")
        params: dict[str, str] = {}
        _set_param(params, "plugin", str(native.get("plugin") or ""))
        fragment = quote(name, safe="")
        query = _share_query(params)
        return f"ss://{encoded}@{_share_host(native.get('server') or server)}:{int(native.get('server_port') or port)}{'?' + query if query else ''}#{fragment}"
    settings = outbound.get("settings") if isinstance(outbound.get("settings"), dict) else {}
    server_item = _first_dict(settings.get("servers"))
    credentials = f"{server_item.get('method') or ''}:{server_item.get('password') or ''}"
    encoded = base64.urlsafe_b64encode(credentials.encode("utf-8")).decode("ascii").rstrip("=")
    params: dict[str, str] = {}
    _set_param(params, "plugin", str(server_item.get("plugin") or ""))
    query = _share_query(params)
    fragment = quote(name, safe="")
    return f"ss://{encoded}@{_share_host(server)}:{port}{'?' + query if query else ''}#{fragment}"


def _build_socks_link(name: str, server: str, port: int, outbound: dict[str, Any]) -> str:
    native = _native_payload(outbound)
    if native:
        username = str(native.get("username") or "")
        password = str(native.get("password") or "")
        credentials = f"{quote(username, safe='')}:{quote(password, safe='')}@" if username else ""
        fragment = quote(name, safe="")
        return f"socks://{credentials}{_share_host(native.get('server') or server)}:{int(native.get('server_port') or port)}#{fragment}"
    settings = outbound.get("settings") if isinstance(outbound.get("settings"), dict) else {}
    server_item = _first_dict(settings.get("servers"))
    user = _first_dict(server_item.get("users"))
    username = str(user.get("user") or "")
    credentials = ""
    if username:
        credentials = f"{quote(username, safe='')}:{quote(str(user.get('pass') or ''), safe='')}@"
    fragment = quote(name, safe="")
    return f"socks://{credentials}{_share_host(server)}:{port}#{fragment}"


def _build_http_link(name: str, server: str, port: int, outbound: dict[str, Any]) -> str:
    native = _native_payload(outbound)
    if native:
        username = str(native.get("username") or "")
        password = str(native.get("password") or "")
        credentials = f"{quote(username, safe='')}:{quote(password, safe='')}@" if username else ""
        fragment = quote(name, safe="")
        return f"http://{credentials}{_share_host(native.get('server') or server)}:{int(native.get('server_port') or port)}#{fragment}"
    settings = outbound.get("settings") if isinstance(outbound.get("settings"), dict) else {}
    server_item = _first_dict(settings.get("servers"))
    user = _first_dict(server_item.get("users"))
    username = str(user.get("user") or "")
    password = str(user.get("pass") or "")
    credentials = f"{quote(username, safe='')}:{quote(password, safe='')}@" if username else ""
    fragment = quote(name, safe="")
    return f"http://{credentials}{_share_host(server)}:{port}#{fragment}"


def _build_hysteria_link(name: str, server: str, port: int, outbound: dict[str, Any]) -> str:
    native = _native_payload(outbound)
    params: dict[str, str] = {}
    _native_share_tls_params(params, native)
    _set_param(params, "protocol", native.get("protocol"))
    _set_param(params, "upmbps", native.get("up_mbps"))
    _set_param(params, "downmbps", native.get("down_mbps"))
    ports = native.get("server_ports")
    _set_param(params, "server_ports", ",".join(str(item) for item in ports) if isinstance(ports, list) else ports)
    _set_param(params, "hop_interval", native.get("hop_interval"))
    for key in ("recv_window_conn", "recv_window", "disable_mtu_discovery"):
        value = native.get(key)
        if key == "disable_mtu_discovery":
            _set_param(params, key, "1" if value is True else "")
        else:
            _set_param(params, key, value)
    obfs = native.get("obfs")
    if isinstance(obfs, dict):
        _set_param(params, "obfs", obfs.get("type"))
        _set_param(params, "obfs-password", obfs.get("password"))
    elif obfs:
        _set_param(params, "obfs", obfs)
    fragment = quote(name, safe="")
    auth = quote(str(native.get("auth_str") or native.get("password") or ""), safe="")
    return f"hysteria://{auth}@{_share_host(native.get('server') or server)}:{int(native.get('server_port') or port)}?{_share_query(params)}#{fragment}"


def _build_hysteria2_link(name: str, server: str, port: int, outbound: dict[str, Any]) -> str:
    native = _native_payload(outbound)
    params: dict[str, str] = {}
    _native_share_tls_params(params, native)
    obfs = native.get("obfs")
    if isinstance(obfs, dict):
        _set_param(params, "obfs", str(obfs.get("type") or ""))
        _set_param(params, "obfs-password", str(obfs.get("password") or ""))
    ports = native.get("server_ports")
    _set_param(params, "server_ports", ",".join(str(item) for item in ports) if isinstance(ports, list) else ports)
    _set_param(params, "hop_interval", native.get("hop_interval"))
    _set_param(params, "upmbps", native.get("up_mbps"))
    _set_param(params, "downmbps", native.get("down_mbps"))
    for key in ("recv_window_conn", "recv_window", "disable_mtu_discovery"):
        value = native.get(key)
        if key == "disable_mtu_discovery":
            _set_param(params, key, "1" if value is True else "")
        else:
            _set_param(params, key, value)
    fragment = quote(name, safe="")
    password = quote(str(native.get("password") or ""), safe="")
    return f"hysteria2://{password}@{_share_host(native.get('server') or server)}:{int(native.get('server_port') or port)}?{_share_query(params)}#{fragment}"


def _build_tuic_link(name: str, server: str, port: int, outbound: dict[str, Any]) -> str:
    native = _native_payload(outbound)
    params: dict[str, str] = {}
    _set_param(params, "congestion_control", str(native.get("congestion_control") or ""))
    _set_param(params, "udp_relay_mode", str(native.get("udp_relay_mode") or ""))
    if native.get("zero_rtt_handshake") is True:
        _set_param(params, "zero_rtt_handshake", "1")
    _native_share_tls_params(params, native)
    fragment = quote(name, safe="")
    credentials = quote(str(native.get("uuid") or ""), safe="")
    password = str(native.get("password") or "")
    if password:
        credentials = f"{credentials}:{quote(password, safe='')}"
    return f"tuic://{credentials}@{_share_host(native.get('server') or server)}:{int(native.get('server_port') or port)}?{_share_query(params)}#{fragment}"


def _build_mieru_link(name: str, server: str, port: int, outbound: dict[str, Any]) -> str:
    native = _native_payload(outbound)
    username = quote(str(native.get("username") or ""), safe="")
    password = quote(str(native.get("password") or ""), safe="")
    params: dict[str, str] = {"transport": str(native.get("transport") or "TCP").upper()}
    ports = native.get("server_ports")
    if isinstance(ports, list):
        _set_param(params, "server_ports", ",".join(str(item) for item in ports))
    else:
        _set_param(params, "server_ports", ports)
    _set_param(params, "multiplexing", native.get("multiplexing"))
    _set_param(params, "traffic_pattern", native.get("traffic_pattern"))
    fragment = quote(name, safe="")
    authority_port = int(native.get("server_port") or port or 0)
    authority = _share_host(native.get("server") or server)
    if authority_port:
        authority += f":{authority_port}"
    return f"mieru://{username}:{password}@{authority}?{_share_query(params)}#{fragment}"


def _build_naive_link(name: str, server: str, port: int, outbound: dict[str, Any]) -> str:
    native = _native_payload(outbound)
    scheme = "naive+quic" if native.get("quic") is True else "naive"
    username = quote(str(native.get("username") or ""), safe="")
    password = quote(str(native.get("password") or ""), safe="")
    credentials = f"{username}:{password}@" if username or password else ""
    params: dict[str, str] = {}
    tls = native.get("tls") if isinstance(native.get("tls"), dict) else {}
    _set_param(params, "sni", tls.get("server_name") or "")
    _set_param(params, "insecure_concurrency", native.get("insecure_concurrency"))
    _set_param(params, "quic_congestion_control", native.get("quic_congestion_control"))
    if native.get("udp_over_tcp") not in (None, False, ""):
        value = native["udp_over_tcp"]
        _set_param(params, "udp_over_tcp", value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, separators=(",", ":")))
    if isinstance(native.get("extra_headers"), dict):
        _set_param(params, "extra_headers", json.dumps(native["extra_headers"], ensure_ascii=False, separators=(",", ":")))
    fragment = quote(name, safe="")
    return f"{scheme}://{credentials}{_share_host(native.get('server') or server)}:{int(native.get('server_port') or port or 443)}?{_share_query(params)}#{fragment}"


def _build_anytls_link(name: str, server: str, port: int, outbound: dict[str, Any]) -> str:
    native = _native_payload(outbound)
    params: dict[str, str] = {}
    tls = native.get("tls") if isinstance(native.get("tls"), dict) else {}
    _set_param(params, "sni", tls.get("server_name") or "")
    if tls.get("insecure") is True:
        _set_param(params, "insecure", "1")
    alpn = tls.get("alpn")
    _set_param(params, "alpn", ",".join(str(item) for item in alpn) if isinstance(alpn, list) else alpn)
    pins = tls.get("certificate_public_key_sha256")
    _set_param(params, "pinsha256", ",".join(str(item) for item in pins) if isinstance(pins, list) else pins)
    for key in ("idle_session_check_interval", "idle_session_timeout", "min_idle_session"):
        _set_param(params, key, native.get(key))
    password = quote(str(native.get("password") or ""), safe="")
    fragment = quote(name, safe="")
    return f"anytls://{password}@{_share_host(native.get('server') or server)}:{int(native.get('server_port') or port or 443)}?{_share_query(params)}#{fragment}"


def _build_wireguard_link(name: str, server: str, port: int, outbound: dict[str, Any]) -> str:
    native = _native_payload(outbound)
    protocol = str(outbound.get("protocol") or "wireguard").lower()
    native_type = str(native.get("type") or protocol).lower()
    if native_type == "warp" or protocol == "warp":
        scheme = "awg" if protocol == "awg" or isinstance(native.get("amnezia"), dict) else "warp"
        profile = native.get("profile") if isinstance(native.get("profile"), dict) else {}
        params: dict[str, str] = {}
        for key in ("id", "private_key", "auth_token", "listen_port", "persistent_keepalive_interval", "udp_timeout"):
            _set_param(params, key, profile.get(key) if key in profile else native.get(key))
        amnezia = native.get("amnezia")
        if isinstance(amnezia, dict):
            for key, value in amnezia.items():
                _set_param(params, key, value)
        dns = outbound.get("_dns")
        _set_param(params, "dns", ",".join(str(item) for item in dns) if isinstance(dns, list) else dns)
        fragment = quote(name, safe="")
        return f"{scheme}://engage.cloudflareclient.com:2408?{_share_query(params)}#{fragment}"

    peers = native.get("peers") if isinstance(native.get("peers"), list) else []
    peer = peers[0] if peers and isinstance(peers[0], dict) else {}
    endpoint_server = str(peer.get("address") or peer.get("server") or native.get("server") or server)
    endpoint_port = int(peer.get("port") or peer.get("server_port") or native.get("server_port") or port or 51820)
    params: dict[str, str] = {}
    _set_param(params, "public_key", peer.get("public_key") or peer.get("publicKey"))
    addresses = native.get("address") or native.get("addresses")
    _set_param(params, "address", ",".join(str(item) for item in addresses) if isinstance(addresses, list) else addresses)
    allowed = peer.get("allowed_ips") or peer.get("allowedIPs") or native.get("allowed_ips")
    _set_param(params, "allowed_ips", ",".join(str(item) for item in allowed) if isinstance(allowed, list) else allowed)
    _set_param(params, "pre_shared_key", peer.get("pre_shared_key") or peer.get("preshared_key"))
    _set_param(params, "persistent_keepalive", peer.get("persistent_keepalive_interval") or peer.get("persistent_keepalive"))
    for key in ("mtu", "listen_port", "udp_timeout", "workers", "preallocated_buffers_per_pool", "disable_pauses"):
        _set_param(params, key, native.get(key))
    dns = outbound.get("_dns")
    _set_param(params, "dns", ",".join(str(item) for item in dns) if isinstance(dns, list) else dns)
    amnezia = native.get("amnezia")
    if isinstance(amnezia, dict):
        for key, value in amnezia.items():
            _set_param(params, key, value)
    private_key = quote(str(native.get("private_key") or ""), safe="")
    scheme = "awg" if protocol == "awg" or isinstance(amnezia, dict) else "wireguard"
    fragment = quote(name, safe="")
    return f"{scheme}://{private_key}@{_share_host(endpoint_server)}:{endpoint_port}?{_share_query(params)}#{fragment}"


def _build_masque_link(name: str, server: str, port: int, outbound: dict[str, Any]) -> str:
    native = _native_payload(outbound)
    profile = native.get("profile") if isinstance(native.get("profile"), dict) else {}
    profile_id = str(profile.get("id") or server or "")
    token = quote(str(profile.get("auth_token") or ""), safe="")
    credentials = f"{token}@" if token else ""
    params: dict[str, str] = {
        "name": str(native.get("name") or "masque0"),
        "system": "true" if native.get("system") is True else "false",
        "use_http2": "true" if native.get("use_http2") is True else "false",
        "use_ipv6": "true" if native.get("use_ipv6") is True else "false",
    }
    allowed = native.get("allowed_ips")
    _set_param(params, "allowed_ips", ",".join(str(item) for item in allowed) if isinstance(allowed, list) else allowed)
    _set_param(params, "sni", (native.get("tls") or {}).get("server_name") if isinstance(native.get("tls"), dict) else "")
    if isinstance(native.get("tls"), dict) and native["tls"].get("insecure") is True:
        _set_param(params, "insecure", "true")
    for key in ("udp_timeout", "udp_keepalive_period", "reconnect_delay", "congestion_controller"):
        _set_param(params, key, native.get(key))
    fragment = quote(name, safe="")
    return f"masque://{credentials}{quote(profile_id, safe='')}?{_share_query(params)}#{fragment}"


# Protocols with a portable share URI used by the node editor.  Keep this
# compatibility set stable: native-only editor saves historically retained
# canonical JSON in ``node.link``.
_SHARE_LINK_BUILDERS = {
    "vless": _build_vless_link,
    "vmess": _build_vmess_link,
    "trojan": _build_trojan_link,
    "shadowsocks": _build_shadowsocks_link,
    "socks": _build_socks_link,
    "hysteria2": _build_hysteria2_link,
    "tuic": _build_tuic_link,
}

# Export-only normalizers cover every protocol for which link_parser has a
# lossless URI representation.  Full Xray/sing-box/OpenVPN documents and
# custom protocols intentionally fall back to compact JSON.
_EXPORT_LINK_BUILDERS = {
    **_SHARE_LINK_BUILDERS,
    "http": _build_http_link,
    "hysteria": _build_hysteria_link,
    "mieru": _build_mieru_link,
    "naive": _build_naive_link,
    "anytls": _build_anytls_link,
    "wireguard": _build_wireguard_link,
    "awg": _build_wireguard_link,
    "warp": _build_wireguard_link,
    "masque": _build_masque_link,
}


def _build_node_link(protocol: str, name: str, server: str, port: int, outbound: dict[str, Any]) -> str:
    builder = _SHARE_LINK_BUILDERS.get(protocol)
    if builder is None:
        return json.dumps(outbound, ensure_ascii=False, separators=(",", ":"))
    return builder(name, server, port, outbound)


def _native_payload(outbound: dict[str, Any]) -> dict[str, Any]:
    native = outbound.get("singbox")
    return native if isinstance(native, dict) else {}


def _share_identity_present(protocol: str, outbound: dict[str, Any]) -> bool:
    """Return whether a portable URI can be produced without empty credentials."""
    native = _native_payload(outbound)
    if native:
        if protocol in {"vless", "vmess"}:
            return bool(native.get("uuid") or native.get("id"))
        if protocol == "trojan":
            return bool(native.get("password"))
        if protocol == "shadowsocks":
            return bool(native.get("method") and native.get("password"))
        if protocol in {"hysteria", "hysteria2"}:
            return bool(native.get("auth_str") or native.get("password"))
        if protocol == "tuic":
            return bool(native.get("uuid"))
        if protocol == "mieru":
            return bool(native.get("username") and native.get("password"))
        if protocol == "anytls":
            return bool(native.get("password"))
        if protocol in {"wireguard", "awg"}:
            peers = native.get("peers") if isinstance(native.get("peers"), list) else []
            peer = peers[0] if peers and isinstance(peers[0], dict) else {}
            return bool(native.get("private_key") and (peer.get("public_key") or peer.get("publicKey")))
        if protocol == "warp":
            profile = native.get("profile") if isinstance(native.get("profile"), dict) else {}
            return bool(profile.get("id") or profile.get("private_key") or profile.get("auth_token"))
        if protocol == "masque":
            profile = native.get("profile") if isinstance(native.get("profile"), dict) else {}
            # The URI form represents a registered profile.  Direct MASQUE
            # endpoints carry tunnel keys/addresses that the URI parser cannot
            # reconstruct, so retain those as JSON instead of dropping them.
            direct_fields = ("private_key", "public_key", "address", "server", "server_port")
            if any(native.get(key) not in (None, "", [], {}) for key in direct_fields):
                return False
            if profile.get("private_key"):
                return False
            return bool(profile.get("id"))
    if protocol in {"vless", "vmess"}:
        settings = outbound.get("settings") if isinstance(outbound.get("settings"), dict) else {}
        user = _first_dict(_first_dict(settings.get("vnext")).get("users"))
        return bool(user.get("id"))
    if protocol == "trojan":
        settings = outbound.get("settings") if isinstance(outbound.get("settings"), dict) else {}
        return bool(_first_dict(settings.get("servers")).get("password"))
    if protocol == "shadowsocks":
        settings = outbound.get("settings") if isinstance(outbound.get("settings"), dict) else {}
        server_item = _first_dict(settings.get("servers"))
        return bool(server_item.get("method") and server_item.get("password"))
    return True


def normalized_node_export_link(node) -> str:
    """Return a portable, canonical share link for a node when one exists.

    Imported JSON nodes retain their source document in ``node.link`` for
    round-trip safety.  Share actions should instead expose the protocol URI
    generated from the normalized outbound.  Full sing-box/Xray/OpenVPN
    documents have no lossless single-URI representation and therefore keep a
    compact JSON form (or their original non-URI payload).
    """
    if node is None:
        return ""
    raw = str(getattr(node, "link", "") or "").strip()
    outbound = getattr(node, "outbound", None)
    outbound = outbound if isinstance(outbound, dict) else {}
    protocol = _protocol_from_node(node)
    builder = _EXPORT_LINK_BUILDERS.get(protocol)
    name = str(getattr(node, "name", "") or "").strip()
    server = str(getattr(node, "server", "") or "").strip()
    try:
        port = int(getattr(node, "port", 0) or 0)
    except (TypeError, ValueError):
        port = 0
    native = _native_payload(outbound)
    effective_server = server or str(native.get("server") or "")
    if not effective_server and protocol in {"wireguard", "awg"}:
        peers = native.get("peers") if isinstance(native.get("peers"), list) else []
        if peers and isinstance(peers[0], dict):
            effective_server = str(peers[0].get("address") or peers[0].get("server") or "")
    endpoint_available = protocol in {"warp", "masque"} or bool(effective_server)
    if builder is not None and endpoint_available and _share_identity_present(protocol, outbound):
        try:
            candidate = str(builder(name, server, port, outbound) or "").strip()
        except Exception:
            candidate = ""
        if candidate and "://" in candidate and not candidate.startswith("{"):
            return candidate
    if raw.startswith("{"):
        try:
            return json.dumps(json.loads(raw), ensure_ascii=False, separators=(",", ":"))
        except (TypeError, ValueError):
            pass
    return raw


def _text_list(value: Any) -> str:
    if isinstance(value, (list, tuple)):
        return ", ".join(str(item) for item in value if str(item).strip())
    return str(value or "")


def _json_field(value: Any) -> str:
    if value in (None, ""):
        return ""
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _editor_field(
    key: str,
    label: str,
    value: Any,
    *,
    kind: str = "text",
    options: tuple[str, ...] | list[str] = (),
    secret: bool = False,
    placeholder: str = "",
    when_key: str = "",
    when_values: tuple[str, ...] | list[str] = (),
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "key": key,
        "label": label,
        "value": value if value is not None else "",
        "kind": kind,
    }
    if options:
        result["options"] = list(options)
    if secret:
        result["secret"] = True
    if placeholder:
        result["placeholder"] = placeholder
    if when_key:
        result["whenKey"] = when_key
        result["whenValues"] = list(when_values)
    return result


def _endpoint_fields(values: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        _editor_field("server", "Адрес", values.get("server", "")),
        _editor_field("port", "Порт", values.get("port", ""), kind="number"),
    ]


def _stream_editor_fields(values: dict[str, Any]) -> list[dict[str, Any]]:
    fields = [
        _editor_field("network", "Транспорт", values.get("network", "tcp"), kind="combo", options=NETWORKS),
        _editor_field(
            "transportPath",
            "Путь",
            values.get("transportPath", ""),
            when_key="network",
            when_values=("ws", "http", "h2", "xhttp", "httpupgrade"),
        ),
        _editor_field(
            "transportHost",
            "Host",
            values.get("transportHost", ""),
            when_key="network",
            when_values=("ws", "http", "h2", "xhttp", "httpupgrade"),
        ),
        _editor_field(
            "grpcServiceName",
            "gRPC service name",
            values.get("grpcServiceName", ""),
            when_key="network",
            when_values=("grpc",),
        ),
        _editor_field(
            "xhttpMode",
            "XHTTP mode",
            values.get("xhttpMode", "auto"),
            kind="combo",
            options=("auto", "packet-up", "stream-up", "stream-one"),
            when_key="network",
            when_values=("xhttp",),
        ),
        _editor_field(
            "xhttpExtra",
            "XHTTP extra (JSON)",
            values.get("xhttpExtra", ""),
            kind="area",
            when_key="network",
            when_values=("xhttp",),
        ),
        _editor_field(
            "kcpHeader",
            "mKCP header",
            values.get("kcpHeader", "none"),
            kind="combo",
            options=("none", "srtp", "utp", "wechat-video", "dtls", "wireguard"),
            when_key="network",
            when_values=("kcp",),
        ),
        _editor_field("kcpSeed", "mKCP seed", values.get("kcpSeed", ""), when_key="network", when_values=("kcp",)),
        _editor_field("kcpMtu", "mKCP MTU", values.get("kcpMtu", ""), kind="number", when_key="network", when_values=("kcp",)),
        _editor_field("kcpTti", "mKCP TTI", values.get("kcpTti", ""), kind="number", when_key="network", when_values=("kcp",)),
        _editor_field("kcpUplink", "mKCP upload", values.get("kcpUplink", ""), kind="number", when_key="network", when_values=("kcp",)),
        _editor_field("kcpDownlink", "mKCP download", values.get("kcpDownlink", ""), kind="number", when_key="network", when_values=("kcp",)),
        _editor_field("kcpCongestion", "mKCP congestion", values.get("kcpCongestion", False), kind="bool", when_key="network", when_values=("kcp",)),
    ]
    return fields


def _stream_security_fields(values: dict[str, Any]) -> list[dict[str, Any]]:
    secure = ("tls", "reality")
    return [
        _editor_field("security", "Защита", values.get("security", "none"), kind="combo", options=SECURITY),
        _editor_field("sni", "SNI", values.get("sni", ""), when_key="security", when_values=secure),
        _editor_field("fingerprint", "Fingerprint", values.get("fingerprint", ""), kind="combo", options=FINGERPRINTS, when_key="security", when_values=secure),
        _editor_field("allowInsecure", "Пропускать проверку сертификата", values.get("allowInsecure", False), kind="bool", when_key="security", when_values=("tls",)),
        _editor_field("alpn", "ALPN", values.get("alpn", ""), placeholder="h2, http/1.1", when_key="security", when_values=("tls",)),
        _editor_field("pinnedPeerCertSha256", "TLS SHA-256 pin", values.get("pinnedPeerCertSha256", ""), placeholder="64 hex-символа", when_key="security", when_values=("tls",)),
        _editor_field("publicKey", "REALITY public key", values.get("publicKey", ""), when_key="security", when_values=("reality",)),
        _editor_field("shortId", "REALITY ShortId", values.get("shortId", ""), when_key="security", when_values=("reality",)),
        _editor_field("spiderX", "REALITY SpiderX", values.get("spiderX", ""), when_key="security", when_values=("reality",)),
        _editor_field("pqv", "ML-DSA-65 verify", values.get("pqv", ""), when_key="security", when_values=("reality",)),
        _editor_field("finalmask", "Finalmask", values.get("finalmask", ""), kind="area"),
    ]


def _native_tls_fields(values: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        _editor_field("sni", "SNI", values.get("sni", "")),
        _editor_field("allowInsecure", "Пропускать проверку сертификата", values.get("allowInsecure", False), kind="bool"),
        _editor_field("alpn", "ALPN", values.get("alpn", ""), placeholder="h3, h2, http/1.1"),
    ]


_AMNEZIA_EDITOR_KEYS = (
    "jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4",
    "i1", "i2", "i3", "i4", "i5", "j1", "j2", "j3", "itime",
    "header_protection_key", "content_padding_addition", "rekey_after_time",
    "rekey_timeout", "reject_after_time", "keepalive_timeout", "max_handshake_attempts",
)

_AMNEZIA_NUMERIC_EDITOR_KEYS = {
    "jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "itime",
}
_AMNEZIA_RANGE_EDITOR_KEYS = {
    "content_padding_addition",
    "rekey_after_time",
    "rekey_timeout",
    "reject_after_time",
    "keepalive_timeout",
    "max_handshake_attempts",
}

# AWG can talk to a standard WireGuard peer when the packet padding remains
# disabled and H1-H4 retain WireGuard's original message identifiers.  Client-
# side junk packets are safe because a regular WireGuard server ignores them.
_WG_COMPATIBLE_AMNEZIA_DEFAULTS: dict[str, Any] = {
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


def _amnezia_editor_fields(
    values: dict[str, Any],
    *,
    conditional: bool = False,
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for key in _AMNEZIA_EDITOR_KEYS:
        kind = "number" if key in _AMNEZIA_NUMERIC_EDITOR_KEYS else "area" if key.startswith(("i", "j")) and key not in {"jmin", "jmax"} else "text"
        result.append(
            _editor_field(
                f"awg_{key}",
                f"AWG {key.upper()}",
                values.get(f"awg_{key}", ""),
                kind=kind,
                when_key="amneziaEnabled" if conditional else "",
                when_values=("true",) if conditional else (),
            )
        )
    return result


def _protocol_editor_fields(protocol: str, values: dict[str, Any], native: dict[str, Any]) -> list[dict[str, Any]]:
    if protocol in {"singbox_config", "xray_config"}:
        return []

    fields: list[dict[str, Any]] = []
    if protocol != "warp":
        fields.extend(_endpoint_fields(values))

    if protocol == "vless":
        fields.extend([
            _editor_field("uuid", "UUID / id", values.get("uuid", "")),
            _editor_field("encryption", "Шифрование", values.get("encryption", "none")),
            _editor_field("flow", "Flow", values.get("flow", ""), kind="combo", options=FLOWS),
        ])
        fields.extend(_stream_editor_fields(values))
        fields.extend(_stream_security_fields(values))
    elif protocol == "vmess":
        fields.extend([
            _editor_field("uuid", "UUID / id", values.get("uuid", "")),
            _editor_field("alterId", "Alter ID", values.get("alterId", 0), kind="number"),
            _editor_field("vmessSecurity", "Шифрование", values.get("vmessSecurity", "auto"), kind="combo", options=("auto", "none", "zero", "aes-128-gcm", "chacha20-poly1305")),
        ])
        fields.extend(_stream_editor_fields(values))
        fields.extend(_stream_security_fields(values))
    elif protocol == "trojan":
        fields.append(_editor_field("password", "Пароль", values.get("password", "")))
        fields.extend(_stream_editor_fields(values))
        fields.extend(_stream_security_fields(values))
    elif protocol == "shadowsocks":
        fields.extend([
            _editor_field("method", "Метод шифрования", values.get("method", "")),
            _editor_field("password", "Пароль", values.get("password", "")),
            _editor_field("plugin", "Плагин", values.get("plugin", "")),
        ])
    elif protocol in {"socks", "http"}:
        fields.extend([
            _editor_field("username", "Имя пользователя", values.get("username", "")),
            _editor_field("password", "Пароль", values.get("password", "")),
        ])
    elif protocol == "naive":
        fields.extend([
            _editor_field("username", "Имя пользователя", values.get("username", "")),
            _editor_field("password", "Пароль", values.get("password", "")),
            _editor_field("insecureConcurrency", "Insecure concurrency", values.get("insecureConcurrency", 0), kind="number"),
            _editor_field("extraHeaders", "Дополнительные заголовки (JSON)", values.get("extraHeaders", ""), kind="area", placeholder='{"Host":"example.com"}'),
            _editor_field("udpOverTcpEnabled", "UDP поверх TCP", values.get("udpOverTcpEnabled", False), kind="bool"),
            _editor_field("udpOverTcpOptions", "UDP over TCP (JSON)", values.get("udpOverTcpOptions", ""), kind="area", placeholder="{}"),
            _editor_field("naiveQuic", "Использовать QUIC", values.get("naiveQuic", False), kind="bool"),
            _editor_field("quicCongestionControl", "QUIC congestion control", values.get("quicCongestionControl", "")),
        ])
        # Naive uses Cronet and accepts only the restricted Naive TLS schema.
        # Keep SNI editable without exposing options that make the core reject
        # the generated config (ALPN, insecure and uTLS).
        fields.append(_editor_field("sni", "SNI / Server name", values.get("sni", "")))
    elif protocol == "hysteria":
        fields.extend([
            _editor_field("auth", "Auth / пароль", values.get("auth", "")),
            _editor_field("hysteriaProtocol", "Протокол", values.get("hysteriaProtocol", "")),
            _editor_field("upMbps", "Скорость отдачи, Мбит/с", values.get("upMbps", ""), kind="number"),
            _editor_field("downMbps", "Скорость загрузки, Мбит/с", values.get("downMbps", ""), kind="number"),
            _editor_field("obfsPassword", "Obfs", values.get("obfsPassword", "")),
        ])
        fields.extend(_native_tls_fields(values))
    elif protocol == "hysteria2":
        fields.extend([
            _editor_field("password", "Пароль", values.get("password", "")),
            _editor_field("obfsType", "Obfs", values.get("obfsType", ""), kind="combo", options=("", "salamander")),
            _editor_field("obfsPassword", "Пароль obfs", values.get("obfsPassword", "")),
        ])
        fields.extend(_native_tls_fields(values))
    elif protocol == "tuic":
        fields.extend([
            _editor_field("uuid", "UUID", values.get("uuid", "")),
            _editor_field("password", "Пароль", values.get("password", "")),
            _editor_field("congestionControl", "Congestion control", values.get("congestionControl", "cubic"), kind="combo", options=("cubic", "bbr", "new_reno")),
            _editor_field("udpRelayMode", "UDP relay", values.get("udpRelayMode", "native"), kind="combo", options=("native", "quic")),
            _editor_field("zeroRtt", "0-RTT handshake", values.get("zeroRtt", False), kind="bool"),
        ])
        fields.extend(_native_tls_fields(values))
    elif protocol == "mieru":
        fields.extend([
            _editor_field("serverPorts", "Диапазоны портов", values.get("serverPorts", ""), placeholder="20000-30000, 40000"),
            _editor_field("username", "Имя пользователя", values.get("username", "")),
            _editor_field("password", "Пароль", values.get("password", "")),
            _editor_field("nativeTransport", "Транспорт", values.get("nativeTransport", "TCP"), kind="combo", options=("TCP",)),
            _editor_field("multiplexing", "Multiplexing", values.get("multiplexing", "")),
            _editor_field("trafficPattern", "Traffic pattern", values.get("trafficPattern", "")),
        ])
    elif protocol in {"wireguard", "awg"}:
        fields.extend([
            _editor_field("interfaceAddresses", "Адреса интерфейса", values.get("interfaceAddresses", ""), kind="area", placeholder="10.0.0.2/32, fd00::2/128"),
            _editor_field("privateKey", "Private key", values.get("privateKey", "")),
            _editor_field("peersJson", "Peers (JSON)", values.get("peersJson", ""), kind="area", placeholder='[{"address":"example.com","port":51820,...}]'),
            _editor_field("wgPublicKey", "Peer public key", values.get("wgPublicKey", "")),
            _editor_field("preSharedKey", "Pre-shared key", values.get("preSharedKey", "")),
            _editor_field("allowedIps", "Allowed IPs", values.get("allowedIps", ""), kind="area"),
            _editor_field("mtu", "MTU", values.get("mtu", 1408), kind="number"),
            _editor_field("listenPort", "Локальный порт", values.get("listenPort", ""), kind="number"),
            _editor_field("keepalive", "Persistent keepalive", values.get("keepalive", ""), kind="number"),
            _editor_field("udpTimeout", "UDP timeout", values.get("udpTimeout", "5m0s")),
            _editor_field("workers", "WireGuard workers", values.get("workers", ""), kind="number"),
            _editor_field("preallocatedBuffers", "Preallocated buffers", values.get("preallocatedBuffers", ""), kind="number"),
            _editor_field("disablePauses", "Disable pauses", values.get("disablePauses", False), kind="bool"),
            _editor_field("dns", "DNS профиля", values.get("dns", ""), kind="area"),
            _editor_field(
                "amneziaEnabled",
                "AmneziaWG-совместимость",
                values.get("amneziaEnabled", protocol == "awg"),
                kind="bool",
            ),
        ])
        fields.extend(_amnezia_editor_fields(values, conditional=True))
    elif protocol == "warp":
        fields.extend([
            _editor_field("profileId", "WARP profile ID", values.get("profileId", "")),
            _editor_field("profilePrivateKey", "WARP private key", values.get("profilePrivateKey", "")),
            _editor_field("authToken", "WARP auth token", values.get("authToken", "")),
            _editor_field("reserved", "Reserved bytes", values.get("reserved", ""), placeholder="1, 2, 3"),
            _editor_field("listenPort", "Локальный порт", values.get("listenPort", ""), kind="number"),
            _editor_field("keepalive", "Persistent keepalive", values.get("keepalive", ""), kind="number"),
            _editor_field("udpTimeout", "UDP timeout", values.get("udpTimeout", "5m0s")),
            _editor_field("dns", "DNS профиля", values.get("dns", ""), kind="area"),
        ])
        fields.extend(_amnezia_editor_fields(values))
    elif protocol == "openvpn":
        fields.extend([
            _editor_field("openvpnServersJson", "OpenVPN servers (JSON)", values.get("openvpnServersJson", ""), kind="area", placeholder='[{"server":"vpn.example.com","server_port":1194}]'),
            _editor_field("openvpnProto", "OpenVPN transport", values.get("openvpnProto", "tcp"), kind="combo", options=("tcp",)),
            _editor_field("openvpnCipher", "Data cipher", values.get("openvpnCipher", ""), kind="combo", options=("", "AES-128-GCM", "AES-192-GCM", "AES-256-GCM", "AES-128-CBC", "AES-192-CBC", "AES-256-CBC", "CHACHA20-POLY1305")),
            _editor_field("openvpnAuth", "HMAC auth", values.get("openvpnAuth", ""), kind="combo", options=("", "SHA1", "SHA256", "SHA384", "SHA512")),
            _editor_field("username", "Username", values.get("username", "")),
            _editor_field("password", "Password", values.get("password", ""), secret=True),
            _editor_field("keyPassword", "Private key password", values.get("keyPassword", ""), secret=True),
            _editor_field("openvpnProxyType", "OpenVPN proxy", values.get("openvpnProxyType", ""), kind="combo", options=("", "http", "socks")),
            _editor_field("openvpnProxyServer", "Proxy server", values.get("openvpnProxyServer", ""), when_key="openvpnProxyType", when_values=("http", "socks")),
            _editor_field("openvpnProxyPort", "Proxy port", values.get("openvpnProxyPort", ""), kind="number", when_key="openvpnProxyType", when_values=("http", "socks")),
            _editor_field("openvpnProxyUsername", "Proxy username", values.get("openvpnProxyUsername", ""), when_key="openvpnProxyType", when_values=("http", "socks")),
            _editor_field("openvpnProxyPassword", "Proxy password", values.get("openvpnProxyPassword", ""), secret=True, when_key="openvpnProxyType", when_values=("http", "socks")),
            _editor_field("tlsCrypt", "TLS Crypt", values.get("tlsCrypt", ""), kind="area"),
            _editor_field("tlsCryptV2", "TLS Crypt v2", values.get("tlsCryptV2", False), kind="bool"),
            _editor_field("tlsAuth", "TLS Auth", values.get("tlsAuth", ""), kind="area"),
            _editor_field("keyDirection", "Key direction", values.get("keyDirection", -1), kind="number"),
            _editor_field("certificate", "Client certificate", values.get("certificate", ""), kind="area"),
            _editor_field("privateKey", "Client private key", values.get("privateKey", ""), kind="area"),
            _editor_field("caCertificate", "CA certificate", values.get("caCertificate", ""), kind="area"),
            _editor_field("tlsCipherSuites", "TLS cipher suites", values.get("tlsCipherSuites", ""), kind="area"),
            _editor_field("verifyX509Name", "Verify X.509 name", values.get("verifyX509Name", "")),
            _editor_field("verifyX509NameMode", "X.509 name mode", values.get("verifyX509NameMode", "name"), kind="combo", options=("name", "name-prefix", "name-suffix")),
            _editor_field("allowedIps", "Allowed IPs", values.get("allowedIps", ""), kind="area"),
            _editor_field("interfaceName", "Interface name", values.get("interfaceName", "openvpn0")),
            _editor_field("reconnectDelay", "Reconnect delay", values.get("reconnectDelay", "")),
            _editor_field("pingInterval", "Ping interval", values.get("pingInterval", "")),
            _editor_field("pingRestart", "Ping restart", values.get("pingRestart", "")),
            _editor_field("kernelTx", "Kernel TX", values.get("kernelTx", False), kind="bool"),
            _editor_field("kernelRx", "Kernel RX", values.get("kernelRx", False), kind="bool"),
            _editor_field("dns", "Profile DNS", values.get("dns", ""), kind="area"),
        ])
    elif protocol == "masque":
        fields.extend([
            _editor_field("interfaceName", "Имя интерфейса", values.get("interfaceName", "masque0")),
            _editor_field("systemInterface", "Системный интерфейс", values.get("systemInterface", False), kind="bool"),
            _editor_field("useHttp2", "Использовать HTTP/2", values.get("useHttp2", False), kind="bool"),
            _editor_field("useIpv6", "Использовать IPv6", values.get("useIpv6", False), kind="bool"),
            _editor_field("interfaceAddresses", "Адреса интерфейса", values.get("interfaceAddresses", ""), kind="area"),
            _editor_field("privateKey", "Private key", values.get("privateKey", "")),
            _editor_field("wgPublicKey", "Server public key", values.get("wgPublicKey", "")),
            _editor_field("profileId", "Profile ID", values.get("profileId", "")),
            _editor_field("profilePrivateKey", "Profile private key", values.get("profilePrivateKey", "")),
            _editor_field("authToken", "Auth token", values.get("authToken", "")),
            _editor_field("allowedIps", "Allowed IPs", values.get("allowedIps", ""), kind="area"),
            _editor_field("mtu", "MTU", values.get("mtu", ""), kind="number"),
            _editor_field("udpTimeout", "UDP timeout", values.get("udpTimeout", "5m0s")),
            _editor_field("udpKeepalive", "UDP keepalive", values.get("udpKeepalive", "30s")),
            _editor_field("reconnectDelay", "Задержка переподключения", values.get("reconnectDelay", "5s")),
            _editor_field("congestionController", "Congestion controller", values.get("congestionController", "bbr")),
            _editor_field("sni", "SNI", values.get("sni", "")),
            _editor_field("allowInsecure", "Пропускать проверку сертификата", values.get("allowInsecure", False), kind="bool"),
            _editor_field("dns", "DNS профиля", values.get("dns", ""), kind="area"),
        ])
    return fields


def load_node_edit_fields(node) -> dict:
    """Flatten only fields supported by the selected node protocol."""
    outbound = deepcopy(node.outbound) if isinstance(node.outbound, dict) else {}
    protocol = _protocol_from_node(node)
    capabilities = _field_capabilities(protocol)
    native = _native_payload(outbound)
    fields: dict[str, Any] = {
        "name": node.name or "",
        "group": node.group or "",
        "server": node.server or "",
        "port": str(node.port or ""),
        "protocol": protocol.upper() or "?",
        "protocolKey": protocol,
        "uuid": "",
        "encryption": "none",
        "flow": "",
        "alterId": 0,
        "vmessSecurity": "auto",
        "username": "",
        "password": "",
        "method": "",
        "plugin": "",
        "network": "tcp",
        "rawHeader": "none",
        "transportPath": "",
        "transportHost": "",
        "grpcServiceName": "",
        "xhttpMode": "auto",
        "xhttpExtra": "",
        "kcpHeader": "none",
        "kcpSeed": "",
        "kcpMtu": "",
        "kcpTti": "",
        "kcpUplink": "",
        "kcpDownlink": "",
        "kcpCongestion": False,
        "security": "none",
        "sni": "",
        "fingerprint": "",
        "allowInsecure": False,
        "alpn": "",
        "pinnedPeerCertSha256": "",
        "publicKey": "",
        "shortId": "",
        "spiderX": "",
        "pqv": "",
        "finalmask": "",
        "amneziaEnabled": protocol == "awg" or isinstance(native.get("amnezia"), dict),
        "capabilities": capabilities,
        "editHint": _edit_hint(protocol, capabilities),
    }
    settings = outbound.get("settings") if isinstance(outbound.get("settings"), dict) else {}
    if protocol in {"vless", "vmess"}:
        vnext = _first_dict(settings.get("vnext"))
        user = _first_dict(vnext.get("users"))
        fields["uuid"] = str(user.get("id") or "")
        fields["encryption"] = str(user.get("encryption") or "none")
        fields["flow"] = str(user.get("flow") or "")
        fields["alterId"] = int(user.get("alterId") or 0)
        fields["vmessSecurity"] = str(user.get("security") or "auto")
    elif protocol in {"trojan", "shadowsocks", "socks", "http"}:
        server_item = _first_dict(settings.get("servers"))
        fields["password"] = str(server_item.get("password") or "")
        fields["method"] = str(server_item.get("method") or "")
        fields["plugin"] = str(server_item.get("plugin") or "")
        user = _first_dict(server_item.get("users"))
        fields["username"] = str(user.get("user") or "")
        if protocol in {"socks", "http"}:
            fields["password"] = str(user.get("pass") or "")

    stream = outbound.get("streamSettings") if isinstance(outbound.get("streamSettings"), dict) else {}
    fields["network"] = str(stream.get("network") or "tcp")
    raw = stream.get("rawSettings") if isinstance(stream.get("rawSettings"), dict) else {}
    header = raw.get("header") if isinstance(raw.get("header"), dict) else {}
    fields["rawHeader"] = str(header.get("type") or "none")
    network = str(stream.get("network") or "tcp").lower()
    if network == "ws":
        transport = stream.get("wsSettings") if isinstance(stream.get("wsSettings"), dict) else {}
        fields["transportPath"] = str(transport.get("path") or "")
        headers = transport.get("headers") if isinstance(transport.get("headers"), dict) else {}
        fields["transportHost"] = str(headers.get("Host") or headers.get("host") or "")
    elif network in {"http", "h2"}:
        transport = stream.get("httpSettings") if isinstance(stream.get("httpSettings"), dict) else stream.get("h2Settings") if isinstance(stream.get("h2Settings"), dict) else {}
        fields["transportPath"] = str(transport.get("path") or "")
        fields["transportHost"] = _text_list(transport.get("host"))
    elif network == "grpc":
        transport = stream.get("grpcSettings") if isinstance(stream.get("grpcSettings"), dict) else {}
        fields["grpcServiceName"] = str(transport.get("serviceName") or "")
    elif network == "xhttp":
        transport = stream.get("xhttpSettings") if isinstance(stream.get("xhttpSettings"), dict) else {}
        fields["transportPath"] = str(transport.get("path") or "")
        fields["transportHost"] = str(transport.get("host") or "")
        fields["xhttpMode"] = str(transport.get("mode") or "auto")
        fields["xhttpExtra"] = _json_field(transport.get("extra"))
    elif network == "httpupgrade":
        transport = stream.get("httpupgradeSettings") if isinstance(stream.get("httpupgradeSettings"), dict) else {}
        fields["transportPath"] = str(transport.get("path") or "")
        fields["transportHost"] = str(transport.get("host") or "")
    elif network in {"kcp", "mkcp"}:
        transport = stream.get("kcpSettings") if isinstance(stream.get("kcpSettings"), dict) else {}
        kcp_header = transport.get("header") if isinstance(transport.get("header"), dict) else {}
        fields["network"] = "kcp"
        fields["kcpHeader"] = str(kcp_header.get("type") or "none")
        fields["kcpSeed"] = str(transport.get("seed") or "")
        fields["kcpMtu"] = transport.get("mtu", "")
        fields["kcpTti"] = transport.get("tti", "")
        fields["kcpUplink"] = transport.get("uplinkCapacity", "")
        fields["kcpDownlink"] = transport.get("downlinkCapacity", "")
        fields["kcpCongestion"] = bool(transport.get("congestion", False))
    fields["security"] = str(stream.get("security") or "none")

    tls = stream.get("tlsSettings") if isinstance(stream.get("tlsSettings"), dict) else {}
    reality = stream.get("realitySettings") if isinstance(stream.get("realitySettings"), dict) else {}
    active_security = str(stream.get("security") or "").lower()
    security_payload = reality if active_security == "reality" else tls
    fields["sni"] = str(security_payload.get("serverName") or "")
    fields["fingerprint"] = str(security_payload.get("fingerprint") or "")
    fields["allowInsecure"] = bool(tls.get("allowInsecure", False))
    fields["alpn"] = _text_list(tls.get("alpn"))
    pinned = tls.get("pinnedPeerCertSha256")
    if isinstance(pinned, list):
        fields["pinnedPeerCertSha256"] = "~".join(str(item) for item in pinned if str(item))
    else:
        fields["pinnedPeerCertSha256"] = str(pinned or "")
    fields["publicKey"] = str(reality.get("publicKey") or "")
    fields["shortId"] = str(reality.get("shortId") or "")
    fields["spiderX"] = str(reality.get("spiderX") or "")
    fields["pqv"] = str(reality.get("mldsa65Verify") or "")
    finalmask = stream.get("finalmask")
    if finalmask not in (None, ""):
        fields["finalmask"] = (
            finalmask if isinstance(finalmask, str)
            else json.dumps(finalmask, ensure_ascii=False, separators=(",", ":"))
        )

    if native:
        tls_native = native.get("tls") if isinstance(native.get("tls"), dict) else {}
        fields["sni"] = str(tls_native.get("server_name") or fields["sni"])
        fields["allowInsecure"] = bool(tls_native.get("insecure", False))
        fields["alpn"] = _text_list(tls_native.get("alpn"))
        if protocol == "hysteria":
            fields["auth"] = str(native.get("auth_str") or "")
            fields["hysteriaProtocol"] = str(native.get("protocol") or "")
            fields["upMbps"] = native.get("up_mbps", native.get("up", ""))
            fields["downMbps"] = native.get("down_mbps", native.get("down", ""))
            fields["obfsPassword"] = str(native.get("obfs") or "")
        elif protocol == "hysteria2":
            fields["password"] = str(native.get("password") or "")
            obfs = native.get("obfs") if isinstance(native.get("obfs"), dict) else {}
            fields["obfsType"] = str(obfs.get("type") or "")
            fields["obfsPassword"] = str(obfs.get("password") or "")
        elif protocol == "tuic":
            fields["uuid"] = str(native.get("uuid") or "")
            fields["password"] = str(native.get("password") or "")
            fields["congestionControl"] = str(native.get("congestion_control") or "cubic")
            fields["udpRelayMode"] = str(native.get("udp_relay_mode") or "native")
            fields["zeroRtt"] = bool(native.get("zero_rtt_handshake", False))
        elif protocol == "mieru":
            fields["username"] = str(native.get("username") or "")
            fields["password"] = str(native.get("password") or "")
            fields["nativeTransport"] = str(native.get("transport") or "TCP").upper()
            fields["serverPorts"] = _text_list(native.get("server_ports"))
            fields["multiplexing"] = str(native.get("multiplexing") or "")
            fields["trafficPattern"] = str(native.get("traffic_pattern") or "")
        elif protocol == "naive":
            fields["username"] = str(native.get("username") or "")
            fields["password"] = str(native.get("password") or "")
            fields["insecureConcurrency"] = native.get("insecure_concurrency", 0)
            fields["extraHeaders"] = _json_field(native.get("extra_headers"))
            udp_over_tcp = native.get("udp_over_tcp", False)
            fields["udpOverTcpEnabled"] = bool(udp_over_tcp)
            fields["udpOverTcpOptions"] = _json_field(udp_over_tcp) if isinstance(udp_over_tcp, dict) else ""
            fields["naiveQuic"] = bool(native.get("quic", False))
            fields["quicCongestionControl"] = str(native.get("quic_congestion_control") or "")
        elif protocol in {"wireguard", "awg"}:
            peer = _first_dict(native.get("peers"))
            fields["server"] = str(peer.get("address") or peer.get("server") or fields["server"])
            fields["port"] = str(peer.get("port") or peer.get("server_port") or fields["port"])
            fields["interfaceAddresses"] = _text_list(native.get("address"))
            fields["privateKey"] = str(native.get("private_key") or "")
            fields["peersJson"] = json.dumps(
                native.get("peers") if isinstance(native.get("peers"), list) else [],
                ensure_ascii=False,
                separators=(",", ":"),
            )
            fields["wgPublicKey"] = str(peer.get("public_key") or "")
            fields["preSharedKey"] = str(peer.get("pre_shared_key") or "")
            fields["allowedIps"] = _text_list(peer.get("allowed_ips"))
            fields["mtu"] = native.get("mtu", 1408)
            fields["listenPort"] = native.get("listen_port", "")
            fields["keepalive"] = peer.get("persistent_keepalive_interval", "")
            fields["udpTimeout"] = str(native.get("udp_timeout") or "5m0s")
            fields["workers"] = native.get("workers", "")
            fields["preallocatedBuffers"] = native.get("preallocated_buffers_per_pool", "")
            fields["disablePauses"] = bool(native.get("disable_pauses", False))
            fields["dns"] = _text_list(outbound.get("_dns"))
        elif protocol == "warp":
            profile = native.get("profile") if isinstance(native.get("profile"), dict) else {}
            fields["profileId"] = str(profile.get("id") or "")
            fields["profilePrivateKey"] = str(profile.get("private_key") or "")
            fields["authToken"] = str(profile.get("auth_token") or "")
            fields["reserved"] = _text_list(native.get("reserved"))
            fields["listenPort"] = native.get("listen_port", "")
            fields["keepalive"] = native.get("persistent_keepalive_interval", "")
            fields["udpTimeout"] = str(native.get("udp_timeout") or "5m0s")
            fields["dns"] = _text_list(outbound.get("_dns"))
        elif protocol == "openvpn":
            openvpn_server = _first_dict(native.get("servers"))
            tls_openvpn = native.get("tls") if isinstance(native.get("tls"), dict) else {}
            fields["server"] = str(openvpn_server.get("server") or fields["server"])
            fields["port"] = str(openvpn_server.get("server_port") or fields["port"])
            fields["openvpnServersJson"] = json.dumps(
                native.get("servers") if isinstance(native.get("servers"), list) else [],
                ensure_ascii=False,
                separators=(",", ":"),
            )
            fields["openvpnProto"] = str(native.get("proto") or "tcp")
            fields["openvpnCipher"] = str(native.get("cipher") or "")
            fields["openvpnAuth"] = str(native.get("auth") or "")
            fields["username"] = str(native.get("username") or "")
            fields["password"] = str(native.get("password") or "")
            fields["keyPassword"] = str(native.get("key_password") or "")
            openvpn_proxy = native.get("lumen_proxy") if isinstance(native.get("lumen_proxy"), dict) else {}
            fields["openvpnProxyType"] = str(openvpn_proxy.get("type") or "")
            fields["openvpnProxyServer"] = str(openvpn_proxy.get("server") or "")
            fields["openvpnProxyPort"] = str(openvpn_proxy.get("server_port") or "")
            fields["openvpnProxyUsername"] = str(openvpn_proxy.get("username") or "")
            fields["openvpnProxyPassword"] = str(openvpn_proxy.get("password") or "")
            fields["tlsCrypt"] = str(native.get("tls_crypt") or "")
            fields["tlsCryptV2"] = bool(native.get("tls_crypt_v2", False))
            fields["tlsAuth"] = str(native.get("tls_auth") or "")
            fields["keyDirection"] = native.get("key_direction", -1)
            fields["certificate"] = str(tls_openvpn.get("certificate") or "")
            fields["privateKey"] = str(tls_openvpn.get("key") or "")
            fields["caCertificate"] = str(tls_openvpn.get("ca") or "")
            fields["tlsCipherSuites"] = _text_list(tls_openvpn.get("cipher_suites"))
            fields["verifyX509Name"] = str(tls_openvpn.get("verify_x509_name") or "")
            fields["verifyX509NameMode"] = str(tls_openvpn.get("verify_x509_name_mode") or "name").replace("exact", "name")
            fields["allowedIps"] = _text_list(native.get("allowed_ips"))
            fields["interfaceName"] = str(native.get("name") or "openvpn0")
            fields["reconnectDelay"] = str(native.get("reconnect_delay") or "")
            fields["pingInterval"] = str(native.get("ping_interval") or "")
            fields["pingRestart"] = str(native.get("ping_restart") or "")
            fields["kernelTx"] = bool(tls_openvpn.get("kernel_tx", False))
            fields["kernelRx"] = bool(tls_openvpn.get("kernel_rx", False))
            fields["dns"] = _text_list(outbound.get("_dns"))
        elif protocol == "masque":
            profile = native.get("profile") if isinstance(native.get("profile"), dict) else {}
            fields["server"] = str(native.get("server") or fields["server"])
            fields["port"] = str(native.get("server_port") or fields["port"])
            fields["interfaceName"] = str(native.get("name") or "masque0")
            fields["systemInterface"] = bool(native.get("system", False))
            fields["useHttp2"] = bool(native.get("use_http2", False))
            fields["useIpv6"] = bool(native.get("use_ipv6", False))
            fields["interfaceAddresses"] = _text_list(native.get("address"))
            fields["privateKey"] = str(native.get("private_key") or "")
            fields["wgPublicKey"] = str(native.get("public_key") or "")
            fields["profileId"] = str(profile.get("id") or "")
            fields["profilePrivateKey"] = str(profile.get("private_key") or "")
            fields["authToken"] = str(profile.get("auth_token") or "")
            fields["allowedIps"] = _text_list(native.get("allowed_ips"))
            fields["mtu"] = native.get("mtu", "")
            fields["udpTimeout"] = str(native.get("udp_timeout") or "5m0s")
            fields["udpKeepalive"] = str(native.get("udp_keepalive_period") or "30s")
            fields["reconnectDelay"] = str(native.get("reconnect_delay") or "5s")
            fields["congestionController"] = str(native.get("congestion_controller") or "bbr")
            fields["dns"] = _text_list(outbound.get("_dns"))

        amnezia = native.get("amnezia") if isinstance(native.get("amnezia"), dict) else {}
        for key in _AMNEZIA_EDITOR_KEYS:
            fields[f"awg_{key}"] = amnezia.get(key, "")

    fields["protocolFields"] = _protocol_editor_fields(protocol, fields, native)
    return fields


def new_node_edit_fields(protocol: str, group: str = "Default") -> dict[str, Any]:
    """Return the same protocol-aware schema used by the normal node editor."""
    normalized = str(protocol or "vless").strip().lower()
    if normalized not in MANUAL_NODE_PROTOCOLS:
        normalized = "vless"
    from ...models import Node

    draft = Node(
        scheme=normalized,
        group=str(group or "Default").strip() or "Default",
        outbound={"protocol": normalized},
    )
    return load_node_edit_fields(draft)


def _edit_hint(protocol: str, capabilities: dict[str, bool | str]) -> str:
    return ""


def _split_editor_list(value: Any) -> list[str]:
    if isinstance(value, (list, tuple)):
        return [str(item).strip() for item in value if str(item).strip()]
    return [item.strip() for item in re.split(r"[,;\n]+", str(value or "")) if item.strip()]


def _editor_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _editor_int(value: Any, fallback: int | None = None) -> int | None:
    if value in (None, ""):
        return fallback
    try:
        return int(str(value).strip())
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Ожидалось целое число, получено: {value}") from exc


def _set_optional(parent: dict[str, Any], key: str, value: Any) -> None:
    if value not in (None, "", [], {}):
        parent[key] = value
    else:
        parent.pop(key, None)


def _update_stream_transport(stream: dict[str, Any], value) -> None:
    network = value("network", "tcp").lower() or "tcp"
    stream["network"] = network
    settings_keys = {
        "wsSettings", "httpSettings", "h2Settings", "grpcSettings",
        "xhttpSettings", "httpupgradeSettings", "kcpSettings", "rawSettings", "quicSettings",
    }
    active_key = {
        "ws": "wsSettings",
        "http": "httpSettings",
        "h2": "httpSettings",
        "grpc": "grpcSettings",
        "xhttp": "xhttpSettings",
        "httpupgrade": "httpupgradeSettings",
        "kcp": "kcpSettings",
    }.get(network)
    for key in settings_keys:
        if key != active_key:
            stream.pop(key, None)

    path = value("transportPath")
    host = value("transportHost")
    if network == "ws":
        settings = stream.setdefault("wsSettings", {})
        _set_optional(settings, "path", path)
        headers = settings.setdefault("headers", {})
        if host:
            headers["Host"] = host
        else:
            headers.pop("Host", None)
            headers.pop("host", None)
        if not headers:
            settings.pop("headers", None)
    elif network in {"http", "h2"}:
        settings = stream.setdefault("httpSettings", {})
        _set_optional(settings, "path", path)
        _set_optional(settings, "host", _split_editor_list(host))
    elif network == "grpc":
        settings = stream.setdefault("grpcSettings", {})
        _set_optional(settings, "serviceName", value("grpcServiceName"))
    elif network == "xhttp":
        settings = stream.setdefault("xhttpSettings", {})
        _set_optional(settings, "path", path)
        _set_optional(settings, "host", host)
        mode = value("xhttpMode", "auto") or "auto"
        settings["mode"] = mode
        extra_text = value("xhttpExtra")
        if extra_text:
            try:
                extra = json.loads(extra_text)
            except json.JSONDecodeError as exc:
                raise ValueError("XHTTP extra должен быть корректным JSON") from exc
            if not isinstance(extra, dict):
                raise ValueError("XHTTP extra должен быть JSON-объектом")
            settings["extra"] = extra
        else:
            settings.pop("extra", None)
    elif network == "httpupgrade":
        settings = stream.setdefault("httpupgradeSettings", {})
        _set_optional(settings, "path", path)
        _set_optional(settings, "host", host)
    elif network == "kcp":
        settings = stream.setdefault("kcpSettings", {})
        settings["header"] = {"type": value("kcpHeader", "none") or "none"}
        _set_optional(settings, "seed", value("kcpSeed"))
        for field_key, config_key in (
            ("kcpMtu", "mtu"),
            ("kcpTti", "tti"),
            ("kcpUplink", "uplinkCapacity"),
            ("kcpDownlink", "downlinkCapacity"),
        ):
            parsed = _editor_int(value(field_key), None)
            _set_optional(settings, config_key, parsed)
        settings["congestion"] = _editor_bool(value("kcpCongestion", False))


def _update_stream_security(stream: dict[str, Any], value) -> None:
    security = value("security", "none").lower() or "none"
    stream["security"] = security
    if security == "reality":
        stream.pop("tlsSettings", None)
        reality = stream.setdefault("realitySettings", {})
        _set_optional(reality, "serverName", value("sni"))
        _set_optional(reality, "fingerprint", value("fingerprint"))
        _set_optional(reality, "publicKey", value("publicKey"))
        _set_optional(reality, "shortId", value("shortId"))
        _set_optional(reality, "spiderX", value("spiderX"))
        _set_optional(reality, "mldsa65Verify", value("pqv"))
    elif security == "tls":
        stream.pop("realitySettings", None)
        tls = stream.setdefault("tlsSettings", {})
        _set_optional(tls, "serverName", value("sni"))
        _set_optional(tls, "fingerprint", value("fingerprint"))
        _set_optional(tls, "pinnedPeerCertSha256", value("pinnedPeerCertSha256").lower())
        tls["allowInsecure"] = _editor_bool(value("allowInsecure", False))
        _set_optional(tls, "alpn", _split_editor_list(value("alpn")))
    else:
        stream.pop("tlsSettings", None)
        stream.pop("realitySettings", None)

    finalmask = value("finalmask")
    if finalmask:
        try:
            stream["finalmask"] = json.loads(finalmask)
        except json.JSONDecodeError:
            stream["finalmask"] = finalmask
    else:
        stream.pop("finalmask", None)


def _update_native_tls(native: dict[str, Any], value) -> None:
    tls = native.setdefault("tls", {})
    tls["enabled"] = True
    _set_optional(tls, "server_name", value("sni"))
    tls["insecure"] = _editor_bool(value("allowInsecure", False))
    _set_optional(tls, "alpn", _split_editor_list(value("alpn")))


def _ensure_native(outbound: dict[str, Any], protocol: str) -> dict[str, Any]:
    native = outbound.get("singbox")
    if not isinstance(native, dict):
        native_type = "wireguard" if protocol == "awg" else protocol
        native = {"type": native_type, "tag": "proxy"}
        outbound["singbox"] = native
    return native


def build_node_updates(node, fields: dict) -> dict:
    """Rebuild a node using the field schema for its actual protocol."""
    current = load_node_edit_fields(node)

    def raw(key: str, default: Any = "") -> Any:
        if key in fields:
            return fields[key]
        return current.get(key, default)

    def g(key: str, default: str = "") -> str:
        return str(raw(key, default) or "").strip()

    outbound = deepcopy(node.outbound) if isinstance(node.outbound, dict) else {}
    protocol = _protocol_from_node(node)
    capabilities = _field_capabilities(protocol)
    server = g("server")
    port = _safe_port(raw("port", node.port), node.port)

    name = g("name", node.name or "")
    updates: dict[str, Any] = {
        "name": name,
        "group": g("group", node.group or "") or "Default",
    }

    if not capabilities.get("endpoint"):
        updates["outbound"] = outbound
        return updates

    if protocol != "warp":
        updates["server"] = server
        updates["port"] = port

    if protocol in {"vless", "vmess", "trojan", "shadowsocks", "socks", "http"}:
        settings = outbound.setdefault("settings", {})
        if protocol in {"vless", "vmess"}:
            vnext = _ensure_first_dict(settings, "vnext")
            vnext["address"] = server
            vnext["port"] = port
            user = _ensure_first_dict(vnext, "users")
            user["id"] = g("uuid")
            if protocol == "vless":
                user["encryption"] = g("encryption", "none") or "none"
                _set_or_remove(user, "flow", g("flow"))
            else:
                user["alterId"] = int(_editor_int(raw("alterId", 0), 0) or 0)
                user["security"] = g("vmessSecurity", "auto") or "auto"
        else:
            server_item = _ensure_first_dict(settings, "servers")
            server_item["address"] = server
            server_item["port"] = port
            if protocol == "trojan":
                server_item["password"] = g("password")
            elif protocol == "shadowsocks":
                server_item["method"] = g("method")
                server_item["password"] = g("password")
                _set_optional(server_item, "plugin", g("plugin"))
            else:
                username = g("username")
                if username:
                    server_item["users"] = [{"user": username, "pass": g("password")}]
                else:
                    server_item.pop("users", None)

        if protocol in {"vless", "vmess", "trojan"}:
            certificate_pin = g("pinnedPeerCertSha256").lower()
            if certificate_pin and not re.fullmatch(r"[0-9a-f]{64}", certificate_pin):
                raise ValueError("TLS SHA-256 pin должен содержать ровно 64 hex-символа")
            stream = outbound.setdefault("streamSettings", {})
            _update_stream_transport(stream, g)
            _update_stream_security(stream, g)
    else:
        native = _ensure_native(outbound, protocol)
        if protocol in {"hysteria", "hysteria2", "tuic", "mieru", "naive"}:
            native["server"] = server
            native["server_port"] = port
        if protocol == "hysteria":
            native["auth_str"] = g("auth")
            _set_optional(native, "protocol", g("hysteriaProtocol"))
            _set_optional(native, "up_mbps", _editor_int(raw("upMbps"), None))
            _set_optional(native, "down_mbps", _editor_int(raw("downMbps"), None))
            _set_optional(native, "obfs", g("obfsPassword"))
            _update_native_tls(native, g)
        elif protocol == "hysteria2":
            native["password"] = g("password")
            obfs_type = g("obfsType")
            obfs_password = g("obfsPassword")
            if obfs_type or obfs_password:
                native["obfs"] = {"type": obfs_type or "salamander"}
                _set_optional(native["obfs"], "password", obfs_password)
            else:
                native.pop("obfs", None)
            _update_native_tls(native, g)
        elif protocol == "tuic":
            native["uuid"] = g("uuid")
            _set_optional(native, "password", g("password"))
            native["congestion_control"] = g("congestionControl", "cubic") or "cubic"
            native["udp_relay_mode"] = g("udpRelayMode", "native") or "native"
            native["zero_rtt_handshake"] = _editor_bool(raw("zeroRtt", False))
            _update_native_tls(native, g)
        elif protocol == "mieru":
            native["username"] = g("username")
            native["password"] = g("password")
            native["transport"] = g("nativeTransport", "TCP").upper() or "TCP"
            _set_optional(native, "server_ports", _split_editor_list(raw("serverPorts")))
            _set_optional(native, "multiplexing", g("multiplexing"))
            _set_optional(native, "traffic_pattern", g("trafficPattern"))
        elif protocol == "naive":
            native["username"] = g("username")
            native["password"] = g("password")
            native["insecure_concurrency"] = int(_editor_int(raw("insecureConcurrency", 0), 0) or 0)
            headers_text = g("extraHeaders")
            if headers_text:
                try:
                    headers = json.loads(headers_text)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"Дополнительные заголовки должны быть JSON-объектом: {exc.msg}") from exc
                if not isinstance(headers, dict):
                    raise ValueError("Дополнительные заголовки должны быть JSON-объектом")
                native["extra_headers"] = headers
            else:
                native.pop("extra_headers", None)
            udp_options_text = g("udpOverTcpOptions")
            if udp_options_text:
                try:
                    udp_options = json.loads(udp_options_text)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"UDP over TCP должен быть JSON-объектом: {exc.msg}") from exc
                if not isinstance(udp_options, dict):
                    raise ValueError("UDP over TCP должен быть JSON-объектом")
                native["udp_over_tcp"] = udp_options
            else:
                native["udp_over_tcp"] = _editor_bool(raw("udpOverTcpEnabled", False))
            native["quic"] = _editor_bool(raw("naiveQuic", False))
            _set_optional(native, "quic_congestion_control", g("quicCongestionControl"))
            tls = native.get("tls") if isinstance(native.get("tls"), dict) else {}
            tls["enabled"] = True
            _set_optional(tls, "server_name", g("sni") or server)
            for unsupported_key in ("alpn", "insecure", "utls"):
                tls.pop(unsupported_key, None)
            native["tls"] = tls
        elif protocol in {"wireguard", "awg"}:
            peers_json = g("peersJson")
            if peers_json:
                try:
                    parsed_peers = json.loads(peers_json)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"Peers должен быть корректным JSON-массивом: {exc.msg}") from exc
                if not isinstance(parsed_peers, list) or not all(isinstance(item, dict) for item in parsed_peers):
                    raise ValueError("Peers должен быть JSON-массивом объектов")
                native["peers"] = parsed_peers
            peer = _ensure_first_dict(native, "peers")
            peer["address"] = server
            peer["port"] = port
            peer.pop("server", None)
            peer.pop("server_port", None)
            native["address"] = _split_editor_list(raw("interfaceAddresses"))
            native["private_key"] = g("privateKey")
            peer["public_key"] = g("wgPublicKey")
            _set_optional(peer, "pre_shared_key", g("preSharedKey"))
            peer["allowed_ips"] = _split_editor_list(raw("allowedIps"))
            native["mtu"] = int(_editor_int(raw("mtu", 1408), 1408) or 1408)
            native["system"] = False
            _set_optional(native, "listen_port", _editor_int(raw("listenPort"), None))
            _set_optional(peer, "persistent_keepalive_interval", _editor_int(raw("keepalive"), None))
            _set_optional(native, "udp_timeout", g("udpTimeout", "5m0s") or "5m0s")
            _set_optional(native, "workers", _editor_int(raw("workers"), None))
            _set_optional(
                native,
                "preallocated_buffers_per_pool",
                _editor_int(raw("preallocatedBuffers"), None),
            )
            native["disable_pauses"] = _editor_bool(raw("disablePauses", False))
            _set_optional(outbound, "_dns", _split_editor_list(raw("dns")))
            amnezia_enabled = _editor_bool(
                raw(
                    "amneziaEnabled",
                    protocol == "awg" or isinstance(native.get("amnezia"), dict),
                )
            )
            if amnezia_enabled:
                amnezia = native.setdefault("amnezia", {})
                for key in _AMNEZIA_EDITOR_KEYS:
                    raw_value = raw(f"awg_{key}", "")
                    if protocol == "wireguard" and raw_value in (None, ""):
                        raw_value = _WG_COMPATIBLE_AMNEZIA_DEFAULTS.get(key, "")
                    if key in _AMNEZIA_NUMERIC_EDITOR_KEYS:
                        parsed = _editor_int(raw_value, None)
                    elif key in _AMNEZIA_RANGE_EDITOR_KEYS:
                        text_value = str(raw_value or "").strip()
                        parsed = int(text_value) if text_value.isascii() and text_value.isdigit() else text_value
                    else:
                        parsed = str(raw_value or "").strip()
                    _set_optional(amnezia, key, parsed)
                if not amnezia:
                    native.pop("amnezia", None)
                outbound["protocol"] = "awg"
                updates["scheme"] = "awg"
            else:
                native.pop("amnezia", None)
                outbound["protocol"] = "wireguard"
                updates["scheme"] = "wireguard"
        elif protocol == "warp":
            profile = native.setdefault("profile", {})
            profile["detour"] = "direct"
            _set_optional(profile, "id", g("profileId"))
            _set_optional(profile, "private_key", g("profilePrivateKey"))
            _set_optional(profile, "auth_token", g("authToken"))
            reserved = _split_editor_list(raw("reserved"))
            if reserved:
                try:
                    reserved_bytes = [int(item) for item in reserved]
                except ValueError as exc:
                    raise ValueError("Reserved должен содержать три числа от 0 до 255") from exc
                if len(reserved_bytes) != 3 or any(item < 0 or item > 255 for item in reserved_bytes):
                    raise ValueError("Reserved должен содержать три числа от 0 до 255")
                native["reserved"] = reserved_bytes
            else:
                native.pop("reserved", None)
            _set_optional(native, "listen_port", _editor_int(raw("listenPort"), None))
            _set_optional(native, "persistent_keepalive_interval", _editor_int(raw("keepalive"), None))
            _set_optional(native, "udp_timeout", g("udpTimeout"))
            _set_optional(outbound, "_dns", _split_editor_list(raw("dns")))
            amnezia = native.setdefault("amnezia", {})
            for key in _AMNEZIA_EDITOR_KEYS:
                raw_value = raw(f"awg_{key}", "")
                if key in _AMNEZIA_NUMERIC_EDITOR_KEYS:
                    parsed = _editor_int(raw_value, None)
                elif key in _AMNEZIA_RANGE_EDITOR_KEYS:
                    text_value = str(raw_value or "").strip()
                    parsed = int(text_value) if text_value.isascii() and text_value.isdigit() else text_value
                else:
                    parsed = str(raw_value or "").strip()
                _set_optional(amnezia, key, parsed)
            if not amnezia:
                native.pop("amnezia", None)
        elif protocol == "openvpn":
            servers_json = g("openvpnServersJson")
            if servers_json:
                try:
                    servers = json.loads(servers_json)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"OpenVPN servers must be a valid JSON array: {exc.msg}") from exc
                if not isinstance(servers, list) or not all(isinstance(item, dict) for item in servers):
                    raise ValueError("OpenVPN servers must be a JSON array of objects")
                native["servers"] = servers
            server_item = _ensure_first_dict(native, "servers")
            server_item["server"] = server
            server_item["server_port"] = port
            native["system"] = False
            native["name"] = g("interfaceName", "openvpn0") or "openvpn0"
            native["proto"] = g("openvpnProto", "tcp").lower() or "tcp"
            _set_optional(native, "cipher", g("openvpnCipher").upper())
            _set_optional(native, "auth", g("openvpnAuth").upper())
            _set_optional(native, "username", g("username"))
            _set_optional(native, "password", g("password"))
            _set_optional(native, "key_password", g("keyPassword"))
            proxy_type = g("openvpnProxyType").lower()
            if proxy_type:
                proxy_server = g("openvpnProxyServer")
                proxy_port = _editor_int(raw("openvpnProxyPort"), None)
                if proxy_type not in {"http", "socks"}:
                    raise ValueError("OpenVPN proxy type must be HTTP or SOCKS")
                if not proxy_server or not proxy_port:
                    raise ValueError("OpenVPN proxy server and port are required")
                openvpn_proxy = {
                    "type": proxy_type,
                    "server": proxy_server,
                    "server_port": int(proxy_port),
                }
                _set_optional(openvpn_proxy, "username", g("openvpnProxyUsername"))
                _set_optional(openvpn_proxy, "password", g("openvpnProxyPassword"))
                native["lumen_proxy"] = openvpn_proxy
            else:
                native.pop("lumen_proxy", None)
            _set_optional(native, "allowed_ips", _split_editor_list(raw("allowedIps")))
            _set_optional(native, "reconnect_delay", g("reconnectDelay"))
            _set_optional(native, "ping_interval", g("pingInterval"))
            _set_optional(native, "ping_restart", g("pingRestart"))

            tls_auth = str(raw("tlsAuth", "") or "").strip()
            tls_crypt = str(raw("tlsCrypt", "") or "").strip()
            if tls_auth and tls_crypt:
                raise ValueError("OpenVPN TLS Auth and TLS Crypt cannot be enabled together")
            if tls_auth:
                native["tls_auth"] = tls_auth
                native.pop("tls_auth_path", None)
                native.pop("tls_crypt", None)
                native.pop("tls_crypt_path", None)
                native.pop("tls_crypt_v2", None)
                native["key_direction"] = int(_editor_int(raw("keyDirection", -1), -1) or 0)
            else:
                native.pop("tls_auth", None)
                if not native.get("tls_auth_path"):
                    native.pop("key_direction", None)
                if tls_crypt:
                    native["tls_crypt"] = tls_crypt
                    native.pop("tls_crypt_path", None)
                    native["tls_crypt_v2"] = _editor_bool(raw("tlsCryptV2", False))
                else:
                    native.pop("tls_crypt", None)
                    if not native.get("tls_crypt_path"):
                        native.pop("tls_crypt_v2", None)

            tls = native.setdefault("tls", {})
            for field_key, config_key, path_key in (
                ("certificate", "certificate", "certificate_path"),
                ("privateKey", "key", "key_path"),
                ("caCertificate", "ca", "ca_path"),
            ):
                content = str(raw(field_key, "") or "").strip()
                if content:
                    tls[config_key] = content
                    tls.pop(path_key, None)
                else:
                    tls.pop(config_key, None)
            _set_optional(tls, "cipher_suites", _split_editor_list(raw("tlsCipherSuites")))
            _set_optional(tls, "verify_x509_name", g("verifyX509Name"))
            if tls.get("verify_x509_name"):
                tls["verify_x509_name_mode"] = g("verifyX509NameMode", "name") or "name"
            else:
                tls.pop("verify_x509_name_mode", None)
            tls["kernel_tx"] = _editor_bool(raw("kernelTx", False))
            tls["kernel_rx"] = _editor_bool(raw("kernelRx", False))
            if not any(value not in (None, "", False, [], {}) for value in tls.values()):
                native.pop("tls", None)
            _set_optional(outbound, "_dns", _split_editor_list(raw("dns")))
        elif protocol == "masque":
            native["server"] = server
            native["server_port"] = port
            native["name"] = g("interfaceName", "masque0") or "masque0"
            native["system"] = _editor_bool(raw("systemInterface", False))
            native["use_http2"] = _editor_bool(raw("useHttp2", False))
            native["use_ipv6"] = _editor_bool(raw("useIpv6", False))
            _set_optional(native, "address", _split_editor_list(raw("interfaceAddresses")))
            _set_optional(native, "private_key", g("privateKey"))
            _set_optional(native, "public_key", g("wgPublicKey"))
            profile = native.setdefault("profile", {})
            profile["detour"] = "direct"
            _set_optional(profile, "id", g("profileId"))
            _set_optional(profile, "private_key", g("profilePrivateKey"))
            _set_optional(profile, "auth_token", g("authToken"))
            _set_optional(native, "allowed_ips", _split_editor_list(raw("allowedIps")))
            _set_optional(native, "mtu", _editor_int(raw("mtu"), None))
            _set_optional(native, "udp_timeout", g("udpTimeout"))
            _set_optional(native, "udp_keepalive_period", g("udpKeepalive"))
            _set_optional(native, "reconnect_delay", g("reconnectDelay"))
            _set_optional(native, "congestion_controller", g("congestionController"))
            tls = native.setdefault("tls", {})
            _set_optional(tls, "server_name", g("sni"))
            tls["insecure"] = _editor_bool(raw("allowInsecure", False))
            if not tls.get("server_name") and not tls.get("insecure"):
                native.pop("tls", None)
            _set_optional(outbound, "_dns", _split_editor_list(raw("dns")))

    updates["outbound"] = outbound
    updates["link"] = _build_node_link(protocol, name, server, port, outbound)
    return updates
