from __future__ import annotations

import base64
from copy import deepcopy
from typing import Any

from ...wireguard_normalization import normalize_wireguard_endpoint
from ...openvpn_import import openvpn_requires_user_auth
from ...openvpn_normalization import normalize_openvpn_outbound, openvpn_private_key_is_encrypted

from ...multiplex import apply_singbox_multiplex

_SUPPORTED_NATIVE_PROTOCOLS = {
    "vless",
    "vmess",
    "trojan",
    "shadowsocks",
    "socks",
    "http",
    "warp",
    "wireguard",
    "awg",
    "hysteria",
    "hysteria2",
    "tuic",
    "mieru",
    "masque",
    "openvpn",
    "naive",
    "anytls",
    "snell",
}

_DEFAULT_HYSTERIA_UP_MBPS = 50
_DEFAULT_HYSTERIA_DOWN_MBPS = 200


def _ensure_hysteria_speeds(sb: dict[str, Any]) -> None:
    # sing-box Hysteria v1 refuses to initialize without non-zero up/down
    # speeds; supply defaults when the source link omitted them.
    if str(sb.get("type") or "").lower() != "hysteria":
        return

    def _missing(mbps_key: str, str_key: str) -> bool:
        value = sb.get(mbps_key)
        if isinstance(value, (int, float)) and value > 0:
            return False
        return not str(sb.get(str_key) or "").strip()

    if _missing("up_mbps", "up"):
        sb["up_mbps"] = _DEFAULT_HYSTERIA_UP_MBPS
    if _missing("down_mbps", "down"):
        sb["down_mbps"] = _DEFAULT_HYSTERIA_DOWN_MBPS


def build_singbox_outbound(
    node,
    *,
    tag: str = "proxy",
    multiplex_enabled: bool = False,
    multiplex_concurrency: int = 8,
) -> dict[str, Any]:
    """Convert a stored node outbound into a native sing-box outbound."""
    protocol = str((node.outbound or {}).get("protocol") or "").lower()
    if protocol not in _SUPPORTED_NATIVE_PROTOCOLS:
        raise ValueError(
            f"Текущий сервер нельзя конвертировать в native sing-box outbound: protocol `{protocol or 'unknown'}`"
        )

    outbound = _convert_outbound(deepcopy(node.outbound), tag=tag)
    _preserve_or_reject_semantic_fields(outbound)
    # Current sing-box no longer accepts Xray's grpcSettings.authority.
    # Sanitize native/imported payloads before validation as well.
    _strip_removed_transport_fields(outbound)
    _normalize_vless_vision(outbound)
    unsupported_transport = str(outbound.pop("_unsupported_transport", "") or "").strip()
    if unsupported_transport:
        raise ValueError(
            f"Текущий сервер нельзя конвертировать в native sing-box outbound: transport `{unsupported_transport}` не поддерживается"
        )

    outbound["tag"] = tag
    if str(outbound.get("type") or "").strip().lower() == "openvpn":
        requires_user_auth = bool(outbound.pop("lumen_requires_user_auth", False)) or openvpn_requires_user_auth(
            str(getattr(node, "link", "") or "")
        )
        normalize_openvpn_outbound(outbound)
        if openvpn_private_key_is_encrypted(outbound) and not str(outbound.get("key_password") or "").strip():
            raise ValueError("OpenVPN private key is encrypted and requires a private key password")
        if requires_user_auth:
            username = str(outbound.get("username") or "").strip()
            password = str(outbound.get("password") or "").strip()
            if not username or not password:
                raise ValueError("OpenVPN node requires a username and password")
    _ensure_hysteria_speeds(outbound)
    apply_singbox_multiplex(
        outbound,
        enabled=multiplex_enabled,
        concurrency=multiplex_concurrency,
    )
    return outbound


def _convert_outbound(xray_ob: dict[str, Any], *, tag: str = "proxy") -> dict[str, Any]:
    protocol = str(xray_ob.get("protocol") or "").lower()
    native = xray_ob.get("singbox")
    if isinstance(native, dict):
        sb = deepcopy(native)
        sb = normalize_wireguard_endpoint(sb)
        if str(sb.get("type") or "").strip().lower() == "openvpn":
            sb["system"] = False
            sb["name"] = str(sb.get("name") or "openvpn0")
        sb["tag"] = tag
        return sb

    xray_settings = dict(xray_ob.get("settings") or {})
    stream = dict(xray_ob.get("streamSettings") or {})

    sb: dict[str, Any] = {"type": protocol}

    if protocol in ("vless", "vmess"):
        vnext = (xray_settings.get("vnext") or [{}])[0]
        sb["server"] = str(vnext.get("address") or "")
        sb["server_port"] = int(vnext.get("port") or 0)
        users = (vnext.get("users") or [{}])[0]
        sb["uuid"] = str(users.get("id") or "")
        if protocol == "vless":
            encryption = str(users.get("encryption") or "").strip()
            # Classic VLESS stores the literal value `none`, while the
            # extended core accepts the complete VLESS Encryption descriptor
            # (for example mlkem768x25519plus.native.0rtt.<key>) on the
            # outbound itself.  Dropping it makes otherwise valid servers
            # fail only after the first dial.
            if encryption and encryption.lower() != "none":
                sb["encryption"] = encryption
            # State XUDP explicitly.  The current extended fork defaults to it,
            # but older/newer compatible cores do not all share that default.
            sb["packet_encoding"] = "xudp"
            flow = str(users.get("flow") or "")
            if flow:
                sb["flow"] = flow
        else:
            sb["alter_id"] = int(users.get("alterId") or 0)
            sb["security"] = str(users.get("security") or "auto")

    elif protocol == "trojan":
        servers = (xray_settings.get("servers") or [{}])[0]
        sb["server"] = str(servers.get("address") or "")
        sb["server_port"] = int(servers.get("port") or 0)
        sb["password"] = str(servers.get("password") or "")

    elif protocol == "shadowsocks":
        servers = (xray_settings.get("servers") or [{}])[0]
        sb["server"] = str(servers.get("address") or "")
        sb["server_port"] = int(servers.get("port") or 0)
        sb["method"] = str(servers.get("method") or "")
        sb["password"] = str(servers.get("password") or "")
        plugin = str(servers.get("plugin") or "").strip()
        if plugin:
            sb["plugin"] = plugin
        plugin_opts = str(servers.get("plugin_opts") or "").strip()
        if plugin_opts:
            sb["plugin_opts"] = plugin_opts

    elif protocol in ("socks", "http"):
        servers = (xray_settings.get("servers") or [{}])[0]
        sb["server"] = str(servers.get("address") or "")
        sb["server_port"] = int(servers.get("port") or 0)
        user_list = servers.get("users") or []
        if user_list:
            sb["username"] = str(user_list[0].get("user") or "")
            sb["password"] = str(user_list[0].get("pass") or "")

    _apply_tls(sb, stream, str(sb.get("server") or ""))
    _apply_transport(sb, stream)
    if protocol in {"shadowsocks", "socks", "http"} and "transport" in sb:
        # These exact outbound schemas do not embed V2Ray transports. The
        # Xray runtime can still handle the original streamSettings, so mark
        # the conversion unsupported instead of emitting fatal JSON.
        sb.pop("transport", None)
        sb["_unsupported_transport"] = str(stream.get("network") or "unknown")
    if protocol in {"shadowsocks", "socks"} and "tls" in sb:
        sb.pop("tls", None)
        sb["_unsupported_transport"] = f"{protocol} with TLS"
    return sb


def _normalize_vless_vision(value: Any) -> None:
    """Remove Vision only when its TLS/Reality or Encryption base is absent.

    Lumen's extended sing-box core supports Vision over a V2Ray transport
    (including XHTTP) through its transport connection hook.  Stripping flow
    merely because a transport is present breaks otherwise valid nodes.  The
    runtime warning is caused by a missing TLS/Reality and VLESS Encryption,
    so only that genuinely invalid combination is normalized.

    The recursive form also sanitizes imported full sing-box configurations,
    not only links converted from Xray's schema.
    """
    if isinstance(value, list):
        for nested in value:
            _normalize_vless_vision(nested)
        return
    if not isinstance(value, dict):
        return

    if str(value.get("type") or "").strip().lower() == "vless":
        flow = str(value.get("flow") or "").strip().lower()
        if flow == "xtls-rprx-vision":
            tls = value.get("tls")
            tls_enabled = isinstance(tls, dict) and tls.get("enabled") is True
            encryption = str(value.get("encryption") or "").strip().lower()
            encryption_enabled = encryption not in {"", "none"}
            # The extended core obtains the Vision base connection through a
            # V2Ray transport hook, so XHTTP/gRPC/WS are valid when TLS/Reality
            # or VLESS Encryption is actually present.
            if not tls_enabled and not encryption_enabled:
                value.pop("flow", None)

    for nested in value.values():
        _normalize_vless_vision(nested)


def _apply_tls(sb: dict[str, Any], stream: dict[str, Any], server: str = "") -> None:
    security = str(stream.get("security") or "").lower()
    if security not in ("tls", "reality"):
        return

    tls: dict[str, Any] = {"enabled": True}
    tls_settings = stream.get("tlsSettings")
    if isinstance(tls_settings, dict) and str(
        tls_settings.get("verifyPeerCertByName") or ""
    ).strip():
        sb.setdefault(
            "_unsupported_transport",
            "TLS verifyPeerCertByName requires Xray",
        )

    if security == "reality":
        reality_settings = dict(stream.get("realitySettings") or {})
        if str(
            reality_settings.get("mldsa65Verify")
            or reality_settings.get("mldsa65_verify")
            or ""
        ).strip():
            sb.setdefault(
                "_unsupported_transport",
                "Reality ML-DSA verification requires Xray",
            )
        spider_x = str(
            reality_settings.get("spiderX")
            or reality_settings.get("spider_x")
            or ""
        ).strip()
        if spider_x and spider_x != "/":
            sb.setdefault(
                "_unsupported_transport",
                "Reality SpiderX requires Xray",
            )
        server_name = str(reality_settings.get("serverName") or server or "").strip()
        if server_name:
            tls["server_name"] = server_name
        alpn = reality_settings.get("alpn")
        if alpn:
            tls["alpn"] = list(alpn) if isinstance(alpn, list) else [str(alpn)]
        fingerprint = _normalize_utls_fingerprint(reality_settings.get("fingerprint")) or "chrome"
        # The Reality client in the bundled core requires uTLS even when the
        # share link omitted fp=.
        tls["utls"] = {"enabled": True, "fingerprint": fingerprint}
        public_key = str(reality_settings.get("publicKey") or "")
        short_id = str(reality_settings.get("shortId") or "")
        tls["reality"] = {"enabled": True, "public_key": public_key, "short_id": short_id}
        tls["insecure"] = False
    else:
        tls_settings = dict(stream.get("tlsSettings") or {})
        server_name = str(tls_settings.get("serverName") or _infer_transport_host(stream) or server or "")
        if server_name:
            tls["server_name"] = server_name
        alpn = tls_settings.get("alpn")
        if alpn:
            tls["alpn"] = list(alpn) if isinstance(alpn, list) else [str(alpn)]
        fingerprint = _normalize_utls_fingerprint(tls_settings.get("fingerprint"))
        if fingerprint:
            tls["utls"] = {"enabled": True, "fingerprint": fingerprint}
        if _to_bool(tls_settings.get("allowInsecure", False)):
            tls["insecure"] = True
        pins = (
            tls_settings.get("pinSHA256")
            or tls_settings.get("pinnedPeerCertSha256")
            or tls_settings.get("certificatePublicKeySha256")
            or tls_settings.get("certificate_public_key_sha256")
        )
        if pins:
            tls["certificate_public_key_sha256"] = _normalize_certificate_public_key_pins(pins)
        for source_key, target_key in (
            ("disableSNI", "disable_sni"),
            ("minVersion", "min_version"),
            ("maxVersion", "max_version"),
            ("cipherSuites", "cipher_suites"),
            ("curvePreferences", "curve_preferences"),
            ("handshakeTimeout", "handshake_timeout"),
        ):
            value = tls_settings.get(source_key)
            if value not in (None, "", [], {}):
                tls[target_key] = value
        ech_config = str(tls_settings.get("echConfigList") or "")
        if ech_config:
            if "://" in ech_config:
                query_server, _, server_url = ech_config.partition("+")
                ech: dict[str, Any] = {"enabled": True}
                if query_server and server_url:
                    ech["query_server_name"] = query_server
                tls["ech"] = ech
            else:
                tls["ech"] = {
                    "enabled": True,
                    "config": [f"-----BEGIN ECH CONFIGS-----\n{ech_config}\n-----END ECH CONFIGS-----"],
                }

    sb["tls"] = tls


def _infer_transport_host(stream: dict[str, Any]) -> str:
    network = str(stream.get("network") or "").strip().lower()
    if network in {"tcp", "raw", "ws"}:
        settings = stream.get("wsSettings") if network == "ws" else stream.get("tcpSettings")
        if isinstance(settings, dict):
            headers = settings.get("headers") if network == "ws" else settings.get("header", {}).get("request", {}).get("headers")
            if isinstance(headers, dict):
                host = headers.get("Host") or headers.get("host")
                if isinstance(host, list):
                    return str(host[0]).strip() if host else ""
                return str(host or "").split(",")[0].strip()
    if network in {"http", "h2"}:
        settings = stream.get("httpSettings") if isinstance(stream.get("httpSettings"), dict) else {}
        host = settings.get("host")
        if isinstance(host, list) and host:
            return str(host[0]).strip()
        if isinstance(host, str):
            return host.split(",")[0].strip()
    if network == "grpc":
        settings = stream.get("grpcSettings") if isinstance(stream.get("grpcSettings"), dict) else {}
        return str(settings.get("authority") or "").strip()
    if network in {"xhttp", "httpupgrade"}:
        key = "xhttpSettings" if network == "xhttp" else "httpupgradeSettings"
        settings = stream.get(key) if isinstance(stream.get(key), dict) else {}
        return str(settings.get("host") or "").split(",")[0].strip()
    return ""


def _apply_transport(sb: dict[str, Any], stream: dict[str, Any]) -> None:
    network = str(stream.get("network") or "tcp").lower()
    # Xray calls the plain TCP transport `raw`; sing-box represents the same
    # transport by omitting the V2Ray transport block and using network=tcp.
    if network in {"tcp", "raw"}:
        return

    if network == "ws":
        ws_settings = dict(stream.get("wsSettings") or {})
        transport: dict[str, Any] = {"type": "ws"}
        path = str(ws_settings.get("path") or "")
        if path:
            _apply_websocket_path(transport, path, ws_settings)
        headers = dict(ws_settings.get("headers") or {})
        if headers:
            transport["headers"] = headers
        max_early_data = ws_settings.get("maxEarlyData", ws_settings.get("ed"))
        if max_early_data not in (None, ""):
            transport["max_early_data"] = int(max_early_data)
        early_data_header = str(ws_settings.get("earlyDataHeaderName") or "").strip()
        if early_data_header:
            transport["early_data_header_name"] = early_data_header
        sb["transport"] = transport
        return

    if network in ("http", "h2"):
        http_settings = dict(stream.get("httpSettings") or stream.get("h2Settings") or {})
        transport = {"type": "http"}
        host = http_settings.get("host")
        if host:
            transport["host"] = list(host) if isinstance(host, list) else [str(host)]
        path = str(http_settings.get("path") or "")
        if path:
            transport["path"] = path
        if isinstance(http_settings.get("headers"), dict):
            transport["headers"] = dict(http_settings["headers"])
        method = str(http_settings.get("method") or "").strip()
        if method:
            transport["method"] = method
        _copy_alias_value(http_settings, transport, ("idleTimeout", "idle_timeout"), "idle_timeout")
        _copy_alias_value(http_settings, transport, ("pingTimeout", "ping_timeout"), "ping_timeout")
        sb["transport"] = transport
        return

    if network == "grpc":
        grpc_settings = dict(stream.get("grpcSettings") or {})
        transport = {"type": "grpc"}
        service_name = str(grpc_settings.get("serviceName") or "")
        if service_name:
            transport["service_name"] = service_name
        if str(grpc_settings.get("authority") or "").strip() or _to_bool(
            grpc_settings.get("multiMode", grpc_settings.get("multi_mode", False))
        ):
            sb["_unsupported_transport"] = "gRPC authority/multi-mode requires Xray"
        _copy_alias_value(grpc_settings, transport, ("idleTimeout", "idle_timeout"), "idle_timeout")
        _copy_alias_value(grpc_settings, transport, ("pingTimeout", "ping_timeout"), "ping_timeout")
        permit = grpc_settings.get("permitWithoutStream", grpc_settings.get("permit_without_stream"))
        if permit not in (None, ""):
            transport["permit_without_stream"] = _to_bool(permit)
        sb["transport"] = transport
        return

    if network == "xhttp":
        xhttp_settings = dict(stream.get("xhttpSettings") or {})
        transport: dict[str, Any] = {"type": "xhttp"}
        mode = str(xhttp_settings.get("mode") or "").strip()
        if mode not in {"", "auto", "packet-up", "stream-up", "stream-one"}:
            sb["_unsupported_transport"] = f"xhttp mode {mode}"
            return
        if mode and mode != "auto":
            transport["mode"] = mode
        host = str(xhttp_settings.get("host") or "").strip()
        if host:
            transport["host"] = host
        path = str(xhttp_settings.get("path") or "").strip()
        if path:
            transport["path"] = path
        headers = xhttp_settings.get("headers")
        if isinstance(headers, dict) and headers:
            transport["headers"] = headers
        _copy_xhttp_base_options(xhttp_settings, transport)
        _copy_xhttp_download_settings(xhttp_settings, transport)
        _merge_xhttp_extra(xhttp_settings.get("extra"), transport)
        transport.setdefault("x_padding_bytes", "100-1000")
        sb["transport"] = transport
        return

    if network == "quic":
        sb["_unsupported_transport"] = "QUIC transport options require Xray"
        return

    if network == "httpupgrade":
        settings = dict(stream.get("httpupgradeSettings") or {})
        if str(settings.get("ed") or "").strip() or "?ed=" in str(
            settings.get("path") or ""
        ).lower():
            sb["_unsupported_transport"] = "HTTPUpgrade early-data requires Xray"
            return
        transport = {"type": "httpupgrade"}
        path = str(settings.get("path") or "")
        if path:
            transport["path"] = path.split("?", 1)[0] if "?ed=" in path.lower() else path
        host = str(settings.get("host") or "")
        if host:
            transport["host"] = host
        headers = settings.get("headers")
        if isinstance(headers, dict) and headers:
            transport["headers"] = headers
        sb["transport"] = transport
        return

    if network in {"kcp", "mkcp"}:
        settings = dict(stream.get("kcpSettings") or {})
        transport: dict[str, Any] = {"type": "mkcp"}
        for source_key, target_key, caster in (
            ("mtu", "mtu", int),
            ("tti", "tti", int),
            ("uplinkCapacity", "uplink_capacity", int),
            ("downlinkCapacity", "downlink_capacity", int),
            ("readBufferSize", "read_buffer_size", int),
            ("writeBufferSize", "write_buffer_size", int),
            ("seed", "seed", str),
        ):
            _copy_xhttp_value(settings, transport, source_key, target_key, caster)
        congestion = settings.get("congestion")
        if congestion not in (None, ""):
            transport["congestion"] = _to_bool(congestion)
        header = settings.get("header")
        if isinstance(header, dict):
            header_type = str(header.get("type") or "").strip()
            if header_type:
                transport["header_type"] = header_type
        sb["transport"] = transport
        return

    sb["_unsupported_transport"] = network


def _preserve_or_reject_semantic_fields(value: Any) -> None:
    """Migrate losslessly or reject fields the bundled schema cannot express.

    Schema aliases may be renamed later, but connection semantics must never
    be silently discarded merely to make strict JSON decoding succeed.
    """
    if isinstance(value, list):
        for nested in value:
            _preserve_or_reject_semantic_fields(nested)
        return
    if not isinstance(value, dict):
        return

    transport = value.get("transport")
    if isinstance(transport, dict):
        transport_type = str(transport.get("type") or "").strip().lower()
        if transport_type == "grpc":
            if _to_bool(transport.get("multiMode", transport.get("multi_mode", False))):
                raise ValueError("gRPC multi-mode requires the Xray runtime")
            authority = str(transport.get("authority") or "").strip()
            if authority:
                tls = value.get("tls")
                tls_enabled = isinstance(tls, dict) and tls.get("enabled") is True
                if not tls_enabled:
                    raise ValueError("gRPC authority without TLS requires the Xray runtime")
                existing = str(
                    tls.get("server_name") or tls.get("serverName") or ""
                ).strip()
                if existing and existing.casefold() != authority.casefold():
                    raise ValueError(
                        "different gRPC authority and TLS server name require the Xray runtime"
                    )
                tls["server_name"] = authority
                transport.pop("authority", None)
        elif transport_type == "httpupgrade":
            path = str(transport.get("path") or "")
            if (
                str(transport.get("ed") or transport.get("max_early_data") or "").strip()
                or "?ed=" in path.lower()
            ):
                raise ValueError("HTTPUpgrade early-data requires the Xray runtime")
        elif transport_type == "quic":
            semantic_keys = {str(key) for key in transport if str(key) != "type"}
            if semantic_keys:
                raise ValueError(
                    "QUIC transport options are not supported by the bundled sing-box schema"
                )
        elif transport_type == "xhttp":
            legacy_detour = str(transport.get("download_detour") or "").strip()
            if legacy_detour:
                download = transport.get("download")
                legacy_download = transport.get("download_settings", transport.get("downloadSettings"))
                if isinstance(download, dict):
                    download.setdefault("detour", legacy_detour)
                elif isinstance(legacy_download, dict):
                    legacy_download.setdefault("detour", legacy_detour)
                else:
                    raise ValueError("XHTTP download_detour requires download settings")

    tls = value.get("tls")
    if isinstance(tls, dict):
        reality = tls.get("reality")
        if isinstance(reality, dict):
            if str(
                reality.get("mldsa65Verify")
                or reality.get("mldsa65_verify")
                or ""
            ).strip():
                raise ValueError("Reality ML-DSA verification requires the Xray runtime")
            spider_x = str(
                reality.get("spiderX") or reality.get("spider_x") or ""
            ).strip()
            if spider_x and spider_x != "/":
                raise ValueError("Reality SpiderX requires the Xray runtime")

    for nested in value.values():
        _preserve_or_reject_semantic_fields(nested)


def _strip_removed_transport_fields(value: Any) -> None:
    """Migrate fields removed or renamed in the bundled sing-box schema."""
    if isinstance(value, dict):
        transport = value.get("transport")
        if isinstance(transport, dict):
            transport_type = str(transport.get("type") or "").strip().lower()
            if transport_type in {"tcp", "raw"}:
                value.pop("transport", None)
            else:
                _normalize_native_transport(transport)
        tls = value.get("tls")
        if isinstance(tls, dict):
            _move_alias(tls, "serverName", "server_name")
            _move_alias(tls, "allowInsecure", "insecure", caster=_to_bool)
            _move_alias(tls, "disableSNI", "disable_sni", caster=_to_bool)
            _move_alias(tls, "minVersion", "min_version")
            _move_alias(tls, "maxVersion", "max_version")
            _move_alias(tls, "cipherSuites", "cipher_suites")
            _move_alias(tls, "curvePreferences", "curve_preferences")
            _move_alias(tls, "handshakeTimeout", "handshake_timeout")
            pins = tls.get("certificate_public_key_sha256")
            alias_pins = [
                tls.pop("certificatePublicKeySha256", None),
                tls.pop("pinnedPeerCertSha256", None),
                tls.pop("pinSHA256", None),
            ]
            if not pins:
                pins = next((item for item in alias_pins if item not in (None, "")), None)
            if pins:
                tls["certificate_public_key_sha256"] = _normalize_certificate_public_key_pins(pins)
            utls = tls.get("utls")
            if isinstance(utls, dict) and utls.get("enabled") is not False:
                fingerprint = _normalize_utls_fingerprint(utls.get("fingerprint"))
                if fingerprint:
                    utls["enabled"] = True
                    utls["fingerprint"] = fingerprint
            reality = tls.get("reality")
            if isinstance(reality, dict):
                _move_alias(reality, "publicKey", "public_key")
                _move_alias(reality, "shortId", "short_id")
                reality.pop("spiderX", None)
                reality.pop("mldsa65Verify", None)
        for nested in value.values():
            _strip_removed_transport_fields(nested)
    elif isinstance(value, list):
        for nested in value:
            _strip_removed_transport_fields(nested)


def _move_alias(
    target: dict[str, Any],
    source_key: str,
    target_key: str,
    *,
    caster=None,
) -> None:
    value = target.pop(source_key, None)
    if target_key in target or value in (None, ""):
        return
    target[target_key] = caster(value) if caster is not None else value


def _normalize_native_transport(transport: dict[str, Any]) -> None:
    transport_type = str(transport.get("type") or "").strip().lower()
    transport.pop("authority", None)
    if transport_type == "grpc":
        _move_alias(transport, "serviceName", "service_name")
        _move_alias(transport, "idleTimeout", "idle_timeout")
        _move_alias(transport, "pingTimeout", "ping_timeout")
        _move_alias(transport, "permitWithoutStream", "permit_without_stream", caster=_to_bool)
        transport.pop("multiMode", None)
        transport.pop("multi_mode", None)
        return
    if transport_type == "ws":
        _move_alias(transport, "maxEarlyData", "max_early_data", caster=int)
        _move_alias(transport, "earlyDataHeaderName", "early_data_header_name")
        path = str(transport.get("path") or "")
        if path:
            normalized: dict[str, Any] = {}
            _apply_websocket_path(normalized, path, {
                "maxEarlyData": transport.get("max_early_data"),
                "earlyDataHeaderName": transport.get("early_data_header_name"),
            })
            transport.update(normalized)
        return
    if transport_type == "http":
        _move_alias(transport, "idleTimeout", "idle_timeout")
        _move_alias(transport, "pingTimeout", "ping_timeout")
        return
    if transport_type == "httpupgrade":
        transport.pop("ed", None)
        transport.pop("max_early_data", None)
        transport.pop("early_data_header_name", None)
        path = str(transport.get("path") or "")
        if "?ed=" in path.lower():
            transport["path"] = path.split("?", 1)[0]
        return
    if transport_type == "quic":
        for key in list(transport):
            if key != "type":
                transport.pop(key, None)
        return
    if transport_type != "xhttp":
        return

    legacy_download = transport.pop("download_settings", None)
    if legacy_download is None:
        legacy_download = transport.pop("downloadSettings", None)
    if "download" not in transport and isinstance(legacy_download, dict):
        transport["download"] = _build_xhttp_download(legacy_download)
    transport.pop("download_detour", None)
    normalized: dict[str, Any] = {}
    _copy_xhttp_base_options(transport, normalized)
    for target_key, aliases in _XHTTP_BASE_ALIASES.items():
        for alias in aliases:
            if alias != target_key:
                transport.pop(alias, None)
    transport.update(normalized)


def _copy_xhttp_value(
    source: dict[str, Any],
    target: dict[str, Any],
    source_key: str,
    target_key: str,
    caster,
) -> None:
    value = source.get(source_key)
    if value in (None, ""):
        return
    try:
        target[target_key] = caster(value)
    except Exception:
        target[target_key] = value


def _apply_websocket_path(
    transport: dict[str, Any],
    raw_path: str,
    settings: dict[str, Any],
) -> None:
    path, separator, query = raw_path.partition("?")
    transport["path"] = path if separator else raw_path
    if not separator:
        return
    query_early_data = ""
    for item in query.split("&"):
        key, equals, value = item.partition("=")
        if equals and key.strip().lower() == "ed":
            query_early_data = value.strip()
            break
    configured = settings.get("maxEarlyData", settings.get("ed", query_early_data))
    if configured in (None, ""):
        return
    try:
        early_data = int(configured)
    except (TypeError, ValueError):
        return
    if early_data <= 0:
        return
    transport["max_early_data"] = early_data
    transport.setdefault("early_data_header_name", "Sec-WebSocket-Protocol")


def _copy_xhttp_download_settings(source: dict[str, Any], target: dict[str, Any]) -> None:
    value = source.get("downloadSettings", source.get("download_settings", source.get("download")))
    if not isinstance(value, dict) or not _is_json_safe(value):
        return
    target["download"] = _build_xhttp_download(value)


def _merge_xhttp_extra(extra: Any, target: dict[str, Any]) -> None:
    if not isinstance(extra, dict):
        return
    allowed = {
        "mode",
        "downloadSettings",
        "download_settings",
        "download",
        "host",
        "headers",
        "path",
        "scMaxEachPostBytes",
        "scMaxBufferedPosts",
        "scMinPostsIntervalMs",
        "xPaddingBytes",
        "padding",
        "noGRPCHeader",
        "no_grpc_header",
        "noSSEHeader",
        "no_sse_header",
        "scStreamUpServerSecs",
        "sc_stream_up_server_secs",
        "serverMaxHeaderBytes",
        "server_max_header_bytes",
        "trustedXForwardedFor",
        "trusted_x_forwarded_for",
        "xmux",
        "xPaddingObfsMode",
        "x_padding_obfs_mode",
        "xPaddingKey",
        "xPaddingHeader",
        "xPaddingPlacement",
        "xPaddingMethod",
        "uplinkHTTPMethod",
        "sessionPlacement",
        "sessionKey",
        "seqPlacement",
        "seqKey",
        "uplinkDataPlacement",
        "uplinkDataKey",
        "uplinkChunkSize",
        "sessionIDTable",
        "sessionIDLength",
        "congestionController",
        "cwnd",
        "sc_max_each_post_bytes",
        "sc_max_buffered_posts",
        "sc_min_posts_interval_ms",
        "x_padding_bytes",
    }
    for key, value in extra.items():
        if not isinstance(key, str) or key not in allowed or not _is_json_safe(value):
            continue
        if key in {"download", "downloadSettings", "download_settings"} and isinstance(value, dict):
            target["download"] = _build_xhttp_download(value)
            continue
        if key == "mode" and "mode" not in target:
            mode = str(value or "").strip()
            if mode in {"packet-up", "stream-up", "stream-one"}:
                target["mode"] = mode
    _copy_xhttp_base_options(extra, target, overwrite=False)


def _normalize_xhttp_key(key: str) -> str:
    return {
        "scMaxEachPostBytes": "sc_max_each_post_bytes",
        "scMaxBufferedPosts": "sc_max_buffered_posts",
        "scMinPostsIntervalMs": "sc_min_posts_interval_ms",
        "xPaddingBytes": "x_padding_bytes",
        "padding": "x_padding_bytes",
        "noGRPCHeader": "no_grpc_header",
        "noSSEHeader": "no_sse_header",
        "scStreamUpServerSecs": "sc_stream_up_server_secs",
        "serverMaxHeaderBytes": "server_max_header_bytes",
        "trustedXForwardedFor": "trusted_x_forwarded_for",
        "xPaddingObfsMode": "x_padding_obfs_mode",
        "xPaddingKey": "x_padding_key",
        "xPaddingHeader": "x_padding_header",
        "xPaddingPlacement": "x_padding_placement",
        "xPaddingMethod": "x_padding_method",
        "uplinkHTTPMethod": "uplink_http_method",
        "uplinkHttpMethod": "uplink_http_method",
        "sessionPlacement": "session_placement",
        "sessionKey": "session_key",
        "seqPlacement": "seq_placement",
        "seqKey": "seq_key",
        "uplinkDataPlacement": "uplink_data_placement",
        "uplinkDataKey": "uplink_data_key",
        "uplinkChunkSize": "uplink_chunk_size",
        "sessionIDTable": "session_id_table",
        "sessionIdTable": "session_id_table",
        "sessionIDLength": "session_id_length",
        "sessionIdLength": "session_id_length",
        "congestionController": "congestion_controller",
    }.get(key, key)


def _normalize_json_keys(value: Any) -> Any:
    if isinstance(value, dict):
        return {_normalize_xhttp_key(str(k)): _normalize_json_keys(v) for k, v in value.items() if isinstance(k, str)}
    if isinstance(value, list):
        return [_normalize_json_keys(item) for item in value]
    return value


_XHTTP_BASE_ALIASES: dict[str, tuple[str, ...]] = {
    "host": ("host",),
    "path": ("path",),
    "headers": ("headers",),
    "domain_strategy": ("domain_strategy", "domainStrategy"),
    "x_padding_bytes": ("x_padding_bytes", "xPaddingBytes", "padding"),
    "no_grpc_header": ("no_grpc_header", "noGRPCHeader", "noGrpcHeader"),
    "no_sse_header": ("no_sse_header", "noSSEHeader", "noSseHeader"),
    "sc_max_each_post_bytes": ("sc_max_each_post_bytes", "scMaxEachPostBytes"),
    "sc_min_posts_interval_ms": ("sc_min_posts_interval_ms", "scMinPostsIntervalMs"),
    "sc_max_buffered_posts": ("sc_max_buffered_posts", "scMaxBufferedPosts"),
    "sc_stream_up_server_secs": ("sc_stream_up_server_secs", "scStreamUpServerSecs"),
    "server_max_header_bytes": ("server_max_header_bytes", "serverMaxHeaderBytes"),
    "trusted_x_forwarded_for": ("trusted_x_forwarded_for", "trustedXForwardedFor"),
    "xmux": ("xmux",),
    "x_padding_obfs_mode": ("x_padding_obfs_mode", "xPaddingObfsMode"),
    "x_padding_key": ("x_padding_key", "xPaddingKey"),
    "x_padding_header": ("x_padding_header", "xPaddingHeader"),
    "x_padding_placement": ("x_padding_placement", "xPaddingPlacement"),
    "x_padding_method": ("x_padding_method", "xPaddingMethod"),
    "uplink_http_method": ("uplink_http_method", "uplinkHTTPMethod", "uplinkHttpMethod"),
    "session_placement": ("session_placement", "sessionPlacement"),
    "session_key": ("session_key", "sessionKey"),
    "seq_placement": ("seq_placement", "seqPlacement"),
    "seq_key": ("seq_key", "seqKey"),
    "uplink_data_placement": ("uplink_data_placement", "uplinkDataPlacement"),
    "uplink_data_key": ("uplink_data_key", "uplinkDataKey"),
    "uplink_chunk_size": ("uplink_chunk_size", "uplinkChunkSize"),
    "session_id_table": ("session_id_table", "sessionIDTable", "sessionIdTable"),
    "session_id_length": ("session_id_length", "sessionIDLength", "sessionIdLength"),
    "congestion_controller": ("congestion_controller", "congestionController"),
    "cwnd": ("cwnd",),
}


def _first_present(source: dict[str, Any], aliases: tuple[str, ...]) -> Any:
    for key in aliases:
        if key in source:
            return source[key]
    return None


def _copy_alias_value(
    source: dict[str, Any],
    target: dict[str, Any],
    aliases: tuple[str, ...],
    target_key: str,
) -> None:
    value = _first_present(source, aliases)
    if value not in (None, "", [], {}):
        target[target_key] = deepcopy(value)


def _copy_xhttp_base_options(
    source: dict[str, Any],
    target: dict[str, Any],
    *,
    overwrite: bool = True,
) -> None:
    for target_key, aliases in _XHTTP_BASE_ALIASES.items():
        if not overwrite and target_key in target:
            continue
        value = _first_present(source, aliases)
        if value in (None, "", [], {}):
            continue
        if target_key == "headers" and isinstance(value, dict):
            headers = {str(key): str(item) for key, item in value.items() if item is not None}
            # The fork rejects Host inside headers; it has a dedicated host
            # option. Preserve the value by moving it there.
            for key in list(headers):
                if key.lower() == "host":
                    target.setdefault("host", headers.pop(key))
            if headers:
                target[target_key] = headers
            continue
        if target_key in {"no_grpc_header", "no_sse_header", "x_padding_obfs_mode"}:
            target[target_key] = _to_bool(value)
            continue
        if target_key == "domain_strategy":
            normalized = str(value).strip().lower().replace("-", "_")
            normalized = {
                "preferipv4": "prefer_ipv4",
                "preferipv6": "prefer_ipv6",
                "ipv4only": "ipv4_only",
                "ipv6only": "ipv6_only",
            }.get(normalized.replace("_", ""), normalized)
            if normalized in {"prefer_ipv4", "prefer_ipv6", "ipv4_only", "ipv6_only"}:
                target[target_key] = normalized
            continue
        if target_key in {"sc_max_buffered_posts", "server_max_header_bytes", "cwnd"}:
            try:
                number = int(value)
            except (TypeError, ValueError):
                continue
            if number >= 0:
                target[target_key] = number
            continue
        if target_key == "trusted_x_forwarded_for":
            target[target_key] = (
                [str(item).strip() for item in value if str(item).strip()]
                if isinstance(value, list)
                else [item.strip() for item in str(value).split(",") if item.strip()]
            )
            continue
        if target_key == "xmux" and isinstance(value, dict):
            xmux: dict[str, Any] = {}
            for key, item in value.items():
                normalized = {
                    "maxConcurrency": "max_concurrency",
                    "maxConnections": "max_connections",
                    "cMaxReuseTimes": "c_max_reuse_times",
                    "hMaxRequestTimes": "h_max_request_times",
                    "hMaxReusableSecs": "h_max_reusable_secs",
                    "hKeepAlivePeriod": "h_keep_alive_period",
                }.get(str(key), str(key))
                if normalized in {
                    "max_concurrency",
                    "max_connections",
                    "c_max_reuse_times",
                    "h_max_request_times",
                    "h_max_reusable_secs",
                    "h_keep_alive_period",
                }:
                    if normalized == "h_keep_alive_period":
                        try:
                            xmux[normalized] = int(item)
                        except (TypeError, ValueError):
                            continue
                    else:
                        xmux[normalized] = item
            if xmux:
                target[target_key] = xmux
            continue
        target[target_key] = deepcopy(value)


def _build_xhttp_download(source: dict[str, Any]) -> dict[str, Any]:
    stream = source.get("streamSettings") if isinstance(source.get("streamSettings"), dict) else source
    nested = stream.get("xhttpSettings", stream.get("xhttp_settings"))
    if not isinstance(nested, dict):
        nested = source.get("xhttpSettings", source.get("xhttp_settings"))
    xhttp = nested if isinstance(nested, dict) else source

    server = str(
        source.get("server")
        or source.get("address")
        or stream.get("server")
        or stream.get("address")
        or ""
    ).strip()
    raw_port = source.get("server_port", source.get("port", stream.get("server_port", stream.get("port"))))
    try:
        port = int(raw_port or 0)
    except (TypeError, ValueError):
        port = 0
    if not server or port <= 0:
        raise ValueError("XHTTP download settings require server/address and port/server_port")

    download: dict[str, Any] = {"server": server, "server_port": port}
    _copy_xhttp_base_options(source, download)
    if xhttp is not source:
        _copy_xhttp_base_options(xhttp, download)
    download.setdefault("x_padding_bytes", "100-1000")

    detour = str(source.get("detour") or stream.get("detour") or "").strip()
    if detour:
        download["detour"] = detour

    native_tls = stream.get("tls", source.get("tls"))
    if isinstance(native_tls, dict):
        allowed_tls = {
            "enabled", "engine", "disable_sni", "server_name", "insecure", "alpn",
            "min_version", "max_version", "cipher_suites", "curve_preferences",
            "certificate", "certificate_path", "certificate_public_key_sha256",
            "client_certificate", "client_certificate_path", "client_key", "client_key_path",
            "fragment", "fragment_fallback_delay", "record_fragment", "spoof", "spoof_method",
            "kernel_tx", "kernel_rx", "handshake_timeout", "ech", "utls", "reality",
        }
        download["tls"] = {key: deepcopy(value) for key, value in native_tls.items() if key in allowed_tls}
        download["tls"].setdefault("enabled", True)
    else:
        converted: dict[str, Any] = {}
        _apply_tls(converted, stream, server)
        if isinstance(converted.get("tls"), dict):
            download["tls"] = converted["tls"]
    return download


def _normalize_utls_fingerprint(value: Any) -> str:
    compact = str(value or "").strip().lower().replace("_", "-")
    if not compact:
        return ""
    aliases = {
        "chrome-psk": "chrome_psk",
        "chrome-psk-shuffle": "chrome_psk_shuffle",
        "chrome-padding-psk-shuffle": "chrome_padding_psk_shuffle",
        "chrome-pq": "chrome_pq",
        "chrome-pq-psk": "chrome_pq_psk",
    }
    if compact in aliases:
        return aliases[compact]
    for prefix in ("chrome", "firefox", "edge", "safari", "ios", "android", "qq", "360"):
        if compact.startswith(prefix):
            return prefix
    if compact.startswith("randomized"):
        return "randomized"
    if compact.startswith("random"):
        return "random"
    # A different ClientHello fingerprint can be required by the server.
    # Silently replacing an unknown value with Chrome produces a valid JSON
    # config that cannot connect, which is worse than an explicit fallback.
    raise ValueError(f"Unsupported uTLS fingerprint `{value}`")


def _normalize_certificate_public_key_pins(value: Any) -> list[str]:
    raw_values = value if isinstance(value, list) else [value]
    values = [part.strip() for item in raw_values for part in str(item).split(",") if part.strip()]
    normalized: list[str] = []
    for raw in values:
        compact = raw.removeprefix("sha256/").removeprefix("SHA256/")
        hex_value = compact.replace(":", "").replace("-", "")
        if len(hex_value) == 64 and all(char in "0123456789abcdefABCDEF" for char in hex_value):
            decoded = bytes.fromhex(hex_value)
        else:
            padded = compact + "=" * (-len(compact) % 4)
            try:
                decoded = base64.b64decode(padded, validate=True)
            except Exception:
                try:
                    decoded = base64.urlsafe_b64decode(padded)
                except Exception as exc:
                    raise ValueError("Certificate public-key SHA-256 must be Base64 or 64-digit hex") from exc
        if len(decoded) != 32:
            raise ValueError("Certificate public-key SHA-256 must decode to 32 bytes")
        canonical = base64.b64encode(decoded).decode("ascii")
        if canonical not in normalized:
            normalized.append(canonical)
    return normalized


def _is_json_safe(value: Any) -> bool:
    if value is None or isinstance(value, (str, int, float, bool)):
        return True
    if isinstance(value, list):
        return all(_is_json_safe(item) for item in value)
    if isinstance(value, dict):
        return all(isinstance(key, str) and _is_json_safe(item) for key, item in value.items())
    return False


def _to_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}
