from __future__ import annotations

import base64
import binascii
from copy import deepcopy
import ipaddress
import json
from pathlib import Path
import re
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit
from urllib.request import url2pathname

from .models import Node
from .openvpn_import import looks_like_openvpn_config, parse_openvpn_config
from .wireguard_normalization import (
    _split_endpoint,
    normalize_ip_prefixes,
    normalize_singbox_wireguard_endpoints,
    normalize_wireguard_endpoint,
)

try:  # Optional at runtime, listed in requirements for bundled builds.
    import yaml
except Exception:  # pragma: no cover - dependency fallback
    yaml = None


class LinkParseError(ValueError):
    pass


MAX_IMPORT_BYTES = 8 * 1024 * 1024
MAX_IMPORT_LINES = 20_000
MAX_IMPORT_NODES = 20_000

_AMNEZIA_INT_KEYS = ("jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "itime")
_AMNEZIA_RANGE_KEYS = ("h1", "h2", "h3", "h4")
_AMNEZIA_STR_KEYS = ("i1", "i2", "i3", "i4", "i5", "j1", "j2", "j3")
_AWG_BYTES_TAG_RE = re.compile(r"<b\s+0x([0-9A-Fa-f]*)>")
_AWG_UINT_RANGE_RE = re.compile(r"\d+(?:\s*-\s*\d+)?")

# AmneziaWG 3.0/3.1 fields.  sing-box-extended represents these values in the
# endpoint's ``amnezia`` object using snake_case names.  Keeping the mapping
# here (rather than in the runtime builder) makes .conf, URI and native JSON
# imports follow the same validation path.
_AMNEZIA_AWG3_CONF_NAMES = {
    "contentpaddingaddition": "ContentPaddingAddition",
    "rekeyaftertime": "RekeyAfterTime",
    "rekeytimeout": "RekeyTimeout",
    "rejectaftertime": "RejectAfterTime",
    "keepalivetimeout": "KeepaliveTimeout",
    "maxhandshakeattempts": "MaxHandshakeAttempts",
}
_AMNEZIA_AWG3_DASH_NAMES = {
    "contentpaddingaddition": "content-padding-addition",
    "rekeyaftertime": "rekey-after-time",
    "rekeytimeout": "rekey-timeout",
    "rejectaftertime": "reject-after-time",
    "keepalivetimeout": "keepalive-timeout",
    "maxhandshakeattempts": "max-handshake-attempts",
}
_AMNEZIA_AWG3_RANGE_KEYS = {
    "contentpaddingaddition": "content_padding_addition",
    "rekeyaftertime": "rekey_after_time",
    "rekeytimeout": "rekey_timeout",
    "rejectaftertime": "reject_after_time",
    "keepalivetimeout": "keepalive_timeout",
    "maxhandshakeattempts": "max_handshake_attempts",
}
_AMNEZIA_JSON_RANGE_KEYS = tuple(_AMNEZIA_AWG3_RANGE_KEYS.values())
_AWG_UINT32_MAX = 0xFFFFFFFF
_AWG_RANGE_RE = re.compile(r"^(\d+)-(\d+)$")


def parse_links_text(
    text: str,
    *,
    allow_file_reference: bool = False,
) -> tuple[list[Node], list[str]]:
    if len(text.encode("utf-8", errors="replace")) > MAX_IMPORT_BYTES:
        return [], [f"Import data exceeds the {MAX_IMPORT_BYTES}-byte limit"]
    stripped = text.strip()
    source_path: Path | None = None
    try:
        file_reference = (
            _read_import_file_reference(stripped) if allow_file_reference else None
        )
    except LinkParseError as exc:
        return [], [str(exc)]
    if file_reference is not None:
        file_text, source_path = file_reference
        stripped = file_text.strip()
        text = file_text
    if stripped.startswith(("{", "[")):
        try:
            return _parse_json_nodes_text(stripped)
        except Exception as exc:
            if stripped.startswith("{"):
                json_lines = _try_parse_json_lines(stripped)
                if json_lines is not None:
                    return json_lines
                return [], [f"JSON: {exc}"]
    if _looks_like_clash_yaml(stripped):
        try:
            return _parse_clash_yaml_nodes_text(stripped)
        except Exception as exc:
            return [], [f"Clash YAML: {exc}"]
    if looks_like_openvpn_config(stripped):
        try:
            native, dns_servers, profile_name = parse_openvpn_config(
                stripped,
                source_path=source_path,
            )
            first_server = _first_mapping(native.get("servers"))
            outbound: dict[str, Any] = {
                "protocol": "openvpn",
                "singbox": native,
            }
            if dns_servers:
                outbound["_dns"] = dns_servers
            return [
                Node(
                    name=profile_name,
                    scheme="openvpn",
                    server=str(first_server.get("server") or ""),
                    port=int(first_server.get("server_port") or 0),
                    link=json.dumps(outbound, ensure_ascii=False, separators=(",", ":")),
                    outbound=outbound,
                )
            ], []
        except Exception as exc:
            return [], [f"OpenVPN: {exc}"]
    lowered = stripped.lower()
    if "[interface]" in lowered and "[peer]" in lowered:
        try:
            return [_parse_wireguard_config(stripped)], []
        except Exception as exc:
            return [], [f"Config: {exc}"]

    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if len(lines) > MAX_IMPORT_LINES:
        return [], [f"Import contains more than {MAX_IMPORT_LINES} non-empty lines"]
    nodes: list[Node] = []
    errors: list[str] = []

    for idx, line in enumerate(lines, start=1):
        try:
            node = parse_single(line)
            _apply_happ_server_metadata(node, line)
            nodes.append(node)
        except Exception as exc:
            errors.append(f"Line {idx}: {exc}")

    return nodes, errors


def _read_import_file_reference(text: str) -> tuple[str, Path] | None:
    """Accept paths copied from Explorer/QML instead of treating them as links."""
    if not text or "\n" in text:
        return None
    candidate_text = text.strip().strip('"')
    parsed = urlsplit(candidate_text)
    path_text = ""
    if len(candidate_text) >= 3 and candidate_text[1] == ":" and candidate_text[2] in {"\\", "/"}:
        path_text = candidate_text
    elif parsed.scheme.lower() == "file":
        # A `file://host/share` target makes Windows open an SMB session and
        # authenticate to `host`, so remote hosts are never followed.
        if parsed.netloc:
            return None
        path_text = url2pathname(unquote(parsed.path or ""))
    elif parsed.scheme == "":
        candidate = candidate_text
        if candidate.lower().endswith((".conf", ".ovpn", ".txt", ".json", ".yaml", ".yml")):
            path_text = candidate
    if not path_text or path_text.startswith(("\\\\", "//")):
        return None
    path = Path(path_text)
    if not path.is_file():
        return None
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise LinkParseError(f"Cannot inspect import file: {exc}") from exc
    if size > MAX_IMPORT_BYTES:
        raise LinkParseError(
            f"Import file exceeds the {MAX_IMPORT_BYTES}-byte limit"
        )
    return path.read_text(encoding="utf-8", errors="replace"), path


def parse_single(raw: str) -> Node:
    text = raw.strip()
    if not text:
        raise LinkParseError("empty input")

    if text.startswith("{"):
        return _parse_json_outbound(text)
    if text.startswith("["):
        try:
            nodes, errors = _parse_json_nodes_text(text)
        except Exception:
            nodes, errors = [], []
        if nodes:
            return nodes[0]
        if errors:
            raise LinkParseError("; ".join(errors[:3]))
    if text.startswith("["):
        return _parse_wireguard_config(text)

    scheme = urlsplit(text).scheme.lower()
    if scheme == "vless":
        return _parse_vless(text)
    if scheme == "vmess":
        return _parse_vmess(text)
    if scheme == "trojan":
        return _parse_trojan(text)
    if scheme == "ss":
        return _parse_shadowsocks(text)
    if scheme in {"socks", "socks5"}:
        return _parse_socks(text)
    if scheme in {"http", "https"}:
        return _parse_http_proxy(text)
    if scheme in {"naive", "naive+https", "naive+quic", "quic"}:
        return _parse_naive_link(text)
    if scheme in {"wireguard", "wg", "awg", "warp"}:
        return _parse_wireguard_like_link(text, scheme)
    if scheme in {"hysteria", "hy"}:
        return _parse_hysteria(text)
    if scheme in {"hysteria2", "hy2"}:
        return _parse_hysteria2(text)

    if scheme == "tuic":
        return _parse_tuic(text)
    if scheme in {"mieru", "mierus"}:
        return _parse_mieru(text)
    if scheme == "masque":
        return _parse_masque(text)
    if scheme == "anytls":
        return _parse_anytls(text)

    raise LinkParseError(f"unsupported scheme: {scheme or 'unknown'}")


def _first(query: dict[str, list[str]], key: str, default: str = "") -> str:
    values = query.get(key)
    if not values:
        return default
    return values[0]


def _get_param(params: dict[str, str], *keys: str, default: str = "") -> str:
    empty_value: str | None = None
    for key in keys:
        if key in params:
            value = params[key]
            if value:
                return value
            if empty_value is None:
                empty_value = value

    lower_params = {str(key).lower(): value for key, value in params.items()}
    for key in keys:
        lowered = str(key).lower()
        if lowered in lower_params:
            value = lower_params[lowered]
            if value:
                return value
            if empty_value is None:
                empty_value = value
    if empty_value is not None:
        return empty_value
    return default


def _decode_b64(data: str) -> str:
    data = data.strip()
    data += "=" * ((4 - len(data) % 4) % 4)
    try:
        raw = base64.urlsafe_b64decode(data.encode("utf-8"))
    except Exception:
        raw = base64.b64decode(data.encode("utf-8"))
    for encoding in ("utf-8", "cp1251", "gb18030", "latin-1"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


def _clean_name(name: str, fallback: str) -> str:
    value = unquote(name).partition("?")[0].strip()
    return value if value else fallback


def _decode_happ_description(value: str) -> str:
    raw = unquote(str(value or "")).strip()
    if not raw:
        return ""
    try:
        decoded = _decode_b64(raw).strip()
        if decoded and all(char.isprintable() or char.isspace() for char in decoded):
            return decoded[:30]
    except Exception:
        pass
    return raw[:30]


def _apply_happ_server_metadata(node: Node, raw: str) -> None:
    description = ""
    text = str(raw or "").strip()
    parsed = urlsplit(text)
    fragment = unquote(parsed.fragment or "")
    if "?" in fragment:
        title, _, query_text = fragment.partition("?")
        query = parse_qs(query_text, keep_blank_values=True)
        values = query.get("serverDescription") or query.get("serverdescription")
        if values:
            description = _decode_happ_description(values[0])
        if title.strip():
            node.name = title.strip()
    if not description and parsed.scheme.lower() == "vmess":
        try:
            payload = json.loads(_decode_b64(text.split("://", 1)[1]))
            description = _decode_happ_description(str(payload.get("serverDescription") or ""))
        except Exception:
            pass
    if not description and text.startswith("{"):
        try:
            payload = json.loads(text)
            meta = payload.get("meta") if isinstance(payload, dict) else None
            if isinstance(meta, dict):
                description = str(meta.get("serverDescription") or "").strip()[:30]
        except Exception:
            pass
    if description:
        node.description = description


def _json_name(payload: dict[str, Any], fallback: str) -> str:
    for key in ("remarks", "remark", "ps", "name", "tag"):
        value = str(payload.get(key) or "").strip()
        if value:
            return value
    return fallback


def _to_bool(value: str) -> bool:
    return str(value).lower() in {"1", "true", "yes", "on"}


def _camel_to_snake(value: str) -> str:
    result: list[str] = []
    for char in value:
        if char.isupper():
            result.append("_")
            result.append(char.lower())
        else:
            result.append(char)
    return "".join(result).lstrip("_")


def _build_stream_settings(params: dict[str, str], default_network: str = "tcp", default_security: str = "none") -> dict[str, Any]:
    network = (_get_param(params, "type", "net", default=default_network or "tcp") or "tcp").lower()
    network = {
        "gun": "grpc",
        "http-upgrade": "httpupgrade",
        "splithttp": "xhttp",
        "split-http": "xhttp",
    }.get(network, network)
    security = (_get_param(params, "security", "tls", default=default_security or "none") or "none").lower()
    if security == "none" and _get_param(params, "tls") == "tls":
        security = "tls"

    stream: dict[str, Any] = {
        "network": network,
        "security": security,
    }

    host = _get_param(params, "host")
    path = _get_param(params, "path")

    if network == "ws":
        ws_settings: dict[str, Any] = {}
        if path:
            ws_settings["path"] = path
        if host:
            ws_settings["headers"] = {"Host": host}
        early_data = _get_param(params, "ed", "maxEarlyData", "max_early_data")
        if early_data:
            try:
                ws_settings["maxEarlyData"] = int(early_data)
            except (TypeError, ValueError):
                ws_settings["maxEarlyData"] = early_data
        early_data_header = _get_param(
            params,
            "eh",
            "earlyDataHeaderName",
            "early_data_header_name",
        )
        if early_data_header:
            ws_settings["earlyDataHeaderName"] = early_data_header
        stream["wsSettings"] = ws_settings
    elif network in {"http", "h2"}:
        http_settings: dict[str, Any] = {}
        if host:
            http_settings["host"] = [h.strip() for h in host.split(",") if h.strip()]
        if path:
            http_settings["path"] = path
        for source_key, target_key in (
            ("method", "method"),
            ("idleTimeout", "idleTimeout"),
            ("idle_timeout", "idleTimeout"),
            ("pingTimeout", "pingTimeout"),
            ("ping_timeout", "pingTimeout"),
        ):
            value = _get_param(params, source_key)
            if value:
                http_settings[target_key] = value
        stream["httpSettings"] = http_settings
    elif network == "grpc":
        grpc_settings: dict[str, Any] = {}
        service_name = _get_param(params, "serviceName", "service_name")
        if service_name:
            grpc_settings["serviceName"] = service_name
        authority = _get_param(params, "authority")
        if authority:
            grpc_settings["authority"] = authority
        mode = _get_param(params, "mode")
        if mode == "multi":
            grpc_settings["multiMode"] = True
        for source_key, target_key in (
            ("idleTimeout", "idleTimeout"),
            ("idle_timeout", "idleTimeout"),
            ("pingTimeout", "pingTimeout"),
            ("ping_timeout", "pingTimeout"),
        ):
            value = _get_param(params, source_key)
            if value:
                grpc_settings[target_key] = value
        permit_without_stream = _get_param(
            params,
            "permitWithoutStream",
            "permit_without_stream",
        )
        if permit_without_stream:
            grpc_settings["permitWithoutStream"] = _to_bool(permit_without_stream)
        stream["grpcSettings"] = grpc_settings
    elif network == "xhttp":
        xhttp_settings: dict[str, Any] = {}
        if path:
            xhttp_settings["path"] = path
        if host:
            xhttp_settings["host"] = host
        mode = _get_param(params, "mode")
        if mode in {"auto", "packet-up", "stream-up", "stream-one"}:
            xhttp_settings["mode"] = mode
        extra = _get_param(params, "extra")
        if extra:
            try:
                decoded_extra = json.loads(extra)
            except Exception:
                decoded_extra = None
            if isinstance(decoded_extra, dict):
                xhttp_settings["extra"] = decoded_extra
        for key in (
            "scMaxEachPostBytes",
            "scMaxBufferedPosts",
            "scMinPostsIntervalMs",
            "xPaddingBytes",
            "padding",
            "downloadSettings",
            "download_settings",
            "noGRPCHeader",
            "noSSEHeader",
            "scStreamUpServerSecs",
            "serverMaxHeaderBytes",
            "trustedXForwardedFor",
            "xmux",
            "xPaddingObfsMode",
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
        ):
            value = _get_param(params, key)
            if value:
                if key in {"downloadSettings", "download_settings", "xmux"}:
                    try:
                        xhttp_settings[key] = json.loads(unquote(value))
                    except Exception:
                        xhttp_settings[key] = value
                else:
                    xhttp_settings[key] = value
        stream["xhttpSettings"] = xhttp_settings
    elif network == "httpupgrade":
        httpupgrade_settings: dict[str, Any] = {}
        if path:
            httpupgrade_settings["path"] = path
        if host:
            httpupgrade_settings["host"] = host
        early_data = _get_param(params, "ed")
        if early_data:
            httpupgrade_settings["ed"] = early_data
        stream["httpupgradeSettings"] = httpupgrade_settings
    elif network == "quic":
        stream["quicSettings"] = {
            "security": _get_param(params, "quicSecurity", "quic_security") or "none",
            "key": _get_param(params, "key") or "",
            "header": {"type": _get_param(params, "headerType", "header_type") or "none"},
        }
    elif network in {"kcp", "mkcp"}:
        kcp_settings: dict[str, Any] = {
            "header": {"type": _get_param(params, "headerType", "header_type") or "none"},
        }
        for key in (
            "mtu",
            "tti",
            "uplinkCapacity",
            "downlinkCapacity",
            "readBufferSize",
            "writeBufferSize",
            "seed",
            "congestion",
        ):
            value = _get_param(params, key, _camel_to_snake(key))
            if not value:
                continue
            if key in {"mtu", "tti", "uplinkCapacity", "downlinkCapacity", "readBufferSize", "writeBufferSize"}:
                try:
                    kcp_settings[key] = int(value)
                except Exception:
                    kcp_settings[key] = value
            elif key == "congestion":
                kcp_settings[key] = _to_bool(value)
            else:
                kcp_settings[key] = value
        stream["network"] = "kcp"
        stream["kcpSettings"] = kcp_settings

    if security == "tls":
        tls_settings: dict[str, Any] = {}
        sni = _get_param(params, "sni", "serverName", "server_name")
        if sni:
            tls_settings["serverName"] = sni
        alpn = _get_param(params, "alpn")
        if alpn:
            tls_settings["alpn"] = [item.strip() for item in alpn.split(",") if item.strip()]
        fp = _get_param(params, "fp", "fingerprint")
        if fp:
            tls_settings["fingerprint"] = fp
        allow_insecure = _get_param(params, "allowInsecure", "allow_insecure", "insecure")
        if allow_insecure:
            tls_settings["allowInsecure"] = _to_bool(allow_insecure)
        cert_sha = _get_param(params, "pcs", "pinnedPeerCertSha256", "certSha")
        if cert_sha:
            tls_settings["pinnedPeerCertSha256"] = cert_sha
        ech = _get_param(params, "ech", "echConfigList")
        if ech:
            tls_settings["echConfigList"] = ech
            tls_settings["echForceQuery"] = "full"
        verify_names = _get_param(params, "vcn", "verifyPeerCertByName")
        if verify_names:
            tls_settings["verifyPeerCertByName"] = ",".join(
                item.strip() for item in verify_names.split(",") if item.strip()
            )
        for aliases, target_key in (
            (("disableSNI", "disable_sni"), "disableSNI"),
            (("minVersion", "min_version"), "minVersion"),
            (("maxVersion", "max_version"), "maxVersion"),
            (("cipherSuites", "cipher_suites"), "cipherSuites"),
            (("curvePreferences", "curve_preferences"), "curvePreferences"),
            (("handshakeTimeout", "handshake_timeout"), "handshakeTimeout"),
        ):
            value = _get_param(params, *aliases)
            if value:
                tls_settings[target_key] = (
                    [item.strip() for item in value.split(",") if item.strip()]
                    if target_key in {"cipherSuites", "curvePreferences"}
                    else (_to_bool(value) if target_key == "disableSNI" else value)
                )
        stream["tlsSettings"] = tls_settings
    elif security == "reality":
        reality_settings: dict[str, Any] = {}
        sni = _get_param(params, "sni", "serverName", "server_name")
        if sni:
            reality_settings["serverName"] = sni
        fp = _get_param(params, "fp", "fingerprint")
        if fp:
            reality_settings["fingerprint"] = fp
        pbk = _get_param(params, "pbk", "publicKey", "public_key", "password")
        if pbk:
            reality_settings["publicKey"] = pbk
        sid = _get_param(params, "sid", "shortId", "short_id")
        if sid:
            reality_settings["shortId"] = sid
        spx = _get_param(params, "spx", "spiderX", "spider_x")
        if spx:
            reality_settings["spiderX"] = spx
        pqv = _get_param(params, "pqv", "mldsa65Verify", "mldsa65_verify")
        if pqv:
            reality_settings["mldsa65Verify"] = pqv
        reality_settings["show"] = False
        stream["realitySettings"] = reality_settings

    finalmask = _get_param(params, "fm", "finalmask")
    if finalmask:
        try:
            stream["finalmask"] = json.loads(finalmask)
        except Exception:
            stream["finalmask"] = finalmask

    return stream


def _parse_vless(link: str) -> Node:
    parsed = urlsplit(link)
    query = {k: v for k, v in parse_qs(parsed.query, keep_blank_values=True).items()}
    params = {k: _first(query, k) for k in query}

    user_id = unquote(parsed.username or "")
    server = parsed.hostname or ""
    port = parsed.port or 443

    if not user_id or not server:
        raise LinkParseError("invalid vless link")

    user: dict[str, Any] = {
        "id": user_id,
        "encryption": _get_param(params, "encryption") or "none",
    }
    flow = _get_param(params, "flow")
    if flow:
        user["flow"] = flow

    stream_settings = _build_stream_settings(params, default_network="tcp", default_security=params.get("security", "none"))
    outbound = {
        "protocol": "vless",
        "settings": {
            "vnext": [
                {
                    "address": server,
                    "port": port,
                    "users": [user],
                }
            ]
        },
        "streamSettings": stream_settings,
    }
    if str(stream_settings.get("network") or "").lower() == "xhttp":
        outbound["mux"] = {"enabled": False, "concurrency": -1}

    name = _clean_name(parsed.fragment, f"vless-{server}:{port}")
    return Node(
        name=name,
        scheme="vless",
        server=server,
        port=port,
        link=link,
        outbound=outbound,
    )


def repair_node_outbound_from_link(node: Node) -> bool:
    link = str(node.link or "").strip()
    changed = False
    if not link:
        return _repair_legacy_direct_masque_shape(node)
    clash_payload: dict[str, Any] | None = None
    try:
        if link.startswith("{"):
            decoded = json.loads(link)
            if _is_clash_proxy_payload(decoded):
                clash_payload = decoded
        reparsed = (
            _parse_clash_proxy_payload(clash_payload)
            if clash_payload is not None
            else parse_single(link)
        )
    except Exception:
        return _repair_legacy_direct_masque_shape(node)
    if clash_payload is not None:
        reparsed_changed = (
            reparsed.outbound != node.outbound
            or reparsed.link != node.link
            or reparsed.scheme != node.scheme
        )
        if reparsed_changed:
            node.outbound = reparsed.outbound
            node.link = reparsed.link
            node.scheme = reparsed.scheme
            changed = True
    else:
        if reparsed.outbound != node.outbound:
            node.outbound = reparsed.outbound
            changed = True
    if not node.scheme:
        node.scheme = reparsed.scheme
        changed = True
    if not node.server:
        node.server = reparsed.server
        changed = True
    if node.port <= 0:
        node.port = reparsed.port
        changed = True
    return _repair_legacy_direct_masque_shape(node) or changed


def _repair_legacy_direct_masque_shape(node: Node) -> bool:
    """Move old Clash MASQUE credentials out of the registration profile.

    Early builds stored the client private key under ``profile.private_key``.
    sing-box extended interprets that as a Cloudflare registration profile and
    never initializes the imported usque tunnel.  The remaining endpoint data
    is already present in the node, so it can be migrated without reimporting
    or contacting the subscription server.
    """
    outbound = node.outbound if isinstance(node.outbound, dict) else {}
    native = (
        outbound.get("singbox")
        if isinstance(outbound.get("singbox"), dict)
        else None
    )
    if not isinstance(native, dict):
        return False
    protocol = str(
        outbound.get("protocol") or node.scheme or native.get("type") or ""
    ).strip().lower()
    if (
        protocol != "masque"
        and str(native.get("type") or "").strip().lower() != "masque"
    ):
        return False

    profile = native.get("profile") if isinstance(native.get("profile"), dict) else {}
    profile_private_key = str(profile.get("private_key") or "").strip()
    private_key = str(native.get("private_key") or profile_private_key).strip()
    public_key = str(native.get("public_key") or "").strip()
    changed = False
    address = native.get("tunnel_address")
    legacy_address = native.get("address")
    if not address and isinstance(legacy_address, list):
        address = legacy_address
        native["tunnel_address"] = address
        native.pop("address", None)
        changed = True
    server = str(native.get("server") or node.server or "").strip()
    if not (private_key and public_key and address and server):
        return False

    if native.get("private_key") != private_key:
        native["private_key"] = private_key
        changed = True
    if str(native.get("server") or "").strip() != server:
        native["server"] = server
        changed = True
    if not native.get("server_port") and int(node.port or 0) > 0:
        native["server_port"] = int(node.port)
        changed = True

    normalized_profile = dict(profile)
    if "private_key" in normalized_profile:
        normalized_profile.pop("private_key", None)
        changed = True
    if normalized_profile.get("detour") != "direct":
        normalized_profile["detour"] = "direct"
        changed = True
    if native.get("profile") != normalized_profile:
        native["profile"] = normalized_profile
        changed = True
    return changed


def _is_clash_proxy_payload(payload: Any) -> bool:
    if not isinstance(payload, dict):
        return False
    kind = str(payload.get("type") or "").strip().lower()
    if kind not in {
        "vless", "vmess", "trojan", "ss", "shadowsocks",
        "hy", "hysteria", "hy2", "hysteria2", "tuic", "wireguard",
        "awg", "amneziawg", "amnezia-wg", "masque", "naive", "mieru",
        "anytls", "snell", "socks", "socks5", "http", "https",
    }:
        return False
    return (
        (
            "server" in payload
            and any(key in payload for key in ("port", "server-port", "server-ports", "server_ports", "ports"))
            and "server_port" not in payload
        )
        or "private-key" in payload
        or "public-key" in payload
        or "amnezia-wg-option" in payload
    )


def normalize_node_outbound(node: Node | None) -> bool:
    if node is None or not isinstance(node.outbound, dict):
        return False
    return normalize_outbound_for_runtime(node.outbound, node.server)


def normalize_outbound_for_runtime(outbound: dict[str, Any], server: str = "") -> bool:
    changed = False
    stream_settings = outbound.get("streamSettings")
    if not isinstance(stream_settings, dict):
        return False

    if str(stream_settings.get("network") or "").strip().lower() == "xhttp":
        mux = outbound.get("mux")
        if not isinstance(mux, dict):
            outbound["mux"] = {"enabled": False, "concurrency": -1}
            changed = True
        else:
            if mux.get("enabled") is not False:
                mux["enabled"] = False
                changed = True
            if mux.get("concurrency") != -1:
                mux["concurrency"] = -1
                changed = True

    security = str(stream_settings.get("security") or "").strip().lower()
    if security == "tls":
        tls_settings = stream_settings.get("tlsSettings")
        if not isinstance(tls_settings, dict):
            tls_settings = {}
            stream_settings["tlsSettings"] = tls_settings
            changed = True
        if not str(tls_settings.get("serverName") or "").strip():
            inferred = _infer_transport_host(stream_settings) or server
            if inferred:
                tls_settings["serverName"] = inferred
                changed = True
        if tls_settings.get("echConfigList") and not tls_settings.get("echForceQuery"):
            tls_settings["echForceQuery"] = "full"
            changed = True
    elif security == "reality":
        reality_settings = stream_settings.get("realitySettings")
        if not isinstance(reality_settings, dict):
            reality_settings = {}
            stream_settings["realitySettings"] = reality_settings
            changed = True
        if reality_settings.get("show") is not False:
            reality_settings["show"] = False
            changed = True
    return changed


def _infer_transport_host(stream_settings: dict[str, Any]) -> str:
    network = str(stream_settings.get("network") or "").strip().lower()
    if network == "ws":
        headers = (stream_settings.get("wsSettings") or {}).get("headers") if isinstance(stream_settings.get("wsSettings"), dict) else {}
        if isinstance(headers, dict):
            return str(headers.get("Host") or headers.get("host") or "").split(",")[0].strip()
    if network in {"http", "h2"}:
        http_settings = stream_settings.get("httpSettings")
        if isinstance(http_settings, dict):
            hosts = http_settings.get("host")
            if isinstance(hosts, list) and hosts:
                return str(hosts[0]).strip()
            if isinstance(hosts, str):
                return hosts.split(",")[0].strip()
    if network == "grpc":
        grpc_settings = stream_settings.get("grpcSettings")
        if isinstance(grpc_settings, dict):
            return str(grpc_settings.get("authority") or "").strip()
    return ""


def _validate_wireguard_endpoint(node: Node, endpoint: dict[str, Any]) -> str | None:
    endpoint_type = str(endpoint.get("type") or "").strip().lower()
    amnezia = endpoint.get("amnezia")
    if endpoint_type not in {"wireguard", "awg"}:
        if isinstance(amnezia, dict) and amnezia:
            return _validate_amnezia_settings(node, amnezia)
        return None

    node_label = str(node.name or node.server or "WireGuard").strip()
    if not str(endpoint.get("private_key") or "").strip():
        return f"Сервер {node_label} не содержит private_key для WireGuard/AWG."
    addresses = endpoint.get("address")
    if not isinstance(addresses, list) or not any(str(item).strip() for item in addresses):
        return f"Сервер {node_label} не содержит адрес интерфейса WireGuard/AWG."
    peers = endpoint.get("peers")
    if not isinstance(peers, list) or not peers:
        return f"Сервер {node_label} не содержит peers для WireGuard/AWG."
    for peer in peers:
        if not isinstance(peer, dict) or not str(peer.get("public_key") or "").strip():
            return f"Сервер {node_label}: у peer отсутствует public_key."
        peer_address = str(peer.get("address") or "").strip()
        try:
            peer_port = int(peer.get("port") or 0)
        except (TypeError, ValueError):
            peer_port = 0
        if not peer_address or not 0 < peer_port <= 65535:
            return f"Сервер {node_label}: у peer отсутствует корректный address или port."
    if isinstance(amnezia, dict) and amnezia:
        return _validate_amnezia_settings(node, amnezia)
    return None


def _validate_amnezia_settings(node: Node, amnezia: dict[str, Any]) -> str | None:
    node_label = str(node.name or node.server or "AWG").strip()
    for key in _AMNEZIA_INT_KEYS:
        value = amnezia.get(key)
        if value is not None and type(value) is not int:
            return f"Сервер {node_label}: параметр AWG `{key}` должен быть целым числом."
    for key in _AMNEZIA_RANGE_KEYS:
        value = amnezia.get(key)
        if value is None or type(value) is int:
            continue
        if not isinstance(value, str) or not _AWG_UINT_RANGE_RE.fullmatch(value.strip()):
            return f"Сервер {node_label}: параметр AWG `{key}` должен быть числом или диапазоном."
    for key in _AMNEZIA_STR_KEYS:
        value = amnezia.get(key)
        if value is None:
            continue
        if not isinstance(value, str):
            return f"Сервер {node_label}: параметр AWG `{key}` должен быть строкой."
        for match in _AWG_BYTES_TAG_RE.finditer(value):
            if len(match.group(1)) % 2:
                return f"AWG: нечётное число hex-символов в {key.upper()}."
    header_key = amnezia.get("header_protection_key")
    if header_key is not None:
        try:
            _validate_awg3_header_key(str(header_key))
        except LinkParseError as exc:
            return f"Сервер {node_label}: {exc}"
        for key in ("s1", "s2", "s3", "s4"):
            value = amnezia.get(key)
            if type(value) is not int or value < 12:
                return (
                    f"Сервер {node_label}: AWG 3.0 с HeaderProtectionKey требует "
                    f"{key.upper()} не меньше 12."
                )
    for key in _AMNEZIA_JSON_RANGE_KEYS:
        value = amnezia.get(key)
        if value is None:
            continue
        if isinstance(value, bool) or not isinstance(value, (int, str)):
            return (
                f"Сервер {node_label}: параметр AWG `{key}` должен быть числом "
                "или диапазоном A-B."
            )
        try:
            _validate_awg3_range(str(value), key)
        except LinkParseError as exc:
            return f"Сервер {node_label}: {exc}"
    jmin = amnezia.get("jmin")
    jmax = amnezia.get("jmax")
    if type(jmin) is int and type(jmax) is int and jmin > jmax:
        return f"Сервер {node_label}: параметр AWG `jmin` не может быть больше `jmax`."
    return None


def validate_node_outbound(node: Node) -> str | None:
    name_l = str(node.name or "").strip().lower()
    if str(node.scheme or "").strip().lower() in {
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
        "openvpn",
        "naive",
    } and (not str(node.server or "").strip() or int(node.port or 0) <= 0):
        return f"Сервер {node.name or node.scheme} пропущен: нет адреса или порта."

    if str(node.server or "").strip() in {"0.0.0.0", "::"} and int(node.port or 0) <= 1:
        if (
            "приложение не поддерживается" in name_l
            or "установите другое приложение" in name_l
            or "happ" in name_l
            or "unsupported" in name_l
        ):
            return "Провайдер подписки отдал заглушку «приложение не поддерживается». Lumen попробует совместимые профили клиента; если ошибка повторяется, нужен формат sing-box/SFA или Clash."
        label = str(node.name or "").strip()
        if label:
            return f"Провайдер подписки вернул служебное сообщение: {label}"
        return "Сервер-заглушка 0.0.0.0:1 пропущен."

    outbound = node.outbound if isinstance(node.outbound, dict) else {}
    native_outbound = (
        outbound.get("singbox")
        if isinstance(outbound.get("singbox"), dict)
        else outbound
    )
    if str(node.scheme or outbound.get("protocol") or "").strip().lower() == "openvpn":
        servers = native_outbound.get("servers")
        if not isinstance(servers, list) or not servers:
            return "OpenVPN-профиль не содержит ни одного remote-сервера."
        for server_options in servers:
            if not isinstance(server_options, dict):
                return "OpenVPN servers должен быть списком объектов."
            try:
                remote_port = int(server_options.get("server_port") or 0)
            except (TypeError, ValueError):
                remote_port = 0
            if not str(server_options.get("server") or "").strip() or remote_port <= 0:
                return "OpenVPN remote должен содержать адрес и порт."
        if str(native_outbound.get("proto") or "").strip().lower() not in {"udp", "tcp"}:
            return "OpenVPN transport должен быть udp или tcp."
        tls_openvpn = native_outbound.get("tls") if isinstance(native_outbound.get("tls"), dict) else {}
        if not str(tls_openvpn.get("ca") or tls_openvpn.get("ca_path") or "").strip():
            return "OpenVPN-профиль не содержит CA-сертификат."
        has_tls_auth = bool(native_outbound.get("tls_auth") or native_outbound.get("tls_auth_path"))
        has_tls_crypt = bool(native_outbound.get("tls_crypt") or native_outbound.get("tls_crypt_path"))
        if has_tls_auth and has_tls_crypt:
            return "OpenVPN TLS Auth и TLS Crypt нельзя включать одновременно."
        if native_outbound.get("tls_crypt_v2") and not has_tls_crypt:
            return "OpenVPN TLS Crypt v2 включён без ключа TLS Crypt."
    endpoint_problem = _validate_wireguard_endpoint(node, native_outbound)
    if endpoint_problem:
        return endpoint_problem
    stream_settings = outbound.get("streamSettings") if isinstance(outbound, dict) else None
    if not isinstance(stream_settings, dict):
        return None

    security = str(stream_settings.get("security") or "").strip().lower()
    if security != "reality":
        return None

    reality_settings = stream_settings.get("realitySettings")
    if not isinstance(reality_settings, dict):
        reality_settings = {}

    public_key = str(reality_settings.get("publicKey") or "").strip()
    node_name = str(node.name or node.server or "\u0431\u0435\u0437\u044b\u043c\u044f\u043d\u043d\u044b\u0439 \u0441\u0435\u0440\u0432\u0435\u0440").strip()
    if not public_key:
        return (
            f"\u0421\u0435\u0440\u0432\u0435\u0440 {node_name} \u043d\u0435 \u043c\u043e\u0436\u0435\u0442 \u0431\u044b\u0442\u044c \u0437\u0430\u043f\u0443\u0449\u0435\u043d: \u0434\u043b\u044f REALITY \u043e\u0431\u044f\u0437\u0430\u0442\u0435\u043b\u0435\u043d publicKey "
            "(\u043f\u0430\u0440\u0430\u043c\u0435\u0442\u0440 pbk \u0432 VLESS-\u0441\u0441\u044b\u043b\u043a\u0435), \u043d\u043e \u0432 \u044d\u0442\u043e\u0439 \u0441\u0441\u044b\u043b\u043a\u0435 \u043e\u043d \u043f\u0443\u0441\u0442\u043e\u0439 \u0438\u043b\u0438 \u043e\u0442\u0441\u0443\u0442\u0441\u0442\u0432\u0443\u0435\u0442."
        )

    short_id = str(reality_settings.get("shortId") or "").strip()
    if short_id and (len(short_id) > 16 or len(short_id) % 2 != 0 or any(ch not in "0123456789abcdefABCDEF" for ch in short_id)):
        return (
            f"\u0421\u0435\u0440\u0432\u0435\u0440 {node_name} \u043d\u0435 \u043c\u043e\u0436\u0435\u0442 \u0431\u044b\u0442\u044c \u0437\u0430\u043f\u0443\u0449\u0435\u043d: shortId \u0434\u043b\u044f REALITY \u0434\u043e\u043b\u0436\u0435\u043d \u0431\u044b\u0442\u044c hex-\u0441\u0442\u0440\u043e\u043a\u043e\u0439 "
            "\u0447\u0435\u0442\u043d\u043e\u0439 \u0434\u043b\u0438\u043d\u044b \u0434\u043e 16 \u0441\u0438\u043c\u0432\u043e\u043b\u043e\u0432. \u041f\u0440\u043e\u0432\u0435\u0440\u044c\u0442\u0435 \u043f\u0430\u0440\u0430\u043c\u0435\u0442\u0440 sid \u0432 \u0441\u0441\u044b\u043b\u043a\u0435."
        )
    return None


def _parse_vmess(link: str) -> Node:
    encoded = link[len("vmess://") :]
    payload = json.loads(_decode_b64(encoded))

    server = str(payload.get("add") or "")
    port = int(payload.get("port") or 443)
    user_id = str(payload.get("id") or "")
    if not server or not user_id:
        raise LinkParseError("invalid vmess link")

    security = str(payload.get("tls") or "none").lower()
    params = {
        "net": str(payload.get("net") or "tcp"),
        "type": str(payload.get("net") or "tcp"),
        "security": "tls" if security in {"tls", "reality"} else "none",
        "host": str(payload.get("host") or ""),
        "path": str(payload.get("path") or ""),
        "sni": str(payload.get("sni") or payload.get("host") or ""),
        "alpn": str(payload.get("alpn") or ""),
        "fp": str(payload.get("fp") or ""),
        "serviceName": str(payload.get("serviceName") or ""),
    }

    outbound = {
        "protocol": "vmess",
        "settings": {
            "vnext": [
                {
                    "address": server,
                    "port": port,
                    "users": [
                        {
                            "id": user_id,
                            "alterId": int(payload.get("aid") or 0),
                            "security": str(payload.get("scy") or "auto"),
                        }
                    ],
                }
            ]
        },
        "streamSettings": _build_stream_settings(params, default_network=params["net"], default_security=params["security"]),
    }

    name = _clean_name(str(payload.get("ps") or ""), f"vmess-{server}:{port}")
    return Node(
        name=name,
        scheme="vmess",
        server=server,
        port=port,
        link=link,
        outbound=outbound,
    )


def _parse_trojan(link: str) -> Node:
    parsed = urlsplit(link)
    query = parse_qs(parsed.query, keep_blank_values=True)
    params = {k: _first(query, k) for k in query}

    password = unquote(parsed.username or "")
    server = parsed.hostname or ""
    port = parsed.port or 443
    if not password or not server:
        raise LinkParseError("invalid trojan link")

    outbound = {
        "protocol": "trojan",
        "settings": {
            "servers": [
                {
                    "address": server,
                    "port": port,
                    "password": password,
                }
            ]
        },
        "streamSettings": _build_stream_settings(params, default_network="tcp", default_security=params.get("security", "tls")),
    }

    name = _clean_name(parsed.fragment, f"trojan-{server}:{port}")
    return Node(
        name=name,
        scheme="trojan",
        server=server,
        port=port,
        link=link,
        outbound=outbound,
    )


def _parse_shadowsocks(link: str) -> Node:
    parsed = urlsplit(link)
    query = parse_qs(parsed.query, keep_blank_values=True)

    method = ""
    password = ""
    server = parsed.hostname or ""
    port = parsed.port or 8388

    if parsed.username and parsed.password:
        method = unquote(parsed.username)
        password = unquote(parsed.password)
    elif parsed.username and not parsed.password:
        decoded = _decode_b64(parsed.username)
        if ":" not in decoded:
            raise LinkParseError("invalid shadowsocks credentials")
        method, password = decoded.split(":", 1)
    else:
        # urlsplit stops the netloc at the first `/`, which is a valid base64
        # symbol, and the decoded credentials may contain `?`, so isolate the
        # blob and split it without going through urlsplit again.
        body = link.split("://", 1)[-1].split("#", 1)[0].split("?", 1)[0]
        try:
            decoded = _decode_b64(body)
        except Exception as exc:
            raise LinkParseError("invalid shadowsocks link") from exc
        credentials, separator, host_port = decoded.rpartition("@")
        host, port_separator, port_text = host_port.rpartition(":")
        if not port_separator or not port_text.isdigit():
            host, port_text = host_port, "8388"
        host = host.strip().strip("[]").lower()
        if not separator or ":" not in credentials or not host:
            raise LinkParseError("invalid shadowsocks link")
        method, password = credentials.split(":", 1)
        method = unquote(method)
        password = unquote(password)
        server = host
        port = int(port_text)

    if not method or not password or not server:
        raise LinkParseError("invalid shadowsocks link")

    plugin = _first(query, "plugin")
    outbound_server: dict[str, Any] = {
        "address": server,
        "port": port,
        "method": method,
        "password": password,
    }
    if plugin:
        # SIP003 stores the plugin executable and its options in one query
        # value (``v2ray-plugin;tls;host=...``), while sing-box models them as
        # two fields.  Passing the complete value as the executable name makes
        # an otherwise valid Shadowsocks server fail only when it is dialled.
        plugin_name, separator, plugin_opts = plugin.partition(";")
        outbound_server["plugin"] = plugin_name
        if separator and plugin_opts:
            outbound_server["plugin_opts"] = plugin_opts

    outbound = {
        "protocol": "shadowsocks",
        "settings": {
            "servers": [outbound_server],
        },
    }

    name = _clean_name(parsed.fragment, f"ss-{server}:{port}")
    return Node(
        name=name,
        scheme="ss",
        server=server,
        port=port,
        link=link,
        outbound=outbound,
    )


def _parse_socks(link: str) -> Node:
    parsed = urlsplit(link)
    server = parsed.hostname or ""
    port = parsed.port or 1080
    if not server:
        raise LinkParseError("invalid socks link")

    user = unquote(parsed.username or "")
    password = unquote(parsed.password or "")

    server_item: dict[str, Any] = {
        "address": server,
        "port": port,
    }
    if user:
        server_item["users"] = [{"user": user, "pass": password}]

    outbound = {
        "protocol": "socks",
        "settings": {"servers": [server_item]},
    }

    name = _clean_name(parsed.fragment, f"socks-{server}:{port}")
    return Node(
        name=name,
        scheme="socks",
        server=server,
        port=port,
        link=link,
        outbound=outbound,
    )


def _parse_http_proxy(link: str) -> Node:
    parsed = urlsplit(link)
    server = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if not server:
        raise LinkParseError("invalid http proxy link")

    user = unquote(parsed.username or "")
    password = unquote(parsed.password or "")

    server_item: dict[str, Any] = {
        "address": server,
        "port": port,
    }
    if user:
        server_item["users"] = [{"user": user, "pass": password}]

    outbound = {
        "protocol": "http",
        "settings": {"servers": [server_item]},
    }
    if parsed.scheme.lower() == "https":
        outbound["streamSettings"] = {
            "network": "tcp",
            "security": "tls",
            "tlsSettings": {"serverName": server},
        }

    name = _clean_name(parsed.fragment, f"http-{server}:{port}")
    return Node(
        name=name,
        scheme="http",
        server=server,
        port=port,
        link=link,
        outbound=outbound,
    )


def _parse_json_nodes_text(text: str) -> tuple[list[Node], list[str]]:
    payload = json.loads(text)
    return _parse_json_nodes_payload(payload)


def _try_parse_json_lines(text: str) -> tuple[list[Node], list[str]] | None:
    """Parse subscriptions that contain one complete JSON node per line.

    Some Clash/AWG providers concatenate standalone proxy objects instead of
    wrapping them in a JSON array.  Only use this fallback when every non-empty
    line is valid JSON, so a malformed pretty-printed document still reports
    the original whole-document JSON error.
    """
    lines = [
        (line_number, line.strip())
        for line_number, line in enumerate(text.splitlines(), start=1)
        if line.strip()
    ]
    if len(lines) <= 1 or len(lines) > MAX_IMPORT_LINES:
        return None

    payloads: list[tuple[int, Any]] = []
    for line_number, line in lines:
        try:
            payloads.append((line_number, json.loads(line)))
        except json.JSONDecodeError:
            return None

    nodes: list[Node] = []
    errors: list[str] = []
    for line_number, payload in payloads:
        try:
            parsed_nodes, parsed_errors = _parse_json_nodes_payload(payload)
            nodes.extend(parsed_nodes)
            errors.extend(f"JSON line {line_number}: {error}" for error in parsed_errors)
        except Exception as exc:
            errors.append(f"JSON line {line_number}: {exc}")
        if len(nodes) > MAX_IMPORT_NODES:
            return [], [f"JSON contains more than {MAX_IMPORT_NODES} nodes"]
    return nodes, errors


def _parse_json_nodes_payload(payload: Any) -> tuple[list[Node], list[str]]:
    nodes: list[Node] = []
    errors: list[str] = []

    if isinstance(payload, dict) and "proxy" in payload and not any(
        key in payload for key in ("type", "protocol", "outbounds", "endpoints", "proxies")
    ):
        return _parse_naiveproxy_config_payload(payload)

    if isinstance(payload, list):
        items = payload
    elif isinstance(payload, dict):
        links = payload.get("links")
        if isinstance(links, list):
            items = links
        elif isinstance(payload.get("configs"), list):
            items = payload["configs"]
        elif isinstance(payload.get("nodes"), list):
            items = payload["nodes"]
        elif isinstance(payload.get("items"), list):
            items = payload["items"]
        elif _is_singbox_wireguard_config_payload(payload) or _is_singbox_openvpn_config_payload(payload):
            items = [payload]
        elif isinstance(payload.get("providers"), list) and isinstance(payload.get("outbounds"), list):
            items = [payload]
        elif _is_xray_auto_config_payload(payload):
            items = [payload]
        elif isinstance(payload.get("outbounds"), list):
            items = _json_proxy_outbounds(payload["outbounds"])
        elif _json_payload_can_be_node(payload):
            items = [payload]
        else:
            raise LinkParseError("JSON must contain links, configs, nodes, items, protocol, type, endpoints, or outbounds")
    else:
        raise LinkParseError("JSON subscription must be an object or an array")

    if len(items) > MAX_IMPORT_NODES:
        raise LinkParseError(f"JSON contains more than {MAX_IMPORT_NODES} nodes")

    for idx, item in enumerate(items, start=1):
        try:
            if isinstance(item, str):
                nodes.append(parse_single(item))
            elif isinstance(item, dict):
                nodes.append(_parse_json_outbound_payload(item))
            else:
                raise LinkParseError(f"unsupported JSON item type: {type(item).__name__}")
        except Exception as exc:
            errors.append(f"JSON item {idx}: {exc}")

    return nodes, errors


def _json_proxy_outbounds(outbounds: list[Any]) -> list[dict[str, Any]]:
    supported = {
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
        "hy",
        "hy2",
        "tuic",
        "mieru",
        "masque",
        "openvpn",
        "naive",
    }
    auto_kinds = {"selector", "urltest", "url-test"}
    ignored = {"freedom", "blackhole", "dns", "direct", "block", *auto_kinds}
    result: list[dict[str, Any]] = []
    candidates = [dict(item) for item in outbounds if isinstance(item, dict)]
    tag_map = {str(item.get("tag") or "").strip(): item for item in candidates if str(item.get("tag") or "").strip()}

    for item in candidates:
        kind = str(item.get("protocol") or item.get("type") or "").strip().lower()
        if kind not in auto_kinds:
            continue
        resolved = _resolve_auto_selector_payload(item, tag_map)
        if resolved:
            result.append(resolved)

    for item in outbounds:
        if not isinstance(item, dict):
            continue
        kind = str(item.get("protocol") or item.get("type") or "").strip().lower()
        if kind in supported:
            result.append(dict(item))
        elif kind and kind not in ignored:
            result.append(dict(item))
    return result


def _resolve_auto_selector_payload(selector: dict[str, Any], tag_map: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    refs = selector.get("outbounds")
    if not isinstance(refs, list):
        return None
    for ref in refs:
        target = tag_map.get(str(ref or "").strip())
        if not isinstance(target, dict):
            continue
        target_kind = str(target.get("protocol") or target.get("type") or "").strip().lower()
        if target_kind in {"freedom", "blackhole", "dns", "direct", "block", "selector", "urltest", "url-test"}:
            continue
        config = {
            "outbounds": [dict(item) for item in tag_map.values()],
            "route": {"final": str(selector.get("tag") or "proxy")},
        }
        name = str(selector.get("name") or selector.get("remarks") or selector.get("tag") or "Автовыбор сервера").strip()
        target_server = _first_mapping(target.get("servers")) if target_kind == "openvpn" else {}
        server = str(target.get("server") or target.get("address") or target_server.get("server") or "")
        port = int(target.get("server_port") or target.get("port") or target_server.get("server_port") or 0)
        return {
            "protocol": "singbox_config",
            "tag": name,
            "remarks": name,
            "singbox_config": config,
            "__lumen_scheme": "hysteria2" if target_kind == "hy2" else ("hysteria" if target_kind == "hy" else target_kind),
            "__lumen_server": server,
            "__lumen_port": port,
        }
    return None


def _looks_like_clash_yaml(text: str) -> bool:
    sections = {
        match.group(1).lower()
        for match in re.finditer(
            r"(?mi)^\s*(proxies|proxy-providers|proxy-groups|rules)\s*:",
            text,
        )
    }
    return "proxies" in sections or "proxy-providers" in sections or {"proxy-groups", "rules"} <= sections


def _parse_clash_yaml_nodes_text(text: str) -> tuple[list[Node], list[str]]:
    if yaml is None:
        raise LinkParseError("PyYAML is not installed")
    # A few generators emit tabs in indentation or as trailing whitespace.
    # YAML forbids those tabs even though they do not change the document's
    # meaning, so normalize structural whitespace before parsing.
    normalized_lines: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.rstrip(" \t")
        prefix = re.match(r"^[ \t]+", line)
        if prefix and "\t" in prefix.group(0):
            line = prefix.group(0).expandtabs(2) + line[len(prefix.group(0)) :]
        normalized_lines.append(line)
    payload = yaml.safe_load("\n".join(normalized_lines))
    if not isinstance(payload, dict):
        raise LinkParseError("YAML root must be an object")
    proxies = payload.get("proxies")
    if not isinstance(proxies, list):
        raise LinkParseError("YAML must contain a proxies list")
    if len(proxies) > MAX_IMPORT_NODES:
        raise LinkParseError(f"YAML contains more than {MAX_IMPORT_NODES} proxies")
    nodes: list[Node] = []
    errors: list[str] = []
    for idx, item in enumerate(proxies, start=1):
        try:
            if not isinstance(item, dict):
                raise LinkParseError(f"unsupported proxy item type: {type(item).__name__}")
            nodes.append(_parse_clash_proxy_payload(item))
        except Exception as exc:
            errors.append(f"Clash proxy {idx}: {exc}")
    nodes.extend(_parse_clash_wireguard_auto_groups(payload, nodes, errors))
    return nodes, errors


def _parse_clash_wireguard_auto_groups(
    payload: dict[str, Any],
    nodes: list[Node],
    errors: list[str],
) -> list[Node]:
    """Translate Clash url-test groups made from WG endpoints to sing-box AUTO."""
    groups = payload.get("proxy-groups") or payload.get("proxy_groups")
    if not isinstance(groups, list):
        return []

    node_by_name = {node.name: node for node in nodes if node.name}
    auto_nodes: list[Node] = []
    for index, group in enumerate(groups, start=1):
        if not isinstance(group, dict):
            continue
        group_type = str(group.get("type") or "").strip().lower()
        if group_type not in {"url-test", "urltest"}:
            continue
        refs = group.get("proxies")
        if not isinstance(refs, list):
            continue
        members = [node_by_name.get(str(ref or "").strip()) for ref in refs]
        members = [node for node in members if node is not None]
        if len(members) < 2 or not all(
            str((node.outbound or {}).get("protocol") or "").lower()
            in {"wireguard", "awg", "warp"}
            for node in members
        ):
            continue
        try:
            endpoint_tags: list[str] = []
            endpoints: list[dict[str, Any]] = []
            for member_index, member in enumerate(members, start=1):
                native = (member.outbound or {}).get("singbox")
                if not isinstance(native, dict):
                    raise LinkParseError(f"{member.name}: missing native WireGuard endpoint")
                endpoint = deepcopy(native)
                endpoint_tag = f"wg-auto-{index}-{member_index}"
                endpoint["tag"] = endpoint_tag
                endpoint_tags.append(endpoint_tag)
                endpoints.append(endpoint)

            group_name = str(group.get("name") or f"AUTO WG {index}").strip()
            group_tag = f"auto-wg-{index}"
            interval = group.get("interval")
            interval_text = (
                f"{int(interval)}s"
                if isinstance(interval, (int, float)) and int(interval) > 0
                else str(interval or "3m")
            )
            urltest: dict[str, Any] = {
                "type": "urltest",
                "tag": group_tag,
                "outbounds": endpoint_tags,
                "url": str(group.get("url") or "https://www.gstatic.com/generate_204"),
                "interval": interval_text,
                "tolerance": int(group.get("tolerance") or 50),
                "interrupt_exist_connections": True,
            }
            config = {
                "endpoints": endpoints,
                "outbounds": [
                    {"type": "direct", "tag": "direct"},
                    urltest,
                ],
                "route": {"final": group_tag, "auto_detect_interface": True},
            }
            wrapper = _native_singbox_config(config)
            wrapper.update(
                {
                    "tag": group_name,
                    "remarks": group_name,
                    "__lumen_scheme": "auto",
                    "__lumen_server": members[0].server,
                    "__lumen_port": members[0].port,
                }
            )
            node = _parse_json_outbound_payload(wrapper)
            node.name = group_name
            node.description = "Автовыбор лучших серверов"
            auto_nodes.append(node)
        except Exception as exc:
            errors.append(f"Clash AUTO WG group {index}: {exc}")
    return auto_nodes


def _parse_clash_proxy_payload(payload: dict[str, Any]) -> Node:
    kind = str(payload.get("type") or "").strip().lower()
    if kind in {"ss", "shadowsocks"}:
        kind = "shadowsocks"
    elif kind in {"hy", "hysteria"}:
        kind = "hysteria"
    elif kind in {"hy2", "hysteria2"}:
        kind = "hysteria2"
    elif kind in {"socks", "socks5"}:
        kind = "socks"
    elif kind == "https":
        kind = "http"
        payload = {**payload, "tls": True}
    elif kind in {"awg", "amneziawg", "amnezia-wg"}:
        kind = "wireguard"
    if kind not in {"vless", "vmess", "trojan", "shadowsocks", "socks", "http", "wireguard", "hysteria", "hysteria2", "tuic", "masque", "naive", "mieru", "anytls", "snell"}:
        raise LinkParseError(f"unsupported Clash proxy type: {kind or 'unknown'}")

    server = str(payload.get("server") or "").strip()
    server_ports = _clash_list(payload.get("server-ports", payload.get("server_ports", payload.get("ports"))))
    port = int(payload.get("port") or payload.get("server-port") or _representative_clash_port(server_ports) or 0)
    name = str(payload.get("name") or payload.get("tag") or f"{kind}-{server}:{port}").strip()
    if not server or port <= 0:
        raise LinkParseError("proxy must contain server and port")

    outbound: dict[str, Any]
    if kind == "wireguard":
        return _parse_clash_wireguard_payload(payload, name, server, port)
    if kind == "masque":
        return _parse_clash_masque_payload(payload, name, server, port)
    if kind in {"hysteria", "hysteria2", "tuic", "naive", "mieru", "anytls", "snell"}:
        outbound = _native_singbox_outbound(_clash_to_singbox_outbound(payload, kind))
    else:
        outbound = _clash_to_xray_outbound(payload, kind)

    return Node(
        name=name,
        scheme=kind,
        server=server,
        port=port,
        link=json.dumps(outbound, ensure_ascii=False, separators=(",", ":")),
        outbound=outbound,
    )


def _parse_naive_link(link: str, *, source_scheme: str = "") -> Node:
    """Parse an explicit NaiveProxy URI into sing-box extended's native outbound.

    Plain ``https://`` remains an HTTP proxy everywhere else.  The explicit
    ``naive*`` schemes are intentional aliases used by Lumen imports, while
    official NaiveProxy JSON configs pass their ``https://``/``quic://`` URI
    here with ``source_scheme`` so the two formats never conflict.
    """
    parsed = urlsplit(link)
    scheme = (source_scheme or parsed.scheme).strip().lower()
    is_quic = scheme in {"quic", "naive+quic"}
    if scheme not in {"naive", "naive+https", "naive+quic", "https", "quic"}:
        raise LinkParseError(f"unsupported NaiveProxy transport: {scheme or 'unknown'}")

    server = str(parsed.hostname or "").strip()
    port = int(parsed.port or 443)
    if not server or port <= 0:
        raise LinkParseError("NaiveProxy URI must contain server and port")

    query = parse_qs(parsed.query, keep_blank_values=True)
    username = unquote(parsed.username or "")
    password = unquote(parsed.password or "")
    server_name = _first(query, "sni") or _first(query, "server_name") or server
    native: dict[str, Any] = {
        "type": "naive",
        "tag": "proxy",
        "server": server,
        "server_port": port,
        "username": username,
        "password": password,
        "quic": is_quic or _to_bool(_first(query, "quic")),
        "tls": {
            "enabled": True,
            "server_name": server_name,
        },
    }
    concurrency = _first(query, "insecure_concurrency") or _first(query, "insecure-concurrency")
    if concurrency:
        native["insecure_concurrency"] = int(concurrency)
    congestion = _first(query, "quic_congestion_control") or _first(query, "quic-congestion-control")
    if congestion:
        native["quic_congestion_control"] = congestion
    udp_over_tcp = _first(query, "udp_over_tcp") or _first(query, "udp-over-tcp")
    if udp_over_tcp:
        try:
            decoded_uot = json.loads(udp_over_tcp)
        except json.JSONDecodeError:
            decoded_uot = _to_bool(udp_over_tcp)
        if isinstance(decoded_uot, (bool, dict)):
            native["udp_over_tcp"] = decoded_uot
    extra_headers = _first(query, "extra_headers") or _first(query, "extra-headers")
    if extra_headers:
        try:
            decoded_headers = json.loads(extra_headers)
        except json.JSONDecodeError as exc:
            raise LinkParseError("NaiveProxy extra_headers must be a JSON object") from exc
        if not isinstance(decoded_headers, dict):
            raise LinkParseError("NaiveProxy extra_headers must be a JSON object")
        native["extra_headers"] = decoded_headers

    name = _clean_name(parsed.fragment, f"naive-{server}:{port}")
    outbound = _native_singbox_outbound(native)
    return Node(
        name=name,
        scheme="naive",
        server=server,
        port=port,
        link=link,
        outbound=outbound,
    )


def _parse_naiveproxy_config_payload(payload: dict[str, Any]) -> tuple[list[Node], list[str]]:
    raw_proxies = payload.get("proxy")
    proxy_uris = raw_proxies if isinstance(raw_proxies, list) else [raw_proxies]
    nodes: list[Node] = []
    errors: list[str] = []
    for index, value in enumerate(proxy_uris, start=1):
        uri = str(value or "").strip()
        if not uri:
            continue
        scheme = urlsplit(uri).scheme.lower()
        if scheme not in {"https", "quic"}:
            errors.append(f"NaiveProxy proxy {index}: unsupported transport `{scheme or 'unknown'}`")
            continue
        try:
            nodes.append(_parse_naive_link(uri, source_scheme=scheme))
        except Exception as exc:
            errors.append(f"NaiveProxy proxy {index}: {exc}")
    return nodes, errors


def _clash_list(value: Any) -> list[str]:
    if isinstance(value, (list, tuple)):
        return [str(item).strip() for item in value if str(item).strip()]
    return _split_csv(str(value or ""))


def _representative_clash_port(ranges: list[str]) -> int:
    for value in ranges:
        match = re.match(r"^\s*(\d{1,5})", value)
        if match and 1 <= int(match.group(1)) <= 65535:
            return int(match.group(1))
    return 0


def _clash_speed_mbps(value: Any) -> int | None:
    digits = "".join(char for char in str(value or "") if char.isdigit())
    return int(digits) if digits else None


def _clash_duration(value: Any) -> str:
    text = str(value or "").strip()
    return f"{text}s" if text.isdigit() else text


def _clash_certificate_pins(payload: dict[str, Any]) -> list[str]:
    for key in (
        "certificate-public-key-sha256",
        "certificate_public_key_sha256",
        "pin-sha256",
        "pinSHA256",
    ):
        pins = _clash_list(payload.get(key))
        if pins:
            return pins
    return []


def _parse_clash_masque_payload(
    payload: dict[str, Any],
    name: str,
    server: str,
    port: int,
) -> Node:
    """Convert WARP-generator Clash MASQUE entries to sing-box-extended."""
    network = str(payload.get("network") or "").strip().lower()
    profile: dict[str, Any] = {"detour": "direct"}
    for source, target in (
        ("profile-id", "id"),
        ("profile_id", "id"),
        ("auth-token", "auth_token"),
        ("auth_token", "auth_token"),
        ("masque-private-key", "private_key"),
        ("masque_private_key", "private_key"),
    ):
        value = str(payload.get(source) or "").strip()
        if value:
            profile[target] = value
    private_key = str(payload.get("private-key") or payload.get("private_key") or "").strip()
    public_key = str(payload.get("public-key") or payload.get("public_key") or "").strip()
    address = normalize_ip_prefixes(
        _clash_list(payload.get("ip") or payload.get("address"))
    )
    address.extend(
        item
        for item in normalize_ip_prefixes(_clash_list(payload.get("ipv6")))
        if item not in address
    )
    native: dict[str, Any] = {
        "type": "masque",
        "tag": "proxy",
        "system": False,
        "name": "masque0",
        "use_http2": network in {"h2", "http2"},
        "use_ipv6": _to_bool(payload.get("use-ipv6") or payload.get("use_ipv6") or False),
        "profile": profile,
        "udp_timeout": "5m0s",
        "udp_keepalive_period": "30s",
        "reconnect_delay": "5s",
        "congestion_controller": "bbr",
    }
    # Mihomo/usque MASQUE profiles contain a ready-to-use ECDSA client key,
    # endpoint public key and tunnel addresses.  Keep those values together;
    # treating this format as an empty Cloudflare registration profile leaves
    # the outbound permanently in "tunnel not initialized" state.
    if private_key or public_key:
        if not private_key or not public_key or not server:
            raise LinkParseError(
                "direct MASQUE proxy must contain server, private-key and public-key"
            )
        if not address:
            raise LinkParseError(
                "direct MASQUE proxy must contain ip, ipv6 or address"
            )
        native.update(
            {
                "server": server,
                "server_port": int(port or 443),
                "private_key": private_key,
                "public_key": public_key,
                "tunnel_address": address,
                "mtu": int(payload.get("mtu") or 1280),
            }
        )
    allowed_ips = normalize_ip_prefixes(
        _clash_list(payload.get("allowed-ips") or payload.get("allowed_ips"))
    )
    if allowed_ips:
        native["allowed_ips"] = allowed_ips
    server_name = str(payload.get("sni") or payload.get("servername") or "").strip()
    if server_name:
        native["tls"] = {"server_name": server_name}
    outbound = _native_singbox_outbound(native)
    dns_servers = _clash_list(payload.get("dns"))
    if dns_servers:
        outbound["_dns"] = dns_servers
    return Node(
        name=name,
        scheme="masque",
        server=server,
        port=port,
        link=json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
        outbound=outbound,
        tags=["WARP"],
    )


def _parse_clash_wireguard_payload(
    payload: dict[str, Any],
    name: str,
    server: str,
    port: int,
) -> Node:
    private_key = str(payload.get("private-key") or payload.get("private_key") or "").strip()
    public_key = str(payload.get("public-key") or payload.get("public_key") or "").strip()
    if not private_key or not public_key:
        raise LinkParseError("wireguard proxy must contain private-key and public-key")

    address = normalize_ip_prefixes(_clash_list(payload.get("ip") or payload.get("address")))
    address.extend(
        item
        for item in normalize_ip_prefixes(_clash_list(payload.get("ipv6")))
        if item not in address
    )
    allowed_ips = normalize_ip_prefixes(
        _clash_list(payload.get("allowed-ips") or payload.get("allowed_ips"))
    )
    amnezia_options = payload.get("amnezia-wg-option") or payload.get("amnezia")
    amnezia = (
        _amnezia_from_params({str(key): str(value) for key, value in amnezia_options.items()})
        if isinstance(amnezia_options, dict)
        else {}
    )
    reserved_bytes = _parse_reserved_bytes(payload.get("reserved"))
    keepalive = payload.get("persistent-keepalive") or payload.get("persistent_keepalive_interval")

    if reserved_bytes and not _is_warp_endpoint(server):
        raise LinkParseError("reserved bytes are supported only for Cloudflare WARP profiles")

    if reserved_bytes:
        endpoint = _build_warp_profile_endpoint(
            private_key=private_key,
            persistent_keepalive=keepalive,
            amnezia=amnezia,
            listen_port=payload.get("listen-port") or payload.get("listen_port") or "",
        )
        scheme = "awg" if amnezia else "warp"
        outbound = _native_singbox_outbound(endpoint)
        dns_servers = _clash_list(payload.get("dns"))
        if dns_servers:
            outbound["_dns"] = dns_servers
        return Node(
            name=name,
            scheme=scheme,
            server=server,
            port=port,
            link=json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
            outbound=outbound,
            tags=["WARP"],
        )

    endpoint = _build_wireguard_endpoint(
        server=server,
        port=port,
        private_key=private_key,
        public_key=public_key,
        address=address,
        allowed_ips=allowed_ips,
        pre_shared_key=str(
            payload.get("pre-shared-key")
            or payload.get("preshared-key")
            or payload.get("pre_shared_key")
            or ""
        ),
        mtu=int(payload.get("mtu") or 1408),
        amnezia=amnezia,
        listen_port=payload.get("listen-port") or payload.get("listen_port") or "",
        udp_timeout=payload.get("udp-timeout") or payload.get("udp_timeout") or "5m0s",
        workers=payload.get("workers") or "",
        preallocated_buffers_per_pool=(
            payload.get("preallocated-buffers-per-pool")
            or payload.get("preallocated_buffers_per_pool")
            or ""
        ),
        disable_pauses=(
            payload.get("disable-pauses")
            if "disable-pauses" in payload
            else payload.get("disable_pauses")
        ),
    )
    peer = endpoint["peers"][0]
    if keepalive not in (None, ""):
        peer["persistent_keepalive_interval"] = int(keepalive)

    scheme = "awg" if amnezia else "wireguard"
    outbound = _native_singbox_outbound(endpoint)
    dns_servers = _clash_list(payload.get("dns"))
    if dns_servers:
        outbound["_dns"] = dns_servers
    return Node(
        name=name,
        scheme=scheme,
        server=server,
        port=port,
        link=json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
        outbound=outbound,
        tags=["WARP"] if _is_warp_endpoint(server) else [],
    )


def _clash_to_xray_outbound(payload: dict[str, Any], kind: str) -> dict[str, Any]:
    server = str(payload.get("server") or "").strip()
    port = int(payload.get("port") or payload.get("server-port") or 0)
    user_id = str(payload.get("uuid") or payload.get("id") or "").strip()
    password = str(payload.get("password") or "").strip()

    if kind in {"vless", "vmess"}:
        user: dict[str, Any] = {"id": user_id}
        if kind == "vless":
            user["encryption"] = str(payload.get("encryption") or "none")
            flow = str(payload.get("flow") or "").strip()
            if flow:
                user["flow"] = flow
        else:
            user["alterId"] = int(payload.get("alterId") or payload.get("alter-id") or 0)
            user["security"] = str(payload.get("cipher") or "auto")
        settings = {"vnext": [{"address": server, "port": port, "users": [user]}]}
    elif kind == "trojan":
        settings = {"servers": [{"address": server, "port": port, "password": password}]}
    elif kind in {"socks", "http"}:
        server_item: dict[str, Any] = {"address": server, "port": port}
        username = str(payload.get("username") or payload.get("user") or "").strip()
        if username:
            server_item["users"] = [{"user": username, "pass": password}]
        settings = {"servers": [server_item]}
    else:
        plugin_options = payload.get("plugin-opts", payload.get("plugin_opts", ""))
        if isinstance(plugin_options, dict):
            plugin_options = ";".join(
                str(key) if value is True else f"{key}={value}"
                for key, value in plugin_options.items()
            )
        server_item = {
            "address": server,
            "port": port,
            "method": str(payload.get("cipher") or payload.get("method") or "none"),
            "password": password,
        }
        if payload.get("plugin"):
            server_item["plugin"] = str(payload["plugin"])
        if plugin_options:
            server_item["plugin_opts"] = str(plugin_options)
        settings = {
            "servers": [server_item]
        }

    outbound = {
        "protocol": kind,
        "settings": settings,
    }
    if kind not in {"socks", "http"} or (
        kind == "http"
        and (
            _to_bool(payload.get("tls"))
            or str(payload.get("servername") or payload.get("sni") or "").strip()
        )
    ):
        outbound["streamSettings"] = _clash_stream_settings(payload)
    return outbound


def _clash_stream_settings(payload: dict[str, Any]) -> dict[str, Any]:
    network = str(payload.get("network") or "tcp").strip().lower()
    if network in {"httpupgrade", "http-upgrade"}:
        network = "httpupgrade"
    security = "tls" if _to_bool(payload.get("tls")) else "none"
    if str(payload.get("reality-opts") or "").strip() or payload.get("reality"):
        security = "reality"
    stream = {"network": network, "security": security}

    ws_opts = payload.get("ws-opts", payload.get("ws_opts"))
    ws_opts = ws_opts if isinstance(ws_opts, dict) else {}
    grpc_opts = payload.get("grpc-opts", payload.get("grpc_opts"))
    grpc_opts = grpc_opts if isinstance(grpc_opts, dict) else {}
    http_opts = payload.get("h2-opts", payload.get("h2_opts"))
    if not isinstance(http_opts, dict):
        http_opts = payload.get("http-opts", payload.get("http_opts"))
    http_opts = http_opts if isinstance(http_opts, dict) else {}
    xhttp_opts = payload.get("xhttp-opts") if isinstance(payload.get("xhttp-opts"), dict) else {}

    if network == "ws":
        headers = dict(ws_opts.get("headers") or {}) if isinstance(ws_opts.get("headers"), dict) else {}
        ws_settings = {
            "path": str(ws_opts.get("path") or payload.get("path") or "/"),
            "headers": headers,
        }
        early_data = ws_opts.get("max-early-data", ws_opts.get("max_early_data", payload.get("max-early-data")))
        if str(early_data or "").strip().isdigit():
            ws_settings["maxEarlyData"] = int(early_data)
        early_header = ws_opts.get("early-data-header-name", ws_opts.get("early_data_header_name"))
        if early_header:
            ws_settings["earlyDataHeaderName"] = str(early_header)
        stream["wsSettings"] = ws_settings
    elif network == "grpc":
        grpc_settings = {
            "serviceName": str(grpc_opts.get("grpc-service-name") or grpc_opts.get("service-name") or grpc_opts.get("service_name") or grpc_opts.get("serviceName") or payload.get("service-name") or "")
        }
        authority = grpc_opts.get("authority") or grpc_opts.get("grpc-authority") or grpc_opts.get("grpc_authority") or payload.get("grpc-authority") or payload.get("grpc_authority")
        if authority:
            grpc_settings["authority"] = str(authority)
        for clash_key, target_key in (
            ("idle-timeout", "idleTimeout"),
            ("idle_timeout", "idleTimeout"),
            ("ping-timeout", "pingTimeout"),
            ("ping_timeout", "pingTimeout"),
        ):
            if grpc_opts.get(clash_key) not in (None, ""):
                grpc_settings[target_key] = grpc_opts[clash_key]
        permit = grpc_opts.get("permit-without-stream", grpc_opts.get("permit_without_stream"))
        if permit not in (None, ""):
            grpc_settings["permitWithoutStream"] = _to_bool(permit)
        if _to_bool(grpc_opts.get("multi-mode", grpc_opts.get("multi_mode", False))):
            grpc_settings["multiMode"] = True
        stream["grpcSettings"] = grpc_settings
    elif network in {"http", "h2"}:
        host = http_opts.get("host") or payload.get("host") or []
        if isinstance(host, str):
            host = [host]
        path = http_opts.get("path") or payload.get("path") or "/"
        if isinstance(path, list):
            path = path[0] if path else "/"
        http_settings: dict[str, Any] = {"host": host, "path": str(path)}
        if isinstance(http_opts.get("headers"), dict):
            http_settings["headers"] = deepcopy(http_opts["headers"])
        if http_opts.get("method"):
            http_settings["method"] = str(http_opts["method"])
        for clash_key, target_key in (
            ("idle-timeout", "idleTimeout"),
            ("idle_timeout", "idleTimeout"),
            ("ping-timeout", "pingTimeout"),
            ("ping_timeout", "pingTimeout"),
        ):
            if http_opts.get(clash_key) not in (None, ""):
                http_settings[target_key] = http_opts[clash_key]
        stream["httpSettings"] = http_settings
    elif network == "xhttp":
        xhttp_settings = deepcopy(xhttp_opts)
        xhttp_settings.setdefault("path", str(payload.get("path") or "/"))
        xhttp_settings.setdefault("host", str(payload.get("host") or ""))
        xhttp_settings.setdefault("mode", str(payload.get("mode") or "auto"))
        stream["xhttpSettings"] = xhttp_settings

    if security == "tls":
        tls_settings = {
            "serverName": str(payload.get("servername") or payload.get("sni") or payload.get("server") or ""),
            "fingerprint": str(payload.get("client-fingerprint") or payload.get("fingerprint") or ""),
            "allowInsecure": _to_bool(payload.get("skip-cert-verify", False)),
        }
        alpn = _clash_list(payload.get("alpn"))
        if alpn:
            tls_settings["alpn"] = alpn
        pins = _clash_certificate_pins(payload)
        if pins:
            tls_settings["pinSHA256"] = pins
        stream["tlsSettings"] = tls_settings
    elif security == "reality":
        reality_opts = payload.get("reality-opts") if isinstance(payload.get("reality-opts"), dict) else {}
        stream["realitySettings"] = {
            "serverName": str(payload.get("servername") or payload.get("sni") or ""),
            "fingerprint": str(payload.get("client-fingerprint") or payload.get("fingerprint") or ""),
            "publicKey": str(reality_opts.get("public-key") or reality_opts.get("publicKey") or payload.get("pbk") or ""),
            "shortId": str(reality_opts.get("short-id") or reality_opts.get("shortId") or payload.get("sid") or ""),
            "spiderX": str(reality_opts.get("spider-x") or reality_opts.get("spiderX") or payload.get("spx") or "/"),
        }
        mldsa = (
            reality_opts.get("mldsa65-verify")
            or reality_opts.get("mldsa65_verify")
            or reality_opts.get("mldsa65Verify")
            or payload.get("pqv")
        )
        if mldsa:
            stream["realitySettings"]["mldsa65Verify"] = str(mldsa)
    return stream


def _clash_to_singbox_outbound(payload: dict[str, Any], kind: str) -> dict[str, Any]:
    native = {
        "type": kind,
        "tag": str(payload.get("name") or kind),
        "server": str(payload.get("server") or ""),
        "server_port": int(payload.get("port") or payload.get("server-port") or 0),
    }
    for clash_key, singbox_key in (
        ("password", "password"),
        ("auth", "auth_str"),
        ("auth-str", "auth_str"),
        ("uuid", "uuid"),
        ("congestion-controller", "congestion_control"),
        ("udp-relay-mode", "udp_relay_mode"),
        ("username", "username"),
        ("insecure-concurrency", "insecure_concurrency"),
        ("quic-congestion-control", "quic_congestion_control"),
        ("min-idle-session", "min_idle_session"),
        ("idle-session-check-interval", "idle_session_check_interval"),
        ("psk", "psk"),
        ("version", "version"),
    ):
        value = payload.get(clash_key)
        if value not in (None, ""):
            native[singbox_key] = value
    if kind == "snell" and not native.get("psk"):
        native["psk"] = str(payload.get("password") or "")
    if kind == "mieru":
        native["transport"] = str(payload.get("transport") or "TCP").upper()
        server_ports = _clash_list(payload.get("server-ports", payload.get("server_ports", payload.get("ports"))))
        if server_ports:
            native["server_ports"] = server_ports
        traffic_pattern = payload.get("traffic-pattern", payload.get("traffic_pattern"))
        if traffic_pattern:
            native["traffic_pattern"] = str(traffic_pattern)
        if payload.get("multiplexing"):
            native["multiplexing"] = payload["multiplexing"]
    if kind in {"hysteria", "hysteria2"}:
        server_ports = _clash_list(payload.get("ports", payload.get("server-ports", payload.get("server_ports"))))
        if server_ports:
            native["server_ports"] = server_ports
        hop_interval = payload.get("hop-interval", payload.get("hop_interval"))
        if hop_interval not in (None, ""):
            native["hop_interval"] = _clash_duration(hop_interval)
        up_value = payload.get("up", payload.get("up-mbps", payload.get("up_mbps", payload.get("up-speed"))))
        down_value = payload.get("down", payload.get("down-mbps", payload.get("down_mbps", payload.get("down-speed"))))
        if (up_mbps := _clash_speed_mbps(up_value)) is not None:
            native["up_mbps"] = up_mbps
        if (down_mbps := _clash_speed_mbps(down_value)) is not None:
            native["down_mbps"] = down_mbps
        for clash_key, singbox_key in (
            ("recv-window-conn", "recv_window_conn"),
            ("recv_window_conn", "recv_window_conn"),
            ("recv-window", "recv_window"),
            ("recv_window", "recv_window"),
        ):
            if payload.get(clash_key) not in (None, ""):
                native[singbox_key] = int(payload[clash_key])
        if _to_bool(payload.get("disable-mtu-discovery", payload.get("disable_mtu_discovery", False))):
            native["disable_mtu_discovery"] = True
        if kind == "hysteria":
            auth = payload.get("auth-str", payload.get("auth_str", payload.get("auth", payload.get("password"))))
            if auth:
                native["auth_str"] = str(auth)
            protocol = str(payload.get("protocol") or "").strip()
            if protocol and protocol.lower() != "hysteria":
                native["protocol"] = protocol
            if payload.get("obfs"):
                native["obfs"] = str(payload["obfs"])
            native.pop("password", None)
        else:
            if not native.get("password") and payload.get("auth"):
                native["password"] = str(payload["auth"])
            native.pop("auth_str", None)
            obfs_type = str(payload.get("obfs") or "").strip()
            obfs_password = str(payload.get("obfs-password", payload.get("obfs_password", "")) or "")
            if obfs_type:
                native["obfs"] = {"type": obfs_type, "password": obfs_password}
    server_name = str(payload.get("servername") or payload.get("sni") or "").strip()
    if _to_bool(payload.get("tls")) or server_name or kind in {"naive", "anytls"}:
        native["tls"] = {"enabled": True}
        if server_name:
            native["tls"]["server_name"] = server_name
        # The Cronet-backed Naive outbound intentionally supports only a
        # restricted TLS subset.  Passing insecure/ALPN makes sing-box reject
        # the whole config instead of merely ignoring the unsupported option.
        if _to_bool(payload.get("skip-cert-verify")) and kind != "naive":
            native["tls"]["insecure"] = True
        alpn = _clash_list(payload.get("alpn"))
        if alpn and kind != "naive":
            native["tls"]["alpn"] = alpn
        pins = _clash_certificate_pins(payload)
        if pins and kind != "naive":
            native["tls"]["certificate_public_key_sha256"] = pins
    if kind == "naive":
        native["quic"] = _to_bool(payload.get("quic", False))
        udp_over_tcp = payload.get("udp-over-tcp", payload.get("udp_over_tcp"))
        if isinstance(udp_over_tcp, (bool, dict)):
            native["udp_over_tcp"] = deepcopy(udp_over_tcp)
        extra_headers = payload.get("extra-headers", payload.get("extra_headers"))
        if isinstance(extra_headers, dict):
            native["extra_headers"] = deepcopy(extra_headers)
    return native


def _json_payload_can_be_node(payload: dict[str, Any]) -> bool:
    return (
        "type" in payload
        or "protocol" in payload
        or isinstance(payload.get("endpoints"), list)
        or isinstance(payload.get("outbounds"), list)
        or isinstance(payload.get("providers"), list)
    )


def _parse_json_outbound(text: str) -> Node:
    payload = json.loads(text)
    if not isinstance(payload, dict):
        raise LinkParseError("JSON node must be an object")
    return _parse_json_outbound_payload(payload)


def _parse_json_outbound_payload(payload: dict[str, Any]) -> Node:
    original_payload = payload

    outbound: dict[str, Any]
    explicit_protocol = str(payload.get("protocol") or "").strip().lower()
    if explicit_protocol == "singbox_config" and isinstance(payload.get("singbox_config"), dict):
        inferred = _native_singbox_config(payload["singbox_config"])
        outbound = {**inferred, **dict(payload)}
        outbound["singbox_config"] = inferred["singbox_config"]
        for metadata_key in ("__lumen_scheme", "__lumen_server", "__lumen_port"):
            if payload.get(metadata_key) in (None, "") and inferred.get(metadata_key) not in (None, ""):
                outbound[metadata_key] = inferred[metadata_key]
    elif explicit_protocol == "xray_config" and isinstance(payload.get("xray_config"), dict):
        outbound = dict(payload)
    elif _is_xray_auto_config_payload(payload):
        outbound = _native_xray_config(payload)
    elif _is_singbox_wireguard_config_payload(payload) or _is_singbox_openvpn_config_payload(payload):
        outbound = _native_singbox_config(payload)
    elif _is_clash_proxy_payload(payload):
        return _parse_clash_proxy_payload(payload)
    elif "type" in payload:
        outbound = _native_singbox_outbound(payload)
    elif "protocol" in payload:
        outbound = dict(payload)
    elif isinstance(payload.get("providers"), list) and isinstance(payload.get("outbounds"), list):
        outbound = _native_singbox_config(payload)
    elif isinstance(payload.get("endpoints"), list) and payload["endpoints"]:
        outbound = _native_singbox_outbound(payload["endpoints"][0])
    elif isinstance(payload.get("outbounds"), list) and payload["outbounds"]:
        first_outbound = _pick_json_proxy_outbound(payload["outbounds"])
        outbound = _native_singbox_outbound(first_outbound) if "type" in first_outbound else first_outbound
    else:
        raise LinkParseError("JSON must contain `protocol` or `outbounds`")

    protocol = str(outbound.get("protocol") or "custom")
    tag = str(outbound.get("tag") or protocol)
    server = ""
    port = 0

    native = outbound.get("singbox") if isinstance(outbound.get("singbox"), dict) else {}
    settings = outbound.get("settings") or {}
    if protocol in {"vless", "vmess"}:
        if native:
            server = str(native.get("server") or "")
            port = int(native.get("server_port") or 0)
        else:
            vnext = (settings.get("vnext") or [{}])[0]
            server = str(vnext.get("address") or "")
            port = int(vnext.get("port") or 0)
    elif protocol in {"trojan", "shadowsocks", "socks", "http"}:
        if native:
            server = str(native.get("server") or "")
            port = int(native.get("server_port") or 0)
        else:
            servers = (settings.get("servers") or [{}])[0]
            server = str(servers.get("address") or "")
            port = int(servers.get("port") or 0)
    elif protocol in {"warp", "wireguard", "awg"} and native:
        peers = native.get("peers")
        peer = peers[0] if isinstance(peers, list) and peers and isinstance(peers[0], dict) else {}
        server = str(peer.get("address") or native.get("server") or "")
        port = int(peer.get("port") or native.get("server_port") or 0)
    elif protocol in {"hysteria", "hysteria2", "tuic", "mieru", "naive", "anytls", "snell"}:
        if native:
            server = str(native.get("server") or "")
            port = int(native.get("server_port") or 0)
        else:
            server = str(settings.get("address") or settings.get("server") or "")
            port = int(settings.get("port") or settings.get("server_port") or 0)
    elif protocol == "masque" and native:
        server = str((native.get("profile") or {}).get("id") or native.get("server") or "")
        port = int(native.get("server_port") or 0)
    elif protocol == "openvpn" and native:
        openvpn_server = _first_mapping(native.get("servers"))
        server = str(openvpn_server.get("server") or "")
        port = int(openvpn_server.get("server_port") or 0)
    elif protocol == "singbox_config":
        full_config = outbound.get("singbox_config") if isinstance(outbound.get("singbox_config"), dict) else {}
        endpoint = _first_wireguard_endpoint(full_config)
        if endpoint:
            peer = _first_mapping(endpoint.get("peers"))
            server = str(
                peer.get("address")
                or ("engage.cloudflareclient.com" if endpoint.get("type") == "warp" else "")
            )
            port = int(
                peer.get("port")
                or (2408 if endpoint.get("type") == "warp" else 0)
            )
        else:
            proxy = _pick_json_proxy_outbound(list(full_config.get("outbounds") or [])) if isinstance(full_config.get("outbounds"), list) else {}
            native_proxy = proxy if isinstance(proxy, dict) else {}
            openvpn_server = _first_mapping(native_proxy.get("servers"))
            server = str(native_proxy.get("server") or openvpn_server.get("server") or "")
            port = int(native_proxy.get("server_port") or openvpn_server.get("server_port") or 0)
    elif protocol == "xray_config":
        full_config = outbound.get("xray_config") if isinstance(outbound.get("xray_config"), dict) else {}
        proxy = _pick_json_proxy_outbound(list(full_config.get("outbounds") or [])) if isinstance(full_config.get("outbounds"), list) else {}
        if isinstance(proxy, dict):
            proxy_node = _parse_json_outbound_payload(proxy)
            server = proxy_node.server
            port = proxy_node.port

    display_scheme = str(
        original_payload.get("__lumen_scheme")
        or outbound.get("__lumen_scheme")
        or ("auto" if protocol == "xray_config" else protocol)
    )
    if original_payload.get("__lumen_server"):
        server = str(original_payload.get("__lumen_server") or server)
    if original_payload.get("__lumen_port"):
        port = int(original_payload.get("__lumen_port") or port)

    meta = original_payload.get("meta") if isinstance(original_payload.get("meta"), dict) else {}
    description = str(
        original_payload.get("serverDescription")
        or meta.get("serverDescription")
        or ""
    ).strip()[:30]

    if protocol == "singbox_config":
        fallback_name = str(outbound.get("tag") or ("AUTO" if display_scheme == "auto" else display_scheme.upper()))
    else:
        fallback_name = f"json-{tag}"
    if display_scheme == "auto" and not description:
        description = "Автовыбор лучших серверов"

    return Node(
        name=_json_name(original_payload, fallback_name),
        scheme=display_scheme,
        server=server,
        port=port,
        link=json.dumps(original_payload, ensure_ascii=False, separators=(",", ":")),
        outbound=outbound,
        description=description,
    )


def _pick_json_proxy_outbound(outbounds: list[Any]) -> dict[str, Any]:
    candidates = [dict(item) for item in outbounds if isinstance(item, dict)]
    if not candidates:
        raise LinkParseError("JSON outbounds list is empty")

    def kind(item: dict[str, Any]) -> str:
        return str(item.get("protocol") or item.get("type") or "").strip().lower()

    ignored = {"freedom", "blackhole", "dns", "direct", "block", "selector", "urltest", "url-test"}
    supported = {
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
        "hy",
        "hy2",
        "tuic",
        "mieru",
        "masque",
        "openvpn",
        "naive",
    }
    for item in candidates:
        if str(item.get("tag") or "").strip().lower() == "proxy" and kind(item) not in ignored:
            return item
    for item in candidates:
        if kind(item) in supported:
            return item
    for item in candidates:
        if kind(item) not in ignored:
            return item
    return candidates[0]


def _native_singbox_outbound(payload: dict[str, Any]) -> dict[str, Any]:
    native = dict(payload)
    protocol = str(native.get("type") or "custom").lower()
    if protocol == "hy":
        protocol = native["type"] = "hysteria"
    elif protocol == "hy2":
        protocol = native["type"] = "hysteria2"
    elif protocol == "openvpn":
        native["system"] = False
        native["name"] = str(native.get("name") or "openvpn0")
    elif protocol in {"wireguard", "awg", "warp"}:
        native = normalize_wireguard_endpoint(native)
        protocol = str(native.get("type") or "custom").lower()
    return {
        "protocol": "awg" if protocol == "wireguard" and isinstance(native.get("amnezia"), dict) else protocol,
        "singbox": native,
    }


def _native_singbox_config(payload: dict[str, Any]) -> dict[str, Any]:
    config = deepcopy(payload)
    for metadata_key in (
        "remarks",
        "remark",
        "ps",
        "name",
        "meta",
        "serverDescription",
        "__lumen_scheme",
        "__lumen_server",
        "__lumen_port",
    ):
        config.pop(metadata_key, None)
    normalize_singbox_wireguard_endpoints(config)
    used_openvpn_names: set[str] = set()
    openvpn_index = 0
    for item in config.get("outbounds") or []:
        if not isinstance(item, dict) or str(item.get("type") or "").strip().lower() != "openvpn":
            continue
        item["system"] = False
        requested_name = str(item.get("name") or f"openvpn{openvpn_index}").strip()
        name_candidate = requested_name
        suffix = 1
        while name_candidate in used_openvpn_names:
            name_candidate = f"{requested_name}-{suffix}"
            suffix += 1
        item["name"] = name_candidate
        used_openvpn_names.add(name_candidate)
        openvpn_index += 1
    name = _json_name(payload, "")
    endpoint = _first_wireguard_endpoint(config)
    openvpn_outbound = _first_openvpn_outbound(config)
    wireguard_auto_group = _wireguard_auto_group(config)
    openvpn_auto_group = _openvpn_auto_group(config)
    auto_group = wireguard_auto_group or openvpn_auto_group
    if not isinstance(config.get("outbounds"), list):
        config["outbounds"] = []
    if not any(
        isinstance(item, dict) and str(item.get("tag") or "") == "direct"
        for item in config["outbounds"]
    ):
        config["outbounds"].insert(0, {"type": "direct", "tag": "direct"})

    wrapper: dict[str, Any] = {
        "protocol": "singbox_config",
        "tag": name or (
            "AUTO OpenVPN"
            if openvpn_auto_group
            else "AUTO WG"
            if wireguard_auto_group
            else "OpenVPN"
            if openvpn_outbound
            else "sing-box providers"
        ),
        "singbox_config": config,
    }
    if endpoint:
        peer = _first_mapping(endpoint.get("peers"))
        wrapper["__lumen_server"] = str(
            peer.get("address")
            or ("engage.cloudflareclient.com" if endpoint.get("type") == "warp" else "")
        )
        wrapper["__lumen_port"] = int(
            peer.get("port")
            or (2408 if endpoint.get("type") == "warp" else 0)
        )
        if auto_group:
            wrapper["__lumen_scheme"] = "auto"
        elif str(endpoint.get("type") or "") == "warp":
            wrapper["__lumen_scheme"] = "warp"
        elif isinstance(endpoint.get("amnezia"), dict):
            wrapper["__lumen_scheme"] = "awg"
        else:
            wrapper["__lumen_scheme"] = "wireguard"
    elif openvpn_outbound:
        openvpn_server = _first_mapping(openvpn_outbound.get("servers"))
        wrapper["__lumen_server"] = str(openvpn_server.get("server") or "")
        wrapper["__lumen_port"] = int(openvpn_server.get("server_port") or 0)
        wrapper["__lumen_scheme"] = "auto" if openvpn_auto_group else "openvpn"
    return wrapper


def _is_singbox_wireguard_config_payload(payload: Any) -> bool:
    """Detect complete WG configs that must stay intact instead of being split."""
    if not isinstance(payload, dict):
        return False
    endpoints = payload.get("endpoints")
    outbounds = payload.get("outbounds")
    endpoint_items = [item for item in endpoints if isinstance(item, dict)] if isinstance(endpoints, list) else []
    outbound_items = [item for item in outbounds if isinstance(item, dict)] if isinstance(outbounds, list) else []
    wireguard_endpoints = [
        item
        for item in endpoint_items
        if str(item.get("type") or "").strip().lower() in {"wireguard", "awg", "warp"}
    ]
    legacy_wireguard = [
        item
        for item in outbound_items
        if str(item.get("type") or "").strip().lower() in {"wireguard", "awg"}
    ]
    if not wireguard_endpoints and not legacy_wireguard:
        return False

    endpoint_tags = {
        str(item.get("tag") or "").strip()
        for item in [*wireguard_endpoints, *legacy_wireguard]
        if str(item.get("tag") or "").strip()
    }
    has_wg_group = any(
        str(item.get("type") or "").strip().lower() in {"urltest", "url-test", "selector"}
        and isinstance(item.get("outbounds"), list)
        and bool(endpoint_tags.intersection(str(tag or "").strip() for tag in item["outbounds"]))
        for item in outbound_items
    )
    return bool(
        has_wg_group
        or len(wireguard_endpoints) + len(legacy_wireguard) > 1
        or isinstance(payload.get("route"), dict)
        or isinstance(payload.get("inbounds"), list)
        or isinstance(payload.get("dns"), dict)
    )


def _is_singbox_openvpn_config_payload(payload: Any) -> bool:
    """Keep complete OpenVPN/urltest configs intact instead of splitting them."""
    if not isinstance(payload, dict):
        return False
    outbounds = payload.get("outbounds")
    items = [item for item in outbounds if isinstance(item, dict)] if isinstance(outbounds, list) else []
    openvpn_items = [
        item for item in items
        if str(item.get("type") or "").strip().lower() == "openvpn"
    ]
    if not openvpn_items:
        return False
    tags = {
        str(item.get("tag") or "").strip()
        for item in openvpn_items
        if str(item.get("tag") or "").strip()
    }
    has_group = any(
        str(item.get("type") or "").strip().lower() in {"urltest", "url-test", "selector"}
        and isinstance(item.get("outbounds"), list)
        and bool(tags.intersection(str(tag or "").strip() for tag in item["outbounds"]))
        for item in items
    )
    return bool(
        has_group
        or len(openvpn_items) > 1
        or isinstance(payload.get("route"), dict)
        or isinstance(payload.get("inbounds"), list)
        or isinstance(payload.get("dns"), dict)
    )


def _first_wireguard_endpoint(config: dict[str, Any]) -> dict[str, Any]:
    endpoints = config.get("endpoints")
    if not isinstance(endpoints, list):
        return {}
    for endpoint in endpoints:
        if isinstance(endpoint, dict) and str(endpoint.get("type") or "").strip().lower() in {
            "wireguard",
            "warp",
        }:
            return endpoint
    return {}


def _first_openvpn_outbound(config: dict[str, Any]) -> dict[str, Any]:
    outbounds = config.get("outbounds")
    if not isinstance(outbounds, list):
        return {}
    for outbound in outbounds:
        if isinstance(outbound, dict) and str(outbound.get("type") or "").strip().lower() == "openvpn":
            return outbound
    return {}


def _first_mapping(value: Any) -> dict[str, Any]:
    if not isinstance(value, list):
        return {}
    for item in value:
        if isinstance(item, dict):
            return item
    return {}


def _wireguard_auto_group(config: dict[str, Any]) -> dict[str, Any]:
    endpoint_tags = {
        str(item.get("tag") or "").strip()
        for item in config.get("endpoints") or []
        if isinstance(item, dict)
        and str(item.get("type") or "").strip().lower() in {"wireguard", "warp"}
        and str(item.get("tag") or "").strip()
    }
    if not endpoint_tags:
        return {}
    groups = [item for item in config.get("outbounds") or [] if isinstance(item, dict)]
    route = config.get("route") if isinstance(config.get("route"), dict) else {}
    final_tag = str(route.get("final") or "").strip()
    groups.sort(key=lambda item: str(item.get("tag") or "") != final_tag)
    for group in groups:
        if str(group.get("type") or "").strip().lower() not in {"urltest", "url-test", "selector"}:
            continue
        refs = group.get("outbounds")
        if isinstance(refs, list) and endpoint_tags.intersection(str(ref or "").strip() for ref in refs):
            return group
    return {}


def _openvpn_auto_group(config: dict[str, Any]) -> dict[str, Any]:
    outbound_tags = {
        str(item.get("tag") or "").strip()
        for item in config.get("outbounds") or []
        if isinstance(item, dict)
        and str(item.get("type") or "").strip().lower() == "openvpn"
        and str(item.get("tag") or "").strip()
    }
    if not outbound_tags:
        return {}
    groups = [item for item in config.get("outbounds") or [] if isinstance(item, dict)]
    route = config.get("route") if isinstance(config.get("route"), dict) else {}
    final_tag = str(route.get("final") or "").strip()
    groups.sort(key=lambda item: str(item.get("tag") or "") != final_tag)
    for group in groups:
        if str(group.get("type") or "").strip().lower() not in {"urltest", "url-test", "selector"}:
            continue
        refs = group.get("outbounds")
        if isinstance(refs, list) and outbound_tags.intersection(str(ref or "").strip() for ref in refs):
            return group
    return {}


def _parse_hysteria(link: str) -> Node:
    parsed = urlsplit(link)
    query = parse_qs(parsed.query, keep_blank_values=True)
    params = {k: _first(query, k) for k in query}
    server = parsed.hostname or _get_param(params, "server", "address", "host")
    port = parsed.port or int(_get_param(params, "port", default="0") or 0) or 443
    auth = unquote(parsed.username or "") or _get_param(params, "auth", "auth_str", "authStr", "password")
    if not server or not auth:
        raise LinkParseError("hysteria link must contain server and auth/password")

    outbound: dict[str, Any] = {
        "type": "hysteria",
        "tag": "proxy",
        "server": server,
        "server_port": int(port),
    }
    if auth:
        outbound["auth_str"] = auth
    protocol = _get_param(params, "protocol")
    if protocol:
        outbound["protocol"] = protocol
    up_mbps = _get_param(params, "upmbps", "up_mbps", "up")
    down_mbps = _get_param(params, "downmbps", "down_mbps", "down")
    if up_mbps:
        outbound["up_mbps"] = int(up_mbps)
    if down_mbps:
        outbound["down_mbps"] = int(down_mbps)
    server_ports = _get_param(params, "server_ports", "server-ports", "ports")
    if server_ports:
        outbound["server_ports"] = [item.strip() for item in server_ports.split(",") if item.strip()]
    hop_interval = _get_param(params, "hop_interval", "hop-interval")
    if hop_interval:
        outbound["hop_interval"] = hop_interval
    for key in ("recv_window_conn", "recv-window-conn", "recv_window", "recv-window"):
        value = _get_param(params, key)
        if value:
            outbound[key.replace("-", "_")] = int(value)
    if _to_bool(_get_param(params, "disable_mtu_discovery", "disable-mtu-discovery")):
        outbound["disable_mtu_discovery"] = True
    _apply_hysteria_tls(outbound, params, server)
    _apply_hysteria_obfs(outbound, params)
    name = _clean_name(parsed.fragment, f"hysteria-{server}:{port}")
    return Node(name=name, scheme="hysteria", server=server, port=int(port), link=link, outbound=_native_singbox_outbound(outbound))


def _parse_hysteria2(link: str) -> Node:
    parsed = urlsplit(link)
    query = parse_qs(parsed.query, keep_blank_values=True)
    params = {k: _first(query, k) for k in query}
    server = parsed.hostname or _get_param(params, "server", "address", "host")
    port = parsed.port or int(_get_param(params, "port", default="0") or 0) or 443
    password = unquote(parsed.username or "") or _get_param(params, "password", "auth", "auth_str", "authStr")
    if not server or not password:
        raise LinkParseError("hysteria2 link must contain server and password")

    outbound: dict[str, Any] = {
        "type": "hysteria2",
        "tag": "proxy",
        "server": server,
        "server_port": int(port),
        "password": password,
    }
    server_ports = _get_param(params, "server_ports", "server-ports", "ports")
    if server_ports:
        outbound["server_ports"] = [item.strip() for item in server_ports.split(",") if item.strip()]
    hop_interval = _get_param(params, "hop_interval", "hop-interval")
    if hop_interval:
        outbound["hop_interval"] = hop_interval
    up_mbps = _get_param(params, "upmbps", "up_mbps", "up")
    down_mbps = _get_param(params, "downmbps", "down_mbps", "down")
    if up_mbps:
        outbound["up_mbps"] = int(up_mbps)
    if down_mbps:
        outbound["down_mbps"] = int(down_mbps)
    for key in ("recv_window_conn", "recv-window-conn", "recv_window", "recv-window"):
        value = _get_param(params, key)
        if value:
            outbound[key.replace("-", "_")] = int(value)
    if _to_bool(_get_param(params, "disable_mtu_discovery", "disable-mtu-discovery")):
        outbound["disable_mtu_discovery"] = True
    _apply_hysteria_tls(outbound, params, server)
    _apply_hysteria_obfs(outbound, params)
    name = _clean_name(parsed.fragment, f"hysteria2-{server}:{port}")
    return Node(name=name, scheme="hysteria2", server=server, port=int(port), link=link, outbound=_native_singbox_outbound(outbound))


def _parse_tuic(link: str) -> Node:
    # Разбор TUIC-ссылки: tuic://uuid:password@host:port?congestion_control=&udp_relay_mode=&sni=&alpn=#name
    parsed = urlsplit(link)
    query = parse_qs(parsed.query, keep_blank_values=True)
    params = {k: _first(query, k) for k in query}
    server = parsed.hostname or _get_param(params, "server", "address", "host")
    port = parsed.port or int(_get_param(params, "port", default="0") or 0) or 443
    uuid = unquote(parsed.username or "") or _get_param(params, "uuid", "id")
    password = unquote(parsed.password or "") or _get_param(params, "password", "passwd", "pass")
    if not server or not uuid:
        raise LinkParseError("tuic link must contain server and uuid")
    outbound: dict[str, Any] = {
        "type": "tuic",
        "tag": "proxy",
        "server": server,
        "server_port": int(port),
        "uuid": uuid,
    }
    if password:
        outbound["password"] = password
    congestion = _get_param(params, "congestion_control", "congestion", "cc")  # cubic/bbr/new_reno
    if congestion:
        outbound["congestion_control"] = congestion
    udp_relay = _get_param(params, "udp_relay_mode", "udp_relay", "udpRelayMode")  # native/quic
    if udp_relay:
        outbound["udp_relay_mode"] = udp_relay
    if _to_bool(_get_param(params, "zero_rtt_handshake", "zero_rtt", "reduce_rtt", default="")):
        outbound["zero_rtt_handshake"] = True
    _apply_hysteria_tls(outbound, params, server)  # переиспользуем TLS-хелпер (sni/alpn/insecure)
    name = _clean_name(parsed.fragment, f"tuic-{server}:{port}")
    return Node(name=name, scheme="tuic", server=server, port=int(port), link=link, outbound=_native_singbox_outbound(outbound))


def _parse_mieru(link: str) -> Node:
    parsed = urlsplit(link)
    query = parse_qs(parsed.query, keep_blank_values=True)
    params = {k: _first(query, k) for k in query}
    server = parsed.hostname or _get_param(params, "server", "address", "host")
    port = parsed.port or int(_get_param(params, "port", "server_port", default="0") or 0)
    username = unquote(parsed.username or "") or _get_param(params, "username", "user")
    password = unquote(parsed.password or "") or _get_param(params, "password", "pass")
    if not server or not username or not password:
        raise LinkParseError("mieru link must contain server, username and password")

    outbound: dict[str, Any] = {
        "type": "mieru",
        "tag": "proxy",
        "server": server,
        "transport": (_get_param(params, "transport", default="TCP") or "TCP").upper(),
        "username": username,
        "password": password,
    }
    if port:
        outbound["server_port"] = int(port)
    ports = _get_param(params, "server_ports", "ports")
    if ports:
        outbound["server_ports"] = [item.strip() for item in ports.split(",") if item.strip()]
    multiplexing = _get_param(params, "multiplexing", "mux")
    if multiplexing:
        outbound["multiplexing"] = multiplexing
    traffic_pattern = _get_param(params, "traffic_pattern", "trafficPattern")
    if traffic_pattern:
        outbound["traffic_pattern"] = traffic_pattern
    name = _clean_name(parsed.fragment, f"mieru-{server}:{port or 'range'}")
    return Node(name=name, scheme="mieru", server=server, port=int(port or 0), link=link, outbound=_native_singbox_outbound(outbound))


def _parse_anytls(link: str) -> Node:
    parsed = urlsplit(link)
    query = parse_qs(parsed.query, keep_blank_values=True)
    params = {key.lower(): _first(query, key) for key in query}
    server = str(parsed.hostname or "").strip()
    port = int(parsed.port or 443)
    password = unquote(parsed.username or "") or _get_param(params, "password")
    if not server or not password:
        raise LinkParseError("anytls link must contain server and password")
    tls: dict[str, Any] = {
        "enabled": True,
        "server_name": _get_param(params, "sni", "peer", "server_name", "servername", default=server),
    }
    if _to_bool(_get_param(params, "insecure", "allowinsecure", "allow_insecure")):
        tls["insecure"] = True
    pins = _get_param(
        params,
        "pinsha256",
        "certificate_public_key_sha256",
        "certificate-public-key-sha256",
        "certsha256",
    )
    if pins:
        tls["certificate_public_key_sha256"] = _split_csv(pins)
    alpn = _get_param(params, "alpn")
    if alpn:
        tls["alpn"] = _split_csv(alpn)
    native: dict[str, Any] = {
        "type": "anytls",
        "tag": "proxy",
        "server": server,
        "server_port": port,
        "password": password,
        "tls": tls,
    }
    for source, target in (
        ("idle_session_check_interval", "idle_session_check_interval"),
        ("idle-session-check-interval", "idle_session_check_interval"),
        ("idle_session_timeout", "idle_session_timeout"),
        ("idle-session-timeout", "idle_session_timeout"),
    ):
        if params.get(source):
            native[target] = params[source]
    min_idle = _get_param(params, "min_idle_session", "min-idle-session")
    if min_idle:
        try:
            native["min_idle_session"] = int(min_idle)
        except ValueError as exc:
            raise LinkParseError("AnyTLS min_idle_session must be an integer") from exc
    name = _clean_name(parsed.fragment, f"anytls-{server}:{port}")
    return Node(
        name=name,
        scheme="anytls",
        server=server,
        port=port,
        link=link,
        outbound=_native_singbox_outbound(native),
    )


def _parse_masque(link: str) -> Node:
    parsed = urlsplit(link)
    query = parse_qs(parsed.query, keep_blank_values=True)
    params = {k: _first(query, k) for k in query}
    profile_id = unquote(parsed.hostname or "") or _get_param(params, "id", "profile_id")
    auth_token = unquote(parsed.username or "") or _get_param(params, "auth_token", "token")
    outbound: dict[str, Any] = {
        "type": "masque",
        "tag": "proxy",
        "system": _to_bool(_get_param(params, "system", default="false")),
        "name": _get_param(params, "name", default="masque0") or "masque0",
        "use_http2": _to_bool(_get_param(params, "use_http2", "http2", default="false")),
        "use_ipv6": _to_bool(_get_param(params, "use_ipv6", "ipv6", default="false")),
        "profile": {"detour": "direct"},
        "udp_timeout": _get_param(params, "udp_timeout", "udpTimeout", default="5m0s") or "5m0s",
        "udp_keepalive_period": _get_param(
            params,
            "udp_keepalive_period",
            "udpKeepalivePeriod",
            default="30s",
        ) or "30s",
        "reconnect_delay": _get_param(params, "reconnect_delay", "reconnectDelay", default="5s") or "5s",
        "congestion_controller": _get_param(
            params,
            "congestion_controller",
            "congestionController",
            default="bbr",
        ) or "bbr",
    }
    if profile_id:
        outbound["profile"]["id"] = profile_id
    if auth_token:
        outbound["profile"]["auth_token"] = auth_token
    allowed_ips = _get_param(params, "allowed_ips", "allowedIPs")
    if allowed_ips:
        outbound["allowed_ips"] = _split_csv(allowed_ips)
    server_name = _get_param(params, "sni", "server_name", "serverName")
    insecure = _get_param(params, "insecure", "allowInsecure")
    if server_name or insecure:
        tls: dict[str, Any] = {}
        if server_name:
            tls["server_name"] = server_name
        if insecure:
            tls["insecure"] = _to_bool(insecure)
        outbound["tls"] = tls
    name = _clean_name(parsed.fragment, "MASQUE")
    return Node(name=name, scheme="masque", server=profile_id, port=0, link=link, outbound=_native_singbox_outbound(outbound))


def _apply_hysteria_tls(outbound: dict[str, Any], params: dict[str, str], server: str) -> None:
    tls: dict[str, Any] = {"enabled": True}
    sni = _get_param(params, "sni", "peer", "server_name", "serverName")
    if sni:
        tls["server_name"] = sni
    elif server:
        tls["server_name"] = server
    insecure = _get_param(params, "insecure", "allowInsecure")
    if insecure:
        tls["insecure"] = _to_bool(insecure)
    alpn = _get_param(params, "alpn")
    if alpn:
        tls["alpn"] = [item.strip() for item in alpn.split(",") if item.strip()]
    outbound["tls"] = tls


def _apply_hysteria_obfs(outbound: dict[str, Any], params: dict[str, str]) -> None:
    obfs_type = _get_param(params, "obfs", "obfs_type", "obfsType")
    obfs_password = _get_param(params, "obfs-password", "obfs_password", "obfsPassword", "obfs-pass", "obfsPass")
    if not obfs_type and not obfs_password:
        return
    if obfs_type == "none":
        return
    if str(outbound.get("type") or "") == "hysteria":
        outbound["obfs"] = obfs_password or obfs_type
        return
    outbound["obfs"] = {
        "type": obfs_type or "salamander",
        **({"password": obfs_password} if obfs_password else {}),  # salamander: пароль опционален
    }


def _parse_wireguard_like_link(link: str, scheme: str) -> Node:
    parsed = urlsplit(link)
    query = parse_qs(parsed.query, keep_blank_values=True)
    params = {k: _first(query, k) for k in query}

    if scheme == "warp":
        endpoint = _build_warp_endpoint(params)
        dns_servers = _split_csv(_get_param(params, "dns", "dns_servers"))
        outbound = _native_singbox_outbound(endpoint)
        if dns_servers:
            outbound["_dns"] = dns_servers
        name = _clean_name(parsed.fragment, "AWG/WARP" if endpoint.get("amnezia") else "WARP")
        return Node(name=name, scheme="warp", server="engage.cloudflareclient.com", port=2408, link=link, outbound=outbound, tags=["WARP"])

    server = parsed.hostname or _get_param(params, "server", "endpoint", "address")
    port = parsed.port or int(_get_param(params, "port", default="0") or 0) or 51820
    private_key = _clean_b64_key(unquote(parsed.username or "") or _get_param(params, "private_key", "privateKey", "key"))
    public_key = _clean_b64_key(_get_param(params, "public_key", "publicKey", "peer_public_key", "peerPublicKey", "pbk"))
    address = normalize_ip_prefixes(
        _split_csv(
            _get_param(
                params,
                "address",
                "addresses",
                "local_address",
                "localAddress",
                default="10.0.0.2/32",
            )
        )
    )
    allowed_ips = normalize_ip_prefixes(
        _split_csv(
            _get_param(
                params,
                "allowed_ips",
                "allowedIPs",
                "allowed",
                default="0.0.0.0/0,::/0",
            )
        )
    )
    pre_shared_key = _get_param(params, "pre_shared_key", "preshared_key", "psk")
    reserved = _parse_reserved_bytes(_get_param(params, "reserved"))
    keepalive = _get_param(
        params,
        "persistent_keepalive",
        "persistentKeepalive",
        "persistent_keepalive_interval",
        "keepalive",
    )
    mtu = int(_get_param(params, "mtu", default="1408") or 1408)

    if not private_key or not public_key or not server:
        raise LinkParseError("wireguard/awg link must contain server, private_key and public_key")

    amnezia = _amnezia_from_params(params)
    if (_is_warp_endpoint(server) or scheme == "warp") and reserved:
        endpoint = _build_warp_profile_endpoint(
            private_key=private_key,
            persistent_keepalive=keepalive,
            amnezia=amnezia,
            listen_port=_get_param(params, "listen_port", "listenPort"),
        )
    else:
        endpoint = _build_wireguard_endpoint(
            server=server,
            port=port,
            private_key=_clean_b64_key(private_key),
            public_key=_clean_b64_key(public_key),
            address=address,
            allowed_ips=allowed_ips,
            pre_shared_key=pre_shared_key,
            mtu=mtu,
            amnezia=amnezia,
            persistent_keepalive=keepalive,
            listen_port=_get_param(params, "listen_port", "listenPort"),
            udp_timeout=_get_param(
                params,
                "udp_timeout",
                "udpTimeout",
                default="5m0s",
            ),
            workers=_get_param(params, "workers"),
            preallocated_buffers_per_pool=_get_param(
                params,
                "preallocated_buffers_per_pool",
                "preallocatedBuffersPerPool",
            ),
            disable_pauses=_get_param(
                params,
                "disable_pauses",
                "disablePauses",
            ),
        )
    dns_servers = _split_csv(_get_param(params, "dns", "dns_servers"))
    outbound = _native_singbox_outbound(endpoint)
    if dns_servers:
        outbound["_dns"] = dns_servers
    name = _clean_name(
        parsed.fragment,
        _wireguard_display_name(server, port, bool(endpoint.get("amnezia")), scheme),
    )
    tags = ["WARP"] if _is_warp_endpoint(server) else []
    display_scheme = "awg" if amnezia else ("warp" if endpoint.get("type") == "warp" else scheme)
    return Node(name=name, scheme=display_scheme, server=server, port=port, link=link, outbound=outbound, tags=tags)


def _parse_wireguard_config(text: str) -> Node:
    interface: dict[str, str] = {}
    peers: list[dict[str, str]] = []
    current: dict[str, str] | None = None
    for raw_line in text.lstrip("\ufeff").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line.strip("[]").strip().lower()
            if section == "interface":
                current = interface
            elif section.startswith("peer"):
                current = {}
                peers.append(current)
            else:
                current = None
            continue
        if "=" not in line or current is None:
            continue
        key, value = line.split("=", 1)
        normalized_key = _canonical_wireguard_key(key)
        normalized_value = value.strip()
        if normalized_key in {"address", "allowedips", "dns"} and current.get(normalized_key):
            current[normalized_key] += "," + normalized_value
        else:
            current[normalized_key] = normalized_value

    private_key = interface.get("privatekey", "")
    if not peers or not private_key:
        raise LinkParseError("wireguard config must contain [Interface] PrivateKey and [Peer] Endpoint/PublicKey")

    parsed_peers: list[dict[str, Any]] = []
    first_server = ""
    first_port = 0
    for peer in peers:
        server, port = _split_endpoint(peer.get("endpoint", ""))
        public_key = peer.get("publickey", "")
        if not server or not public_key:
            raise LinkParseError("each [Peer] must contain Endpoint and PublicKey")
        if not first_server:
            first_server, first_port = server, port or 51820
        parsed_peers.append(
            _build_wireguard_peer(
                server=server,
                port=port or 51820,
                public_key=public_key,
                allowed_ips=normalize_ip_prefixes(
                    _split_csv(peer.get("allowedips", "0.0.0.0/0,::/0"))
                ),
                pre_shared_key=peer.get("presharedkey", ""),
                persistent_keepalive=peer.get("persistentkeepalive", ""),
            )
        )

    amnezia = _amnezia_from_params({key: value for key, value in interface.items()})
    reserved = _parse_reserved_bytes(
        interface.get("reserved") or peers[0].get("reserved") or ""
    )
    if _is_warp_endpoint(first_server) and reserved:
        endpoint = _build_warp_profile_endpoint(
            private_key=private_key,
            persistent_keepalive=peers[0].get("persistentkeepalive", ""),
            amnezia=amnezia,
            listen_port=interface.get("listenport", ""),
        )
    else:
        endpoint = {
            "type": "wireguard",
            "tag": "proxy",
            "mtu": int(interface.get("mtu", "1408") or 1408),
            "address": normalize_ip_prefixes(
                _split_csv(interface.get("address", "10.0.0.2/32"))
            ),
            "private_key": _clean_b64_key(private_key),
            "peers": parsed_peers,
            "udp_timeout": interface.get("udptimeout", "5m0s") or "5m0s",
        }
        if interface.get("listenport"):
            endpoint["listen_port"] = int(interface["listenport"])
        if amnezia:
            endpoint["amnezia"] = amnezia
        _apply_wireguard_performance_options(
            endpoint,
            workers=interface.get("workers", ""),
            preallocated_buffers_per_pool=interface.get(
                "preallocatedbuffersperpool",
                "",
            ),
            disable_pauses=interface.get("disablepauses"),
        )
    scheme = "awg" if amnezia else ("warp" if endpoint.get("type") == "warp" else "wireguard")
    outbound = _native_singbox_outbound(endpoint)
    dns_servers = _split_csv(interface.get("dns", ""))
    if dns_servers:
        outbound["_dns"] = dns_servers
    protocol_masking = {
        key: interface[key]
        for key in ("id", "ip", "ib")
        if str(interface.get(key) or "").strip()
    }
    if protocol_masking:
        # sing-box-extended currently has no Id/Ip/Ib schema.  Preserve the
        # source values outside the native endpoint instead of silently
        # destroying them or passing unknown fields to the strict decoder.
        outbound["_protocol_masking"] = protocol_masking
    return Node(
        name=_wireguard_display_name(first_server, first_port, bool(amnezia), scheme),
        scheme=scheme,
        server=first_server,
        port=first_port,
        link=text,
        outbound=outbound,
        tags=["WARP"] if _is_warp_endpoint(first_server) else [],
    )


def _build_warp_endpoint(params: dict[str, str]) -> dict[str, Any]:
    endpoint: dict[str, Any] = {
        "type": "warp",
        "tag": "proxy",
        "udp_timeout": _get_param(params, "udp_timeout", "udpTimeout", default="5m0s") or "5m0s",
    }
    listen_port = _get_param(params, "listen_port", "listenPort")
    if listen_port:
        endpoint["listen_port"] = int(listen_port)
    amnezia = _amnezia_from_params(params)
    if amnezia:
        endpoint["amnezia"] = amnezia
    # `reserved` is validated but never emitted: sing-box-extended 2.5.1+ rejects
    # the field on WARP endpoints and derives the bytes from the profile itself.
    _parse_reserved_bytes(_get_param(params, "reserved"))
    keepalive = _get_param(
        params,
        "persistent_keepalive",
        "persistentKeepalive",
        "persistent_keepalive_interval",
        "keepalive",
    )
    if keepalive:
        endpoint["persistent_keepalive_interval"] = int(keepalive)
    profile: dict[str, Any] = {"detour": "direct"}
    for source, target in (("id", "id"), ("private_key", "private_key"), ("privateKey", "private_key"), ("auth_token", "auth_token"), ("authToken", "auth_token")):
        value = _get_param(params, source)
        if value:
            profile[target] = value
    endpoint["profile"] = profile
    return endpoint


def _wireguard_display_name(server: str, port: int, amnezia: bool, scheme: str = "wireguard") -> str:
    return f"{server}:{int(port or 51820)}"


def _is_warp_endpoint(server: str) -> bool:
    host = str(server or "").strip().lower().strip(".")
    if host == "engage.cloudflareclient.com" or host.endswith(".cloudflareclient.com"):
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return any(
        address in network
        for network in (
            ipaddress.ip_network("162.159.192.0/24"),
            ipaddress.ip_network("162.159.193.0/24"),
            ipaddress.ip_network("162.159.195.0/24"),
            ipaddress.ip_network("188.114.96.0/20"),
            ipaddress.ip_network("2606:4700:d0::/48"),
            ipaddress.ip_network("2606:4700:d1::/48"),
        )
    )


def _build_wireguard_endpoint(
    *,
    server: str,
    port: int,
    private_key: str,
    public_key: str,
    address: list[str],
    allowed_ips: list[str],
    pre_shared_key: str = "",
    mtu: int = 1408,
    amnezia: dict[str, Any] | None = None,
    persistent_keepalive: Any = "",
    listen_port: Any = "",
    udp_timeout: Any = "5m0s",
    workers: Any = "",
    preallocated_buffers_per_pool: Any = "",
    disable_pauses: Any = None,
) -> dict[str, Any]:
    peer = _build_wireguard_peer(
        server=server,
        port=port,
        public_key=public_key,
        allowed_ips=allowed_ips,
        pre_shared_key=pre_shared_key,
        persistent_keepalive=persistent_keepalive,
    )
    endpoint: dict[str, Any] = {
        "type": "wireguard",
        "tag": "proxy",
        "mtu": int(mtu or 1408),
        "address": normalize_ip_prefixes(address or ["10.0.0.2/32"]),
        "private_key": _clean_b64_key(private_key),
        "peers": [peer],
        "udp_timeout": str(udp_timeout or "5m0s").strip() or "5m0s",
    }
    if listen_port not in (None, ""):
        endpoint["listen_port"] = int(listen_port)
    if amnezia:
        endpoint["amnezia"] = amnezia
    _apply_wireguard_performance_options(
        endpoint,
        workers=workers,
        preallocated_buffers_per_pool=preallocated_buffers_per_pool,
        disable_pauses=disable_pauses,
    )
    return endpoint


def _apply_wireguard_performance_options(
    endpoint: dict[str, Any],
    *,
    workers: Any = "",
    preallocated_buffers_per_pool: Any = "",
    disable_pauses: Any = None,
) -> None:
    """Apply the extra userspace options exposed by sing-box-extended."""
    if workers not in (None, ""):
        endpoint["workers"] = int(workers)
    if preallocated_buffers_per_pool not in (None, ""):
        endpoint["preallocated_buffers_per_pool"] = int(preallocated_buffers_per_pool)
    if disable_pauses not in (None, ""):
        endpoint["disable_pauses"] = _to_bool(disable_pauses)


def _build_wireguard_peer(
    *,
    server: str,
    port: int,
    public_key: str,
    allowed_ips: list[str],
    pre_shared_key: str = "",
    persistent_keepalive: Any = "",
) -> dict[str, Any]:
    peer: dict[str, Any] = {
        "address": server,
        "port": int(port),
        "public_key": _clean_b64_key(public_key),
        "allowed_ips": normalize_ip_prefixes(allowed_ips or ["0.0.0.0/0", "::/0"]),
    }
    if pre_shared_key:
        peer["pre_shared_key"] = _clean_b64_key(pre_shared_key)
    if persistent_keepalive not in (None, ""):
        peer["persistent_keepalive_interval"] = int(persistent_keepalive)
    return peer


def _build_warp_profile_endpoint(
    *,
    private_key: str,
    persistent_keepalive: Any = "",
    amnezia: dict[str, Any] | None = None,
    listen_port: Any = "",
) -> dict[str, Any]:
    endpoint: dict[str, Any] = {
        "type": "warp",
        "tag": "proxy",
        "udp_timeout": "5m0s",
        "profile": {"detour": "direct", "private_key": _clean_b64_key(private_key)},
    }
    if listen_port not in (None, ""):
        endpoint["listen_port"] = int(listen_port)
    if persistent_keepalive not in (None, ""):
        endpoint["persistent_keepalive_interval"] = int(persistent_keepalive)
    if amnezia:
        endpoint["amnezia"] = amnezia
    return endpoint


def _canonical_wireguard_key(value: str) -> str:
    return re.sub(r"[\s_-]+", "", str(value or "").strip().lower())


def _parse_reserved_bytes(value: Any) -> list[int]:
    if value in (None, "", [], ()):
        return []
    if isinstance(value, (list, tuple)):
        parts = list(value)
    else:
        text = str(value).strip().strip("[]")
        parts = [part for part in re.split(r"[\s,;]+", text) if part]
        if len(parts) == 1:
            encoded = parts[0].replace("-", "+").replace("_", "/")
            try:
                decoded = base64.b64decode(
                    encoded + "=" * (-len(encoded) % 4),
                    validate=True,
                )
            except (ValueError, TypeError):
                decoded = b""
            if len(decoded) == 3:
                return list(decoded)
    try:
        result = [int(part) for part in parts]
    except (TypeError, ValueError) as exc:
        raise LinkParseError("wireguard reserved must contain three bytes") from exc
    if len(result) != 3 or any(item < 0 or item > 255 for item in result):
        raise LinkParseError("wireguard reserved must contain three bytes")
    return result


def _validate_awg3_header_key(value: str) -> str:
    """Validate HeaderProtectionKey as a base64 encoded 32-byte key."""
    text = str(value or "").strip()
    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise LinkParseError(
            f"некорректный HeaderProtectionKey: ожидается base64 ключ длиной 32 байта"
        ) from exc
    if len(raw) != 32:
        raise LinkParseError(
            f"некорректный HeaderProtectionKey: {len(raw)} байт вместо 32"
        )
    return text


def _validate_awg3_range(value: str, field: str) -> int | str:
    """Validate an AWG 3.0 uint32 value or an inclusive ``A-B`` range."""
    text = str(value or "").strip()
    # Restrict to ASCII digits: ``str.isdigit`` accepts Unicode superscripts
    # which ``int`` cannot parse consistently across Python versions.
    if re.fullmatch(r"[0-9]+", text):
        number = int(text)
        if number > _AWG_UINT32_MAX:
            raise LinkParseError(f"слишком большое значение в поле {field}: {value}")
        return number
    match = _AWG_RANGE_RE.fullmatch(text)
    if match is None:
        raise LinkParseError(
            f"некорректный диапазон в поле {field}: {value} (ожидается число или A-B)"
        )
    low, high = int(match.group(1)), int(match.group(2))
    if high > _AWG_UINT32_MAX or low > high:
        raise LinkParseError(f"некорректный диапазон в поле {field}: {value}")
    return f"{low}-{high}"


def _is_xray_auto_config_payload(payload: Any) -> bool:
    """Recognize full Xray configs whose balancer must not be split into nodes."""
    if not isinstance(payload, dict):
        return False
    outbounds = payload.get("outbounds")
    if not isinstance(outbounds, list) or not any(
        isinstance(item, dict) and str(item.get("protocol") or "").strip()
        for item in outbounds
    ):
        return False
    if isinstance(payload.get("observatory"), dict):
        return True
    routing = payload.get("routing")
    if not isinstance(routing, dict):
        return False
    if isinstance(routing.get("balancers"), list) and bool(routing["balancers"]):
        return True
    rules = routing.get("rules")
    return isinstance(rules, list) and any(
        isinstance(rule, dict) and str(rule.get("balancerTag") or "").strip()
        for rule in rules
    )


def _native_xray_config(payload: dict[str, Any]) -> dict[str, Any]:
    name = _json_name(payload, "AUTO")
    return {
        "protocol": "xray_config",
        "tag": name,
        "xray_config": dict(payload),
    }


def _amnezia_from_params(params: dict[str, str]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key in ("jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4", "itime"):
        value = _get_param(params, key, key.upper())
        if value:
            try:
                result[key] = int(value)
            except ValueError:
                result[key] = value
    for key in ("i1", "i2", "i3", "i4", "i5", "j1", "j2", "j3"):
        value = _get_param(params, key, key.upper())
        if value:
            result[key] = value
    header_key = _get_param(
        params,
        "header_protection_key",
        "header-protection-key",
        "headerprotectionkey",
        "headerProtectionKey",
        "HeaderProtectionKey",
    )
    if header_key:
        result["header_protection_key"] = _validate_awg3_header_key(header_key)
    for source_key, json_key in _AMNEZIA_AWG3_RANGE_KEYS.items():
        value = _get_param(
            params,
            source_key,
            source_key.replace("_", ""),
            _AMNEZIA_AWG3_DASH_NAMES[source_key],
            _AMNEZIA_AWG3_CONF_NAMES[source_key],
            json_key,
        )
        if value:
            result[json_key] = _validate_awg3_range(
                value, _AMNEZIA_AWG3_CONF_NAMES[source_key]
            )
    return result


def _split_csv(value: str) -> list[str]:
    return [item.strip() for item in str(value or "").split(",") if item.strip()]


def _clean_b64_key(value: str) -> str:
    return str(value or "").strip().replace(" ", "+")
