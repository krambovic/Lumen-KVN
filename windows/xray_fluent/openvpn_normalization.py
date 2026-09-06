from __future__ import annotations

from typing import Any


DATA_CIPHERS = {
    "AES-128-GCM", "AES-192-GCM", "AES-256-GCM",
    "AES-128-CBC", "AES-192-CBC", "AES-256-CBC",
    "CHACHA20-POLY1305",
}
AUTH_DIGESTS = {"MD5", "SHA1", "SHA256", "SHA384", "SHA512"}

_GO_TLS_CIPHER_SUITES = {
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
}
_OPENSSL_TLS_ALIASES = {
    "ECDHE-ECDSA-AES128-SHA": "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    "ECDHE-ECDSA-AES256-SHA": "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    "ECDHE-RSA-AES128-SHA": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "ECDHE-RSA-AES256-SHA": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "ECDHE-ECDSA-AES128-GCM-SHA256": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384": "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "ECDHE-RSA-AES128-GCM-SHA256": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "ECDHE-RSA-AES256-GCM-SHA384": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "ECDHE-RSA-CHACHA20-POLY1305": "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "ECDHE-ECDSA-CHACHA20-POLY1305": "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
}


def normalize_data_cipher(value: object) -> str:
    normalized = str(value or "").strip().upper()
    return normalized if normalized in DATA_CIPHERS else ""


def normalize_auth_digest(value: object) -> str:
    normalized = str(value or "").strip().upper()
    return normalized if normalized in AUTH_DIGESTS else ""


def normalize_tls_cipher_suite(value: object) -> str:
    normalized = str(value or "").strip().upper()
    if not normalized:
        return ""
    if normalized in _GO_TLS_CIPHER_SUITES:
        return normalized
    if normalized in _OPENSSL_TLS_ALIASES:
        return _OPENSSL_TLS_ALIASES[normalized]
    iana = normalized.replace("-", "_")
    return iana if iana in _GO_TLS_CIPHER_SUITES else ""


def normalize_tls_cipher_suites(value: object) -> list[str]:
    if isinstance(value, (list, tuple, set)):
        raw_values = [str(item) for item in value]
    elif value in (None, ""):
        raw_values = []
    else:
        raw_values = [str(value)]
    result: list[str] = []
    for raw in raw_values:
        for candidate in raw.split(":"):
            normalized = normalize_tls_cipher_suite(candidate)
            if normalized and normalized not in result:
                result.append(normalized)
    return result


def normalize_openvpn_outbound(outbound: dict[str, Any]) -> None:
    """Apply the compatibility contract of the bundled extended OpenVPN core."""
    if str(outbound.get("type") or "").strip().lower() != "openvpn":
        return

    proto = str(outbound.get("proto") or "").strip().lower()
    if not proto:
        outbound["proto"] = "tcp"
    elif proto in {"tcp", "tcp-client", "tcp4", "tcp4-client", "tcp6", "tcp6-client"}:
        outbound["proto"] = "tcp"
    elif proto in {"udp", "udp4", "udp6"}:
        raise ValueError(
            "OpenVPN over UDP is not supported by this core; re-import the profile using its TCP remote"
        )
    else:
        raise ValueError(f"Unsupported OpenVPN transport `{proto}`")

    raw_cipher = str(outbound.get("cipher") or "").strip()
    cipher = normalize_data_cipher(raw_cipher)
    if cipher:
        outbound["cipher"] = cipher
    elif raw_cipher:
        raise ValueError(f"Unsupported OpenVPN data cipher `{raw_cipher}`")
    raw_auth = str(outbound.get("auth") or "").strip()
    auth = normalize_auth_digest(raw_auth)
    if auth:
        outbound["auth"] = auth
    elif raw_auth:
        raise ValueError(f"Unsupported OpenVPN auth digest `{raw_auth}`")

    tls = outbound.get("tls")
    if isinstance(tls, dict):
        raw_suites = tls.get("cipher_suites")
        suites = normalize_tls_cipher_suites(raw_suites)
        if suites:
            tls["cipher_suites"] = suites
        elif raw_suites not in (None, "", [], (), set()):
            raise ValueError("Unsupported OpenVPN TLS cipher suite")
        verify_mode = str(tls.get("verify_x509_name_mode") or "").strip().lower()
        if verify_mode == "exact":
            verify_mode = "name"
            tls["verify_x509_name_mode"] = verify_mode
        if verify_mode == "subject":
            raise ValueError(
                "OpenVPN verify-x509-name mode `subject` is not supported by the bundled core"
            )
        if verify_mode and verify_mode not in {"name", "name-prefix", "name-suffix"}:
            raise ValueError(f"Invalid OpenVPN verify-x509-name mode `{verify_mode}`")

    if str(outbound.get("tls_auth") or "").strip() and "key_direction" not in outbound:
        outbound["key_direction"] = -1


def openvpn_private_key_is_encrypted(outbound: dict[str, Any]) -> bool:
    tls = outbound.get("tls") if isinstance(outbound.get("tls"), dict) else {}
    private_key = str(tls.get("key") or "").upper()
    return "ENCRYPTED PRIVATE KEY" in private_key or (
        "PROC-TYPE:" in private_key and "ENCRYPTED" in private_key
    )
