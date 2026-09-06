from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field
import hashlib
import hmac
import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, quote, unquote, urlparse

from PyQt6.QtCore import QTimer

from ..constants import APP_VERSION, SUBSCRIPTION_PARSER_REVISION
from ..country_flags import detect_country
from ..data_paths import get_install_id
from ..happ_crypt import HappDecryptError, decrypt_happ_link, is_happ_crypt_link, is_happ_link
from ..link_parser import normalize_node_outbound, parse_links_text, validate_node_outbound
from ..models import DEFAULT_SUBSCRIPTION_HWID, Node
from ..subscription_fetcher import (
    SubscriptionFetcherCancelled,
    fetch_subscription_http,
)

if TYPE_CHECKING:
    from ..app_controller import AppController


MAX_SUBSCRIPTION_BYTES = 8 * 1024 * 1024
HAPP_WINDOWS_USER_AGENT = "Happ/2.18.3/Windows/2606241603601"
# Lumen's own subscription User-Agent; the Android build sends the same shape
# with an "Android-" platform tag.
LUMEN_SUBSCRIPTION_USER_AGENT = f"Lumen-Subscription/Windows-{APP_VERSION}"


@dataclass(slots=True)
class SubscriptionPayloadResult:
    """Network result used by the worker and conditional subscription updates."""

    text: str = ""
    userinfo: dict = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    status: int = 0
    not_modified: bool = False


# Parameters documented by Happ for premium subscriptions.  Keep the original
# kebab-case names in persisted metadata so providers and users can see exactly
# what the subscription requested, including platform-specific options.
HAPP_PREMIUM_PARAMETERS: tuple[str, ...] = (
    "new-url",
    "new-domain",
    "subscription-always-hwid-enable",
    "notification-subs-expire",
    "hide-settings",
    "server-address-resolve-enable",
    "server-address-resolve-dns-domain",
    "server-address-resolve-dns-ip",
    "subscription-autoconnect",
    "subscription-autoconnect-type",
    "subscription-ping-onopen-enabled",
    "subscription-auto-update-enable",
    "fragmentation-enable",
    "fragmentation-packets",
    "fragmentation-length",
    "fragmentation-interval",
    "ping-type",
    "check-url-via-proxy",
    "change-user-agent",
    "app-auto-start",
    "subscription-auto-update-open-enable",
    "per-app-proxy-mode",
    "per-app-proxy-list",
    "sniffing-enable",
    "subscriptions-collapse",
    "ping-result",
    "mux-enable",
    "mux-tcp-connections",
    "mux-xudp-connections",
    "mux-quic",
    "exclude-routes",
)
_HAPP_BODY_METADATA_KEYS = {
    "providerid",
    "provider-id",
    "profile-title",
    "support-url",
    "profile-web-page-url",
    "telegram-url",
    "announce",
    "announce-url",
    "subscription-name",
    "profile-description",
    "announcement",
    "announcement-url",
    "telegram",
    "support",
    "support-email",
    "homepage",
    "premium-url",
    "banner-text",
    "banner-button-text",
    "banner-button-url",
    "banner-bg-color",
    "banner-button-color",
    "hide-url",
    "sort-order",
    "profile-update-interval",
    *HAPP_PREMIUM_PARAMETERS,
}


@lru_cache(maxsize=1)
def _windows_machine_guid() -> str:
    """Return the raw Windows installation identifier without spawning a process."""
    try:
        import winreg
    except ImportError:
        return ""

    access = winreg.KEY_READ
    view_flags = [getattr(winreg, "KEY_WOW64_64KEY", 0), 0]
    for view_flag in dict.fromkeys(view_flags):
        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Cryptography",
                0,
                access | view_flag,
            ) as key:
                raw_value, _ = winreg.QueryValueEx(key, "MachineGuid")
        except OSError:
            continue
        value = str(raw_value or "").strip().strip("{}")
        if not value or "\r" in value or "\n" in value:
            continue
        try:
            return str(uuid.UUID(value))
        except ValueError:
            return value[:256]
    return ""


@lru_cache(maxsize=1)
def _windows_machine_hwid() -> str:
    """Return an app-scoped device id for subscription providers.

    MachineGuid is an OS-wide installation identifier shared with every other
    program on the machine, so it is never sent verbatim: the value handed to a
    provider is HMAC-SHA256(MachineGuid) keyed with the random per-install id.
    It stays stable for this install (what panels bind licences to) without
    being correlatable with fingerprints collected by unrelated software.
    """
    machine_guid = _windows_machine_guid()
    if not machine_guid:
        return ""
    key = get_install_id().encode("utf-8")
    digest = hmac.new(key, machine_guid.encode("utf-8"), hashlib.sha256).digest()
    return str(uuid.UUID(bytes=digest[:16]))


def _resolve_subscription_hwid(hwid: str, *, use_real_hwid: bool) -> str:
    if use_real_hwid:
        machine_hwid = _windows_machine_hwid()
        if machine_hwid:
            return machine_hwid
    return str(hwid or DEFAULT_SUBSCRIPTION_HWID).strip()


class SubscriptionFetchCancelled(RuntimeError):
    pass


def _raise_if_subscription_cancelled(cancelled=None) -> None:
    if cancelled is not None and cancelled():
        raise SubscriptionFetchCancelled("загрузка подписки отменена")


def import_nodes_from_text(
    controller: AppController,
    text: str,
    *,
    group: str | None = None,
    auto_connect: bool | None = None,
    select_imported: bool = False,
) -> tuple[int, list[str]]:
    # User-initiated import (paste / drag-drop / "open file" dialog). This is the
    # only entry point where `text` may legitimately be a local filesystem path,
    # so it is the only one that enables file references; every subscription path
    # below parses remote, untrusted bodies and must keep the secure default.
    nodes, errors = parse_links_text(text, allow_file_reference=True)
    if not nodes:
        return 0, errors

    previous_selected_id = controller.state.selected_node_id
    existing_nodes = {
        (node.link, (node.group or "Default").strip().casefold())
        for node in controller.state.nodes
        if node.link
    }
    max_order = max((node.sort_order for node in controller.state.nodes), default=0)
    first_new_id: str | None = None
    added = 0
    for node in nodes:
        normalize_node_outbound(node)
        problem = validate_node_outbound(node)
        if problem:
            errors.append(problem)
            continue
        effective_group = str(group if group is not None else (node.group or "Default")).strip() or "Default"
        identity = (node.link, effective_group.casefold())
        if node.link and identity in existing_nodes:
            continue
        node.group = effective_group
        if not node.country_code:
            node.country_code = detect_country(node.name, node.server)
        max_order += 1
        node.sort_order = max_order
        controller.state.nodes.append(node)
        if node.link:
            existing_nodes.add(identity)
        if first_new_id is None:
            first_new_id = node.id
        added += 1

    if first_new_id and select_imported:
        controller.state.selected_node_id = first_new_id

    selection_changed = controller.state.selected_node_id != previous_selected_id
    if selection_changed:
        controller._reset_auto_switch_state(reset_cooldown=True, reset_cycle=True)

    controller.nodes_changed.emit(controller.state.nodes)
    controller.selection_changed.emit(controller.selected_node)
    controller.save()
    QTimer.singleShot(500, controller._start_country_ip_resolution)

    should_auto_connect = (
        controller.state.settings.auto_connect_on_import
        if auto_connect is None
        else auto_connect
    )
    should_reconcile_running = auto_connect is not False and selection_changed and (
        controller.connected or controller._desired_connected
    )
    if added and (should_auto_connect or should_reconcile_running):
        controller._desired_connected = True
        controller._request_transition("new node imported")

    return added, errors


def remove_nodes(controller: AppController, node_ids: set[str]) -> None:
    if not node_ids:
        return
    removed_selected = controller.state.selected_node_id in node_ids
    should_reconcile = removed_selected and (controller.connected or controller._desired_connected)
    controller.state.nodes = [node for node in controller.state.nodes if node.id not in node_ids]
    if removed_selected:
        controller.state.selected_node_id = controller.state.nodes[0].id if controller.state.nodes else None
        controller._reset_auto_switch_state(reset_cooldown=True, reset_cycle=True)
    controller.nodes_changed.emit(controller.state.nodes)
    controller.selection_changed.emit(controller.selected_node)
    controller.save()
    if not should_reconcile:
        return
    if controller.state.selected_node_id is None:
        if controller._can_connect_without_selected_node():
            controller._request_transition("active node removed")
            return
        controller._desired_connected = False
        controller._request_transition("active node removed")
        return
    controller._desired_connected = True
    controller._request_transition("active node removed")


def update_node(controller: AppController, node_id: str, updates: dict) -> bool:
    node = controller._get_node_by_id(node_id)
    if not node:
        return False
    if "name" in updates:
        node.name = updates["name"]
    if "group" in updates:
        node.group = updates["group"]
    if "scheme" in updates:
        node.scheme = str(updates["scheme"] or "")
    if "server" in updates:
        node.server = str(updates["server"])
    if "port" in updates:
        node.port = int(updates["port"] or 0)
    if "outbound" in updates and isinstance(updates["outbound"], dict):
        node.outbound = dict(updates["outbound"])
    if "link" in updates:
        node.link = str(updates["link"] or "")
    controller.nodes_changed.emit(controller.state.nodes)
    controller.save()
    if controller.connected or controller._desired_connected:
        controller._request_transition("node updated")
    return True


def add_manual_node(controller: AppController, node: Node) -> str:
    """Validate and persist a node assembled by the protocol-aware editor."""
    normalize_node_outbound(node)
    problem = validate_node_outbound(node)
    if problem:
        raise ValueError(problem)

    node.group = str(node.group or "Default").strip() or "Default"
    node.name = str(node.name or node.server or node.scheme or "Server").strip()
    if not node.country_code:
        node.country_code = detect_country(node.name, node.server)
    node.sort_order = max(
        (item.sort_order for item in controller.state.nodes),
        default=0,
    ) + 1
    controller.state.nodes.append(node)
    controller.nodes_changed.emit(controller.state.nodes)
    controller.save()
    QTimer.singleShot(500, controller._start_country_ip_resolution)
    return node.id


def bulk_update_nodes(controller: AppController, node_ids: set[str], operations: dict) -> int:
    group = operations.get("group", "")
    updated = 0
    for node in controller.state.nodes:
        if node.id not in node_ids:
            continue
        if group:
            node.group = group
        updated += 1
    if updated:
        controller.nodes_changed.emit(controller.state.nodes)
        controller.save()
    return updated


def get_all_groups(controller: AppController) -> list[str]:
    groups = {node.group for node in controller.state.nodes if node.group}
    groups.update(
        str(group).strip()
        for group in getattr(controller.state, "manual_groups", [])
        if str(group).strip()
    )
    other_groups = {
        str(group).strip()
        for group in groups
        if str(group).strip() and str(group).strip().casefold() != "default"
    }
    return ["Default", *sorted(other_groups, key=str.lower)]


def delete_group(controller: AppController, group: str) -> bool:
    """Delete a user group together with its nodes and linked subscriptions."""
    name = str(group or "").strip()
    if not name or name.casefold() == "default":
        return False
    key = name.casefold()

    subscriptions = list(getattr(controller.state, "subscriptions", []))
    removed_subscriptions = [
        item
        for item in subscriptions
        if str(item.get("group") or item.get("name") or "").strip().casefold() == key
    ]
    removed_subscription_ids = {
        str(item.get("id") or "").strip()
        for item in removed_subscriptions
        if str(item.get("id") or "").strip()
    }
    if removed_subscriptions:
        controller.state.subscriptions = [item for item in subscriptions if item not in removed_subscriptions]
        controller.subscriptions_changed.emit(list(controller.state.subscriptions))

    manual_groups = list(getattr(controller.state, "manual_groups", []))
    controller.state.manual_groups = [
        item for item in manual_groups if str(item or "").strip().casefold() != key
    ]
    node_ids = {
        node.id
        for node in controller.state.nodes
        if (node.group or "Default").strip().casefold() == key
        or (node.subscription_id and node.subscription_id in removed_subscription_ids)
    }
    changed = bool(removed_subscriptions or node_ids or len(manual_groups) != len(controller.state.manual_groups))
    if node_ids:
        remove_nodes(controller, node_ids)
    elif changed:
        controller.save()
    return changed


def reorder_nodes(controller: AppController, node_id: str, direction: str) -> None:
    ordered = sorted(controller.state.nodes, key=lambda node: node.sort_order)
    idx = next((i for i, node in enumerate(ordered) if node.id == node_id), None)
    if idx is None:
        return
    if direction == "up" and idx > 0:
        ordered[idx], ordered[idx - 1] = ordered[idx - 1], ordered[idx]
    elif direction == "down" and idx < len(ordered) - 1:
        ordered[idx], ordered[idx + 1] = ordered[idx + 1], ordered[idx]
    elif direction == "top" and idx > 0:
        node = ordered.pop(idx)
        ordered.insert(0, node)
    elif direction == "bottom" and idx < len(ordered) - 1:
        node = ordered.pop(idx)
        ordered.append(node)
    else:
        return
    for index, node in enumerate(ordered):
        node.sort_order = index + 1
    controller.nodes_changed.emit(controller.state.nodes)
    controller.save()


def set_selected_node(controller: AppController, node_id: str) -> None:
    if controller.state.selected_node_id == node_id:
        return
    controller.state.selected_node_id = node_id
    controller._reset_auto_switch_state(reset_cooldown=True, reset_cycle=True)
    controller.selection_changed.emit(controller.selected_node)
    controller.schedule_save()
    if controller.connected or controller._desired_connected:
        controller._desired_connected = True
        controller._request_transition("node switched")


# --- Подписки (subscriptions) ---------------------------------------------


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _decode_subscription_bytes(raw: bytes) -> str:
    """Decode provider text while tolerating legacy Windows/Chinese encodings."""
    for encoding in ("utf-8", "cp1251", "gb18030", "latin-1"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


def _maybe_base64_decode(text: str) -> str:
    """Подписки часто отдают base64-блоб со списком ссылок."""
    if "://" in text:
        return ""
    compact = "".join(text.split())
    if not compact:
        return ""
    for decoder in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            padded = compact + "=" * (-len(compact) % 4)
            decoded = _decode_subscription_bytes(decoder(padded))
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
        if "://" in decoded:
            return decoded
    return ""


def _parse_userinfo_header(value: str) -> dict:
    """Разбирает заголовок subscription-userinfo: upload=..; download=..; total=..; expire=.."""
    info: dict = {}
    if not value:
        return info
    for part in re.split(r"[;,]", value):
        if "=" not in part:
            continue
        key, _, raw = part.partition("=")
        key = key.strip().lower()
        raw = raw.strip()
        if not key:
            continue
        try:
            number = int(raw)
        except (TypeError, ValueError):
            continue
        if key == "expire":
            number = _normalize_expire_seconds(number)
        if number >= 0:
            info[key] = number
    return info


def _normalize_expire_seconds(value: object) -> int:
    """Normalize seconds/milliseconds/microseconds to a valid Unix timestamp."""
    try:
        expire = int(value)
    except (TypeError, ValueError):
        return 0
    if expire <= 0:
        return 0
    max_seconds = 253_402_300_799
    while expire > max_seconds:
        expire //= 1000
    return expire


def _subscription_web_url(value: object, *, telegram: bool = False) -> str:
    text = str(value or "").strip()
    if not text or len(text) > 2048 or any(char.isspace() for char in text):
        return ""
    if telegram and text.startswith("@") and len(text) > 1:
        text = f"https://t.me/{text[1:]}"
    parsed = urlparse(text)
    if not parsed.scheme and parsed.path and "." in parsed.path:
        host = parsed.path.split("/", 1)[0]
        if not host or host.startswith(".") or host.endswith("."):
            return ""
        text = f"https://{text}"
        parsed = urlparse(text)
    if parsed.scheme.lower() not in ({"http", "https", "tg"} if telegram else {"http", "https"}):
        return ""
    return text if (parsed.netloc or parsed.scheme.lower() == "tg") else ""


def _subscription_hex_color(value: object) -> str:
    text = str(value or "").strip()
    match = re.fullmatch(r"#?([0-9A-Fa-f]{6})", text)
    return f"#{match.group(1).upper()}" if match else ""


def _subscription_flag(value: object) -> bool | None:
    text = str(value or "").strip().lower()
    if text in {"1", "true", "yes", "on", "enabled"}:
        return True
    if text in {"0", "false", "no", "off", "disabled"}:
        return False
    return None


def _extract_userinfo_from_body(text: str) -> tuple[str, dict]:
    """Если тело — JSON вида {"user": {...}, "links": [...]}, достаёт инфо и ссылки."""
    stripped = (text or "").strip()
    if not stripped.startswith("{"):
        return text, {}
    try:
        data = json.loads(stripped)
    except (ValueError, TypeError):
        return text, {}
    if not isinstance(data, dict):
        return text, {}
    info: dict = {}
    user = data.get("user")
    if isinstance(user, dict):
        info = {str(k): v for k, v in user.items()}
    elif isinstance(data.get("userStatus"), str) or "username" in data:
        info = {str(k): v for k, v in data.items() if k != "links"}
    if "expire" in info:
        info["expire"] = _normalize_expire_seconds(info.get("expire"))
    for key in (
        "profileTitle",
        "subscriptionName",
        "supportUrl",
        "profileUrl",
        "telegramUrl",
        "announcement",
        "announcementUrl",
        "providerId",
        "profileUpdateInterval",
        "profileDescription",
        "supportEmail",
        "premiumUrl",
        "bannerText",
        "bannerButtonText",
        "bannerButtonUrl",
        "bannerBgColor",
        "bannerButtonColor",
        "hideUrl",
        "sortOrder",
    ):
        if key in data and data.get(key) not in (None, ""):
            info[key] = data.get(key)
    for key, telegram in (
        ("supportUrl", False),
        ("profileUrl", False),
        ("telegramUrl", True),
        ("announcementUrl", False),
        ("premiumUrl", False),
        ("bannerButtonUrl", False),
    ):
        if key in info:
            normalized_url = _subscription_web_url(info.get(key), telegram=telegram)
            if normalized_url:
                info[key] = normalized_url
            else:
                info.pop(key, None)
    for key in ("bannerBgColor", "bannerButtonColor"):
        if key in info:
            color = _subscription_hex_color(info.get(key))
            if color:
                info[key] = color
            else:
                info.pop(key, None)
    premium = data.get("premiumFeatures")
    if isinstance(premium, dict):
        info["premiumFeatures"] = {str(key): str(value) for key, value in premium.items()}
    direct_premium = {
        key: str(data.get(key))
        for key in HAPP_PREMIUM_PARAMETERS
        if data.get(key) not in (None, "")
    }
    if direct_premium:
        info["premiumFeatures"] = {
            **dict(info.get("premiumFeatures") or {}),
            **direct_premium,
        }
    links = data.get("links")
    if isinstance(links, list) and links:
        links_text = "\n".join(str(item) for item in links if item)
        return links_text, info
    return text, info


def _merge_subscription_info(*parts: dict | None) -> dict:
    result: dict = {}
    premium: dict[str, str] = {}
    for part in parts:
        if not isinstance(part, dict):
            continue
        nested = part.get("premiumFeatures")
        if isinstance(nested, dict):
            premium.update({str(key): str(value) for key, value in nested.items()})
        result.update({key: value for key, value in part.items() if key != "premiumFeatures"})
    if premium:
        result["premiumFeatures"] = premium
    return result


def _extract_happ_body_metadata(text: str) -> tuple[str, dict]:
    """Extract Happ directives from ``#key value`` subscription comments."""
    if not text or "#" not in text:
        return text, {}
    kept: list[str] = []
    premium: dict[str, str] = {}
    info: dict = {}
    for line in text.splitlines():
        match = re.match(r"^\s*#\s*([A-Za-z0-9_-]+)\s*:?[ \t]*(.*?)\s*$", line)
        if not match:
            kept.append(line)
            continue
        key = match.group(1).strip().lower().replace("_", "-")
        value = match.group(2).strip()
        if key not in _HAPP_BODY_METADATA_KEYS:
            kept.append(line)
            continue
        if key in HAPP_PREMIUM_PARAMETERS:
            premium[key] = value
        elif key in {"providerid", "provider-id"}:
            info["providerId"] = value
        elif key in {"profile-title", "subscription-name"}:
            info["profileTitle"] = _decode_profile_header(value)
        elif key == "profile-description":
            info["profileDescription"] = _decode_profile_header(value)
        elif key in {"support-url", "support"}:
            info["supportUrl"] = _subscription_web_url(value)
        elif key in {"profile-web-page-url", "homepage"}:
            info["profileUrl"] = _subscription_web_url(value)
        elif key in {"telegram-url", "telegram"}:
            info["telegramUrl"] = _subscription_web_url(value, telegram=True)
        elif key in {"announce", "announcement"}:
            info["announcement"] = _decode_profile_header(value)
        elif key in {"announce-url", "announcement-url"}:
            info["announcementUrl"] = _subscription_web_url(value)
        elif key == "support-email":
            email = re.sub(r"^mailto:", "", value, flags=re.IGNORECASE).strip()
            if len(email) <= 254 and re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
                info["supportEmail"] = email
        elif key in {"premium-url", "banner-button-url"}:
            info[{"premium-url": "premiumUrl", "banner-button-url": "bannerButtonUrl"}[key]] = _subscription_web_url(value)
        elif key in {"banner-bg-color", "banner-button-color"}:
            color = _subscription_hex_color(value)
            if color:
                info[{"banner-bg-color": "bannerBgColor", "banner-button-color": "bannerButtonColor"}[key]] = color
        elif key in {"banner-text", "banner-button-text", "sort-order", "profile-update-interval"}:
            target_key = {
                "banner-text": "bannerText",
                "banner-button-text": "bannerButtonText",
                "sort-order": "sortOrder",
                "profile-update-interval": "profileUpdateInterval",
            }[key]
            normalized_value = value.lower() if key == "sort-order" else value
            if key != "sort-order" or normalized_value in {"ping", "name", "none"}:
                info[target_key] = normalized_value
        elif key == "hide-url":
            flag = _subscription_flag(value)
            if flag is not None:
                info["hideUrl"] = flag
    if premium:
        info["premiumFeatures"] = premium
    return "\n".join(kept), info


def _metadata_from_subscription_url(url: str) -> dict:
    parsed = urlparse(str(url or "").strip())
    values: dict[str, list[str]] = {}
    for raw in (parsed.query, parsed.fragment.lstrip("?")):
        if raw:
            values.update(parse_qs(raw, keep_blank_values=True))
    lowered = {str(key).lower().replace("_", "-"): items for key, items in values.items()}
    for key in ("providerid", "provider-id"):
        items = lowered.get(key)
        if items and str(items[0]).strip():
            return {"providerId": str(items[0]).strip()}
    return {}


def _subscription_name_from_info(info: dict | None) -> str:
    if not isinstance(info, dict):
        return ""
    for key in ("profileTitle", "subscriptionName", "name", "title"):
        value = str(info.get(key) or "").strip()
        if value:
            return value[:160]
    return ""


def _premium_subscription_url(url: str, info: dict | None) -> str:
    premium = info.get("premiumFeatures") if isinstance(info, dict) else None
    if not isinstance(premium, dict):
        return url
    replacement = str(premium.get("new-url") or "").strip()
    if replacement:
        parsed = urlparse(replacement)
        if parsed.scheme == "https" and parsed.netloc:
            return replacement
    new_domain = str(premium.get("new-domain") or "").strip()
    if new_domain:
        domain = urlparse("//" + new_domain).netloc
        source = urlparse(url)
        if domain and source.scheme in {"http", "https"}:
            return source._replace(netloc=domain).geturl()
    return url


def _migrate_subscription_url(controller: AppController, old_url: str, new_url: str) -> bool:
    if not new_url or new_url == old_url:
        return False
    if _find_subscription(controller, new_url) is not None:
        return False
    old_id = _subscription_id(controller, old_url)
    new_id = str(uuid.uuid5(uuid.NAMESPACE_URL, new_url.strip()))
    for node in controller.state.nodes:
        if node.subscription_id == old_id:
            node.subscription_id = new_id
    existing = _find_subscription(controller, old_url)
    if existing is not None:
        existing["url"] = new_url
        existing["id"] = new_id
    return True


# Lumen asks as itself first; the compatibility profiles below are only walked
# when the panel makes clear it does not accept the Lumen client (empty body, no
# usable servers, a "client not supported" stub or a profile dependent status).
_SUBSCRIPTION_CLIENT_PROFILES: tuple[tuple[str, dict[str, str]], ...] = (
    (
        "Lumen",
        {
            "User-Agent": LUMEN_SUBSCRIPTION_USER_AGENT,
            "Accept": "text/yaml,application/yaml,application/json,text/plain,*/*",
            "Profile-Update-Interval": "24",
        },
    ),
    (
        "Happ Windows",
        {
            "User-Agent": HAPP_WINDOWS_USER_AGENT,
            "Accept": "*/*",
            "Accept-Language": "ru-RU,en,*",
            "Profile-Update-Interval": "24",
            "X-App-Version": "2.18.3",
            "X-Device-Locale": "RU",
            "X-Device-Model": "Windows_x86_64",
            "X-Device-Os": "Windows",
            "X-Hwid": DEFAULT_SUBSCRIPTION_HWID,
            "X-Ver-Os": "11_10.0.26200",
        },
    ),
    (
        "SFA",
        {
            "User-Agent": "SFA/1.11.0",
            "Accept": "application/json,*/*",
            "Profile-Update-Interval": "24",
        },
    ),
    (
        "v2rayNG",
        {
            "User-Agent": "v2rayNG/1.10.29",
            "Accept": "application/json,text/plain,*/*",
            "Profile-Update-Interval": "24",
        },
    ),
    (
        "Streisand",
        {
            "User-Agent": "Streisand/1.6.54",
            "Accept": "application/json,text/plain,*/*",
            "Profile-Update-Interval": "24",
        },
    ),
    (
        "Clash Verge",
        {
            "User-Agent": "ClashVerge/2.0.0",
            "Accept": "text/yaml,application/yaml,*/*",
            "Profile-Update-Interval": "24",
        },
    ),
    (
        "Clash Meta",
        {
            "User-Agent": "clash.meta",
            "Accept": "text/yaml,application/yaml,*/*",
            "Profile-Update-Interval": "24",
        },
    ),
    (
        "FlClashX",
        {
            "User-Agent": "FlClashX/1.0",
            "Accept": "text/yaml,application/yaml,*/*",
            "Profile-Update-Interval": "24",
        },
    ),
    (
        "Happ",
        {
            "User-Agent": HAPP_WINDOWS_USER_AGENT,
            "Accept": "*/*",
            "Profile-Update-Interval": "24",
        },
    ),
)


def _decode_profile_header(value: str) -> str:
    text = str(value or "").strip()
    if text.lower().startswith("base64:"):
        raw = text.split(":", 1)[1].strip()
        for decoder in (base64.urlsafe_b64decode, base64.b64decode):
            try:
                decoded = decoder(raw + "=" * (-len(raw) % 4)).decode("utf-8", errors="strict").strip()
            except (binascii.Error, ValueError, UnicodeDecodeError):
                continue
            if decoded:
                return decoded[:512]
        return text[:512]
    return text[:512]


def _extract_subscription_metadata(headers: object, profile_name: str) -> dict:
    info: dict = {"clientProfile": profile_name}
    try:
        profile_title = _decode_profile_header(
            _first_header(headers, "profile-title", "profile_title", "subscription-name", "subscription_name")
        )
        profile_description = _decode_profile_header(
            _first_header(headers, "profile-description", "profile_description")
        )
        support_url = _first_header(headers, "support-url", "support_url", "support-link", "support")
        profile_url = _first_header(
            headers,
            "profile-web-page-url",
            "profile-url",
            "profile_url",
            "panel-url",
            "panel_url",
            "sub-web-page-url",
            "subscription-url",
        )
        telegram_url = _first_header(headers, "telegram-url", "telegram_url", "telegram-link", "telegram")
        announcement = _decode_profile_header(_first_header(headers, "announce", "announcement"))
        announcement_url = _first_header(headers, "announce-url", "announcement-url")
        provider_id = _first_header(headers, "providerid", "provider-id", "provider_id")
        update_interval = _first_header(headers, "profile-update-interval")
        content_disposition = _first_header(headers, "content-disposition")
        support_email = _first_header(headers, "support-email", "support_email")
        premium_url = _first_header(headers, "premium-url", "premium_url")
        banner_text = _decode_profile_header(_first_header(headers, "banner-text", "banner_text"))
        banner_button_text = _decode_profile_header(
            _first_header(headers, "banner-button-text", "banner_button_text")
        )
        banner_button_url = _first_header(headers, "banner-button-url", "banner_button_url")
        banner_bg_color = _first_header(headers, "banner-bg-color", "banner_bg_color")
        banner_button_color = _first_header(headers, "banner-button-color", "banner_button_color")
        hide_url = _first_header(headers, "hide-url", "hide_url")
        sort_order = _first_header(headers, "sort-order", "sort_order").lower()
    except Exception:
        return info
    if not profile_title and content_disposition:
        filename_match = re.search(
            r"filename\*?=(?:UTF-8''|\")?([^\";]+)",
            content_disposition,
            flags=re.IGNORECASE,
        )
        if filename_match:
            candidate = unquote(filename_match.group(1)).strip().strip('"')
            candidate = re.sub(r"\.(?:ya?ml|json|txt|conf)$", "", candidate, flags=re.IGNORECASE)
            if candidate.lower() not in {"config", "subscription", "download"} and not candidate.isdigit():
                profile_title = candidate[:160]
    if profile_title:
        info["profileTitle"] = profile_title
    if profile_description:
        info["profileDescription"] = profile_description
    if sanitized := _subscription_web_url(support_url):
        info["supportUrl"] = sanitized
    if sanitized := _subscription_web_url(profile_url):
        info["profileUrl"] = sanitized
    if sanitized := _subscription_web_url(telegram_url, telegram=True):
        info["telegramUrl"] = sanitized
    if announcement:
        info["announcement"] = announcement
    if sanitized := _subscription_web_url(announcement_url):
        info["announcementUrl"] = sanitized
    if provider_id:
        info["providerId"] = provider_id
    if update_interval:
        info["profileUpdateInterval"] = update_interval
    support_email = re.sub(r"^mailto:", "", support_email, flags=re.IGNORECASE).strip()
    if len(support_email) <= 254 and re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", support_email):
        info["supportEmail"] = support_email
    if sanitized := _subscription_web_url(premium_url):
        info["premiumUrl"] = sanitized
    if banner_text:
        info["bannerText"] = banner_text
    if banner_button_text:
        info["bannerButtonText"] = banner_button_text
    if sanitized := _subscription_web_url(banner_button_url):
        info["bannerButtonUrl"] = sanitized
    if color := _subscription_hex_color(banner_bg_color):
        info["bannerBgColor"] = color
    if color := _subscription_hex_color(banner_button_color):
        info["bannerButtonColor"] = color
    if (flag := _subscription_flag(hide_url)) is not None:
        info["hideUrl"] = flag
    if sort_order in {"ping", "name", "none"}:
        info["sortOrder"] = sort_order
    premium = {
        key: _first_header(headers, key, key.replace("-", "_"))
        for key in HAPP_PREMIUM_PARAMETERS
    }
    premium = {key: value for key, value in premium.items() if value != ""}
    if premium:
        info["premiumFeatures"] = premium
    return info


def _first_header(headers: object, *names: str) -> str:
    for name in names:
        try:
            value = str(headers.get(name, "") or "").strip()
        except Exception:
            value = ""
        if value:
            return value
    return ""


def _fetch_subscription_with_headers(
    url: str,
    profile_name: str,
    headers: dict[str, str],
    *,
    direct: bool = True,
    proxy_url: str = "",
    cancelled=None,
    response_opened=None,
    response_closed=None,
    response_meta: dict[str, object] | None = None,
) -> tuple[str, dict]:
    """Загружает подписку и возвращает (текст_со_ссылками, userinfo).

    userinfo берётся из HTTP-заголовка subscription-userinfo и/или из JSON-тела.
    При ``direct=True`` системный/ENV-прокси отключён, а сборка использует
    одноразовый helper-процесс и физический маршрут. При ``direct=False``
    запрос идёт через переданный локальный proxy либо через обычный системный
    сетевой стек, который перехватывается активным TUN.
    """
    _raise_if_subscription_cancelled(cancelled)
    try:
        response = fetch_subscription_http(
            url,
            dict(headers),
            timeout=20,
            max_bytes=MAX_SUBSCRIPTION_BYTES,
            use_proxy_tun=not direct,
            proxy_url=proxy_url,
            cancelled=cancelled,
            response_opened=response_opened,
            response_closed=response_closed,
        )
    except SubscriptionFetcherCancelled as exc:
        raise SubscriptionFetchCancelled(str(exc)) from exc
    if response_meta is not None:
        response_meta.clear()
        response_meta.update(
            {
                "status": int(getattr(response, "status", 0) or 0),
                "headers": dict(getattr(response, "headers", {}) or {}),
                "transport": str(getattr(response, "transport", "") or ""),
            }
        )
        # SubscriptionHttpPayload keeps normalized headers; use those when
        # available so callers can reliably look up ETag/Last-Modified.
        payload_headers = getattr(response, "headers", None)
        if isinstance(payload_headers, dict):
            response_meta["headers"] = {
                str(key).lower(): str(value)
                for key, value in payload_headers.items()
            }
        response_meta["status"] = int(getattr(response, "status", 0) or 0)
        response_meta["transport"] = str(getattr(response, "transport", "") or "")
    effective_url = str(response.headers.get("x-lumen-effective-url") or url).strip()
    if urlparse(url).scheme.lower() == "https" and urlparse(effective_url).scheme.lower() != "https":
        raise RuntimeError("Subscription redirect from HTTPS to an insecure URL was blocked")
    raw = response.body
    header_value = response.headers.get("subscription-userinfo", "")
    metadata = _extract_subscription_metadata(response.headers, profile_name)
    userinfo = _merge_subscription_info(_parse_userinfo_header(header_value), metadata)
    text = raw.decode("utf-8", errors="replace").strip()
    text, directive_info = _extract_happ_body_metadata(text)
    # JSON-тело (например, формат с {"user": {...}, "links": [...]}).
    text, body_info = _extract_userinfo_from_body(text)
    # Данные из тела приоритетнее заголовка.
    userinfo = _merge_subscription_info(userinfo, directive_info, body_info, metadata)
    if int(getattr(response, "status", 0) or 0) == 304:
        # A conditional hit deliberately has no body.  The outer fetch loop
        # recognizes this marker and never replaces the existing node snapshot.
        userinfo["_lumen_not_modified"] = True
        return "", userinfo
    decoded = _maybe_base64_decode(text)
    return (decoded or text), userinfo


def _fetch_subscription(url: str, *, user_agent: str = LUMEN_SUBSCRIPTION_USER_AGENT) -> tuple[str, dict]:
    return _fetch_subscription_with_headers(url, "Lumen", {"User-Agent": user_agent, "Accept": "*/*"})


def _fetch_subscription_happ(url: str) -> tuple[str, dict]:
    return _fetch_subscription_with_headers(
        url,
        "Happ Windows",
        {"User-Agent": HAPP_WINDOWS_USER_AGENT, "Accept": "*/*"},
    )


def _is_permanent_subscription_error(exc: BaseException) -> bool:
    """404/410 не зависят от профиля клиента — перебирать User-Agent бессмысленно."""
    match = re.search(r"http error\s+(\d{3})", str(exc).lower())
    return bool(match) and int(match.group(1)) in {404, 410}


def _is_tls_eof_error(exc: BaseException) -> bool:
    text = str(exc).lower()
    return (
        "tls/ssl connection has been closed" in text
        or "_ssl.c:1010" in text
        or "unexpected eof" in text
        or "eof occurred in violation of protocol" in text
    )


def _subscription_proxy_tun_hint(use_proxy_tun: bool) -> str:
    if use_proxy_tun:
        return (
            "Загрузка через прокси/TUN уже включена — проверьте подключение Lumen "
            "или временно отключите эту настройку."
        )
    return (
        "Попробуйте включить «Загружать подписки через прокси/TUN» "
        "в Настройки → Подписки."
    )


def _friendly_subscription_fetch_error(exc: BaseException, *, use_proxy_tun: bool) -> str | None:
    raw = str(exc or "").strip()
    low = raw.casefold()
    hint = _subscription_proxy_tun_hint(use_proxy_tun)

    if any(
        token in low
        for token in (
            "getaddrinfo failed",
            "errno 11001",
            "name or service not known",
            "nodename nor servname provided",
            "no address associated with hostname",
            "temporary failure in name resolution",
            "eai_again",
            "eai_noname",
        )
    ):
        return f"Не удалось определить адрес сервера подписки: ошибка DNS. Проверьте системный DNS. {hint}"

    if "certificate verify failed" in low or "cert_verify_failed" in low:
        return (
            "Не удалось проверить TLS-сертификат сервера подписки. "
            "Проверьте дату и время Windows, а также правильность ссылки подписки."
        )

    http_match = re.search(r"http error\s+(\d{3})", low)
    if http_match:
        status = int(http_match.group(1))
        if status == 401:
            return "Сервер подписки отклонил авторизацию (HTTP 401). Проверьте ссылку, HWID и срок подписки."
        if status == 403:
            return f"Сервер подписки запретил доступ (HTTP 403). Проверьте ссылку и HWID. {hint}"
        if status == 404:
            return "Подписка не найдена (HTTP 404). Возможно, ссылка устарела или была удалена."
        if status == 429:
            return "Сервер подписки временно ограничил частоту запросов (HTTP 429). Повторите позже."
        if 500 <= status <= 599:
            return f"Сервер подписки временно недоступен (HTTP {status}). Повторите попытку позже."

    if any(token in low for token in ("timed out", "timeout", "winerror 10060")):
        return f"Сервер подписки не ответил вовремя: превышено время ожидания. {hint}"
    if any(
        token in low
        for token in (
            "winerror 10054",
            "connection reset",
            "forcibly closed",
            "принудительно разорвал",
            "connection aborted",
        )
    ):
        return f"Соединение с сервером подписки было принудительно разорвано. {hint}"
    if any(token in low for token in ("winerror 10061", "connection refused")):
        return f"Сервер подписки отклонил соединение. {hint}"
    if any(
        token in low
        for token in (
            "winerror 10051",
            "winerror 10065",
            "network is unreachable",
            "no route to host",
            "physical internet interface",
            "физический интернет-интерфейс",
            "direct network",
        )
    ):
        return f"Не удалось построить прямой маршрут к серверу подписки. {hint}"
    if _is_tls_eof_error(exc) or any(
        token in low for token in ("ssl eof", "tls handshake", "wrong version number")
    ):
        return f"Защищённое соединение с сервером подписки было прервано во время TLS-обмена. {hint}"
    if "tunnel connection failed" in low or "proxy error" in low:
        return f"Прокси/TUN не смог подключиться к серверу подписки. {hint}"
    return None


def _append_subscription_fetch_error(
    attempts: list[str],
    profile_name: str,
    exc: BaseException,
    *,
    use_proxy_tun: bool,
) -> None:
    friendly = _friendly_subscription_fetch_error(exc, use_proxy_tun=use_proxy_tun)
    message = friendly or f"{profile_name}: {exc}"
    if message not in attempts:
        attempts.append(message)


def _parsed_nodes_are_usable(nodes: list) -> bool:
    for node in nodes:
        normalize_node_outbound(node)
        if validate_node_outbound(node) is None:
            return True
    return False


_SUBSCRIPTION_PLACEHOLDER_MARKERS: tuple[str, ...] = (
    "client not supported",
    "client is not supported",
    "unsupported client",
    "app not supported",
    "unsupported app",
    "application is not supported",
    "update your app",
    "update your client",
    "use another client",
    "клиент не поддерживается",
    "неподдерживаемый клиент",
    "приложение не поддерживается",
    "обновите приложение",
    "обновите клиент",
    "используйте другой клиент",
)


def _looks_like_client_stub(text: str, nodes: list) -> bool:
    """Ответ-заглушка вида «ваш клиент не поддерживается» вместо самой подписки."""
    if len(nodes) > 2:
        return False
    raw = str(text or "")
    if not raw.strip():
        return True
    try:
        haystack = f"{raw}\n{unquote(raw)}".casefold()
    except Exception:
        haystack = raw.casefold()
    return any(marker in haystack for marker in _SUBSCRIPTION_PLACEHOLDER_MARKERS)


def _subscription_response_is_accepted(text: str, nodes: list) -> bool:
    """Панель приняла текущий профиль клиента и вернула настоящую подписку."""
    if not nodes or not _parsed_nodes_are_usable(nodes):
        return False
    return not _looks_like_client_stub(text, nodes)


def _subscription_reject_reason(text: str, nodes: list, errors: list[str]) -> str:
    if nodes and _parsed_nodes_are_usable(nodes) and _looks_like_client_stub(text, nodes):
        return "панель вернула заглушку «клиент не поддерживается»"
    return "; ".join((_node_validation_errors(nodes) or errors or [])[:2]) or "нет подходящих серверов"


def _node_validation_errors(nodes: list) -> list[str]:
    errors: list[str] = []
    seen: set[str] = set()
    for node in nodes:
        normalize_node_outbound(node)
        problem = validate_node_outbound(node)
        if problem and problem not in seen:
            errors.append(problem)
            seen.add(problem)
    return errors


def _derive_subscription_name(url: str) -> str:
    if is_happ_link(url):
        return "Подписка Happ"
    host = urlparse(url).hostname or ""
    host = host.strip()
    if host:
        return f"Подписка {host}"
    return "Подписка"


def _happ_direct_payload(decrypted: str) -> tuple[str, dict, list[str]]:
    """Оформляет расшифрованное тело happ-подписки (список ссылок / base64 / JSON)."""
    text, directive_info = _extract_happ_body_metadata(decrypted)
    text, body_info = _extract_userinfo_from_body(text)
    merged_info = _merge_subscription_info({"clientProfile": "Happ"}, directive_info, body_info)
    text = _maybe_base64_decode(text) or text
    nodes, errors = parse_links_text(text)
    if nodes and _parsed_nodes_are_usable(nodes):
        return text, merged_info, errors
    detail = "; ".join((_node_validation_errors(nodes) or errors)[:2]) or "нет подходящих серверов"
    return "", merged_info, [f"Happ: {detail}"]


def _find_subscription(controller: AppController, url: str) -> dict | None:
    for sub in getattr(controller.state, "subscriptions", []):
        if sub.get("url") == url:
            return sub
    return None


def _subscription_id(controller: AppController, url: str) -> str:
    subscription = _find_subscription(controller, url)
    if subscription is not None:
        value = str(subscription.get("id") or "").strip()
        if value:
            return value
    return str(uuid.uuid5(uuid.NAMESPACE_URL, url.strip()))


def _subscription_source_key(node: Node) -> str:
    """Build a stable identity for one provider entry.

    Provider ordering, display names and insignificant URI formatting change
    frequently.  The protocol/server/port plus canonical outbound is stable
    enough to reconcile snapshots while still distinguishing real replacements.
    """
    existing = str(getattr(node, "source_key", "") or "").strip()
    if existing:
        return existing
    payload = {
        "scheme": str(node.scheme or "").strip().lower(),
        "server": str(node.server or "").strip().lower(),
        "port": int(node.port or 0),
        "outbound": node.outbound if isinstance(node.outbound, dict) else {},
    }
    encoded = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _subscription_fallback_key(node: Node) -> tuple[str, str, int, str]:
    return (
        str(node.scheme or "").strip().lower(),
        str(node.server or "").strip().lower(),
        int(node.port or 0),
        str(node.name or "").strip().casefold(),
    )


def _mark_subscription_fetch_metadata(
    subscription: dict,
    *,
    headers: dict[str, str] | None = None,
    status: int = 0,
    success: bool = False,
    not_modified: bool = False,
    error: str = "",
) -> None:
    """Persist validators/timestamps and bounded exponential retry backoff."""
    now = _utc_now_iso()
    normalized_headers = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    if normalized_headers.get("etag"):
        subscription["etag"] = normalized_headers["etag"]
    if normalized_headers.get("last-modified"):
        subscription["last_modified"] = normalized_headers["last-modified"]
    subscription["last_checked_at"] = now
    subscription["parser_revision"] = SUBSCRIPTION_PARSER_REVISION
    subscription["last_status"] = int(status or 0)
    if success or not_modified:
        subscription["last_success_at"] = now
        subscription["failure_count"] = 0
        subscription["backoff_until"] = ""
        subscription["last_error"] = ""
        return
    if error:
        try:
            failures = max(0, int(subscription.get("failure_count") or 0)) + 1
        except (TypeError, ValueError):
            failures = 1
        subscription["failure_count"] = failures
        # 15m, 30m, 60m ... capped at six hours; Retry-After is handled by
        # callers as a status-specific error but never disables manual retry.
        delay_minutes = min(360, 15 * (2 ** min(failures - 1, 5)))
        subscription["backoff_until"] = (
            datetime.fromisoformat(now) + timedelta(minutes=delay_minutes)
        ).isoformat()
        subscription["last_error"] = str(error)[:500]


def _fetch_with_optional_meta(
    url: str,
    profile_name: str,
    headers: dict[str, str],
    *,
    response_meta: dict[str, object],
    **options,
) -> tuple[str, dict]:
    """Call the fetch helper while keeping compatibility with test/providers.

    A few integrations monkeypatch the old helper signature.  Falling back
    only for an unexpected ``response_meta`` keyword keeps those callers
    working without hiding real network/type errors.
    """
    try:
        return _fetch_subscription_with_headers(
            url,
            profile_name,
            headers,
            response_meta=response_meta,
            **options,
        )
    except TypeError as exc:
        if "response_meta" not in str(exc):
            raise
        return _fetch_subscription_with_headers(url, profile_name, headers, **options)


def fetch_subscription_payload(
    url: str,
    *,
    user_agent: str = "",
    hwid: str = DEFAULT_SUBSCRIPTION_HWID,
    use_real_hwid: bool = True,
    use_proxy_tun: bool = False,
    proxy_url: str = "",
    converter_url: str = "",
    cancelled=None,
    response_opened=None,
    response_closed=None,
    cache_etag: str = "",
    cache_last_modified: str = "",
    response_meta: dict[str, object] | None = None,
) -> tuple[str, dict, list[str]]:
    """Загружает подписку по сети и возвращает (текст_ссылок, userinfo, errors).

    Только сеть, не трогает controller/state — безопасно вызывать в фоновом потоке.
    При неудаче текст пустой, а ошибки лежат в errors.
    """
    url = (url or "").strip()
    _raise_if_subscription_cancelled(cancelled)
    if not url:
        return "", {}, ["Пустой URL подписки"]
    # Закрытые ссылки Happ (happ://crypt*): сначала расшифровываем. Результат —
    # либо реальный URL подписки (грузим ниже штатно), либо готовый текст ссылок.
    if is_happ_crypt_link(url):
        try:
            decrypted = decrypt_happ_link(url).strip()
        except HappDecryptError as exc:
            return "", {}, [f"Happ: {exc}"]
        if not decrypted:
            return "", {}, ["Happ: пустой результат расшифровки"]
        if decrypted.lower().startswith("https://"):
            url = decrypted
        elif decrypted.lower().startswith("http://"):
            return "", {}, ["Happ: URL подписки внутри crypt-ссылки должен использовать HTTPS"]
        else:
            return _happ_direct_payload(decrypted)
    if converter_url:
        try:
            url = _subscription_converter_target(converter_url, url)
        except ValueError as exc:
            return "", {}, [str(exc)]
    attempts: list[str] = []
    first_userinfo: dict = {}
    fetch_options = {"direct": not use_proxy_tun}
    if proxy_url:
        fetch_options["proxy_url"] = str(proxy_url).strip()
    if cancelled is not None:
        fetch_options["cancelled"] = cancelled
    if response_opened is not None:
        fetch_options["response_opened"] = response_opened
    if response_closed is not None:
        fetch_options["response_closed"] = response_closed
    request_hwid = _resolve_subscription_hwid(hwid, use_real_hwid=use_real_hwid)
    if "\r" in request_hwid or "\n" in request_hwid:
        return "", {}, ["HWID не должен содержать переносы строк"]
    if len(request_hwid) > 256:
        return "", {}, ["HWID не должен быть длиннее 256 символов"]
    profiles = [
        (profile_name, {**headers, "X-Hwid": request_hwid})
        for profile_name, headers in _SUBSCRIPTION_CLIENT_PROFILES
    ]
    custom_user_agent = str(user_agent or "").strip()
    if custom_user_agent:
        profiles.insert(
            0,
            (
                "Custom",
                {
                    "User-Agent": custom_user_agent,
                    "Accept": "text/yaml,application/yaml,application/json,*/*",
                    "Profile-Update-Interval": "24",
                    "X-Hwid": request_hwid,
                },
            ),
        )
    validators = {
        "If-None-Match": str(cache_etag or "").strip(),
        "If-Modified-Since": str(cache_last_modified or "").strip(),
    }
    if any(validators.values()):
        for _profile_name, profile_headers in profiles:
            for key, value in validators.items():
                if value:
                    profile_headers[key] = value
    request_meta: dict[str, object] = {}
    for profile_name, headers in profiles:
        _raise_if_subscription_cancelled(cancelled)
        try:
            request_meta.clear()
            text, userinfo = _fetch_with_optional_meta(
                url,
                profile_name,
                headers,
                response_meta=request_meta,
                **fetch_options,
            )
            if response_meta is not None:
                response_meta.clear()
                response_meta.update(request_meta)
            userinfo = _merge_subscription_info(_metadata_from_subscription_url(url), userinfo)
            network_path = "proxy-tun" if use_proxy_tun else "direct"
            userinfo = {**userinfo, "networkPath": network_path}
            if userinfo and not first_userinfo:
                first_userinfo = dict(userinfo)
            if userinfo.get("_lumen_not_modified") or int(request_meta.get("status") or 0) == 304:
                userinfo = dict(userinfo)
                userinfo["_lumen_not_modified"] = True
                return "", userinfo, []
            nodes, errors = parse_links_text(text)
            if _subscription_response_is_accepted(text, nodes):
                return text, userinfo, errors
            attempts.append(f"{profile_name}: {_subscription_reject_reason(text, nodes, errors)}")
        except SubscriptionFetchCancelled:
            raise
        except Exception as exc:  # noqa: BLE001 - пробуем следующий профиль клиента
            if _is_tls_eof_error(exc):
                try:
                    request_meta.clear()
                    text, userinfo = _fetch_with_optional_meta(
                        url,
                        profile_name,
                        headers,
                        response_meta=request_meta,
                        **fetch_options,
                    )
                    if response_meta is not None:
                        response_meta.clear()
                        response_meta.update(request_meta)
                    userinfo = _merge_subscription_info(_metadata_from_subscription_url(url), userinfo)
                    network_path = "proxy-tun" if use_proxy_tun else "direct"
                    userinfo = {**userinfo, "networkPath": network_path}
                    if userinfo and not first_userinfo:
                        first_userinfo = dict(userinfo)
                    if userinfo.get("_lumen_not_modified") or int(request_meta.get("status") or 0) == 304:
                        userinfo = dict(userinfo)
                        userinfo["_lumen_not_modified"] = True
                        return "", userinfo, []
                    nodes, errors = parse_links_text(text)
                    if _subscription_response_is_accepted(text, nodes):
                        return text, {**userinfo, "networkPath": network_path}, errors
                    attempts.append(
                        f"{profile_name} direct: {_subscription_reject_reason(text, nodes, errors)}"
                    )
                    continue
                except SubscriptionFetchCancelled:
                    raise
                except Exception as direct_exc:
                    _append_subscription_fetch_error(
                        attempts,
                        f"{profile_name} direct",
                        direct_exc,
                        use_proxy_tun=use_proxy_tun,
                    )
                    continue
            _append_subscription_fetch_error(
                attempts,
                profile_name,
                exc,
                use_proxy_tun=use_proxy_tun,
            )
            if _is_permanent_subscription_error(exc):
                break
    return "", first_userinfo, attempts or ["Не удалось загрузить подписку"]


def fetch_subscription_payload_result(
    url: str,
    *,
    user_agent: str = "",
    hwid: str = DEFAULT_SUBSCRIPTION_HWID,
    use_real_hwid: bool = True,
    use_proxy_tun: bool = False,
    proxy_url: str = "",
    converter_url: str = "",
    cache_etag: str = "",
    cache_last_modified: str = "",
    cancelled=None,
    response_opened=None,
    response_closed=None,
) -> SubscriptionPayloadResult:
    """Fetch a subscription while retaining HTTP validators/status metadata."""
    metadata: dict[str, object] = {}
    text, userinfo, errors = fetch_subscription_payload(
        url,
        user_agent=user_agent,
        hwid=hwid,
        use_real_hwid=use_real_hwid,
        use_proxy_tun=use_proxy_tun,
        proxy_url=proxy_url,
        converter_url=converter_url,
        cache_etag=cache_etag,
        cache_last_modified=cache_last_modified,
        cancelled=cancelled,
        response_opened=response_opened,
        response_closed=response_closed,
        response_meta=metadata,
    )
    info = dict(userinfo or {})
    not_modified = bool(info.pop("_lumen_not_modified", False)) or int(
        metadata.get("status") or 0
    ) == 304
    headers = metadata.get("headers")
    normalized_headers = (
        {str(key).lower(): str(value) for key, value in headers.items()}
        if isinstance(headers, dict)
        else {}
    )
    return SubscriptionPayloadResult(
        text=text or "",
        userinfo=info,
        errors=list(errors or []),
        headers=normalized_headers,
        status=int(metadata.get("status") or 0),
        not_modified=not_modified,
    )


def _subscription_converter_target(template: str, source_url: str) -> str:
    value = str(template or "").strip()
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("URL конвертера должен начинаться с http:// или https://")
    if "{url}" not in value and "{raw_url}" not in value:
        raise ValueError("URL конвертера должен содержать {url} или {raw_url}")
    return value.replace("{url}", quote(source_url, safe="")).replace("{raw_url}", source_url)


def _compile_subscription_patterns(value: str, label: str) -> tuple[list[re.Pattern[str]], list[str]]:
    patterns: list[re.Pattern[str]] = []
    errors: list[str] = []
    for line_number, raw in enumerate(str(value or "").splitlines(), start=1):
        expression = raw.strip()
        if not expression:
            continue
        try:
            patterns.append(re.compile(expression, re.IGNORECASE))
        except re.error as exc:
            errors.append(f"{label}, строка {line_number}: {exc}")
    return patterns, errors


def _filter_subscription_nodes(controller: AppController, nodes: list) -> tuple[list, list[str]]:
    settings = controller.state.settings
    includes, include_errors = _compile_subscription_patterns(
        getattr(settings, "subscription_include_regex", ""),
        "Include regex",
    )
    excludes, exclude_errors = _compile_subscription_patterns(
        getattr(settings, "subscription_exclude_regex", ""),
        "Exclude regex",
    )
    errors = [*include_errors, *exclude_errors]
    if errors:
        return [], errors
    if not includes and not excludes:
        return list(nodes), []
    filtered = []
    for node in nodes:
        haystack = "\n".join(
            (
                str(getattr(node, "name", "") or ""),
                str(getattr(node, "server", "") or ""),
                str(getattr(node, "scheme", "") or ""),
                str(getattr(node, "link", "") or ""),
            )
        )
        if includes and not any(pattern.search(haystack) for pattern in includes):
            continue
        if excludes and any(pattern.search(haystack) for pattern in excludes):
            continue
        filtered.append(node)
    return filtered, []


def _happ_enabled(value: object) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _apply_happ_premium_settings(controller: AppController, info: dict) -> list[str]:
    """Apply only Happ commands that have a direct, safe Windows equivalent."""
    premium = info.get("premiumFeatures") if isinstance(info, dict) else None
    if not isinstance(premium, dict) or not premium:
        return []
    settings = getattr(getattr(controller, "state", None), "settings", None)
    if settings is None:
        return []
    applied: list[str] = []

    def assign(key: str, attribute: str, value: object) -> None:
        if key not in premium:
            return
        if getattr(settings, attribute, None) != value:
            setattr(settings, attribute, value)
        applied.append(key)

    if "subscription-always-hwid-enable" in premium and _happ_enabled(
        premium["subscription-always-hwid-enable"]
    ):
        assign("subscription-always-hwid-enable", "subscription_use_real_hwid", True)
    if "subscription-autoconnect" in premium:
        assign("subscription-autoconnect", "auto_connect_last", _happ_enabled(premium["subscription-autoconnect"]))
    if "subscription-auto-update-enable" in premium:
        enabled = _happ_enabled(premium["subscription-auto-update-enable"])
        current = int(getattr(settings, "subscription_auto_update_minutes", 240) or 0)
        assign("subscription-auto-update-enable", "subscription_auto_update_minutes", max(1, current or 240) if enabled else 0)
    if "fragmentation-enable" in premium:
        enabled = _happ_enabled(premium["fragmentation-enable"])
        assign("fragmentation-enable", "enable_xray_fragment", enabled)
        settings.enable_final_fragment = enabled
    assign("fragmentation-packets", "fragment_packets", str(premium.get("fragmentation-packets") or "tlshello").strip())
    assign("fragmentation-length", "fragment_length", str(premium.get("fragmentation-length") or "50-100").strip())
    assign("fragmentation-interval", "fragment_delay", str(premium.get("fragmentation-interval") or "10-20").strip())
    if "ping-type" in premium:
        ping_method = {
            "proxy": "real",
            "http": "http",
            "tcp": "tcping",
            "icmp": "icmp",
        }.get(str(premium["ping-type"]).strip().lower())
        if ping_method:
            assign("ping-type", "ping_method", ping_method)
    if "change-user-agent" in premium:
        assign("change-user-agent", "subscription_user_agent", str(premium["change-user-agent"]).strip())
    if "mux-enable" in premium:
        assign("mux-enable", "multiplex_enabled", _happ_enabled(premium["mux-enable"]))
    if "mux-tcp-connections" in premium:
        try:
            concurrency = max(-1, min(1024, int(str(premium["mux-tcp-connections"]).strip())))
        except (TypeError, ValueError):
            concurrency = None
        if concurrency is not None:
            assign("mux-tcp-connections", "multiplex_concurrency", concurrency)
    if "exclude-routes" in premium:
        routing = getattr(getattr(controller, "state", None), "routing", None)
        if routing is not None:
            values = [
                value
                for value in re.split(r"[\s,;]+", str(premium["exclude-routes"] or "").strip())
                if value
            ]
            routing.tun_route_exclude_address = values
            applied.append("exclude-routes")
    # Sniffing is part of both generated Xray and sing-box runtime configs.
    if "sniffing-enable" in premium and _happ_enabled(premium["sniffing-enable"]):
        applied.append("sniffing-enable")
    return list(dict.fromkeys(applied))


def _apply_subscription_payload(
    controller: AppController,
    url: str,
    group: str,
    fetched: tuple[str, dict, list[str]],
    *,
    replace_existing_group: bool = False,
    response_meta: dict[str, object] | None = None,
) -> tuple[int, list[str], dict]:
    """Apply a fetched subscription as one in-memory transaction."""
    chosen_text, chosen_userinfo, chosen_errors = fetched
    result_info = dict(chosen_userinfo or {})
    result_info["_lumen_applied"] = False
    if result_info.pop("_lumen_not_modified", False) or bool(
        (response_meta or {}).get("not_modified")
    ):
        subscription = _find_subscription(controller, url)
        if subscription is not None:
            headers = (response_meta or {}).get("headers")
            _mark_subscription_fetch_metadata(
                subscription,
                headers=headers if isinstance(headers, dict) else {},
                status=int((response_meta or {}).get("status") or 304),
                success=True,
                not_modified=True,
            )
            subscription["node_count"] = sum(
                1 for node in controller.state.nodes if node.subscription_id == subscription.get("id")
            )
            controller.subscriptions_changed.emit(list(controller.state.subscriptions))
            controller.save()
        result_info["_lumen_not_modified"] = True
        return 0, [], result_info
    if not chosen_text:
        return 0, list(chosen_errors), result_info

    subscription_id = _subscription_id(controller, url)
    parsed_nodes, parse_errors = parse_links_text(chosen_text)
    parsed_nodes, filter_errors = _filter_subscription_nodes(controller, parsed_nodes)
    if filter_errors:
        return 0, [*chosen_errors, *parse_errors, *filter_errors], result_info
    prepared = []
    validation_errors: list[str] = []
    seen_links: set[str] = set()
    for node in parsed_nodes:
        normalize_node_outbound(node)
        problem = validate_node_outbound(node)
        if problem:
            validation_errors.append(problem)
            continue
        if not node.link or node.link in seen_links:
            continue
        seen_links.add(node.link)
        node.group = group
        node.subscription_id = subscription_id
        node.source_key = _subscription_source_key(node)
        if not node.country_code:
            node.country_code = detect_country(node.name, node.server)
        prepared.append(node)

    if not prepared:
        errors = [*chosen_errors, *parse_errors, *validation_errors]
        if not errors:
            errors.append("Подписка не содержит серверов, подходящих под regex-фильтры")
        return 0, errors, result_info

    old_nodes = [
        node
        for node in controller.state.nodes
        if node.subscription_id == subscription_id
        or (
            replace_existing_group
            and not node.subscription_id
            and (node.group or "Default") == group
        )
    ]
    old_ids = {node.id for node in old_nodes}
    old_by_key: dict[str, list[Node]] = {}
    old_by_link = {node.link: node for node in old_nodes if node.link}
    old_by_fallback: dict[tuple[str, str, int, str], list[Node]] = {}
    for old_node in old_nodes:
        old_by_key.setdefault(_subscription_source_key(old_node), []).append(old_node)
        old_by_fallback.setdefault(_subscription_fallback_key(old_node), []).append(old_node)
    occupied_nodes = {
        (node.link, (node.group or "Default").strip().casefold())
        for node in controller.state.nodes
        if node.id not in old_ids and node.link
    }
    prepared = [
        node
        for node in prepared
        if (node.link, (node.group or "Default").strip().casefold()) not in occupied_nodes
    ]
    if not prepared:
        return 0, [*chosen_errors, "Все серверы подписки уже есть в этой группе"], result_info

    selected_id = controller.state.selected_node_id
    selected_old = next((node for node in old_nodes if node.id == selected_id), None)
    max_order = max(
        (node.sort_order for node in controller.state.nodes if node.id not in old_ids),
        default=0,
    )
    used_old_ids: set[str] = set()
    reconnect_needed = False
    for node in prepared:
        previous = next(
            (candidate for candidate in old_by_key.get(node.source_key, []) if candidate.id not in used_old_ids),
            None,
        )
        if previous is None:
            previous = old_by_link.get(node.link)
            if previous is not None and previous.id in used_old_ids:
                previous = None
        if previous is None:
            candidates = [
                candidate
                for candidate in old_by_fallback.get(_subscription_fallback_key(node), [])
                if candidate.id not in used_old_ids
            ]
            if len(candidates) == 1:
                previous = candidates[0]
        if previous is not None:
            previous_outbound = json.dumps(
                previous.outbound if isinstance(previous.outbound, dict) else {},
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            )
            incoming_outbound = json.dumps(
                node.outbound if isinstance(node.outbound, dict) else {},
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            )
            if previous.id == selected_id and previous_outbound != incoming_outbound:
                reconnect_needed = True
            used_old_ids.add(previous.id)
            node.id = previous.id
            node.source_key = _subscription_source_key(node)
            node.sort_order = previous.sort_order
            node.ping_ms = previous.ping_ms
            node.speed_mbps = previous.speed_mbps
            node.is_alive = previous.is_alive
            node.ping_history = list(previous.ping_history)
            node.speed_history = list(previous.speed_history)
            node.last_used_at = previous.last_used_at
            node.created_at = previous.created_at
            node.tags = list(previous.tags)
            node.description = previous.description
            if previous.country_code:
                node.country_code = previous.country_code
        else:
            max_order += 1
            node.sort_order = max_order

    remaining = [node for node in controller.state.nodes if node.id not in old_ids]
    controller.state.nodes = [*remaining, *prepared]

    effective_url = _premium_subscription_url(url, result_info)
    if effective_url != url and _migrate_subscription_url(controller, url, effective_url):
        result_info["_lumen_effective_url"] = effective_url

    premium_applied = _apply_happ_premium_settings(controller, result_info)
    if premium_applied:
        result_info["premiumApplied"] = premium_applied

    if selected_old is not None:
        selected_key = _subscription_source_key(selected_old)
        replacement = next(
            (node for node in prepared if _subscription_source_key(node) == selected_key),
            None,
        )
        if replacement is None:
            replacement = next((node for node in prepared if node.link == selected_old.link), None)
        if replacement is None:
            replacement = prepared[0]
            reconnect_needed = True
        controller.state.selected_node_id = replacement.id

    controller.nodes_changed.emit(controller.state.nodes)
    controller.selection_changed.emit(controller.selected_node)
    result_info["_lumen_applied"] = True
    if response_meta:
        result_info["_lumen_response_meta"] = dict(response_meta)
    if reconnect_needed and (controller.connected or controller._desired_connected):
        controller._desired_connected = True
        controller._request_transition("active subscription updated")
    errors = [*chosen_errors, *parse_errors, *validation_errors]
    return len(prepared), errors, result_info


def _import_subscription_payload(
    controller: AppController,
    url: str,
    group: str,
    *,
    replace_existing_group: bool = False,
    prefer_metadata_name: bool = False,
) -> tuple[int, list[str], dict]:
    # Синхронный путь (блокирует поток). Оставлен для обратной совместимости.
    settings = controller.state.settings
    subscription = _find_subscription(controller, url)
    cache_allowed = bool(
        subscription
        and int(subscription.get("parser_revision") or 0) == SUBSCRIPTION_PARSER_REVISION
    )
    fetched_result = fetch_subscription_payload_result(
        url,
        user_agent=getattr(settings, "subscription_user_agent", ""),
        hwid=getattr(settings, "subscription_hwid", DEFAULT_SUBSCRIPTION_HWID),
        use_real_hwid=bool(getattr(settings, "subscription_use_real_hwid", True)),
        converter_url=(
            getattr(settings, "subscription_converter_url", "")
            if getattr(settings, "subscription_converter_enabled", False)
            else ""
        ),
        cache_etag=str((subscription or {}).get("etag") or "") if cache_allowed else "",
        cache_last_modified=(
            str((subscription or {}).get("last_modified") or "") if cache_allowed else ""
        ),
    )
    effective_group = group
    if prefer_metadata_name:
        effective_group = _subscription_name_from_info(fetched_result.userinfo) or group
    fetched = (
        fetched_result.text,
        fetched_result.userinfo,
        fetched_result.errors,
    )
    added, errors, info = _apply_subscription_payload(
        controller,
        url,
        effective_group,
        fetched,
        replace_existing_group=replace_existing_group,
        response_meta={
            "headers": fetched_result.headers,
            "status": fetched_result.status,
            "not_modified": fetched_result.not_modified,
        },
    )
    info["_lumen_group"] = effective_group
    # Synchronous imports/updates use the same cache metadata contract as the
    # background worker.  Keep failures visible and apply bounded backoff so a
    # startup refresh cannot hammer an unavailable provider.
    if not info.get("_lumen_applied") and not info.get("_lumen_not_modified"):
        subscription = _find_subscription(controller, url)
        if subscription is not None and fetched_result.errors:
            _mark_subscription_fetch_metadata(
                subscription,
                headers=fetched_result.headers,
                status=fetched_result.status,
                error=fetched_result.errors[0],
            )
            controller.subscriptions_changed.emit(list(controller.state.subscriptions))
            controller.save()
    return added, errors, info


def _record_subscription(
    controller: AppController,
    url: str,
    group: str,
    node_count: int,
    userinfo: dict | None = None,
    response_meta: dict[str, object] | None = None,
) -> None:
    now = _utc_now_iso()
    info = dict(userinfo) if isinstance(userinfo, dict) else {}
    info.pop("_lumen_applied", None)
    subscription_id = _subscription_id(controller, url)
    existing = _find_subscription(controller, url)
    if existing is not None:
        existing["id"] = subscription_id
        existing["name"] = group
        existing["group"] = group
        existing["updated_at"] = now
        existing["node_count"] = node_count
        # Сохраняем старую инфо, если новая не пришла.
        if info:
            existing["userinfo"] = info
        elif "userinfo" not in existing:
            existing["userinfo"] = {}
        meta = response_meta or {}
        headers = meta.get("headers")
        _mark_subscription_fetch_metadata(
            existing,
            headers=headers if isinstance(headers, dict) else {},
            status=int(meta.get("status") or 200),
            success=True,
        )
    else:
        created = {
            "id": subscription_id,
            "url": url,
            "name": group,
            "group": group,
            "updated_at": now,
            "node_count": node_count,
            "userinfo": info,
        }
        _mark_subscription_fetch_metadata(
            created,
            headers=(response_meta or {}).get("headers")
            if isinstance((response_meta or {}).get("headers"), dict)
            else {},
            status=int((response_meta or {}).get("status") or 200),
            success=True,
        )
        controller.state.subscriptions.append(created)
    controller.subscriptions_changed.emit(list(controller.state.subscriptions))
    controller.save()


def import_subscription(
    controller: AppController, url: str, name: str | None = None
) -> tuple[int, list[str]]:
    url = (url or "").strip()
    if not url:
        return 0, ["Пустой URL подписки"]
    existing = _find_subscription(controller, url)
    if existing is not None:
        # Подписка с таким URL уже есть. Если пользователь задал новое имя —
        # переименовываем группу (у самой записи и у её узлов), иначе сохраняем
        # прежнее. Затем обновляем содержимое.
        new_name = (name or "").strip()
        old_group = (existing.get("group") or "").strip()
        if new_name and new_name != old_group:
            subscription_id = _subscription_id(controller, url)
            if old_group:
                for node in controller.state.nodes:
                    if node.subscription_id == subscription_id or (
                        not node.subscription_id
                        and (node.group or "Default") == old_group
                    ):
                        node.group = new_name
                        node.subscription_id = subscription_id
            existing["name"] = new_name
            existing["group"] = new_name
            controller.nodes_changed.emit(controller.state.nodes)
            controller.subscriptions_changed.emit(list(controller.state.subscriptions))
            controller.save()
        return update_subscription(controller, url)
    explicit_group = (name or "").strip()
    group = explicit_group or _derive_subscription_name(url)
    added, errors, userinfo = _import_subscription_payload(
        controller,
        url,
        group,
        prefer_metadata_name=not bool(explicit_group),
    )
    group = str(userinfo.pop("_lumen_group", group) or group)
    effective_url = str(userinfo.pop("_lumen_effective_url", url) or url)
    meta = userinfo.pop("_lumen_response_meta", None)
    if userinfo.pop("_lumen_applied", False):
        _record_subscription(
            controller,
            effective_url,
            group,
            added,
            userinfo,
            meta if isinstance(meta, dict) else None,
        )
    return added, errors


def update_subscription(controller: AppController, url: str) -> tuple[int, list[str]]:
    url = (url or "").strip()
    sub = _find_subscription(controller, url)
    if sub is None:
        return 0, ["Подписка не найдена"]
    group = (sub.get("group") or "").strip() or _derive_subscription_name(url)
    added, errors, userinfo = _import_subscription_payload(
        controller, url, group, replace_existing_group=True
    )
    userinfo.pop("_lumen_group", None)
    effective_url = str(userinfo.pop("_lumen_effective_url", url) or url)
    meta = userinfo.pop("_lumen_response_meta", None)
    if userinfo.pop("_lumen_applied", False):
        _record_subscription(
            controller,
            effective_url,
            group,
            added,
            userinfo,
            meta if isinstance(meta, dict) else None,
        )
    return added, errors


def update_all_subscriptions(controller: AppController) -> tuple[int, list[str]]:
    total_added = 0
    all_errors: list[str] = []
    for sub in list(controller.state.subscriptions):
        url = sub.get("url") or ""
        if not url:
            continue
        added, errors = update_subscription(controller, url)
        total_added += added
        all_errors.extend(errors)
    return total_added, all_errors


def apply_fetched_subscription(
    controller: AppController,
    url: str,
    name: str | None,
    kind: str,
    text: str,
    userinfo: dict | None,
    errors: list[str] | None,
    response_meta: dict | None = None,
) -> tuple[int, list[str]]:
    """Применяет подписку, загруженную в фоне (вызывать в GUI-потоке).

    kind: "import" — добавить/обновить по ссылке; "update" — обновить существующую.
    """
    url = (url or "").strip()
    if not url:
        return 0, ["Пустой URL подписки"]
    existing = _find_subscription(controller, url)

    if kind == "import" and existing is None:
        group = (
            (name or "").strip()
            or _subscription_name_from_info(userinfo)
            or _derive_subscription_name(url)
        )
        replace = False
    else:
        if existing is None:
            return 0, ["Подписка не найдена"]
        if kind == "import":
            # Подписка уже есть: при новом имени переименовываем группу и узлы.
            new_name = (name or "").strip()
            old_group = (existing.get("group") or "").strip()
            if new_name and new_name != old_group:
                subscription_id = _subscription_id(controller, url)
                if old_group:
                    for node in controller.state.nodes:
                        if node.subscription_id == subscription_id or (
                            not node.subscription_id
                            and (node.group or "Default") == old_group
                        ):
                            node.group = new_name
                            node.subscription_id = subscription_id
                existing["name"] = new_name
                existing["group"] = new_name
                controller.nodes_changed.emit(controller.state.nodes)
                controller.subscriptions_changed.emit(list(controller.state.subscriptions))
                controller.save()
        group = (existing.get("group") or "").strip() or _derive_subscription_name(url)
        replace = True

    fetched = (text or "", dict(userinfo or {}), list(errors or []))
    added, errs, info = _apply_subscription_payload(
        controller,
        url,
        group,
        fetched,
        replace_existing_group=replace,
        response_meta=dict(response_meta or {}),
    )
    applied = bool(info.pop("_lumen_applied", False))
    meta = info.pop("_lumen_response_meta", None)
    if info.pop("_lumen_not_modified", False):
        # The existing snapshot is intentionally left untouched for HTTP 304.
        return added, errs
    if not applied:
        if existing is not None:
            meta_value = meta if isinstance(meta, dict) else dict(response_meta or {})
            _mark_subscription_fetch_metadata(
                existing,
                headers=meta_value.get("headers")
                if isinstance(meta_value.get("headers"), dict)
                else {},
                status=int(meta_value.get("status") or 0),
                error=(errs or ["Не удалось применить подписку"])[0],
            )
            controller.subscriptions_changed.emit(list(controller.state.subscriptions))
            controller.save()
        return added, errs
    effective_url = str(info.pop("_lumen_effective_url", url) or url)
    _record_subscription(
        controller,
        effective_url,
        group,
        added,
        info,
        meta if isinstance(meta, dict) else dict(response_meta or {}),
    )
    return added, errs


def remove_subscription(controller: AppController, url: str, *, delete_nodes: bool = True) -> None:
    url = (url or "").strip()
    sub = _find_subscription(controller, url)
    if sub is None:
        return
    group = (sub.get("group") or "").strip()
    subscription_id = str(sub.get("id") or "").strip()
    controller.state.subscriptions = [
        item for item in controller.state.subscriptions if item.get("url") != url
    ]
    controller.subscriptions_changed.emit(list(controller.state.subscriptions))
    if delete_nodes:
        ids = {
            node.id
            for node in controller.state.nodes
            if (subscription_id and node.subscription_id == subscription_id)
            or (
                not subscription_id
                and group
                and not node.subscription_id
                and (node.group or "Default") == group
            )
        }
        if ids:
            remove_nodes(controller, ids)
            return
    controller.save()
