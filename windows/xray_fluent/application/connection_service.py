from __future__ import annotations

import ctypes
import socket
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from ..constants import (
    DEFAULT_XRAY_STATS_API_PORT,
    SINGBOX_PATH_DEFAULT,
    XRAY_PATH_DEFAULT,
)
from ..engines.singbox import SingboxRuntimePlan, start_proxy as start_singbox_proxy, start_tun as start_singbox_tun
from ..engines.xray import start_proxy as start_xray_proxy
from ..core_resource_updater import regional_geodata_installed
from ..path_utils import resolve_configured_path
from ..process_conflicts import scan_network_conflicts
from ..routing_presets import normalize_regional_preset, preset_requires_regional_geodata
from ..subprocess_utils import kill_processes_by_path
from .server_preflight import validate_server_preflight
from .node_runtime_service import proxy_core_for_node

if TYPE_CHECKING:
    from ..app_controller import AppController
    from ..application.session_state import XrayRuntimeConfig


def _cleanup_orphaned_lumen_engines(controller: AppController) -> None:
    settings = getattr(getattr(controller, "state", None), "settings", None)
    for manager, cfg_path, def_path in (
        (getattr(controller, "xray", None), getattr(settings, "xray_path", None), XRAY_PATH_DEFAULT),
        (getattr(controller, "singbox", None), getattr(settings, "singbox_path", None), SINGBOX_PATH_DEFAULT),
    ):
        if manager is not None and getattr(manager, "_proc", None) is None:
            exe = getattr(manager, "_exe_path", None)
            if exe is None:
                exe = resolve_configured_path(
                    cfg_path,
                    default_path=def_path,
                    use_default_if_empty=True,
                    migrate_default_location=True,
                )
            if exe is not None:
                try:
                    kill_processes_by_path(exe.name, exe, timeout=1.5)
                except Exception:
                    pass


def find_free_api_port(preferred: int | None = None, excluded: set[int] | None = None) -> int:
    if preferred is None:
        preferred = DEFAULT_XRAY_STATS_API_PORT
    for port in range(preferred, preferred + 100):
        if excluded and port in excluded:
            continue
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    raise RuntimeError(f"No free port in range {preferred}-{preferred + 100}")


def should_block_vpn_conflicts(controller: AppController) -> bool:
    """Return the persisted conflict guard setting, defaulting safely to on.

    Older state files do not have this field.  Treating a missing value as
    enabled preserves the pre-existing safety behavior after an upgrade.
    """
    settings = getattr(getattr(controller, "state", None), "settings", None)
    return bool(getattr(settings, "block_vpn_conflicts", True))


def connect_selected(controller: AppController, allow_during_reconnect: bool = False) -> bool:
    if controller._connecting:
        controller._set_connection_status("starting", "Подключение уже выполняется...", level="info")
        return False
    controller._connecting = True
    controller._kill_switch_engaged = False  # новая попытка подключения снимает fail-closed
    try:
        if controller._reconnecting and not allow_during_reconnect:
            controller._set_connection_status("starting", "Переподключение...", level="info")
            return False

        if controller.locked:
            controller._set_connection_status(
                "error",
                "Приложение заблокировано. Разблокируйте для подключения.",
                level="warning",
            )
            return False

        _cleanup_orphaned_lumen_engines(controller)

        ignored_pids = controller.owned_core_process_pids()
        owned_paths = getattr(controller, "owned_core_executable_paths", None)
        ignored_paths = set(owned_paths()) if callable(owned_paths) else set()
        settings = getattr(getattr(controller, "state", None), "settings", None)
        # Initial connections must reject another VPN client. A reconnect has
        # already passed that validation; while switching servers, Windows can
        # briefly retain the previous Lumen core in its process snapshot after
        # the manager released it, which must not be reported as foreign Xray.
        conflicts = {"apps": [], "unknown_client": False}
        if should_block_vpn_conflicts(controller) and not controller._reconnecting:
            conflicts = scan_network_conflicts(
                {
                    int(getattr(settings, "local_socks_port", 10808) or 10808),
                    int(getattr(settings, "local_http_port", 10809) or 10809),
                    10818,
                },
                ignored_pids=ignored_pids,
                ignored_executable_paths=ignored_paths,
            )
        conflicting_apps = list(conflicts.get("apps") or [])
        unknown_client = bool(conflicts.get("unknown_client"))
        if conflicting_apps or unknown_client:
            if conflicting_apps:
                names = ", ".join(conflicting_apps[:4])
                message = (
                    f"Нельзя запустить Lumen: одновременно работает другой VPN/прокси-клиент — {names}. "
                    f"Отключите или закройте {names} и повторите запуск."
                )
            else:
                message = (
                    "Нельзя запустить Lumen: уже работает другой VPN/прокси-клиент. "
                    "Отключите или закройте его и повторите запуск."
                )
            controller._set_connection_status(
                "error",
                message,
                level="error",
            )
            return False

        routing = controller.state.routing
        if preset_requires_regional_geodata(routing.preset_id):
            region = normalize_regional_preset(controller.state.settings.regional_preset)
            if not regional_geodata_installed(region):
                controller._set_connection_status(
                    "error",
                    "Файлы маршрутизации выбранного региона отсутствуют или повреждены. "
                    "Обновите geoip/geosite и повторите подключение.",
                    level="error",
                )
                return False

        node = controller.selected_node
        singbox_editor_mode = controller.is_singbox_editor_mode()
        xray_raw_mode = controller.uses_xray_raw_config()
        if node is None and not controller._can_connect_without_selected_node():
            message = "Сначала выберите сервер."
            if singbox_editor_mode or xray_raw_mode:
                message = "В конфиге есть outbound tag `proxy`. Сначала выберите сервер."
            controller._set_connection_status("error", message, level="warning")
            return False

        controller._reset_auto_switch_state(
            reset_cooldown=not controller._auto_switch_transitioning,
            reset_cycle=not controller._auto_switch_transitioning,
        )

        prev_active_core = controller._active_core
        tun = controller.state.settings.tun_mode
        controller._xray_api_port = 0

        singbox_plan: SingboxRuntimePlan | None = None
        runtime_xray: XrayRuntimeConfig | None = None
        if singbox_editor_mode:
            session_label = node.name if node else controller.get_active_singbox_config_name()
        elif xray_raw_mode:
            session_label = node.name if node else controller.get_active_xray_config_name()
        else:
            session_label = node.name if node else "unknown"

        if node is not None:
            problem = controller._prepare_node_for_runtime(node)
            if problem:
                controller._set_connection_status("error", problem, level="error")
                return False
            problem = validate_server_preflight(node, controller.state.settings)
            if problem:
                controller._set_connection_status("error", problem, level="error")
                return False

        if tun:
            controller._log(f"[tun] attempting TUN connect, admin={_is_admin()}")
            controller._set_connection_status("starting", f"Запуск VPN: {session_label}...", level="info")

            if not _is_admin():
                controller._log("[tun] NOT admin — aborting")
                controller._set_connection_status(
                    "error",
                    "Режим TUN требует прав Администратора. Запустите приложение от имени Администратора.",
                    level="error",
                )
                return False

            # TUN catches traffic at the adapter level. Restore browser/system
            # proxy prefs even when WinINET already looks disabled, because
            # Necko browsers can keep Lumen's manual 127.0.0.1 proxy block from
            # the previous system-proxy session and then fail in TUN mode.
            controller.proxy.disable(restore_previous=True)
            if controller.state.settings.discord_proxy_enabled:
                result = controller.discord_proxy.disable()
                controller._log(f"[discord-proxy] disabled for TUN: {result.message}")

            controller._tun_log_count = 0
            result = start_singbox_tun(controller, node, prev_active_core=prev_active_core)
            if result is None:
                return False
            singbox_plan = result.plan
            session_label = result.session_label
        else:
            if proxy_core_for_node(node) == "singbox":
                result = start_singbox_proxy(controller, node, prev_active_core=prev_active_core)
                if result is None:
                    return False
                singbox_plan = result.plan
                session_label = result.session_label
            else:
                result = start_xray_proxy(controller, node, prev_active_core=prev_active_core)
                if result is None:
                    return False
                runtime_xray = result.runtime
                session_label = result.session_label

        session_node = node
        if singbox_editor_mode and singbox_plan is not None and not singbox_plan.used_selected_node:
            session_node = None
        if xray_raw_mode and runtime_xray is not None and not runtime_xray.used_selected_node:
            session_node = None

        if session_node is not None:
            session_node.last_used_at = datetime.now(timezone.utc).isoformat()

        controller._set_connection_status(
            "running",
            f"Подключено: {session_label}"
            + (
                " (TUN, xray sidecar)"
                if tun and singbox_plan is not None and singbox_plan.is_hybrid
                else " (TUN)" if tun else " (sing-box)" if singbox_plan is not None else ""
            ),
            level="success",
        )
        controller._capture_active_session(
            session_node,
            tun=tun,
            core=controller._active_core,
            api_port=controller._xray_api_port,
            clash_api_secret=singbox_plan.clash_api_secret if singbox_plan is not None else "",
            clash_api_selector=singbox_plan.clash_api_selector if singbox_plan is not None else "",
            clash_api_node_signatures=(
                singbox_plan.clash_api_node_signatures if singbox_plan is not None else ()
            ),
            hybrid=bool(singbox_plan is not None and singbox_plan.is_hybrid),
            socks_port=runtime_xray.socks_port if runtime_xray is not None else None,
            http_port=runtime_xray.http_port if runtime_xray is not None else None,
            xray_inbound_tags=runtime_xray.inbound_tags if runtime_xray is not None else (),
            sidecar_relay_port=singbox_plan.xray_sidecar.relay_port if singbox_plan and singbox_plan.xray_sidecar else 0,
            protect_ss_port=controller._protect_ss_port,
            protect_ss_password=controller._protect_ss_password,
            ping_host=(
                runtime_xray.ping_host
                if runtime_xray is not None
                else controller._infer_singbox_ping_target(
                    singbox_plan.singbox_config if singbox_plan is not None else {},
                    session_node,
                )[0]
            ),
            ping_port=(
                runtime_xray.ping_port
                if runtime_xray is not None
                else controller._infer_singbox_ping_target(
                    singbox_plan.singbox_config if singbox_plan is not None else {},
                    session_node,
                )[1]
            ),
        )
        controller.save()
        controller._traffic_history.start_session(session_label, controller._active_core)
        # Discord-proxy применяем в GUI-потоке из _on_transition_action_complete:
        # этот код идёт в рабочем потоке перехода, QTimer оттуда запускать нельзя.
        return True
    finally:
        controller._connecting = False


def disconnect_current(
    controller: AppController,
    disable_proxy: bool = True,
    emit_status: bool = True,
    *,
    fast: bool = False,
) -> bool:
    controller._disconnecting = True
    controller._kill_switch_engaged = False  # ручное отключение снимает fail-closed
    try:
        controller._cleanup_connection_runtime_state(
            end_traffic_session=True,
            reset_auto_switch_cycle=not controller._auto_switch_transitioning,
            reset_auto_switch_cooldown=not controller._reconnecting and not controller._auto_switch_transitioning,
        )
        active_tun = controller._active_session.tun_mode if controller._active_session is not None else controller.state.settings.tun_mode
        if emit_status and active_tun:
            controller.status.emit("info", "Остановка VPN...")
        stopped = controller._stop_active_connection_processes(disable_proxy=disable_proxy, fast=fast)
        if stopped:
            controller._active_core = "xray"
            controller._clear_active_session()
        if emit_status:
            if stopped:
                controller._set_connection_status("idle", "Отключено", level="info")
            else:
                controller._set_connection_status("error", "Не удалось корректно остановить подключение", level="error")
        return stopped
    finally:
        controller._disconnecting = False


def reconnect(controller: AppController, reason: str) -> bool:
    if controller._reconnecting:
        controller._set_connection_status("starting", "Переподключение уже выполняется...", level="info")
        return False
    controller._reconnecting = True
    controller._switching = True
    try:
        controller._log(f"[reconnect] {reason}")
        controller._set_connection_status("starting", "Переподключение...", level="info")
        stopped = disconnect_current(
            controller,
            disable_proxy=False,
            emit_status=False,
            fast=True,
        )
        if not stopped:
            controller._set_connection_status("error", "Не удалось остановить предыдущий процесс Xray", level="error")
            if controller.state.settings.enable_system_proxy:
                controller.proxy.disable(restore_previous=True)
            return False

        ok = connect_selected(controller, allow_during_reconnect=True)
        if not ok and controller.state.settings.enable_system_proxy:
            controller.proxy.disable(restore_previous=True)
        return ok
    finally:
        controller._reconnecting = False
        controller._switching = False
        controller._auto_switch_transitioning = False
        _, controller.connected = controller._refresh_connected_state()
        controller.connection_changed.emit(controller.connected)
        controller._metrics_request.emit(controller.connected)


def _is_admin() -> bool:
    if not hasattr(ctypes, "windll"):
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False
