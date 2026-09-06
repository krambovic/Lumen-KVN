from __future__ import annotations

from concurrent.futures import Future, ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from copy import deepcopy
import logging
import socket
import threading
import time
from datetime import datetime, timezone
import json
from pathlib import Path

from .constants import APP_VERSION, DIAGNOSTICS_UPLOAD_URL
from .logging_setup import configure_diagnostics_upload, configure_logging, get_logger
from .diagnostics_uploader import upload_bundle
from typing import TYPE_CHECKING, Any

from PyQt6.QtCore import QMetaObject, QObject, QThread, QTimer, Qt, pyqtSignal, pyqtSlot

from .application.config import (
    SingboxDocumentCache,
    apply_singbox_config_text as apply_singbox_config_text_operation,
    apply_xray_config_text as apply_xray_config_text_operation,
    build_runtime_xray_config as build_runtime_xray_config_operation,
    collect_xray_inbound_ports,
    config_has_proxy_outbound,
    default_singbox_config_text,
    default_xray_config_text,
    ensure_active_config as ensure_active_config_operation,
    ensure_dict,
    ensure_list,
    ensure_xray_metrics_contract as ensure_xray_metrics_contract_operation,
    extract_xray_runtime_ports,
    format_json_error_message,
    get_active_config_name as get_active_config_name_operation,
    get_active_config_path as get_active_config_path_operation,
    get_active_template_path as get_active_template_path_operation,
    import_template as import_template_operation,
    infer_singbox_outbound_endpoint,
    infer_singbox_ping_target,
    infer_xray_outbound_endpoint,
    infer_xray_ping_target,
    inspect_active_xray_config as inspect_active_xray_config_operation,
    is_local_runtime_host,
    load_active_config_text as load_active_config_text_operation,
    load_config_text as load_config_text_operation,
    normalize_relative_json_path,
    replace_or_append_tagged,
    reset_active_config_to_template as reset_active_config_to_template_operation,
    resolve_profile_path,
    save_config_text as save_config_text_operation,
    validate_json_text,
)
from .application.nodes import (
    add_manual_node as add_manual_node_operation,
    apply_fetched_subscription as apply_fetched_subscription_operation,
    bulk_update_nodes as bulk_update_nodes_operation,
    delete_group as delete_group_operation,
    check_auto_switch as check_auto_switch_operation,
    detect_countries_sync as detect_countries_sync_operation,
    get_all_groups as get_all_groups_operation,
    get_fastest_alive_node as get_fastest_alive_node_operation,
    get_next_node_for_auto_switch as get_next_node_for_auto_switch_operation,
    get_node_by_id as get_node_by_id_operation,
    import_nodes_from_text as import_nodes_from_text_operation,
    import_subscription as import_subscription_operation,
    on_countries_resolved as on_countries_resolved_operation,
    prepare_node_for_runtime as prepare_node_for_runtime_operation,
    remove_nodes as remove_nodes_operation,
    remove_subscription as remove_subscription_operation,
    reorder_nodes as reorder_nodes_operation,
    set_selected_node as set_selected_node_operation,
    start_country_ip_resolution as start_country_ip_resolution_operation,
    update_all_subscriptions as update_all_subscriptions_operation,
    update_node as update_node_operation,
    update_subscription as update_subscription_operation,
)
from .application.node_runtime_service import proxy_core_for_node
from .application.runtime import (
    ActiveSessionSnapshot,
    TransitionContext,
    XrayRuntimeConfig,
    build_active_session_snapshot,
    can_apply_proxy_runtime_change as can_apply_proxy_runtime_change_rule,
    can_proxy_hot_swap as can_proxy_hot_swap_rule,
    can_tun_hot_swap as can_tun_hot_swap_rule,
    cancel_speed_test as cancel_speed_test_operation,
    cleanup_connection_runtime_state as cleanup_connection_runtime_state_operation,
    compute_transition_action,
    connect_selected as connect_selected_operation,
    disconnect_current as disconnect_current_operation,
    handle_unexpected_disconnect as handle_unexpected_disconnect_operation,
    needs_transition,
    on_connectivity_result as on_connectivity_result_operation,
    on_core_state_changed as on_core_state_changed_operation,
    on_live_metrics as on_live_metrics_operation,
    on_ping_complete as on_ping_complete_operation,
    on_ping_progress as on_ping_progress_operation,
    on_ping_result as on_ping_result_operation,
    on_speed_complete as on_speed_complete_operation,
    on_speed_node_progress as on_speed_node_progress_operation,
    on_speed_progress as on_speed_progress_operation,
    on_speed_result as on_speed_result_operation,
    on_xray_update_worker_done as on_xray_update_worker_done_operation,
    ping_nodes as ping_nodes_operation,
    reconnect as reconnect_operation,
    routing_signature as routing_signature_operation,
    run_xray_core_update as run_xray_core_update_operation,
    shutdown as shutdown_operation,
    signature as signature_operation,
    speed_test_nodes as speed_test_nodes_operation,
    start_metrics_worker as start_metrics_worker_operation,
    stop_active_connection_processes as stop_active_connection_processes_operation,
    stop_metrics_worker as stop_metrics_worker_operation,
    system_proxy_bypass_lan as system_proxy_bypass_lan_operation,
    test_connectivity as test_connectivity_operation,
    transition_signature as transition_signature_operation,
    transition_status_text,
    tun_layer_signature as tun_layer_signature_operation,
    xray_layer_signature as xray_layer_signature_operation,
)
from .country_flags import CountryResolver
from .engines.xray import (
    XrayManager,
    build_xray_config,
    get_xray_version,
    restart_proxy_core as restart_xray_proxy_core,
)
from .network_route_context import (
    get_windows_default_route_context,
    invalidate_windows_default_route_context,
)
from .engines.singbox import (
    SingBoxManager,
    get_singbox_version,
    ParsedSingboxDocument,
    parse_singbox_document,
    plan_singbox_runtime,
    prime_endpoint_resolution,
    restart_runtime as restart_singbox_runtime_operation,
    SingboxDocumentState,
    SingboxRuntimePlan,
    try_hot_switch_selector as try_singbox_hot_switch_selector_operation,
)
from .routing_runtime import routing_with_ip_preference
from .constants import (
    APP_NAME,
    DEFAULT_DISCORD_SOCKS_PORT,
    DEFAULT_HTTP_PORT,
    DEFAULT_SOCKS_PORT,
    DEFAULT_XRAY_STATS_API_PORT,
    LOG_DIR,
    PROXY_HOST,
    ROUTING_MODES,
    SINGBOX_PATH_DEFAULT,
    SINGBOX_CONFIGS_DIR,
    SINGBOX_DEFAULT_CONFIG_NAME,
    SINGBOX_TEMPLATES_DIR,
    XRAY_CONFIGS_DIR,
    XRAY_DEFAULT_CONFIG_NAME,
    XRAY_TEMPLATES_DIR,
    XRAY_PATH_DEFAULT,
)
from .path_utils import resolve_configured_path
from .diagnostics import export_diagnostics
from .discord_proxy_manager import DiscordProxyManager
from .live_metrics_worker import LiveMetricsWorker
from .link_parser import repair_node_outbound_from_link
from .log_utils import classify_log_level, clean_log_text
from .models import AppSettings, AppState, Node, RoutingSettings
from .network_monitor import NetworkMonitor
from .proxy_manager import ProxyManager
from .process_conflicts import scan_network_conflicts
from .routing_presets import (
    build_routing_preset,
    equivalent_regional_preset,
    normalize_regional_preset,
    normalize_routing_preset_for_region,
    repair_builtin_preset_service_routes,
)
from .security import create_password_hash, get_idle_seconds, verify_password
from .storage import PassphraseRequired, StateLoadError, StateStorage
from .startup import (
    STARTUP_STATE_ABSENT,
    STARTUP_STATE_DISABLED,
    build_startup_command,
    get_startup_state,
    is_process_elevated,
    set_always_run_as_admin,
    set_startup_enabled,
)
from .traffic_history import TrafficHistoryStorage
from .zapret_manager import ZapretManager

if TYPE_CHECKING:
    from .connectivity_test import ConnectivityTestWorker
    from .engines.xray import XrayCoreUpdateResult, XrayCoreUpdateWorker
    from .ping_worker import PingWorker
    from .speed_test_worker import SpeedTestWorker


def _find_free_api_port(preferred: int | None = None, excluded: set[int] | None = None) -> int:
    """Find a free TCP port near *preferred* for the xray stats API."""
    if preferred is None:
        preferred = DEFAULT_XRAY_STATS_API_PORT
    for port in range(preferred, preferred + 100):
        if excluded and port in excluded:
            continue
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    raise RuntimeError(f"No free port in range {preferred}-{preferred + 100}")


_DNS_DEFAULTS_MIGRATION_KEY = "recommended_dns_defaults_2026_07"
_MASQUE_DIRECT_MIGRATION_KEY = "masque_direct_outbound_v1"
_DNS_SETTING_FIELDS = (
    "dns_mode",
    "dns_bootstrap_server",
    "dns_bootstrap_servers",
    "dns_bootstrap_type",
    "dns_bootstrap_strategy",
    "dns_proxy_server",
    "dns_proxy_servers",
    "dns_proxy_type",
    "dns_proxy_strategy",
    "dns_fake_enabled",
    "dns_hijack_enabled",
    "dns_parallel_query",
    "dns_optimistic_cache",
    "dns_geo_check",
    "dns_hosts",
)


def apply_dns_defaults_update_once(state: AppState) -> bool:
    """Apply the new DNS profile once without touching nodes or other user data."""
    migrations = state.applied_migrations
    if migrations.get(_DNS_DEFAULTS_MIGRATION_KEY):
        return False

    defaults = RoutingSettings()
    for field_name in _DNS_SETTING_FIELDS:
        setattr(state.routing, field_name, deepcopy(getattr(defaults, field_name)))
    migrations[_DNS_DEFAULTS_MIGRATION_KEY] = True
    return True


def apply_masque_direct_update_once(state: AppState) -> bool:
    """Repair saved Clash MASQUE nodes once, without reimporting subscriptions."""
    migrations = state.applied_migrations
    if migrations.get(_MASQUE_DIRECT_MIGRATION_KEY):
        return False

    for node in state.nodes:
        outbound = node.outbound if isinstance(node.outbound, dict) else {}
        native = (
            outbound.get("singbox")
            if isinstance(outbound.get("singbox"), dict)
            else {}
        )
        protocol = str(
            outbound.get("protocol") or node.scheme or native.get("type") or ""
        ).strip().lower()
        if (
            protocol == "masque"
            or str(native.get("type") or "").strip().lower() == "masque"
        ):
            repair_node_outbound_from_link(node)
    migrations[_MASQUE_DIRECT_MIGRATION_KEY] = True
    return True


_XRAY_METRICS_API_TAG = "__app_metrics_api"
_XRAY_METRICS_API_INBOUND_TAG = "__app_metrics_api_in"


class AppController(QObject):
    nodes_changed = pyqtSignal(object)
    selection_changed = pyqtSignal(object)
    connection_changed = pyqtSignal(bool)
    connection_status_changed = pyqtSignal(str, str)
    routing_changed = pyqtSignal(object)
    settings_changed = pyqtSignal(object)
    subscriptions_changed = pyqtSignal(object)  # list[dict] of subscriptions
    log_line = pyqtSignal(str)
    status = pyqtSignal(str, str)
    admin_relaunch_requested = pyqtSignal()
    bulk_task_progress = pyqtSignal(str, int, int, bool)  # task, current, total, completed
    request_transition_signal = pyqtSignal(str)
    ping_updated = pyqtSignal(str, object)
    speed_updated = pyqtSignal(str, object, bool)  # node_id, speed_mbps, is_alive
    speed_progress_updated = pyqtSignal(str, int)  # node_id, percent
    speed_test_cancelled = pyqtSignal(int, int)  # completed, total
    connectivity_test_done = pyqtSignal(bool, str, object)
    live_metrics_updated = pyqtSignal(object)
    xray_update_result = pyqtSignal(object)
    xray_update_progress = pyqtSignal(int)
    resource_update_result = pyqtSignal(object)
    resource_update_progress = pyqtSignal(str, int)
    lock_state_changed = pyqtSignal(bool)
    passphrase_required = pyqtSignal()
    auto_switch_triggered = pyqtSignal(str)  # node name we're switching to
    transition_state_changed = pyqtSignal(bool, str)
    _transition_completed = pyqtSignal(bool, str, str, int)
    _metrics_request = pyqtSignal(bool)

    def __init__(self, parent: QObject | None = None):
        super().__init__(parent)
        self.storage = StateStorage()
        self.xray = XrayManager(self)
        self.singbox = SingBoxManager(self)
        self.zapret = ZapretManager(self)
        self.proxy = ProxyManager()
        # An abnormal exit leaves the registry pointing at our own dead port;
        # repair it at launch instead of waiting for the next connect/disconnect.
        try:
            self.proxy.reconcile_stale_state()
        except Exception:
            pass
        self.discord_proxy = DiscordProxyManager()
        self.network_monitor = NetworkMonitor(parent=self)

        self.state = AppState()
        self.recent_logs: list[str] = []
        self.connected = False
        self.locked = False

        # --- Domain-separated logging (core / app / traffic / errors) ---
        configure_logging(
            LOG_DIR,
            upload_url="",
            app_version=APP_VERSION,
        )
        self._logger = get_logger("app")
        # Check and log previous native crash logs (faulthandler)
        prev_fh_path = LOG_DIR / "faulthandler.prev"
        if prev_fh_path.is_file():
            try:
                prev_content = prev_fh_path.read_text(encoding="utf-8", errors="replace").strip()
                if prev_content:
                    self._logger.error(
                        f"[app] Native crash traceback detected from the previous run:\n{prev_content}"
                    )
                prev_fh_path.unlink()
            except Exception:
                pass
        self._core_logger = get_logger("core")
        self._traffic_logger = get_logger("traffic")
        self._domain_loggers = {
            "core": self._core_logger,
            "traffic": self._traffic_logger,
            "app": self._logger,
        }

        self._country_resolver: CountryResolver | None = None
        self._ping_worker: PingWorker | None = None
        self._speed_worker: SpeedTestWorker | None = None
        self._ping_node_map: dict[str, Node] = {}
        self._speed_node_map: dict[str, Node] = {}
        self._connectivity_worker: ConnectivityTestWorker | None = None
        self._metrics_worker: LiveMetricsWorker | None = None
        self._retired_metrics_workers: list[LiveMetricsWorker] = []
        self._retired_workers: list[QThread] = []
        self._xray_update_worker: XrayCoreUpdateWorker | None = None
        self._resource_update_workers: list[QThread] = []
        self._pending_regional_preset = ""
        self._singbox_documents = SingboxDocumentCache()
        self._parsed_singbox_document: ParsedSingboxDocument | None = None
        self._ping_total = 0
        self._ping_completed = 0
        self._speed_total = 0
        self._speed_completed = 0
        self._xray_update_silent = False
        self._xray_update_proxy_url: str | None = None
        self._reconnect_after_xray_update = False
        self._reconnect_after_resource_updates = False
        self._pending_update_disconnects: list[QThread] = []
        self._xray_update_apply_requested = False
        self._reconnecting = False
        self._resume_reconnect_pending = False
        self._connecting = False
        self._disconnecting = False
        self._cleaning_connection_state = False
        self._switching = False
        self._active_core: str = "xray"  # "xray" | "singbox"
        self._protect_ss_port: int = 0
        self._protect_ss_password: str = ""
        self._xray_api_port: int = 0
        self._traffic_history = TrafficHistoryStorage()
        self._traffic_save_counter = 0

        # --- Auto-switch state ---
        self._auto_switch_low_since: float = 0.0
        self._auto_switch_last_switch: float = 0.0
        self._auto_switch_high_ticks: int = 0
        self._auto_switch_active_download: bool = False
        self._auto_switch_cycle_attempts: int = 0
        self._auto_switch_exhausted: bool = False
        self._auto_switch_transitioning: bool = False
        self._health_down_since: float = 0.0
        self._kill_switch_engaged: bool = False
        self._active_session: ActiveSessionSnapshot | None = None
        self._desired_connected = False
        self._transition_active = False
        self._transition_scheduled = False
        self._transition_pending = False
        self._transition_reason = ""
        self._transition_generation = 0
        self._blocked_transition_signature = ""
        self._transition_worker_thread: threading.Thread | None = None
        self._transition_worker_lock = threading.Lock()
        self._deferred_services_started = False
        self._shutting_down = False
        self._system_shutdown = False
        self._background_threads: set[threading.Thread] = set()
        self._background_threads_lock = threading.Lock()
        self._save_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="state-save")
        self._save_futures: set[Future] = set()
        self._save_futures_lock = threading.Lock()
        self._save_executor_shutdown = False

        self.xray.log_received.connect(lambda line: self._on_core_log("xray", line))
        self.xray.error.connect(self._on_xray_error)
        self.xray.state_changed.connect(self._on_core_state_changed)
        self.xray.stopped.connect(lambda code: self._on_core_stopped("xray", code))

        self.singbox.log_received.connect(lambda line: self._on_core_log("singbox", line))
        self.singbox.error.connect(self._on_singbox_error)
        self.singbox.state_changed.connect(self._on_core_state_changed)
        self.singbox.stopped.connect(lambda code: self._on_core_stopped("singbox", code))

        self.zapret.log_line.connect(lambda line: self._on_core_log("zapret", line))

        self.network_monitor.network_changed.connect(self._on_network_changed)

        self._lock_timer = QTimer(self)
        self._lock_timer.setInterval(15_000)
        self._lock_timer.timeout.connect(self._check_auto_lock)
        self._save_timer = QTimer(self)
        self._save_timer.setSingleShot(True)
        self._save_timer.setInterval(250)
        self._save_timer.timeout.connect(self._flush_scheduled_save)
        self._save_pending = False
        self._transition_timer = QTimer(self)
        self._transition_timer.setSingleShot(True)
        self._transition_timer.timeout.connect(self._drain_transition_queue)
        self.request_transition_signal.connect(self._request_transition, Qt.ConnectionType.QueuedConnection)
        self._transition_completed.connect(
            self._on_transition_action_complete,
            Qt.ConnectionType.QueuedConnection,
        )
        self._metrics_request.connect(self._on_metrics_request, Qt.ConnectionType.QueuedConnection)
        self._startup_sync_active = False
        self._startup_sync_timer = QTimer(self)
        self._startup_sync_timer.setInterval(120_000)
        self._startup_sync_timer.timeout.connect(self._schedule_startup_state_sync)

    def load(self) -> bool:
        try:
            self.state = self.storage.load()
        except PassphraseRequired:
            self.passphrase_required.emit()
            return False
        except StateLoadError as exc:
            self.status.emit("error", str(exc))
            self.state = self.storage._default_state()
            return False

        self._migrate_sort_order()
        region = normalize_regional_preset(self.state.settings.regional_preset)
        current_preset = str(self.state.routing.preset_id or "").strip().lower()
        normalized_preset = normalize_routing_preset_for_region(current_preset, region)
        migrated = normalized_preset != current_preset
        if migrated:
            self.state.routing = build_routing_preset(self.state.routing, normalized_preset)
            self._log(
                f"[routing] normalized saved preset for {region}: "
                f"{current_preset} -> {normalized_preset}"
            )
        repaired_routing = repair_builtin_preset_service_routes(self.state.routing)
        if repaired_routing is not self.state.routing:
            self.state.routing = repaired_routing
            migrated = True
            self._log("[routing] restored missing service routes for the saved blocked preset")
        migrated = apply_masque_direct_update_once(self.state) or migrated
        migrated = apply_dns_defaults_update_once(self.state) or migrated
        if not is_process_elevated() and self.state.settings.tun_mode:
            # Preserve the usable proxy-only application instead of letting a
            # saved TUN preference make non-admin startup fail completely.
            self.state.settings.tun_mode = False
            migrated = True
        if migrated:
            self.save()
        self.nodes_changed.emit(self.state.nodes)
        self.selection_changed.emit(self.selected_node)
        self.routing_changed.emit(self.state.routing)
        self.settings_changed.emit(self.state.settings)
        self._configure_diagnostics_upload()
        self.subscriptions_changed.emit(list(self.state.subscriptions))
        return True

    def _configure_diagnostics_upload(self) -> None:
        upload_url = (
            DIAGNOSTICS_UPLOAD_URL
            if getattr(self.state.settings, "diagnostics_upload_enabled", True)
            else ""
        )
        configure_diagnostics_upload(upload_url=upload_url, app_version=APP_VERSION)

    def start_deferred_services(self) -> None:
        """Start non-visual work only after the first QML frame is available."""
        if self._deferred_services_started:
            return
        self._deferred_services_started = True
        self.network_monitor.start()
        self._lock_timer.start()

        if self._detect_countries_sync():
            self.nodes_changed.emit(self.state.nodes)
        QTimer.singleShot(500, self._start_country_ip_resolution)

        self._start_background_task(self._probe_core_versions, "core-version-probe")
        self._start_background_task(self._prewarm_connection_context, "connection-context-prewarm")

        if self.state.settings.always_run_as_admin:
            try:
                set_always_run_as_admin(True)
            except Exception as exc:
                self.status.emit("error", f"Ошибка настройки запуска от администратора: {exc}")
        self._reconcile_startup_registration()
        self._startup_sync_timer.start()
        # Restrictions are explained by the relevant controls when clicked.
        # A delayed global warning here could surface during an unrelated
        # server switch and incorrectly make that switch look rejected.

    def _reconcile_startup_registration(self) -> None:
        try:
            if self._sync_startup_state_from_windows():
                return
            set_startup_enabled(
                APP_NAME,
                bool(self.state.settings.launch_on_startup),
                build_startup_command(
                    in_tray=bool(getattr(self.state.settings, "launch_in_tray_on_startup", True))
                ),
            )
        except Exception as exc:
            self._logger.warning("Failed to reconcile startup registration: %s", exc)

    def _schedule_startup_state_sync(self) -> None:
        # Registry + schtasks probing must never run on the GUI thread.
        if self._startup_sync_active or self._shutting_down:
            return
        self._startup_sync_active = True
        self._start_background_task(self._run_startup_state_sync, "startup-state-sync")

    def _run_startup_state_sync(self) -> None:
        try:
            self._sync_startup_state_from_windows()
        finally:
            self._startup_sync_active = False

    def _sync_startup_state_from_windows(self) -> bool:
        try:
            command = build_startup_command(
                in_tray=bool(getattr(self.state.settings, "launch_in_tray_on_startup", True))
            )
            if not bool(self.state.settings.launch_on_startup):
                if get_startup_state(APP_NAME) != STARTUP_STATE_ABSENT:
                    set_startup_enabled(APP_NAME, False, command)
                return False
            if get_startup_state(APP_NAME) != STARTUP_STATE_DISABLED:
                return False
            # StartupApproved can be reset by Windows when an executable is
            # replaced, especially when an elevated task is also registered.
            # The persisted user preference is authoritative: repair the
            # registration instead of silently turning autostart off.
            set_startup_enabled(APP_NAME, True, command)
            return True
        except Exception as exc:
            self._logger.warning("Failed to sync startup state from Windows: %s", exc)
            return False

    def _probe_core_versions(self) -> None:
        version = get_xray_version(self.state.settings.xray_path)
        if version:
            self._log(f"[core] {version}")
        else:
            self.status.emit("warning", "Не удалось прочитать версию Xray")
        sb_version = get_singbox_version(self.state.settings.singbox_path)
        if sb_version:
            self._log(f"[core] sing-box: {sb_version}")

    def _prewarm_connection_context(self) -> None:
        get_windows_default_route_context()
        node = self.selected_node
        if node is not None:
            prime_endpoint_resolution(node.server)

    def _start_background_task(self, target, name: str) -> None:
        def _run() -> None:
            try:
                target()
            except Exception:
                self._logger.exception("[app] Background task %s failed", name)
            finally:
                with self._background_threads_lock:
                    self._background_threads.discard(threading.current_thread())

        thread = threading.Thread(target=_run, name=name)
        with self._background_threads_lock:
            self._background_threads.add(thread)
        thread.start()

    def _join_background_tasks(self, timeout: float = 3.0) -> None:
        with self._background_threads_lock:
            threads = list(self._background_threads)
        deadline = time.monotonic() + max(0.1, timeout)
        for thread in threads:
            if thread is not threading.current_thread():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                thread.join(timeout=remaining)

    def set_data_passphrase(self, passphrase: str) -> None:
        self.storage.passphrase = passphrase
        self.save()
        self.status.emit("success", "Шифрование данных включено")

    def clear_data_passphrase(self) -> None:
        self.storage.passphrase = ""
        self.save()
        self.status.emit("info", "Шифрование данных отключено (портативный режим)")

    def is_data_encrypted(self) -> bool:
        return self.storage.is_encrypted()

    @pyqtSlot()
    def save(self) -> None:
        if self.thread() != QThread.currentThread():
            self._enqueue_state_save()
            return
        if self._save_timer.isActive():
            self._save_timer.stop()
        self._save_pending = False
        self._enqueue_state_save()

    @pyqtSlot()
    def schedule_save(self) -> None:
        if self.thread() != QThread.currentThread():
            QMetaObject.invokeMethod(self, "schedule_save", Qt.ConnectionType.QueuedConnection)
            return
        self._save_pending = True
        self._save_timer.start()

    def _flush_scheduled_save(self) -> None:
        if not self._save_pending:
            return
        self._save_pending = False
        self._enqueue_state_save()

    def _enqueue_state_save(self) -> Future | None:
        if self._save_executor_shutdown:
            return None
        try:
            snapshot = deepcopy(self.state)
        except Exception as exc:
            self._logger.error(f"[state] Failed to snapshot state for saving: {exc}")
            return None
        future = self._save_executor.submit(self.storage.save, snapshot)
        with self._save_futures_lock:
            self._save_futures.add(future)

        def _cleanup(done: Future) -> None:
            with self._save_futures_lock:
                self._save_futures.discard(done)
            try:
                done.result()
            except Exception as exc:
                self._logger.error(f"[state] Failed to save state: {exc}")

        future.add_done_callback(_cleanup)
        return future

    def _flush_state_saves(self, timeout: float = 5.0) -> None:
        if self.thread() == QThread.currentThread():
            if self._save_timer.isActive():
                self._save_timer.stop()
            if self._save_pending:
                self._save_pending = False
                self._enqueue_state_save()
        deadline = datetime.now(timezone.utc).timestamp() + max(0.0, timeout)
        while True:
            with self._save_futures_lock:
                futures = list(self._save_futures)
            if not futures:
                return
            remaining = deadline - datetime.now(timezone.utc).timestamp()
            if remaining <= 0:
                self._logger.warning("[state] Timed out waiting for pending state saves")
                return
            for future in futures:
                try:
                    future.result(timeout=min(remaining, 0.25))
                except FutureTimeoutError:
                    pass
                except Exception:
                    pass

    @staticmethod
    def _signature(payload: object) -> str:
        return signature_operation(payload)

    def _routing_signature(self, routing: RoutingSettings | None = None) -> str:
        return routing_signature_operation(self, routing)

    def is_singbox_editor_mode(self, settings: AppSettings | None = None) -> bool:
        settings = settings or self.state.settings
        return bool(settings.tun_mode)

    def uses_xray_raw_config(self, settings: AppSettings | None = None) -> bool:
        settings = settings or self.state.settings
        return not self.is_singbox_editor_mode(settings)

    def _can_connect_without_selected_node(self, settings: AppSettings | None = None) -> bool:
        settings = settings or self.state.settings
        if self.is_singbox_editor_mode(settings):
            _, _, has_proxy_outbound = self._inspect_active_singbox_config()
            return not has_proxy_outbound
        if self.uses_xray_raw_config(settings):
            _, _, has_proxy_outbound, _, _, _ = self._inspect_active_xray_config()
            return not has_proxy_outbound
        return False

    def _system_proxy_bypass_lan(self, settings: AppSettings | None = None) -> bool:
        return system_proxy_bypass_lan_operation(self, settings)

    def get_singbox_config_dir(self) -> Path:
        SINGBOX_CONFIGS_DIR.mkdir(parents=True, exist_ok=True)
        return SINGBOX_CONFIGS_DIR

    def get_xray_config_dir(self) -> Path:
        XRAY_CONFIGS_DIR.mkdir(parents=True, exist_ok=True)
        return XRAY_CONFIGS_DIR

    def get_singbox_template_dir(self) -> Path:
        SINGBOX_TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)
        return SINGBOX_TEMPLATES_DIR

    def get_xray_template_dir(self) -> Path:
        XRAY_TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)
        return XRAY_TEMPLATES_DIR

    def _normalize_singbox_config_relative_path(self, value: str | Path | None) -> str:
        return normalize_relative_json_path(value, SINGBOX_DEFAULT_CONFIG_NAME)

    def _normalize_singbox_template_relative_path(self, value: str | Path | None) -> str:
        return self._normalize_singbox_config_relative_path(value)

    def _resolve_singbox_config_path(self, path: str | Path | None = None) -> Path:
        value = self.state.settings.singbox_config_file if path is None or not str(path).strip() else path
        return resolve_profile_path(
            self.get_singbox_config_dir(),
            value,
            SINGBOX_DEFAULT_CONFIG_NAME,
            label="sing-box",
        )

    def _resolve_singbox_template_path(self, path: str | Path | None = None) -> Path:
        value = self.state.settings.singbox_template_file if path is None or not str(path).strip() else path
        return resolve_profile_path(
            self.get_singbox_template_dir(),
            value,
            SINGBOX_DEFAULT_CONFIG_NAME,
            label="sing-box template",
        )

    def _normalize_xray_config_relative_path(self, value: str | Path | None) -> str:
        return normalize_relative_json_path(value, XRAY_DEFAULT_CONFIG_NAME)

    def _normalize_xray_template_relative_path(self, value: str | Path | None) -> str:
        return self._normalize_xray_config_relative_path(value)

    def _resolve_xray_config_path(self, path: str | Path | None = None) -> Path:
        value = self.state.settings.xray_config_file if path is None or not str(path).strip() else path
        return resolve_profile_path(
            self.get_xray_config_dir(),
            value,
            XRAY_DEFAULT_CONFIG_NAME,
            label="xray",
        )

    def _resolve_xray_template_path(self, path: str | Path | None = None) -> Path:
        value = self.state.settings.xray_template_file if path is None or not str(path).strip() else path
        return resolve_profile_path(
            self.get_xray_template_dir(),
            value,
            XRAY_DEFAULT_CONFIG_NAME,
            label="xray template",
        )

    def _set_active_singbox_config_path(self, path: Path, *, emit_signal: bool = True) -> Path:
        resolved = self._resolve_singbox_config_path(path)
        relative = resolved.relative_to(self.get_singbox_config_dir().resolve()).as_posix()
        if self.state.settings.singbox_config_file == relative:
            return resolved
        self.state.settings.singbox_config_file = relative
        if emit_signal:
            self.settings_changed.emit(self.state.settings)
        self.schedule_save()
        return resolved

    def _set_active_singbox_template_path(self, path: Path, *, emit_signal: bool = True) -> Path:
        resolved = self._resolve_singbox_template_path(path)
        relative = resolved.relative_to(self.get_singbox_template_dir().resolve()).as_posix()
        if self.state.settings.singbox_template_file == relative:
            return resolved
        self.state.settings.singbox_template_file = relative
        if emit_signal:
            self.settings_changed.emit(self.state.settings)
        self.schedule_save()
        return resolved

    def _set_active_xray_config_path(self, path: Path, *, emit_signal: bool = True) -> Path:
        resolved = self._resolve_xray_config_path(path)
        relative = resolved.relative_to(self.get_xray_config_dir().resolve()).as_posix()
        if self.state.settings.xray_config_file == relative:
            return resolved
        self.state.settings.xray_config_file = relative
        if emit_signal:
            self.settings_changed.emit(self.state.settings)
        self.schedule_save()
        return resolved

    def _set_active_xray_template_path(self, path: Path, *, emit_signal: bool = True) -> Path:
        resolved = self._resolve_xray_template_path(path)
        relative = resolved.relative_to(self.get_xray_template_dir().resolve()).as_posix()
        if self.state.settings.xray_template_file == relative:
            return resolved
        self.state.settings.xray_template_file = relative
        if emit_signal:
            self.settings_changed.emit(self.state.settings)
        self.schedule_save()
        return resolved

    @staticmethod
    def _default_singbox_config_text() -> str:
        return default_singbox_config_text()

    @staticmethod
    def _default_xray_config_text() -> str:
        return default_xray_config_text(
            proxy_host=PROXY_HOST,
            socks_port=DEFAULT_SOCKS_PORT,
            http_port=DEFAULT_HTTP_PORT,
            api_port=DEFAULT_XRAY_STATS_API_PORT,
        )

    def get_active_singbox_config_path(self) -> Path:
        return get_active_config_path_operation(self, "singbox")

    def get_active_singbox_config_name(self) -> str:
        return get_active_config_name_operation(self, "singbox")

    def get_active_singbox_template_path(self) -> Path | None:
        return get_active_template_path_operation(self, "singbox")

    def get_active_xray_config_path(self) -> Path:
        return get_active_config_path_operation(self, "xray")

    def get_active_xray_config_name(self) -> str:
        return get_active_config_name_operation(self, "xray")

    def get_active_xray_template_path(self) -> Path | None:
        return get_active_template_path_operation(self, "xray")

    def get_effective_proxy_ports(self) -> tuple[int, int]:
        session = self._active_session
        if session is not None and session.socks_port > 0 and session.http_port > 0:
            return session.socks_port, session.http_port
        try:
            _, _, _, socks_port, http_port, _ = self._inspect_active_xray_config()
        except Exception:
            socks_port = 0
            http_port = 0
        if socks_port > 0 and http_port > 0:
            return socks_port, http_port
        return int(self.state.settings.local_socks_port), int(self.state.settings.local_http_port)

    def get_effective_http_proxy_port(self) -> int | None:
        session = self._active_session
        if (session is not None and session.tun_mode) or self.state.settings.tun_mode:
            return None
        _, http_port = self.get_effective_proxy_ports()
        return http_port if http_port > 0 else None

    def get_effective_http_proxy_url(self) -> str | None:
        """Return the live local HTTP proxy URL, including optional auth."""
        from urllib.parse import quote

        port = self.get_effective_http_proxy_port()
        if not port:
            return None
        settings = self.state.settings
        username = str(getattr(settings, "proxy_auth_username", "") or "").strip()
        password = str(getattr(settings, "proxy_auth_password", "") or "")
        if bool(getattr(settings, "proxy_auth_enabled", False)) and username and password:
            credentials = f"{quote(username, safe='')}:{quote(password, safe='')}@"
        else:
            credentials = ""
        return f"http://{credentials}{PROXY_HOST}:{int(port)}"

    def owned_core_process_pids(self) -> set[int]:
        """Return main and temporary core PIDs currently owned by this Lumen instance."""
        pids: set[int] = set()
        for manager in (self.xray, self.singbox):
            proc = getattr(manager, "_proc", None)
            pid = int(getattr(proc, "pid", 0) or 0)
            if pid > 0:
                pids.add(pid)

        workers = [self._ping_worker, self._speed_worker, *self._retired_workers]
        for worker in workers:
            if worker is None:
                continue
            lock = getattr(worker, "_process_lock", None)
            try:
                if lock is None:
                    processes = list(getattr(worker, "_processes", ()))
                else:
                    with lock:
                        processes = list(getattr(worker, "_processes", ()))
            except Exception:
                continue
            for proc in processes:
                pid = int(getattr(proc, "pid", 0) or 0)
                if pid > 0:
                    pids.add(pid)
        return pids

    def owned_core_executable_paths(self) -> set[Path]:
        """Return configured core paths used by this Lumen instance.

        PID snapshots can briefly lag while Xray/sing-box is being replaced.
        The canonical image path is a second ownership signal that prevents
        our own core from being reported as a foreign VPN client in that gap.
        """
        paths: set[Path] = set()
        settings = self.state.settings
        for manager, configured, default in (
            (self.xray, getattr(settings, "xray_path", ""), XRAY_PATH_DEFAULT),
            (self.singbox, getattr(settings, "singbox_path", ""), SINGBOX_PATH_DEFAULT),
        ):
            path = getattr(manager, "_exe_path", None)
            if path is None:
                path = resolve_configured_path(
                    configured,
                    default_path=default,
                    use_default_if_empty=True,
                    migrate_default_location=False,
                )
            if path is not None:
                paths.add(Path(path))
        return paths

    def _cache_singbox_document_state(self, path: Path, text: str) -> SingboxDocumentState:
        state = self._singbox_documents.cache_state(path, text)
        parsed = self._parsed_singbox_document
        if parsed is not None and (parsed.source_path != state.source_path or parsed.text_hash != state.text_hash):
            self._parsed_singbox_document = None
        return state

    def _get_singbox_document_state(self) -> SingboxDocumentState:
        path = self._ensure_active_singbox_config()
        return self._singbox_documents.get_state(path)

    def _default_singbox_template_path_for_config(self, config_path: Path) -> Path | None:
        relative = config_path.relative_to(self.get_singbox_config_dir().resolve()).as_posix()
        template = self._resolve_singbox_template_path(relative)
        return template if template.exists() else None

    def _default_xray_template_path_for_config(self, config_path: Path) -> Path | None:
        relative = config_path.relative_to(self.get_xray_config_dir().resolve()).as_posix()
        template = self._resolve_xray_template_path(relative)
        return template if template.exists() else None

    def _ensure_active_singbox_config(self, path: str | Path | None = None) -> Path:
        return ensure_active_config_operation(self, "singbox", path)

    def _ensure_active_xray_config(self, path: str | Path | None = None) -> Path:
        return ensure_active_config_operation(self, "xray", path)

    def load_active_singbox_config_text(self) -> tuple[Path, str]:
        return load_active_config_text_operation(self, "singbox")

    def load_active_xray_config_text(self) -> tuple[Path, str]:
        return load_active_config_text_operation(self, "xray")

    def load_singbox_config_text(self, path: str | Path) -> tuple[Path, str]:
        return load_config_text_operation(self, "singbox", path)

    def load_xray_config_text(self, path: str | Path) -> tuple[Path, str]:
        return load_config_text_operation(self, "xray", path)

    def import_singbox_template(self, path: str | Path) -> tuple[Path, str]:
        return import_template_operation(self, "singbox", path)

    def import_xray_template(self, path: str | Path) -> tuple[Path, str]:
        return import_template_operation(self, "xray", path)

    def reset_active_singbox_config_to_template(self) -> tuple[bool, Path | None, str]:
        return reset_active_config_to_template_operation(self, "singbox")

    def reset_active_xray_config_to_template(self) -> tuple[bool, Path | None, str]:
        return reset_active_config_to_template_operation(self, "xray")

    def save_singbox_config_text(self, text: str, path: str | Path | None = None) -> Path:
        return save_config_text_operation(self, "singbox", text, path)

    def save_xray_config_text(self, text: str, path: str | Path | None = None) -> Path:
        return save_config_text_operation(self, "xray", text, path)

    @staticmethod
    def _format_json_error_message(text: str, exc: json.JSONDecodeError) -> str:
        return format_json_error_message(text, exc)

    def validate_json_text(self, text: str) -> tuple[bool, str]:
        return validate_json_text(text)

    def validate_singbox_json_text(self, text: str) -> tuple[bool, str]:
        return self.validate_json_text(text)

    def validate_xray_json_text(self, text: str) -> tuple[bool, str]:
        ok, message = self.validate_json_text(text)
        if not ok:
            return False, message
        if "fakedns" in text.lower():
            return (
                True,
                "JSON корректен. Внимание: в конфиге есть FakeDNS; некоторые версии Xray-core могут падать на старте. "
                "Если запуск завершается с panic, отключите FakeDNS или обновите Xray core.",
            )
        return True, message

    def apply_singbox_config_text(self, text: str) -> tuple[bool, Path | None, str]:
        return apply_singbox_config_text_operation(self, text)

    def apply_xray_config_text(self, text: str) -> tuple[bool, Path | None, str]:
        return apply_xray_config_text_operation(self, text)

    @staticmethod
    def _config_has_proxy_outbound(payload: Any) -> bool:
        return config_has_proxy_outbound(payload)

    @staticmethod
    def _is_local_runtime_host(value: str) -> bool:
        return is_local_runtime_host(value)

    @staticmethod
    def _infer_singbox_outbound_endpoint(outbound: dict[str, Any]) -> tuple[str, int]:
        return infer_singbox_outbound_endpoint(outbound)

    @staticmethod
    def _infer_xray_outbound_endpoint(outbound: dict[str, Any]) -> tuple[str, int]:
        return infer_xray_outbound_endpoint(outbound)

    @staticmethod
    def _infer_singbox_ping_target(payload: dict[str, Any], node: Node | None) -> tuple[str, int]:
        return infer_singbox_ping_target(payload, node)

    @staticmethod
    def _infer_xray_ping_target(payload: dict[str, Any], node: Node | None) -> tuple[str, int]:
        return infer_xray_ping_target(payload, node)

    @staticmethod
    def _ensure_dict(parent: dict[str, Any], key: str) -> dict[str, Any]:
        return ensure_dict(parent, key)

    @staticmethod
    def _ensure_list(parent: dict[str, Any], key: str) -> list[Any]:
        return ensure_list(parent, key)

    @staticmethod
    def _replace_or_append_tagged(items: list[Any], tag: str, payload: dict[str, Any]) -> None:
        replace_or_append_tagged(items, tag, payload)

    @staticmethod
    def _collect_xray_inbound_ports(payload: Any) -> set[int]:
        return collect_xray_inbound_ports(payload)

    def _ensure_xray_metrics_contract(
        self,
        payload: dict[str, Any],
        *,
        allocate_port: bool,
    ) -> tuple[int, tuple[str, ...]]:
        return ensure_xray_metrics_contract_operation(self, payload, allocate_port=allocate_port)

    def _inspect_active_singbox_config(self) -> tuple[Path, str, bool]:
        state = self._get_singbox_document_state()
        return state.source_path, state.text_hash, state.has_proxy_outbound

    @staticmethod
    def _extract_xray_runtime_ports(payload: Any) -> tuple[int, int, int]:
        return extract_xray_runtime_ports(payload)

    def _inspect_active_xray_config(self) -> tuple[Path, str, bool, int, int, int]:
        return inspect_active_xray_config_operation(self)

    def _plan_runtime_singbox(self, node: Node | None = None, *, tun_mode: bool = True) -> SingboxRuntimePlan:
        state = self._get_singbox_document_state()
        document = self._parsed_singbox_document
        if document is None or document.source_path != state.source_path or document.text_hash != state.text_hash:
            document = parse_singbox_document(state.source_path, state.text)
            self._parsed_singbox_document = document
        route_context = get_windows_default_route_context()
        system_dns_servers = route_context.dns_servers if route_context is not None else ()
        preferred_relay_port = 0
        preferred_protect_port = 0
        preferred_protect_password = ""
        session = self._active_session
        if session is not None and session.active_core == "singbox" and session.hybrid:
            preferred_relay_port = session.sidecar_relay_port
            preferred_protect_port = session.protect_ss_port
            preferred_protect_password = session.protect_ss_password
        runtime_routing = self._runtime_routing()
        return plan_singbox_runtime(
            document,
            node,
            routing=runtime_routing,
            enable_final_fragment=self.state.settings.enable_final_fragment,
            fragment_packets=self.state.settings.fragment_packets,
            fragment_length=self.state.settings.fragment_length,
            fragment_delay=self.state.settings.fragment_delay,
            tail_fragment_enabled=self.state.settings.tail_fragment_enabled,
            multiplex_enabled=self.state.settings.multiplex_enabled,
            multiplex_concurrency=self.state.settings.multiplex_concurrency,
            discord_proxy_enabled=self.state.settings.discord_proxy_enabled,
            tun_strict_route=self.state.settings.tun_strict_route,
            tun_stack=self.state.settings.tun_stack,
            tun_mtu=self.state.settings.tun_mtu,
            tun_endpoint_independent_nat=self.state.settings.tun_endpoint_independent_nat,
            tun_block_quic=self.state.settings.tun_block_quic,
            local_socks_port=self.state.settings.local_socks_port,
            local_http_port=self.state.settings.local_http_port,
            proxy_auth_username=(
                self.state.settings.proxy_auth_username
                if self.state.settings.proxy_auth_enabled
                else ""
            ),
            proxy_auth_password=(
                self.state.settings.proxy_auth_password
                if self.state.settings.proxy_auth_enabled
                else ""
            ),
            preferred_relay_port=preferred_relay_port,
            preferred_protect_port=preferred_protect_port,
            preferred_protect_password=preferred_protect_password,
            system_dns_servers=system_dns_servers,
            tun_mode=tun_mode,
            enable_hot_switch=bool(tun_mode),
            hot_switch_nodes=tuple(self.state.nodes),
        )

    def _start_singbox_runtime_plan(self, plan: SingboxRuntimePlan) -> bool:
        if plan.xray_sidecar is not None:
            self._protect_ss_port = plan.xray_sidecar.protect_port
            self._protect_ss_password = plan.xray_sidecar.protect_password
            self._log(
                "[tun] starting hybrid xray sidecar "
                f"relay=127.0.0.1:{plan.xray_sidecar.relay_port} "
                f"protect=127.0.0.1:{plan.xray_sidecar.protect_port}"
            )
            if not self.xray.start(
                self.state.settings.xray_path,
                plan.xray_sidecar.config,
                prevalidated=True,
            ):
                self._protect_ss_port = 0
                self._protect_ss_password = ""
                return False
        else:
            self._protect_ss_port = 0
            self._protect_ss_password = ""
            if self.xray.is_running and not self.xray.stop():
                self._log("[tun] failed to stop xray before starting sing-box local proxy inbounds")
                return False

        sb_ok = self.singbox.start(
            self.state.settings.singbox_path,
            plan.singbox_config,
            prevalidated=True,
        )
        self._log(f"[tun] sing-box start result: {sb_ok}")
        if sb_ok:
            return True

        if plan.xray_sidecar is not None and self.xray.is_running:
            self.xray.stop()
        self._protect_ss_port = 0
        self._protect_ss_password = ""
        return False

    def _build_runtime_xray_config(self, node: Node | None = None) -> XrayRuntimeConfig:
        return build_runtime_xray_config_operation(self, node)

    def _runtime_routing(
        self,
        routing: RoutingSettings | None = None,
        settings: AppSettings | None = None,
    ) -> RoutingSettings:
        settings = settings or self.state.settings
        routing = routing or self.state.routing
        return routing_with_ip_preference(
            routing,
            prefer_ipv6=bool(getattr(settings, "prefer_ipv6", False)),
        )

    def _transition_signature(
        self,
        node: Node | None = None,
        settings: AppSettings | None = None,
        routing: RoutingSettings | None = None,
    ) -> str:
        return transition_signature_operation(self, node, settings, routing)

    def _xray_layer_signature(
        self,
        node: Node | None = None,
        settings: AppSettings | None = None,
        routing: RoutingSettings | None = None,
    ) -> str:
        return xray_layer_signature_operation(self, node, settings, routing)

    def _tun_layer_signature(
        self,
        node: Node | None = None,
        settings: AppSettings | None = None,
        routing: RoutingSettings | None = None,
    ) -> str:
        return tun_layer_signature_operation(self, node, settings, routing)

    def _capture_active_session(
        self,
        node: Node | None,
        *,
        tun: bool,
        core: str,
        api_port: int,
        clash_api_secret: str = "",
        clash_api_selector: str = "",
        clash_api_node_signatures: tuple[tuple[str, str], ...] = (),
        hybrid: bool = False,
        socks_port: int | None = None,
        http_port: int | None = None,
        xray_inbound_tags: tuple[str, ...] | None = None,
        sidecar_relay_port: int = 0,
        protect_ss_port: int = 0,
        protect_ss_password: str = "",
        ping_host: str = "",
        ping_port: int = 0,
    ) -> None:
        settings = self.state.settings
        routing = self.state.routing
        if socks_port is None:
            socks_port = int(settings.local_socks_port)
        if http_port is None:
            http_port = int(settings.local_http_port)
        if xray_inbound_tags is None:
            xray_inbound_tags = ()
        if not ping_host and node is not None:
            ping_host = node.server
        if ping_port <= 0 and node is not None:
            ping_port = int(node.port)
        proxy_bypass_lan = bool(routing.bypass_lan) if tun else self._system_proxy_bypass_lan(settings)
        self._active_session = build_active_session_snapshot(
            node_id=node.id if node else None,
            node_server=node.server if node else "",
            active_core=core,
            tun_mode=bool(tun),
            proxy_enabled=bool(settings.enable_system_proxy),
            proxy_bypass_lan=proxy_bypass_lan,
            xray_path=str(settings.xray_path),
            singbox_path=str(settings.singbox_path),
            socks_port=int(socks_port),
            http_port=int(http_port),
            routing_signature=self._routing_signature(routing),
            transition_signature=self._transition_signature(node, settings, routing),
            xray_layer_signature=self._xray_layer_signature(node, settings, routing),
            tun_layer_signature=self._tun_layer_signature(node, settings, routing),
            hybrid=hybrid,
            api_port=int(api_port),
            clash_api_secret=str(clash_api_secret),
            xray_inbound_tags=tuple(xray_inbound_tags),
            sidecar_relay_port=int(sidecar_relay_port),
            protect_ss_port=int(protect_ss_port),
            protect_ss_password=str(protect_ss_password),
            ping_host=str(ping_host),
            ping_port=int(ping_port),
            clash_api_selector=str(clash_api_selector),
            clash_api_node_signatures=tuple(clash_api_node_signatures),
        )
        self._blocked_transition_signature = ""

    def _clear_active_session(self) -> None:
        self._active_session = None

    def _apply_proxy_runtime_change(self) -> bool:
        settings = self.state.settings
        bypass_lan = self._system_proxy_bypass_lan()
        if self._active_session is not None:
            socks_port = self._active_session.socks_port
            http_port = self._active_session.http_port
        else:
            socks_port, http_port = self.get_effective_proxy_ports()
        try:
            if settings.enable_system_proxy:
                self.proxy.enable(
                    http_port,
                    socks_port,
                    bypass_lan=bypass_lan,
                    configure_firefox=bool(settings.firefox_proxy_integration),
                )
            else:
                self.proxy.disable(restore_previous=True)
        except Exception as exc:
            self._set_connection_status(
                "error",
                f"Не удалось применить системный прокси: {exc}",
                level="error",
            )
            return False

        node = self.selected_node
        if self.connected:
            self._capture_active_session(
                node,
                tun=False,
                core="xray",
                api_port=self._active_session.api_port if self._active_session else self._xray_api_port,
                socks_port=socks_port,
                http_port=http_port,
                xray_inbound_tags=self._active_session.xray_inbound_tags if self._active_session else (),
                ping_host=self._active_session.ping_host if self._active_session else "",
                ping_port=self._active_session.ping_port if self._active_session else 0,
            )
        return True

    def _needs_transition(self) -> bool:
        node = self.selected_node
        context = TransitionContext(
            desired_connected=self._desired_connected,
            locked=self.locked,
            has_selected_node=node is not None,
            can_connect_without_selected_node=self._can_connect_without_selected_node(),
            connected=self.connected,
            blocked_transition_signature=self._blocked_transition_signature,
            current_transition_signature=self._transition_signature(node),
            active_session=self._active_session,
            can_apply_proxy_runtime_change=False,
            can_tun_hot_swap=False,
            can_proxy_hot_swap=False,
        )
        return needs_transition(context)

    def _can_apply_proxy_runtime_change(self, session: ActiveSessionSnapshot) -> bool:
        settings = self.state.settings
        return can_apply_proxy_runtime_change_rule(
            session=session,
            settings_tun_mode=bool(settings.tun_mode),
            current_xray_layer_signature=self._xray_layer_signature(),
            proxy_enabled=bool(settings.enable_system_proxy),
            proxy_bypass_lan=self._system_proxy_bypass_lan(),
        )

    def _can_proxy_hot_swap(self, session: ActiveSessionSnapshot) -> bool:
        settings = self.state.settings
        if proxy_core_for_node(self.selected_node) != "xray":
            return False
        _, _, _, socks_port, http_port, _ = self._inspect_active_xray_config()
        return can_proxy_hot_swap_rule(
            session=session,
            settings_tun_mode=bool(settings.tun_mode),
            socks_port=int(socks_port),
            http_port=int(http_port),
            current_xray_layer_signature=self._xray_layer_signature(),
        )

    def _can_tun_hot_swap(self, session: ActiveSessionSnapshot) -> bool:
        settings = self.state.settings
        node = self.selected_node
        if node is None or session.node_id == node.id:
            return False
        return can_tun_hot_swap_rule(
            session=session,
            settings_tun_mode=bool(settings.tun_mode),
            has_selected_node=node is not None,
            current_tun_layer_signature=self._tun_layer_signature(node, settings, self.state.routing),
        )

    def _compute_transition_action(self) -> str | None:
        if self._resume_reconnect_pending:
            if not self._desired_connected or self.locked:
                return None
            if self.connected:
                return "reconnect"
            return "connect"
        node = self.selected_node
        session = self._active_session
        context = TransitionContext(
            desired_connected=self._desired_connected,
            locked=self.locked,
            has_selected_node=node is not None,
            can_connect_without_selected_node=self._can_connect_without_selected_node(),
            connected=self.connected,
            blocked_transition_signature=self._blocked_transition_signature,
            current_transition_signature=self._transition_signature(node),
            active_session=session,
            can_apply_proxy_runtime_change=self._can_apply_proxy_runtime_change(session) if session is not None else False,
            can_tun_hot_swap=self._can_tun_hot_swap(session) if session is not None else False,
            can_proxy_hot_swap=self._can_proxy_hot_swap(session) if session is not None else False,
        )
        return compute_transition_action(context)

    def _transition_status_text(self, action: str) -> str:
        return transition_status_text(action)

    def _emit_no_transition_feedback(self) -> None:
        if not self._desired_connected:
            return
        node = self.selected_node
        if self.locked:
            self._set_connection_status(
                "error",
                "Приложение заблокировано. Разблокируйте для подключения.",
                level="warning",
            )
            return
        if node is None and not self._can_connect_without_selected_node():
            self._set_connection_status("error", "Сначала выберите сервер.", level="warning")
            return
        if self._blocked_transition_signature and self._transition_signature(node) == self._blocked_transition_signature:
            self._set_connection_status(
                "error",
                "Предыдущая попытка подключения уже завершилась ошибкой. Измените сервер или настройки и попробуйте снова.",
                level="warning",
            )

    @pyqtSlot(str)
    def _request_transition(self, reason: str) -> None:
        if self._shutting_down or getattr(self, "_system_shutdown", False):
            return
        if self.thread() != QThread.currentThread():
            self._logger.debug(f"[app] Enqueueing transition from worker thread: {reason}")
            self.request_transition_signal.emit(reason)
            return
        self._logger.info(f"[app] Requesting transition on GUI thread: {reason}")
        self._blocked_transition_signature = ""
        self._transition_pending = True
        self._transition_reason = reason
        self._transition_generation += 1
        if self._transition_active or self._transition_scheduled:
            return
        self._transition_scheduled = True
        self._transition_timer.start(120)

    def _drain_transition_queue(self) -> None:
        if self._shutting_down:
            self._transition_scheduled = False
            self._transition_pending = False
            return
        self._transition_scheduled = False
        if self._transition_active:
            return

        if not self._transition_pending and not self._needs_transition():
            self.transition_state_changed.emit(False, "")
            return

        action = self._compute_transition_action()
        if action is None:
            self._resume_reconnect_pending = False
            self._auto_switch_transitioning = False
            self._emit_no_transition_feedback()
            self._transition_pending = False
            self.transition_state_changed.emit(False, "")
            self._resolve_pending_update_disconnects()
            return

        self._transition_pending = False
        self._resume_reconnect_pending = False
        reason = self._transition_reason or action
        self._transition_active = True
        self.transition_state_changed.emit(True, self._transition_status_text(action))
        generation = self._transition_generation
        QTimer.singleShot(16, lambda: self._execute_transition_action(action, reason, generation))

    def _execute_transition_action(self, action: str, reason: str, generation: int) -> None:
        if not self._transition_active:
            return
        if reason == "system resume" and not self._desired_connected:
            self._transition_completed.emit(True, action, reason, generation)
            return

        def _run() -> None:
            ok = False
            try:
                ok = self._run_transition_action(action, reason)
            except Exception as exc:
                self._log(f"[transition] worker error: {exc}")
            finally:
                self._transition_completed.emit(ok, action, reason, generation)
                with self._transition_worker_lock:
                    if self._transition_worker_thread is threading.current_thread():
                        self._transition_worker_thread = None

        worker = threading.Thread(
            target=_run,
            name="lumen-transition",
            daemon=True,
        )
        with self._transition_worker_lock:
            active_worker = self._transition_worker_thread
            if active_worker is not None and active_worker.is_alive():
                self._logger.warning("[transition] Refusing to start a second transition worker")
                self._transition_completed.emit(False, action, reason, generation)
                return
            self._transition_worker_thread = worker
        worker.start()

    def _join_transition_worker(self, timeout: float = 3.0) -> None:
        with self._transition_worker_lock:
            worker = self._transition_worker_thread
        if worker is None or worker is threading.current_thread():
            return
        worker.join(timeout=max(0.1, timeout))
        if worker.is_alive():
            self._logger.warning("[app] Transition worker did not stop before shutdown timeout")
            return
        with self._transition_worker_lock:
            if self._transition_worker_thread is worker:
                self._transition_worker_thread = None

    def _on_transition_action_complete(self, ok: bool, action: str, reason: str, generation: int) -> None:
        # Any finished transition ends the auto-switch window: leaving the flag
        # set would make the next unexpected drop evaluate the kill-switch as
        # inactive and tear down the system proxy (fail-open).
        self._auto_switch_transitioning = False
        if self._shutting_down:
            self._transition_active = False
            return
        was_connected, is_connected = self._refresh_connected_state()
        if was_connected != is_connected:
            self.connection_changed.emit(is_connected)
            self._on_metrics_request(is_connected)
        if (
            ok
            and action in ("proxy_hot_swap", "connect", "reconnect")
            and self.connected
            and self.state.settings.discord_proxy_enabled
            and not self.state.settings.tun_mode
        ):
            QTimer.singleShot(250, self.apply_discord_proxy)
        if ok:
            self._blocked_transition_signature = ""
        else:
            self._blocked_transition_signature = self._transition_signature()
            self._desired_connected = self.connected
        self._transition_active = False
        if generation != self._transition_generation:
            self._transition_pending = True
        if self._transition_pending or self._needs_transition():
            self._transition_scheduled = True
            self._transition_timer.start(50)
        else:
            self.transition_state_changed.emit(False, "")
        self._resolve_pending_update_disconnects()

    def _on_metrics_request(self, start: bool) -> None:
        # Always runs on the GUI thread (owns the metrics worker / its QThread).
        if start:
            self._start_metrics_worker()
        else:
            self._stop_metrics_worker()

    def _run_transition_action(self, action: str, reason: str) -> bool:
        if action == "disconnect":
            return self.disconnect_current()
        if action == "connect":
            return self.connect_selected()
        if action == "proxy_update":
            return self._apply_proxy_runtime_change()
        if action == "proxy_hot_swap":
            return self._restart_proxy_core(reason)
        if action == "tun_hot_swap":
            return self._hot_swap_node(reason)
        return self._reconnect(reason)

    # ── Country detection helpers ──

    def _detect_countries_sync(self) -> None:
        detect_countries_sync_operation(self)

    def _start_country_ip_resolution(self) -> None:
        start_country_ip_resolution_operation(self)

    def _on_countries_resolved(self, results: dict[str, str]) -> None:
        on_countries_resolved_operation(self, results)

    def shutdown(self) -> None:
        if self._shutting_down:
            return
        self._shutting_down = True
        self._logger.info("[app] AppController shutting down...")
        self._transition_timer.stop()
        self._transition_pending = False
        self._transition_scheduled = False
        self._desired_connected = False
        self._resume_reconnect_pending = False
        for worker in self._pending_update_disconnects:
            self._confirm_update_disconnect(worker, False)
        self._pending_update_disconnects.clear()
        if not getattr(self, "_system_shutdown", False):
            self._join_background_tasks()
            self._join_transition_worker()
        try:
            self._flush_state_saves(timeout=5.0)
            shutdown_operation(self)
        finally:
            self._flush_state_saves(timeout=5.0)
            self._save_executor_shutdown = True
            self._save_executor.shutdown(wait=False, cancel_futures=True)
            configure_diagnostics_upload(upload_url="", app_version=APP_VERSION)

    @staticmethod
    def _cleanup_tun_adapter(max_wait: float = 3.0) -> None:
        """Remove the wintun TUN adapter if it was left behind."""
        try:
            from .engines.singbox.manager import SingBoxManager

            SingBoxManager.cleanup_orphaned_tun_adapters(max_wait=max_wait)
        except Exception:
            pass

    @property
    def selected_node(self) -> Node | None:
        return self._get_node_by_id(self.state.selected_node_id)

    def _get_node_by_id(self, node_id: str | None) -> Node | None:
        return get_node_by_id_operation(self, node_id)

    def _prepare_node_for_runtime(self, node: Node | None) -> str | None:
        return prepare_node_for_runtime_operation(self, node)

    def export_node_outbound_json(self, node_id: str | None = None) -> str | None:
        node = self._get_node_by_id(node_id) if node_id else self.selected_node
        if not node:
            return None
        return json.dumps(node.outbound, ensure_ascii=True, indent=2)

    def export_runtime_config_json(self, node_id: str | None = None) -> str | None:
        node = self._get_node_by_id(node_id) if node_id else self.selected_node
        try:
            settings = self.state.settings
            use_singbox = self.is_singbox_editor_mode(settings) or (
                not settings.tun_mode and proxy_core_for_node(node) == "singbox"
            )
            if use_singbox:
                plan = self._plan_runtime_singbox(node, tun_mode=bool(settings.tun_mode))
                return json.dumps(plan.singbox_config, ensure_ascii=True, indent=2)
            node_protocol = (
                str((node.outbound or {}).get("protocol") or node.scheme or "").strip().lower()
                if node
                else ""
            )
            if self.uses_xray_raw_config() or node_protocol == "xray_config":
                runtime = self._build_runtime_xray_config(node)
                return json.dumps(runtime.config, ensure_ascii=True, indent=2)
            if not node:
                return None
            problem = self._prepare_node_for_runtime(node)
            if problem:
                return None
            cfg = build_xray_config(
                node,
                self._runtime_routing(),
                self.state.settings,
                socks_port=int(self.state.settings.local_socks_port),
                http_port=int(self.state.settings.local_http_port),
            )
            return json.dumps(cfg, ensure_ascii=True, indent=2)
        except (ValueError, RuntimeError):
            # RuntimeError comes from a missing rule-set binary or port exhaustion.
            return None

    def import_nodes_from_text(
        self,
        text: str,
        *,
        group: str | None = None,
        auto_connect: bool | None = None,
        select_imported: bool = False,
    ) -> tuple[int, list[str]]:
        return import_nodes_from_text_operation(
            self,
            text,
            group=group,
            auto_connect=auto_connect,
            select_imported=select_imported,
        )

    def import_subscription(self, url: str, name: str | None = None) -> tuple[int, list[str]]:
        return import_subscription_operation(self, url, name)

    def update_subscription(self, url: str) -> tuple[int, list[str]]:
        return update_subscription_operation(self, url)

    def update_all_subscriptions(self) -> tuple[int, list[str]]:
        return update_all_subscriptions_operation(self)

    def apply_fetched_subscription(
        self,
        url: str,
        name: str | None,
        kind: str,
        text: str,
        userinfo: dict | None,
        errors: list[str] | None,
        response_meta: dict | None = None,
    ) -> tuple[int, list[str]]:
        return apply_fetched_subscription_operation(
            self, url, name, kind, text, userinfo, errors, response_meta
        )

    def remove_subscription(self, url: str, delete_nodes: bool = True) -> None:
        remove_subscription_operation(self, url, delete_nodes=delete_nodes)

    def remove_nodes(self, node_ids: set[str]) -> None:
        remove_nodes_operation(self, node_ids)

    def delete_group(self, group: str) -> bool:
        return delete_group_operation(self, group)

    def update_node(self, node_id: str, updates: dict) -> bool:
        return update_node_operation(self, node_id, updates)

    def add_manual_node(self, node: Node) -> str:
        return add_manual_node_operation(self, node)

    def bulk_update_nodes(self, node_ids: set[str], operations: dict) -> int:
        return bulk_update_nodes_operation(self, node_ids, operations)

    def get_all_groups(self) -> list[str]:
        return get_all_groups_operation(self)

    def _migrate_sort_order(self) -> None:
        if self.state.nodes and all(n.sort_order == 0 for n in self.state.nodes):
            for i, node in enumerate(self.state.nodes):
                node.sort_order = i + 1
            self.save()

    def reorder_nodes(self, node_id: str, direction: str) -> None:
        reorder_nodes_operation(self, node_id, direction)

    def set_selected_node(self, node_id: str) -> None:
        set_selected_node_operation(self, node_id)
        node = self._get_node_by_id(node_id)
        if node is not None:
            prime_endpoint_resolution(node.server)

    def _set_connection_status(self, phase: str, message: str, level: str | None = None) -> None:
        self.connection_status_changed.emit(phase, message)
        if level is not None:
            self.status.emit(level, message)

    def _compute_connected_state(self) -> bool:
        if self._active_core == "singbox":
            if self._active_session is not None and self._active_session.hybrid:
                return self.singbox.is_running and self.xray.is_running
            return self.singbox.is_running
        return self.xray.is_running

    def _refresh_connected_state(self) -> tuple[bool, bool]:
        previous = self.connected
        self.connected = self._compute_connected_state()
        return previous, self.connected

    def _reset_auto_switch_state(self, *, reset_cooldown: bool = False, reset_cycle: bool = True) -> None:
        self._auto_switch_low_since = 0.0
        self._auto_switch_high_ticks = 0
        self._auto_switch_active_download = False
        self._health_down_since = 0.0
        if reset_cycle:
            self._auto_switch_cycle_attempts = 0
            self._auto_switch_exhausted = False
        if reset_cooldown:
            self._auto_switch_last_switch = 0.0

    def _cleanup_connection_runtime_state(
        self,
        *,
        end_traffic_session: bool,
        reset_auto_switch_cycle: bool,
        reset_auto_switch_cooldown: bool,
    ) -> None:
        cleanup_connection_runtime_state_operation(
            self,
            end_traffic_session=end_traffic_session,
            reset_auto_switch_cycle=reset_auto_switch_cycle,
            reset_auto_switch_cooldown=reset_auto_switch_cooldown,
        )

    def _stop_active_connection_processes(self, *, disable_proxy: bool, fast: bool = False) -> bool:
        return stop_active_connection_processes_operation(self, disable_proxy=disable_proxy, fast=fast)

    def _handle_unexpected_disconnect(self) -> None:
        handle_unexpected_disconnect_operation(self)

    def connect_selected(self, allow_during_reconnect: bool = False) -> bool:
        return connect_selected_operation(self, allow_during_reconnect=allow_during_reconnect)

    def request_resume_reconnect(self, reason: str = "system resume") -> bool:
        """Queue a reconnect for a session that was active before system sleep."""
        settings = self.state.settings
        if self._shutting_down or getattr(self, "_system_shutdown", False) or self.locked:
            return False
        if not bool(getattr(settings, "reconnect_after_sleep", True)):
            return False
        if not self._desired_connected:
            return False
        self._resume_reconnect_pending = True
        self._request_transition(reason)
        return True

    def disconnect_current(self, disable_proxy: bool = True, emit_status: bool = True, *, fast: bool = False) -> bool:
        return disconnect_current_operation(self, disable_proxy=disable_proxy, emit_status=emit_status, fast=fast)

    def _restart_proxy_core(self, reason: str) -> bool:
        return restart_xray_proxy_core(self, reason)

    def _restart_singbox_runtime(self, reason: str) -> bool:
        return restart_singbox_runtime_operation(self, reason)

    @property
    def traffic_history(self) -> TrafficHistoryStorage:
        return self._traffic_history

    def toggle_connection(self) -> None:
        current_target = self._desired_connected if (self._transition_active or self._transition_pending) else self.connected
        if not current_target and self.state.settings.tun_mode and not is_process_elevated():
            self.status.emit("warning", "VPN (TUN) недоступен без прав администратора. Переключитесь на режим прокси.")
            return
        if current_target:
            self._resume_reconnect_pending = False
        self._desired_connected = not current_target
        self._request_transition("toggle connection")

    def set_discord_proxy_enabled(self, enabled: bool) -> None:
        enabled = bool(enabled)
        if enabled and not is_process_elevated():
            self.status.emit("warning", "Discord Voice через WinDivert недоступен без прав администратора.")
            return
        if enabled and (self.state.settings.tun_mode or (self._active_session is not None and self._active_session.tun_mode)):
            self.status.emit("warning", "Discord Voice недоступен при включенном TUN: трафик Discord уже идет через VPN.")
            return
        if enabled and getattr(self.state.settings, "block_vpn_conflicts", True):
            ignored_pids = {
                int(proc.pid)
                for manager in (self.xray, self.singbox)
                if (proc := getattr(manager, "_proc", None)) is not None and getattr(proc, "pid", 0)
            }
            snapshot = scan_network_conflicts(
                {
                    int(self.state.settings.local_socks_port),
                    int(self.state.settings.local_http_port),
                    DEFAULT_DISCORD_SOCKS_PORT,
                },
                ignored_pids=ignored_pids,
                ignored_executable_paths=self.owned_core_executable_paths(),
            )
            conflicts = list(snapshot.get("apps") or [])
            if conflicts or snapshot.get("unknown_client"):
                name = ", ".join(conflicts[:4]) if conflicts else "другой VPN/прокси-клиент"
                self.status.emit(
                    "error",
                    "Нельзя включить Discord Voice одновременно с другим VPN/прокси-клиентом: "
                    + name
                    + ". Отключите или закройте его.",
                )
                return
        if self.state.settings.discord_proxy_enabled == enabled:
            return
        settings = deepcopy(self.state.settings)
        settings.discord_proxy_enabled = enabled
        self.state.settings = settings
        self.settings_changed.emit(self.state.settings)
        self.schedule_save()
        if self.connected or self._desired_connected:
            self._request_transition("discord proxy changed")
        if not enabled:
            result = self.discord_proxy.disable()
            self._log(f"[discord-proxy] disable: {result.message}")
            self.status.emit("success" if result.ok else "warning", result.message)
        elif not self.connected and not self._desired_connected:
            self.apply_discord_proxy()

    def apply_discord_proxy(self) -> None:
        if not self.state.settings.discord_proxy_enabled:
            return
        if self.state.settings.tun_mode or (self._active_session is not None and self._active_session.tun_mode):
            result = self.discord_proxy.disable()
            self._log(f"[discord-proxy] disabled while TUN is active: {result.message}")
            return
        if not self.connected and not self._desired_connected:
            self.status.emit("warning", "Сначала запустите прокси Lumen, потом включите Discord Voice через прокси")
            return
        result = self.discord_proxy.enable(int(DEFAULT_DISCORD_SOCKS_PORT))
        self._log(f"[discord-proxy] enable: {result.message}")
        self.status.emit("success" if result.ok else "error", result.message)

    def switch_next_node(self) -> None:
        if not self.state.nodes:
            return
        current_id = self.state.selected_node_id
        index = 0
        if current_id:
            for idx, node in enumerate(self.state.nodes):
                if node.id == current_id:
                    index = idx
                    break
        index = (index + 1) % len(self.state.nodes)
        self.set_selected_node(self.state.nodes[index].id)

    def switch_prev_node(self) -> None:
        if not self.state.nodes:
            return
        current_id = self.state.selected_node_id
        index = 0
        if current_id:
            for idx, node in enumerate(self.state.nodes):
                if node.id == current_id:
                    index = idx
                    break
        index = (index - 1) % len(self.state.nodes)
        self.set_selected_node(self.state.nodes[index].id)

    def update_routing(self, routing: RoutingSettings, *, restart_runtime: bool = True) -> None:
        if routing.mode not in ROUTING_MODES:
            routing.mode = "rule"
        self.state.routing = routing
        self.routing_changed.emit(self.state.routing)
        self.schedule_save()

        if restart_runtime and (self.connected or self._desired_connected):
            self._request_transition("routing changed")

    def apply_routing_preset(self, preset_id: str, *, restart_runtime: bool = True) -> None:
        region = normalize_regional_preset(self.state.settings.regional_preset)
        requested_preset = str(preset_id or "").strip().lower()
        preset_id = normalize_routing_preset_for_region(requested_preset, region)
        if requested_preset != preset_id:
            self._log(
                f"[routing] mapped incompatible preset for {region}: "
                f"{requested_preset} -> {preset_id}"
            )
        before = self._routing_signature(self.state.routing)
        routing = build_routing_preset(self.state.routing, preset_id)
        after = self._routing_signature(routing)
        if before == after:
            self._log(f"[routing] preset {preset_id} already active")
            return
        self._log(f"[routing] applying dashboard preset: {preset_id}")
        self.update_routing(routing, restart_runtime=restart_runtime)

    def _commit_regional_preset(self, region: str, *, restart_runtime: bool) -> bool:
        """Atomically apply a region and its equivalent built-in route preset."""
        region = normalize_regional_preset(region)
        old_region = normalize_regional_preset(
            getattr(self.state.settings, "regional_preset", "russia")
        )
        current_preset = str(getattr(self.state.routing, "preset_id", "") or "")
        target_preset = equivalent_regional_preset(current_preset, region)
        routing = build_routing_preset(self.state.routing, target_preset)
        routing_changed = self._routing_signature(self.state.routing) != self._routing_signature(routing)
        if old_region == region and not routing_changed:
            return False

        settings = deepcopy(self.state.settings)
        settings.regional_preset = region
        self.state.settings = settings
        self.state.routing = routing
        self.settings_changed.emit(settings)
        # The regional quick-preset model also listens to routing changes, even
        # when the currently selected preset remains "global".
        if routing_changed or old_region != region:
            self.routing_changed.emit(routing)
        self.schedule_save()
        self._log(f"[routing] regional profile committed: {old_region} -> {region}, preset={target_preset}")

        if restart_runtime and (self.connected or self._desired_connected):
            self._request_transition("regional routing profile changed")
        return True

    def request_regional_preset_change(self, value: str) -> str:
        """Apply a region now or download its resources before committing it.

        Returns ``applied``, ``downloading``, ``unchanged``, ``pending`` or
        ``busy`` for the QML bridge.  The previous region remains active until
        a successful geodata installation has been reported.
        """
        from .core_resource_updater import regional_geodata_installed

        region = normalize_regional_preset(value)
        current_region = normalize_regional_preset(
            getattr(self.state.settings, "regional_preset", "russia")
        )
        if self._pending_regional_preset:
            return "pending" if self._pending_regional_preset == region else "busy"
        if regional_geodata_installed(region):
            if current_region == region:
                return "unchanged"
            self._commit_regional_preset(region, restart_runtime=True)
            return "applied"

        self._pending_regional_preset = region
        if not self.run_resource_update(
            "geodata",
            apply_update=True,
            region=region,
        ):
            self._pending_regional_preset = ""
            return "busy"
        return "downloading"

    def update_settings(self, settings: AppSettings) -> None:
        old_settings = self.state.settings
        old_launch = old_settings.launch_on_startup
        old_launch_in_tray = getattr(old_settings, "launch_in_tray_on_startup", True)
        old_admin = old_settings.always_run_as_admin
        old_tun = old_settings.tun_mode
        old_proxy = old_settings.enable_system_proxy
        old_firefox_proxy = getattr(old_settings, "firefox_proxy_integration", False)
        old_diagnostics_upload = getattr(old_settings, "diagnostics_upload_enabled", True)
        self.state.settings = settings
        if old_diagnostics_upload != getattr(settings, "diagnostics_upload_enabled", True):
            self._configure_diagnostics_upload()
        self.settings_changed.emit(self.state.settings)
        self.schedule_save()

        if settings.tun_mode and not old_tun and settings.discord_proxy_enabled:
            QTimer.singleShot(0, self.apply_discord_proxy)  # strip droute from Discord as soon as TUN takes over

        if old_proxy and not settings.enable_system_proxy:
            self.proxy.disable_necko_overrides()
        elif old_firefox_proxy and not settings.firefox_proxy_integration:
            self.proxy.disable_necko_overrides()

        if (
            old_launch != settings.launch_on_startup
            or (
                settings.launch_on_startup
                and old_launch_in_tray != getattr(settings, "launch_in_tray_on_startup", True)
            )
        ):
            try:
                set_startup_enabled(
                    APP_NAME,
                    settings.launch_on_startup,
                    build_startup_command(
                        in_tray=bool(getattr(settings, "launch_in_tray_on_startup", True))
                    ),
                )
            except Exception as exc:
                self.status.emit("error", f"Ошибка настройки автозапуска: {exc}")

        if old_admin != settings.always_run_as_admin:
            try:
                set_always_run_as_admin(settings.always_run_as_admin)
                if settings.always_run_as_admin:
                    if is_process_elevated():
                        self.status.emit("success", "Запуск от имени администратора включён")
                    else:
                        self.status.emit("warning", "Запуск от имени администратора включён. Перезапускаю Lumen с повышенными правами.")
                        self.admin_relaunch_requested.emit()
                else:
                    self.status.emit("info", "Запуск от имени администратора отключён")
            except Exception as exc:
                self.status.emit("error", f"Ошибка настройки запуска от администратора: {exc}")

        if self.connected or self._desired_connected:
            if old_tun != settings.tun_mode:
                self._desired_connected = True
                self._request_transition("TUN mode toggled")
                return
            self._request_transition("settings changed")

    def reset_settings_to_defaults(self) -> None:
        """Reset application and routing settings while preserving servers and subscriptions."""
        defaults = self.storage.default_state()
        self.update_settings(defaults.settings)
        self.update_routing(defaults.routing)

    def ping_nodes(self, node_ids: set[str] | None = None, method: str | None = None) -> None:
        ping_nodes_operation(self, node_ids, method)

    def speed_test_nodes(self, node_ids: set[str] | None = None) -> bool:
        return speed_test_nodes_operation(self, node_ids)

    def cancel_speed_test(self) -> bool:
        return cancel_speed_test_operation(self)

    def get_fastest_alive_node(self) -> Node | None:
        return get_fastest_alive_node_operation(self)

    def test_connectivity(self, url: str | None = None) -> None:
        test_connectivity_operation(self, url)

    def run_xray_core_update(self, apply_update: bool, silent: bool = False) -> None:
        run_xray_core_update_operation(self, apply_update, silent=silent)

    def run_resource_update(
        self,
        kind: str,
        *,
        apply_update: bool = True,
        region: str | None = None,
    ) -> bool:
        from .core_resource_updater import ResourceUpdateWorker
        from .qthread_utils import retain_thread_until_finished

        if self._shutting_down:
            return False
        kind = str(kind or "").strip().lower()
        if kind not in {"singbox", "geodata", "droute"}:
            self.status.emit("error", f"Неизвестный тип обновления: {kind}")
            return False
        active_same_kind = next(
            (
                worker
                for worker in self._resource_update_workers
                if getattr(worker, "_kind", "") == kind and worker.isRunning()
            ),
            None,
        )
        if active_same_kind is not None:
            self.status.emit("info", f"Проверка или обновление {kind} уже выполняется")
            return False
        proxy_url = None
        if self.connected:
            try:
                proxy_url = self.get_effective_http_proxy_url()
            except Exception:
                proxy_url = None
        update_region = normalize_regional_preset(
            region or getattr(self.state.settings, "regional_preset", "russia")
        )
        worker = ResourceUpdateWorker(
            kind,
            singbox_path=self.state.settings.singbox_path,
            apply_update=apply_update,
            proxy_url=proxy_url,
            region=update_region,
        )
        worker.finished.connect(self._on_resource_update_worker_finished)
        retain_thread_until_finished(self, self._resource_update_workers, worker)
        worker.progress.connect(
            lambda percent, update_kind=kind: self.resource_update_progress.emit(update_kind, int(percent))
        )
        worker.done.connect(self._on_resource_update_done)
        worker.request_disconnect.connect(self._on_update_disconnect_request)
        worker.start()
        return True

    def _on_update_disconnect_request(self) -> None:
        """Callback from background update thread before files are replaced.
        Stops the running connection so files are not locked.
        """
        worker = self.sender()
        if self._shutting_down:
            self._reconnect_after_resource_updates = False
            self._reconnect_after_xray_update = False
            self._confirm_update_disconnect(worker, False)
            return
        if not self.connected:
            self._confirm_update_disconnect(worker, True)
            return
        self._logger.info("[updater] Connection active. Disconnecting before replacing files...")
        self.status.emit("info", "Остановка ядра для установки обновлений...")
        if worker is self._xray_update_worker:
            self._reconnect_after_xray_update = True
        else:
            self._reconnect_after_resource_updates = True
        # The teardown itself must go through the transition state machine so it
        # never races an in-flight connect worker and never blocks the GUI thread.
        self._pending_update_disconnects.append(worker)
        self._desired_connected = False
        self._request_transition("updater disconnect")

    def _resolve_pending_update_disconnects(self) -> None:
        if not self._pending_update_disconnects:
            return
        stopped = not self.connected
        if not stopped and (self._transition_pending or self._transition_scheduled or self._transition_active):
            return
        workers = list(self._pending_update_disconnects)
        self._pending_update_disconnects.clear()
        if stopped:
            self._logger.info("[updater] Disconnected successfully.")
        else:
            self._reconnect_after_resource_updates = False
            self._reconnect_after_xray_update = False
            self._logger.warning("[updater] Failed to disconnect.")
        for worker in workers:
            self._confirm_update_disconnect(worker, stopped)

    def _confirm_update_disconnect(self, worker, success: bool) -> None:
        if hasattr(worker, "confirm_disconnect"):
            worker.confirm_disconnect(success)

    def _on_resource_update_worker_finished(self) -> None:
        if not self._reconnect_after_resource_updates or self._shutting_down:
            return
        worker = self.sender()
        another_install_running = any(
            candidate is not worker
            and candidate.isRunning()
            and bool(getattr(candidate, "_apply_update", False))
            for candidate in self._resource_update_workers
        )
        if another_install_running:
            return
        self._reconnect_after_resource_updates = False
        self._desired_connected = True
        self._request_transition("resource update reconnect")

    def _on_resource_update_done(self, result) -> None:
        status = getattr(result, "status", "")
        message = getattr(result, "message", "") or ""
        kind = getattr(result, "kind", "resources")
        pending_region = self._pending_regional_preset if kind == "geodata" else ""
        if pending_region:
            worker = self.sender()
            worker_region = normalize_regional_preset(
                getattr(worker, "_region", pending_region)
            )
            if worker_region == pending_region:
                if status in {"updated", "up_to_date"}:
                    # An actual install has already stopped the active core and
                    # _on_resource_update_worker_finished will reconnect it.
                    # If nothing had to be installed, request one normal runtime
                    # transition here so the active config still adopts the region.
                    self._commit_regional_preset(
                        pending_region,
                        restart_runtime=not self._reconnect_after_resource_updates,
                    )
                self._pending_regional_preset = ""
        self.resource_update_result.emit(result)
        if status == "error":
            self.status.emit("error", message)
            self._logger.error(f"[updater] Failed to update {kind}: {message}")
        elif status in {"updated", "up_to_date"}:
            self.status.emit("success" if status == "updated" else "info", message)
            self._logger.info(f"[updater] Resource update ({kind}) finished: status={status}, message={message}")
        else:
            self.status.emit("warning", message)
            self._logger.warning(f"[updater] Resource update ({kind}) warning: status={status}, message={message}")

        if kind == "droute" and status == "updated" and not self._shutting_down:
            QTimer.singleShot(0, self.apply_discord_proxy)

    def _start_metrics_worker(self) -> None:
        start_metrics_worker_operation(self)

    def _stop_metrics_worker(self) -> None:
        stop_metrics_worker_operation(self)

    def set_master_password(self, password: str) -> None:
        password_hash, salt = create_password_hash(password)
        self.state.security.enabled = True
        self.state.security.password_hash = password_hash
        self.state.security.salt = salt
        self.save()

    def disable_master_password(self) -> None:
        self.state.security.enabled = False
        self.state.security.password_hash = ""
        self.state.security.salt = ""
        self.locked = False
        self.lock_state_changed.emit(False)
        self.save()

    def unlock(self, password: str) -> bool:
        if not self.state.security.enabled:
            self.locked = False
            self.lock_state_changed.emit(False)
            return True

        ok = verify_password(password, self.state.security.password_hash, self.state.security.salt)
        if ok:
            self.locked = False
            self.lock_state_changed.emit(False)
        return ok

    def lock(self) -> None:
        if not self.state.security.enabled:
            return
        self.locked = True
        self.lock_state_changed.emit(True)
        self._desired_connected = False
        self._resume_reconnect_pending = False
        self._request_transition("app locked")

    def build_diagnostics(self, *, include: dict | None = None, upload: bool = True) -> Path:
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output = LOG_DIR / f"diagnostics_{stamp}.zip"
        bundle = export_diagnostics(output, self.state, self.recent_logs, include=include)
        if upload and DIAGNOSTICS_UPLOAD_URL and self.state.settings.diagnostics_upload_enabled:
            upload_bundle(DIAGNOSTICS_UPLOAD_URL, bundle, app_version=APP_VERSION)
        return bundle

    def auto_connect_if_needed(self) -> None:
        if not self.state.settings.auto_connect_last or self.locked:
            return
        if self.selected_node is None and not self._can_connect_without_selected_node():
            return
        if self.selected_node is not None or self._can_connect_without_selected_node():
            self._desired_connected = True
            self._request_transition("auto connect")

    _CORE_TAGS = frozenset({
        "xray", "singbox", "sing-box", "tun", "zapret", "proxy",
        "core", "xray-error", "singbox-error", "zapret-error", "discord",
        "discord-proxy",
    })
    _TRAFFIC_TAGS = frozenset({
        "speed", "ping", "traffic", "metrics", "auto-switch", "autoswitch",
        "kill-switch", "killswitch", "health",
    })

    def _classify_log(self, line: str) -> tuple[str, int]:
        """Infer (domain, level) from a leading [tag] in the log line."""
        tag = ""
        text = line.lstrip()
        if text.startswith("["):
            end = text.find("]")
            if end != -1:
                tag = text[1:end].strip().lower()
        if tag in self._TRAFFIC_TAGS or tag.startswith(
            ("speed", "ping", "auto", "traffic", "kill", "health")
        ):
            domain = "traffic"
        elif tag in self._CORE_TAGS or tag.startswith(
            ("xray", "singbox", "sing-box", "tun", "zapret", "proxy", "core", "discord")
        ):
            domain = "core"
        else:
            domain = "app"
        if "error" in tag:
            level = logging.ERROR
        elif "warn" in tag:
            level = logging.WARNING
        else:
            parsed_level = classify_log_level(line)
            if parsed_level == "error":
                level = logging.ERROR
            elif parsed_level == "warning":
                level = logging.WARNING
            else:
                level = logging.INFO
        return domain, level

    def _log(self, line: str) -> None:
        """Route a log line to its domain file + the UI, with a severity level."""
        line = clean_log_text(line)
        if not line:
            return
        self.recent_logs.append(line)
        if len(self.recent_logs) > 5000:
            self.recent_logs = self.recent_logs[-5000:]
        domain, level = self._classify_log(line)
        self._domain_loggers.get(domain, self._logger).log(level, line, extra={"from_controller": True})
        self.log_line.emit(line)

    def _on_xray_log(self, line: str) -> None:
        if self._is_noisy_local_proxy_log(line):
            self._routine_log_count = getattr(self, "_routine_log_count", 0) + 1
            if self._routine_log_count % 50 == 0:
                self._core_logger.info("[core] %d routine local proxy logs suppressed", self._routine_log_count)
            return
        if self.state.settings.tun_mode and self._is_noisy_tun_log(line):
            self._tun_log_count = getattr(self, "_tun_log_count", 0) + 1
            if self._tun_log_count % 200 == 0:
                self._core_logger.info("[tun] %d internal/noisy logs hidden", self._tun_log_count)
            return
        self._log(line)

    def _on_core_log(self, source: str, line: str) -> None:
        clean = str(line or "").strip()
        if not clean:
            return
        if clean.lower().startswith(("[tun]", "[xray]", "[singbox]")):
            self._on_xray_log(clean)
        else:
            self._on_xray_log(f"[{source}] {clean}")

    @staticmethod
    def _is_noisy_local_proxy_log(line: str) -> bool:
        text = line.lower()
        if "proxy/http: failed to write response" in text and (
            "wsasend" in text
            or "wsarecv" in text
            or "connection was aborted by the software in your host machine" in text
        ):
            return True
        if (
            "127.0.0.1" in text
            and "an established connection was aborted by the software in your host machine" in text
        ):
            return True
        return False

    @staticmethod
    def _is_noisy_tun_log(line: str) -> bool:
        text = line.lower()
        # Show real sing-box connection logs (like v2rayN with the sing-box
        # core). Only hide the app's own internal polling (metrics/clash API on
        # loopback) and low-level Windows socket spam.
        if "__app_" in text:
            return True
        if "wsarecv" in text or "wsasend" in text:
            return True
        return False

    def _log_network_context(self) -> None:
        try:
            from .diagnostics import collect_network_context
            net = collect_network_context()
            self._logger.info(
                "[network-diagnostic] IPv4 Internet: %s, IPv6 Internet: %s, DNS: %s",
                "OK" if net.get("ipv4_internet") else "FAIL",
                "OK" if net.get("ipv6_internet") else "FAIL",
                ", ".join(net.get("system_dns", [])) or "None",
            )
        except Exception as exc:
            self._logger.debug("[network-diagnostic] Failed to collect net context: %s", exc)

    def _on_xray_error(self, message: str) -> None:
        self._log(f"[xray-error] {message}")
        self._log_network_context()
        self._set_connection_status("error", message, level="error")

    def _on_singbox_error(self, message: str) -> None:
        self._log(f"[singbox-error] {message}")
        self._log_network_context()
        self._set_connection_status("error", message, level="error")

    def _on_core_stopped(self, core: str, exit_code: int) -> None:
        expected = (
            getattr(self, "_disconnecting", False)
            or getattr(self, "_reconnecting", False)
            or getattr(self, "_switching", False)
            or getattr(self, "_system_shutdown", False)
        )
        suffix = " (expected)" if expected else ""
        self._log(f"[{core}] process stopped with code {exit_code}{suffix}")

    def _on_core_state_changed(self, _running: bool) -> None:
        on_core_state_changed_operation(self, _running)

    def _on_ping_result(self, node_id: str, ping_ms: int | None) -> None:
        on_ping_result_operation(self, node_id, ping_ms)

    def _on_ping_progress(self, current: int, total: int) -> None:
        on_ping_progress_operation(self, current, total)

    def _on_ping_complete(self) -> None:
        on_ping_complete_operation(self)

    def _on_speed_result(self, node_id: str, speed_mbps: float | None, is_alive: bool) -> None:
        on_speed_result_operation(self, node_id, speed_mbps, is_alive)

    def _on_speed_progress(self, current: int, total: int) -> None:
        on_speed_progress_operation(self, current, total)

    def _on_speed_node_progress(self, node_id: str, percent: int) -> None:
        on_speed_node_progress_operation(self, node_id, percent)

    def _on_speed_complete(self) -> None:
        on_speed_complete_operation(self)

    def _on_connectivity_result(self, ok: bool, message: str, elapsed_ms: int | None) -> None:
        on_connectivity_result_operation(self, ok, message, elapsed_ms)

    def _on_live_metrics(self, payload: dict[str, object]) -> None:
        on_live_metrics_operation(self, payload)

    _AUTO_SWITCH_HIGH_TICKS_REQUIRED = 10
    _AUTO_SWITCH_IDLE_BPS = 1024.0

    def _check_auto_switch(self, down_bps: float, latency_ms: int | None = None) -> None:
        check_auto_switch_operation(self, down_bps, latency_ms)

    def _get_next_node_for_auto_switch(self) -> Node | None:
        return get_next_node_for_auto_switch_operation(self)

    def _on_xray_update_worker_done(self, result: XrayCoreUpdateResult) -> None:
        on_xray_update_worker_done_operation(self, result)

    def _on_network_changed(self, old: str, new: str) -> None:
        self._log(f"[network] changed: {old} -> {new}")
        invalidate_windows_default_route_context()
        if self.state.settings.tun_mode:
            self._log("[network] ignoring change in TUN mode")
            return
        if self.connected and self.state.settings.reconnect_on_network_change:
            self._desired_connected = True
            self._request_transition("network changed")

    def _hot_swap_node(self, reason: str) -> bool:
        """Handle node switch while TUN is active."""
        session = self._active_session
        if session is None:
            self._auto_switch_transitioning = False
            return False

        self._xray_api_port = session.api_port
        self._protect_ss_port = session.protect_ss_port
        self._protect_ss_password = session.protect_ss_password

        if self._active_core == "singbox":
            try:
                if try_singbox_hot_switch_selector_operation(self, reason):
                    return True
                return self._restart_singbox_runtime(reason)
            finally:
                self._auto_switch_transitioning = False

        return self._reconnect(f"{reason} (sing-box config change)")

    def _reconnect(self, reason: str) -> bool:
        return reconnect_operation(self, reason)

    def export_backup(self, path: Path, passphrase: str = "") -> None:
        self.storage.export_backup(path, passphrase)

    def import_backup(self, path: Path, passphrase: str = "") -> None:
        self.state = self.storage.import_backup(path, passphrase)
        self.save()
        self.nodes_changed.emit(self.state.nodes)
        self.selection_changed.emit(self.selected_node)
        self.routing_changed.emit(self.state.routing)
        self.settings_changed.emit(self.state.settings)

    def _check_auto_lock(self) -> None:
        if not self.state.security.enabled:
            return
        if self.locked:
            return
        minutes = max(1, self.state.security.auto_lock_minutes)
        if get_idle_seconds() >= minutes * 60:
            self.lock()
