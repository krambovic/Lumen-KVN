"""Facade QObject that exposes the existing AppController to QML.

Design goals:
- **Reuse the backend as-is.** ``AppController`` and all engines/workers stay
  PyQt6 and are not modified. The bridge simply owns a controller instance and
  relays its signals to QML-friendly properties/signals.
- **Property bindings instead of imperative label updates.** QML binds to the
  properties below; when a controller signal arrives we update the property and
  Qt Quick repaints only the affected bindings on the render thread.
- **Models for collections.** Nodes/logs/process-stats go through dedicated
  list models (see siblings) for delegate recycling.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import json
import logging
import re
import sys
from pathlib import Path
import socket
from typing import Any

from PyQt6.QtCore import QPoint, QRect, QObject, Qt, QThread, QTimer, QUrl, pyqtProperty, pyqtSignal, pyqtSlot
from PyQt6.QtGui import QDesktopServices, QGuiApplication

from ...app_controller import AppController
from ...application.node_runtime_service import proxy_core_for_node
from ...subscription_worker import SubscriptionFetchWorker, SubscriptionJob
from ...constants import (
    APP_NAME,
    APP_VERSION,
    DEFAULT_DISCORD_SOCKS_PORT,
    DEFAULT_HTTP_PORT,
    DEFAULT_SOCKS_PORT,
    SPEED_TEST_MAX_CONCURRENCY,
    SUBSCRIPTION_PARSER_REVISION,
)
from ...country_flags import detect_country, get_flag_emoji, get_flag_svg_data_uri
from ...deeplinks import DeepLinkError, parse_lumen_deep_link
from ...engines.singbox import get_singbox_version
from ...models import Node, RoutingSettings
from ...node_transport import node_transport
from ...process_conflicts import scan_network_conflicts, terminate_scanned_conflicts
from ...qthread_utils import retain_thread_until_finished, stop_and_wait_for_thread
from ...routing_rule_import import parse_routing_rules
from ...startup import is_process_elevated, relaunch_as_admin
from .log_model import LogFilterModel, LogModel
from .node_list_model import NodeListModel
from .process_model import ProcessModel
from ..toast import set_toasts_enabled, show_toast
from ..window_geometry import fit_window_geometry
from ...i18n import active_map, available_languages, language_name, set_language, tr, translate_dynamic
from ...log_utils import parse_log_line


def _server_display_name_without_country_prefix(name: str, country: str) -> str:
    original = str(name or "").strip()
    cleaned = original
    emoji = get_flag_emoji(country)
    if emoji and cleaned.startswith(emoji):
        cleaned = cleaned[len(emoji):].strip()
    country = str(country or "").strip().upper()
    if len(country) == 2:
        cleaned = re.sub(
            r"^\s*[\[\(\{]?" + re.escape(country) + r"[\]\)\}]?(?:\s*[-_.|#:]\s*|\s+)",
            "",
            cleaned,
            count=1,
            flags=re.IGNORECASE,
        ).strip()
    return cleaned or original


class _ApplicationLogEmitter(QObject):
    line = pyqtSignal(str)


class _ApplicationLogHandler(logging.Handler):
    def __init__(self, emitter: _ApplicationLogEmitter) -> None:
        super().__init__(logging.WARNING)
        self._emitter = emitter

    def emit(self, record: logging.LogRecord) -> None:
        try:
            if getattr(record, "from_controller", False):
                return
            source = record.name.rsplit(".", 1)[-1] or "app"
            self._emitter.line.emit(f"[{source}] {self.format(record)}")
        except Exception:
            pass


def is_mica_supported() -> bool:
    """Check if the system supports the Mica backdrop effect and it is enabled."""
    if sys.platform != "win32":
        return False
    try:
        win_ver = sys.getwindowsversion()
        if win_ver.build < 22000:
            return False

        import ctypes
        from ctypes import wintypes

        # 1. Check DWM Composition
        enabled = ctypes.c_bool(False)
        hr = ctypes.windll.dwmapi.DwmIsCompositionEnabled(ctypes.byref(enabled))
        if hr != 0 or not enabled.value:
            return False

        # 2. Check High Contrast mode
        class HIGHCONTRAST(ctypes.Structure):
            _fields_ = [
                ("cbSize", wintypes.UINT),
                ("dwFlags", wintypes.DWORD),
                ("lpszDefaultScheme", wintypes.LPWSTR),
            ]
        SPI_GETHIGHCONTRAST = 0x0042
        HCF_HIGHCONTRASTON = 0x00000001

        hc = HIGHCONTRAST()
        hc.cbSize = ctypes.sizeof(HIGHCONTRAST)

        user32 = ctypes.windll.user32
        SystemParametersInfo = user32.SystemParametersInfoW
        SystemParametersInfo.argtypes = [wintypes.UINT, wintypes.UINT, ctypes.c_void_p, wintypes.UINT]
        SystemParametersInfo.restype = wintypes.BOOL

        success = SystemParametersInfo(SPI_GETHIGHCONTRAST, hc.cbSize, ctypes.byref(hc), 0)
        if success and (hc.dwFlags & HCF_HIGHCONTRASTON) != 0:
            return False

        # 3. Check Transparency setting in registry
        import winreg
        try:
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"
            )
            val, _ = winreg.QueryValueEx(key, "EnableTransparency")
            winreg.CloseKey(key)
            if val == 0:
                return False
        except Exception:
            pass

        return True
    except Exception:
        return False


class AppBridge(QObject):
    # ── notification signals ─────────────────────────────────────
    toast = pyqtSignal(str, str)              # (level, message)
    actionToast = pyqtSignal(str, str, str, str)  # level, message, action id, button label
    autoSwitch = pyqtSignal(str)              # (node name)
    bulkTaskProgress = pyqtSignal(str, int, int, bool)  # task, cur, total, done
    connectivityResult = pyqtSignal(bool, str, object)  # ok, message, elapsed_ms (None on failure)
    appUpdateState = pyqtSignal("QVariantMap")     # application updater
    xrayUpdateState = pyqtSignal("QVariantMap")    # Xray-core updater
    resourceUpdateState = pyqtSignal("QVariantMap")    # sing-box/geodata updater
    updatesAvailableChanged = pyqtSignal()    # флаг наличия любых обновлений (бейдж)
    networkConflictRequested = pyqtSignal(str, str, bool)  # mode, message, can terminate

    # ── property-change signals ──────────────────────────────────
    connectedChanged = pyqtSignal()
    transitionBusyChanged = pyqtSignal()
    transitionDirectionChanged = pyqtSignal()
    runtimeChanged = pyqtSignal()
    metricsChanged = pyqtSignal()
    selectionChanged = pyqtSignal()
    routingChanged = pyqtSignal()
    settingsChanged = pyqtSignal()
    subscriptionsChanged = pyqtSignal()    # subscription list changed
    nodeFiltersChanged = pyqtSignal()      # distinct group option list changed
    lockedChanged = pyqtSignal()           # app lock/unlock state changed
    trayAvailableChanged = pyqtSignal()    # system tray availability resolved
    trayMessageRequested = pyqtSignal()    # ask the tray to show its balloon
    trayNotify = pyqtSignal(str, str)      # (заголовок, текст) — уведомление события
    nodeQrReady = pyqtSignal(str, str)     # (png data uri, node name)
    nodeImported = pyqtSignal(str)         # first newly imported node id
    subscriptionImported = pyqtSignal(str) # newly created subscription group
    quittingChanged = pyqtSignal()         # real-exit flag flipped on quit
    languageChanged = pyqtSignal()         # active UI language changed
    subscriptionImportingChanged = pyqtSignal()
    subscriptionImportStatusChanged = pyqtSignal()
    regionalPresetBusyChanged = pyqtSignal()

    # Внутренний: запуск фоновой загрузки подписок (jobs, batch_id)
    _sub_fetch_run = pyqtSignal(object, int)

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._node_model = NodeListModel(self)
        self._log_source_model = LogModel(parent=self)
        self._log_model = LogFilterModel(self._log_source_model, parent=self)
        self._process_model = ProcessModel(self)
        self._missing_wallpaper_clear_pending = ""

        # Reuse the existing backend untouched.
        self.controller = AppController(self)
        self.controller.resource_update_result.connect(self._on_resource_update_result)
        self.controller.resource_update_progress.connect(self._on_resource_update_progress)
        self._application_log_emitter = _ApplicationLogEmitter(self)
        self._application_log_emitter.line.connect(self._capture_application_log, type=Qt.ConnectionType.QueuedConnection)
        self._application_log_handler = _ApplicationLogHandler(self._application_log_emitter)
        self._application_log_handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
        logging.getLogger("xray_fluent").addHandler(self._application_log_handler)

        # Фоновая загрузка подписок (ленивая инициализация потока).
        self._sub_thread: QThread | None = None
        self._sub_worker: SubscriptionFetchWorker | None = None
        self._retired_sub_threads: list[QThread] = []
        self._retired_sub_workers: dict[QThread, SubscriptionFetchWorker] = {}
        self._app_update_checker: QThread | None = None
        self._app_update_downloader: QThread | None = None
        self._startup_resource_worker: QThread | None = None
        self._pending_regional_preset = ""
        self._sub_batches: dict[int, dict] = {}
        self._sub_batch_seq = 0

        # cached state for QML properties
        self._connected = False
        self._busy = False
        self._transition_target_connected = False
        self._transition_connecting = False
        self._runtime_phase = ""
        self._runtime_message = ""
        self._down_bps = 0.0
        self._up_bps = 0.0
        self._latency_ms = -1
        self._selected_id = ""
        self._selected_name = ""
        self._selected_flag = ""
        self._selected_flag_source = ""
        self._selected_latency = -1
        self._manual_selection_in_progress = False
        self._routing_mode = "rule"
        self._tun_mode = False
        self._proxy_enabled = False
        self._discord_proxy = False
        self._theme = "dark"
        self._language = "en"
        set_language(self._language)
        self._accent = "#0078D4"

        # Filled from persisted settings in load(), after state.enc has been
        # decoded. Search text remains intentionally session-local.
        self._filter_group = ""
        self._filter_text = ""
        self._sort_key = "manual"
        self._sort_asc = True

        self._tray_available = False
        self._quitting = False
        self._system_shutdown = False
        self._updates_available = False
        self._deferred_started = False
        self._toasts_ready = False
        self._pending_toasts: list[tuple[str, tuple]] = []
        self._pending_network_mode = ""
        self._pending_conflict_processes: list[dict] = []
        self._sub_importing = False
        self._sub_import_status = ""

        # Таймер авто-обновления подписок (интервал берётся из настроек).
        self._sub_timer = QTimer(self)
        self._sub_timer.setSingleShot(False)
        self._sub_timer.timeout.connect(self._on_sub_auto_update)

        self._app_update_timer = QTimer(self)
        self._app_update_timer.setInterval(6 * 60 * 60 * 1000)
        self._app_update_timer.timeout.connect(
            lambda: self._start_app_update_check(silent=True)
        )
        self._wire_controller()

    @pyqtSlot(str)
    def _capture_application_log(self, line: str) -> None:
        self.controller.recent_logs.append(line)
        if len(self.controller.recent_logs) > 5000:
            self.controller.recent_logs = self.controller.recent_logs[-5000:]
        self._log_source_model.append_line(self._localized_log_line(line))

    # ── notifications ──────────────────────────────────────
    def _notify(self, level: str, message: str) -> None:
        """Emit a toast, buffering it while QML has not connected to us yet."""
        if self._toasts_ready:
            self.toast.emit(level, message)
        elif len(self._pending_toasts) < 20:
            self._pending_toasts.append(("toast", (level, message)))

    def _notify_action(self, level: str, message: str, action_id: str, action_label: str) -> None:
        if self._toasts_ready:
            self.actionToast.emit(level, message, action_id, action_label)
        elif len(self._pending_toasts) < 20:
            self._pending_toasts.append(("actionToast", (level, message, action_id, action_label)))

    def _flush_pending_toasts(self) -> None:
        self._toasts_ready = True
        pending, self._pending_toasts = self._pending_toasts, []
        for name, args in pending:
            getattr(self, name).emit(*args)

    # ── lifecycle ──────────────────────────────────────────
    def load(self) -> None:
        """Load persisted state and push initial snapshots into QML."""
        try:
            self.controller.load()
        except Exception as exc:  # pragma: no cover - defensive
            self._notify("error", tr("Ошибка загрузки: {error}", error=exc))
        saved_settings = self.controller.state.settings
        self._filter_group = str(saved_settings.node_filter_group or "")
        self._sort_key = str(saved_settings.node_sort_key or "manual")
        self._sort_asc = bool(saved_settings.node_sort_ascending)
        self._push_initial_snapshot()
        self._reconfigure_sub_timer()
        self._reconfigure_app_update_timer()
        try:
            settings = self.controller.state.settings
            if (
                getattr(settings, "check_updates", True)
                or getattr(settings, "app_auto_update", False)
            ):
                QTimer.singleShot(
                    2500, lambda: self._start_app_update_check(silent=True)
                )
        except Exception:
            pass
        try:
            if getattr(self.controller.state.settings, "resource_update_check", False):
                QTimer.singleShot(4000, self._start_resource_update_check)
        except Exception:
            pass
        try:
            settings = self.controller.state.settings
            if getattr(settings, "xray_auto_update", False):
                QTimer.singleShot(
                    4500,
                    lambda: self.controller.run_xray_core_update(True, silent=True),
                )
            elif getattr(settings, "resource_update_check", False):
                QTimer.singleShot(
                    4500,
                    lambda: self.controller.run_xray_core_update(False, silent=True),
                )
        except Exception:
            pass
        try:
            if self.controller.state.subscriptions:
                try:
                    minutes = int(self.controller.state.settings.subscription_auto_update_minutes)
                except Exception:
                    minutes = 240
                if minutes > 0:
                    QTimer.singleShot(3000, self._on_sub_auto_update)
        except Exception:
            pass
    @pyqtSlot()
    def startDeferred(self) -> None:
        self._flush_pending_toasts()
        if self._deferred_started:
            return
        self._deferred_started = True
        self.controller.start_deferred_services()
        QTimer.singleShot(150, self.controller.auto_connect_if_needed)

    def shutdown(self) -> None:
        logger = logging.getLogger("xray_fluent.app")
        logger.info("[app] AppBridge shutting down...")
        self.prepareQuit()
        try:
            self._sub_timer.stop()
            self._app_update_timer.stop()
        except Exception:
            pass
        thread = self._sub_thread
        if thread is not None:
            logger.info("[app] Stopping subscription thread...")
            stopped = False
            try:
                worker = self._sub_worker
                if worker is not None:
                    worker.stop()
                thread.quit()
                stopped = stop_and_wait_for_thread(
                    thread,
                    label="subscription thread",
                    logger=logger,
                )
            except Exception as exc:
                logger.error(f"[app] Error stopping subscription thread: {exc}")
            if stopped:
                self._sub_thread = None
                self._sub_worker = None
                thread.deleteLater()

        for retired_thread in list(self._retired_sub_threads):
            retired_worker = self._retired_sub_workers.get(retired_thread)
            if retired_worker is not None:
                retired_worker.stop()
            retired_thread.quit()
            stop_and_wait_for_thread(
                retired_thread,
                label="cancelled subscription thread",
                logger=logger,
            )

        for attribute, label in (
            ("_app_update_checker", "application update checker"),
            ("_startup_resource_worker", "startup resource checker"),
            ("_app_update_downloader", "application update downloader"),
        ):
            worker = getattr(self, attribute, None)
            if worker is None:
                continue
            stop = worker.cancel if hasattr(worker, "cancel") else None
            stopped = stop_and_wait_for_thread(worker, stop=stop, label=label, logger=logger)
            if stopped:
                if getattr(self, attribute, None) is worker:
                    setattr(self, attribute, None)
                worker.deleteLater()
        try:
            self.controller.shutdown()
        except Exception:
            pass
        try:
            logging.getLogger("xray_fluent").removeHandler(self._application_log_handler)
        except Exception:
            pass

    # ── Авто-обновление подписок ────────────────────────
    def _reconfigure_sub_timer(self) -> None:
        """Перезапускает таймер авто-обновления по текущим настройкам."""
        try:
            minutes = int(self.controller.state.settings.subscription_auto_update_minutes)
        except Exception:
            minutes = 240
        if minutes > 0:
            self._sub_timer.setInterval(minutes * 60 * 1000)
            self._sub_timer.start()
        else:
            self._sub_timer.stop()

    def _on_sub_auto_update(self) -> None:
        """Тихое фоновое обновление подписок. Не трогает VPN/прокси."""
        try:
            if getattr(self.controller, "locked", False):
                return
            subs = self.controller.state.subscriptions
            if not subs:
                return
            now = datetime.now(timezone.utc)
            jobs = []
            for subscription in subs:
                url = str(subscription.get("url") or "").strip()
                if not url:
                    continue
                try:
                    backoff = datetime.fromisoformat(
                        str(subscription.get("backoff_until") or "")
                    )
                    if backoff.tzinfo is None:
                        backoff = backoff.replace(tzinfo=timezone.utc)
                    if backoff > now:
                        continue
                except (TypeError, ValueError):
                    pass
                jobs.append(SubscriptionJob(url=url, kind="update"))
            self._dispatch_sub_jobs(jobs, "auto")
        except Exception:
            pass

    def _reconfigure_app_update_timer(self) -> None:
        settings = self.controller.state.settings
        if bool(getattr(settings, "app_auto_update", False)):
            self._app_update_timer.start()
        else:
            self._app_update_timer.stop()

    # ── Фоновая загрузка подписок (сеть вне UI-потока) ──
    def _retire_sub_worker(self, thread: QThread, worker: SubscriptionFetchWorker | None) -> None:
        """Keep a cancelled worker alive until its QThread has actually stopped."""
        if worker is not None:
            self._retired_sub_workers[thread] = worker

        def _release_worker() -> None:
            self._retired_sub_workers.pop(thread, None)

        retain_thread_until_finished(
            self,
            self._retired_sub_threads,
            thread,
            on_finished=_release_worker,
        )

    def _ensure_sub_worker(self) -> None:
        """Лениво поднимает поток+воркер для загрузки подписок (GUI-поток)."""
        if self._quitting or self._sub_thread is not None:
            return
        logger = logging.getLogger("xray_fluent.app")
        logger.info("[app] Starting subscription fetch thread...")
        thread = QThread()
        thread.setObjectName("lumen-subscriptions")
        worker = SubscriptionFetchWorker()
        worker.moveToThread(thread)
        self._sub_fetch_run.connect(worker.run_batch)
        worker.fetched.connect(self._on_sub_fetched)
        worker.completed.connect(self._on_sub_batch_completed)
        thread.finished.connect(worker.deleteLater)
        thread.start()
        self._sub_thread = thread
        self._sub_worker = worker

    def _dispatch_sub_jobs(self, jobs: list, kind: str) -> None:
        """Передаёт задачи в фоновый поток; тосты покажем по завершению батча."""
        if self._quitting:
            return
        if not jobs:
            if kind in ("update", "update_all"):
                self.toast.emit("info", self._localized_backend_message("Подписок нет"))
            return
        settings = self.controller.state.settings
        user_agent = str(getattr(settings, "subscription_user_agent", "") or "").strip()
        hwid = str(getattr(settings, "subscription_hwid", "") or "").strip()
        use_real_hwid = bool(getattr(settings, "subscription_use_real_hwid", True))
        use_proxy_tun = bool(getattr(settings, "subscription_use_proxy_tun", False))
        proxy_url = ""
        if use_proxy_tun and self.controller.connected:
            try:
                proxy_port = self.controller.get_effective_http_proxy_port()
                if proxy_port:
                    proxy_url = self.controller.get_effective_http_proxy_url() or ""
            except Exception:
                proxy_url = ""
        converter_url = ""
        if bool(getattr(settings, "subscription_converter_enabled", False)):
            converter_url = str(getattr(settings, "subscription_converter_url", "") or "").strip()
        for job in jobs:
            job.user_agent = user_agent
            job.hwid = hwid
            job.use_real_hwid = use_real_hwid
            job.use_proxy_tun = use_proxy_tun
            job.proxy_url = proxy_url
            job.converter_url = converter_url
            job.etag = ""
            job.last_modified = ""
            existing = next(
                (
                    item
                    for item in getattr(self.controller.state, "subscriptions", [])
                    if str(item.get("url") or "").strip() == str(job.url or "").strip()
                ),
                None,
            )
            if isinstance(existing, dict):
                try:
                    cache_allowed = (
                        int(existing.get("parser_revision") or 0)
                        == SUBSCRIPTION_PARSER_REVISION
                    )
                except (TypeError, ValueError):
                    cache_allowed = False
                if cache_allowed:
                    job.etag = str(existing.get("etag") or "")
                    job.last_modified = str(existing.get("last_modified") or "")
        self._sub_batch_seq += 1
        batch_id = self._sub_batch_seq
        self._sub_batches[batch_id] = {"kind": kind, "added": 0, "errors": []}
        self._ensure_sub_worker()
        self._sub_fetch_run.emit(list(jobs), batch_id)

    def _on_sub_fetched(
        self,
        batch_id: int,
        job: object,
        text: str,
        userinfo: object,
        errors: object,
        metadata: object = None,
    ) -> None:
        """Применяет результат одной подписки. Всегда GUI-поток (queued)."""
        batch = self._sub_batches.get(batch_id)
        if batch is None:
            return
        before_subscription_ids = {
            str(item.get("id") or "")
            for item in getattr(self.controller.state, "subscriptions", [])
        }
        try:
            added, errs = self.controller.apply_fetched_subscription(
                job.url,
                job.name,
                job.kind,
                text,
                userinfo,
                list(errors or []),
                dict(metadata or {}),
            )
        except Exception as exc:  # noqa: BLE001
            added, errs = 0, [str(exc)]
        batch["added"] += int(added or 0)
        if errs:
            batch["errors"].extend(errs)
        if getattr(job, "kind", "") == "import":
            created = next(
                (
                    item
                    for item in getattr(self.controller.state, "subscriptions", [])
                    if str(item.get("id") or "") not in before_subscription_ids
                ),
                None,
            )
            if created is not None:
                group = str(created.get("group") or created.get("name") or "Default").strip() or "Default"
                self.subscriptionImported.emit(group)

    def _on_sub_batch_completed(self, batch_id: int, total: int) -> None:
        """Показывает итоговый тост после завершения всех задач батча."""
        batch = self._sub_batches.pop(batch_id, None)
        if batch is None:
            return
        kind = batch["kind"]
        added = batch["added"]
        errors = batch["errors"]
        if kind == "import":
            self._sub_importing = False
            self._sub_import_status = ""
            self.subscriptionImportingChanged.emit()
            self.subscriptionImportStatusChanged.emit()
        if kind == "auto":
            if added:
                self.toast.emit("info", tr("Авто-обновление подписок: +{count} серверов", count=added))
            return
        if kind == "import":
            if added:
                self.toast.emit("success", tr("Импортировано серверов: {count}", count=added))
            if errors:
                self.toast.emit("warning", "; ".join(errors[:2]))
            if not added and not errors:
                self.toast.emit("info", "Новых серверов не найдено")
        elif kind == "update":
            self.toast.emit("success", tr("Подписка обновлена: {count} серверов", count=added))
            if errors:
                self.toast.emit("warning", "; ".join(errors[:2]))
        else:  # update_all
            self.toast.emit("success", tr("Подписки обновлены: {count} серверов", count=added))
            if errors:
                self.toast.emit("warning", "; ".join(errors[:2]))

    # ── Tray / background ───────────────────────────────────────
    def set_tray_available(self, value: bool) -> None:
        value = bool(value)
        if value != self._tray_available:
            self._tray_available = value
            self.trayAvailableChanged.emit()

    @pyqtProperty(bool, notify=trayAvailableChanged)
    def trayAvailable(self) -> bool:
        return self._tray_available

    @pyqtProperty(bool, constant=True)
    def uiBackdropAvailable(self) -> bool:
        return is_mica_supported()

    def _set_updates_available(self, value: bool) -> None:
        value = bool(value)
        if value != self._updates_available:
            self._updates_available = value
            self.updatesAvailableChanged.emit()

    @pyqtProperty(bool, notify=updatesAvailableChanged)
    def updatesAvailable(self) -> bool:
        return self._updates_available

    @pyqtSlot()
    def markUpdatesSeen(self) -> None:
        """Сбросить бейдж обновлений (пользователь открыл вкладку)."""
        self._set_updates_available(False)

    @pyqtProperty(bool, notify=quittingChanged)
    def quitting(self) -> bool:
        return self._quitting

    @pyqtSlot()
    def prepareQuit(self) -> None:
        if not self._quitting:
            self._quitting = True
            set_toasts_enabled(False)
            self.quittingChanged.emit()

    def prepareSystemShutdown(self) -> None:
        """Enter the non-interactive, no-new-process Windows shutdown path."""
        self._system_shutdown = True
        self.controller._system_shutdown = True
        self.prepareQuit()
        try:
            self._sub_timer.stop()
            self._app_update_timer.stop()
        except Exception:
            pass

    @pyqtSlot()
    def notifyHiddenToTray(self) -> None:
        if self._quitting:
            return
        self.trayMessageRequested.emit()

    def _on_admin_relaunch(self) -> None:
        """Relaunch elevated when the controller asks for admin rights"""
        import logging
        logger = logging.getLogger("xray_fluent.app")
        logger.info("[app] Relaunch as admin requested")
        
        if is_process_elevated():
            logger.info("[app] Process is already elevated, ignoring relaunch request")
            return
        try:
            self.controller.save()
        except Exception:
            pass
        server = getattr(self, "_single_instance_server", None)
        if server is not None:
            try:
                server.close()
            except Exception:
                pass
        if not relaunch_as_admin():
            msg = "Не удалось перезапустить Lumen от имени администратора"
            logger.error("[app] relaunch_as_admin returned False")
            self.toast.emit("error", msg)
            try:
                from ..toast import show_toast
                show_toast(APP_NAME, msg)
            except Exception as exc:
                logger.error("[app] Failed to show system toast", exc_info=exc)
            if server is not None:
                try:
                    from PyQt6.QtNetwork import QLocalServer
                    QLocalServer.removeServer("Lumen.SingleInstance")
                    server.listen("Lumen.SingleInstance")
                except Exception:
                    pass
            return
        logger.info("[app] relaunch_as_admin triggered successfully, quitting current instance")
        app = QGuiApplication.instance()
        if app is not None:
            app.quit()

    def _push_initial_snapshot(self) -> None:
        state = self.controller.state
        self._node_model.set_nodes(state.nodes, state.selected_node_id)
        self._on_selection_changed(self.controller.selected_node)
        self._on_routing_changed(state.routing)
        self._on_settings_changed(state.settings)
        self._transition_target_connected = bool(getattr(self.controller, "_desired_connected", self.controller.connected))
        self._transition_connecting = self._transition_target_connected
        self._on_connection_changed(self.controller.connected)

    # ── controller signal wiring ────────────────────────────────
    def _wire_controller(self) -> None:
        c = self.controller
        c.nodes_changed.connect(self._on_nodes_changed)
        c.selection_changed.connect(self._on_selection_changed)
        c.connection_changed.connect(self._on_connection_changed)
        c.connection_status_changed.connect(self._on_runtime_status)
        c.routing_changed.connect(self._on_routing_changed)
        c.settings_changed.connect(self._on_settings_changed)
        c.subscriptions_changed.connect(self._on_subscriptions_changed)
        c.transition_state_changed.connect(self._on_transition)
        c.status.connect(self._on_status_message)
        c.log_line.connect(self._on_controller_log_line, type=Qt.ConnectionType.QueuedConnection)
        c.ping_updated.connect(self._on_ping)
        c.speed_updated.connect(self._on_speed)
        c.speed_progress_updated.connect(self._node_model.update_speed_progress)
        c.bulk_task_progress.connect(self._on_bulk_task_progress)
        c.live_metrics_updated.connect(self._on_live_metrics)
        c.auto_switch_triggered.connect(self._on_auto_switch)
        c.connectivity_test_done.connect(self.connectivityResult.emit)
        c.lock_state_changed.connect(self._on_lock_state)
        c.passphrase_required.connect(self._on_passphrase_required)
        c.admin_relaunch_requested.connect(self._on_admin_relaunch)

    def _english_ui(self) -> bool:
        return (self._language or "en").lower() != "ru"

    def _localized_backend_message(self, message: str) -> str:
        if not message or not self._english_ui():
            return message
        catalog = active_map()
        localized = translate_dynamic(message, catalog)
        if localized is not None:
            return localized
        catalog_prefix = max(
            (source for source in catalog if source and message.startswith(source)),
            key=len,
            default="",
        )
        if catalog_prefix:
            tail = message[len(catalog_prefix):]
            localized_tail = translate_dynamic(tail, catalog)
            return catalog[catalog_prefix] + (localized_tail if localized_tail is not None else tail)
        replacements = (
            ("Запуск VPN...", "Starting VPN..."),
            ("Подключение VPN...", "Connecting VPN..."),
            ("VPN подключён", "VPN connected"),
            ("VPN отключён", "VPN disconnected"),
            ("Остановка прокси...", "Stopping proxy..."),
            ("Прокси подключён", "Proxy connected"),
            ("Прокси отключён", "Proxy disconnected"),
            ("Остановка VPN...", "Stopping VPN..."),
            ("Проверка обновлений sing-box...", "Checking sing-box updates..."),
            ("Обновление sing-box...", "Updating sing-box..."),
            ("Проверка обновлений geoip/geosite...", "Checking geoip/geosite updates..."),
            ("Обновление geoip/geosite...", "Updating geoip/geosite..."),
            ("geoip/geosite уже обновляются", "geoip/geosite update is already running"),
            ("Проверка обновлений приложения...", "Checking app updates..."),
            ("Приложение обновлено", "Application is up to date"),
            ("Обновление уже выполняется", "Update is already running"),
            ("Обновление Xray уже выполняется", "Xray update is already running"),
            ("Обновление Xray...", "Updating Xray..."),
            ("Проверка обновлений Xray...", "Checking Xray updates..."),
            ("geoip.dat и geosite.dat обновлены", "geoip.dat and geosite.dat updated"),
            ("Новых серверов не найдено", "No new servers found"),
            ("Подписка удалена", "Subscription removed"),
        )
        for ru, en in replacements:
            if message == ru:
                return catalog.get(ru, en)
        prefix_replacements = (
            ("Не удалось проверить droute: ", "Could not check droute: "),
            ("Не удалось обновить droute: ", "Could not update droute: "),
            ("Доступен droute ", "droute available: "),
            ("droute обновлен до ", "droute updated to "),
            ("droute актуален (", "droute is up to date ("),
            ("Запуск прокси: ", "Starting proxy: "),
            ("Подключено: ", "Connected: "),
            ("Запуск VPN: ", "Starting VPN: "),
            ("Подключение VPN: ", "Connecting VPN: "),
            ("Не удалось подключиться: ", "Could not connect: "),
            ("Не удалось отключиться: ", "Could not disconnect: "),
            ("Подписка обновлена: ", "Subscription updated: "),
            ("Подписки обновлены: ", "Subscriptions updated: "),
            ("Импортировано серверов: ", "Servers imported: "),
            ("Авто-обновление подписок: +", "Subscription auto update: +"),
            ("Доступно обновление v", "Update available: v"),
            ("Не удалось обновить geoip/geosite: ", "Could not update geoip/geosite: "),
            ("Не удалось проверить sing-box: ", "Could not check sing-box: "),
            ("Не удалось обновить sing-box: ", "Could not update sing-box: "),
            ("Ошибка загрузки: ", "Download error: "),
            ("Ошибка установки: ", "Install error: "),
            ("Доступно обновление Xray: ", "Xray update available: "),
            ("Xray core обновлён до ", "Xray core updated to "),
            ("sing-box обновлен до ", "sing-box updated to "),
            ("sing-box обновлён до ", "sing-box updated to "),
            ("Доступен sing-box extended ", "sing-box extended available: "),
        )
        for ru, en in prefix_replacements:
            if message.startswith(ru):
                return catalog.get(ru, en) + message[len(ru):]
        if message.startswith("Xray core актуален (") and message.endswith(")"):
            return (
                catalog.get("Xray core актуален", "Xray core is up to date")
                + " "
                + message[len("Xray core актуален "):]
            )
        if message.startswith("sing-box актуален (") and message.endswith(")"):
            return (
                catalog.get("sing-box актуален", "sing-box is up to date")
                + " "
                + message[len("sing-box актуален "):]
            )
        return message

    def _localized_log_line(self, line: str) -> str:
        """Translate app/backend log text while preserving its severity prefix."""
        match = re.match(r"^(?P<prefix>(?:DEBUG|INFO|WARNING|ERROR|CRITICAL):\s*)(?P<body>.*)$", line, re.DOTALL)
        if match is None:
            return self._localized_backend_message(line)
        return match.group("prefix") + self._localized_backend_message(match.group("body"))

    @pyqtSlot(str)
    def _on_controller_log_line(self, line: str) -> None:
        self._log_source_model.append_line(self._localized_log_line(line))

    def _on_status_message(self, level: str, message: str) -> None:
        localized = self._localized_backend_message(message)
        if level in {"error", "warning"}:
            recent = self.controller.recent_logs[-3:]
            if not any(localized in item for item in recent):
                self.controller._log(f"[app-{level}] {localized}")
            entry = parse_log_line(localized)
            if entry.action_id:
                self._notify_action(level, entry.message + "\n" + entry.details.split(". ", 1)[0] + ".", entry.action_id, tr(entry.action_label))
                return
            if entry.message != entry.details:
                self._notify(level, entry.message + "\n" + entry.details.split(". ", 1)[0] + ".")
                return
        self._notify(level, localized)

    # ── controller -> QML slots ─────────────────────────────────
    def _on_nodes_changed(self, nodes: list[Node]) -> None:
        self._apply_node_model()
        self.nodeFiltersChanged.emit()

    def _apply_node_model(self) -> None:
        """Re-push the controller's nodes into the model honouring the active
        sort key/direction chosen in the Серверы toolbar"""
        state = self.controller.state
        self._node_model.set_runtime_support(True)
        self._node_model.set_nodes(
            self._sorted_nodes(self._filtered_nodes(state.nodes)),
            state.selected_node_id,
        )

    def _filtered_nodes(self, nodes: list[Node]) -> list[Node]:
        """Apply the active group/text filter (mirrors the old QML rowVisible)."""
        group = self._filter_group
        text = (self._filter_text or "").strip().lower()
        if not group and not text:
            return list(nodes)
        result: list[Node] = []
        for n in nodes:
            if group and (n.group or "Default") != group:
                continue
            if text and not (
                text in (n.name or "").lower()
                or text in (n.server or "").lower()
                or text in (n.group or "").lower()
                or text in node_transport(n).lower()
            ):
                continue
            result.append(n)
        return result

    def _sorted_nodes(self, nodes: list[Node]) -> list[Node]:
        items = list(nodes)
        key = getattr(self, "_sort_key", "manual")
        if key == "name":
            items.sort(key=lambda n: (n.name or n.server or "").lower())
        elif key == "group":
            items.sort(key=lambda n: (n.group or "").lower())
        elif key == "scheme":
            items.sort(key=lambda n: (n.scheme or "").lower())
        elif key == "transport":
            items.sort(key=lambda n: node_transport(n).lower())
        elif key == "ping":
            items.sort(key=lambda n: (n.ping_ms is None, n.ping_ms if n.ping_ms is not None else 1e12))
        elif key == "speed":
            # Higher speed first under ascending, unknown speeds last.
            items.sort(key=lambda n: (n.speed_mbps is None, -(n.speed_mbps or 0.0)))
        elif key == "last":
            items.sort(key=lambda n: (not n.last_used_at, n.last_used_at or ""))
        else:  # "manual"
            items.sort(key=lambda n: (n.sort_order if n.sort_order is not None else 0))
        if not getattr(self, "_sort_asc", True):
            items.reverse()
        return items

    def _on_selection_changed(self, node: Node | None) -> None:
        prev_id = self._selected_id
        new_id = node.id if node else ""
        new_name = (node.name or node.server) if node else ""
        country = (node.country_code or "").upper() or detect_country(node.name or "", node.server or "") if node else ""
        display_name = _server_display_name_without_country_prefix(new_name, country)
        selection_changed = bool(new_id and new_id != prev_id)
        # A QML selection signal is delivered synchronously, before the
        # controller starts reconnecting. Show the in-app notification here so
        # the user's click receives immediate feedback without waiting for the
        # new runtime to become ready. Startup/restore selections are excluded.
        if selection_changed and self._manual_selection_in_progress:
            self.toast.emit("info", f'{tr("Сервер изменён")}: {display_name}')
        if self._connected and prev_id and selection_changed:
            self.trayNotify.emit(tr("Сервер изменён"), new_name)
        self._selected_id = new_id
        self._selected_name = display_name
        self._selected_flag = get_flag_emoji(country)
        self._selected_flag_source = get_flag_svg_data_uri(country)
        self._selected_latency = (
            -1 if (node is None or node.ping_ms is None) else int(node.ping_ms)
        )
        self._node_model.set_selected(self._selected_id or None)
        self.selectionChanged.emit()

    def _on_connection_changed(self, connected: bool) -> None:
        if connected == self._connected:
            return
        self._connected = bool(connected)
        if not self._busy:
            self._transition_target_connected = bool(connected)
        if not connected:
            self._down_bps = self._up_bps = 0.0
            self._latency_ms = -1
            self.metricsChanged.emit()
        self.connectedChanged.emit()

    def _transition_message_connecting(self, message: str) -> bool:
        msg = message or ""
        if "Отключ" in msg or "Disconnect" in msg:
            return False
        if "Подключ" in msg or "Запуск" in msg or "Переподключ" in msg or "Переключ" in msg:
            return True
        if "Connect" in msg or "Starting" in msg or "Reconnect" in msg or "Switch" in msg:
            return True
        return bool(getattr(self.controller, "_desired_connected", self._connected))

    def _on_transition(self, busy: bool, _message: str) -> None:
        target = bool(getattr(self.controller, "_desired_connected", self._connected))
        connecting = self._transition_message_connecting(_message) if busy else bool(self._connected)
        changed = (
            (bool(busy) != self._busy)
            or (target != self._transition_target_connected)
            or (connecting != self._transition_connecting)
        )
        if not changed:
            return
        self._busy = bool(busy)
        self._transition_target_connected = target if self._busy else self._connected
        self._transition_connecting = connecting if self._busy else self._connected
        self.transitionDirectionChanged.emit()
        self.transitionBusyChanged.emit()

    def _on_runtime_status(self, phase: str, message: str) -> None:
        self._runtime_phase = phase or ""
        self._runtime_message = message or ""
        self.runtimeChanged.emit()

    def _on_auto_switch(self, node_name: str) -> None:
        # Уведомление об успешном авто-переключении на резервный сервер.
        name = node_name or ""
        self.autoSwitch.emit(name)
        self.trayNotify.emit(tr("Автопереключение"), name)

    def _on_routing_changed(self, routing: RoutingSettings) -> None:
        self._routing_mode = routing.mode
        self.routingChanged.emit()

    def _on_settings_changed(self, settings) -> None:
        self._tun_mode = bool(settings.tun_mode)
        self._proxy_enabled = bool(settings.enable_system_proxy)
        self._discord_proxy = bool(getattr(settings, "discord_proxy_enabled", False))
        self._theme = settings.theme
        new_language = getattr(settings, "language", "en")
        _language_changed = new_language != self._language
        self._language = new_language
        set_language(self._language)
        if _language_changed:
            self.languageChanged.emit()
            # Built-in routing preset labels are translated in the bridge and
            # exposed through properties notified by routingChanged. Refresh
            # those models immediately when the UI language changes.
            self.routingChanged.emit()
        self._accent = settings.accent_color or "#0078D4"
        self._node_model.set_runtime_support(True)
        self.settingsChanged.emit()

    def _on_subscriptions_changed(self, _subscriptions=None) -> None:
        self.subscriptionsChanged.emit()

    def _on_ping(self, node_id: str, ping_ms) -> None:
        self._node_model.update_ping(node_id, ping_ms)
        if node_id == self._selected_id:
            self._selected_latency = -1 if ping_ms is None else int(ping_ms)
            self.selectionChanged.emit()

    def _on_bulk_task_progress(self, task: str, current: int, total: int, done: bool) -> None:
        if task == "ping":
            if done:
                self._node_model.clear_pinging()
            elif current == 0:
                self._node_model.set_pinging_ids(getattr(self.controller, "_ping_node_map", {}).keys())
        self.bulkTaskProgress.emit(task, current, total, done)

    def _on_speed(self, node_id: str, speed_mbps, is_alive: bool) -> None:
        self._node_model.update_speed(node_id, speed_mbps)
        self._node_model.update_alive(node_id, is_alive)

    def _on_live_metrics(self, payload: dict) -> None:
        self._down_bps = float(payload.get("down_bps") or 0.0)
        self._up_bps = float(payload.get("up_bps") or 0.0)
        latency = payload.get("latency_ms")
        self._latency_ms = int(latency) if isinstance(latency, int) else -1
        self.metricsChanged.emit()
        stats = payload.get("process_stats")
        if stats is not None:
            self._process_model.set_stats(stats)

    def _on_lock_state(self, locked: bool) -> None:
        if locked:
            self.toast.emit("warning", "Приложение заблокировано")
        self.lockedChanged.emit()

    def _on_passphrase_required(self) -> None:
        """State file is passphrase-encrypted: say so instead of starting empty."""
        message = tr("Данные зашифрованы: укажите пароль шифрования в разделе «Данные», иначе серверы не будут загружены")
        self.controller._log(f"[app-error] {message}")
        self._notify("error", message)

    # ── QML-invokable commands ──────────────────────────────────
    @pyqtSlot()
    def toggleConnection(self) -> None:
        if (
            not self._connected
            and bool(self.controller.state.settings.tun_mode)
            and not is_process_elevated()
        ):
            self._notify_action(
                "warning",
                tr("VPN (TUN) требует права администратора"),
                "restart-admin",
                tr("Перезапустить от администратора"),
            )
            return
        self.controller.toggle_connection()
        target = bool(getattr(self.controller, "_desired_connected", self._connected))
        if target != self._transition_target_connected:
            self._transition_target_connected = target
            self.transitionBusyChanged.emit()

    @pyqtSlot(str)
    def selectNode(self, node_id: str) -> None:
        if node_id:
            self._manual_selection_in_progress = True
            try:
                self.controller.set_selected_node(node_id)
            finally:
                self._manual_selection_in_progress = False

    @pyqtSlot()
    def switchNext(self) -> None:
        self._manual_selection_in_progress = True
        try:
            self.controller.switch_next_node()
        finally:
            self._manual_selection_in_progress = False

    @pyqtSlot()
    def switchPrev(self) -> None:
        self._manual_selection_in_progress = True
        try:
            self.controller.switch_prev_node()
        finally:
            self._manual_selection_in_progress = False

    @pyqtSlot(str)
    def setRoutingMode(self, mode: str) -> None:
        routing = deepcopy(self.controller.state.routing)
        routing.mode = mode
        routing.preset_id = "custom"
        self.controller.update_routing(routing)

    @pyqtSlot(str)
    def applyRoutingPreset(self, preset_id: str) -> None:
        self.controller.apply_routing_preset(preset_id)

    @pyqtSlot(str)
    def applyRoutingPresetOption(self, preset_id: str) -> None:
        from ...routing_presets import BUILT_IN_ROUTING_PRESET_IDS

        preset_id = (preset_id or "").strip()
        if preset_id in BUILT_IN_ROUTING_PRESET_IDS:
            self.applyRoutingPreset(preset_id)
        else:
            self.applyCustomRoutingPreset(preset_id)

    @pyqtSlot(str)
    def saveRoutingPreset(self, name: str) -> None:
        from uuid import uuid4
        title = (name or "").strip() or tr("Пресет")
        preset = {
            "id": uuid4().hex,
            "name": title,
            "routing": self.controller.state.routing.to_dict(),
        }
        self.controller.state.routing_presets.append(preset)
        self.controller.save()
        self.routingChanged.emit()
        self.toast.emit("success", tr("Пресет сохранён: {name}", name=title))

    @pyqtSlot(str)
    def applyCustomRoutingPreset(self, preset_id: str) -> None:
        preset = next(
            (p for p in self.controller.state.routing_presets if p.get("id") == preset_id),
            None,
        )
        if preset is None:
            self.toast.emit("warning", tr("Пресет не найден"))
            return
        routing = RoutingSettings.from_dict(dict(preset.get("routing") or {}))
        routing.preset_id = str(preset_id)
        self.controller.update_routing(routing)
        self.toast.emit("success", tr("Применён пресет: {name}", name=preset.get("name", "")))

    @pyqtSlot(str)
    def deleteRoutingPreset(self, preset_id: str) -> None:
        before = len(self.controller.state.routing_presets)
        self.controller.state.routing_presets = [
            p for p in self.controller.state.routing_presets if p.get("id") != preset_id
        ]
        if len(self.controller.state.routing_presets) != before:
            self.controller.save()
            self.routingChanged.emit()

    def _own_engine_pids(self) -> set[int]:
        return self.controller.owned_core_process_pids()

    def _network_conflicts(self) -> dict:
        settings = self.controller.state.settings
        return scan_network_conflicts(
            {
                int(getattr(settings, "local_socks_port", DEFAULT_SOCKS_PORT) or DEFAULT_SOCKS_PORT),
                int(getattr(settings, "local_http_port", DEFAULT_HTTP_PORT) or DEFAULT_HTTP_PORT),
                DEFAULT_DISCORD_SOCKS_PORT,
            },
            ignored_pids=self._own_engine_pids(),
            ignored_executable_paths=(
                self.controller.owned_core_executable_paths()
                if hasattr(self.controller, "owned_core_executable_paths")
                else set()
            ),
        )

    def _request_network_mode(self, mode: str) -> bool:
        # The guard is opt-out.  A missing field in an old state file keeps
        # the historic safe behavior until the user explicitly disables it.
        if not bool(getattr(self.controller.state.settings, "block_vpn_conflicts", True)):
            return True
        snapshot = self._network_conflicts()
        apps = [str(name) for name in snapshot.get("apps") or []]
        unknown = bool(snapshot.get("unknown_client"))
        if not apps and not unknown:
            return True
        names = ", ".join(apps[:6]) if apps else tr("другой VPN/прокси-клиент")
        self._pending_network_mode = mode
        self._pending_conflict_processes = list(snapshot.get("processes") or [])
        self.networkConflictRequested.emit(
            mode,
            tr(
                "Работе Lumen могут помешать запущенные процессы: {names}. Закройте окно или завершите конфликтующие процессы и продолжите.",
                names=names,
            ),
            bool(self._pending_conflict_processes),
        )
        return False

    def _apply_network_mode(self, mode: str) -> None:
        settings = deepcopy(self.controller.state.settings)
        if mode == "tun":
            settings.tun_mode = True
            settings.enable_system_proxy = False
        elif mode == "proxy":
            settings.enable_system_proxy = True
            settings.tun_mode = False
        else:
            return
        self.controller.update_settings(settings)

    @pyqtSlot()
    def cancelNetworkConflict(self) -> None:
        self._pending_network_mode = ""
        self._pending_conflict_processes = []
        self.settingsChanged.emit()

    @pyqtSlot(result=bool)
    def closeNetworkConflictsAndContinue(self) -> bool:
        mode = self._pending_network_mode
        scanned = list(self._pending_conflict_processes)
        if not mode:
            self.cancelNetworkConflict()
            return False
        if not bool(getattr(self.controller.state.settings, "block_vpn_conflicts", True)):
            self._pending_network_mode = ""
            self._pending_conflict_processes = []
            self._apply_network_mode(mode)
            return True
        if not scanned:
            self.cancelNetworkConflict()
            return False
        _closed, failed = terminate_scanned_conflicts(scanned)
        snapshot = self._network_conflicts()
        remaining = list(snapshot.get("apps") or [])
        if failed or remaining or snapshot.get("unknown_client"):
            names = ", ".join(dict.fromkeys([*failed, *remaining])) or tr("другой VPN/прокси-клиент")
            self._pending_conflict_processes = list(snapshot.get("processes") or [])
            self.toast.emit("error", tr("Не удалось закрыть конфликтующие процессы: {names}", names=names))
            return False
        self._pending_network_mode = ""
        self._pending_conflict_processes = []
        self._apply_network_mode(mode)
        return True

    @pyqtSlot(bool, result=bool)
    def setTun(self, enabled: bool) -> bool:
        if enabled and not is_process_elevated():
            self._notify_action(
                "warning",
                tr("VPN (TUN) требует права администратора"),
                "restart-admin",
                tr("Перезапустить от администратора"),
            )
            self.settingsChanged.emit()
            return False
        if enabled and not self._request_network_mode("tun"):
            self.settingsChanged.emit()
            return False
        settings = deepcopy(self.controller.state.settings)
        settings.tun_mode = enabled
        if enabled:
            settings.enable_system_proxy = False
        self.controller.update_settings(settings)
        return True

    @pyqtSlot(bool, result=bool)
    def setProxy(self, enabled: bool) -> bool:
        if enabled and not self._request_network_mode("proxy"):
            self.settingsChanged.emit()
            return False
        settings = deepcopy(self.controller.state.settings)
        settings.enable_system_proxy = enabled
        if enabled and settings.tun_mode:
            settings.tun_mode = False
        self.controller.update_settings(settings)
        return True

    @pyqtSlot(bool)
    def setDiscordProxy(self, enabled: bool) -> None:
        self.controller.set_discord_proxy_enabled(enabled)

    @pyqtSlot(str)
    def setTheme(self, name: str) -> None:
        settings = deepcopy(self.controller.state.settings)
        settings.theme = name
        self.controller.update_settings(settings)

    @pyqtSlot(str)
    def setLanguage(self, language: str) -> None:
        value = (language or "en").strip().lower()
        if value not in available_languages():
            value = "en"
        settings = deepcopy(self.controller.state.settings)
        settings.language = value
        self.controller.update_settings(settings)

    @pyqtSlot(str)
    def setAccent(self, hex_color: str) -> None:
        if not hex_color:
            return
        settings = deepcopy(self.controller.state.settings)
        settings.accent_color = hex_color
        self.controller.update_settings(settings)

    @staticmethod
    def _accent_for_theme_preset(value: str) -> str:
        return {
            "default": "#0078D4",
            "absolutely": "#CC7D5E",
            "ayu": "#D97706",
            "catppuccin": "#CBA6F7",
            "codex": "#2563EB",
            "dracula": "#BD93F9",
            "everforest": "#4F8A10",
            "github": "#0969DA",
            "gruvbox": "#B57614",
            "linear": "#5E6AD2",
            "lobster": "#E11D48",
            "material": "#1976D2",
            "matrix": "#16A34A",
            "midnight": "#2563EB",
            "monokai": "#679E00",
            "night-owl": "#0E7CBF",
            "nord": "#5E81AC",
            "notion": "#2383E2",
            "one": "#4078F2",
            "oscurange": "#EA580C",
            "raycast": "#FF3B30",
            "rose-pine": "#907AA9",
            "sentry": "#6E56CF",
            "solarized": "#268BD2",
            "temple": "#7A9F00",
            "tokyo-night": "#34548A",
            "vercel": "#111111",
            "vscode-plus": "#007ACC",
            "xcode": "#0066CC",
        }.get((value or "default").strip().lower(), "#0078D4")

    @pyqtSlot(result=str)
    def systemAccent(self) -> str:
        """Читает текущий акцентный цвет Windows из реестра.
        DWM\\AccentColor хранится как DWORD в формате ABGR (0xAABBGGRR).
        Возвращает '#RRGGBB' или '' если недоступно."""
        if sys.platform != "win32":
            return ""
        try:
            import winreg

            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\DWM"
            ) as key:
                raw, _ = winreg.QueryValueEx(key, "AccentColor")
            val = int(raw) & 0xFFFFFFFF
            r = val & 0xFF
            g = (val >> 8) & 0xFF
            b = (val >> 16) & 0xFF
            return "#{:02X}{:02X}{:02X}".format(r, g, b)
        except Exception:
            return ""

    @pyqtSlot()
    def useSystemAccent(self) -> None:
        """Применяет системный акцент Windows как акцент приложения."""
        hex_color = self.systemAccent()
        if not hex_color:
            self.toast.emit("warning", tr("Не удалось получить системный акцент"))
            return
        self.setAccent(hex_color)

    @pyqtSlot(str)
    def setInterfaceMode(self, mode: str) -> None:
        settings = deepcopy(self.controller.state.settings)
        settings.interface_mode = mode
        self.controller.update_settings(settings)

    # ── Внешний вид 2.0 (Appearance Studio) ─────────────────────
    @pyqtSlot(str)
    def setUiDensity(self, value: str) -> None:
        v = (value or "comfortable").strip().lower()
        if v not in ("comfortable", "compact", "spacious"):
            v = "comfortable"
        settings = deepcopy(self.controller.state.settings)
        settings.ui_density = v
        self.controller.update_settings(settings)

    @pyqtSlot(int)
    def setUiCornerRadius(self, value: int) -> None:
        settings = deepcopy(self.controller.state.settings)
        settings.ui_corner_radius = max(0, min(20, int(value)))
        self.controller.update_settings(settings)

    @pyqtSlot(str)
    def setUiFontFamily(self, value: str) -> None:
        settings = deepcopy(self.controller.state.settings)
        settings.ui_font_family = (value or "").strip()
        self.controller.update_settings(settings)

    @pyqtSlot(int)
    def setUiFontScale(self, value: int) -> None:
        settings = deepcopy(self.controller.state.settings)
        settings.ui_font_scale = max(80, min(140, int(value)))
        self.controller.update_settings(settings)

    @pyqtSlot(str)
    def setUiBackdrop(self, value: str) -> None:
        v = (value or "mica").strip().lower()
        if v == "acrylic":
            v = "mica"
        if v not in ("mica", "solid"):
            v = "mica"
        settings = deepcopy(self.controller.state.settings)
        settings.ui_backdrop = v
        self.controller.update_settings(settings)

    @pyqtSlot(int)
    def setUiTransparencyStrength(self, value: int) -> None:
        settings = deepcopy(self.controller.state.settings)
        settings.ui_transparency_strength = max(0, min(100, int(value)))
        self.controller.update_settings(settings)

    @pyqtSlot(str)
    def setUiThemePreset(self, value: str) -> None:
        preset = (value or "default").strip().lower()
        settings = deepcopy(self.controller.state.settings)
        settings.ui_theme_preset = preset
        settings.accent_color = self._accent_for_theme_preset(preset)
        self.controller.update_settings(settings)

    @pyqtProperty(str, notify=settingsChanged)
    def uiBaseTint(self) -> str:
        try:
            return str(self.controller.state.settings.ui_base_tint or "")
        except Exception:
            return ""

    @pyqtSlot(str)
    def setUiBaseTint(self, value: str) -> None:
        settings = deepcopy(self.controller.state.settings)
        settings.ui_base_tint = (value or "").strip()
        self.controller.update_settings(settings)

    @pyqtProperty(str, notify=settingsChanged)
    def uiBaseTintSrc(self) -> str:
        """Состояние пикера базового тона: "#RRGGBB|mute" (база + приглушение)."""
        try:
            return str(self.controller.state.settings.ui_base_tint_src or "")
        except Exception:
            return ""

    @pyqtSlot(str)
    def setUiBaseTintSrc(self, value: str) -> None:
        settings = deepcopy(self.controller.state.settings)
        settings.ui_base_tint_src = (value or "").strip()
        self.controller.update_settings(settings)

    # ── Обои (B7) ───────────────────────────────────────
    @pyqtProperty(str, notify=settingsChanged)
    def uiWallpaper(self) -> str:
        try:
            value = str(self.controller.state.settings.ui_wallpaper or "").strip()
            if value and not Path(value).is_file():
                self._schedule_missing_wallpaper_clear(value)
                return ""
            return value
        except Exception:
            return ""

    def _schedule_missing_wallpaper_clear(self, value: str) -> None:
        if self._missing_wallpaper_clear_pending == value:
            return
        self._missing_wallpaper_clear_pending = value
        QTimer.singleShot(0, lambda path=value: self._clear_missing_wallpaper(path))

    def _clear_missing_wallpaper(self, value: str) -> None:
        try:
            current = str(self.controller.state.settings.ui_wallpaper or "").strip()
            if current != value or Path(value).is_file():
                return
            settings = deepcopy(self.controller.state.settings)
            settings.ui_wallpaper = ""
            self.controller.update_settings(settings)
            logging.getLogger("xray_fluent.app").warning("[ui] Cleared missing wallpaper: %s", value)
        finally:
            if self._missing_wallpaper_clear_pending == value:
                self._missing_wallpaper_clear_pending = ""

    @pyqtSlot(str)
    def setUiWallpaper(self, value: str) -> None:
        v = (value or "").strip()
        if v.startswith("file://"):
            v = QUrl(v).toLocalFile()
        settings = deepcopy(self.controller.state.settings)
        new_image = bool(v)
        settings.ui_wallpaper = v
        if new_image:
            settings.ui_wallpaper_opacity = 50
            settings.ui_wallpaper_blur = 10
            settings.ui_wallpaper_brightness = 50
        self.controller.update_settings(settings)


    @pyqtProperty(int, notify=settingsChanged)
    def uiWallpaperOpacity(self) -> int:
        try:
            return int(self.controller.state.settings.ui_wallpaper_opacity)
        except Exception:
            return 100

    @pyqtSlot(int)
    def setUiWallpaperOpacity(self, value: int) -> None:
        settings = deepcopy(self.controller.state.settings)
        settings.ui_wallpaper_opacity = max(0, min(100, int(value)))
        self.controller.update_settings(settings)

    @pyqtProperty(int, notify=settingsChanged)
    def uiWallpaperBlur(self) -> int:
        try:
            return int(self.controller.state.settings.ui_wallpaper_blur)
        except Exception:
            return 0

    @pyqtSlot(int)
    def setUiWallpaperBlur(self, value: int) -> None:
        settings = deepcopy(self.controller.state.settings)
        settings.ui_wallpaper_blur = max(0, min(100, int(value)))
        self.controller.update_settings(settings)

    @pyqtProperty(int, notify=settingsChanged)
    def uiWallpaperBrightness(self) -> int:
        try:
            return int(self.controller.state.settings.ui_wallpaper_brightness)
        except Exception:
            return 50

    @pyqtSlot(int)
    def setUiWallpaperBrightness(self, value: int) -> None:
        settings = deepcopy(self.controller.state.settings)
        settings.ui_wallpaper_brightness = max(0, min(100, int(value)))
        self.controller.update_settings(settings)


    @pyqtSlot(bool)
    def setUiAnimations(self, enabled: bool) -> None:
        settings = deepcopy(self.controller.state.settings)
        settings.ui_animations = bool(enabled)
        self.controller.update_settings(settings)

    @pyqtProperty(str, notify=settingsChanged)
    def uiDensity(self) -> str:
        try:
            return str(self.controller.state.settings.ui_density or "comfortable")
        except Exception:
            return "comfortable"

    @pyqtProperty(int, notify=settingsChanged)
    def uiCornerRadius(self) -> int:
        try:
            return int(self.controller.state.settings.ui_corner_radius)
        except Exception:
            return 8

    @pyqtProperty(str, notify=settingsChanged)
    def uiFontFamily(self) -> str:
        try:
            return str(self.controller.state.settings.ui_font_family or "")
        except Exception:
            return ""

    @pyqtProperty(int, notify=settingsChanged)
    def uiFontScale(self) -> int:
        try:
            return int(self.controller.state.settings.ui_font_scale)
        except Exception:
            return 100

    @pyqtProperty(str, notify=settingsChanged)
    def uiBackdrop(self) -> str:
        try:
            return str(self.controller.state.settings.ui_backdrop or "mica")
        except Exception:
            return "mica"

    @pyqtProperty(int, notify=settingsChanged)
    def uiTransparencyStrength(self) -> int:
        try:
            return int(getattr(self.controller.state.settings, "ui_transparency_strength", 50))
        except Exception:
            return 50

    @pyqtProperty(str, notify=settingsChanged)
    def uiThemePreset(self) -> str:
        try:
            return str(self.controller.state.settings.ui_theme_preset or "default")
        except Exception:
            return "default"

    @pyqtProperty(bool, notify=settingsChanged)
    def uiAnimations(self) -> bool:
        try:
            return bool(self.controller.state.settings.ui_animations)
        except Exception:
            return True

    @pyqtSlot(bool)
    def setAppAutoUpdate(self, enabled: bool) -> None:
        settings = deepcopy(self.controller.state.settings)
        settings.app_auto_update = bool(enabled)
        if settings.app_auto_update:
            settings.check_updates = True
        self.controller.update_settings(settings)
        self._reconfigure_app_update_timer()
        if settings.app_auto_update:
            QTimer.singleShot(0, lambda: self._start_app_update_check(silent=True))

    @pyqtSlot(bool)
    def setAllowUpdates(self, enabled: bool) -> None:
        pass

    @pyqtSlot(bool)
    def setCheckUpdates(self, enabled: bool) -> None:
        settings = deepcopy(self.controller.state.settings)
        settings.check_updates = bool(enabled)
        if not settings.check_updates:
            settings.app_auto_update = False
        self.controller.update_settings(settings)
        self._reconfigure_app_update_timer()

    @pyqtSlot(bool)
    def setAlwaysRunAsAdmin(self, enabled: bool) -> None:
        settings = deepcopy(self.controller.state.settings)
        settings.always_run_as_admin = bool(enabled)
        self.controller.update_settings(settings)

    @pyqtProperty(bool, notify=settingsChanged)
    def alwaysRunAsAdmin(self) -> bool:
        try:
            return bool(self.controller.state.settings.always_run_as_admin)
        except Exception:
            return False

    @pyqtProperty(bool, constant=True)
    def isAdmin(self) -> bool:
        try:
            return bool(is_process_elevated())
        except Exception:
            return False

    @pyqtProperty(int, notify=settingsChanged)
    def windowWidth(self) -> int:
        try:
            return int(self.controller.state.settings.window_width or 1280)
        except Exception:
            return 1280

    @pyqtProperty(int, notify=settingsChanged)
    def windowHeight(self) -> int:
        try:
            return int(self.controller.state.settings.window_height or 720)
        except Exception:
            return 720

    @pyqtProperty(int, notify=settingsChanged)
    def windowX(self) -> int:
        try:
            return int(self.controller.state.settings.window_x)
        except Exception:
            return -1

    @pyqtProperty(int, notify=settingsChanged)
    def windowY(self) -> int:
        try:
            return int(self.controller.state.settings.window_y)
        except Exception:
            return -1

    @pyqtSlot(int, int, int, int)
    def saveWindowGeometry(self, width: int, height: int, x: int, y: int) -> None:
        settings = deepcopy(self.controller.state.settings)
        settings.window_width = int(width)
        settings.window_height = int(height)
        settings.window_x = int(x)
        settings.window_y = int(y)
        self.controller.update_settings(settings)

    @pyqtSlot(int, int, int, int, int, int, result="QVariantMap")
    def fitWindowGeometry(
        self,
        width: int,
        height: int,
        x: int,
        y: int,
        minimum_width: int,
        minimum_height: int,
    ) -> dict[str, int]:
        # -1/-1 is the persisted sentinel for "no saved position". Negative
        # coordinates are otherwise valid for monitors left/above the primary.
        position_saved = int(x) != -1 and int(y) != -1
        screens = list(QGuiApplication.screens())
        target_screen = None

        if position_saved and screens:
            restored = QRect(int(x), int(y), max(1, int(width)), max(1, int(height)))

            def _intersection_area(screen) -> int:
                intersection = restored.intersected(screen.geometry())
                return max(0, intersection.width()) * max(0, intersection.height())

            target_screen = max(screens, key=_intersection_area)
            if _intersection_area(target_screen) == 0:
                target_screen = QGuiApplication.screenAt(QPoint(int(x), int(y)))

        if target_screen is None:
            target_screen = QGuiApplication.primaryScreen()
        if target_screen is None:
            return {
                "x": max(0, int(x)),
                "y": max(0, int(y)),
                "width": max(int(minimum_width), int(width)),
                "height": max(int(minimum_height), int(height)),
            }

        available = target_screen.availableGeometry()
        return fit_window_geometry(
            width,
            height,
            x,
            y,
            minimum_width,
            minimum_height,
            available.x(),
            available.y(),
            available.width(),
            available.height(),
            position_saved=position_saved,
        )

    # ── «Обновления» settings persistence ───────────────────────
    @pyqtSlot(str)
    def setReleaseChannel(self, channel: str) -> None:
        normalized = "prerelease" if str(channel).strip().lower() in ("prerelease", "pre-release", "pre", "beta", "nightly") else "stable"
        settings = deepcopy(self.controller.state.settings)
        if settings.release_channel == normalized:
            return
        settings.release_channel = normalized
        self.controller.update_settings(settings)
        # Перепроверяем обновления под новый канал, чтобы виджет сразу обновил состояние.
        self._start_app_update_check(silent=False)



    @pyqtSlot(bool)
    def setXrayAutoUpdate(self, enabled: bool) -> None:
        settings = deepcopy(self.controller.state.settings)
        settings.xray_auto_update = bool(enabled)
        self.controller.update_settings(settings)

    @pyqtSlot(str)
    def setXrayReleaseChannel(self, channel: str) -> None:
        normalized = str(channel or "").strip().lower()
        if normalized not in {"stable", "beta"}:
            normalized = "beta"
        settings = deepcopy(self.controller.state.settings)
        if settings.xray_release_channel == normalized:
            return
        settings.xray_release_channel = normalized
        self.controller.update_settings(settings)
        self.checkXrayUpdate()

    @pyqtProperty(str, notify=settingsChanged)
    def xrayReleaseChannel(self) -> str:
        try:
            value = str(self.controller.state.settings.xray_release_channel or "beta").strip().lower()
        except Exception:
            return "beta"
        return value if value in {"stable", "beta"} else "beta"

    @pyqtProperty(str, notify=settingsChanged)
    def releaseChannel(self) -> str:
        try:
            value = str(self.controller.state.settings.release_channel or "stable").strip().lower()
        except Exception:
            return "stable"
        return "prerelease" if value in ("prerelease", "pre-release", "pre", "beta", "nightly") else "stable"

    @pyqtProperty(bool, notify=settingsChanged)
    def checkUpdates(self) -> bool:
        try:
            return bool(self.controller.state.settings.check_updates)
        except Exception:
            return True

    @pyqtProperty(bool, notify=settingsChanged)
    def allowUpdates(self) -> bool:
        try:
            return bool(self.controller.state.settings.allow_updates)
        except Exception:
            return True

    @pyqtProperty(bool, notify=settingsChanged)
    def appAutoUpdate(self) -> bool:
        try:
            return bool(self.controller.state.settings.app_auto_update)
        except Exception:
            return False

    @pyqtProperty(bool, notify=settingsChanged)
    def xrayAutoUpdate(self) -> bool:
        try:
            return bool(self.controller.state.settings.xray_auto_update)
        except Exception:
            return False

    # ════════════════════════════════════════════════════════════
    # Settings
    # ════════════════════════════════════════════════════════════

    # ── Network ──────────────────────────────────────────────────
    @pyqtSlot(bool)
    def setProxyBypassLan(self, enabled: bool) -> None:
        settings = deepcopy(self.controller.state.settings)
        settings.system_proxy_bypass_lan = bool(enabled)
        self.controller.update_settings(settings)

    @pyqtSlot(bool)
    def setFirefoxProxyIntegration(self, enabled: bool) -> None:
        settings = deepcopy(self.controller.state.settings)
        settings.firefox_proxy_integration = bool(enabled)
        self.controller.update_settings(settings)

    @pyqtSlot(bool)
    def setReconnectOnNetworkChange(self, enabled: bool) -> None:
        settings = deepcopy(self.controller.state.settings)
        settings.reconnect_on_network_change = bool(enabled)
        self.controller.update_settings(settings)

    @pyqtSlot(bool)
    def setReconnectAfterSleep(self, enabled: bool) -> None:
        settings = deepcopy(self.controller.state.settings)
        settings.reconnect_after_sleep = bool(enabled)
        self.controller.update_settings(settings)

    @pyqtSlot(str)
    def setRegionalPreset(self, value: str) -> None:
        from ...routing_presets import normalize_regional_preset
        region = normalize_regional_preset(value)
        outcome = self.controller.request_regional_preset_change(region)
        if outcome == "downloading":
            self._pending_regional_preset = region
            self.regionalPresetBusyChanged.emit()
            self.resourceUpdateState.emit(
                {"kind": "geodata", "phase": "updating", "percent": 0}
            )
            self.toast.emit("info", tr("Обновление geoip/geosite..."))
        elif outcome == "applied":
            self.toast.emit("success", tr("Применено"))
        elif outcome in {"pending", "busy"}:
            self.settingsChanged.emit()
            self.regionalPresetBusyChanged.emit()
            self.toast.emit("info", tr("Обновление уже выполняется"))

    @pyqtSlot(bool)
    def setPreferIpv6(self, enabled: bool) -> None:
        settings = deepcopy(self.controller.state.settings)
        settings.prefer_ipv6 = bool(enabled)
        self.controller.update_settings(settings)

    @pyqtSlot(bool)
    def setKillSwitch(self, enabled: bool) -> None:
        settings = deepcopy(self.controller.state.settings)
        settings.kill_switch = bool(enabled)
        self.controller.update_settings(settings)

    @pyqtSlot(bool)
    def setResourceUpdateCheck(self, enabled: bool) -> None:
        settings = deepcopy(self.controller.state.settings)
        settings.resource_update_check = bool(enabled)
        self.controller.update_settings(settings)

    @pyqtSlot(bool)
    def setDiagnosticsUpload(self, enabled: bool) -> None:
        settings = deepcopy(self.controller.state.settings)
        settings.diagnostics_upload_enabled = bool(enabled)
        self.controller.update_settings(settings)

    @pyqtSlot(bool)
    def setProxyAllowLan(self, enabled: bool) -> None:
        settings = deepcopy(self.controller.state.settings)
        settings.proxy_allow_lan = bool(enabled)
        self.controller.update_settings(settings)

    @pyqtSlot(bool)
    def setTunStrictRoute(self, enabled: bool) -> None:
        settings = deepcopy(self.controller.state.settings)
        settings.tun_strict_route = bool(enabled)
        self.controller.update_settings(settings)

    @pyqtSlot(str)
    def setTunStack(self, stack: str) -> None:
        settings = deepcopy(self.controller.state.settings)
        settings.tun_stack = str(stack or "").strip().lower()
        self.controller.update_settings(settings)

    @pyqtSlot(int)
    def setTunMtu(self, mtu: int) -> None:
        settings = deepcopy(self.controller.state.settings)
        settings.tun_mtu = int(mtu)
        self.controller.update_settings(settings)

    @pyqtSlot(int)
    def setLocalSocksPort(self, port: int) -> None:
        settings = deepcopy(self.controller.state.settings)
        settings.local_socks_port = int(port)
        settings.__post_init__()  # re-run normalization: range, droute port 10818, socks/http collision
        self.controller.update_settings(settings)

    @pyqtSlot(int)
    def setLocalHttpPort(self, port: int) -> None:
        settings = deepcopy(self.controller.state.settings)
        settings.local_http_port = int(port)
        settings.__post_init__()  # re-run normalization: range, droute port 10818, socks/http collision
        self.controller.update_settings(settings)

    @pyqtSlot(str, str)
    def setProxyAuthCredentials(self, username: str, password: str) -> None:
        settings = deepcopy(self.controller.state.settings)
        settings.proxy_auth_username = str(username or "").strip()[:256]
        settings.proxy_auth_password = str(password or "")[:256]
        if settings.proxy_auth_enabled and not (
            settings.proxy_auth_username and settings.proxy_auth_password
        ):
            settings.proxy_auth_enabled = False
            self.toast.emit("warning", tr("Авторизация прокси отключена: укажите логин и пароль"))
        self.controller.update_settings(settings)

    @pyqtSlot(bool, result=bool)
    def setProxyAuthEnabled(self, enabled: bool) -> bool:
        settings = deepcopy(self.controller.state.settings)
        if enabled and not (
            str(settings.proxy_auth_username or "").strip()
            and str(settings.proxy_auth_password or "")
        ):
            self.toast.emit("warning", tr("Сначала укажите логин и пароль прокси"))
            return False
        settings.proxy_auth_enabled = bool(enabled)
        self.controller.update_settings(settings)
        return True

    @pyqtSlot(bool)
    def setTunEndpointIndependentNat(self, enabled: bool) -> None:
        settings = deepcopy(self.controller.state.settings)
        settings.tun_endpoint_independent_nat = bool(enabled)
        self.controller.update_settings(settings)

    @pyqtSlot(bool)
    def setTunBlockQuic(self, enabled: bool) -> None:
        settings = deepcopy(self.controller.state.settings)
        settings.tun_block_quic = bool(enabled)
        self.controller.update_settings(settings)

    @pyqtSlot(bool)
    def setSniffRouteOnly(self, enabled: bool) -> None:
        settings = deepcopy(self.controller.state.settings)
        settings.sniff_route_only = bool(enabled)
        self.controller.update_settings(settings)

    @pyqtSlot(bool)
    def setXrayFragment(self, enabled: bool) -> None:
        settings = deepcopy(self.controller.state.settings)
        settings.enable_xray_fragment = bool(enabled)
        self.controller.update_settings(settings)

    @pyqtSlot(bool)
    def setFinalFragment(self, enabled: bool) -> None:
        settings = deepcopy(self.controller.state.settings)
        settings.enable_final_fragment = bool(enabled)
        self.controller.update_settings(settings)

    @pyqtSlot(bool)
    def setFragmentation(self, enabled: bool) -> None:
        settings = deepcopy(self.controller.state.settings)
        value = bool(enabled)
        settings.enable_xray_fragment = value
        settings.enable_final_fragment = value
        self.controller.update_settings(settings)

    @pyqtSlot(str, str, str)
    def setFragmentSettings(self, packets: str, length: str, delay: str) -> None:
        settings = deepcopy(self.controller.state.settings)
        settings.fragment_packets = (packets or "tlshello").strip() or "tlshello"
        settings.fragment_length = (length or "50-100").strip() or "50-100"
        settings.fragment_delay = (delay or "10-20").strip() or "10-20"
        self.controller.update_settings(settings)

    @pyqtSlot(bool)
    def setTailFragment(self, enabled: bool) -> None:
        settings = deepcopy(self.controller.state.settings)
        settings.tail_fragment_enabled = bool(enabled)
        self.controller.update_settings(settings)

    @pyqtSlot(bool)
    def setMultiplexing(self, enabled: bool) -> None:
        settings = deepcopy(self.controller.state.settings)
        settings.multiplex_enabled = bool(enabled)
        self.controller.update_settings(settings)

    @pyqtSlot(int)
    def setMultiplexConcurrency(self, value: int) -> None:
        settings = deepcopy(self.controller.state.settings)
        try:
            concurrency = int(value)
        except Exception:
            concurrency = 8
        settings.multiplex_concurrency = max(1, min(32, concurrency))
        self.controller.update_settings(settings)

    # ── Auto-switch ──────────────────────────────────────────────
    @pyqtSlot(bool)
    def setAutoSwitch(self, enabled: bool) -> None:
        settings = deepcopy(self.controller.state.settings)
        settings.auto_switch_enabled = bool(enabled)
        self.controller.update_settings(settings)

    @pyqtSlot(int)
    def setAutoSwitchThreshold(self, kbps: int) -> None:
        settings = deepcopy(self.controller.state.settings)
        settings.auto_switch_threshold_kbps = max(1, int(kbps))
        self.controller.update_settings(settings)

    @pyqtSlot(int)
    def setAutoSwitchDelay(self, seconds: int) -> None:
        settings = deepcopy(self.controller.state.settings)
        settings.auto_switch_delay_sec = max(1, int(seconds))
        self.controller.update_settings(settings)

    @pyqtSlot(int)
    def setAutoSwitchCooldown(self, seconds: int) -> None:
        settings = deepcopy(self.controller.state.settings)
        settings.auto_switch_cooldown_sec = max(1, int(seconds))
        self.controller.update_settings(settings)

    # ── Core paths ───────────────────────────────────────────────
    @pyqtSlot(str)
    def setXrayPath(self, path: str) -> None:
        from ...constants import XRAY_PATH_DEFAULT
        settings = deepcopy(self.controller.state.settings)
        settings.xray_path = self._normalize_core_path_setting(path, XRAY_PATH_DEFAULT)
        self.controller.update_settings(settings)

    @pyqtSlot(str)
    def setSingboxPath(self, path: str) -> None:
        from ...constants import SINGBOX_PATH_DEFAULT
        settings = deepcopy(self.controller.state.settings)
        settings.singbox_path = self._normalize_core_path_setting(path, SINGBOX_PATH_DEFAULT)
        self.controller.update_settings(settings)

    @staticmethod
    def _normalize_core_path_setting(path: str, default_path: Path) -> str:
        value = (path or "").strip().strip('"')
        if not value:
            return ""
        normalized = value.replace("/", "\\")
        default_relative = f"core\\{default_path.name}"
        if normalized.lower() == default_relative.lower():
            return ""
        try:
            if Path(value).expanduser().resolve() == default_path.resolve():
                return ""
        except Exception:
            pass
        return value

    @staticmethod
    def _display_core_path(path: str, default_path: Path) -> str:
        value = (path or "").strip()
        if not value:
            return f"core\\{default_path.name}"
        try:
            if Path(value).expanduser().resolve() == default_path.resolve():
                return f"core\\{default_path.name}"
        except Exception:
            pass
        normalized = value.replace("/", "\\")
        if normalized.lower() == f"core\\{default_path.name}".lower():
            return f"core\\{default_path.name}"
        return value

    @pyqtSlot(result=str)
    def browseXrayPath(self) -> str:
        from PyQt6.QtWidgets import QFileDialog
        path, _ = QFileDialog.getOpenFileName(
            None, tr("Выберите xray.exe"), "", "xray.exe (xray.exe);;" + tr("Все файлы (*.*)")
        )
        if path:
            self.setXrayPath(path)
        return path or ""

    @pyqtSlot(result=str)
    def browseSingboxPath(self) -> str:
        from PyQt6.QtWidgets import QFileDialog
        path, _ = QFileDialog.getOpenFileName(
            None, tr("Выберите sing-box.exe"), "", "sing-box.exe (sing-box.exe);;" + tr("Все файлы (*.*)")
        )
        if path:
            self.setSingboxPath(path)
        return path or ""

    # ── Startup ──────────────────────────────────────────────────
    @pyqtSlot(bool)
    def setLaunchOnStartup(self, enabled: bool) -> None:
        settings = deepcopy(self.controller.state.settings)
        settings.launch_on_startup = bool(enabled)
        self.controller.update_settings(settings)

    @pyqtSlot(bool)
    def setLaunchInTrayOnStartup(self, enabled: bool) -> None:
        settings = deepcopy(self.controller.state.settings)
        settings.launch_in_tray_on_startup = bool(enabled)
        self.controller.update_settings(settings)

    @pyqtSlot(bool)
    def setBlockVpnConflicts(self, enabled: bool) -> None:
        settings = deepcopy(self.controller.state.settings)
        settings.block_vpn_conflicts = bool(enabled)
        self.controller.update_settings(settings)

    @pyqtSlot(bool)
    def setZapretAutostart(self, enabled: bool) -> None:
        settings = deepcopy(self.controller.state.settings)
        settings.zapret_autostart = bool(enabled)
        self.controller.update_settings(settings)

    # ── Security: master password / auto-lock ────────────────────
    @pyqtSlot(str)
    def setMasterPassword(self, password: str) -> None:
        pw = (password or "").strip()
        if not pw:
            self.toast.emit("warning", "Введите пароль")
            return
        self.controller.set_master_password(pw)
        self.settingsChanged.emit()
        self.toast.emit("success", "Пароль установлен")

    @pyqtSlot(str, result=bool)
    def disableMasterPassword(self, password: str) -> bool:
        pw = (password or "").strip()
        if not pw:
            self.toast.emit("warning", "Введите текущий пароль")
            return False
        if not self.controller.unlock(pw):
            self.toast.emit("error", "Неверный пароль")
            return False
        self.controller.disable_master_password()
        self.settingsChanged.emit()
        self.toast.emit("info", "Мастер-пароль отключён")
        return True

    @pyqtSlot(int)
    def setAutoLockMinutes(self, minutes: int) -> None:
        value = max(1, min(120, int(minutes)))
        self.controller.state.security.auto_lock_minutes = value
        self.controller.save()
        self.settingsChanged.emit()

    # ── Data: encryption + backup ────────────────────────────────
    @pyqtSlot(str)
    def setEncryptionPassword(self, password: str) -> None:
        pw = (password or "").strip()
        if not pw:
            self.toast.emit("warning", "Введите пароль шифрования")
            return
        self.controller.set_data_passphrase(pw)
        self.settingsChanged.emit()

    @pyqtSlot()
    def disableEncryption(self) -> None:
        self.controller.clear_data_passphrase()
        self.settingsChanged.emit()

    @pyqtSlot()
    def exportBackup(self) -> None:
        from PyQt6.QtWidgets import QFileDialog
        from pathlib import Path
        path, _ = QFileDialog.getSaveFileName(
            None, tr("Сохранить резервную копию"), "lumen-backup.json",
            tr("Резервная копия (*.json);;Все файлы (*.*)")
        )
        if not path:
            return
        try:
            self.controller.export_backup(Path(path))
            self.toast.emit("success", "Резервная копия сохранена")
        except Exception as exc:
            self.toast.emit("error", tr("Ошибка экспорта: {error}", error=exc))

    @pyqtSlot()
    def importBackup(self) -> None:
        from PyQt6.QtWidgets import QFileDialog
        from pathlib import Path
        path, _ = QFileDialog.getOpenFileName(
            None, tr("Импорт резервной копии"), "",
            tr("Резервная копия (*.json);;Все файлы (*.*)")
        )
        if not path:
            return
        try:
            self.controller.import_backup(Path(path))
            self.toast.emit("success", "Резервная копия импортирована")
        except Exception as exc:
            self.toast.emit("error", tr("Ошибка импорта: {error}", error=exc))

    @pyqtSlot()
    def resetSettingsToDefaults(self) -> None:
        self.controller.reset_settings_to_defaults()
        self.toast.emit("success", tr("Настройки сброшены по умолчанию. Серверы и подписки сохранены."))

    @pyqtSlot()
    @pyqtSlot('QVariantList')
    def pingNodes(self, ids: list | None = None) -> None:
        self.controller.ping_nodes(set(ids) if ids else None)

    @pyqtSlot()
    @pyqtSlot('QVariantList')
    def tcpingNodes(self, ids: list | None = None) -> None:
        self.controller.ping_nodes(set(ids) if ids else None, method="tcping")

    @pyqtSlot()
    @pyqtSlot('QVariantList')
    def httpGetNodes(self, ids: list | None = None) -> None:
        self.controller.ping_nodes(set(ids) if ids else None, method="http")

    @pyqtSlot()
    @pyqtSlot('QVariantList')
    def realDelayNodes(self, ids: list | None = None) -> None:
        self.controller.ping_nodes(set(ids) if ids else None, method="real")

    @pyqtSlot()
    @pyqtSlot('QVariantList')
    def speedTestNodes(self, ids: list | None = None) -> None:
        self.controller.speed_test_nodes(set(ids) if ids else None)

    @pyqtSlot()
    @pyqtSlot('QVariantList')
    def downloadSpeedNodes(self, ids: list | None = None) -> None:
        self.controller.speed_test_nodes(set(ids) if ids else None)

    @pyqtSlot()
    def cancelSpeedTest(self) -> None:
        self.controller.cancel_speed_test()

    @pyqtSlot('QVariantList')
    def deleteNodes(self, ids: list) -> None:
        if ids:
            self.controller.remove_nodes(set(ids))

    @pyqtSlot(str, str)
    def reorderNode(self, node_id: str, direction: str) -> None:
        self.controller.reorder_nodes(node_id, direction)

    # ── node edit / bulk-edit / share-link ───────────────────────
    @pyqtSlot(str, result="QVariantMap")
    def nodeEditFields(self, node_id: str):
        """Flattened editable fields for the node-edit form (or {} if missing)."""
        node = self.controller._get_node_by_id(node_id) if node_id else None
        if node is None:
            return {}
        from .node_edit_helpers import load_node_edit_fields
        return load_node_edit_fields(node)

    @pyqtProperty("QVariantList", constant=True)
    def manualNodeProtocols(self):
        from .node_edit_helpers import MANUAL_NODE_PROTOCOLS
        return list(MANUAL_NODE_PROTOCOLS)

    @pyqtSlot(str, str, result="QVariantMap")
    def manualNodeFields(self, protocol: str, group: str):
        from .node_edit_helpers import new_node_edit_fields
        return new_node_edit_fields(protocol, group)

    @pyqtProperty("QVariantMap", constant=True)
    def nodeEditOptions(self):
        """Static combo option lists for the node-edit form (mirror the dialog)."""
        from .node_edit_helpers import FINGERPRINTS, FLOWS, NETWORKS, RAW_HEADERS, SECURITY
        return {
            "fingerprints": list(FINGERPRINTS),
            "networks": list(NETWORKS),
            "security": list(SECURITY),
            "flows": list(FLOWS),
            "rawHeaders": list(RAW_HEADERS),
        }

    @pyqtSlot(str, "QVariantMap")
    def saveNodeEdit(self, node_id: str, fields) -> None:
        """Rebuild the outbound from the form values and persist via update_node."""
        node = self.controller._get_node_by_id(node_id) if node_id else None
        if node is None:
            self.toast.emit("warning", "Сервер не найден")
            return
        from .node_edit_helpers import build_node_updates
        try:
            updates = build_node_updates(node, dict(fields or {}))
            self.controller.update_node(node_id, updates)
        except Exception as exc:  # noqa: BLE001 - surface failures as a toast
            self.toast.emit("error", tr("Не удалось сохранить: {error}", error=exc))
            return
        self.toast.emit("success", "Сервер обновлён")

    @pyqtSlot("QVariantMap", result=str)
    def createManualNode(self, fields) -> str:
        """Build, validate and persist a manually entered server."""
        from .node_edit_helpers import (
            MANUAL_NODE_PROTOCOLS,
            build_node_updates,
        )

        payload = dict(fields or {})
        protocol = str(payload.pop("protocol", "vless") or "vless").strip().lower()
        if protocol not in MANUAL_NODE_PROTOCOLS:
            self.toast.emit("error", tr("Неподдерживаемый протокол: {protocol}", protocol=protocol))
            return ""
        draft = Node(
            scheme=protocol,
            group=str(payload.get("group") or "Default").strip() or "Default",
            outbound={"protocol": protocol},
        )
        try:
            updates = build_node_updates(draft, payload)
            for key in ("name", "group", "scheme", "server", "port", "link", "outbound"):
                if key in updates:
                    setattr(draft, key, updates[key])
            node_id = self.controller.add_manual_node(draft)
        except Exception as exc:  # noqa: BLE001 - show validation errors in the UI
            self.toast.emit("error", tr("Не удалось добавить сервер: {error}", error=exc))
            return ""
        self.toast.emit("success", tr("Сервер добавлен"))
        return node_id

    @pyqtSlot("QVariantList", "QVariantMap")
    def bulkEditNodes(self, ids: list, operations) -> None:
        """Apply a bulk group move to the selected nodes."""
        node_ids = {str(i) for i in (ids or []) if i}
        if not node_ids:
            self.toast.emit("warning", "Не выбрано ни одного сервера")
            return
        ops = dict(operations or {})
        payload = {
            "group": str(ops.get("group", "") or "").strip(),
        }
        self.controller.bulk_update_nodes(node_ids, payload)
        self.toast.emit("success", tr("Обновлено серверов: {count}", count=len(node_ids)))

    @pyqtSlot()
    @pyqtSlot(str)
    def copyNodeLink(self, node_id: str = "") -> None:
        """Copy a node's share link (vless://…) to the clipboard."""
        node = (
            self.controller._get_node_by_id(node_id) if node_id
            else self.controller.selected_node
        )
        from .node_edit_helpers import normalized_node_export_link

        link = normalized_node_export_link(node)
        if not link:
            self.toast.emit("warning", "У сервера нет ссылки для копирования")
            return
        clipboard = QGuiApplication.clipboard()
        if clipboard is not None:
            clipboard.setText(link)
            self.toast.emit("success", "Ссылка скопирована в буфер обмена")

    @staticmethod
    def _node_export_family(node) -> str:
        """Group nodes by config architecture for export compatibility."""
        # WireGuard-family (warp/wireguard/awg) and URI-style configs cannot be
        # exported together, so callers can compare families before exporting.
        proto = ""
        try:
            ob = node.outbound if isinstance(getattr(node, "outbound", None), dict) else {}
            proto = str(ob.get("protocol") or "").lower()
        except Exception:
            proto = ""
        if not proto:
            proto = str(getattr(node, "scheme", "") or "").lower()
        if proto in ("warp", "wireguard", "awg", "amneziawg"):
            return "wireguard"
        if proto in ("openvpn", "singbox_config"):
            return "singbox-config"
        return "uri"

    @pyqtSlot('QVariantList')
    def exportNodeLinks(self, ids: list | None = None) -> None:
        """Copy share links of the given nodes (or all) to the clipboard, one per line."""
        wanted = {str(i) for i in (ids or [])}
        selected = [n for n in self.controller.state.nodes if not wanted or n.id in wanted]
        # Запрет на экспорт несовместимых архитектур вместе (например awg + vless).
        if wanted and len({self._node_export_family(n) for n in selected}) > 1:
            self.toast.emit("warning", tr("Нельзя экспортировать вместе конфиги разных архитектур (например AWG и VLESS)"))
            return
        links: list[str] = []
        from .node_edit_helpers import normalized_node_export_link

        for node in selected:
            link = normalized_node_export_link(node)
            if link:
                links.append(link)
        if not links:
            self.toast.emit("warning", tr("Нет ссылок для экспорта"))
            return
        clipboard = QGuiApplication.clipboard()
        if clipboard is not None:
            clipboard.setText("\n".join(links))
            self.toast.emit("success", tr("Скопировано ссылок: {count}", count=len(links)))

    @pyqtSlot(str)
    def showNodeQr(self, node_id: str = "") -> None:
        """Render a node's share link as a QR code and hand a PNG data URI to QML."""
        node = (
            self.controller._get_node_by_id(node_id) if node_id
            else self.controller.selected_node
        )
        from .node_edit_helpers import normalized_node_export_link

        link = normalized_node_export_link(node)
        if not link:
            self.toast.emit("warning", tr("У сервера нет ссылки для QR-кода"))
            return
        try:
            data_uri = self._qr_data_uri(link)
        except Exception as exc:  # noqa: BLE001
            self.toast.emit("error", tr("Не удалось создать QR-код (слишком длинный конфиг?): {err}", err=str(exc)))
            return
        name = getattr(node, "name", "") or getattr(node, "server", "") or ""
        self.nodeQrReady.emit(data_uri, name)

    @staticmethod
    def _qr_data_uri(payload: str) -> str:
        import base64
        import io
        import qrcode

        # Низкий уровень коррекции + авто-подбор версии: вмещает длинные
        # awg/warp/wireguard конфиги, которые не влезали в qrcode.make().
        qr = qrcode.QRCode(
            version=None,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=6,
            border=2,
        )
        qr.add_data(payload)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode("ascii")

    @pyqtSlot(str, result=str)
    def qrDataUri(self, payload: str) -> str:
        """Return an in-memory QR PNG for small static values used by QML."""
        value = str(payload or "").strip()
        if not value:
            return ""
        try:
            return self._qr_data_uri(value)
        except Exception:
            return ""

    @pyqtSlot(int, result="QVariantMap")
    def historyData(self, days: int = 30):
        """Aggregated traffic-history payload for the History tab.

        Mirrors ui/history_page._refresh(): summary totals plus formatted
        sessions / daily / per-process rows for the given period (in days).
        """
        from .history_helpers import build_history_payload
        try:
            storage = self.controller.traffic_history
        except Exception:
            storage = None
        try:
            return build_history_payload(storage, int(days) if days else 30)
        except Exception as exc:  # noqa: BLE001 - never break the QML binding
            self.toast.emit("error", tr("Не удалось загрузить историю: {error}", error=exc))
            return build_history_payload(None, 30)

    # ── Updates tab ──────────────────────────────────────────────


    @pyqtSlot()
    def clearTrafficHistory(self) -> None:
        try:
            self.controller.traffic_history.clear()
        except Exception as exc:  # noqa: BLE001 - surface failures as a toast
            self.toast.emit("error", tr("Не удалось очистить историю: {error}", error=exc))
            return
        self.toast.emit("success", "История очищена")
    @pyqtSlot(result="QVariantMap")
    def updatesInitialState(self):
        """Snapshot shown when the Updates tab first appears."""
        from ...discord_proxy_manager import get_droute_bundle_version
        from ...engines.xray import get_xray_version
        try:
            version = get_xray_version(self.controller.state.settings.xray_path) or ""
        except Exception:
            version = ""
        try:
            singbox_version = get_singbox_version(self.controller.state.settings.singbox_path) or ""
        except Exception:
            singbox_version = ""
        return {
            "appVersion": APP_VERSION,
            "xrayVersion": version,
            "singboxVersion": singbox_version,
            "drouteVersion": get_droute_bundle_version(),
        }

    # -- application updater --
    @pyqtSlot()
    def checkAppUpdate(self) -> None:
        self._start_app_update_check(silent=False)

    def _start_app_update_check(self, silent: bool = False) -> None:
        from ...app_updater import UpdateChecker
        if self._quitting:
            return
        if getattr(self, "_app_update_downloader", None) is not None:
            if not silent:
                self._notify("info", tr("Обновление уже выполняется"))
            return
        if getattr(self, "_app_update_checker", None) is not None:
            if not silent:
                # A silent check is already in flight — promote it so the Updates page
                # shows its progress and result instead of ignoring the click.
                self._app_update_silent = False
                self.appUpdateState.emit({"phase": "checking"})
            return
        self._app_update_silent = silent
        if not silent:
            self.appUpdateState.emit({"phase": "checking"})
        channel = self.releaseChannel
        proxy_url = None
        if self.controller.connected:
            try:
                proxy_port = self.controller.get_effective_http_proxy_port()
                if proxy_port:
                    proxy_url = self.controller.get_effective_http_proxy_url()
            except Exception:
                proxy_url = None
        checker = UpdateChecker(
            self,
            channel=channel,
            prefer_qml=False,
            proxy_url=proxy_url,
        )
        self._app_update_checker = checker
        checker.result.connect(self._on_app_update_result)
        checker.error.connect(self._on_app_update_error)
        checker.finished.connect(self._clear_app_update_checker)
        checker.start()

    def _clear_app_update_checker(self) -> None:
        checker = self.sender()
        if self._app_update_checker is checker:
            self._app_update_checker = None
        if checker is not None:
            checker.deleteLater()

    def _start_resource_update_check(self) -> None:
        from ...core_resource_updater import StartupResourceCheckWorker
        if self._quitting or self._startup_resource_worker is not None:
            return
        proxy_url = None
        if self.controller.connected:
            try:
                proxy_port = self.controller.get_effective_http_proxy_port()
                if proxy_port:
                    proxy_url = self.controller.get_effective_http_proxy_url()
            except Exception:
                proxy_url = None
        worker = StartupResourceCheckWorker(
            singbox_path=self.controller.state.settings.singbox_path,
            proxy_url=proxy_url,
            region=getattr(self.controller.state.settings, "regional_preset", "russia"),
        )
        self._startup_resource_worker = worker
        worker.done.connect(self._on_startup_resource_check_done)
        worker.finished.connect(self._clear_startup_resource_worker)
        worker.start()

    def _clear_startup_resource_worker(self) -> None:
        worker = self.sender()
        if self._startup_resource_worker is worker:
            self._startup_resource_worker = None
        if worker is not None:
            worker.deleteLater()

    def _on_startup_resource_check_done(self, results) -> None:
        if self._quitting:
            return
        labels = {"singbox": "sing-box", "geodata": "geoip/geosite"}
        available = [
            labels.get(getattr(r, "kind", ""), getattr(r, "kind", ""))
            for r in (results or [])
            if getattr(r, "status", "") == "available"
        ]
        if not available:
            return
        self.toast.emit("info", tr("Доступны обновления: {items}", items=", ".join(available)))
        self.trayMessageRequested.emit()

    def _on_app_update_result(self, update) -> None:
        if self._quitting:
            return
        self._pending_app_update = update
        silent = getattr(self, "_app_update_silent", False)
        if update is None:
            if not silent:
                self.appUpdateState.emit({"phase": "uptodate"})
            return
        notes = (update.notes or "").strip()
        if len(notes) > 1200:
            notes = notes[:1200].rstrip() + "…"
        is_downgrade = bool(getattr(update, "is_downgrade", False))
        self._set_updates_available(True)
        self.appUpdateState.emit({
            "phase": "available",
            "version": update.version,
            "notes": notes,
            "channel": getattr(update, "channel", self.releaseChannel),
            "isDowngrade": is_downgrade,
        })
        if silent:
            # При тихой проверке на старте уведомляем пользователя тостом.
            if is_downgrade:
                _msg = tr("Доступен откат к v{version}", version=update.version)
            else:
                _msg = tr("Доступно обновление v{version}", version=update.version)
            self.toast.emit("info", _msg)
        from ...app_updater import should_auto_install
        settings = self.controller.state.settings
        if should_auto_install(
            update,
            enabled=bool(getattr(settings, "app_auto_update", False)),
        ):
            self._app_update_auto_installing = True
            message = tr("Найдено обновление v{version}. Lumen сейчас автоматически обновится.", version=update.version)
            self.toast.emit("info", message)
            show_toast("Lumen", message)
            QTimer.singleShot(0, self.downloadAppUpdate)

    def _on_app_update_error(self, message: str) -> None:
        if self._quitting:
            return
        if getattr(self, "_app_update_silent", False):
            return
        self.appUpdateState.emit({"phase": "error", "message": message})

    @pyqtSlot()
    def downloadAppUpdate(self) -> None:
        if self._quitting:
            return
        update = getattr(self, "_pending_app_update", None)
        if update is None:
            self.appUpdateState.emit({"phase": "error", "message": "Сначала проверьте обновления"})
            return
        if getattr(self, "_app_update_downloader", None) is not None:
            return
        from ...app_updater import UpdateDownloader
        proxy_url = None
        try:
            if self.controller.connected:
                port = self.controller.get_effective_http_proxy_port()
                if port:
                    proxy_url = self.controller.get_effective_http_proxy_url()
        except Exception:
            proxy_url = None
        self.appUpdateState.emit({"phase": "downloading", "percent": 0})
        downloader = UpdateDownloader(
            update,
            proxy_url=proxy_url,
            # An update is an interactive internal relaunch. The autostart
            # preference must not hide the freshly updated application.
            restart_in_tray=False,
            parent=self,
        )
        self._app_update_downloader = downloader
        downloader.progress.connect(self._on_app_download_progress)
        downloader.status.connect(self._on_app_download_status)
        downloader.finished_ok.connect(self._on_app_download_ok)
        downloader.error.connect(self._on_app_download_error)
        downloader.finished.connect(self._clear_app_update_downloader)
        downloader.start()

    def _clear_app_update_downloader(self) -> None:
        downloader = self.sender()
        if self._app_update_downloader is downloader:
            self._app_update_downloader = None
        if downloader is not None:
            downloader.deleteLater()

    def _on_app_download_progress(self, percent: int) -> None:
        self.appUpdateState.emit({"phase": "downloading", "percent": int(percent)})

    def _on_app_download_status(self, message: str) -> None:
        self.appUpdateState.emit({"phase": "downloading", "message": message})

    def _on_app_download_ok(self) -> None:
        self.appUpdateState.emit({"phase": "ready", "message": "Обновление загружено. Перезапуск..."})
        # PowerShell-скрипт перезапуска ждёт выхода этого процесса перед заменой
        # файлов. Если не закрыться самим, он ждёт ~60с и лишь потом убивает процесс —
        # это и была минутная задержка. Закрываемся быстро (как _quit_for_update в widgets-версии),
        # чтобы перезапуск произошёл практически сразу.
        self.prepareQuit()
        QTimer.singleShot(1500, self._quit_for_update)

    def _quit_for_update(self) -> None:
        # app.aboutToQuit уже вызывает bridge.shutdown() → корректно останавливает VPN/Wintun.
        app = QGuiApplication.instance()
        if app is not None:
            app.quit()

    def _on_app_download_error(self, message: str) -> None:
        self.appUpdateState.emit({"phase": "error", "message": message})
        if getattr(self, "_app_update_auto_installing", False):
            self.toast.emit(
                "error",
                tr("Не удалось автоматически установить обновление: {error}", error=message),
            )
        self._app_update_auto_installing = False

    # -- Xray core updater --
    def _ensure_xray_update_wired(self) -> None:
        if getattr(self, "_xray_update_wired", False):
            return
        try:
            self.controller.xray_update_progress.connect(self._on_xray_update_progress)
            self.controller.xray_update_result.connect(self._on_xray_update_result)
            self._xray_update_wired = True
        except Exception:
            pass

    @pyqtSlot()
    def checkXrayUpdate(self) -> None:
        self._ensure_xray_update_wired()
        self.xrayUpdateState.emit({"phase": "checking", "percent": 0})
        try:
            self.controller.run_xray_core_update(False)
        except Exception as exc:  # noqa: BLE001
            self.xrayUpdateState.emit({"phase": "error", "message": str(exc)})

    @pyqtSlot()
    def updateXrayCore(self) -> None:
        self._ensure_xray_update_wired()
        self.xrayUpdateState.emit({"phase": "updating", "percent": 0})
        try:
            self.controller.run_xray_core_update(True)
        except Exception as exc:  # noqa: BLE001
            self.xrayUpdateState.emit({"phase": "error", "message": str(exc)})

    def _on_xray_update_progress(self, percent: int) -> None:
        self.xrayUpdateState.emit({"phase": "updating", "percent": int(percent)})

    def _on_xray_update_result(self, result) -> None:
        phase = {
            "up_to_date": "uptodate",
            "available": "available",
            "updated": "updated",
            "error": "error",
        }.get(getattr(result, "status", ""), "uptodate")
        current_version = getattr(result, "current_version", "") or ""
        latest_version = getattr(result, "latest_version", "") or ""
        version = ""
        if phase == "updated":
            from ...engines.xray import get_xray_version

            try:
                version = get_xray_version(self.controller.state.settings.xray_path) or latest_version
            except Exception:
                version = latest_version
        self.xrayUpdateState.emit({
            "phase": phase,
            "version": version,
            "currentVersion": current_version,
            "latestVersion": latest_version,
            "message": self._localized_backend_message(getattr(result, "message", "") or ""),
            "percent": 100 if phase == "updated" else 0,
        })

    @pyqtSlot()
    def checkSingboxUpdate(self) -> None:
        self.resourceUpdateState.emit({"kind": "singbox", "phase": "checking", "percent": 0})
        try:
            if not self.controller.run_resource_update("singbox", apply_update=False):
                self.resourceUpdateState.emit({"kind": "singbox", "phase": "idle", "percent": 0})
        except Exception as exc:  # noqa: BLE001
            self.resourceUpdateState.emit({"kind": "singbox", "phase": "error", "message": str(exc)})

    @pyqtSlot()
    def updateSingboxCore(self) -> None:
        self.resourceUpdateState.emit({"kind": "singbox", "phase": "updating", "percent": 0})
        try:
            if not self.controller.run_resource_update("singbox", apply_update=True):
                self.resourceUpdateState.emit({"kind": "singbox", "phase": "idle", "percent": 0})
        except Exception as exc:  # noqa: BLE001
            self.resourceUpdateState.emit({"kind": "singbox", "phase": "error", "message": str(exc)})

    @pyqtSlot()
    def checkGeodataUpdate(self) -> None:
        self.resourceUpdateState.emit({"kind": "geodata", "phase": "checking", "percent": 0})
        try:
            if not self.controller.run_resource_update("geodata", apply_update=False):
                self.resourceUpdateState.emit({"kind": "geodata", "phase": "idle", "percent": 0})
        except Exception as exc:  # noqa: BLE001
            self.resourceUpdateState.emit({"kind": "geodata", "phase": "error", "message": str(exc)})

    @pyqtSlot()
    def updateGeodataFiles(self) -> None:
        self.resourceUpdateState.emit({"kind": "geodata", "phase": "updating", "percent": 0})
        try:
            if not self.controller.run_resource_update("geodata", apply_update=True):
                self.resourceUpdateState.emit({"kind": "geodata", "phase": "idle", "percent": 0})
        except Exception as exc:  # noqa: BLE001
            self.resourceUpdateState.emit({"kind": "geodata", "phase": "error", "message": str(exc)})

    @pyqtSlot()
    def checkDrouteUpdate(self) -> None:
        self.resourceUpdateState.emit({"kind": "droute", "phase": "checking", "percent": 0})
        try:
            if not self.controller.run_resource_update("droute", apply_update=False):
                self.resourceUpdateState.emit({"kind": "droute", "phase": "idle", "percent": 0})
        except Exception as exc:  # noqa: BLE001
            self.resourceUpdateState.emit({"kind": "droute", "phase": "error", "message": str(exc)})

    @pyqtSlot()
    def updateDroute(self) -> None:
        self.resourceUpdateState.emit({"kind": "droute", "phase": "updating", "percent": 0})
        try:
            if not self.controller.run_resource_update("droute", apply_update=True):
                self.resourceUpdateState.emit({"kind": "droute", "phase": "idle", "percent": 0})
        except Exception as exc:  # noqa: BLE001
            self.resourceUpdateState.emit({"kind": "droute", "phase": "error", "message": str(exc)})

    def _on_resource_update_progress(self, kind: str, percent: int) -> None:
        self.resourceUpdateState.emit({"kind": kind, "phase": "updating", "percent": int(percent)})

    def _on_resource_update_result(self, result) -> None:
        if (
            getattr(result, "kind", "") == "geodata"
            and self._pending_regional_preset
        ):
            self._pending_regional_preset = ""
            self.regionalPresetBusyChanged.emit()
            # Re-evaluate the bound selection after a successful commit and
            # after a failed download, where the previous region is retained.
            self.settingsChanged.emit()
            self.routingChanged.emit()
        phase = {
            "up_to_date": "uptodate",
            "available": "available",
            "updated": "updated",
            "error": "error",
        }.get(getattr(result, "status", ""), "uptodate")
        current_version = getattr(result, "current_version", "") or ""
        latest_version = getattr(result, "latest_version", "") or ""
        displayed_version = latest_version if phase == "updated" else current_version
        payload = {
            "kind": getattr(result, "kind", ""),
            "phase": phase,
            "message": self._localized_backend_message(getattr(result, "message", "") or ""),
            "version": displayed_version,
            "currentVersion": current_version,
            "latestVersion": latest_version,
            "percent": 100 if phase == "updated" else 0,
        }
        self.resourceUpdateState.emit(payload)

    # ── Zapret tab ──────────────────────────────────────────────
    zapretState = pyqtSignal("QVariantMap")        # {running, preset, error}
    zapretPresetsChanged = pyqtSignal()            # preset list changed

    def _ensure_zapret_wired(self) -> None:
        if getattr(self, "_zapret_wired", False):
            return
        try:
            z = self.controller.zapret
            z.started.connect(self._on_zapret_started)
            z.stopped.connect(self._on_zapret_stopped)
            z.error.connect(self._on_zapret_error)
            self._zapret_wired = True
        except Exception:
            pass

    @pyqtSlot(result="QVariantList")
    def zapretPresets(self):
        self._ensure_zapret_wired()
        from .zapret_helpers import list_preset_maps
        return list_preset_maps()

    @pyqtSlot(result="QVariantMap")
    def zapretStatus(self):
        self._ensure_zapret_wired()
        try:
            running = bool(self.controller.zapret.running)
        except Exception:
            running = False
        preset = ""
        try:
            if running:
                preset = self.controller.state.settings.zapret_preset or ""
        except Exception:
            preset = ""
        return {"running": running, "preset": preset, "error": ""}

    @pyqtSlot(str)
    def startZapret(self, preset_name: str) -> None:
        name = (preset_name or "").strip()
        if not name:
            return
        self._ensure_zapret_wired()
        try:
            self.controller.state.settings.zapret_preset = name
            self.controller.save()
            if not is_process_elevated():
                self._notify_action(
                    "warning",
                    tr("Zapret требует права администратора"),
                    "restart-admin",
                    tr("Перезапустить от администратора"),
                )
                return
            self.controller.zapret.start(name)
        except Exception as exc:  # noqa: BLE001
            self.zapretState.emit({"running": False, "preset": "", "error": str(exc)})

    @pyqtSlot()
    def stopZapret(self) -> None:
        self._ensure_zapret_wired()
        try:
            self.controller.zapret.stop()
        except Exception as exc:  # noqa: BLE001
            self.zapretState.emit({"running": False, "preset": "", "error": str(exc)})

    @pyqtSlot(str, result=str)
    def readPreset(self, name: str) -> str:
        from ...zapret_manager import ZapretManager
        try:
            return ZapretManager.read_preset(name)
        except Exception:
            return ""

    @pyqtSlot(str, str, str)
    def savePreset(self, name: str, description: str, content: str) -> None:
        from ...zapret_manager import ZapretManager
        name = (name or "").strip()
        if not name:
            self.toast.emit("warning", "Укажите имя пресета")
            return
        if any(c in '\\/:*?"<>|' for c in name):
            self.toast.emit("warning", "Недопустимые символы в имени")
            return
        try:
            ZapretManager.save_preset(name, content, description or "")
            self.toast.emit("success", tr("Пресет сохранён: {name}", name=name))
            self.zapretPresetsChanged.emit()
        except Exception as exc:  # noqa: BLE001
            self.toast.emit("error", tr("Не удалось сохранить пресет: {error}", error=exc))

    @pyqtSlot(str)
    def deletePreset(self, name: str) -> None:
        from ...zapret_manager import ZapretManager
        if not name:
            return
        try:
            if self.controller.zapret.running and name == self.controller.state.settings.zapret_preset:
                self.controller.zapret.stop()
            ZapretManager.delete_preset(name)
            self.toast.emit("success", tr("Пресет удалён: {name}", name=name))
            self.zapretPresetsChanged.emit()
        except Exception as exc:  # noqa: BLE001
            self.toast.emit("error", tr("Не удалось удалить пресет: {error}", error=exc))

    @pyqtSlot(result=str)
    def importZapretPreset(self) -> str:
        from pathlib import Path
        from ...zapret_manager import ZapretManager
        from PyQt6.QtWidgets import QFileDialog
        path, _ = QFileDialog.getOpenFileName(
            None, tr("Импорт пресета"), "", tr("Текстовые файлы (*.txt);;Все файлы (*)")
        )
        if not path:
            return ""
        try:
            info = ZapretManager.import_preset(Path(path))
        except Exception as exc:  # noqa: BLE001
            self.toast.emit("error", tr("Не удалось импортировать: {error}", error=exc))
            return ""
        if info is None:
            self.toast.emit("warning", "Не удалось импортировать пресет")
            return ""
        self.toast.emit("success", tr("Импортирован пресет: {name}", name=info.name))
        self.zapretPresetsChanged.emit()
        return info.name

    def _on_zapret_started(self) -> None:
        try:
            active = self.controller.state.settings.zapret_preset or ""
        except Exception:
            active = ""
        self.zapretState.emit({"running": True, "preset": active, "error": ""})

    def _on_zapret_stopped(self) -> None:
        self.zapretState.emit({"running": False, "preset": "", "error": ""})

    def _on_zapret_error(self, message: str) -> None:
        self.zapretState.emit({"running": False, "preset": "", "error": message})
        self.toast.emit("error", tr("Zapret: {message}", message=self._localized_backend_message(message)))

    # ── Configs (sing-box / xray raw editors) ──────────────────────
    def _config_state(self, core, *, text="", file_label=None, level="", message=""):
        from .configs_helpers import build_state
        return build_state(
            self.controller, core, text=text, file_label=file_label,
            status_level=level, status_message=message,
        )

    @pyqtSlot(str)
    def openConfigDirectory(self, core: str) -> None:
        if core not in ("singbox", "xray"):
            return
        try:
            path = getattr(self.controller, f"get_{core}_config_dir")().resolve()
            path.mkdir(parents=True, exist_ok=True)
            if not QDesktopServices.openUrl(QUrl.fromLocalFile(str(path))):
                raise OSError(tr("Windows не удалось открыть папку"))
        except Exception as exc:  # noqa: BLE001
            self.toast.emit("error", tr("Не удалось открыть папку конфигов: {error}", error=exc))

    @pyqtSlot(str, result="QVariantMap")
    def loadConfig(self, core: str):
        if core not in ("singbox", "xray"):
            return self._config_state("singbox")
        try:
            path, text = getattr(self.controller, f"load_active_{core}_config_text")()
        except Exception as exc:  # noqa: BLE001
            return self._config_state(core, level="error", message=str(exc))
        return self._config_state(
            core, text=text, file_label=path.as_posix(),
            level="info", message=tr("Открыта активная копия: {name}", name=path.name),
        )

    @pyqtSlot(str, str, result="QVariantMap")
    def selectConfig(self, core: str, relative_path: str):
        from .configs_helpers import sync_template_for_config
        if core not in ("singbox", "xray") or not relative_path:
            return self._config_state(core if core in ("singbox", "xray") else "singbox")
        try:
            path, text = getattr(self.controller, f"load_{core}_config_text")(relative_path)
            sync_template_for_config(self.controller, core, path)
        except Exception as exc:  # noqa: BLE001
            self.toast.emit("error", str(exc).splitlines()[0])
            return self._config_state(core, level="error", message=str(exc))
        self.toast.emit("success", tr("Открыт конфиг: {name}", name=path.name))
        return self._config_state(
            core, text=text, file_label=path.as_posix(),
            level="info", message=tr("Открыт конфиг: {name}", name=path.name),
        )

    @pyqtSlot(str, str, result="QVariantMap")
    def selectTemplate(self, core: str, relative_path: str):
        from pathlib import Path
        if core not in ("singbox", "xray") or not relative_path:
            return self._config_state(core if core in ("singbox", "xray") else "singbox")
        try:
            path, text = getattr(self.controller, f"import_{core}_template")(relative_path)
        except Exception as exc:  # noqa: BLE001
            self.toast.emit("error", str(exc).splitlines()[0])
            return self._config_state(core, level="error", message=str(exc))
        name = Path(relative_path).name
        self.toast.emit("success", tr("Применён шаблон: {name}", name=name))
        return self._config_state(
            core, text=text, file_label=path.as_posix(),
            level="info", message=tr("Применён шаблон: {name}", name=name),
        )

    @pyqtSlot(str, result="QVariantMap")
    def importTemplate(self, core: str):
        from pathlib import Path
        from PyQt6.QtWidgets import QFileDialog
        if core not in ("singbox", "xray"):
            return {"cancelled": True}
        title = "sing-box" if core == "singbox" else "xray"
        base_dir = str(getattr(self.controller, f"get_{core}_template_dir")())
        file_path, _ = QFileDialog.getOpenFileName(
            None, tr("Импортировать {title} template", title=title), base_dir, "JSON files (*.json)"
        )
        if not file_path:
            return {"cancelled": True}
        try:
            path, text = getattr(self.controller, f"import_{core}_template")(file_path)
        except Exception as exc:  # noqa: BLE001
            self.toast.emit("error", str(exc).splitlines()[0])
            return self._config_state(core, level="error", message=str(exc))
        self.toast.emit("success", tr("Импортирован template: {name}", name=Path(file_path).name))
        return self._config_state(
            core, text=text, file_label=path.as_posix(),
            level="info", message=tr("Импортирован template и обновлена активная копия: {name}", name=path.name),
        )

    @pyqtSlot(str, result="QVariantMap")
    def resetConfig(self, core: str):
        if core not in ("singbox", "xray"):
            return self._config_state("singbox")
        try:
            ok, path, message = getattr(self.controller, f"reset_active_{core}_config_to_template")()
        except Exception as exc:  # noqa: BLE001
            self.toast.emit("error", str(exc).splitlines()[0])
            return self._config_state(core, level="error", message=str(exc))
        if not ok or path is None:
            msg = message or "Сброс не выполнен"
            self.toast.emit("error", msg.splitlines()[0])
            return self._config_state(core, level="error", message=msg)
        try:
            loaded_path, text = getattr(self.controller, f"load_active_{core}_config_text")()
        except Exception as exc:  # noqa: BLE001
            return self._config_state(core, level="error", message=str(exc))
        self.toast.emit("success", message)
        return self._config_state(
            core, text=text, file_label=loaded_path.as_posix(),
            level="success", message=message,
        )

    @pyqtSlot(str, str, result="QVariantMap")
    def saveConfig(self, core: str, text: str):
        if core not in ("singbox", "xray"):
            return self._config_state("singbox", text=text)
        try:
            path = getattr(self.controller, f"save_{core}_config_text")(text)
        except Exception as exc:  # noqa: BLE001
            self.toast.emit("error", str(exc).splitlines()[0])
            return self._config_state(core, text=text, level="error", message=str(exc))
        self.toast.emit("success", tr("Сохранено: {name}", name=path.name))
        return self._config_state(
            core, text=text, file_label=path.as_posix(),
            level="success", message=tr("Сохранено: {name}", name=path.name),
        )

    @pyqtSlot(str, str, result="QVariantMap")
    def validateConfig(self, core: str, text: str):
        if core not in ("singbox", "xray"):
            return {"statusLevel": "error", "statusMessage": "Неизвестное ядро"}
        try:
            ok, message = getattr(self.controller, f"validate_{core}_json_text")(text)
        except Exception as exc:  # noqa: BLE001
            return {"statusLevel": "error", "statusMessage": str(exc)}
        if ok:
            self.toast.emit("success", "JSON корректен")
        return {"statusLevel": "success" if ok else "error", "statusMessage": message}

    @pyqtSlot(str, str, result="QVariantMap")
    def applyConfig(self, core: str, text: str):
        if core not in ("singbox", "xray"):
            return {"statusLevel": "error", "statusMessage": "Неизвестное ядро", "fileLabel": ""}
        try:
            ok, path, message = getattr(self.controller, f"apply_{core}_config_text")(text)
        except Exception as exc:  # noqa: BLE001
            self.toast.emit("error", str(exc).splitlines()[0])
            return {"statusLevel": "error", "statusMessage": str(exc), "fileLabel": ""}
        if not ok:
            msg = message or "Не удалось применить"
            self.toast.emit("error", self._localized_backend_message(msg.splitlines()[0]))
            return {"statusLevel": "error", "statusMessage": self._localized_backend_message(msg), "fileLabel": ""}
        level = "info" if "Применяю" in (message or "") else "success"
        self.toast.emit(level, self._localized_backend_message((message or "Применено").splitlines()[0]))
        return {
            "statusLevel": level,
            "statusMessage": self._localized_backend_message(message or ""),
            "fileLabel": path.as_posix() if path is not None else "",
        }

    @pyqtSlot()
    def importClipboard(self) -> None:
        clipboard = QGuiApplication.clipboard()
        mime_data = clipboard.mimeData() if clipboard is not None else None
        if mime_data is not None and mime_data.hasUrls():
            clipboard_urls = list(mime_data.urls())
            if any(self._dropped_config_path(value) is not None for value in clipboard_urls):
                self.importNodeFiles(clipboard_urls)
                return
        text = clipboard.text().strip() if clipboard is not None else ""
        if not text:
            self.toast.emit("warning", "Буфер обмена пуст")
            return
        target_group = (self._filter_group or "").strip() or None
        existing_ids = {node.id for node in self.controller.state.nodes}
        added, errors = self.controller.import_nodes_from_text(text, group=target_group)
        if added:
            imported_id = next(
                (node.id for node in self.controller.state.nodes if node.id not in existing_ids),
                "",
            )
            if imported_id:
                self.nodeImported.emit(imported_id)
            self.toast.emit("success", tr("Импортировано серверов: {count}", count=added))
        if errors:
            self.toast.emit("warning", "; ".join(errors[:2]))
        if not added and not errors:
            self.toast.emit("warning", "Новых серверов не импортировано")

    @pyqtSlot()
    def importNodeFile(self) -> None:
        from PyQt6.QtWidgets import QFileDialog

        file_path, _ = QFileDialog.getOpenFileName(
            None,
            tr("Импортировать сервер"),
            "",
            "VPN configs (*.conf *.ovpn *.txt *.json *.yaml *.yml);;OpenVPN profiles (*.ovpn);;All files (*.*)",
        )
        if not file_path:
            return
        target_group = (self._filter_group or "").strip() or None
        existing_ids = {node.id for node in self.controller.state.nodes}
        added, errors = self.controller.import_nodes_from_text(file_path, group=target_group)
        if added:
            imported_id = next(
                (node.id for node in self.controller.state.nodes if node.id not in existing_ids),
                "",
            )
            if imported_id:
                self.nodeImported.emit(imported_id)
            self.toast.emit("success", tr("Импортировано серверов: {count}", count=added))
        if errors:
            self.toast.emit("warning", "; ".join(errors[:2]))
        if not added and not errors:
            self.toast.emit("warning", "Новых серверов не импортировано")

    @staticmethod
    def _dropped_config_path(value) -> Path | None:
        if isinstance(value, QUrl):
            local_path = value.toLocalFile()
        else:
            raw_value = str(value or "").strip().strip('"')
            url = QUrl(raw_value)
            local_path = url.toLocalFile() if url.isLocalFile() else raw_value
        if not local_path:
            return None
        path = Path(local_path)
        if path.suffix.lower() not in {".conf", ".ovpn", ".txt", ".json", ".yaml", ".yml"}:
            return None
        return path if path.is_file() else None

    @pyqtSlot("QVariantList")
    def importNodeFiles(self, values) -> None:
        paths: list[Path] = []
        invalid_count = 0
        for value in values or []:
            path = self._dropped_config_path(value)
            if path is None:
                invalid_count += 1
                continue
            if path not in paths:
                paths.append(path)
        if not paths:
            self.toast.emit("warning", tr("Перетащите поддерживаемый файл конфигурации"))
            return

        target_group = (self._filter_group or "").strip() or None
        existing_ids = {node.id for node in self.controller.state.nodes}
        total_added = 0
        errors: list[str] = []
        for path in paths:
            added, file_errors = self.controller.import_nodes_from_text(str(path), group=target_group)
            total_added += added
            errors.extend(f"{path.name}: {error}" for error in file_errors)

        if total_added:
            imported_id = next(
                (node.id for node in self.controller.state.nodes if node.id not in existing_ids),
                "",
            )
            if imported_id:
                self.nodeImported.emit(imported_id)
            self.toast.emit("success", tr("Импортировано серверов: {count}", count=total_added))
        if invalid_count:
            errors.append(tr("Пропущено неподдерживаемых файлов: {count}", count=invalid_count))
        if errors:
            self.toast.emit("warning", "; ".join(errors[:2]))
        if not total_added and not errors:
            self.toast.emit("warning", tr("Новых серверов не импортировано"))

    @pyqtSlot()
    @pyqtSlot(str)
    def copyOutboundJson(self, node_id: str = "") -> None:
        payload = self.controller.export_node_outbound_json(node_id or None)
        self._copy_or_warn(payload)

    @pyqtSlot()
    @pyqtSlot(str)
    def copyRuntimeJson(self, node_id: str = "") -> None:
        payload = self.controller.export_runtime_config_json(node_id or None)
        self._copy_or_warn(payload)

    @pyqtSlot()
    @pyqtSlot(str)
    def saveOutboundJson(self, node_id: str = "") -> None:
        payload = self.controller.export_node_outbound_json(node_id or None)
        self._save_json_payload(payload, "outbound.json")

    @pyqtSlot()
    @pyqtSlot(str)
    def saveRuntimeJson(self, node_id: str = "") -> None:
        payload = self.controller.export_runtime_config_json(node_id or None)
        try:
            settings = self.controller.state.settings
            node = self.controller._get_node_by_id(node_id) if node_id else self.controller.selected_node
            singbox = self.controller.is_singbox_editor_mode(settings) or (
                not settings.tun_mode and proxy_core_for_node(node) == "singbox"
            )
        except Exception:  # noqa: BLE001 - defensive, default to xray name
            singbox = False
        suggested = "singbox_config.json" if singbox else "xray_config.json"
        self._save_json_payload(payload, suggested)

    def _save_json_payload(self, payload: str | None, suggested_name: str) -> None:
        if not payload:
            self.toast.emit("warning", "Выберите сервер для экспорта")
            return
        from PyQt6.QtWidgets import QApplication, QFileDialog
        file_path, _ = QFileDialog.getSaveFileName(
            None, tr("Экспорт JSON"), suggested_name, "JSON files (*.json)"
        )
        if file_path:
            try:
                with open(file_path, "w", encoding="utf-8") as fh:
                    fh.write(payload)
            except OSError as exc:
                self.toast.emit("error", tr("Не удалось сохранить файл: {error}", error=exc))
                return
            self.toast.emit("success", tr("JSON экспортирован: {path}", path=file_path))
            return
        clipboard = QApplication.clipboard()
        if clipboard is not None:
            clipboard.setText(payload)
            self.toast.emit("info", "Экспорт отменён, JSON скопирован в буфер обмена")

    @pyqtSlot(str, bool)
    def setNodeSort(self, key: str, ascending: bool) -> None:
        """Set the active sort key/direction for the node list and re-push it."""
        self._sort_key = key or "manual"
        self._sort_asc = bool(ascending)
        settings = self.controller.state.settings
        if (
            settings.node_sort_key != self._sort_key
            or settings.node_sort_ascending != self._sort_asc
        ):
            settings.node_sort_key = self._sort_key
            settings.node_sort_ascending = self._sort_asc
            self.controller.schedule_save()
        self._apply_node_model()

    @pyqtSlot(str, str)
    def setNodeFilter(self, group: str, text: str) -> None:
        """Set the active group/text filter and re-push the node list so the
        model holds only visible rows (keeps ListView count/contentHeight correct)."""
        self._filter_group = group or ""
        self._filter_text = text or ""
        if self.controller.state.settings.node_filter_group != self._filter_group:
            self.controller.state.settings.node_filter_group = self._filter_group
            self.controller.schedule_save()
        self._apply_node_model()

    @pyqtProperty(str)
    def nodeSortKey(self) -> str:
        return str(self._sort_key or "manual")

    @pyqtProperty(bool)
    def nodeSortAscending(self) -> bool:
        return bool(self._sort_asc)

    @pyqtProperty(str)
    def nodeFilterGroup(self) -> str:
        return str(self._filter_group or "")

    @pyqtProperty(str)
    def selectedSubscriptionId(self) -> str:
        return str(self.controller.state.settings.selected_subscription_id or "")

    @pyqtSlot(str)
    def setSelectedSubscriptionId(self, subscription_id: str) -> None:
        value = str(subscription_id or "").strip()
        settings = self.controller.state.settings
        if settings.selected_subscription_id == value:
            return
        settings.selected_subscription_id = value
        self.controller.schedule_save()

    @pyqtProperty("QVariantMap")
    def nodeTableLayout(self) -> dict:
        return dict(self.controller.state.settings.node_table_layout)

    @pyqtSlot("QVariantMap")
    def setNodeTableLayout(self, layout: dict) -> None:
        if not isinstance(layout, dict):
            return
        allowed = {
            "manual", "name", "type", "transport", "address", "port",
            "group", "ping", "speed", "status", "last",
        }
        normalized: dict[str, Any] = {}
        for key, value in layout.items():
            key = str(key)
            if key not in allowed:
                continue
            if key == "manual":
                normalized[key] = bool(value)
                continue
            try:
                normalized[key] = max(48.0, min(float(value), 2000.0))
            except (TypeError, ValueError):
                continue
        settings = self.controller.state.settings
        if settings.node_table_layout == normalized:
            return
        settings.node_table_layout = normalized
        self.controller.schedule_save()

    @pyqtSlot(str, result=bool)
    def createManualGroup(self, name: str) -> bool:
        group = (name or "").strip()
        if not group:
            self.toast.emit("warning", tr("Введите имя группы"))
            return False
        existing = {"default"}
        existing.update(str(item).strip().lower() for item in getattr(self.controller.state, "manual_groups", []))
        existing.update((node.group or "Default").strip().lower() for node in self.controller.state.nodes)
        if group.lower() in existing:
            self.toast.emit("info", tr("Такая группа уже есть"))
            return False
        self.controller.state.manual_groups.append(group)
        self.controller.save()
        self.nodeFiltersChanged.emit()
        self.toast.emit("success", tr("Группа создана: {name}", name=group))
        return True

    @pyqtSlot(str, result=bool)
    def deleteGroup(self, name: str) -> bool:
        group = str(name or "").strip()
        if not group or group.casefold() == "default":
            return False
        if not self.controller.delete_group(group):
            return False
        self.nodeFiltersChanged.emit()
        self.toast.emit("success", tr("Группа удалена: {name}", name=group))
        return True

    @pyqtProperty("QVariantList", notify=nodeFiltersChanged)
    def groupOptions(self) -> list:
        """Distinct group names across all nodes (for the Группа filter combo)."""
        seen: list[str] = ["Default"]
        seen_keys = {"default"}
        for group in getattr(self.controller.state, "manual_groups", []):
            grp = str(group or "").strip()
            key = grp.casefold()
            if grp and key not in seen_keys:
                seen.append(grp)
                seen_keys.add(key)
        for node in self.controller.state.nodes:
            grp = str(node.group or "Default").strip() or "Default"
            key = grp.casefold()
            if key not in seen_keys:
                seen.append(grp)
                seen_keys.add(key)
        return ["Default", *sorted(seen[1:], key=str.lower)]

    @pyqtSlot()
    def exportDiagnostics(self) -> None:
        """Build a diagnostics zip and reveal it in the file manager."""
        try:
            path = self.controller.build_diagnostics()
        except Exception as exc:  # noqa: BLE001
            self.toast.emit("error", tr("Не удалось собрать диагностику: {error}", error=exc))
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(path.parent)))
        self.toast.emit("success", tr("Диагностика сохранена: {name}", name=path.name))

    @pyqtSlot("QVariantMap")
    def runDiagnosticsExport(self, options) -> None:
        """Build a diagnostics zip from the chosen sections; optionally upload it."""
        opts = dict(options) if options else {}
        include = {
            "errors": bool(opts.get("errors", True)),
            "core": bool(opts.get("core", True)),
            "app": bool(opts.get("app", True)),
            "traffic": bool(opts.get("traffic", True)),
            "state": bool(opts.get("state", True)),
            "recent": bool(opts.get("recent", True)),
        }
        upload = bool(opts.get("upload", False))
        if not any(include.values()):
            self.toast.emit("error", tr("Выберите хотя бы один раздел для экспорта"))
            return
        try:
            path = self.controller.build_diagnostics(include=include, upload=upload)
        except Exception as exc:  # noqa: BLE001
            self.toast.emit("error", tr("Не удалось собрать диагностику: {error}", error=exc))
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(path.parent)))
        if upload:
            self.toast.emit("success", tr("Диагностика собрана и отправлена: {name}", name=path.name))
        else:
            self.toast.emit("success", tr("Диагностика сохранена: {name}", name=path.name))

    @pyqtSlot(int, result=str)
    def nodeIdAt(self, row: int) -> str:
        """Map a ListView row index to a node id (used for drag/shift range select)."""
        return self._node_model.node_id_at(row) or ""

    @pyqtSlot(str, result=int)
    def nodeIndexById(self, node_id: str) -> int:
        return self._node_model.index_of_id(node_id)

    @pyqtSlot(int, result="QVariant")
    def nodeRowAt(self, row: int):
        """Return a row's filterable fields by index.

        Used by Ctrl+A so it can select only the rows that pass the current
        group/text filter instead of every node in the model.
        """
        return self._node_model.node_row_at(row)

    @pyqtSlot()
    def lockNow(self) -> None:
        self.controller.lock()

    @pyqtSlot()
    def clearLogs(self) -> None:
        self._log_model.clear()

    @pyqtSlot(str)
    def setLogLevelFilter(self, value: str) -> None:
        self._log_model.setLevelFilter(value)

    @pyqtSlot(str)
    def setLogSearch(self, value: str) -> None:
        self._log_model.setSearchText(value)

    @staticmethod
    def _find_free_local_port(start: int, excluded: set[int]) -> int:
        for port in range(max(1024, start), 65535):
            if port in excluded:
                continue
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                try:
                    probe.bind(("127.0.0.1", port))
                except OSError:
                    continue
            return port
        raise RuntimeError("Не удалось найти свободный локальный порт")

    @pyqtSlot(str)
    def runToastAction(self, action_id: str) -> None:
        if action_id == "restart-admin":
            self._on_admin_relaunch()
            return
        if not action_id.startswith("change-port:"):
            return
        try:
            occupied = int(action_id.split(":", 1)[1])
            path, text = self.controller.load_active_xray_config_text()
            payload = json.loads(text)
            inbounds = payload.get("inbounds")
            if not isinstance(inbounds, list):
                raise RuntimeError("В активном Xray-конфиге нет локальных входящих портов")
            used = {
                int(item.get("port"))
                for item in inbounds
                if isinstance(item, dict) and isinstance(item.get("port"), int)
            }
            new_port = self._find_free_local_port(occupied + 1, used)
            changed = False
            for inbound in inbounds:
                if isinstance(inbound, dict) and inbound.get("port") == occupied:
                    inbound["port"] = new_port
                    changed = True
            if not changed:
                raise RuntimeError(f"Порт {occupied} не найден в активном Xray-конфиге")
            self.controller.save_xray_config_text(
                json.dumps(payload, ensure_ascii=False, indent=2), path
            )
            self.controller._log(f"[proxy] Локальный порт автоматически изменён: {occupied} -> {new_port}")
            if self.controller.connected or getattr(self.controller, "_desired_connected", False):
                self.controller._request_transition("local proxy port changed")
            self.toast.emit("success", tr("Порт изменён: {old} → {new}", old=occupied, new=new_port))
        except Exception as exc:
            self.controller._log(f"[app-error] Не удалось автоматически сменить порт: {exc}")
            self.toast.emit("error", tr("Не удалось сменить порт: {error}", error=exc))

    @pyqtSlot(str)
    def testConnectivity(self, url: str) -> None:
        self.controller.test_connectivity(url or None)

    @pyqtSlot(str)
    def openUrl(self, url: str) -> None:
        """Open an external link in the user's default browser (About page)."""
        target = (url or "").strip()
        if not target:
            return
        QDesktopServices.openUrl(QUrl(target))

    @pyqtSlot(str)
    def copyText(self, text: str) -> None:
        payload = (text or "").strip()
        if not payload:
            return
        clipboard = QGuiApplication.clipboard()
        if clipboard is not None:
            clipboard.setText(payload)
            self.toast.emit("success", "Скопировано в буфер обмена")

    def _copy_or_warn(self, payload: str | None) -> None:
        if not payload:
            self.toast.emit("warning", "Выберите сервер для экспорта")
            return
        clipboard = QGuiApplication.clipboard()
        if clipboard is not None:
            clipboard.setText(payload)
            self.toast.emit("success", "JSON скопирован в буфер обмена")

    # ── QML-readable models ────────────────────────────────────
    @pyqtProperty(QObject, constant=True)
    def nodeModel(self) -> NodeListModel:
        return self._node_model

    @pyqtProperty(QObject, constant=True)
    def logModel(self) -> LogModel:
        return self._log_model

    @pyqtProperty(QObject, constant=True)
    def processModel(self) -> ProcessModel:
        return self._process_model

    @pyqtProperty(str, constant=True)
    def appName(self) -> str:
        return APP_NAME

    @pyqtProperty(str, constant=True)
    def appVersion(self) -> str:
        return APP_VERSION

    # ── QML-readable state properties ─────────────────────────────
    @pyqtProperty(bool, notify=connectedChanged)
    def connected(self) -> bool:
        return self._connected

    @pyqtProperty(bool, notify=transitionBusyChanged)
    def transitionBusy(self) -> bool:
        return self._busy

    @pyqtProperty(bool, notify=transitionBusyChanged)
    def transitionTargetConnected(self) -> bool:
        return self._transition_target_connected

    @pyqtProperty(bool, notify=transitionDirectionChanged)
    def transitionConnecting(self) -> bool:
        return self._transition_connecting

    @pyqtProperty(str, notify=runtimeChanged)
    def runtimePhase(self) -> str:
        return self._runtime_phase

    @pyqtProperty(str, notify=runtimeChanged)
    def runtimeMessage(self) -> str:
        return self._runtime_message

    @pyqtProperty(float, notify=metricsChanged)
    def downBps(self) -> float:
        return self._down_bps

    @pyqtProperty(float, notify=metricsChanged)
    def upBps(self) -> float:
        return self._up_bps

    @pyqtProperty(int, notify=metricsChanged)
    def latencyMs(self) -> int:
        return self._latency_ms

    @pyqtProperty(str, notify=selectionChanged)
    def selectedNodeId(self) -> str:
        return self._selected_id

    @pyqtProperty(str, notify=selectionChanged)
    def selectedNodeName(self) -> str:
        return self._selected_name

    @pyqtProperty(str, notify=selectionChanged)
    def selectedNodeFlag(self) -> str:
        return self._selected_flag

    @pyqtProperty(str, notify=selectionChanged)
    def selectedNodeFlagSource(self) -> str:
        return self._selected_flag_source

    @pyqtProperty(int, notify=selectionChanged)
    def selectedLatency(self) -> int:
        return self._selected_latency

    @pyqtProperty(str, notify=routingChanged)
    def routingMode(self) -> str:
        return self._routing_mode

    @pyqtProperty(str, notify=routingChanged)
    def activeRoutingPresetId(self) -> str:
        try:
            return str(self.controller.state.routing.preset_id or "custom")
        except Exception:
            return "custom"

    @pyqtProperty(bool, notify=settingsChanged)
    def tunMode(self) -> bool:
        return self._tun_mode

    @pyqtProperty(bool, constant=True)
    def limitedMode(self) -> bool:
        return not is_process_elevated()

    @pyqtProperty(bool, notify=settingsChanged)
    def proxyEnabled(self) -> bool:
        return self._proxy_enabled

    @pyqtProperty(bool, notify=settingsChanged)
    def discordProxy(self) -> bool:
        return self._discord_proxy

    @pyqtProperty(str, notify=settingsChanged)
    def themeName(self) -> str:
        return self._theme

    @pyqtProperty(str, notify=settingsChanged)
    def language(self) -> str:
        return self._language

    @pyqtProperty(str, notify=settingsChanged)
    def effectiveLanguage(self) -> str:
        return self._language if self._language in available_languages() else "en"

    @pyqtProperty("QVariantMap", notify=languageChanged)
    def translations(self) -> dict:
        return active_map()

    @pyqtProperty("QStringList", constant=True)
    def availableLanguages(self) -> list:
        return available_languages()

    @pyqtProperty("QStringList", constant=True)
    def languageLabels(self) -> list:
        return [language_name(code) for code in available_languages()]

    @pyqtProperty(str, notify=settingsChanged)
    def accentColor(self) -> str:
        return self._accent

    @pyqtProperty(bool, notify=settingsChanged)
    def compactMode(self) -> bool:
        try:
            return self.controller.state.settings.interface_mode == "compact"
        except Exception:
            return False

    # ── Network / auto-switch / paths / startup mirrors ──────────
    @pyqtProperty(bool, notify=settingsChanged)
    def proxyBypassLan(self) -> bool:
        try:
            return bool(self.controller.state.settings.system_proxy_bypass_lan)
        except Exception:
            return True

    @pyqtProperty(bool, notify=settingsChanged)
    def firefoxProxyIntegration(self) -> bool:
        try:
            return bool(self.controller.state.settings.firefox_proxy_integration)
        except Exception:
            return False

    @pyqtProperty(bool, notify=settingsChanged)
    def reconnectOnNetworkChange(self) -> bool:
        try:
            return bool(self.controller.state.settings.reconnect_on_network_change)
        except Exception:
            return True

    @pyqtProperty(bool, notify=settingsChanged)
    def reconnectAfterSleep(self) -> bool:
        try:
            return bool(self.controller.state.settings.reconnect_after_sleep)
        except Exception:
            return True

    @pyqtProperty(str, notify=settingsChanged)
    def regionalPreset(self) -> str:
        try:
            return str(self.controller.state.settings.regional_preset or "russia")
        except Exception:
            return "russia"

    @pyqtProperty(bool, notify=regionalPresetBusyChanged)
    def regionalPresetBusy(self) -> bool:
        return bool(self._pending_regional_preset)

    @pyqtProperty(bool, notify=settingsChanged)
    def preferIpv6(self) -> bool:
        try:
            return bool(self.controller.state.settings.prefer_ipv6)
        except Exception:
            return False

    @pyqtProperty(bool, notify=settingsChanged)
    def killSwitch(self) -> bool:
        try:
            return bool(self.controller.state.settings.kill_switch)
        except Exception:
            return False

    @pyqtProperty(bool, notify=settingsChanged)
    def proxyAllowLan(self) -> bool:
        try:
            return bool(self.controller.state.settings.proxy_allow_lan)
        except Exception:
            return False

    @pyqtProperty(bool, notify=settingsChanged)
    def tunStrictRoute(self) -> bool:
        try:
            return bool(self.controller.state.settings.tun_strict_route)
        except Exception:
            return False

    @pyqtProperty(str, notify=settingsChanged)
    def tunStack(self) -> str:
        try:
            return str(self.controller.state.settings.tun_stack)
        except Exception:
            return "mixed"

    @pyqtProperty(int, notify=settingsChanged)
    def tunMtu(self) -> int:
        try:
            return int(self.controller.state.settings.tun_mtu)
        except Exception:
            return 9000

    @pyqtProperty(int, notify=settingsChanged)
    def localSocksPort(self) -> int:
        try:
            return int(self.controller.state.settings.local_socks_port)
        except Exception:
            return 10808

    @pyqtProperty(int, notify=settingsChanged)
    def localHttpPort(self) -> int:
        try:
            return int(self.controller.state.settings.local_http_port)
        except Exception:
            return 10809

    @pyqtProperty(bool, notify=settingsChanged)
    def proxyAuthEnabled(self) -> bool:
        return bool(getattr(self.controller.state.settings, "proxy_auth_enabled", False))

    @pyqtProperty(str, notify=settingsChanged)
    def proxyAuthUsername(self) -> str:
        return str(getattr(self.controller.state.settings, "proxy_auth_username", "") or "")

    @pyqtProperty(str, notify=settingsChanged)
    def proxyAuthPassword(self) -> str:
        return str(getattr(self.controller.state.settings, "proxy_auth_password", "") or "")

    @pyqtProperty(bool, notify=settingsChanged)
    def tunBlockQuic(self) -> bool:
        try:
            return bool(self.controller.state.settings.tun_block_quic)
        except Exception:
            return True

    @pyqtProperty(bool, notify=settingsChanged)
    def tunEndpointIndependentNat(self) -> bool:
        try:
            return bool(self.controller.state.settings.tun_endpoint_independent_nat)
        except Exception:
            return False

    @pyqtProperty(bool, notify=settingsChanged)
    def sniffRouteOnly(self) -> bool:
        try:
            return bool(self.controller.state.settings.sniff_route_only)
        except Exception:
            return False

    @pyqtProperty(bool, notify=settingsChanged)
    def resourceUpdateCheck(self) -> bool:
        try:
            return bool(self.controller.state.settings.resource_update_check)
        except Exception:
            return False

    @pyqtProperty(bool, notify=settingsChanged)
    def diagnosticsUploadEnabled(self) -> bool:
        try:
            return bool(self.controller.state.settings.diagnostics_upload_enabled)
        except Exception:
            return True

    @pyqtProperty(bool, notify=settingsChanged)
    def xrayFragmentEnabled(self) -> bool:
        try:
            return bool(self.controller.state.settings.enable_xray_fragment)
        except Exception:
            return False

    @pyqtProperty(bool, notify=settingsChanged)
    def finalFragmentEnabled(self) -> bool:
        try:
            return bool(self.controller.state.settings.enable_final_fragment)
        except Exception:
            return False

    @pyqtProperty(bool, notify=settingsChanged)
    def fragmentationEnabled(self) -> bool:
        try:
            settings = self.controller.state.settings
            return bool(settings.enable_xray_fragment or settings.enable_final_fragment)
        except Exception:
            return False

    @pyqtProperty(str, notify=settingsChanged)
    def fragmentPackets(self) -> str:
        try:
            return str(self.controller.state.settings.fragment_packets)
        except Exception:
            return "tlshello"

    @pyqtProperty(str, notify=settingsChanged)
    def fragmentLength(self) -> str:
        try:
            return str(self.controller.state.settings.fragment_length)
        except Exception:
            return "50-100"

    @pyqtProperty(str, notify=settingsChanged)
    def fragmentDelay(self) -> str:
        try:
            return str(self.controller.state.settings.fragment_delay)
        except Exception:
            return "10-20"

    @pyqtProperty(bool, notify=settingsChanged)
    def tailFragmentEnabled(self) -> bool:
        try:
            return bool(self.controller.state.settings.tail_fragment_enabled)
        except Exception:
            return False

    @pyqtProperty(bool, notify=settingsChanged)
    def multiplexingEnabled(self) -> bool:
        try:
            return bool(self.controller.state.settings.multiplex_enabled)
        except Exception:
            return False

    @pyqtProperty(int, notify=settingsChanged)
    def multiplexConcurrency(self) -> int:
        try:
            return int(self.controller.state.settings.multiplex_concurrency)
        except Exception:
            return 8

    @pyqtProperty(bool, notify=settingsChanged)
    def autoSwitchEnabled(self) -> bool:
        try:
            return bool(self.controller.state.settings.auto_switch_enabled)
        except Exception:
            return True

    @pyqtProperty(int, notify=settingsChanged)
    def autoSwitchThreshold(self) -> int:
        try:
            return int(self.controller.state.settings.auto_switch_threshold_kbps)
        except Exception:
            return 50

    @pyqtProperty(int, notify=settingsChanged)
    def autoSwitchDelay(self) -> int:
        try:
            return int(self.controller.state.settings.auto_switch_delay_sec)
        except Exception:
            return 30

    @pyqtProperty(int, notify=settingsChanged)
    def autoSwitchCooldown(self) -> int:
        try:
            return int(self.controller.state.settings.auto_switch_cooldown_sec)
        except Exception:
            return 60

    @pyqtProperty(str, notify=settingsChanged)
    def xrayPath(self) -> str:
        try:
            from ...constants import XRAY_PATH_DEFAULT
            path = (self.controller.state.settings.xray_path or "").strip()
            return self._display_core_path(path, XRAY_PATH_DEFAULT)
        except Exception:
            return ""

    @pyqtProperty(str, notify=settingsChanged)
    def singboxPath(self) -> str:
        try:
            from ...constants import SINGBOX_PATH_DEFAULT
            path = (self.controller.state.settings.singbox_path or "").strip()
            return self._display_core_path(path, SINGBOX_PATH_DEFAULT)
        except Exception:
            return ""

    @pyqtProperty(bool, notify=settingsChanged)
    def launchOnStartup(self) -> bool:
        try:
            return bool(self.controller.state.settings.launch_on_startup)
        except Exception:
            return False

    @pyqtProperty(bool, notify=settingsChanged)
    def launchInTrayOnStartup(self) -> bool:
        try:
            return bool(getattr(self.controller.state.settings, "launch_in_tray_on_startup", True))
        except Exception:
            return True

    @pyqtProperty(bool, notify=settingsChanged)
    def blockVpnConflicts(self) -> bool:
        try:
            return bool(getattr(self.controller.state.settings, "block_vpn_conflicts", True))
        except Exception:
            return True

    @pyqtProperty(bool, notify=settingsChanged)
    def zapretAutostart(self) -> bool:
        try:
            return bool(self.controller.state.settings.zapret_autostart)
        except Exception:
            return False

    # ── Auto-connect / server-test settings ──────────────────────
    @pyqtSlot(bool)
    def setAutoConnectLast(self, enabled: bool) -> None:
        settings = deepcopy(self.controller.state.settings)
        settings.auto_connect_last = bool(enabled)
        self.controller.update_settings(settings)

    @pyqtProperty(bool, notify=settingsChanged)
    def autoConnectLast(self) -> bool:
        try:
            return bool(self.controller.state.settings.auto_connect_last)
        except Exception:
            return True

    @pyqtSlot(bool)
    def setAutoConnectOnImport(self, enabled: bool) -> None:
        settings = deepcopy(self.controller.state.settings)
        settings.auto_connect_on_import = bool(enabled)
        self.controller.update_settings(settings)

    @pyqtProperty(bool, notify=settingsChanged)
    def autoConnectOnImport(self) -> bool:
        try:
            return bool(self.controller.state.settings.auto_connect_on_import)
        except Exception:
            return False

    @pyqtSlot(str)
    def setPingMethod(self, method: str) -> None:
        value = (method or "tcping").strip().lower()
        if value not in ("tcping", "icmp", "http", "real"):
            value = "tcping"
        settings = deepcopy(self.controller.state.settings)
        settings.ping_method = value
        self.controller.update_settings(settings)

    @pyqtProperty(str, notify=settingsChanged)
    def pingMethod(self) -> str:
        try:
            return self.controller.state.settings.ping_method or "tcping"
        except Exception:
            return "tcping"

    @pyqtSlot(str)
    def setSpeedTestUrl(self, url: str) -> None:
        settings = deepcopy(self.controller.state.settings)
        settings.speed_test_url = (url or "").strip()
        self.controller.update_settings(settings)

    @pyqtProperty(str, notify=settingsChanged)
    def speedTestUrl(self) -> str:
        try:
            return self.controller.state.settings.speed_test_url or ""
        except Exception:
            return ""

    @pyqtSlot(int)
    def setSpeedTestConcurrency(self, value: int) -> None:
        try:
            count = int(value)
        except Exception:
            count = 0
        count = max(0, min(SPEED_TEST_MAX_CONCURRENCY, count))
        settings = deepcopy(self.controller.state.settings)
        settings.speed_test_concurrency = count
        self.controller.update_settings(settings)

    @pyqtProperty(int, notify=settingsChanged)
    def speedTestConcurrency(self) -> int:
        try:
            return int(self.controller.state.settings.speed_test_concurrency)
        except Exception:
            return 0

    @pyqtSlot(int)
    def setSubscriptionAutoUpdateMinutes(self, value: int) -> None:
        try:
            minutes = int(value)
        except Exception:
            minutes = 240
        minutes = max(0, min(1440, minutes))
        settings = deepcopy(self.controller.state.settings)
        settings.subscription_auto_update_minutes = minutes
        self.controller.update_settings(settings)
        self._reconfigure_sub_timer()

    @pyqtProperty(int, notify=settingsChanged)
    def subscriptionAutoUpdateMinutes(self) -> int:
        try:
            return int(self.controller.state.settings.subscription_auto_update_minutes)
        except Exception:
            return 240

    @pyqtProperty(str, notify=subscriptionsChanged)
    def subscriptionUrlsText(self) -> str:
        return "\n".join(
            str(item.get("url") or "").strip()
            for item in self.controller.state.subscriptions
            if str(item.get("url") or "").strip()
        )

    @pyqtProperty(str, notify=settingsChanged)
    def subscriptionIncludeRegex(self) -> str:
        return str(self.controller.state.settings.subscription_include_regex or "")

    @pyqtSlot(str)
    def setSubscriptionIncludeRegex(self, value: str) -> None:
        settings = deepcopy(self.controller.state.settings)
        settings.subscription_include_regex = str(value or "").strip()
        self.controller.update_settings(settings)

    @pyqtProperty(str, notify=settingsChanged)
    def subscriptionExcludeRegex(self) -> str:
        return str(self.controller.state.settings.subscription_exclude_regex or "")

    @pyqtSlot(str)
    def setSubscriptionExcludeRegex(self, value: str) -> None:
        settings = deepcopy(self.controller.state.settings)
        settings.subscription_exclude_regex = str(value or "").strip()
        self.controller.update_settings(settings)

    @pyqtProperty(str, notify=settingsChanged)
    def subscriptionUserAgent(self) -> str:
        return str(self.controller.state.settings.subscription_user_agent or "")

    @pyqtSlot(str)
    def setSubscriptionUserAgent(self, value: str) -> None:
        settings = deepcopy(self.controller.state.settings)
        settings.subscription_user_agent = str(value or "").strip()
        self.controller.update_settings(settings)

    @pyqtProperty(bool, notify=settingsChanged)
    def subscriptionUseRealHwid(self) -> bool:
        return bool(getattr(self.controller.state.settings, "subscription_use_real_hwid", True))

    @pyqtSlot(bool)
    def setSubscriptionUseRealHwid(self, enabled: bool) -> None:
        settings = deepcopy(self.controller.state.settings)
        settings.subscription_use_real_hwid = bool(enabled)
        self.controller.update_settings(settings)

    @pyqtProperty(bool, notify=settingsChanged)
    def subscriptionUseProxyTun(self) -> bool:
        return bool(getattr(self.controller.state.settings, "subscription_use_proxy_tun", False))

    @pyqtSlot(bool)
    def setSubscriptionUseProxyTun(self, enabled: bool) -> None:
        settings = deepcopy(self.controller.state.settings)
        settings.subscription_use_proxy_tun = bool(enabled)
        self.controller.update_settings(settings)

    @pyqtProperty(str, notify=settingsChanged)
    def subscriptionHwid(self) -> str:
        return str(self.controller.state.settings.subscription_hwid or "")

    @pyqtSlot(str)
    def setSubscriptionHwid(self, value: str) -> None:
        settings = deepcopy(self.controller.state.settings)
        settings.subscription_hwid = str(value or "").strip()
        self.controller.update_settings(settings)

    @pyqtProperty(bool, notify=settingsChanged)
    def subscriptionConverterEnabled(self) -> bool:
        return bool(self.controller.state.settings.subscription_converter_enabled)

    @pyqtSlot(bool)
    def setSubscriptionConverterEnabled(self, enabled: bool) -> None:
        settings = deepcopy(self.controller.state.settings)
        settings.subscription_converter_enabled = bool(enabled)
        self.controller.update_settings(settings)

    @pyqtProperty(str, notify=settingsChanged)
    def subscriptionConverterUrl(self) -> str:
        return str(self.controller.state.settings.subscription_converter_url or "")

    @pyqtSlot(str)
    def setSubscriptionConverterUrl(self, value: str) -> None:
        settings = deepcopy(self.controller.state.settings)
        settings.subscription_converter_url = str(value or "").strip()
        self.controller.update_settings(settings)

    @pyqtProperty(bool, notify=subscriptionImportingChanged)
    def subscriptionImporting(self) -> bool:
        return self._sub_importing

    @pyqtProperty(str, notify=subscriptionImportStatusChanged)
    def subscriptionImportStatus(self) -> str:
        return self._sub_import_status

    # ── Subscriptions ────────────────────────────────────────────
    @pyqtSlot()
    def cancelSubscriptionImport(self) -> None:
        if not self._sub_importing:
            return
        self._sub_importing = False
        self._sub_import_status = ""
        self.subscriptionImportingChanged.emit()
        self.subscriptionImportStatusChanged.emit()
        for batch_id in list(self._sub_batches.keys()):
            self._sub_batches.pop(batch_id, None)
        worker = self._sub_worker
        thread = self._sub_thread
        if worker is not None:
            try:
                worker.stop()
            except Exception:
                pass
        if thread is not None:
            if worker is not None:
                try:
                    self._sub_fetch_run.disconnect(worker.run_batch)
                except Exception:
                    pass
            self._retire_sub_worker(thread, worker)
            if self._sub_thread is thread:
                self._sub_thread = None
            if self._sub_worker is worker:
                self._sub_worker = None
            thread.quit()
        self.toast.emit("info", tr("Импорт подписки отменён"))

    @pyqtSlot(str)
    @pyqtSlot(str, str)
    def importSubscription(self, url: str, name: str = "") -> None:
        target = (url or "").strip()
        if not target:
            self.toast.emit("warning", tr("Введите ссылку на подписку"))
            return
        self._sub_importing = True
        self._sub_import_status = tr("Загрузка подписки...")
        self.subscriptionImportingChanged.emit()
        self.subscriptionImportStatusChanged.emit()
        # Сеть в фоне: UI не блокируется, итог придёт через _on_sub_batch_completed.
        job = SubscriptionJob(url=target, kind="import", name=(name or "").strip())
        self._dispatch_sub_jobs([job], "import")

    @pyqtSlot(str, result=bool)
    def handleDeepLink(self, value: str) -> bool:
        """Validate a ``lumen:`` URL and route it through normal import logic."""
        try:
            request = parse_lumen_deep_link(value)
        except DeepLinkError as exc:
            logging.getLogger(__name__).warning("Rejected lumen deep link: %s", exc)
            self.toast.emit(
                "warning",
                tr("Некорректная ссылка lumen"),
            )
            return False
        if request is None:
            return False
        self.importSubscription(request.url, request.name)
        return True

    @pyqtSlot(str)
    def importSubscriptions(self, text: str) -> None:
        urls: list[str] = []
        for raw in str(text or "").splitlines():
            value = raw.strip()
            if value and value not in urls:
                urls.append(value)
        if not urls:
            self.toast.emit("warning", tr("Введите хотя бы один URL подписки"))
            return
        self._sub_importing = True
        self._sub_import_status = tr("Загрузка подписок...")
        self.subscriptionImportingChanged.emit()
        self.subscriptionImportStatusChanged.emit()
        self._dispatch_sub_jobs(
            [SubscriptionJob(url=url, kind="import") for url in urls],
            "import",
        )

    @pyqtSlot(str)
    def updateSubscription(self, url: str) -> None:
        target = (url or "").strip()
        if not target:
            return
        job = SubscriptionJob(url=target, kind="update")
        self._dispatch_sub_jobs([job], "update")

    @pyqtSlot()
    def updateAllSubscriptions(self) -> None:
        jobs = [
            SubscriptionJob(url=(s.get("url") or "").strip(), kind="update")
            for s in self.controller.state.subscriptions
            if (s.get("url") or "").strip()
        ]
        self._dispatch_sub_jobs(jobs, "update_all")

    @pyqtSlot(str)
    @pyqtSlot(str, bool)
    def removeSubscription(self, url: str, delete_nodes: bool = True) -> None:
        target = (url or "").strip()
        if not target:
            return
        try:
            self.controller.remove_subscription(target, bool(delete_nodes))
        except Exception as exc:  # noqa: BLE001
            self.toast.emit("error", tr("Ошибка удаления подписки: {error}", error=exc))
            return
        self.toast.emit("info", "Подписка удалена")

    @pyqtProperty("QVariantList", notify=subscriptionsChanged)
    def subscriptions(self) -> list:
        try:
            return [dict(item) for item in self.controller.state.subscriptions]
        except Exception:
            return []

    # ── Security / data mirrors ──────────────────────────────────
    @pyqtProperty(int, notify=settingsChanged)
    def autoLockMinutes(self) -> int:
        try:
            return int(self.controller.state.security.auto_lock_minutes)
        except Exception:
            return 15

    @pyqtProperty(bool, notify=settingsChanged)
    def masterPasswordEnabled(self) -> bool:
        try:
            return bool(self.controller.state.security.enabled)
        except Exception:
            return False

    @pyqtProperty(bool, notify=lockedChanged)
    def locked(self) -> bool:
        try:
            return bool(self.controller.locked)
        except Exception:
            return False

    @pyqtSlot(str, result=bool)
    def unlock(self, password: str) -> bool:
        try:
            return bool(self.controller.unlock(password or ""))
        except Exception:
            return False

    @pyqtProperty(bool, notify=settingsChanged)
    def encryptionActive(self) -> bool:
        try:
            return bool(self.controller.is_data_encrypted())
        except Exception:
            return False

    @pyqtProperty(bool, notify=routingChanged)
    def bypassLan(self) -> bool:
        return bool(self.controller.state.routing.bypass_lan)

    @pyqtProperty(str, notify=routingChanged)
    def dnsMode(self) -> str:
        return self.controller.state.routing.dns_mode

    @pyqtProperty(str, notify=routingChanged)
    def dnsBootstrapServer(self) -> str:
        return self.controller.state.routing.dns_bootstrap_server

    @pyqtProperty(str, notify=routingChanged)
    def dnsBootstrapServersText(self) -> str:
        return "\n".join(self.controller.state.routing.dns_bootstrap_servers)

    @pyqtProperty(str, notify=routingChanged)
    def dnsBootstrapType(self) -> str:
        return self.controller.state.routing.dns_bootstrap_type

    @pyqtProperty(str, notify=routingChanged)
    def dnsProxyServer(self) -> str:
        return self.controller.state.routing.dns_proxy_server

    @pyqtProperty(str, notify=routingChanged)
    def dnsProxyServersText(self) -> str:
        return "\n".join(self.controller.state.routing.dns_proxy_servers)

    @pyqtProperty(str, notify=routingChanged)
    def dnsProxyType(self) -> str:
        return self.controller.state.routing.dns_proxy_type

    @pyqtProperty(str, notify=routingChanged)
    def dnsBootstrapStrategy(self) -> str:
        return str(self.controller.state.routing.dns_bootstrap_strategy or "ipv4_only")

    @pyqtProperty(str, notify=routingChanged)
    def dnsProxyStrategy(self) -> str:
        return str(self.controller.state.routing.dns_proxy_strategy or "ipv4_only")

    @pyqtProperty(bool, notify=routingChanged)
    def dnsFakeEnabled(self) -> bool:
        return bool(self.controller.state.routing.dns_fake_enabled)

    @pyqtProperty(bool, notify=routingChanged)
    def dnsHijackEnabled(self) -> bool:
        return bool(self.controller.state.routing.dns_hijack_enabled)

    @pyqtProperty(bool, notify=routingChanged)
    def dnsParallelQuery(self) -> bool:
        return bool(self.controller.state.routing.dns_parallel_query)

    @pyqtProperty(bool, notify=routingChanged)
    def dnsOptimisticCache(self) -> bool:
        return bool(self.controller.state.routing.dns_optimistic_cache)

    @pyqtProperty(bool, notify=routingChanged)
    def dnsGeoCheck(self) -> bool:
        return bool(self.controller.state.routing.dns_geo_check)

    @pyqtProperty(str, notify=routingChanged)
    def dnsHostsText(self) -> str:
        lines = []
        for domain, addresses in self.controller.state.routing.dns_hosts.items():
            lines.append(f"{domain}={','.join(addresses)}")
        return "\n".join(lines)

    @pyqtProperty(str, notify=routingChanged)
    def tunRouteExcludeAddress(self) -> str:
        return "\n".join(self.controller.state.routing.tun_route_exclude_address)

    @pyqtProperty('QVariantList', notify=routingChanged)
    def processRules(self):
        return [dict(x) for x in self.controller.state.routing.process_rules]

    @pyqtProperty('QVariantList', notify=routingChanged)
    def domainRules(self):
        routing = self.controller.state.routing
        out: list[dict[str, str]] = []
        for addr in routing.direct_domains:
            if not self._is_internal_domain_rule(addr):
                out.append({"addr": addr, "action": "direct"})
        for addr in routing.proxy_domains:
            if not self._is_internal_domain_rule(addr):
                out.append({"addr": addr, "action": "proxy"})
        for addr in routing.block_domains:
            if not self._is_internal_domain_rule(addr):
                out.append({"addr": addr, "action": "block"})
        return out

    @staticmethod
    def _is_internal_domain_rule(addr: str) -> bool:
        from ...routing_presets import is_internal_preset_rule

        return is_internal_preset_rule(addr)

    @pyqtProperty('QVariantList', notify=routingChanged)
    def serviceList(self):
        from ...routing_runtime import effective_service_action
        from ...service_presets import SERVICE_PRESETS
        routing = self.controller.state.routing
        return [
            {
                "id": s.id,
                "name": s.name,
                "description": s.description,
                "defaultAction": s.default_action,
                # defaultAction is catalog metadata.  The selected value must
                # instead reflect the active preset's effective fallback.
                "action": effective_service_action(routing, s.id),
            }
            for s in SERVICE_PRESETS
        ]

    @pyqtProperty('QVariantList', notify=routingChanged)
    def processPresetList(self):
        from ...process_presets import PROCESS_PRESETS
        routes = self.controller.state.routing.process_preset_routes
        return [
            {
                "id": p.id,
                "name": p.name,
                "description": p.description,
                "defaultAction": p.default_action,
                "action": routes.get(p.id, "off"),
            }
            for p in PROCESS_PRESETS
        ]

    # ── Routing detail: commands ─────────────────────────────────
    @pyqtProperty('QVariantList', notify=routingChanged)
    def customRoutingPresets(self):
        return [
            {"id": p.get("id", ""), "name": p.get("name", "")}
            for p in self.controller.state.routing_presets
        ]

    @pyqtProperty('QVariantList', notify=routingChanged)
    def routingPresetOptions(self):
        items = list(self.regionalRoutingPresets)
        items.extend(
            {"id": p.get("id", ""), "name": p.get("name", "")}
            for p in self.controller.state.routing_presets
            if p.get("id")
        )
        return items

    @pyqtProperty('QVariantList', notify=routingChanged)
    def regionalRoutingPresets(self):
        from ...routing_presets import regional_routing_preset_ids
        labels = {
            "global": tr("Всё через VPN"),
            "blocked": tr("Только заблокированное"),
            "blocked_cn": tr("Только заблокированное"),
            "except_ru": tr("Всё кроме РФ"),
            "except_cn": tr("Всё кроме Китая"),
            "except_ir": tr("Всё кроме Ирана"),
        }
        return [
            {"id": preset_id, "name": labels[preset_id]}
            for preset_id in regional_routing_preset_ids(self.regionalPreset)
        ]

    def _mutate_routing(self, fn) -> None:
        routing = deepcopy(self.controller.state.routing)
        fn(routing)
        self.controller.update_routing(routing)

    @pyqtSlot(bool)
    def setBypassLan(self, enabled: bool) -> None:
        def apply(r: RoutingSettings) -> None:
            r.bypass_lan = bool(enabled)
        self._mutate_routing(apply)

    @pyqtSlot(str)
    def setDnsMode(self, mode: str) -> None:
        def apply(r: RoutingSettings) -> None:
            r.dns_mode = mode or "system"
        self._mutate_routing(apply)

    @pyqtSlot(str, str)
    def setBootstrapDns(self, server: str, dns_type: str) -> None:
        def apply(r: RoutingSettings) -> None:
            if server:
                r.dns_bootstrap_server = server.strip()
                r.dns_bootstrap_servers = [r.dns_bootstrap_server, *r.dns_bootstrap_servers[1:]]
            if dns_type:
                r.dns_bootstrap_type = dns_type
        self._mutate_routing(apply)

    @pyqtSlot(str, str)
    def setProxyDns(self, server: str, dns_type: str) -> None:
        def apply(r: RoutingSettings) -> None:
            if server:
                r.dns_proxy_server = server.strip()
                r.dns_proxy_servers = [r.dns_proxy_server, *r.dns_proxy_servers[1:]]
            if dns_type:
                r.dns_proxy_type = dns_type
        self._mutate_routing(apply)

    @pyqtSlot(str)
    def setDnsBootstrapStrategy(self, value: str) -> None:
        def apply(r: RoutingSettings) -> None:
            r.dns_bootstrap_strategy = str(value or "ipv4_only")
        self._mutate_routing(apply)

    @pyqtSlot(str)
    def setDnsProxyStrategy(self, value: str) -> None:
        def apply(r: RoutingSettings) -> None:
            r.dns_proxy_strategy = str(value or "ipv4_only")
        self._mutate_routing(apply)

    @pyqtSlot(bool)
    def setDnsFakeEnabled(self, enabled: bool) -> None:
        def apply(r: RoutingSettings) -> None:
            r.dns_fake_enabled = bool(enabled)
        self._mutate_routing(apply)

    @pyqtSlot(bool)
    def setDnsHijackEnabled(self, enabled: bool) -> None:
        def apply(r: RoutingSettings) -> None:
            r.dns_hijack_enabled = bool(enabled)
        self._mutate_routing(apply)

    @pyqtSlot(str)
    def setTunRouteExcludeAddress(self, text: str) -> None:
        def apply(r: RoutingSettings) -> None:
            items: list[str] = []
            for chunk in str(text or "").replace(",", "\n").replace(";", "\n").splitlines():
                value = chunk.strip()
                if value:
                    items.append(value)
            r.tun_route_exclude_address = items
        self._mutate_routing(apply)

    @pyqtSlot(str, str)
    def setServiceRoute(self, service_id: str, action: str) -> None:
        def apply(r: RoutingSettings) -> None:
            routes = dict(r.service_routes)
            if not action or action == "off":
                routes.pop(service_id, None)
            elif action in ("proxy", "direct"):
                routes[service_id] = action
            else:
                routes.pop(service_id, None)
            r.service_routes = routes
        self._mutate_routing(apply)

    @pyqtSlot(str, str)
    def setProcessPresetRoute(self, preset_id: str, action: str) -> None:
        def apply(r: RoutingSettings) -> None:
            routes = dict(r.process_preset_routes)
            if not action or action == "off":
                routes.pop(preset_id, None)
            else:
                routes[preset_id] = action
            r.process_preset_routes = routes
        self._mutate_routing(apply)

    @pyqtSlot(str, str)
    def addProcessRule(self, process: str, action: str) -> None:
        process = (process or "").strip()
        if not process:
            return
        def apply(r: RoutingSettings) -> None:
            rules = [dict(x) for x in r.process_rules if x.get("process") != process]
            rules.append({"process": process, "action": action or "proxy"})
            r.process_rules = rules
        self._mutate_routing(apply)

    @pyqtSlot(str)
    def removeProcessRule(self, process: str) -> None:
        def apply(r: RoutingSettings) -> None:
            r.process_rules = [dict(x) for x in r.process_rules if x.get("process") != process]
        self._mutate_routing(apply)

    @pyqtSlot(result="QVariantList")
    def runningProcesses(self):
        """Список имён exe запущенных процессов для выбора в маршрутизации."""
        try:
            from ...win_process_list import list_running_executables
            return list_running_executables()
        except Exception:
            return []

    @pyqtSlot(str, str)
    def addDomainRule(self, addr: str, action: str) -> None:
        addr = (addr or "").strip()
        if not addr:
            return
        if self._is_internal_domain_rule(addr):
            self.toast.emit("warning", tr("Добавляйте конкретный домен, IP или CIDR"))
            return
        def apply(r: RoutingSettings) -> None:
            r.direct_domains = [d for d in r.direct_domains if d != addr]
            r.proxy_domains = [d for d in r.proxy_domains if d != addr]
            r.block_domains = [d for d in r.block_domains if d != addr]
            if action == "direct":
                r.direct_domains = list(r.direct_domains) + [addr]
            elif action == "block":
                r.block_domains = list(r.block_domains) + [addr]
            else:
                r.proxy_domains = list(r.proxy_domains) + [addr]
        self._mutate_routing(apply)

    @pyqtSlot(str)
    def removeDomainRule(self, addr: str) -> None:
        def apply(r: RoutingSettings) -> None:
            r.direct_domains = [d for d in r.direct_domains if d != addr]
            r.proxy_domains = [d for d in r.proxy_domains if d != addr]
            r.block_domains = [d for d in r.block_domains if d != addr]
        self._mutate_routing(apply)

    @pyqtSlot(str)
    def importDomainRules(self, text: str) -> None:
        try:
            accepted_lines = parse_routing_rules(text)
        except ValueError as exc:
            self.toast.emit("error", str(exc))
            return
        if not accepted_lines:
            self.toast.emit("warning", "Нет строк для импорта")
            return
        accepted_lines = [
            (addr, action)
            for addr, action in accepted_lines
            if not self._is_internal_domain_rule(addr)
        ]
        if not accepted_lines:
            self.toast.emit("warning", tr("Добавляйте конкретный домен, IP или CIDR"))
            return
        imported_count = len(accepted_lines)

        def apply(r: RoutingSettings) -> None:
            direct = list(r.direct_domains)
            proxy = list(r.proxy_domains)
            block = list(r.block_domains)
            for addr, act in accepted_lines:
                for lst in (direct, proxy, block):
                    if addr in lst:
                        lst.remove(addr)
                if act == "direct":
                    direct.append(addr)
                elif act == "block":
                    block.append(addr)
                else:
                    proxy.append(addr)
            r.direct_domains = direct
            r.proxy_domains = proxy
            r.block_domains = block
        self._mutate_routing(apply)
        self.toast.emit("success", tr("Импортировано правил: {count}", count=imported_count))

    @staticmethod
    def _dns_server_lines(text: str, fallback: str = "") -> list[str]:
        values: list[str] = []
        for raw in str(text or "").replace(";", "\n").splitlines():
            value = raw.strip()
            if value and value not in values:
                values.append(value)
        return values or ([fallback] if fallback else [])

    @pyqtSlot(str)
    def setDnsBootstrapServers(self, text: str) -> None:
        def apply(r: RoutingSettings) -> None:
            r.dns_bootstrap_servers = self._dns_server_lines(text)
            r.dns_bootstrap_server = r.dns_bootstrap_servers[0] if r.dns_bootstrap_servers else ""
        self._mutate_routing(apply)

    @pyqtSlot(str)
    def setDnsProxyServers(self, text: str) -> None:
        def apply(r: RoutingSettings) -> None:
            r.dns_proxy_servers = self._dns_server_lines(text, "cloudflare-dns.com")
            r.dns_proxy_server = r.dns_proxy_servers[0]
        self._mutate_routing(apply)

    @pyqtSlot(bool)
    def setDnsParallelQuery(self, enabled: bool) -> None:
        self._mutate_routing(lambda r: setattr(r, "dns_parallel_query", bool(enabled)))

    @pyqtSlot(bool)
    def setDnsOptimisticCache(self, enabled: bool) -> None:
        self._mutate_routing(lambda r: setattr(r, "dns_optimistic_cache", bool(enabled)))

    @pyqtSlot(bool)
    def setDnsGeoCheck(self, enabled: bool) -> None:
        self._mutate_routing(lambda r: setattr(r, "dns_geo_check", bool(enabled)))

    @staticmethod
    def _parse_dns_hosts_text(text: str) -> dict[str, list[str]]:
        hosts: dict[str, list[str]] = {}
        for line_number, raw in enumerate(str(text or "").splitlines(), start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                raise ValueError(tr("Hosts, строка {line}: ожидается domain=address", line=line_number))
            domain, raw_addresses = line.split("=", 1)
            domain = domain.strip().lower().rstrip(".")
            addresses = [
                value.strip()
                for value in raw_addresses.replace(";", ",").split(",")
                if value.strip()
            ]
            if not domain or not addresses:
                raise ValueError(tr("Hosts, строка {line}: пустой домен или адрес", line=line_number))
            hosts[domain] = addresses
        return hosts

    @pyqtSlot(str, result=bool)
    def setDnsHosts(self, text: str) -> bool:
        try:
            hosts = self._parse_dns_hosts_text(text)
        except ValueError as exc:
            self.toast.emit("warning", str(exc))
            return False
        self._mutate_routing(lambda r: setattr(r, "dns_hosts", hosts))
        return True

    @pyqtSlot(str, str, str, result=bool)
    def applyDnsSettings(self, bootstrap_text: str, proxy_text: str, hosts_text: str) -> bool:
        try:
            hosts = self._parse_dns_hosts_text(hosts_text)
        except ValueError as exc:
            self.toast.emit("warning", str(exc))
            return False

        def apply(r: RoutingSettings) -> None:
            r.dns_bootstrap_servers = self._dns_server_lines(bootstrap_text)
            r.dns_bootstrap_server = r.dns_bootstrap_servers[0] if r.dns_bootstrap_servers else ""
            r.dns_proxy_servers = self._dns_server_lines(proxy_text, "cloudflare-dns.com")
            r.dns_proxy_server = r.dns_proxy_servers[0]
            r.dns_hosts = hosts

        self._mutate_routing(apply)
        self.toast.emit("success", tr("Настройки DNS применены"))
        return True

    @pyqtSlot()
    def importDomainRulesFile(self) -> None:
        from PyQt6.QtWidgets import QFileDialog

        file_path, _ = QFileDialog.getOpenFileName(
            None,
            tr("Импорт правил маршрутизации"),
            "",
            tr("Правила (*.txt *.json *.yaml *.yml);;Все файлы (*)"),
        )
        if not file_path:
            return
        path = Path(file_path)
        try:
            payload = path.read_text(encoding="utf-8-sig")
            accepted_lines = parse_routing_rules(payload, suffix=path.suffix)
        except (OSError, UnicodeError, ValueError) as exc:
            self.toast.emit("error", tr("Не удалось импортировать правила: {error}", error=exc))
            return
        if not accepted_lines:
            self.toast.emit("warning", tr("Файл не содержит поддерживаемых правил"))
            return
        self.importDomainRules("\n".join(f"{address}|{action}" for address, action in accepted_lines))

    @pyqtSlot(result=str)
    def exportDomainRules(self) -> str:
        routing = self.controller.state.routing
        lines: list[str] = []
        for addr in routing.direct_domains:
            if not self._is_internal_domain_rule(addr):
                lines.append(f"{addr}|direct")
        for addr in routing.proxy_domains:
            if not self._is_internal_domain_rule(addr):
                lines.append(f"{addr}|proxy")
        for addr in routing.block_domains:
            if not self._is_internal_domain_rule(addr):
                lines.append(f"{addr}|block")
        payload = "\n".join(lines)
        if not payload:
            self.toast.emit("warning", "Нет правил для экспорта")
            return ""
        clipboard = QGuiApplication.clipboard()
        if clipboard is not None:
            clipboard.setText(payload)
            self.toast.emit("success", "Правила скопированы в буфер обмена")
        return payload
