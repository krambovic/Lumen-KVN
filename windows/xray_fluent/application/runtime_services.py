from __future__ import annotations

from typing import TYPE_CHECKING

from PyQt6.QtCore import QMetaObject, QThread, Qt

from ..constants import SINGBOX_CLASH_API_PORT
from ..live_metrics_worker import LiveMetricsWorker
from ..qthread_utils import stop_and_wait_for_thread
from ..subprocess_utils import is_windows_shutting_down

if TYPE_CHECKING:
    from ..app_controller import AppController


def _call_in_qobject_thread(obj: object, method_name: str) -> None:
    thread = getattr(obj, "thread", lambda: None)()
    if thread is None or thread == QThread.currentThread():
        getattr(obj, method_name)()
        return
    QMetaObject.invokeMethod(
        obj,
        method_name,
        Qt.ConnectionType.QueuedConnection,
    )


def start_metrics_worker(controller: AppController) -> None:
    session = controller._active_session
    node = controller.selected_node
    ping_host = session.ping_host if session is not None else (node.server if node else "")
    ping_port = session.ping_port if session is not None else (node.port if node else 0)
    controller._log(f"[metrics] starting worker, active_core={controller._active_core}")

    stop_metrics_worker(controller)
    if controller._active_core == "singbox":
        mode = "singbox"
    else:
        mode = "xray"
    socks_port, http_port = controller.get_effective_proxy_ports()
    inbound_tags = controller._active_session.xray_inbound_tags if controller._active_session else ()
    clash_api_secret = controller._active_session.clash_api_secret if controller._active_session else ""
    controller._metrics_worker = LiveMetricsWorker(
        controller.state.settings.xray_path,
        controller._xray_api_port,
        ping_host=ping_host,
        ping_port=ping_port,
        mode=mode,
        clash_api_port=SINGBOX_CLASH_API_PORT,
        clash_api_secret=clash_api_secret,
        socks_port=socks_port,
        http_port=http_port,
        xray_inbound_tags=list(inbound_tags),
    )
    controller._metrics_worker.metrics.connect(controller._on_live_metrics)
    controller._metrics_worker.start()


def stop_metrics_worker(controller: AppController) -> None:
    worker = controller._metrics_worker
    if not worker:
        return
    controller._metrics_worker = None

    try:
        worker.metrics.disconnect(controller._on_live_metrics)
    except (TypeError, RuntimeError):
        pass

    if not worker.isRunning():
        worker.deleteLater()
        return

    worker.stop()
    retired = controller._retired_metrics_workers
    from ..qthread_utils import retain_thread_until_finished
    retain_thread_until_finished(controller, retired, worker)


def cleanup_connection_runtime_state(
    controller: AppController,
    *,
    end_traffic_session: bool,
    reset_auto_switch_cycle: bool,
    reset_auto_switch_cooldown: bool,
) -> None:
    controller._xray_api_port = 0
    controller._protect_ss_port = 0
    controller._protect_ss_password = ""
    controller._traffic_save_counter = 0
    controller._reset_auto_switch_state(
        reset_cooldown=reset_auto_switch_cooldown,
        reset_cycle=reset_auto_switch_cycle,
    )
    if end_traffic_session:
        controller._traffic_history.end_session()
    from ..process_traffic_collector import reset_connection_tracking
    from ..win_proc_monitor import clear_pid_cache
    reset_connection_tracking()
    clear_pid_cache()


def stop_active_connection_processes(controller: AppController, *, disable_proxy: bool, fast: bool = False) -> bool:
    stopped = True

    if controller._active_core == "singbox":
        if controller.singbox.is_running:
            stopped = controller.singbox.stop(fast=fast) and stopped
        if controller.xray.is_running:
            stopped = controller.xray.stop(fast=fast) and stopped
    else:
        if controller.xray.is_running:
            stopped = controller.xray.stop(fast=fast) and stopped
        if controller.singbox.is_running:
            stopped = controller.singbox.stop(fast=fast) and stopped

    if disable_proxy and controller.state.settings.enable_system_proxy:
        controller.proxy.disable(restore_previous=True)

    return stopped


def handle_unexpected_disconnect(controller: AppController) -> None:
    if (
        controller._cleaning_connection_state
        or getattr(controller, "_shutting_down", False)
        or getattr(controller, "_system_shutdown", False)
    ):
        return
    controller._cleaning_connection_state = True
    # Kill-switch: незапланированный обрыв при желании быть на связи → fail-closed (не сбрасываем прокси).
    kill_switch_active = (
        controller.state.settings.kill_switch
        and controller._desired_connected
        and not controller._reconnecting
        and not controller._auto_switch_transitioning
    )
    controller._kill_switch_engaged = kill_switch_active
    try:
        cleanup_connection_runtime_state(
            controller,
            end_traffic_session=True,
            reset_auto_switch_cycle=not controller._auto_switch_transitioning,
            reset_auto_switch_cooldown=True,
        )
        stop_active_connection_processes(controller, disable_proxy=not controller._reconnecting and not kill_switch_active)
        controller._active_core = "xray"
        controller._clear_active_session()
        if not controller._reconnecting:
            controller._desired_connected = False
        if kill_switch_active:
            controller.status.emit("error", "Kill-switch: соединение разорвано — трафик заблокирован (прокси не сброшен). Переподключитесь.")
            controller._log("[kill-switch] unexpected disconnect — system proxy kept enabled (fail-closed)")
    finally:
        controller._auto_switch_transitioning = False
        controller._cleaning_connection_state = False


def on_core_state_changed(controller: AppController, _running: bool) -> None:
    was_connected, is_connected = controller._refresh_connected_state()
    if not controller._switching and was_connected != is_connected:
        controller.connection_changed.emit(is_connected)
    if is_connected and not controller._switching and not was_connected:
        start_metrics_worker(controller)
    elif not is_connected:
        stop_metrics_worker(controller)
        if was_connected and not controller._switching:
            controller.live_metrics_updated.emit({"down_bps": 0.0, "up_bps": 0.0, "latency_ms": None})
            if (
                not controller._disconnecting
                and not getattr(controller, "_shutting_down", False)
                and not getattr(controller, "_system_shutdown", False)
            ):
                handle_unexpected_disconnect(controller)
    if (
        not is_connected
        and controller._active_core == "xray"
        and controller.state.settings.enable_system_proxy
        and not controller._reconnecting
        and not controller._kill_switch_engaged
    ):
        controller.proxy.disable(restore_previous=True)


def on_live_metrics(controller: AppController, payload: dict[str, object]) -> None:
    controller.live_metrics_updated.emit(payload)
    down_bps = float(payload.get("down_bps") or 0.0)
    latency_raw = payload.get("latency_ms")
    latency_ms = int(latency_raw) if isinstance(latency_raw, (int, float)) else None
    controller._check_auto_switch(down_bps, latency_ms)
    process_stats = payload.get("process_stats")
    if process_stats:
        stats_dict = {}
        for ps in process_stats:
            stats_dict[ps.exe] = (ps.upload, ps.download, ps.route)
        controller._traffic_history.update_session(stats_dict)
        controller._traffic_save_counter += 1
        if controller._traffic_save_counter >= 15:
            # Serialising a year of history must not run on the GUI thread. The
            # write is atomic and TrafficHistoryStorage is lock-guarded, so it is
            # safe on the same single-threaded executor used for state saves.
            if getattr(controller, "_save_executor_shutdown", True):
                controller._traffic_history.save_periodic()
            else:
                controller._save_executor.submit(controller._traffic_history.save_periodic)
            controller._traffic_save_counter = 0


def shutdown(controller: AppController) -> None:
    logger = controller._logger

    def _join(worker, label: str, *, cancel: bool = False, quit_thread: bool = False) -> None:
        stop = None
        if cancel and worker is not None and hasattr(worker, "cancel"):
            stop = worker.cancel
        elif quit_thread and worker is not None:
            stop = worker.quit
        stop_and_wait_for_thread(worker, stop=stop, label=label, logger=logger)

    _join(controller._country_resolver, "country resolver", cancel=True)
    _join(controller._ping_worker, "ping worker", cancel=True)
    _join(controller._connectivity_worker, "connectivity worker", cancel=True)
    stop_metrics_worker(controller)
    for retired_worker in list(controller._retired_metrics_workers):
        _join(retired_worker, "retired metrics worker", cancel=True)
    controller._retired_metrics_workers.clear()
    for retired_worker in list(controller._retired_workers):
        _join(retired_worker, "retired worker", cancel=True)
    controller._retired_workers.clear()
    _join(controller._speed_worker, "speed worker", cancel=True)
    _join(controller._xray_update_worker, "Xray updater", cancel=True)
    for worker in list(controller._resource_update_workers):
        _join(worker, f"{getattr(worker, '_kind', 'resource')} updater", cancel=True)

    controller.disconnect_current(fast=True)
    if controller.singbox.is_running:
        controller.singbox.stop(fast=True)
    if controller.xray.is_running:
        controller.xray.stop(fast=True)
    if controller.zapret.running:
        controller.zapret.stop(fast=True)
    if controller.proxy.is_enabled():
        controller.proxy.disable(restore_previous=True)
    if not getattr(controller, "_system_shutdown", False) and not is_windows_shutting_down():
        controller._cleanup_tun_adapter(max_wait=1.0)
    _call_in_qobject_thread(controller.network_monitor, "stop")
    _call_in_qobject_thread(controller._lock_timer, "stop")
    controller.save()
