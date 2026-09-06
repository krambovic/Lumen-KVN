from __future__ import annotations

import ctypes
from pathlib import Path
from types import SimpleNamespace

from PyQt6.QtCore import QCoreApplication

from xray_fluent.app_controller import AppController
import xray_fluent.power_reconnect as power_reconnect
from xray_fluent.power_reconnect import (
    WM_ENDSESSION,
    WM_POWERBROADCAST,
    WM_QUERYENDSESSION,
    PBT_APMRESUMEAUTOMATIC,
    PBT_APMRESUMESUSPEND,
    PBT_APMSUSPEND,
    WindowsPowerEventFilter,
    power_broadcast_event,
    should_arm_resume_reconnect,
)
from xray_fluent.storage import StateStorage


def _controller(
    *,
    connected: bool,
    desired_connected: bool = True,
    enabled: bool = True,
    resume_enabled: bool = True,
):
    return SimpleNamespace(
        connected=connected,
        _desired_connected=desired_connected,
        _shutting_down=False,
        locked=False,
        state=SimpleNamespace(
            settings=SimpleNamespace(
                reconnect_on_network_change=enabled,
                reconnect_after_sleep=resume_enabled,
            ),
        ),
    )


def test_power_broadcast_events_distinguish_suspend_and_resume() -> None:
    assert power_broadcast_event(PBT_APMSUSPEND) == "suspend"
    assert power_broadcast_event(PBT_APMRESUMESUSPEND) == "resume"
    assert power_broadcast_event(PBT_APMRESUMEAUTOMATIC) == "resume"
    assert power_broadcast_event(0xFFFF) is None


def test_resume_reconnect_arms_only_for_an_intentionally_connected_session() -> None:
    assert should_arm_resume_reconnect(_controller(connected=True)) is True
    assert should_arm_resume_reconnect(_controller(connected=False, desired_connected=False)) is False
    assert should_arm_resume_reconnect(_controller(connected=True, desired_connected=False)) is False
    assert should_arm_resume_reconnect(_controller(connected=True, enabled=False)) is True
    assert should_arm_resume_reconnect(_controller(connected=True, resume_enabled=False)) is False


def test_resume_setting_is_independent_from_network_change_reconnect() -> None:
    controller = _controller(connected=True)
    controller.state.settings.reconnect_after_sleep = False

    assert should_arm_resume_reconnect(controller) is False


def test_resume_setting_is_persisted_and_defaults_to_enabled() -> None:
    from xray_fluent.models import AppSettings

    assert AppSettings().reconnect_after_sleep is True
    settings = AppSettings.from_dict({"reconnect_after_sleep": False})
    assert settings.reconnect_after_sleep is False
    assert settings.to_dict()["reconnect_after_sleep"] is False


def test_bridge_updates_resume_setting(tmp_path: Path) -> None:
    QCoreApplication.instance() or QCoreApplication([])
    from xray_fluent.qml_app.bridge import AppBridge

    bridge = AppBridge()
    bridge.controller.storage = StateStorage(tmp_path / "state.json")
    try:
        bridge.setReconnectAfterSleep(False)
        assert bridge.reconnectAfterSleep is False
        assert bridge.controller.state.settings.reconnect_after_sleep is False
    finally:
        bridge.controller._transition_timer.stop()
        bridge.controller._save_timer.stop()
        bridge.controller._startup_sync_timer.stop()
        bridge.controller._lock_timer.stop()
        bridge.controller._save_executor_shutdown = True
        bridge.controller._save_executor.shutdown(wait=True, cancel_futures=False)


def test_resume_reconnect_does_not_arm_when_app_is_locked_or_shutting_down() -> None:
    controller = _controller(connected=True)
    controller.locked = True
    assert should_arm_resume_reconnect(controller) is False

    controller.locked = False
    controller._shutting_down = True
    assert should_arm_resume_reconnect(controller) is False


def test_controller_forces_reconnect_even_when_core_process_still_looks_alive() -> None:
    QCoreApplication.instance() or QCoreApplication([])
    controller = AppController()
    try:
        controller.connected = True
        controller._desired_connected = True
        controller._active_session = object()

        assert controller.request_resume_reconnect() is True
        assert controller._resume_reconnect_pending is True
        assert controller._compute_transition_action() == "reconnect"
    finally:
        controller._transition_timer.stop()
        controller._save_timer.stop()
        controller._startup_sync_timer.stop()
        controller._lock_timer.stop()
        controller._save_executor_shutdown = True
        controller._save_executor.shutdown(wait=True, cancel_futures=False)


def test_manual_disconnect_cancels_resume_before_worker_starts() -> None:
    QCoreApplication.instance() or QCoreApplication([])
    controller = AppController()
    completed: list[tuple[bool, str, str, int]] = []
    controller._transition_completed.connect(lambda *args: completed.append(args))
    try:
        controller.connected = True
        controller._desired_connected = True
        controller._active_session = object()
        assert controller.request_resume_reconnect() is True

        controller.toggle_connection()
        assert controller._desired_connected is False
        assert controller._resume_reconnect_pending is False

        controller._transition_active = True
        controller._execute_transition_action(
            "reconnect",
            "system resume",
            controller._transition_generation,
        )
        assert completed == [
            (True, "reconnect", "system resume", controller._transition_generation)
        ]
    finally:
        controller._transition_timer.stop()
        controller._save_timer.stop()
        controller._startup_sync_timer.stop()
        controller._lock_timer.stop()
        controller._save_executor_shutdown = True
        controller._save_executor.shutdown(wait=True, cancel_futures=False)


def test_resume_filter_uses_one_request_and_stops_after_restore() -> None:
    app = QCoreApplication.instance() or QCoreApplication([])
    requests: list[str] = []
    controller = _controller(connected=True)
    controller.request_resume_reconnect = lambda reason: requests.append(reason) or True
    controller._log = lambda _message: None
    event_filter = WindowsPowerEventFilter(controller, app)
    try:
        event_filter._armed = True
        event_filter._on_timer()

        assert requests == ["system resume"]
        assert event_filter._attempts == 1

        event_filter._timer.stop()
        event_filter._on_timer()
        assert requests == ["system resume"]
        assert event_filter._armed is False
    finally:
        event_filter.close()


def test_resume_filter_ignores_resume_without_a_matching_suspend(monkeypatch) -> None:
    app = QCoreApplication.instance() or QCoreApplication([])
    requests: list[str] = []
    controller = _controller(connected=True)
    controller.request_resume_reconnect = lambda reason: requests.append(reason) or True
    controller._log = lambda _message: None
    event_filter = WindowsPowerEventFilter(controller, app)
    resume_message = power_reconnect._Message()
    try:
        monkeypatch.setattr(power_reconnect.sys, "platform", "win32")
        resume_message.message = WM_POWERBROADCAST
        resume_message.wParam = PBT_APMRESUMESUSPEND
        event_filter.nativeEventFilter(
            b"windows_generic_MSG", ctypes.addressof(resume_message)
        )

        assert requests == []
        assert event_filter._armed is False
        assert event_filter._timer.isActive() is False
    finally:
        event_filter.close()


def test_native_filter_ignores_non_power_messages_with_power_like_wparam(monkeypatch) -> None:
    app = QCoreApplication.instance() or QCoreApplication([])
    controller = _controller(connected=True)
    controller._log = lambda _message: None
    event_filter = WindowsPowerEventFilter(controller, app)
    message = power_reconnect._Message()
    try:
        monkeypatch.setattr(power_reconnect.sys, "platform", "win32")
        message.message = 0x0201  # WM_LBUTTONDOWN
        message.wParam = PBT_APMRESUMEAUTOMATIC
        event_filter.nativeEventFilter(
            b"windows_generic_MSG", ctypes.addressof(message)
        )

        assert event_filter._armed is False
        assert event_filter._timer.isActive() is False
    finally:
        event_filter.close()


def test_resume_filter_does_not_reset_an_inflight_recovery(monkeypatch) -> None:
    app = QCoreApplication.instance() or QCoreApplication([])
    controller = _controller(connected=True)
    controller._log = lambda _message: None
    event_filter = WindowsPowerEventFilter(controller, app)
    resume_message = power_reconnect._Message()
    try:
        monkeypatch.setattr(power_reconnect.sys, "platform", "win32")
        event_filter._armed = True
        event_filter._attempts = 1
        event_filter._schedule(30_000)
        resume_message.message = WM_POWERBROADCAST
        resume_message.wParam = PBT_APMRESUMEAUTOMATIC
        event_filter.nativeEventFilter(
            b"windows_generic_MSG", ctypes.addressof(resume_message)
        )

        assert event_filter._attempts == 1
        assert event_filter._timer.isActive() is True
    finally:
        event_filter.close()


def test_resume_filter_waits_for_an_existing_transition_before_requesting() -> None:
    app = QCoreApplication.instance() or QCoreApplication([])
    requests: list[str] = []
    controller = _controller(connected=True)
    controller._transition_active = True
    controller.request_resume_reconnect = lambda reason: requests.append(reason) or True
    controller._log = lambda _message: None
    event_filter = WindowsPowerEventFilter(controller, app)
    try:
        event_filter._armed = True
        event_filter._on_timer()

        assert requests == []
        assert event_filter._attempts == 0
        assert event_filter._timer.isActive() is True
    finally:
        event_filter.close()


def test_native_shutdown_message_marks_controller_before_core_exit(monkeypatch) -> None:
    app = QCoreApplication.instance() or QCoreApplication([])
    controller = _controller(connected=True)
    controller._system_shutdown = False
    stopped: list[tuple[bool, bool]] = []
    controller._stop_active_connection_processes = lambda **kwargs: stopped.append(
        (kwargs["disable_proxy"], kwargs["fast"])
    ) or True
    controller._log = lambda _message: None
    event_filter = WindowsPowerEventFilter(controller, app)
    shutdown_message = power_reconnect._Message()
    try:
        monkeypatch.setattr(power_reconnect.sys, "platform", "win32")
        shutdown_message.message = WM_QUERYENDSESSION
        shutdown_message.wParam = 0
        event_filter.nativeEventFilter(
            b"windows_generic_MSG", ctypes.addressof(shutdown_message)
        )
        assert controller._system_shutdown is True
        assert stopped == []
        assert event_filter._armed is False
        assert event_filter._timer.isActive() is False

        controller._system_shutdown = False
        shutdown_message.message = WM_ENDSESSION
        shutdown_message.wParam = 1
        event_filter.nativeEventFilter(
            b"windows_generic_MSG", ctypes.addressof(shutdown_message)
        )
        assert controller._system_shutdown is True
        assert stopped == [(True, True)]
    finally:
        event_filter.close()


def test_native_shutdown_cancel_restores_normal_controller_state(monkeypatch) -> None:
    app = QCoreApplication.instance() or QCoreApplication([])
    controller = _controller(connected=True)
    controller._system_shutdown = False
    controller._log = lambda _message: None
    event_filter = WindowsPowerEventFilter(controller, app)
    message = power_reconnect._Message()
    try:
        monkeypatch.setattr(power_reconnect.sys, "platform", "win32")
        message.message = WM_QUERYENDSESSION
        event_filter.nativeEventFilter(
            b"windows_generic_MSG", ctypes.addressof(message)
        )
        assert controller._system_shutdown is True

        message.message = WM_ENDSESSION
        message.wParam = 0
        event_filter.nativeEventFilter(
            b"windows_generic_MSG", ctypes.addressof(message)
        )
        assert controller._system_shutdown is False
        assert controller._desired_connected is True
    finally:
        event_filter.close()


def test_native_power_callback_arms_and_schedules_resume(monkeypatch) -> None:
    app = QCoreApplication.instance() or QCoreApplication([])
    controller = _controller(connected=True)
    controller._log = lambda _message: None
    event_filter = WindowsPowerEventFilter(controller, app)
    suspend_message = power_reconnect._Message()
    resume_message = power_reconnect._Message()
    try:
        monkeypatch.setattr(power_reconnect.sys, "platform", "win32")
        suspend_message.message = WM_POWERBROADCAST
        resume_message.message = WM_POWERBROADCAST
        suspend_message.wParam = PBT_APMSUSPEND
        assert event_filter.nativeEventFilter(
            b"windows_generic_MSG", ctypes.addressof(suspend_message)
        ) == (False, 0)
        assert event_filter._armed is True

        resume_message.wParam = PBT_APMRESUMESUSPEND
        assert event_filter.nativeEventFilter(
            b"windows_generic_MSG", ctypes.addressof(resume_message)
        ) == (False, 0)
        assert event_filter._timer.isActive() is True
    finally:
        event_filter.close()


def test_qml_launcher_installs_and_removes_the_windows_power_filter() -> None:
    launcher = (
        Path(__file__).parents[1]
        / "xray_fluent"
        / "qml_app"
        / "main_qml.py"
    ).read_text(encoding="utf-8")

    assert "WindowsPowerEventFilter(bridge.controller, app)" in launcher
    assert "app.installNativeEventFilter(power_event_filter)" in launcher
    assert "app.removeNativeEventFilter(power_event_filter)" in launcher


def test_settings_page_exposes_resume_reconnect_toggle() -> None:
    settings_page = (
        Path(__file__).parents[1]
        / "xray_fluent"
        / "qml_app"
        / "qml"
        / "SettingsPage.qml"
    ).read_text(encoding="utf-8")
    bridge = (
        Path(__file__).parents[1]
        / "xray_fluent"
        / "qml_app"
        / "bridge"
        / "app_bridge.py"
    ).read_text(encoding="utf-8")

    assert "App.reconnectAfterSleep" in settings_page
    assert "App.setReconnectAfterSleep(checked)" in settings_page
    assert "def setReconnectAfterSleep" in bridge
