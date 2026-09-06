from __future__ import annotations

from types import SimpleNamespace

from PyQt6.QtCore import QCoreApplication

from xray_fluent.app_controller import AppController
from xray_fluent.application import runtime_services


def _controller() -> AppController:
    QCoreApplication.instance() or QCoreApplication([])
    return AppController()


def _shutdown(controller: AppController) -> None:
    controller._transition_timer.stop()
    controller._save_timer.stop()
    controller._startup_sync_timer.stop()
    controller._lock_timer.stop()
    controller._save_executor_shutdown = True
    controller._save_executor.shutdown(wait=True, cancel_futures=False)


def test_finished_transition_clears_the_auto_switch_flag() -> None:
    controller = _controller()
    try:
        controller._auto_switch_transitioning = True

        controller._on_transition_action_complete(True, "proxy_hot_swap", "auto-switch", 0)

        assert controller._auto_switch_transitioning is False
    finally:
        _shutdown(controller)


def test_no_op_transition_clears_the_auto_switch_flag() -> None:
    controller = _controller()
    try:
        controller._auto_switch_transitioning = True
        controller._transition_pending = True
        controller._compute_transition_action = lambda: None

        controller._drain_transition_queue()

        assert controller._auto_switch_transitioning is False
    finally:
        _shutdown(controller)


def test_kill_switch_keeps_system_proxy_after_a_proxy_hot_swap() -> None:
    controller = _controller()
    disabled: list[bool] = []
    try:
        controller.state.settings.kill_switch = True
        controller.state.settings.enable_system_proxy = True
        controller.state.settings.tun_mode = False
        controller._desired_connected = True
        controller.proxy.disable = lambda restore_previous=True: disabled.append(True)

        # Auto-switch requested a transition that resolved to a proxy hot swap.
        controller._auto_switch_transitioning = True
        controller._on_transition_action_complete(True, "proxy_hot_swap", "auto-switch", 0)

        # The xray process later dies on its own.
        runtime_services.handle_unexpected_disconnect(controller)

        assert controller._kill_switch_engaged is True
        assert disabled == []
    finally:
        _shutdown(controller)


def test_updater_disconnect_goes_through_the_transition_state_machine() -> None:
    controller = _controller()
    acks: list[bool] = []
    try:
        controller.connected = True
        controller._desired_connected = True
        controller.disconnect_current = lambda *_args, **_kwargs: acks.append("direct")

        class _Worker:
            def confirm_disconnect(self, success: bool) -> None:
                acks.append(success)

        worker = _Worker()
        controller.sender = lambda: worker

        controller._on_update_disconnect_request()

        assert acks == []
        assert controller._desired_connected is False
        assert controller._pending_update_disconnects == [worker]

        # The transition actually stopped the core.
        controller.connected = False
        controller._transition_pending = False
        controller._transition_scheduled = False
        controller._resolve_pending_update_disconnects()

        assert acks == [True]
        assert controller._pending_update_disconnects == []
    finally:
        _shutdown(controller)


def test_updater_disconnect_is_acknowledged_on_shutdown() -> None:
    controller = _controller()
    acks: list[bool] = []
    try:
        class _Worker:
            def confirm_disconnect(self, success: bool) -> None:
                acks.append(success)

        controller._pending_update_disconnects.append(_Worker())
        controller.shutdown()

        assert acks == [False]
        assert controller._pending_update_disconnects == []
    finally:
        _shutdown(controller)


def test_unexpected_core_exit_is_ignored_once_windows_shutdown_started() -> None:
    controller = SimpleNamespace(
        _system_shutdown=True,
        _shutting_down=False,
        _cleaning_connection_state=False,
    )

    runtime_services.handle_unexpected_disconnect(controller)

    assert controller._cleaning_connection_state is False
