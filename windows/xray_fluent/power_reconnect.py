"""Reconnect the active Lumen session after Windows sleep/hibernate."""
from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes
from typing import Any

from PyQt6.QtCore import QAbstractNativeEventFilter, QTimer


WM_POWERBROADCAST = 0x0218
WM_QUERYENDSESSION = 0x0011
WM_ENDSESSION = 0x0016
PBT_APMSUSPEND = 0x0004
PBT_APMRESUMECRITICAL = 0x0006
PBT_APMRESUMESUSPEND = 0x0007
PBT_APMRESUMEAUTOMATIC = 0x0012

_RESUME_EVENTS = {
    PBT_APMRESUMECRITICAL,
    PBT_APMRESUMESUSPEND,
    PBT_APMRESUMEAUTOMATIC,
}

_RESUME_INITIAL_DELAY_MS = 4000
_RESUME_RETRY_DELAYS_MS = (8000, 15000)
_RESUME_BUSY_RETRY_MS = 2000
_MAX_RESUME_ATTEMPTS = 1 + len(_RESUME_RETRY_DELAYS_MS)


class _Point(ctypes.Structure):
    _fields_ = [("x", wintypes.LONG), ("y", wintypes.LONG)]


class _Message(ctypes.Structure):
    _fields_ = [
        ("hwnd", wintypes.HWND),
        ("message", wintypes.UINT),
        ("wParam", wintypes.WPARAM),
        ("lParam", wintypes.LPARAM),
        ("time", wintypes.DWORD),
        ("pt", _Point),
        ("lPrivate", wintypes.DWORD),
    ]


def power_broadcast_event(wparam: int) -> str | None:
    """Classify a WM_POWERBROADCAST wParam for platform-independent tests."""
    try:
        value = int(wparam)
    except (TypeError, ValueError):
        return None
    if value == PBT_APMSUSPEND:
        return "suspend"
    if value in _RESUME_EVENTS:
        return "resume"
    return None


def _settings(controller: Any) -> Any:
    state = getattr(controller, "state", None)
    return getattr(state, "settings", None)


def should_arm_resume_reconnect(controller: Any) -> bool:
    """Return whether the current session should be restored after resume."""
    settings = _settings(controller)
    if not bool(getattr(settings, "reconnect_after_sleep", True)):
        return False
    if bool(getattr(controller, "locked", False)):
        return False
    if bool(getattr(controller, "_shutting_down", False)) or bool(
        getattr(controller, "_system_shutdown", False)
    ):
        return False

    desired_connected = getattr(controller, "_desired_connected", None)
    if desired_connected is None:
        desired_connected = bool(getattr(controller, "connected", False))
    if not desired_connected:
        return False

    return bool(
        getattr(controller, "connected", False)
        or getattr(controller, "_active_session", None) is not None
    )


def _native_message(message: Any) -> tuple[int, int] | None:
    try:
        address = int(message)
        if not address:
            return None
        native = ctypes.cast(address, ctypes.POINTER(_Message)).contents
        return int(native.message), int(native.wParam)
    except (TypeError, ValueError, OSError):
        return None


class WindowsPowerEventFilter(QAbstractNativeEventFilter):
    """Queue a bounded reconnect after a Windows suspend/resume cycle."""

    def __init__(self, controller: Any, parent: Any = None) -> None:
        super().__init__()
        self._controller = controller
        self._armed = False
        self._attempts = 0
        self._busy_retries = 0
        self._timer = QTimer(parent)
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self._on_timer)

    def close(self) -> None:
        self._timer.stop()
        self._armed = False
        self._attempts = 0
        self._busy_retries = 0

    def nativeEventFilter(self, event_type: Any, message: Any) -> tuple[bool, int]:
        if sys.platform != "win32":
            return False, 0
        try:
            event_name = bytes(event_type)
        except (TypeError, ValueError):
            return False, 0
        if event_name not in {b"windows_generic_MSG", b"windows_dispatcher_MSG"}:
            return False, 0

        native_message = _native_message(message)
        if native_message is None:
            return False, 0
        message_id, wparam = native_message
        if message_id == WM_QUERYENDSESSION:
            self._mark_system_shutdown()
            return False, 0
        if message_id == WM_ENDSESSION:
            if bool(wparam):
                self._mark_system_shutdown(stop_cores=True)
            else:
                self._cancel_system_shutdown()
            return False, 0
        # Keep accepting message_id=0 for compatibility with lightweight
        # native-message test doubles used by older integrations.
        if message_id not in {0, WM_POWERBROADCAST} or wparam == 0:
            return False, 0
        event = power_broadcast_event(wparam)
        if event == "suspend":
            self._timer.stop()
            self._attempts = 0
            self._armed = should_arm_resume_reconnect(self._controller)
            if self._armed:
                self._log("[power] suspend detected; resume reconnect armed")
        elif event == "resume":
            if not self._armed:
                # A resume without a suspend observed by this process is not
                # enough evidence that the active session needs reconnecting.
                # Windows can emit resume notifications for unrelated power
                # or device changes.
                return False, 0
            if self._timer.isActive() or self._attempts > 0:
                self._log("[power] duplicate resume ignored; recovery already pending")
                return False, 0
            self._busy_retries = 0
            self._log("[power] resume detected; waiting for network")
            self._schedule(_RESUME_INITIAL_DELAY_MS)
        return False, 0

    def _schedule(self, delay_ms: int) -> None:
        if self._armed:
            self._timer.start(max(0, int(delay_ms)))

    def _on_timer(self) -> None:
        if not self._armed or not should_arm_resume_reconnect(self._controller):
            self.close()
            return

        if self._transition_busy():
            self._busy_retries += 1
            if self._busy_retries >= _MAX_RESUME_ATTEMPTS:
                self._log("[power] resume reconnect skipped; transition stayed busy")
                self.close()
                return
            self._schedule(_RESUME_BUSY_RETRY_MS)
            return

        if self._attempts > 0:
            if bool(getattr(self._controller, "connected", False)):
                self._log("[power] resume reconnect already restored the session")
                self.close()
                return

        request = getattr(self._controller, "request_resume_reconnect", None)
        if not callable(request) or not request("system resume"):
            self._log("[power] resume reconnect skipped")
            self.close()
            return

        self._attempts += 1
        self._busy_retries = 0
        self._log(f"[power] resume reconnect attempt {self._attempts}/{_MAX_RESUME_ATTEMPTS}")
        if self._attempts >= _MAX_RESUME_ATTEMPTS:
            self._log("[power] resume reconnect attempts exhausted")
            self.close()
            return
        self._schedule(_RESUME_RETRY_DELAYS_MS[self._attempts - 1])

    def _transition_busy(self) -> bool:
        return bool(
            getattr(self._controller, "_transition_active", False)
            or getattr(self._controller, "_transition_pending", False)
        )

    def _mark_system_shutdown(self, *, stop_cores: bool = False) -> None:
        self._timer.stop()
        self._armed = False
        self._attempts = 0
        self._busy_retries = 0
        try:
            self._controller._system_shutdown = True
        except Exception:
            pass
        self._log("[power] Windows shutdown detected; reconnect disabled")
        if stop_cores:
            stop = getattr(self._controller, "_stop_active_connection_processes", None)
            if callable(stop):
                try:
                    stop(disable_proxy=True, fast=True)
                    self._log("[power] owned core processes stopped for Windows shutdown")
                except Exception as exc:
                    self._log(f"[power] failed to stop owned core processes: {exc}")

    def _cancel_system_shutdown(self) -> None:
        if not bool(getattr(self._controller, "_shutting_down", False)):
            try:
                self._controller._system_shutdown = False
            except Exception:
                pass
        self._log("[power] Windows shutdown cancelled")

    def _log(self, message: str) -> None:
        log = getattr(self._controller, "_log", None)
        if callable(log):
            try:
                log(message)
            except Exception:
                pass
