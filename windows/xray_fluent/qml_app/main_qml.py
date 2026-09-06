"""Entry point for the Qt Quick (QML) frontend"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time
import ctypes
from pathlib import Path

from ..deeplinks import (
    MAX_DEEP_LINK_LENGTH,
    decode_instance_message,
    encode_instance_message,
    find_lumen_deep_link,
)


def _enable_gpu_friendly_defaults() -> None:
    os.environ.setdefault("QT_QUICK_CONTROLS_STYLE", "Universal")
    os.environ.setdefault("QSG_RENDER_LOOP", "threaded")  # threaded: GPU-sync рендер, плавные анимации; краш трея (0xc000041d) устранён откатом routing submenu в 69f86e4
    os.environ.setdefault("QSG_RHI_BACKEND", "opengl")


def _install_message_filter() -> None:
    """Silence the benign ``qt.qpa.mime: Retrying to obtain clipboard.`` line.

    What it is: a Qt-on-Windows *warning* (not an error) emitted by the Windows
    clipboard backend (``qwindowsmime``). When Qt tries to READ the system
    clipboard - here that happens on every paste/«import» (Ctrl+V →
    ``AppBridge.importClipboard`` calls ``QGuiApplication.clipboard().text()``)
    and also when Qt automatically probes paste-availability - it must call the
    Win32 ``OpenClipboard()``. Windows only lets ONE process own the clipboard
    at a time, so if something else is momentarily holding it (clipboard
    managers / Win+V history, Punto Switcher, Ditto, a browser copying, etc.)
    the open is refused and Qt retries a few times, logging this line each
    attempt. It is completely harmless and its timing is dictated by whatever
    third-party clipboard software happens to be touching the clipboard, which
    is why it appears "at random" on some launches and never on others.

    Rather than leave the noise in the console we install a Qt message handler
    that drops just this one category/message and forwards everything else
    unchanged to stderr (so real warnings/errors are still visible).
    """
    try:
        from PyQt6.QtCore import (
            QtMsgType,
            qInstallMessageHandler,
        )
    except Exception:
        return

    def _handler(msg_type, context, message) -> None:
        text = message or ""
        if (
            "Retrying to obtain clipboard" in text
            or "Unable to obtain clipboard" in text
        ) or (
            "qt.qpa.mime" in text and "clipboard" in text
        ):
            return
        if text.startswith("QWindowsWindow::setGeometry: Unable to set geometry"):
            return
        try:
            import logging

            logger = logging.getLogger("xray_fluent.qt")
            if msg_type in (QtMsgType.QtCriticalMsg, QtMsgType.QtFatalMsg):
                logger.error(text)
            elif msg_type == QtMsgType.QtWarningMsg:
                logger.warning(text)
            else:
                logger.debug(text)
        except Exception:
            try:
                sys.stderr.write(text + "\n")
            except Exception:
                pass

    qInstallMessageHandler(_handler)


def _theme_name(bridge) -> str:
    try:
        return str(bridge.themeName)
    except Exception:
        return "system"


def _resolve_dark(app, theme_name: str) -> bool:
    """Mirror Main.qml resolveDark(): explicit light/dark, else follow system."""
    if theme_name == "dark":
        return True
    if theme_name == "light":
        return False
    try:
        from PyQt6.QtCore import Qt
        return app.styleHints().colorScheme() == Qt.ColorScheme.Dark
    except Exception:
        return False


def _apply_mica(window, dark: bool, backdrop_name: str = "mica") -> None:
    """Enable the selected Windows 11 backdrop + dark/light title-bar colour."""
    if sys.platform != "win32":
        return
    try:
        import ctypes

        hwnd = int(window.winId())
        dwm = ctypes.windll.dwmapi

        DWMWA_USE_IMMERSIVE_DARK_MODE = 20
        DWMWA_USE_IMMERSIVE_DARK_MODE_OLD = 19  # builds < 18985
        DWMWA_MICA_EFFECT = 1029                # Win11 21H2 (build 22000)
        DWMWA_SYSTEMBACKDROP_TYPE = 38          # Win11 22H2+ (build 22621)
        DWMSBT_NONE = 1                         # solid (no backdrop)
        DWMSBT_MAINWINDOW = 2                   # Mica
        DWMSBT_ACRYLIC = 3                      # Acrylic (transient)
        DWMWA_BORDER_COLOR = 34
        DWMWA_CAPTION_COLOR = 35
        DWMWA_TEXT_COLOR = 36
        DWMWA_COLOR_NONE = 0xFFFFFFFE

        backdrop_name = (backdrop_name or "mica").strip().lower()
        if backdrop_name == "acrylic":
            backdrop_name = "mica"
        if backdrop_name not in {"mica", "solid"}:
            backdrop_name = "mica"

        dark_flag = ctypes.c_int(1 if dark else 0)
        for attr in (DWMWA_USE_IMMERSIVE_DARK_MODE,
                     DWMWA_USE_IMMERSIVE_DARK_MODE_OLD):
            dwm.DwmSetWindowAttribute(
                hwnd, attr,
                ctypes.byref(dark_flag), ctypes.sizeof(dark_flag),
            )

        build = sys.getwindowsversion().build
        if build >= 22000:
            class _Margins(ctypes.Structure):
                _fields_ = [
                    ("cxLeftWidth", ctypes.c_int),
                    ("cxRightWidth", ctypes.c_int),
                    ("cyTopHeight", ctypes.c_int),
                    ("cyBottomHeight", ctypes.c_int),
                ]

            margins = _Margins(0, 0, 0, 0)
            dwm.DwmExtendFrameIntoClientArea(hwnd, ctypes.byref(margins))

            # Prevent Windows from drawing the user's accent colour as a 1px
            # active-window line above our custom title bar.
            border_color = ctypes.c_int(DWMWA_COLOR_NONE)
            dwm.DwmSetWindowAttribute(
                hwnd, DWMWA_BORDER_COLOR,
                ctypes.byref(border_color), ctypes.sizeof(border_color),
            )
            caption_color = ctypes.c_int(0x002C2631 if dark else 0x00F3F3F3)
            text_color = ctypes.c_int(0x00F3F3F3 if dark else 0x00202020)
            for attr, color in (
                (DWMWA_CAPTION_COLOR, caption_color),
                (DWMWA_TEXT_COLOR, text_color),
            ):
                dwm.DwmSetWindowAttribute(
                    hwnd, attr,
                    ctypes.byref(color), ctypes.sizeof(color),
                )

            if build >= 22621:
                backdrop_map = {
                    "mica": DWMSBT_MAINWINDOW,
                    "acrylic": DWMSBT_ACRYLIC,
                    "solid": DWMSBT_NONE,
                }
                backdrop = ctypes.c_int(backdrop_map[backdrop_name])
                dwm.DwmSetWindowAttribute(
                    hwnd, DWMWA_SYSTEMBACKDROP_TYPE,
                    ctypes.byref(backdrop), ctypes.sizeof(backdrop),
                )
            else:
                # Older Win11 only exposes Mica on/off.
                enable = ctypes.c_int(1 if backdrop_name != "solid" else 0)
                dwm.DwmSetWindowAttribute(
                    hwnd, DWMWA_MICA_EFFECT,
                    ctypes.byref(enable), ctypes.sizeof(enable),
                )
        # Windows 10 has no Mica API.  This is an expected capability fallback,
        # not an error worth repeating in the user's console.
    except Exception:
        # A solid QML backdrop is already active, so DWM failures are harmless.
        pass


def _refresh_custom_frame(window) -> None:
    """Force Windows to recalculate QWindowKit's zero-height native caption.

    Some Windows 10/DPI combinations retain the old caption inset after the
    window agent attaches.  The QML title bar is still exactly 34 logical px,
    but the stale native inset creates a second blank band above it.  A frame
    recalculation removes that inset without changing any QML dimensions or
    styling.
    """
    if sys.platform != "win32":
        return
    try:
        hwnd = int(window.winId())
        user32 = ctypes.windll.user32

        class _Point(ctypes.Structure):
            _fields_ = [("x", ctypes.c_long), ("y", ctypes.c_long)]

        class _Rect(ctypes.Structure):
            _fields_ = [
                ("left", ctypes.c_long),
                ("top", ctypes.c_long),
                ("right", ctypes.c_long),
                ("bottom", ctypes.c_long),
            ]

        class _Margins(ctypes.Structure):
            _fields_ = [
                ("cxLeftWidth", ctypes.c_int),
                ("cxRightWidth", ctypes.c_int),
                ("cyTopHeight", ctypes.c_int),
                ("cyBottomHeight", ctypes.c_int),
            ]

        margins = _Margins(0, 0, 0, 0)
        ctypes.windll.dwmapi.DwmExtendFrameIntoClientArea(hwnd, ctypes.byref(margins))
        window_rect = _Rect()
        client_origin = _Point(0, 0)
        if user32.GetWindowRect(hwnd, ctypes.byref(window_rect)) and user32.ClientToScreen(
            hwnd, ctypes.byref(client_origin)
        ):
            dpi = int(user32.GetDpiForWindow(hwnd) or 96) if hasattr(user32, "GetDpiForWindow") else 96
            stale_caption_threshold = max(16, round(16 * dpi / 96))
            if client_origin.y - window_rect.top > stale_caption_threshold:
                # QWindowKit occasionally misses the initial NCCALCSIZE pass.
                # Strip only the native caption bits; thick-frame resizing and
                # the existing QML title bar/buttons remain unchanged.
                style = int(user32.GetWindowLongW(hwnd, -16))
                user32.SetWindowLongW(hwnd, -16, style & ~0x00C00000)
        flags = 0x0001 | 0x0002 | 0x0004 | 0x0010 | 0x0020  # NOSIZE|NOMOVE|NOZORDER|NOACTIVATE|FRAMECHANGED
        user32.SetWindowPos(hwnd, 0, 0, 0, 0, 0, flags)
    except Exception:
        pass


def _set_app_user_model_id() -> None:
    """Give Windows an explicit AppUserModelID.

    Without it the taskbar button is associated with the generic host process
    and shows the default Windows icon. Setting an explicit ID lets Windows
    use our own icon and group the taskbar button correctly. Must be called
    before the first window is created.
    """
    if sys.platform != "win32":
        return
    try:
        import ctypes
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
            "Lumen.Lumen"
        )
    except Exception:
        pass
    _register_aumid_toast_identity()
    _register_toast_protocol()


def _register_aumid_toast_identity() -> None:
    """Register a friendly DisplayName + icon for our AppUserModelID"""
    if sys.platform != "win32":
        return
    try:
        import winreg
        from ..constants import APP_ICON_PATH, APP_NAME
        key_path = r"Software\Classes\AppUserModelId\Lumen.Lumen"
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path) as key:
            winreg.SetValueEx(key, "DisplayName", 0, winreg.REG_SZ, APP_NAME)
            if APP_ICON_PATH.is_file():
                winreg.SetValueEx(
                    key, "IconUri", 0, winreg.REG_SZ, str(APP_ICON_PATH)
                )
    except Exception:
        pass


def _protocol_launch_command() -> tuple[str, Path] | None:
    """Return the Windows command/icon target for packaged and source runs."""
    if getattr(sys, "frozen", False):
        executable = Path(sys.executable).resolve()
        canonical_exe = executable.with_name("Lumen.exe")
        if canonical_exe.is_file():
            executable = canonical_exe
        return f'"{executable}" "%1"', executable

    run_script = Path(__file__).resolve().parents[2] / "run_qml.py"
    if not run_script.is_file():
        return None
    python_exe = Path(sys.executable).resolve()
    pythonw_exe = python_exe.with_name("pythonw.exe")
    if pythonw_exe.is_file():
        python_exe = pythonw_exe
    return f'"{python_exe}" "{run_script}" "%1"', python_exe


def _register_toast_protocol() -> None:
    """Register deep links for installed, portable and source-tree launches."""
    if sys.platform != "win32":
        return
    try:
        import winreg
        from ..constants import APP_ICON_PATH
        launch = _protocol_launch_command()
        if launch is None:
            return
        command, icon_target = launch
        scheme = "lumen"
        with winreg.CreateKey(
            winreg.HKEY_CURRENT_USER, rf"Software\Classes\{scheme}"
        ) as key:
            winreg.SetValueEx(key, None, 0, winreg.REG_SZ, "URL:Lumen Protocol")
            winreg.SetValueEx(key, "URL Protocol", 0, winreg.REG_SZ, "")
        with winreg.CreateKey(
            winreg.HKEY_CURRENT_USER,
            rf"Software\Classes\{scheme}\shell\open\command",
        ) as key:
            winreg.SetValueEx(key, None, 0, winreg.REG_SZ, command)
        if APP_ICON_PATH.is_file():
            with winreg.CreateKey(
                winreg.HKEY_CURRENT_USER,
                rf"Software\Classes\{scheme}\DefaultIcon",
            ) as key:
                winreg.SetValueEx(key, None, 0, winreg.REG_SZ, f"{icon_target},0")
    except Exception as exc:
        import logging

        logging.getLogger("xray_fluent").warning(
            "Cannot register the lumen: protocol", exc_info=exc
        )


def _cleanup_legacy_root_program_install() -> None:
    if sys.platform != "win32" or not getattr(sys, "frozen", False):
        return
    try:
        current_dir = Path(sys.executable).resolve().parent
        if any((current_dir / marker).is_file() for marker in ("portable", "portable.txt")):
            return
        roots = {
            Path(value).resolve(strict=False)
            for value in (
                os.environ.get("ProgramW6432"),
                os.environ.get("ProgramFiles"),
                os.environ.get("ProgramFiles(x86)"),
            )
            if value
        }
        legacy_names = {"Lumen KVN", "LumenKVN", "lumen-kvn", "Lumen_KVN"}
        legacy_name_keys = {name.casefold() for name in legacy_names}
        candidates = {Path("C:/Program")}
        for root in roots:
            candidates.update(root / name for name in legacy_names)
        removable: list[Path] = []
        for candidate in candidates:
            candidate = candidate.resolve(strict=False)
            if candidate == current_dir or not candidate.is_dir():
                continue
            # Exact legacy product directories under Program Files are owned by
            # Lumen even when a failed old updater recreated only data/logs
            # after the installer had removed the executable.  Keep the marker
            # requirement for the historical C:\Program edge case.
            if candidate.name.casefold() not in legacy_name_keys and not any(
                (candidate / name).is_file() for name in ("Lumen.exe", "LumenKVN.exe")
            ):
                continue
            removable.append(candidate)
        if not removable:
            return
        paths = ",".join("'" + str(path).replace("'", "''") + "'" for path in removable)
        script = f"Start-Sleep -Seconds 3; foreach ($old in @({paths})) {{ Remove-Item -LiteralPath $old -Recurse -Force -ErrorAction SilentlyContinue }}"
        subprocess.Popen(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-Command", script],
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except Exception:
        pass


def _cleanup_legacy_executable_bridge() -> None:
    if sys.platform != "win32" or not getattr(sys, "frozen", False):
        return
    try:
        current_exe = Path(sys.executable).resolve()
        legacy_exe = current_exe.with_name("LumenKVN.exe")
        if not legacy_exe.is_file():
            return
        if current_exe != legacy_exe:
            legacy_exe.unlink(missing_ok=True)
            return
        escaped = str(legacy_exe).replace("'", "''")
        script = (
            f"Wait-Process -Id {os.getpid()} -ErrorAction SilentlyContinue; "
            f"Remove-Item -LiteralPath '{escaped}' -Force -ErrorAction SilentlyContinue"
        )
        subprocess.Popen(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-Command", script],
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except Exception:
        pass


def _notify_primary_instance(
    server_name: str,
    launch_arguments: list[str] | tuple[str, ...] = (),
) -> bool:
    try:
        from PyQt6.QtCore import QIODevice
        from PyQt6.QtNetwork import QLocalSocket
    except Exception:
        return False
    if sys.platform == "win32":
        try:
            # The process that the user just launched is allowed to put a window
            # in the foreground. Transfer that permission before asking the
            # already-running instance to restore its window from the tray.
            ctypes.windll.user32.AllowSetForegroundWindow(ctypes.c_uint(0xFFFFFFFF))
        except Exception:
            pass
    socket = QLocalSocket()
    socket.connectToServer(server_name, QIODevice.OpenModeFlag.WriteOnly)
    if not socket.waitForConnected(250):
        socket.abort()
        return False
    try:
        socket.write(encode_instance_message(launch_arguments))
        socket.flush()
        if not socket.waitForBytesWritten(500) and socket.bytesToWrite() > 0:
            socket.abort()
            return False
    except Exception:
        socket.abort()
        return False
    try:
        # The primary closes the connection after it has read the activation
        # request. Waiting briefly prevents the launcher from disappearing
        # before Windows has granted and consumed foreground permission.
        if socket.state() != QLocalSocket.LocalSocketState.UnconnectedState:
            socket.waitForDisconnected(750)
    except Exception:
        pass
    if socket.state() != QLocalSocket.LocalSocketState.UnconnectedState:
        socket.disconnectFromServer()
    return True


def _show_single_instance_unavailable() -> None:
    """Explain a stale or inaccessible primary instance instead of exiting silently."""
    if sys.platform != "win32":
        return
    try:
        ctypes.windll.user32.MessageBoxW(
            None,
            (
                "Другой экземпляр Lumen уже запущен, но не отвечает.\n\n"
                "Закройте Lumen через значок в области уведомлений или Диспетчер задач, "
                "затем запустите эту копию снова."
            ),
            "Lumen уже запущен",
            0x30,
        )
    except Exception:
        pass


def _create_windows_single_instance_mutex() -> tuple[object | None, bool]:
    if sys.platform != "win32":
        return None, True
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        # Win32 BOOL is a 32-bit integer (not ctypes' one-byte c_bool).
        kernel32.CreateMutexW.argtypes = (ctypes.c_void_p, ctypes.c_int, ctypes.c_wchar_p)
        kernel32.CreateMutexW.restype = ctypes.c_void_p
        # CreateMutexW only promises ERROR_ALREADY_EXISTS when the named
        # object was already present.  Clear the thread-local last-error value
        # first; otherwise a previous Win32 call can make a newly-created
        # mutex look occupied on some Windows startup paths.
        ctypes.set_last_error(0)
        handle = kernel32.CreateMutexW(None, True, "Local\\Lumen.SingleInstance")
        if not handle:
            return None, False
        already_exists = ctypes.get_last_error() == 183
        return handle, not already_exists
    except Exception:
        # Failing to create/check the mutex must never be treated as ownership:
        # doing so would allow two independent Lumen instances to run.
        return None, False


def _close_mutex_handle(handle: object | None) -> None:
    if not handle or sys.platform != "win32":
        return
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CloseHandle.argtypes = (ctypes.c_void_p,)
        kernel32.CloseHandle(handle)
    except Exception:
        pass


def _legacy_single_instance_running() -> bool:
    if sys.platform != "win32":
        return False
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenMutexW.argtypes = (ctypes.c_uint32, ctypes.c_int, ctypes.c_wchar_p)
        kernel32.OpenMutexW.restype = ctypes.c_void_p
        handle = kernel32.OpenMutexW(0x00100000, False, r"Local\LumenKVN.SingleInstance")
        if not handle:
            return False
        kernel32.CloseHandle(handle)
        return True
    except Exception:
        return False


def _acquire_single_instance_mutex(relaunching: bool) -> tuple[object | None, bool]:
    # The caller performs the retry/forwarding loop.  Keeping this operation
    # non-blocking is important during Windows startup: a second launch must
    # be able to notify a primary instance as soon as its local server appears,
    # while still taking over if that primary dies before listening.
    del relaunching
    return _create_windows_single_instance_mutex()


def _create_single_instance(app, launch_arguments=None):
    """Return (server, is_primary), forwarding deep links to the first process."""
    try:
        from PyQt6.QtCore import QLockFile
        from PyQt6.QtNetwork import QLocalServer
    except Exception:
        return None, True

    server_name = "Lumen.SingleInstance"
    arguments = list(launch_arguments if launch_arguments is not None else sys.argv)
    relaunching = any(flag in arguments[1:] for flag in ("--relaunch-as-admin", "--relaunched"))

    legacy_running = _legacy_single_instance_running()
    legacy_notified = _notify_primary_instance("LumenKVN.SingleInstance", arguments)
    if legacy_running or legacy_notified:
        deadline = time.monotonic() + 5.0
        while not legacy_notified and time.monotonic() < deadline:
            legacy_notified = _notify_primary_instance("LumenKVN.SingleInstance", arguments)
            if legacy_notified:
                break
            time.sleep(0.1)
        if not legacy_notified:
            _show_single_instance_unavailable()
        return None, False

    mutex_handle, owns_mutex = _acquire_single_instance_mutex(relaunching)
    if not owns_mutex:
        # A process may have acquired the mutex and then stalled before
        # QLocalServer.listen().  Conversely, it may have crashed and left no
        # live owner at all.  Forward while probing the server and re-create
        # the mutex after every failed probe so a crashed primary can be
        # replaced instead of producing a permanent false-positive dialog.
        deadline = time.monotonic() + (20.0 if relaunching else 5.0)
        notified = False
        while time.monotonic() < deadline:
            notified = _notify_primary_instance(server_name, arguments)
            if notified:
                _close_mutex_handle(mutex_handle)
                return None, False
            _close_mutex_handle(mutex_handle)
            time.sleep(0.1)
            mutex_handle, owns_mutex = _create_windows_single_instance_mutex()
            if owns_mutex:
                break
        if not owns_mutex:
            # Give a just-started primary one final chance before showing the
            # actionable warning.  The warning is now reserved for a mutex
            # that remains occupied and genuinely does not answer.
            notified = _notify_primary_instance(server_name, arguments)
            _close_mutex_handle(mutex_handle)
            if not notified:
                _show_single_instance_unavailable()
            return None, False

    # On Windows the named mutex is the authoritative, kernel-owned lock.  A
    # QLockFile can survive a crash/reboot and block recovery even when no
    # Lumen process exists, so do not put it in the Windows startup path.  It
    # remains in use on other platforms where no equivalent mutex is present.
    lock = None
    if sys.platform != "win32":
        lock = QLockFile(str(Path(tempfile.gettempdir()) / "Lumen.SingleInstance.lock"))
        lock.setStaleLockTime(30_000)
        deadline = time.monotonic() + (20.0 if relaunching else 0.5)
        notified = False

        while not lock.tryLock(0):
            if relaunching:
                lock.removeStaleLockFile()
            else:
                notified = _notify_primary_instance(server_name, arguments) or notified
            if time.monotonic() >= deadline:
                _close_mutex_handle(mutex_handle)
                if not notified:
                    _show_single_instance_unavailable()
                return None, False
            time.sleep(0.1)

    try:
        QLocalServer.removeServer(server_name)
        QLocalServer.removeServer("LumenKVN.SingleInstance")
        legacy_lock = Path(tempfile.gettempdir()) / "LumenKVN.SingleInstance.lock"
        if legacy_lock.is_file():
            legacy_lock.unlink(missing_ok=True)
    except Exception:
        pass
    server = QLocalServer(app)
    try:
        server.setSocketOptions(QLocalServer.SocketOption.UserAccessOption)
    except Exception:
        pass
    if not server.listen(server_name):
        if lock is not None:
            lock.unlock()
        _close_mutex_handle(mutex_handle)
        if not _notify_primary_instance(server_name, arguments):
            _show_single_instance_unavailable()
        return None, False
    server._single_instance_lock = lock
    server._single_instance_mutex_handle = mutex_handle
    return server, True


def _activate_window(window) -> None:
    hwnd = 0
    reveal = getattr(window, "_lumen_reveal", None)
    try:
        if callable(reveal):
            reveal()
        else:
            window.setVisible(True)
            window.showNormal()
            window.show()
            window.raise_()
            window.requestActivate()
    except Exception:
        pass
    if sys.platform != "win32":
        return
    try:
        hwnd = int(window.winId())
        if not hwnd:
            return
        user32 = ctypes.windll.user32
        user32.ShowWindow(hwnd, 9)  # SW_RESTORE
        user32.BringWindowToTop(hwnd)
        user32.SetForegroundWindow(hwnd)
    except Exception:
        pass


def _install_crash_guards() -> None:
    """Stop PyQt6 from turning a stray slot exception into a native abort.

    On Windows an unhandled Python exception raised inside a Qt slot invoked
    synchronously from the native message loop (for example while the tray
    context menu is shown) makes PyQt6 call abort() inside qwindows.dll, which
    crashes the whole app with STATUS_FATAL_USER_CALLBACK_EXCEPTION (0xc000041d).
    Installing a custom sys.excepthook makes PyQt log the traceback and keep
    running instead of aborting. faulthandler is armed so any genuine native
    fault still leaves a trace on disk.
    """
    import logging

    _log = logging.getLogger("xray_fluent")

    def _hook(exc_type, exc, tb):
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc, tb)
            return
        try:
            _log.error(
                "Unhandled exception (suppressed to avoid native abort)",
                exc_info=(exc_type, exc, tb),
            )
        except Exception:
            try:
                import traceback

                traceback.print_exception(exc_type, exc, tb)
            except Exception:
                pass

    sys.excepthook = _hook

    def _thread_hook(args) -> None:
        if issubclass(args.exc_type, SystemExit):
            return
        try:
            _log.error(
                "Unhandled exception in thread %r",
                getattr(args.thread, "name", None),
                exc_info=(args.exc_type, args.exc_value, args.exc_traceback),
            )
        except Exception:
            pass

    def _unraisable_hook(args) -> None:
        try:
            _log.error(
                "Unraisable exception in %r",
                args.object,
                exc_info=(args.exc_type, args.exc_value, args.exc_traceback),
            )
        except Exception:
            pass

    import threading

    threading.excepthook = _thread_hook
    sys.unraisablehook = _unraisable_hook

    try:
        import faulthandler

        from ..constants import LOG_DIR

        LOG_DIR.mkdir(parents=True, exist_ok=True)
        fh_path = LOG_DIR / "faulthandler.log"
        prev_path = LOG_DIR / "faulthandler.prev"
        if fh_path.is_file() and fh_path.stat().st_size > 0:
            try:
                if prev_path.exists():
                    prev_path.unlink()
                fh_path.rename(prev_path)
            except Exception:
                pass
        _fh = open(
            fh_path,
            "a",
            buffering=1,
            encoding="utf-8",
            errors="replace",
        )
        faulthandler.enable(file=_fh)
        globals()["_FAULTHANDLER_FILE"] = _fh
    except Exception:
        pass


def _load_bundled_fonts() -> None:
    try:
        from PyQt6.QtGui import QFontDatabase
        if getattr(sys, "frozen", False):
            font_path = Path(sys._MEIPASS) / "xray_fluent" / "qml_app" / "assets" / "fonts" / "SegoeIcons.ttf"
        else:
            font_path = Path(__file__).resolve().parent / "assets" / "fonts" / "SegoeIcons.ttf"
            
        if font_path.is_file():
            font_id = QFontDatabase.addApplicationFont(str(font_path))
            if font_id == -1:
                print(f"Failed to load bundled icon font: QFontDatabase returned -1", file=sys.stderr)
        else:
            print(f"Bundled icon font file not found at: {font_path}", file=sys.stderr)
    except Exception as exc:
        print(f"Failed to load bundled icon font: {exc}", file=sys.stderr)


def _attach_qwindowkit(window) -> None:
    if sys.platform != "win32":
        return
    try:
        import os
        import ctypes
        import PyQt6
        from PyQt6 import sip
        from PyQt6.QtQuick import QQuickItem

        if getattr(sys, "frozen", False):
            qwk_dir = os.path.join(sys._MEIPASS, "qwk")
        else:
            qwk_dir = os.path.join(os.path.dirname(__file__), "vendor", "qwk")
            qt_bin = os.path.join(os.path.dirname(PyQt6.__file__), "Qt6", "bin")
            if os.path.isdir(qt_bin) and hasattr(os, "add_dll_directory"):
                os.add_dll_directory(qt_bin)

        if os.path.isdir(qwk_dir) and hasattr(os, "add_dll_directory"):
            os.add_dll_directory(qwk_dir)

        qwkshim_path = os.path.join(qwk_dir, "qwkshim.dll")
        if not os.path.isfile(qwkshim_path):
            print(f"qwkshim.dll not found at: {qwkshim_path}", file=sys.stderr)
            return

        qwk = ctypes.CDLL(qwkshim_path)
        
        qwk.qwk_attach_by_hwnd.argtypes = [
            ctypes.c_ulonglong,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
        ]
        qwk.qwk_attach_by_hwnd.restype = ctypes.c_int

        hwnd = int(window.winId())
        
        rc = qwk.qwk_attach_by_hwnd(
            hwnd,
            b"qwkTitleBar",
            b"qwkMinBtn",
            b"qwkMaxBtn",
            b"qwkCloseBtn",
        )
        if rc != 0:
            print(f"qwk_attach_by_hwnd rc={rc}", file=sys.stderr)
            
        window._qwk_lib = qwk
        window._qwk_attach_ok = (rc == 0)
        
    except Exception as exc:
        print(f"QWindowKit attachment failed: {exc}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    _install_crash_guards()
    _set_app_user_model_id()
    _cleanup_legacy_root_program_install()
    _cleanup_legacy_executable_bridge()
    try:
        from ..startup import cleanup_legacy_system_entries
        cleanup_legacy_system_entries()
    except Exception:
        pass
    try:
        from ..discord_proxy_manager import migrate_legacy_droute_markers
        migrate_legacy_droute_markers()
    except Exception:
        pass
    _enable_gpu_friendly_defaults()
    _install_message_filter()

    from PyQt6.QtCore import QMetaObject, QTimer, QUrl, Qt
    from PyQt6.QtGui import QIcon
    from PyQt6.QtQml import QQmlApplicationEngine, qmlRegisterSingletonInstance
    from PyQt6.QtWidgets import QApplication

    from ..constants import APP_ICON_PATH, APP_NAME
    from .bridge import AppBridge
    from .window_reveal import WindowReveal

    QApplication.setApplicationName(APP_NAME)

    from PyQt6.QtGui import QSurfaceFormat
    _fmt = QSurfaceFormat.defaultFormat()
    _fmt.setAlphaBufferSize(8)
    QSurfaceFormat.setDefaultFormat(_fmt)

    from PyQt6.QtQuick import QQuickWindow
    QQuickWindow.setDefaultAlphaBuffer(True)

    launch_arguments = list(argv if argv is not None else sys.argv)
    initial_deep_link = find_lumen_deep_link(launch_arguments)
    app = QApplication(launch_arguments)
    from .native_context_menu_filter import QmlNativeContextMenuFilter

    native_context_menu_filter = QmlNativeContextMenuFilter(app)
    app.installEventFilter(native_context_menu_filter)
    _load_bundled_fonts()
    single_server, is_primary = _create_single_instance(app, launch_arguments)
    if not is_primary:
        return 0

    if APP_ICON_PATH.is_file():
        app.setWindowIcon(QIcon(str(APP_ICON_PATH)))

    bridge = AppBridge()
    bridge._single_instance_server = single_server
    bridge.load()

    qmlRegisterSingletonInstance("App", 1, 0, "App", bridge)

    engine = QQmlApplicationEngine()
    qml_dir = Path(__file__).resolve().parent / "qml"
    engine.addImportPath(str(qml_dir))
    engine.load(QUrl.fromLocalFile(str(qml_dir / "Main.qml")))

    if not engine.rootObjects():
        print("Failed to load Main.qml", file=sys.stderr)
        return 1

    window = engine.rootObjects()[0]
    _attach_qwindowkit(window)
    _refresh_custom_frame(window)
    reveal = WindowReveal(window, lambda callback: QTimer.singleShot(0, callback))
    # QWindowKit updates Qt's non-client-area geometry.  Restore the saved
    # size and install minimum constraints only after that setup is complete;
    # applying them while QML is still loading can leave a DPI-scaled blank
    # strip above the title bar and push the bottom of the scene off-screen.
    if not QMetaObject.invokeMethod(window, "applyStartupWindowGeometry"):
        window.setMinimumWidth(640)
        window.setMinimumHeight(360)
    start_in_tray = "--tray" in launch_arguments[1:] and not initial_deep_link

    if single_server is not None:
        active_connections: set[object] = set()

        def _read_instance_message(conn, state: dict, *, final: bool = False) -> None:
            if state["done"]:
                return
            try:
                state["data"].extend(bytes(conn.readAll()))
            except Exception:
                final = True
            if len(state["data"]) > MAX_DEEP_LINK_LENGTH + 1024:
                state["data"] = state["data"][: MAX_DEEP_LINK_LENGTH + 1024]
                final = True
            if not final and b"\n" not in state["data"]:
                return
            state["done"] = True
            active_connections.discard(conn)
            deep_link = decode_instance_message(bytes(state["data"]))
            try:
                conn.disconnectFromServer()
                conn.deleteLater()
            except Exception:
                pass
            _activate_window(window)
            if deep_link:
                bridge.handleDeepLink(deep_link)

        def _on_second_instance() -> None:
            while single_server.hasPendingConnections():
                conn = single_server.nextPendingConnection()
                if conn is not None:
                    state = {"data": bytearray(), "done": False}
                    active_connections.add(conn)
                    conn.readyRead.connect(
                        lambda c=conn, s=state: _read_instance_message(c, s)
                    )
                    conn.disconnected.connect(
                        lambda c=conn, s=state: _read_instance_message(c, s, final=True)
                    )
                    _read_instance_message(conn, state)

        single_server.newConnection.connect(_on_second_instance)

    if initial_deep_link:
        QTimer.singleShot(0, lambda: bridge.handleDeepLink(initial_deep_link))

    if APP_ICON_PATH.is_file():
        try:
            window.setIcon(QIcon(str(APP_ICON_PATH)))
        except Exception:
            pass

    def _refresh_backdrop() -> None:
        _refresh_custom_frame(window)
        _apply_mica(window, _resolve_dark(app, _theme_name(bridge)), bridge.uiBackdrop)

    def _apply_backdrop_only() -> None:
        _apply_mica(window, _resolve_dark(app, _theme_name(bridge)), bridge.uiBackdrop)

    def _schedule_backdrop_refresh(*_args) -> None:
        QTimer.singleShot(0, _apply_backdrop_only)
        QTimer.singleShot(150, _apply_backdrop_only)

    first_frame = {"done": False}

    def _on_first_frame() -> None:
        reveal.frame_swapped()
        if first_frame["done"]:
            return
        first_frame["done"] = True
        QTimer.singleShot(0, bridge.startDeferred)
        QTimer.singleShot(250, lambda: QMetaObject.invokeMethod(window, "beginBackgroundPageWarmup"))

    _refresh_backdrop()
    try:
        window.frameSwapped.connect(
            _on_first_frame,
            Qt.ConnectionType.QueuedConnection,
        )
    except Exception:
        QTimer.singleShot(0, bridge.startDeferred)
    QTimer.singleShot(750, bridge.startDeferred)
    QTimer.singleShot(1200, lambda: QMetaObject.invokeMethod(window, "beginBackgroundPageWarmup"))
    try:
        bridge.settingsChanged.connect(_refresh_backdrop)
    except Exception:
        pass
    for signal_name in ("visibilityChanged", "windowStateChanged"):
        signal = getattr(window, signal_name, None)
        if signal is not None:
            try:
                signal.connect(_schedule_backdrop_refresh)
            except Exception:
                pass
    from PyQt6.QtWidgets import QSystemTrayIcon
    from .tray import QmlTray

    tray_available = QSystemTrayIcon.isSystemTrayAvailable()
    bridge.set_tray_available(tray_available)
    app.setQuitOnLastWindowClosed(not tray_available)
    def _request_reveal(*, activate: bool = False) -> None:
        reveal.request(activate=activate)
        QTimer.singleShot(500, reveal.reveal_if_pending)

    window._lumen_reveal = lambda: _request_reveal(activate=True)
    tray = (
        QmlTray(app, window, bridge, show_window=lambda: _request_reveal(activate=True))
        if tray_available
        else None
    )
    if not (start_in_tray and tray_available):
        _request_reveal()
    try:
        app.commitDataRequest.connect(lambda _manager: bridge.prepareSystemShutdown())
    except Exception:
        pass
    app.aboutToQuit.connect(bridge.shutdown)

    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
