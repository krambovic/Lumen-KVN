from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys

if sys.platform == "win32":
    import ctypes
    import winreg


RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
STARTUP_APPROVED_RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"
APP_COMPAT_LAYERS_KEY = r"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers"
RUNASADMIN_FLAG = "RUNASADMIN"
TASK_NAME = "Lumen"
CREATE_NO_WINDOW = 0x08000000
STARTUP_STATE_ABSENT = "absent"
STARTUP_STATE_ENABLED = "enabled"
STARTUP_STATE_DISABLED = "disabled"


LEGACY_APP_NAMES = ("Lumen KVN", "LumenKVN", "lumen-kvn", "Lumen_KVN")
LEGACY_EXECUTABLE_NAMES = {"lumenkvn.exe", "lumenkvn-qml.exe"}
LEGACY_PROTOCOL_KEYS = (
    r"Software\Classes\lumen-kvn",
    r"Software\Classes\AppUserModelId\Lumen.LumenKVN",
    r"Software\Classes\Applications\LumenKVN.exe",
    r"Software\Microsoft\Windows\CurrentVersion\App Paths\LumenKVN.exe",
    r"Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Lumen.LumenKVN",
)
_legacy_startup_was_disabled = False
_legacy_cleanup_done = False
SCHTASKS_TIMEOUT = 15


def _legacy_shell_paths() -> tuple[Path, ...]:
    appdata = os.environ.get("APPDATA", "").strip()
    program_data = os.environ.get("ProgramData", "").strip()
    user_profile = os.environ.get("USERPROFILE", "").strip()
    public_profile = os.environ.get("PUBLIC", "").strip()
    paths: list[Path] = []
    for name in LEGACY_APP_NAMES:
        if appdata:
            programs = Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs"
            paths.extend((programs / name, programs / "Startup" / f"{name}.lnk"))
            paths.append(
                Path(appdata)
                / "Microsoft"
                / "Internet Explorer"
                / "Quick Launch"
                / "User Pinned"
                / "TaskBar"
                / f"{name}.lnk"
            )
        if program_data:
            programs = Path(program_data) / "Microsoft" / "Windows" / "Start Menu" / "Programs"
            paths.extend((programs / name, programs / "Startup" / f"{name}.lnk"))
        if user_profile:
            paths.append(Path(user_profile) / "Desktop" / f"{name}.lnk")
        if public_profile:
            paths.append(Path(public_profile) / "Desktop" / f"{name}.lnk")
    return tuple(dict.fromkeys(paths))


def _cleanup_legacy_shell_entries() -> None:
    for path in _legacy_shell_paths():
        try:
            if path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink(missing_ok=True)
        except OSError:
            pass


def cleanup_legacy_system_entries() -> None:
    global _legacy_startup_was_disabled, _legacy_cleanup_done
    if sys.platform != "win32":
        return
    if _legacy_cleanup_done:
        return
    # One-time rebrand migration: registry, scheduled tasks and shell entries
    # left by previous product names. Re-running it on every state poll would
    # spawn schtasks and walk the filesystem forever.
    _legacy_cleanup_done = True
    for name in LEGACY_APP_NAMES:
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, STARTUP_APPROVED_RUN_KEY, 0, winreg.KEY_READ) as key:
                value, _ = winreg.QueryValueEx(key, name)
            if isinstance(value, (bytes, bytearray)) and value and value[0] == 0x03:
                _legacy_startup_was_disabled = True
        except OSError:
            pass
        _delete_registry_startup(name)
        _delete_startup_approved(name)
        try:
            subprocess.run(
                ["schtasks", "/Delete", "/TN", name, "/F"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=SCHTASKS_TIMEOUT,
                creationflags=CREATE_NO_WINDOW,
            )
        except Exception:
            pass

    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            APP_COMPAT_LAYERS_KEY,
            0,
            winreg.KEY_READ | winreg.KEY_SET_VALUE,
        ) as key:
            i = 0
            to_delete: list[str] = []
            while True:
                try:
                    val_name, _, _ = winreg.EnumValue(key, i)
                    executable_name = Path(val_name.strip().strip('"')).name.casefold()
                    if executable_name in LEGACY_EXECUTABLE_NAMES:
                        to_delete.append(val_name)
                    i += 1
                except OSError:
                    break
            for val_name in to_delete:
                try:
                    winreg.DeleteValue(key, val_name)
                except Exception:
                    pass
    except Exception:
        pass

    for key_path in LEGACY_PROTOCOL_KEYS:
        _delete_registry_tree(winreg.HKEY_CURRENT_USER, key_path)
    _cleanup_legacy_shell_entries()


def set_startup_enabled(app_name: str, enabled: bool, command: str) -> None:
    global _legacy_startup_was_disabled
    if sys.platform != "win32":
        return
    cleanup_legacy_system_entries()
    if enabled:
        if _startup_requires_scheduled_task():
            # HKCU Run entries pointing at executables that require elevation
            # are silently skipped by Windows at logon, while Task Manager
            # keeps showing them as "Enabled". Lumen runs elevated (UAC
            # manifest / RUNASADMIN layer), so register a scheduled task with
            # the highest run level instead.
            # Keep a normal Run/StartupApproved entry as the discoverable
            # Startup Apps registration.  Windows 10 Task Manager does not
            # enumerate Task Scheduler entries, which made an enabled Lumen
            # disappear from its Startup tab.  Windows skips this elevated
            # command at logon; the highest-run-level task performs the launch.
            # If a Windows build launches both, the single-instance guard
            # immediately closes the duplicate.
            _create_registry_startup(app_name, command)
            _set_startup_approved(app_name, enabled=True)
            _create_startup_task(command)
        else:
            _delete_startup_task()
            _create_registry_startup(app_name, command)
            _set_startup_approved(app_name, enabled=True)
    else:
        _delete_startup_task()
        _delete_registry_startup(app_name)
        _delete_startup_approved(app_name)
    _legacy_startup_was_disabled = False


def get_startup_state(app_name: str) -> str:
    if sys.platform != "win32":
        return STARTUP_STATE_ABSENT
    cleanup_legacy_system_entries()
    registry_exists = _registry_startup_exists(app_name)
    if not registry_exists:
        if app_name == TASK_NAME and _startup_task_exists():
            return STARTUP_STATE_ENABLED
        if app_name == TASK_NAME and _legacy_startup_was_disabled:
            return STARTUP_STATE_DISABLED
        return STARTUP_STATE_ABSENT
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, STARTUP_APPROVED_RUN_KEY, 0, winreg.KEY_READ) as key:
            value, _ = winreg.QueryValueEx(key, app_name)
    except FileNotFoundError:
        return STARTUP_STATE_ENABLED
    if isinstance(value, (bytes, bytearray)) and value and value[0] == 0x03:
        # Elevated installations intentionally keep a discoverable Run entry
        # beside the real highest-privilege task.  Windows can mark that
        # helper entry as disabled after replacing the executable, while the
        # task remains the effective startup mechanism.
        if app_name == TASK_NAME and _startup_task_exists():
            return STARTUP_STATE_ENABLED
        return STARTUP_STATE_DISABLED
    return STARTUP_STATE_ENABLED


def _startup_requires_scheduled_task() -> bool:
    if is_process_elevated():
        return True
    try:
        return is_always_run_as_admin_enabled()
    except Exception:
        return False


def _startup_task_exists() -> bool:
    try:
        result = subprocess.run(
            ["schtasks", "/Query", "/TN", TASK_NAME],
            capture_output=True,
            timeout=SCHTASKS_TIMEOUT,
            creationflags=CREATE_NO_WINDOW,
        )
    except Exception:
        return False
    return result.returncode == 0


def is_process_elevated() -> bool:
    if sys.platform != "win32":
        return True
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin(extra_args: list[str] | None = None) -> bool:
    if sys.platform != "win32":
        return False
    executable, arguments, working_dir = _admin_launch_command(extra_args)
    try:
        show_command = 1 if getattr(sys, "frozen", False) else 0
        result = ctypes.windll.shell32.ShellExecuteW(
            None,
            "runas",
            str(executable),
            arguments,
            str(working_dir),
            show_command,
        )
        return int(result) > 32
    except Exception:
        return False


def set_always_run_as_admin(enabled: bool, executable: str | Path | None = None) -> None:
    if sys.platform != "win32":
        return
    target = str(Path(executable).resolve() if executable else _current_executable_path())
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, APP_COMPAT_LAYERS_KEY, 0, winreg.KEY_READ | winreg.KEY_WRITE) as key:
        current = ""
        try:
            current, _ = winreg.QueryValueEx(key, target)
        except FileNotFoundError:
            current = ""
        updated = _update_layer_value(str(current or ""), enabled)
        if updated:
            winreg.SetValueEx(key, target, 0, winreg.REG_SZ, updated)
        else:
            try:
                winreg.DeleteValue(key, target)
            except FileNotFoundError:
                pass


def is_always_run_as_admin_enabled(executable: str | Path | None = None) -> bool:
    if sys.platform != "win32":
        return False
    target = str(Path(executable).resolve() if executable else _current_executable_path())
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, APP_COMPAT_LAYERS_KEY, 0, winreg.KEY_READ) as key:
            value, _ = winreg.QueryValueEx(key, target)
    except FileNotFoundError:
        return False
    return RUNASADMIN_FLAG in {part.upper() for part in str(value or "").split()}


def _current_executable_path() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve()
    return Path(sys.executable).resolve()


def _canonical_frozen_executable() -> Path:
    executable = Path(sys.executable).resolve()
    canonical = executable.with_name("Lumen.exe")
    if canonical.is_file():
        return canonical
    return executable


def _admin_launch_command(extra_args: list[str] | None = None) -> tuple[Path, str, Path]:
    # `--tray` describes an OS autostart, not the user's current visibility.
    # Carrying it into an elevation relaunch made the new window disappear.
    args = [
        arg
        for arg in sys.argv[1:]
        if arg not in {"--tray", "--relaunch-as-admin", "--relaunched"}
    ]
    if extra_args:
        args.extend(extra_args)
    args.append("--relaunch-as-admin")
    if getattr(sys, "frozen", False):
        executable = _canonical_frozen_executable()
        return executable, subprocess.list2cmdline(args), executable.parent

    base_dir = Path(__file__).resolve().parents[1]
    current_python = Path(sys.executable).resolve()
    candidates = (
        current_python.with_name("pythonw.exe"),
        base_dir / ".venv" / "Scripts" / "pythonw.exe",
    )
    executable = next((candidate for candidate in candidates if candidate.is_file()), current_python)
    script = base_dir / "run_qml.py"
    return executable, subprocess.list2cmdline([str(script), *args]), base_dir


def _update_layer_value(value: str, enabled: bool) -> str:
    parts = [part for part in str(value or "").split() if part and part != "~"]
    flags = {part.upper(): part for part in parts}
    if enabled:
        flags[RUNASADMIN_FLAG] = RUNASADMIN_FLAG
    else:
        flags.pop(RUNASADMIN_FLAG, None)
    if not flags:
        return ""
    return "~ " + " ".join(flags.values())


def _delete_registry_startup(app_name: str) -> None:
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
            try:
                winreg.DeleteValue(key, app_name)
            except FileNotFoundError:
                pass
    except FileNotFoundError:
        pass


def _delete_registry_tree(root: int, key_path: str) -> None:
    try:
        with winreg.OpenKey(root, key_path, 0, winreg.KEY_READ | winreg.KEY_WRITE) as key:
            children: list[str] = []
            index = 0
            while True:
                try:
                    children.append(winreg.EnumKey(key, index))
                    index += 1
                except OSError:
                    break
        for child in children:
            _delete_registry_tree(root, rf"{key_path}\{child}")
        winreg.DeleteKey(root, key_path)
    except FileNotFoundError:
        pass
    except OSError:
        pass


def _create_registry_startup(app_name: str, command: str) -> None:
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, app_name, 0, winreg.REG_SZ, command)


def _registry_startup_exists(app_name: str) -> bool:
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_READ) as key:
            winreg.QueryValueEx(key, app_name)
        return True
    except FileNotFoundError:
        return False


def _set_startup_approved(app_name: str, *, enabled: bool) -> None:
    # 0x02 = enabled, 0x03 = disabled; the remaining bytes are FILETIME-ish
    # metadata and can be zero for entries created by the app itself.
    payload = bytes([0x02 if enabled else 0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, STARTUP_APPROVED_RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, app_name, 0, winreg.REG_BINARY, payload)


def _delete_startup_approved(app_name: str) -> None:
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, STARTUP_APPROVED_RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
            try:
                winreg.DeleteValue(key, app_name)
            except FileNotFoundError:
                pass
    except FileNotFoundError:
        pass


def _create_startup_task(command: str) -> None:
    _delete_startup_task()
    subprocess.run(
        [
            "schtasks",
            "/Create",
            "/TN",
            TASK_NAME,
            "/SC",
            "ONLOGON",
            "/RL",
            "HIGHEST",
            "/RU",
            _current_task_user(),
            "/TR",
            command,
            "/F",
        ],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=SCHTASKS_TIMEOUT,
        creationflags=CREATE_NO_WINDOW,
    )


def _delete_startup_task() -> None:
    subprocess.run(
        ["schtasks", "/Delete", "/TN", TASK_NAME, "/F"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=SCHTASKS_TIMEOUT,
        creationflags=CREATE_NO_WINDOW,
    )


def _current_task_user() -> str:
    domain = os.environ.get("USERDOMAIN", "").strip()
    user = os.environ.get("USERNAME", "").strip()
    if domain and user:
        return f"{domain}\\{user}"
    return user or os.getlogin()


def _installed_executable_path() -> Path | None:
    candidates: list[Path] = []
    for env_name in ("ProgramFiles", "ProgramFiles(x86)"):
        root = os.environ.get(env_name, "").strip()
        if root:
            candidates.append(Path(root) / "Lumen" / "Lumen.exe")
    candidates.append(Path(r"C:\Program Files\Lumen\Lumen.exe"))
    candidates.append(Path(r"C:\Program Files (x86)\Lumen\Lumen.exe"))
    for candidate in candidates:
        try:
            if candidate.is_file():
                return candidate.resolve()
        except OSError:
            continue
    return None


def build_startup_command(*, in_tray: bool = True) -> str:
    tray_args = ["--tray"] if in_tray else []
    if getattr(sys, "frozen", False):
        exe = _canonical_frozen_executable()
        return subprocess.list2cmdline([str(exe), *tray_args])

    installed_exe = _installed_executable_path()
    if installed_exe is not None:
        return subprocess.list2cmdline([str(installed_exe), *tray_args])

    base_dir = Path(__file__).resolve().parents[1]
    script = base_dir / "run_qml.py"
    venv_pythonw = base_dir / ".venv" / "Scripts" / "pythonw.exe"
    python_exe = venv_pythonw if venv_pythonw.exists() else Path(sys.executable).resolve()
    return subprocess.list2cmdline([str(python_exe), str(script), *tray_args])
