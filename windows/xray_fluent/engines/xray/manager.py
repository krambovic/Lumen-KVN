from __future__ import annotations

import csv
import ctypes
import json
import os
import socket
import subprocess
import tempfile
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any

from PyQt6.QtCore import QObject, pyqtSignal

from ...constants import RUNTIME_DIR, XRAY_CONFIG_FILE, XRAY_PATH_DEFAULT
from ...path_utils import resolve_configured_path
from ...subprocess_utils import (
    decode_output,
    is_windows_shutting_down,
    kill_processes_by_path,
    pump_qt_events,
    result_output_text,
    run_text_pumped,
    sleep_with_events,
)

_CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0


class XrayManager(QObject):
    started = pyqtSignal()
    stopped = pyqtSignal(int)
    log_received = pyqtSignal(str)
    error = pyqtSignal(str)
    state_changed = pyqtSignal(bool)

    def __init__(self, parent: QObject | None = None):
        super().__init__(parent)
        self._proc: subprocess.Popen[bytes] | None = None
        self._reader: threading.Thread | None = None
        self._lock = threading.RLock()
        self._running = False
        self._stop_requested = False
        self._starting = False
        self._startup_failure_reported = False
        self._runtime_error_reported = False
        self._last_output_lines: deque[str] = deque(maxlen=20)
        self._last_exit_code: int | None = None
        self._last_exit_expected = False
        self._exe_path: Path | None = None

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def last_exit_expected(self) -> bool:
        return self._last_exit_expected

    def _proc_alive(self) -> bool:
        proc = self._proc
        return proc is not None and proc.poll() is None

    def validate_config(self, xray_path: str, config: dict[str, Any]) -> tuple[bool, str]:
        exe = resolve_configured_path(
            xray_path,
            default_path=XRAY_PATH_DEFAULT,
            use_default_if_empty=True,
            migrate_default_location=True,
        )
        if exe is None or not exe.is_file():
            return False, f"xray.exe не найден: {exe or xray_path}"
        RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
        config_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                suffix=".json",
                prefix="xray-check-",
                dir=RUNTIME_DIR,
                delete=False,
            ) as handle:
                json.dump(config, handle, ensure_ascii=True, indent=2)
                config_path = Path(handle.name)
            result = subprocess.run(
                [str(exe), "run", "-test", "-c", str(config_path)],
                cwd=str(exe.parent),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=20,
                creationflags=_CREATE_NO_WINDOW,
                check=False,
            )
            output = decode_output(result.stdout).strip()
            return result.returncode == 0, output
        except subprocess.TimeoutExpired:
            return False, "Проверка конфигурации Xray превысила 20 секунд"
        except Exception as exc:
            return False, f"Не удалось проверить конфигурацию Xray: {exc}"
        finally:
            if config_path is not None:
                config_path.unlink(missing_ok=True)

    def start(
        self,
        xray_path: str,
        config: dict[str, Any],
        *,
        prevalidated: bool = False,
    ) -> bool:
        if not xray_path or not xray_path.strip():
            self.error.emit("Путь к Xray не настроен (укажите его в Настройки -> Пути к ядрам)")
            return False
        exe = resolve_configured_path(
            xray_path,
            default_path=XRAY_PATH_DEFAULT,
            use_default_if_empty=True,
            migrate_default_location=True,
        )
        if exe is None:
            self.error.emit("Путь к Xray не настроен (укажите его в Настройки -> Пути к ядрам)")
            return False
        if not exe.is_file():
            self.error.emit(f"xray.exe не найден: {exe}")
            return False
        self._exe_path = exe

        if not prevalidated:
            valid, validation_output = self.validate_config(str(exe), config)
            if not valid:
                detail = validation_output or "неизвестная ошибка проверки"
                self.error.emit(f"Xray не принимает новый конфиг: {detail}")
                return False

        if self._proc_alive():
            if not self.stop(expected=True):
                self.error.emit("Не удалось остановить предыдущий процесс Xray")
                return False
        elif self._running:
            self._running = False
            self.state_changed.emit(False)

        required_ports = self._extract_required_ports(config)
        port_error = self._ensure_ports_available(required_ports)
        if port_error:
            self.error.emit(port_error)
            return False

        RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
        XRAY_CONFIG_FILE.write_text(json.dumps(config, ensure_ascii=True, indent=2), encoding="utf-8")

        self._starting = True
        self._startup_failure_reported = False
        self._runtime_error_reported = False
        self._stop_requested = False
        self._last_exit_expected = False
        self._last_exit_code = None
        self._last_output_lines.clear()

        for attempt in range(2):
            self._last_output_lines.clear()
            self._stop_requested = False
            self._last_exit_expected = False
            self._last_exit_code = None
            if attempt:
                self.log_received.emit("[xray] ports were not ready; restarting core once")
                port_error = self._ensure_ports_available(required_ports)
                if port_error:
                    self._starting = False
                    self._report_startup_failure(port_error)
                    return False

            try:
                proc = subprocess.Popen(
                    [str(exe), "run", "-c", str(XRAY_CONFIG_FILE)],
                    cwd=str(exe.parent),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    stdin=subprocess.DEVNULL,
                    bufsize=0,
                    creationflags=_CREATE_NO_WINDOW,
                )
            except Exception as exc:
                self._starting = False
                self._report_startup_failure(f"Не удалось запустить Xray: {exc}")
                return False

            with self._lock:
                self._proc = proc
            self._reader = threading.Thread(
                target=self._read_output,
                args=(proc,),
                name="xray-output-reader",
                daemon=True,
            )
            self._reader.start()

            if self._wait_until_ready(required_ports, report_on_failure=False):
                self._starting = False
                self._on_started(proc)
                return True

            if not self._proc_alive():
                self._starting = False
                self._report_startup_failure(self._unexpected_exit_message(self._last_exit_code, startup=True))
                return False

            self.stop(expected=True, fast=attempt == 0)
            if attempt == 0:
                sleep_with_events(0.5)
                self._starting = True
                continue

            self._starting = False
            details = self._not_ready_ports_detail(required_ports)
            self._report_startup_failure(f"Xray запустился, но не открыл нужные порты: {details}")
            return False

        self._starting = False
        return False

    def stop(self, expected: bool = True, *, fast: bool = False) -> bool:
        already_stopped = False
        with self._lock:
            proc = self._proc
            if proc is None or proc.poll() is not None:
                self._stop_requested = False
                if self._running:
                    self._running = False
                    self.state_changed.emit(False)
                already_stopped = True
            else:
                self._stop_requested = expected
        if already_stopped:
            self._join_reader()
            return True

        try:
            proc.terminate()
        except Exception:
            pass
        terminate_timeout = 0.8 if fast else 3.0
        kill_timeout = 0.5 if fast else 2.0
        orphan_timeout = 2 if fast else 5
        final_timeout = 0.3 if fast else 1.0

        if self._wait_proc(proc, terminate_timeout):
            self._join_reader()
            return True

        try:
            proc.kill()
        except Exception:
            pass
        if self._wait_proc(proc, kill_timeout):
            self._join_reader()
            return True

        exe = self._exe_path
        if os.name == "nt" and exe is not None:
            try:
                if kill_processes_by_path(exe.name, exe, timeout=orphan_timeout):
                    if self._wait_proc(proc, final_timeout):
                        self._join_reader()
                        return True
            except Exception:
                pass

        if proc.poll() is not None:
            self._join_reader()
            return True

        self._stop_requested = False
        if not is_windows_shutting_down():
            self.error.emit("Не удалось вовремя остановить процесс Xray")
        return False

    def _join_reader(self, timeout: float = 2.0) -> None:
        reader = self._reader
        if reader is None or reader is threading.current_thread():
            return
        reader.join(timeout)
        if not reader.is_alive() and self._reader is reader:
            self._reader = None

    def _wait_proc(self, proc: subprocess.Popen[bytes], timeout_sec: float) -> bool:
        deadline = time.monotonic() + max(0.0, timeout_sec)
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                return True
            pump_qt_events()
            time.sleep(0.05)
        return proc.poll() is not None

    def _read_output(self, proc: subprocess.Popen[bytes]) -> None:
        stream = proc.stdout
        try:
            if stream is not None:
                for raw in iter(stream.readline, b""):
                    text = decode_output(raw)
                    for line in text.splitlines():
                        clean = line.rstrip()
                        if clean:
                            self._last_output_lines.append(clean)
                            self.log_received.emit(clean)
        except Exception:
            pass
        finally:
            try:
                proc.wait()
            except Exception:
                pass
            self._handle_process_exit(proc)

    def _on_started(self, proc: subprocess.Popen[bytes]) -> None:
        with self._lock:
            if proc is not self._proc or proc.poll() is not None:
                return
            self._running = True
        self.started.emit()
        self.state_changed.emit(True)

    def _handle_process_exit(self, proc: subprocess.Popen[bytes]) -> None:
        with self._lock:
            if proc is not self._proc:
                return
            exit_code = proc.returncode if proc.returncode is not None else -1
            expected = self._stop_requested or is_windows_shutting_down()
            was_starting = self._starting
            self._last_exit_expected = expected
            self._last_exit_code = exit_code
            self._stop_requested = False
            self._running = False
            self._proc = None

        if was_starting and not expected:
            self._report_startup_failure(self._unexpected_exit_message(exit_code, startup=True))
        elif not expected and not self._runtime_error_reported:
            self._runtime_error_reported = True
            self.error.emit(self._unexpected_exit_message(exit_code, startup=False))
        self.stopped.emit(exit_code)
        self.state_changed.emit(False)

    def _extract_required_ports(self, config: dict[str, Any]) -> dict[int, str]:
        port_roles: dict[int, str] = {}
        for inbound in config.get("inbounds", []):
            if not isinstance(inbound, dict):
                continue
            port = inbound.get("port")
            if not isinstance(port, int) or port <= 0:
                continue
            protocol = str(inbound.get("protocol") or "").strip().lower()
            tag = str(inbound.get("tag") or "").strip().lower()
            if protocol == "http":
                role = "HTTP"
            elif protocol == "socks":
                role = "SOCKS"
            elif tag == "api":
                role = "API"
            else:
                role = tag or protocol or "local"
            port_roles[port] = role
        return port_roles

    def _ensure_ports_available(self, port_roles: dict[int, str]) -> str | None:
        for port, role in port_roles.items():
            if not self._is_port_ready(port):
                continue
            owner = self._find_listening_port_owner(port)
            if owner is None:
                continue
            pid, name = owner
            owner_path = self._lookup_process_path(pid)
            is_own_stale_xray = (
                pid > 0
                and (name or "").strip().lower() == "xray.exe"
                and self._exe_path is not None
                and owner_path is not None
                and self._same_path(owner_path, self._exe_path)
            )
            if is_own_stale_xray and self._kill_pid(pid):
                sleep_with_events(0.5)
                if not self._is_port_ready(port):
                    self.log_received.emit(f"[xray] terminated stale xray.exe PID {pid} on port {port}")
                    continue
            display_name = name
            if (name or "").strip().lower() == "xray.exe":
                display_name = "другой VPN/прокси-клиент"
            return self._port_conflict_message(port, role, pid, display_name)
        return None

    def _find_listening_port_owner(self, port: int) -> tuple[int, str] | None:
        try:
            result = run_text_pumped(
                ["netstat", "-ano", "-p", "tcp"],
                timeout=5,
                check=False,
                creationflags=_CREATE_NO_WINDOW,
            )
        except Exception:
            return None
        text = result_output_text(result)
        for line in text.splitlines():
            parts = line.split()
            if len(parts) < 5:
                continue
            state = parts[-2].upper()
            if state != "LISTENING":
                continue
            parsed_port = self._parse_port(parts[1])
            if parsed_port != port:
                continue
            try:
                pid = int(parts[-1])
            except ValueError:
                pid = 0
            return pid, self._lookup_process_name(pid)
        return None

    @staticmethod
    def _parse_port(endpoint: str) -> int | None:
        text = endpoint.strip()
        if text.startswith("[") and "]:" in text:
            _, port_text = text.rsplit("]:", 1)
        elif ":" in text:
            _, port_text = text.rsplit(":", 1)
        else:
            return None
        try:
            return int(port_text)
        except ValueError:
            return None

    @staticmethod
    def _lookup_process_name(pid: int) -> str:
        if pid <= 0:
            return ""
        try:
            result = run_text_pumped(
                ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
                timeout=5,
                check=False,
                creationflags=_CREATE_NO_WINDOW,
            )
        except Exception:
            return ""
        rows = list(csv.reader(result_output_text(result).splitlines()))
        if not rows or not rows[0]:
            return ""
        name = rows[0][0].strip()
        if name.upper().startswith("INFO:"):
            return ""
        return name

    @staticmethod
    def _lookup_process_path(pid: int) -> Path | None:
        if os.name != "nt" or pid <= 0:
            return None
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.argtypes = (ctypes.c_uint32, ctypes.c_bool, ctypes.c_uint32)
        kernel32.OpenProcess.restype = ctypes.c_void_p
        kernel32.QueryFullProcessImageNameW.argtypes = (
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_wchar_p,
            ctypes.POINTER(ctypes.c_uint32),
        )
        kernel32.QueryFullProcessImageNameW.restype = ctypes.c_bool
        kernel32.CloseHandle.argtypes = (ctypes.c_void_p,)
        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            return None
        try:
            size = ctypes.c_uint32(32768)
            buffer = ctypes.create_unicode_buffer(size.value)
            if not kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
                return None
            return Path(buffer.value)
        finally:
            kernel32.CloseHandle(handle)

    @staticmethod
    def _same_path(left: Path, right: Path) -> bool:
        try:
            return os.path.normcase(str(left.resolve())) == os.path.normcase(str(right.resolve()))
        except OSError:
            return os.path.normcase(str(left)) == os.path.normcase(str(right))

    @staticmethod
    def _kill_pid(pid: int) -> bool:
        if pid <= 0:
            return False
        try:
            result = run_text_pumped(
                ["taskkill", "/PID", str(pid), "/T", "/F"],
                timeout=5,
                check=False,
                creationflags=_CREATE_NO_WINDOW,
            )
        except Exception:
            return False
        return result.returncode == 0

    @staticmethod
    def _port_conflict_message(port: int, role: str, pid: int, name: str) -> str:
        prefix = f"{role} порт {port}" if role else f"Порт {port}"
        owner = "другим процессом"
        if name == "другой VPN/прокси-клиент" and pid > 0:
            owner = f"другим VPN/прокси-клиентом (PID {pid})"
        elif name and pid > 0:
            owner = f"процессом {name} (PID {pid})"
        elif pid > 0:
            owner = f"PID {pid}"
        hint = ""
        if role == "HTTP":
            hint = " Измените HTTP порт в настройках или закройте конфликтующее приложение."
        elif role == "SOCKS":
            hint = " Измените SOCKS порт в настройках или закройте конфликтующее приложение."
        elif role == "API":
            hint = " Перезапустите приложение или завершите зависший Xray, который держит API порт."
        return f"{prefix} уже занят {owner}.{hint}"

    def _wait_until_ready(
        self,
        port_roles: dict[int, str],
        timeout_sec: float = 15.0,
        *,
        report_on_failure: bool = True,
    ) -> bool:
        if not port_roles:
            return True
        deadline = time.monotonic() + timeout_sec
        while time.monotonic() < deadline:
            pump_qt_events()
            if not self._proc_alive():
                if report_on_failure:
                    self._report_startup_failure(self._unexpected_exit_message(self._last_exit_code, startup=True))
                return False
            if all(self._is_port_ready(port) for port in port_roles):
                return True
            sleep_with_events(0.1)
        if report_on_failure:
            self.stop(expected=True)
            self._report_startup_failure(
                f"Xray запустился, но не открыл нужные порты: {self._not_ready_ports_detail(port_roles)}"
            )
        return False

    def _not_ready_ports_detail(self, port_roles: dict[int, str]) -> str:
        not_ready = [
            f"{role} {port}" if role else str(port)
            for port, role in port_roles.items()
            if not self._is_port_ready(port)
        ]
        return ", ".join(not_ready) if not_ready else "нужные порты"

    @staticmethod
    def _is_port_ready(port: int) -> bool:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            return False

    def _unexpected_exit_message(
        self,
        exit_code: int | None,
        *,
        startup: bool,
    ) -> str:
        stage = "во время запуска" if startup else "неожиданно"
        diagnostic = self._diagnose_output_failure(stage)
        if diagnostic:
            return diagnostic
        detail = self._best_output_detail()
        if detail:
            return f"Xray завершился {stage}: {detail}"
        if exit_code is None:
            return f"Xray завершился {stage}."
        status_name = "CrashExit" if exit_code < 0 else "NormalExit"
        return f"Xray завершился {stage} с кодом {exit_code} ({status_name})."

    def _report_startup_failure(self, message: str) -> None:
        if self._startup_failure_reported:
            return
        self._startup_failure_reported = True
        self.error.emit(message)

    def _best_output_detail(self) -> str:
        if not self._last_output_lines:
            return ""
        preferred_markers = ("panic:", "[xray-error]", "error", "failed", "invalid", "not found")
        for line in reversed(self._last_output_lines):
            clean = line.strip()
            lower = clean.lower()
            if any(marker in lower for marker in preferred_markers):
                return clean
        for line in reversed(self._last_output_lines):
            clean = line.strip()
            lower = clean.lower()
            if not clean:
                continue
            if clean.startswith("github.com/") or lower.startswith("goroutine ") or lower.startswith("[signal"):
                continue
            return clean
        return self._last_output_lines[-1].strip()

    def _diagnose_output_failure(self, stage: str) -> str | None:
        if not self._last_output_lines:
            return None
        joined = "\n".join(self._last_output_lines).lower()
        if "fakednspostprocessingstage" not in joined and "fakedns" not in joined:
            return None
        if "panic:" not in joined and "nil pointer dereference" not in joined:
            return None
        return (
            f"Xray завершился {stage}: текущий Xray core упал на секции FakeDNS в конфиге. "
            "Отключите FakeDNS в Xray JSON, сбросьте конфиг на шаблон по умолчанию или обновите Xray core."
        )


def get_xray_version(xray_path: str) -> str | None:
    exe = resolve_configured_path(
        xray_path,
        default_path=XRAY_PATH_DEFAULT,
        use_default_if_empty=True,
        migrate_default_location=True,
    )
    if exe is None:
        return None
    if not exe.exists():
        return None
    try:
        result = run_text_pumped(
            [str(exe), "version"],
            timeout=3,
            check=False,
            creationflags=_CREATE_NO_WINDOW,
        )
    except Exception:
        return None

    lines = result_output_text(result).splitlines()
    if not lines:
        return None
    return lines[0].strip()
