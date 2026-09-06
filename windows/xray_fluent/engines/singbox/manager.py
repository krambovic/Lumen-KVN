from __future__ import annotations

from collections import deque
from ipaddress import ip_network
import json
import os
import re
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

from PyQt6.QtCore import QObject, pyqtSignal

from ...constants import (
    PROXY_HOST,
    RUNTIME_DIR,
    SINGBOX_CLASH_API_PORT,
    SINGBOX_CONFIG_FILE,
    SINGBOX_LEGACY_TUN_INTERFACE_NAMES,
    SINGBOX_PATH_DEFAULT,
    SINGBOX_TUN_INTERFACE_NAME,
)
from ...path_utils import resolve_configured_path
from ...process_conflicts import is_process_name_running
from ...log_utils import is_routine_core_log
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
_MANAGED_TUN_ADAPTER_NAMES_PS = ",".join(
    f"'{name}'" for name in (*SINGBOX_LEGACY_TUN_INTERFACE_NAMES, SINGBOX_TUN_INTERFACE_NAME)
)
_MANAGED_TUN_ADAPTER_FILTER_PS = (
    f"($_.Name -ne '{SINGBOX_TUN_INTERFACE_NAME}') -or "
    "($_.InterfaceDescription -match '(?i)wintun|sing.?box')"
)


def _is_ipv4_prefix(value: Any) -> bool:
    try:
        return ip_network(str(value), strict=False).version == 4
    except ValueError:
        return False


class SingBoxManager(QObject):
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
        self._starting = False
        self._stop_requested = False
        self._startup_failure_reported = False
        self._runtime_error_reported = False
        # Keep enough startup context to retain the original WARP/MASQUE
        # initialization error even when subsequent DNS requests repeat the
        # shorter "endpoint/tunnel not initialized" message.
        self._last_output_lines: deque[str] = deque(maxlen=100)
        self._last_exit_code: int | None = None
        self._exe_path: Path | None = None
        self._tun_mode = True
        # sing-box's own ready marker is a better startup boundary than a
        # separate PowerShell route/DNS probe.  The latter used to keep the UI
        # in "connecting" for several seconds after real traffic was already
        # flowing through the TUN adapter.
        self._core_ready_event = threading.Event()
        self._profile_ready_event = threading.Event()
        self._profile_error_event = threading.Event()

    @property
    def is_running(self) -> bool:
        return self._running

    def _proc_alive(self) -> bool:
        proc = self._proc
        return proc is not None and proc.poll() is None

    def validate_config(self, singbox_path: str, config: dict[str, Any]) -> tuple[bool, str]:
        exe = resolve_configured_path(
            singbox_path,
            default_path=SINGBOX_PATH_DEFAULT,
            use_default_if_empty=True,
            migrate_default_location=True,
        )
        if exe is None or not exe.is_file():
            return False, f"sing-box.exe not found: {exe or singbox_path}"
        compatibility_error = self._direct_masque_compatibility_error(exe, config)
        if compatibility_error:
            return False, compatibility_error
        RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
        config_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                suffix=".json",
                prefix="singbox-check-",
                dir=RUNTIME_DIR,
                delete=False,
            ) as handle:
                json.dump(config, handle, ensure_ascii=True, indent=2)
                config_path = Path(handle.name)
            result = subprocess.run(
                [str(exe), "check", "-c", str(config_path), "-D", str(exe.parent)],
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
            return False, "sing-box config check timed out after 20 seconds"
        except Exception as exc:
            return False, f"failed to check sing-box config: {exc}"
        finally:
            if config_path is not None:
                config_path.unlink(missing_ok=True)

    def start(
        self,
        singbox_path: str,
        config: dict[str, Any],
        *,
        prevalidated: bool = False,
    ) -> bool:
        exe = resolve_configured_path(
            singbox_path,
            default_path=SINGBOX_PATH_DEFAULT,
            use_default_if_empty=True,
            migrate_default_location=True,
        )
        if exe is None:
            self.error.emit("sing-box path is not configured (set it in Settings → Core paths)")
            return False
        if not exe.is_file():
            self.error.emit(f"sing-box.exe not found: {exe}")
            return False
        self._exe_path = exe

        if not prevalidated:
            valid, validation_output = self.validate_config(str(exe), config)
            if not valid:
                detail = validation_output or "unknown config validation error"
                self.error.emit(f"sing-box does not accept the new config: {detail}")
                return False

        tun_interface_name = self._extract_tun_interface_name(config)
        proxy_ports = self._extract_local_proxy_ports(config)
        requires_profile_readiness = self._requires_profile_outbound_readiness(config)
        requires_profile_confirmation = self._requires_lumen_direct_masque(config)
        self._tun_mode = bool(tun_interface_name)
        if not self._tun_mode and not proxy_ports:
            self.error.emit("sing-box config does not contain a TUN or local proxy inbound")
            return False

        RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
        SINGBOX_CONFIG_FILE.write_text(
            json.dumps(config, ensure_ascii=True, indent=2), encoding="utf-8"
        )

        if self._proc_alive():
            if not self.stop(expected=True, fast=True):
                self.error.emit("failed to stop previous sing-box process")
                return False
        elif self._running:
            self._running = False
            self.state_changed.emit(False)

        # Kill only orphaned processes before start. The stable tun0
        # adapter is reused by Wintun; retry cleanup handles real conflicts.
        self._kill_orphaned(exe)

        # A freshly killed sing-box can still hold the clash-api port; wait for it.
        self._wait_clash_api_port_released()

        # Set working directory to core/ so sing-box can find wintun.dll
        core_dir = exe.parent
        self._starting = True
        self._startup_failure_reported = False
        self._runtime_error_reported = False
        with self._lock:
            self._last_output_lines.clear()

        # Retry only actual Wintun/socket races. Profile initialization errors
        # are deterministic for a given config, so repeating the whole startup
        # only turns a useful failure into a long UI stall.
        max_attempts = 1 if requires_profile_readiness or requires_profile_confirmation else 3
        for attempt in range(max_attempts):
            attempt_started = time.monotonic()
            runtime_label = f"TUN interface={tun_interface_name}" if self._tun_mode else f"proxy ports={proxy_ports}"
            self.log_received.emit(
                f"[sing-box] startup attempt {attempt + 1}/{max_attempts}, {runtime_label}"
            )
            with self._lock:
                self._last_output_lines.clear()
            self._core_ready_event.clear()
            self._profile_ready_event.clear()
            self._profile_error_event.clear()
            self._stop_requested = False
            self._last_exit_code = None

            try:
                proc = subprocess.Popen(
                    [str(exe), "run", "-c", str(SINGBOX_CONFIG_FILE), "-D", str(core_dir)],
                    cwd=str(core_dir),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    stdin=subprocess.DEVNULL,
                    bufsize=0,
                    creationflags=_CREATE_NO_WINDOW,
                )
            except Exception as exc:
                self._starting = False
                self._report_startup_failure(f"failed to start sing-box process: {exc}")
                return False

            with self._lock:
                self._proc = proc
            self._reader = threading.Thread(
                target=self._read_output,
                args=(proc,),
                name="singbox-output-reader",
                daemon=True,
            )
            self._reader.start()

            profile_readiness_failed = False
            ready = (
                self._wait_until_tun_ready(proc, tun_interface_name)
                if self._tun_mode
                else self._wait_until_proxy_ready(proc, proxy_ports)
            )
            if ready:
                ready_ms = int((time.monotonic() - attempt_started) * 1000)
                ready_label = "core and TUN" if self._tun_mode else "local proxy inbounds"
                self.log_received.emit(f"[sing-box] {ready_label} ready in {ready_ms} ms")
                if self._tun_mode:
                    if requires_profile_confirmation:
                        ready = self._wait_for_profile_confirmation(proc, max_wait=3.0)
                        profile_readiness_failed = not ready
                    elif requires_profile_readiness and not self._wait_for_profile_startup_settle(
                        proc,
                        max_wait=0.4,
                    ):
                        profile_readiness_failed = True
                        ready = False
                if ready:
                    self._starting = False
                    total_ms = int((time.monotonic() - attempt_started) * 1000)
                    self.log_received.emit(
                        f"[sing-box] runtime ready in {total_ms} ms, {runtime_label}"
                    )
                    self._mark_running()
                    return True
                if profile_readiness_failed:
                    suffix = "; retrying" if attempt + 1 < max_attempts else ""
                    self.log_received.emit(
                        f"[sing-box] WARP/MASQUE outbound did not become ready{suffix}"
                    )
                else:
                    suffix = "; retrying" if attempt + 1 < max_attempts else ""
                    self.log_received.emit(
                        f"[sing-box] TUN did not become ready{suffix}"
                    )

            exited = not self._proc_alive()
            retryable = exited and self._startup_error_is_retryable()
            if not exited:
                self.stop(expected=True, fast=True)
                if self._tun_mode and attempt + 1 < max_attempts:
                    self.cleanup_orphaned_tun_adapters()
                    self._wait_tun_released()
                    self._wait_clash_api_port_released()
                    self._starting = True
                    continue

            if self._tun_mode and retryable and attempt + 1 < max_attempts:
                self._kill_orphaned(exe)
                if self._startup_error_is_ipv6_disabled():
                    self._disable_ipv6_in_singbox_config()
                elif self._startup_error_is_stale_adapter():
                    self._purge_stale_wintun_devices()  # ghost Wintun device is invisible to Get-NetAdapter cleanup
                self.cleanup_orphaned_tun_adapters()
                self._wait_tun_released()
                self._wait_clash_api_port_released()
                self._starting = True
                continue

            self._starting = False
            if self._tun_mode:
                self.cleanup_orphaned_tun_adapters()
            if self._tun_mode and exited and self._startup_error_is_stale_adapter():
                self._purge_stale_wintun_devices()  # clear the ghost so the next connect attempt can succeed
            if exited:
                self._report_startup_failure(
                    self._unexpected_exit_message(self._last_exit_code, startup=True)
                )
            elif profile_readiness_failed:
                self._report_startup_failure(self._profile_outbound_not_ready_message())
            elif self._tun_mode:
                self._report_startup_failure(self._tun_not_ready_message(tun_interface_name))
            else:
                self._report_startup_failure(f"sing-box local proxy ports did not become ready: {proxy_ports}")
            return False

        self._starting = False
        return False

    @staticmethod
    def _kill_orphaned(exe: Path) -> None:
        """Kill orphaned sing-box processes that hold the TUN adapter."""
        if os.name != "nt":
            return
        if not is_process_name_running(exe.name):
            return
        try:
            if kill_processes_by_path(exe.name, exe, timeout=5):
                sleep_with_events(1.0)
        except Exception:
            pass

    def stop(self, expected: bool = True, *, fast: bool = False) -> bool:
        already_stopped = False
        with self._lock:
            proc = self._proc
            if proc is None or proc.poll() is not None:
                self._stop_requested = False
                self._starting = False
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

        if not self._wait_proc(proc, terminate_timeout):
            try:
                proc.kill()
            except Exception:
                pass
            self._wait_proc(proc, kill_timeout)

        if proc.poll() is None:
            exe = self._exe_path
            if os.name == "nt" and exe is not None:
                try:
                    if kill_processes_by_path(exe.name, exe, timeout=orphan_timeout):
                        self._wait_proc(proc, final_timeout)
                except Exception:
                    pass

        if proc.poll() is None:
            self._stop_requested = False
            if not is_windows_shutting_down():
                self.error.emit("failed to stop sing-box process in time")
            return False

        # Let sing-box/Wintun perform the normal adapter teardown. Disabling a
        # healthy adapter here makes Windows rebuild its network state on every
        # reconnect and delays the first real connections. Do not start a
        # PowerShell adapter-release probe here either: retry handling already
        # covers the rare Wintun race, while the probe delayed every hot-swap.
        self._starting = False
        self._join_reader()
        return True

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

    @staticmethod
    def _wait_tun_released(max_wait: float = 10.0) -> None:
        """Poll until the TUN adapter is gone, up to max_wait seconds."""
        if os.name != "nt":
            return
        step = 0.3
        waited = 0.0
        while waited < max_wait:
            try:
                result = run_text_pumped(
                    [
                        "powershell",
                        "-NoProfile",
                        "-NonInteractive",
                        "-Command",
                        (
                            f"$active = @(Get-NetAdapter -Name @({_MANAGED_TUN_ADAPTER_NAMES_PS}) -ErrorAction SilentlyContinue "
                            f"| Where-Object {{ ({_MANAGED_TUN_ADAPTER_FILTER_PS}) -and "
                            "$_.Status -notin @('Disabled','Not Present') }); "
                            "if ($active.Count -eq 0) { exit 0 } else { exit 1 }"
                        ),
                    ],
                    timeout=3,
                    check=False,
                    creationflags=_CREATE_NO_WINDOW,
                )
                if result.returncode == 0:
                    return
            except Exception:
                return  # can't check, proceed anyway
            sleep_with_events(step)
            waited += step

    @staticmethod
    def _wait_clash_api_port_released(max_wait: float = 5.0) -> None:
        """Wait until the clash-api controller port can be bound again."""
        if os.name != "nt":
            return
        waited = 0.0
        step = 0.2
        while waited < max_wait:
            probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                probe.bind((PROXY_HOST, SINGBOX_CLASH_API_PORT))
                return
            except OSError:
                pass
            finally:
                probe.close()
            sleep_with_events(step)
            waited += step

    @staticmethod
    def cleanup_orphaned_tun_adapters(max_wait: float = 5.0) -> None:
        """Remove routes from app-owned sing-box TUN adapters and disable them."""
        if os.name != "nt" or is_windows_shutting_down():
            return
        script = (
            "$ErrorActionPreference = 'SilentlyContinue'; "
            f"$adapters = @(Get-NetAdapter -Name @({_MANAGED_TUN_ADAPTER_NAMES_PS}) -ErrorAction SilentlyContinue "
            f"| Where-Object {{ {_MANAGED_TUN_ADAPTER_FILTER_PS} }}); "
            "foreach ($adapter in $adapters) { "
            "$alias = $adapter.Name; "
            "Get-NetRoute -InterfaceAlias $alias -ErrorAction SilentlyContinue "
            "| Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue; "
            "Disable-NetAdapter -Name $alias -Confirm:$false -ErrorAction SilentlyContinue; "
            "}"
        )
        try:
            run_text_pumped(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                timeout=max_wait,
                check=False,
                creationflags=_CREATE_NO_WINDOW,
            )
        except Exception:
            pass

    def _purge_stale_wintun_devices(self, max_wait: float = 20.0) -> None:
        """Remove ghost Wintun device instances that block 'create adapter'."""
        if os.name != "nt":
            return
        script = (
            "$ErrorActionPreference = 'SilentlyContinue'; "
            "$ghosts = @(Get-PnpDevice -Class Net -ErrorAction SilentlyContinue "
            "| Where-Object { ($_.InstanceId -like 'SWD\\WINTUN*') -and ($_.Status -ne 'OK') }); "
            "foreach ($dev in $ghosts) { pnputil /remove-device \"$($dev.InstanceId)\" | Out-Null }; "
            "Write-Output $ghosts.Count"
        )
        try:
            result = run_text_pumped(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                timeout=max_wait,
                check=False,
                creationflags=_CREATE_NO_WINDOW,
            )
            lines = result_output_text(result).strip().splitlines()
            count = lines[-1].strip() if lines else "0"
            self.log_received.emit(f"[tun] purged {count} stale Wintun device(s)")
        except Exception:
            pass

    def _read_output(self, proc: subprocess.Popen[bytes]) -> None:
        stream = proc.stdout
        try:
            if stream is not None:
                for raw in iter(stream.readline, b""):
                    text = decode_output(raw)
                    for line in text.splitlines():
                        clean = line.rstrip()
                        if clean:
                            with self._lock:
                                self._last_output_lines.append(clean)
                            self._observe_startup_line(clean)
                            # Windows can send captured DNS and connection
                            # traffic to the adapter before sing-box prints its
                            # final ready marker.  Hide only that routine chatter
                            # during this short startup window; failures and all
                            # logs after the manager has published its running
                            # state remain visible verbatim.
                            if not self._running and self._is_startup_routine_line(clean):
                                continue
                            self.log_received.emit(clean)
        except Exception:
            pass
        finally:
            try:
                proc.wait()
            except Exception:
                pass
            self._handle_process_exit(proc)

    def _handle_process_exit(self, proc: subprocess.Popen[bytes]) -> None:
        with self._lock:
            if proc is not self._proc:
                # A newer process superseded this handle; ignore the stale exit.
                return
            exit_code = proc.returncode if proc.returncode is not None else -1
            expected = self._stop_requested or is_windows_shutting_down()
            was_starting = self._starting
            was_running = self._running
            self._last_exit_code = exit_code
            self._stop_requested = False
            self._running = False
            self._proc = None

        # start() owns startup retries and reports only the final failure.  The
        # reader thread used to report the first transient exit immediately,
        # before start() could retry a Wintun race.
        if was_running and not expected and not self._runtime_error_reported:
            if self._tun_mode:
                self.cleanup_orphaned_tun_adapters()
            self._runtime_error_reported = True
            self.error.emit(self._unexpected_exit_message(exit_code, startup=False))
        # A failed startup attempt is an internal detail.  Emitting `stopped`
        # here makes the controller log it as a final core crash even when the
        # next Wintun attempt succeeds a moment later.
        if not was_starting:
            self.stopped.emit(exit_code)
        if was_running:
            self.state_changed.emit(False)

    def _mark_running(self) -> None:
        if self._running:
            return
        self._stop_requested = False
        self._running = True
        self.started.emit()
        self.state_changed.emit(True)

    def _observe_startup_line(self, line: str) -> None:
        """Translate native core markers into thread-safe startup events."""
        text = str(line or "").lower()
        if "sing-box started" in text:
            self._core_ready_event.set()
        if "connected to masque server" in text:
            self._profile_ready_event.set()
        if "tunnel not initialized" in text or "endpoint not initialized" in text:
            self._profile_error_event.set()

    @staticmethod
    def _extract_tun_interface_name(config: dict[str, Any]) -> str:
        for inbound in config.get("inbounds") or []:
            if not isinstance(inbound, dict):
                continue
            if str(inbound.get("type") or "").strip().lower() != "tun":
                continue
            return str(inbound.get("interface_name") or "").strip()
        return ""

    @staticmethod
    def _extract_local_proxy_ports(config: dict[str, Any]) -> tuple[int, ...]:
        ports: list[int] = []
        for inbound in config.get("inbounds") or []:
            if not isinstance(inbound, dict):
                continue
            inbound_type = str(inbound.get("type") or "").strip().lower()
            if inbound_type not in {"mixed", "socks", "http"}:
                continue
            try:
                port = int(inbound.get("listen_port") or inbound.get("port") or 0)
            except (TypeError, ValueError):
                continue
            if 0 < port <= 65535 and port not in ports:
                ports.append(port)
        return tuple(ports)

    @staticmethod
    def _requires_profile_outbound_readiness(config: dict[str, Any]) -> bool:
        """Return whether adapter readiness alone cannot prove connectivity."""
        for section in ("outbounds", "endpoints"):
            for item in config.get(section) or []:
                if not isinstance(item, dict):
                    continue
                item_type = str(item.get("type") or "").strip().lower()
                if item_type == "warp":
                    return True
                if item_type == "masque" and not (
                    item.get("server")
                    and item.get("private_key")
                    and item.get("public_key")
                    and item.get("address")
                ):
                    return True
        return False

    @staticmethod
    def _requires_lumen_direct_masque(config: dict[str, Any]) -> bool:
        """Return whether the config uses Lumen's raw Clash/usque MASQUE fields."""
        for outbound in config.get("outbounds") or []:
            if not isinstance(outbound, dict):
                continue
            if str(outbound.get("type") or "").strip().lower() != "masque":
                continue
            if all(
                (
                    outbound.get("server"),
                    outbound.get("private_key"),
                    outbound.get("public_key"),
                    outbound.get("address"),
                )
            ):
                return True
        return False

    @classmethod
    def _direct_masque_compatibility_error(
        cls,
        exe: Path,
        config: dict[str, Any],
    ) -> str:
        if not cls._requires_lumen_direct_masque(config):
            return ""
        version = get_singbox_version(str(exe)) or ""
        if re.search(r"-lumen(?:\.|\b)", version, flags=re.IGNORECASE):
            return ""
        rendered = version or "unknown"
        return (
            "This MASQUE profile requires the Lumen-compatible sing-box core "
            f"(installed: {rendered}). Reinstall or update Lumen; the regular "
            "sing-box extended build ignores raw MASQUE keys and leaves the tunnel uninitialized."
        )

    @staticmethod
    def _wait_until_proxy_ready(
        proc: subprocess.Popen[bytes],
        ports: tuple[int, ...],
        max_wait: float = 10.0,
    ) -> bool:
        deadline = time.monotonic() + max_wait
        while time.monotonic() < deadline and proc.poll() is None:
            all_ready = True
            for port in ports:
                try:
                    with socket.create_connection((PROXY_HOST, port), timeout=0.15):
                        pass
                except OSError:
                    all_ready = False
                    break
            if all_ready:
                return True
            pump_qt_events()
            time.sleep(0.05)
        return False

    def _wait_until_tun_ready(
        self,
        proc: subprocess.Popen[bytes],
        tun_interface_name: str,
        max_wait: float = 20.0,
    ) -> bool:
        # `NOTICE sing-box started` is emitted after the TUN service has been
        # initialized.  In real logs traffic already flows before the slower
        # Get-NetIPAddress/Get-NetRoute probe returns, so use the native marker
        # as the primary readiness contract and keep the Windows probe only as
        # a compatibility fallback for cores that do not print it.
        marker_wait = min(max_wait, 5.0)
        deadline = time.monotonic() + marker_wait
        while time.monotonic() < deadline and proc.poll() is None:
            if self._core_ready_event.wait(0.05):
                return proc.poll() is None
            pump_qt_events()

        if proc.poll() is not None:
            return False
        if os.name == "nt":
            remaining = max(0.2, max_wait - marker_wait)
            return self._wait_for_windows_tun_ready(proc, tun_interface_name, remaining)
        return True

    def _wait_for_profile_confirmation(
        self,
        proc: subprocess.Popen[bytes],
        *,
        max_wait: float,
    ) -> bool:
        """Wait for the patched direct-MASQUE handshake, without DNS probes."""
        deadline = time.monotonic() + max(0.0, max_wait)
        while time.monotonic() < deadline and proc.poll() is None:
            if self._profile_ready_event.wait(0.05):
                return proc.poll() is None
            pump_qt_events()
        return self._profile_ready_event.is_set() and proc.poll() is None

    def _wait_for_profile_startup_settle(
        self,
        proc: subprocess.Popen[bytes],
        *,
        max_wait: float,
    ) -> bool:
        """Give lazy WARP/profile endpoints a brief error-detection window."""
        deadline = time.monotonic() + max(0.0, max_wait)
        while time.monotonic() < deadline and proc.poll() is None:
            if self._profile_error_event.wait(0.05):
                return False
            pump_qt_events()
        return proc.poll() is None and not self._profile_error_event.is_set()

    @staticmethod
    def _wait_for_windows_tun_ready(
        proc: subprocess.Popen[bytes],
        tun_interface_name: str,
        max_wait: float,
    ) -> bool:
        escaped_name = tun_interface_name.replace("'", "''")
        wait_ms = max(200, int(max_wait * 1000))
        script = (
            f"$deadline = [DateTime]::UtcNow.AddMilliseconds({wait_ms}); "
            f"while ([DateTime]::UtcNow -lt $deadline) {{ "
            f"if (-not (Get-Process -Id {int(proc.pid)} -ErrorAction SilentlyContinue)) {{ exit 2 }}; "
            f"$ipv4 = Get-NetIPAddress -InterfaceAlias '{escaped_name}' -AddressFamily IPv4 "
            "-ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -and $_.IPAddress -ne '0.0.0.0' } "
            "| Select-Object -First 1 IPAddress; "
            f"$route = Get-NetRoute -InterfaceAlias '{escaped_name}' -AddressFamily IPv4 "
            "-ErrorAction SilentlyContinue | Where-Object { "
            "$_.DestinationPrefix -in @('0.0.0.0/0','0.0.0.0/1','128.0.0.0/1') } "
            "| Select-Object -First 1 DestinationPrefix; "
            "if ($ipv4 -and $route) { exit 0 }; Start-Sleep -Milliseconds 75 }; exit 1"
        )
        try:
            result = run_text_pumped(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                timeout=max_wait + 2.0,
                check=False,
                creationflags=_CREATE_NO_WINDOW,
            )
        except Exception:
            return False
        return result.returncode == 0 and proc.poll() is None

    def _output_snapshot(self) -> tuple[str, ...]:
        # The reader thread appends while start()/stop() classify; iterate a copy
        # so CPython never raises "deque mutated during iteration".
        with self._lock:
            return tuple(self._last_output_lines)

    def _startup_error_is_retryable(self) -> bool:
        needles = (
            "already exists",
            "cannot create a file when that file already exists",
            "only one usage of each socket address",
            "external controller listen error",
            "address already in use",
            "bind:",
            "element not found",
        )
        for line in self._output_snapshot():
            text = line.lower()
            if any(needle in text for needle in needles):
                return True
        return False

    def _profile_outbound_not_ready_message(self) -> str:
        marker_detail = ""
        for line in reversed(self._output_snapshot()):
            text = str(line).lower()
            if "tunnel not initialized" in text or "endpoint not initialized" in text:
                marker_detail = str(line).strip()
                break
        suffix = f" Last core error: {marker_detail}" if marker_detail else ""
        return (
            "sing-box could not initialize the WARP/MASQUE profile outbound; "
            "TUN was stopped instead of being reported as connected."
            + suffix
        )

    def _startup_error_is_stale_adapter(self) -> bool:
        needles = (
            "create adapter",
            "open existing adapter",
            "element not found",
        )
        for line in self._output_snapshot():
            text = line.lower()
            if any(needle in text for needle in needles):
                return True
        return False

    def _startup_error_is_ipv6_disabled(self) -> bool:
        return any(
            "set ipv6 address" in line.lower()
            for line in self._output_snapshot()
        )

    def _disable_ipv6_in_singbox_config(self) -> None:
        try:
            with open(SINGBOX_CONFIG_FILE, "r", encoding="utf-8") as f:
                config = json.load(f)
            modified = False
            for inbound in config.get("inbounds", []):
                if not isinstance(inbound, dict) or inbound.get("type") != "tun":
                    continue
                inbound.pop("inet6_address", None)
                addresses = inbound.get("address")
                if not isinstance(addresses, list):
                    continue
                ipv4_only = [prefix for prefix in addresses if _is_ipv4_prefix(prefix)]
                if ipv4_only != addresses:
                    inbound["address"] = ipv4_only
                    modified = True
            if modified:
                with open(SINGBOX_CONFIG_FILE, "w", encoding="utf-8") as f:
                    json.dump(config, f, indent=2, ensure_ascii=False)
                self.log_received.emit("[sing-box] Automatically disabled IPv6 for TUN due to broken Windows IPv6 stack.")
        except Exception as e:
            self.log_received.emit(f"[sing-box] Failed to auto-disable TUN IPv6: {type(e).__name__}: {e}")

    def _tun_not_ready_message(self, tun_interface_name: str) -> str:
        markers = (
            "open interface take too much time",
            "configure tun interface",
            "wintun",
            "create adapter",
        )
        for line in self._output_snapshot():
            text = str(line).lower()
            if any(marker in text for marker in markers):
                return (
                    f"sing-box did not open the Wintun TUN adapter '{tun_interface_name}': "
                    "opening the interface stalls. Common Windows-side causes: TUN address/subnet "
                    "172.18.0.1/30 collides with an existing adapter (Docker/WSL/Hyper-V 172.18.0.0/16), "
                    "a stale hidden TUN adapter, a stopped Base Filtering Engine service, "
                    "or another VPN's network filter driver."
                )
        return (
            f"sing-box started but TUN interface '{tun_interface_name}' "
            "did not get an address and route in time."
        )

    def _unexpected_exit_message(
        self,
        exit_code: int | None,
        *,
        startup: bool,
    ) -> str:
        stage = "during startup" if startup else "unexpectedly"
        lines = self._output_snapshot()
        detail = lines[-1].strip() if lines else ""
        if detail:
            return f"sing-box exited {stage}: {detail}"
        if exit_code is None:
            return f"sing-box exited {stage}."
        status_name = "CrashExit" if exit_code < 0 else "NormalExit"
        return f"sing-box exited {stage} with code {exit_code} ({status_name})."

    def _report_startup_failure(self, message: str) -> None:
        if self._startup_failure_reported:
            return
        self._startup_failure_reported = True
        self.error.emit(message)

    @staticmethod
    def _is_noisy_runtime_line(line: str) -> bool:
        return is_routine_core_log(line)

    @classmethod
    def _is_startup_routine_line(cls, line: str) -> bool:
        text = str(line or "").lower()
        if any(marker in text for marker in ("error", "failed", "fatal", "panic")):
            return False
        return cls._is_noisy_runtime_line(line)


def get_singbox_version(singbox_path: str) -> str | None:
    exe = resolve_configured_path(
        singbox_path,
        default_path=SINGBOX_PATH_DEFAULT,
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
    first_line = lines[0].strip()
    match = re.search(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?", first_line)
    return match.group(0) if match else first_line
