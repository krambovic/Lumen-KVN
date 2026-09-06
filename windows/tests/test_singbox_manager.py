from __future__ import annotations

import json
import threading
from types import SimpleNamespace

import xray_fluent.engines.singbox.manager as manager_module
from xray_fluent.engines.singbox.manager import SingBoxManager


def test_routine_connection_logs_are_suppressed_when_not_normalized() -> None:
    lines = [
        "INFO inbound/tun[tun-in]: inbound connection from 172.18.0.1:12345",
        "INFO inbound/tun[tun-in]: inbound packet connection to 172.18.0.2:53",
        "INFO outbound/vless[proxy]: outbound connection to 203.0.113.1:443",
        "ERROR connection: connection upload closed: wsarecv: connection was closed",
    ]

    assert all(SingBoxManager._is_noisy_runtime_line(line) for line in lines)


def test_actionable_runtime_errors_are_not_suppressed() -> None:
    lines = [
        "ERROR dns: exchange failed: context deadline exceeded",
        "FATAL start service: initialize rule-set failed",
        "ERROR connection: report handshake success: connection refused",
    ]

    assert not any(SingBoxManager._is_noisy_runtime_line(line) for line in lines)


def test_routine_process_and_dns_info_noise_is_suppressed() -> None:
    lines = [
        "INFO [12345 0ms] router: found process path: C:\\\\Program Files\\\\Google\\\\Chrome\\\\chrome.exe",
        "INFO [12345 1ms] dns: exchanged chatgpt.com. IN A 104.18.0.1",
        "INFO [12345 2ms] dns: lookup succeeded for claude.ai",
        "INFO [12345 0ms] dns: cached gemini.google.com. IN A",
    ]

    assert all(SingBoxManager._is_noisy_runtime_line(line) for line in lines)


def test_error_lines_win_over_info_noise_markers() -> None:
    # A line carrying an error token must never be suppressed even if it also
    # contains an info-noise marker like "dns:" or "found process".
    line = "ERROR [1 5.0s] dns: lookup failed for api.openai.com: i/o timeout context deadline"
    # This specific shape is recognised as repeated DNS runtime noise, but a
    # plain unexpected error with the same markers stays visible:
    plain = "ERROR router: found process failed unexpectedly"
    assert SingBoxManager._is_noisy_runtime_line(plain) is False


def test_repeated_dns_runtime_errors_stay_visible() -> None:
    lines = [
        "ERROR [1 10.0s] dns: exchange failed for www.msftconnecttest.com. IN A: context deadline exceeded",
        "WARN dns: bad question size: 0",
    ]

    assert not any(SingBoxManager._is_noisy_runtime_line(line) for line in lines)


def test_singbox_process_lookup_and_bad_question_noise_is_suppressed() -> None:
    lines = [
        "ERROR router: process DNS packet: unpack request: bad question name: dns: bad rdata",
        "INFO router: failed to search process: process not found for 172.18.0.1:63918",
        "INFO router: failed to search process: Access is denied.",
    ]

    assert all(SingBoxManager._is_noisy_runtime_line(line) for line in lines)


def test_windows_tun_readiness_uses_single_persistent_probe(monkeypatch) -> None:
    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(returncode=0)

    proc = SimpleNamespace(pid=1234, poll=lambda: None)
    monkeypatch.setattr(manager_module, "run_text_pumped", fake_run)

    assert SingBoxManager._wait_for_windows_tun_ready(proc, "tun0", 8.0)
    assert len(calls) == 1
    assert "Get-NetIPAddress" in calls[0][0][-1]


def test_native_core_ready_marker_skips_slow_windows_probe(monkeypatch) -> None:
    manager = SingBoxManager()
    manager._observe_startup_line("NOTICE sing-box started (0.42s)")
    proc = SimpleNamespace(poll=lambda: None)

    def unexpected_probe(*_args, **_kwargs):
        raise AssertionError("PowerShell readiness probe must be a fallback only")

    monkeypatch.setattr(manager, "_wait_for_windows_tun_ready", unexpected_probe)

    assert manager._wait_until_tun_ready(proc, "tun0", max_wait=1.0)


def test_direct_masque_confirmation_uses_native_handshake_marker() -> None:
    manager = SingBoxManager()
    manager._observe_startup_line(
        "NOTICE outbound/masque[proxy]: Connected to MASQUE server 162.159.198.2:443"
    )
    proc = SimpleNamespace(poll=lambda: None)

    assert manager._wait_for_profile_confirmation(proc, max_wait=0.1)


def test_transient_masque_error_does_not_override_later_handshake() -> None:
    manager = SingBoxManager()
    manager._observe_startup_line("ERROR outbound/masque[proxy]: tunnel not initialized")
    manager._observe_startup_line(
        "NOTICE outbound/masque[proxy]: Connected to MASQUE server 162.159.198.2:443"
    )
    proc = SimpleNamespace(poll=lambda: None)

    assert manager._wait_for_profile_confirmation(proc, max_wait=0.1)


def test_profile_initialization_error_fails_fast() -> None:
    manager = SingBoxManager()
    manager._observe_startup_line("ERROR outbound/masque[proxy]: tunnel not initialized")
    proc = SimpleNamespace(poll=lambda: None)

    assert not manager._wait_for_profile_startup_settle(proc, max_wait=1.0)


def test_fast_stop_does_not_block_on_adapter_release_probe(monkeypatch) -> None:
    class FakeProc:
        def __init__(self) -> None:
            self.returncode = None

        def poll(self):
            return self.returncode

        def terminate(self) -> None:
            self.returncode = 0

    manager = SingBoxManager()
    manager._proc = FakeProc()
    manager._tun_mode = True

    def unexpected_release_probe(*_args, **_kwargs):
        raise AssertionError("fast stop must not launch a PowerShell release probe")

    monkeypatch.setattr(manager, "_wait_tun_released", unexpected_release_probe)

    assert manager.stop(fast=True)


def test_startup_chatter_filter_never_hides_errors() -> None:
    assert SingBoxManager._is_startup_routine_line(
        "INFO outbound/masque[proxy]: outbound connection to 1.1.1.1:53"
    )
    assert not SingBoxManager._is_startup_routine_line(
        "ERROR outbound/masque[proxy]: tunnel not initialized"
    )


def test_proxy_runtime_ports_are_detected_without_tun() -> None:
    config = {
        "inbounds": [
            {"type": "mixed", "listen": "127.0.0.1", "listen_port": 10808},
            {"type": "http", "listen": "127.0.0.1", "listen_port": 10809},
        ]
    }

    assert SingBoxManager._extract_tun_interface_name(config) == ""
    assert SingBoxManager._extract_local_proxy_ports(config) == (10808, 10809)


def test_custom_warp_and_masque_require_runtime_readiness() -> None:
    assert SingBoxManager._requires_profile_outbound_readiness(
        {"endpoints": [{"type": "warp", "tag": "proxy"}]}
    )
    assert SingBoxManager._requires_profile_outbound_readiness(
        {"outbounds": [{"type": "masque", "tag": "proxy"}]}
    )
    assert not SingBoxManager._requires_profile_outbound_readiness(
        {
            "outbounds": [
                {
                    "type": "masque",
                    "tag": "proxy",
                    "server": "162.159.198.2",
                    "private_key": "private",
                    "public_key": "public",
                    "address": ["172.16.0.2/32"],
                }
            ]
        }
    )
    assert not SingBoxManager._requires_profile_outbound_readiness(
        {"endpoints": [{"type": "wireguard", "tag": "proxy", "amnezia": {"jc": 4}}]}
    )
    assert not SingBoxManager._requires_profile_outbound_readiness(
        {"endpoints": [{"type": "wireguard", "tag": "proxy"}]}
    )


def test_direct_masque_requires_lumen_compatible_core(monkeypatch, tmp_path) -> None:
    exe = tmp_path / "sing-box.exe"
    exe.write_bytes(b"upstream")
    config = {
        "outbounds": [
            {
                "type": "masque",
                "tag": "proxy",
                "server": "162.159.198.2",
                "private_key": "private",
                "public_key": "public",
                "address": ["172.16.0.2/32"],
            }
        ]
    }
    monkeypatch.setattr(
        manager_module,
        "get_singbox_version",
        lambda _path: "1.13.14-extended-2.5.1",
    )

    valid, detail = SingBoxManager().validate_config(str(exe), config)

    assert valid is False
    assert "Lumen-compatible" in detail
    assert "tunnel uninitialized" in detail


def test_direct_masque_compatibility_accepts_lumen_core(monkeypatch, tmp_path) -> None:
    exe = tmp_path / "sing-box.exe"
    exe.write_bytes(b"lumen")
    config = {
        "outbounds": [
            {
                "type": "masque",
                "tag": "proxy",
                "server": "162.159.198.2",
                "private_key": "private",
                "public_key": "public",
                "address": ["172.16.0.2/32"],
            }
        ]
    }
    monkeypatch.setattr(
        manager_module,
        "get_singbox_version",
        lambda _path: "1.13.14-extended-2.5.1-lumen.1",
    )
    monkeypatch.setattr(
        manager_module.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout=b"", stderr=b""),
    )

    valid, detail = SingBoxManager().validate_config(str(exe), config)

    assert valid is True
    assert detail == ""


def test_element_not_found_is_a_retryable_wintun_startup_race() -> None:
    manager = SingBoxManager()
    manager._last_output_lines.append(
        "FATAL start inbound/tun: configure tun interface: set ipv6 address: Element not found."
    )

    assert manager._startup_error_is_retryable()
    assert manager._startup_error_is_stale_adapter()


def test_ipv6_auto_disable_strips_the_ipv6_prefix_the_planner_emits(monkeypatch, tmp_path) -> None:
    config_path = tmp_path / "singbox.json"
    config_path.write_text(
        json.dumps(
            {
                "inbounds": [
                    {
                        "type": "tun",
                        "tag": "tun-in",
                        "address": ["172.18.0.1/30", "fdfe:dcba:9876::1/126"],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(manager_module, "SINGBOX_CONFIG_FILE", config_path)

    manager = SingBoxManager()
    logs: list[str] = []
    manager.log_received.connect(logs.append)

    manager._disable_ipv6_in_singbox_config()

    payload = json.loads(config_path.read_text(encoding="utf-8"))

    assert payload["inbounds"][0]["address"] == ["172.18.0.1/30"]
    assert not any("Failed to auto-disable" in line for line in logs)


def test_startup_classifiers_survive_concurrent_reader_output() -> None:
    manager = SingBoxManager()
    for index in range(100):
        manager._last_output_lines.append(f"INFO line {index}")

    stop = threading.Event()

    def append_output() -> None:
        while not stop.is_set():
            with manager._lock:
                manager._last_output_lines.append("INFO more output")

    writer = threading.Thread(target=append_output, name="fake-output-reader", daemon=True)
    writer.start()
    try:
        for _ in range(200):
            assert manager._startup_error_is_retryable() is False
            assert manager._startup_error_is_stale_adapter() is False
            assert manager._startup_error_is_ipv6_disabled() is False
    finally:
        stop.set()
        writer.join(2.0)


def test_reader_does_not_report_transient_startup_exit_before_retry() -> None:
    manager = SingBoxManager()
    proc = SimpleNamespace(returncode=1)
    manager._proc = proc
    manager._starting = True
    errors: list[str] = []
    stopped: list[int] = []
    manager.error.connect(errors.append)
    manager.stopped.connect(stopped.append)

    manager._handle_process_exit(proc)

    assert errors == []
    assert stopped == []
    assert manager._last_exit_code == 1


def test_singbox_exit_during_windows_shutdown_is_not_reported_as_runtime_error(monkeypatch) -> None:
    manager = SingBoxManager()
    proc = SimpleNamespace(returncode=1)
    manager._proc = proc
    manager._running = True
    errors: list[str] = []
    manager.error.connect(errors.append)
    monkeypatch.setattr(manager_module, "is_windows_shutting_down", lambda: True)

    manager._handle_process_exit(proc)

    assert errors == []
