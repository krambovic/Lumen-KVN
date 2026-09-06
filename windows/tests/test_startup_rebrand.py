from __future__ import annotations

from pathlib import Path

from xray_fluent import app_updater
from xray_fluent import startup
from xray_fluent.qml_app import main_qml


def test_legacy_registry_cleanup_covers_all_app_owned_identities() -> None:
    assert r"Software\Classes\lumen-kvn" in startup.LEGACY_PROTOCOL_KEYS
    assert r"Software\Classes\AppUserModelId\Lumen.LumenKVN" in startup.LEGACY_PROTOCOL_KEYS
    assert r"Software\Classes\Applications\LumenKVN.exe" in startup.LEGACY_PROTOCOL_KEYS
    assert r"Software\Microsoft\Windows\CurrentVersion\App Paths\LumenKVN.exe" in startup.LEGACY_PROTOCOL_KEYS
    assert (
        r"Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Lumen.LumenKVN"
        in startup.LEGACY_PROTOCOL_KEYS
    )


def test_legacy_shell_shortcuts_and_start_menu_groups_are_removed(
    tmp_path: Path,
    monkeypatch,
) -> None:
    appdata = tmp_path / "AppData" / "Roaming"
    program_data = tmp_path / "ProgramData"
    user_profile = tmp_path / "User"
    public_profile = tmp_path / "Public"
    monkeypatch.setenv("APPDATA", str(appdata))
    monkeypatch.setenv("ProgramData", str(program_data))
    monkeypatch.setenv("USERPROFILE", str(user_profile))
    monkeypatch.setenv("PUBLIC", str(public_profile))

    old_group = appdata / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Lumen KVN"
    old_group.mkdir(parents=True)
    (old_group / "Lumen KVN.lnk").write_bytes(b"shortcut")
    old_startup = (
        program_data
        / "Microsoft"
        / "Windows"
        / "Start Menu"
        / "Programs"
        / "Startup"
        / "LumenKVN.lnk"
    )
    old_startup.parent.mkdir(parents=True)
    old_startup.write_bytes(b"shortcut")
    old_desktop = user_profile / "Desktop" / "lumen-kvn.lnk"
    old_desktop.parent.mkdir(parents=True)
    old_desktop.write_bytes(b"shortcut")

    startup._cleanup_legacy_shell_entries()

    assert not old_group.exists()
    assert not old_startup.exists()
    assert not old_desktop.exists()


def test_legacy_bridge_uses_canonical_executable_for_startup(tmp_path: Path, monkeypatch) -> None:
    legacy = tmp_path / "LumenKVN.exe"
    canonical = tmp_path / "Lumen.exe"
    legacy.write_bytes(b"bridge")
    canonical.write_bytes(b"app")
    monkeypatch.setattr(startup.sys, "frozen", True, raising=False)
    monkeypatch.setattr(startup.sys, "executable", str(legacy))

    command = startup.build_startup_command()

    assert str(canonical) in command
    assert str(legacy) not in command


def test_development_admin_relaunch_prefers_pythonw_beside_active_interpreter(
    tmp_path: Path, monkeypatch
) -> None:
    python = tmp_path / "python.exe"
    pythonw = tmp_path / "pythonw.exe"
    python.write_bytes(b"console interpreter")
    pythonw.write_bytes(b"windowless interpreter")
    monkeypatch.setattr(startup.sys, "frozen", False, raising=False)
    monkeypatch.setattr(startup.sys, "executable", str(python))
    monkeypatch.setattr(startup.sys, "argv", ["run_qml.py"])

    executable, _arguments, _working_dir = startup._admin_launch_command()

    assert executable == pythonw.resolve()


def test_internal_relaunch_never_starts_hidden_in_tray() -> None:
    assert main_qml._should_start_in_tray(["Lumen.exe", "--tray"]) is True
    assert main_qml._should_start_in_tray(
        ["Lumen.exe", "--tray", "--relaunched"]
    ) is False
    assert main_qml._should_start_in_tray(
        ["Lumen.exe", "--tray", "--relaunch-as-admin"]
    ) is False


def test_admin_relaunch_drops_autostart_tray_flag(tmp_path: Path, monkeypatch) -> None:
    executable = tmp_path / "Lumen.exe"
    executable.write_bytes(b"app")
    monkeypatch.setattr(startup.sys, "frozen", True, raising=False)
    monkeypatch.setattr(startup.sys, "executable", str(executable))
    monkeypatch.setattr(
        startup.sys,
        "argv",
        [str(executable), "--tray", "--relaunched", "lumen://import/test"],
    )

    _executable, arguments, _working_dir = startup._admin_launch_command()

    assert "--tray" not in arguments
    assert "--relaunched" not in arguments
    assert "--relaunch-as-admin" in arguments
    assert "lumen://import/test" in arguments


def test_data_only_legacy_program_files_directory_is_scheduled_for_cleanup(
    tmp_path: Path,
    monkeypatch,
) -> None:
    program_files = tmp_path / "Program Files"
    current_dir = program_files / "Lumen"
    legacy_dir = program_files / "Lumen KVN"
    current_dir.mkdir(parents=True)
    (legacy_dir / "data" / "logs").mkdir(parents=True)
    (legacy_dir / "data" / "logs" / "update_error.log").write_text(
        "old updater failure",
        encoding="utf-8",
    )
    current_exe = current_dir / "Lumen.exe"
    current_exe.write_bytes(b"app")
    launched: list[list[str]] = []

    monkeypatch.setattr(main_qml.sys, "platform", "win32")
    monkeypatch.setattr(main_qml.sys, "frozen", True, raising=False)
    monkeypatch.setattr(main_qml.sys, "executable", str(current_exe))
    monkeypatch.setenv("ProgramFiles", str(program_files))
    monkeypatch.delenv("ProgramW6432", raising=False)
    monkeypatch.delenv("ProgramFiles(x86)", raising=False)
    monkeypatch.setattr(
        main_qml.subprocess,
        "Popen",
        lambda command, **_kwargs: launched.append(command),
    )

    main_qml._cleanup_legacy_root_program_install()

    assert len(launched) == 1
    assert str(legacy_dir.resolve()) in launched[0][-1]


def test_installed_update_moves_legacy_install_to_renamed_sibling(tmp_path: Path, monkeypatch) -> None:
    legacy_dir = tmp_path / "Lumen KVN"
    monkeypatch.setattr(app_updater, "is_portable", lambda: False)
    monkeypatch.setattr(app_updater, "_registered_install_dir", lambda: legacy_dir)

    assert app_updater._target_app_dir(legacy_dir) == tmp_path / "Lumen"


def test_registered_legacy_install_is_not_reused(tmp_path: Path, monkeypatch) -> None:
    current_dir = tmp_path / "downloaded-copy"
    legacy_dir = tmp_path / "LumenKVN"
    monkeypatch.setattr(app_updater, "is_portable", lambda: False)
    monkeypatch.setattr(app_updater, "_registered_install_dir", lambda: legacy_dir)

    assert app_updater._target_app_dir(current_dir) == tmp_path / "Lumen"


def test_portable_update_keeps_user_selected_directory(tmp_path: Path, monkeypatch) -> None:
    current_dir = tmp_path / "My portable VPN"
    monkeypatch.setattr(app_updater, "is_portable", lambda: True)

    assert app_updater._target_app_dir(current_dir) == current_dir


def test_portable_update_renames_only_known_legacy_directory(tmp_path: Path, monkeypatch) -> None:
    current_dir = tmp_path / "LumenKVN"
    monkeypatch.setattr(app_updater, "is_portable", lambda: True)

    assert app_updater._target_app_dir(current_dir) == tmp_path / "Lumen"


def test_portable_update_does_not_overwrite_existing_renamed_directory(
    tmp_path: Path,
    monkeypatch,
) -> None:
    current_dir = tmp_path / "Lumen KVN"
    (tmp_path / "Lumen").mkdir()
    monkeypatch.setattr(app_updater, "is_portable", lambda: True)

    assert app_updater._target_app_dir(current_dir) == current_dir
