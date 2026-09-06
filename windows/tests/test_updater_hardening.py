from __future__ import annotations

import hashlib
import os
import shutil
import sys
from pathlib import Path

import pytest

from xray_fluent import app_updater, update_checker
from xray_fluent.app_updater import AppUpdate
import run_qml


def test_update_interpreter_is_launched_from_an_absolute_system_path() -> None:
    path = Path(app_updater._powershell_path())

    if sys.platform != "win32":
        assert str(path) == "powershell"
        return

    system_root = Path(os.environ.get("SystemRoot") or r"C:\Windows")
    assert path.is_absolute()
    assert path == system_root / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"


def test_setup_asset_name_cannot_escape_the_download_directory(tmp_path) -> None:
    for candidate in (
        "..\\..\\evil.exe",
        "../../evil.exe",
        "C:\\Windows\\System32\\evil.exe",
        "",
        "..",
        "Lumen Setup.exe",
    ):
        name = app_updater._safe_asset_name(candidate, "Lumen-Setup-windows-x64.exe")
        assert (tmp_path / name).parent == tmp_path

    assert (
        app_updater._safe_asset_name("Lumen-Setup-windows-x64.exe", "default.exe")
        == "Lumen-Setup-windows-x64.exe"
    )


def test_nightly_channel_prefers_the_qml_asset() -> None:
    plain = {"name": "Lumen-Setup-windows-x64.exe"}
    qml = {"name": "Lumen-qml-Setup-windows-x64.exe"}
    assets = [plain, qml]

    assert max(assets, key=lambda a: app_updater._asset_score(a, True, False)) is qml
    assert max(assets, key=lambda a: app_updater._asset_score(a, False, False)) is plain


def test_elevated_update_script_reverifies_the_installer_hash(monkeypatch) -> None:
    payload = b"installer-payload"
    update = AppUpdate(
        version="2.0.0",
        tag="v2.0.0",
        download_url="https://example.test/Lumen-Setup-windows-x64.exe",
        size=len(payload),
        notes="",
        digest_sha256=hashlib.sha256(payload).hexdigest(),
        asset_name="Lumen-Setup-windows-x64.exe",
    )
    launched: list[Path] = []
    monkeypatch.setattr(app_updater, "is_portable", lambda: False)
    monkeypatch.setattr(
        app_updater,
        "_launch_update_script",
        lambda script, *, elevated: bool(launched.append(script)) or True,
    )
    worker = app_updater.UpdateDownloader(update)
    monkeypatch.setattr(worker, "_download", lambda target, _proxy: target.write_bytes(payload))

    try:
        worker.run()

        assert launched
        script_text = launched[0].read_bytes().decode("utf-8-sig")
        assert "Get-FileHash -LiteralPath $setupPath -Algorithm SHA256" in script_text
        assert update.digest_sha256 in script_text
        assert "& $exePath '--version-file' $versionFile" in script_text
        assert "Start-Process -FilePath $exePath -ArgumentList '--version-file',$versionFile" not in script_text
        assert "continuing because installer finished successfully" not in script_text
    finally:
        for script in launched:
            shutil.rmtree(script.parent, ignore_errors=True)


def test_version_probe_rejects_drive_root_output(monkeypatch, tmp_path: Path) -> None:
    target = tmp_path / "runtime" / "version.txt"
    monkeypatch.setattr(run_qml.sys, "argv", ["run_qml.py", "--version-file", r"C:\Program"])
    assert run_qml._run() == 2
    assert not target.exists()


def test_version_probe_accepts_nested_output(monkeypatch, tmp_path: Path) -> None:
    target = tmp_path / "folder with spaces" / "runtime" / "version.txt"
    target.parent.mkdir(parents=True)
    monkeypatch.setattr(run_qml.sys, "argv", ["run_qml.py", "--version-file", str(target)])
    assert run_qml._run() == 0
    assert target.read_text(encoding="utf-8") == "1.9.10"


def test_update_feed_url_must_use_https() -> None:
    for feed_url in (
        "http://feed.example.test/xray.json",
        "file:///C:/temp/xray.json",
        "ftp://feed.example.test/xray.json",
    ):
        with pytest.raises(ValueError):
            update_checker.check_update(feed_url)


def test_update_feed_rejects_a_plain_http_download_url(monkeypatch) -> None:
    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args) -> None:
            return None

        def read(self) -> bytes:
            return b'{"version":"99.0.0","url":"http://evil.test/x.zip","sha256":"' + b"a" * 64 + b'"}'

    monkeypatch.setattr(update_checker, "urlopen_proxy_first", lambda *_a, **_k: Response())

    with pytest.raises(ValueError):
        update_checker.check_update("https://feed.example.test/xray.json")


def test_https_update_feed_is_accepted(monkeypatch) -> None:
    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args) -> None:
            return None

        def read(self) -> bytes:
            return b'{"version":"99.0.0","url":"https://example.test/x.zip","sha256":"' + b"a" * 64 + b'"}'

    monkeypatch.setattr(update_checker, "urlopen_proxy_first", lambda *_a, **_k: Response())

    info = update_checker.check_update("https://feed.example.test/xray.json")

    assert info is not None
    assert info.url == "https://example.test/x.zip"
    assert info.digest_sha256 == "a" * 64
