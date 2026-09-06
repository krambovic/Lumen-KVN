from __future__ import annotations

from pathlib import Path

from xray_fluent import data_paths


def test_user_data_migration_repairs_already_created_target(tmp_path: Path, monkeypatch) -> None:
    legacy = tmp_path / "Lumen KVN" / "data"
    target = tmp_path / "Lumen" / "data"
    legacy.mkdir(parents=True)
    target.mkdir(parents=True)
    (legacy / "state.enc").write_bytes(b"real-old-state")
    (legacy / "install_id").write_text("existing-install", encoding="utf-8")
    (target / "state.enc").write_bytes(b"fresh-broken-state")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))

    result = data_paths.user_data_dir("Lumen")

    assert result == target
    assert (target / "state.enc").read_bytes() == b"real-old-state"
    assert (target / "state.enc.pre_lumen_migration").read_bytes() == b"fresh-broken-state"
    assert (target / "install_id").read_text(encoding="utf-8") == "existing-install"
    assert (target / data_paths.NAME_MIGRATION_MARKER).is_file()
    assert not legacy.exists()
    assert "lumen kvn" not in (target / data_paths.NAME_MIGRATION_MARKER).read_text(encoding="utf-8").casefold()


def test_user_data_migration_runs_only_once(tmp_path: Path, monkeypatch) -> None:
    legacy = tmp_path / "Lumen KVN" / "data"
    legacy.mkdir(parents=True)
    (legacy / "state.enc").write_bytes(b"original")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))

    target = data_paths.user_data_dir("Lumen")
    (target / "state.enc").write_bytes(b"new-lumen-state")

    data_paths.user_data_dir("Lumen")

    assert (target / "state.enc").read_bytes() == b"new-lumen-state"
    assert not legacy.exists()


def test_portable_data_migrates_from_adjacent_legacy_folder(tmp_path: Path, monkeypatch) -> None:
    base_dir = tmp_path / "Lumen"
    install_data = base_dir / "data"
    legacy_data = tmp_path / "Lumen KVN" / "data"
    base_dir.mkdir()
    legacy_data.mkdir(parents=True)
    (base_dir / "portable").write_text("", encoding="utf-8")
    (legacy_data / "state.enc").write_bytes(b"portable-state")
    monkeypatch.setattr(data_paths.sys, "frozen", True, raising=False)

    result = data_paths.resolve_data_dir(base_dir, install_data, "Lumen")

    assert result == install_data
    assert (install_data / "state.enc").read_bytes() == b"portable-state"
    assert not legacy_data.exists()


def test_development_data_uses_the_same_user_profile_as_installed_app(
    tmp_path: Path,
    monkeypatch,
) -> None:
    base_dir = tmp_path / "checkout"
    install_data = base_dir / "data"
    local_app_data = tmp_path / "LocalAppData"
    monkeypatch.setattr(data_paths.sys, "frozen", False, raising=False)
    monkeypatch.setenv("LOCALAPPDATA", str(local_app_data))
    monkeypatch.delenv("APPDATA", raising=False)

    result = data_paths.resolve_data_dir(base_dir, install_data, "Lumen")

    assert result == local_app_data / "Lumen" / "data"


def test_seed_user_data_keeps_checkout_state_when_user_profile_exists(tmp_path: Path) -> None:
    source = tmp_path / "checkout" / "data"
    target = tmp_path / "LocalAppData" / "Lumen" / "data"
    source.mkdir(parents=True)
    target.mkdir(parents=True)
    (source / "state.enc").write_bytes(b"checkout-state")
    (target / "state.enc").write_bytes(b"user-state")

    data_paths.seed_user_data(source, target)

    assert (source / "state.enc").read_bytes() == b"checkout-state"
    assert (target / "state.enc").read_bytes() == b"user-state"


def test_seed_user_data_updates_only_pristine_legacy_singbox_default(tmp_path: Path) -> None:
    source = tmp_path / "checkout" / "data"
    target = tmp_path / "LocalAppData" / "Lumen" / "data"
    source_template = source / "templates" / "sing-box" / "default.json"
    target_template = target / "templates" / "sing-box" / "default.json"
    source_template.parent.mkdir(parents=True)
    target_template.parent.mkdir(parents=True)
    source_template.write_text(
        '{"inbounds":[{"type":"tun","interface_name":"singbox_tun"}],"route":{}}',
        encoding="utf-8",
    )
    target_template.write_text(
        '{"inbounds":[{"type":"tun","interface_name":"tun0"}],"route":{}}',
        encoding="utf-8",
    )

    data_paths.seed_user_data(source, target)

    assert '"interface_name":"singbox_tun"' in target_template.read_text(encoding="utf-8")

    target_template.write_text(
        '{"inbounds":[{"type":"tun","interface_name":"custom_tun"}],"route":{}}',
        encoding="utf-8",
    )
    data_paths.seed_user_data(source, target)

    assert '"interface_name":"custom_tun"' in target_template.read_text(encoding="utf-8")


def test_failed_legacy_cleanup_is_retried_without_overwriting_new_state(tmp_path: Path, monkeypatch) -> None:
    legacy = tmp_path / "Lumen KVN" / "data"
    legacy.mkdir(parents=True)
    (legacy / "state.enc").write_bytes(b"legacy-state")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))

    real_rmtree = data_paths.shutil.rmtree
    attempts = 0

    def fail_cleanup_once(path: Path) -> None:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise PermissionError("still in use")
        real_rmtree(path)

    monkeypatch.setattr(data_paths.shutil, "rmtree", fail_cleanup_once)
    target = data_paths.user_data_dir("Lumen")
    assert legacy.exists()
    assert (target / data_paths.NAME_MIGRATION_MARKER).is_file()

    (target / "state.enc").write_bytes(b"new-state")
    data_paths.user_data_dir("Lumen")

    assert not legacy.exists()
    assert (target / "state.enc").read_bytes() == b"new-state"


def test_pre_release_path_marker_is_sanitized_and_cleanup_finishes(tmp_path: Path, monkeypatch) -> None:
    legacy = tmp_path / "Lumen KVN" / "data"
    target = tmp_path / "Lumen" / "data"
    legacy.mkdir(parents=True)
    target.mkdir(parents=True)
    (legacy / "state.enc").write_bytes(b"legacy-state")
    (target / "state.enc").write_bytes(b"legacy-state")
    marker = target / data_paths.NAME_MIGRATION_MARKER
    marker.write_text(str(legacy), encoding="utf-8")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))

    data_paths.user_data_dir("Lumen")

    assert not legacy.exists()
    marker_value = marker.read_text(encoding="utf-8").strip()
    assert len(marker_value) == 64
    assert "lumen" not in marker_value


def test_all_legacy_data_directories_are_merged_and_removed(tmp_path: Path, monkeypatch) -> None:
    first = tmp_path / "Lumen KVN" / "data"
    second = tmp_path / "LumenKVN" / "data"
    first.mkdir(parents=True)
    second.mkdir(parents=True)
    (first / "state.enc").write_bytes(b"primary-legacy-state")
    (second / "state.enc").write_bytes(b"secondary-legacy-state")
    (second / "configs" / "xray").mkdir(parents=True)
    (second / "configs" / "xray" / "extra.json").write_text("{}", encoding="utf-8")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))

    target = data_paths.user_data_dir("Lumen")

    assert (target / "state.enc").read_bytes() == b"primary-legacy-state"
    assert (target / "configs" / "xray" / "extra.json").is_file()
    conflict_states = list(
        (target / data_paths.MIGRATION_CONFLICTS_DIR).rglob("state.enc")
    )
    assert len(conflict_states) == 1
    assert conflict_states[0].read_bytes() == b"secondary-legacy-state"
    assert not (tmp_path / "Lumen KVN").exists()
    assert not (tmp_path / "LumenKVN").exists()
    marker_ids = (target / data_paths.NAME_MIGRATION_MARKER).read_text(
        encoding="utf-8"
    ).splitlines()
    assert len(marker_ids) == 2
    assert all(len(source_id) == 64 for source_id in marker_ids)


def test_legacy_root_cache_is_removed_and_unknown_files_are_preserved(
    tmp_path: Path,
    monkeypatch,
) -> None:
    legacy_root = tmp_path / "Lumen KVN"
    (legacy_root / "cache").mkdir(parents=True)
    (legacy_root / "cache" / "stale.bin").write_bytes(b"cache")
    (legacy_root / "custom-note.txt").write_text("keep me", encoding="utf-8")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))

    target = data_paths.user_data_dir("Lumen")

    assert not legacy_root.exists()
    preserved = list(
        (target / data_paths.MIGRATION_ROOT_BACKUPS_DIR).rglob("custom-note.txt")
    )
    assert len(preserved) == 1
    assert preserved[0].read_text(encoding="utf-8") == "keep me"
    assert not list(target.rglob("stale.bin"))


def test_roaming_legacy_data_migrates_to_local_appdata(tmp_path: Path, monkeypatch) -> None:
    local = tmp_path / "Local"
    roaming = tmp_path / "Roaming"
    legacy = roaming / "LumenKVN" / "data"
    legacy.mkdir(parents=True)
    (legacy / "state.enc").write_bytes(b"roaming-state")
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    monkeypatch.setenv("APPDATA", str(roaming))

    target = data_paths.user_data_dir("Lumen")

    assert target == local / "Lumen" / "data"
    assert (target / "state.enc").read_bytes() == b"roaming-state"
    assert not (roaming / "LumenKVN").exists()
