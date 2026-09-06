from __future__ import annotations

from pathlib import Path
import filecmp
import hashlib
import os
import shutil
import sys

PORTABLE_MARKERS = ("portable.txt", "portable")
LEGACY_APP_NAMES = ("Lumen KVN", "lumen-kvn", "LumenKVN", "Lumen_KVN")
NAME_MIGRATION_MARKER = ".lumen_name_migration_v1"
MIGRATION_BACKUP_SUFFIX = ".pre_lumen_migration"
MIGRATION_CONFLICTS_DIR = ".legacy_migration_conflicts"
MIGRATION_ROOT_BACKUPS_DIR = ".legacy_root_files"
LEGACY_EPHEMERAL_ROOT_NAMES = {"cache", "logs", "runtime", "temp", "tmp"}


def is_writable(path: Path) -> bool:
    try:
        path.mkdir(parents=True, exist_ok=True)
        probe = path / ".write_test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        return True
    except Exception:
        return False


def _backup_conflicting_state(source: Path, target: Path) -> None:
    for name in ("state.enc", "traffic_history.json", "install_id"):
        source_file = source / name
        target_file = target / name
        backup_file = target / f"{name}{MIGRATION_BACKUP_SUFFIX}"
        if not source_file.is_file() or not target_file.is_file() or backup_file.exists():
            continue
        shutil.copy2(target_file, backup_file)


def _migration_source_id(source: Path) -> str:
    normalized = str(source.resolve()).replace("\\", "/").casefold()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _is_migration_id(value: str) -> bool:
    return len(value) == 64 and all(char in "0123456789abcdef" for char in value.casefold())


def _read_migration_ids(marker: Path) -> set[str]:
    try:
        return {
            line.strip().casefold()
            for line in marker.read_text(encoding="utf-8").splitlines()
            if _is_migration_id(line.strip())
        }
    except Exception:
        return set()


def _write_migration_ids(marker: Path, source_ids: set[str]) -> None:
    marker.write_text("\n".join(sorted(source_ids)), encoding="utf-8")


def _copied_tree_matches(source: Path, target: Path) -> bool:
    for source_file in source.rglob("*"):
        if not source_file.is_file():
            continue
        target_file = target / source_file.relative_to(source)
        if not target_file.is_file() or not filecmp.cmp(source_file, target_file, shallow=False):
            return False
    return True


def _merge_additional_legacy_data(source: Path, target: Path, source_id: str) -> bool:
    """Merge a second legacy tree without overwriting already migrated state."""
    conflict_root = target / MIGRATION_CONFLICTS_DIR / source_id
    for source_file in source.rglob("*"):
        if not source_file.is_file():
            continue
        relative = source_file.relative_to(source)
        target_file = target / relative
        if not target_file.exists():
            target_file.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source_file, target_file)
            continue
        if target_file.is_file() and filecmp.cmp(source_file, target_file, shallow=False):
            continue
        conflict_file = conflict_root / relative
        conflict_file.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_file, conflict_file)

    for source_file in source.rglob("*"):
        if not source_file.is_file():
            continue
        relative = source_file.relative_to(source)
        target_file = target / relative
        conflict_file = conflict_root / relative
        target_matches = target_file.is_file() and filecmp.cmp(
            source_file, target_file, shallow=False
        )
        conflict_matches = conflict_file.is_file() and filecmp.cmp(
            source_file, conflict_file, shallow=False
        )
        if not target_matches and not conflict_matches:
            return False
    return True


def _remove_migrated_source(source: Path) -> None:
    shutil.rmtree(source)
    try:
        source.parent.rmdir()
    except OSError:
        pass


def _cleanup_legacy_app_root(legacy_root: Path, target_data: Path) -> bool:
    """Remove the old branded root after data migration without losing extras."""
    try:
        if not legacy_root.is_dir():
            return False
        # Never remove a root whose data migration did not finish.
        if (legacy_root / "data").exists():
            return False
        for child in tuple(legacy_root.iterdir()):
            if child.name.casefold() not in LEGACY_EPHEMERAL_ROOT_NAMES:
                continue
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink()
        remaining = tuple(legacy_root.iterdir())
        if remaining:
            backup_root = (
                target_data
                / MIGRATION_ROOT_BACKUPS_DIR
                / _migration_source_id(legacy_root)
            )
            backup_root.mkdir(parents=True, exist_ok=True)
            for child in remaining:
                destination = backup_root / child.name
                if destination.exists():
                    return False
                shutil.move(str(child), str(destination))
        legacy_root.rmdir()
        return True
    except Exception:
        return False


def _migrate_legacy_data(source: Path, target: Path) -> bool:
    """Move legacy user data once, preferring and preserving the pre-rename state."""
    try:
        if source.resolve() == target.resolve() or not source.is_dir():
            return False
        marker = target / NAME_MIGRATION_MARKER
        source_id = _migration_source_id(source)
        migrated_ids = _read_migration_ids(marker)
        if source_id in migrated_ids:
            _remove_migrated_source(source)
            return True
        target.mkdir(parents=True, exist_ok=True)
        if migrated_ids:
            if not _merge_additional_legacy_data(source, target, source_id):
                return False
        else:
            _backup_conflicting_state(source, target)
            shutil.copytree(source, target, dirs_exist_ok=True)
            if not _copied_tree_matches(source, target):
                return False
        migrated_ids.add(source_id)
        _write_migration_ids(marker, migrated_ids)
        _remove_migrated_source(source)
        return True
    except Exception:
        return False


def _migrate_first_legacy_data(candidates: tuple[Path, ...], target: Path) -> None:
    marker = target / NAME_MIGRATION_MARKER
    if marker.is_file():
        try:
            marker_value = marker.read_text(encoding="utf-8").strip()
            if not _read_migration_ids(marker):
                matched_source = next(
                    (
                        candidate
                        for candidate in candidates
                        if marker_value and Path(marker_value).resolve() == candidate.resolve()
                    ),
                    None,
                )
                if matched_source is not None:
                    _write_migration_ids(marker, {_migration_source_id(matched_source)})
        except Exception:
            pass
    for legacy_dir in candidates:
        _migrate_legacy_data(legacy_dir, target)


def user_data_dir(app_name: str) -> Path:
    bases = tuple(
        dict.fromkeys(
            Path(value).resolve(strict=False)
            for value in (
                os.environ.get("LOCALAPPDATA", "").strip(),
                os.environ.get("APPDATA", "").strip(),
            )
            if value
        )
    )
    if bases:
        target_dir = bases[0] / app_name / "data"
        legacy_roots = tuple(
            base / legacy_name
            for base in bases
            for legacy_name in LEGACY_APP_NAMES
        )
        _migrate_first_legacy_data(
            tuple(root / "data" for root in legacy_roots),
            target_dir,
        )
        for legacy_root in legacy_roots:
            _cleanup_legacy_app_root(legacy_root, target_dir)
        return target_dir

    target_dir = Path.home() / f".{app_name}" / "data"
    _migrate_first_legacy_data(
        tuple(Path.home() / f".{legacy_name}" / "data" for legacy_name in LEGACY_APP_NAMES),
        target_dir,
    )
    return target_dir


def _portable_marker_present(base_dir: Path) -> bool:
    for name in PORTABLE_MARKERS:
        try:
            if (base_dir / name).is_file():
                return True
        except Exception:
            pass
    return False


def resolve_data_dir(base_dir: Path, install_data_dir: Path, app_name: str) -> Path:
    if not getattr(sys, "frozen", False):
        # Development launches must use the same profile as the installed
        # application.  Keeping state below the checkout makes ``py
        # run_qml.py`` appear to reset settings whenever the user switches
        # between the dev launcher and the packaged executable.
        return user_data_dir(app_name)
    if _portable_marker_present(base_dir) and is_writable(install_data_dir):
        legacy_roots = tuple(base_dir.parent / legacy_folder for legacy_folder in LEGACY_APP_NAMES)
        _migrate_first_legacy_data(
            tuple(root / "data" for root in legacy_roots),
            install_data_dir,
        )
        for legacy_root in legacy_roots:
            _cleanup_legacy_app_root(legacy_root, install_data_dir)
        return install_data_dir
    return user_data_dir(app_name)


def seed_user_data(src: Path, dst: Path) -> None:
    if src == dst or not src.exists():
        return
    try:
        dst.mkdir(parents=True, exist_ok=True)
    except Exception:
        return
    for sub in ("templates", "configs"):
        source = src / sub
        target = dst / sub
        if source.is_dir() and not target.exists():
            try:
                shutil.copytree(source, target)
            except Exception:
                pass
    for name in ("state.enc", "traffic_history.json"):
        source = src / name
        target = dst / name
        if not source.is_file():
            continue
        if not target.exists():
            try:
                shutil.copy2(source, target)
            except Exception:
                continue



_install_id_cache: str | None = None


def get_install_id() -> str:
    """Stable anonymous client id to correlate diagnostics."""
    global _install_id_cache
    if _install_id_cache:
        return _install_id_cache

    from .constants import DATA_DIR

    path = DATA_DIR / "install_id"
    try:
        value = path.read_text(encoding="utf-8").strip()
    except Exception:
        value = ""
    if not value:
        import uuid

        value = uuid.uuid4().hex
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(value, encoding="utf-8")
        except Exception:
            pass
    _install_id_cache = value
    return value
