from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path


PACKAGE_DIR = Path(__file__).resolve().parents[1]
LEGACY_CONFIG_DIR = PACKAGE_DIR / "config"
LEGACY_STORAGE_DIR = PACKAGE_DIR / "storage"

APP_NAME = "NetworkMonitor"
LINUX_APP_NAME = "networkmonitor"


def _env_path(name: str) -> Path | None:
    value = os.environ.get(name, "").strip()
    return Path(value).expanduser() if value else None


def _platform_config_dir() -> Path:
    override = _env_path("NETWORKMONITOR_CONFIG_DIR")
    if override:
        return override

    if sys.platform == "win32":
        base = _env_path("APPDATA") or (Path.home() / "AppData" / "Roaming")
        return base / APP_NAME

    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / APP_NAME

    base = _env_path("XDG_CONFIG_HOME") or (Path.home() / ".config")
    return base / LINUX_APP_NAME


def _platform_data_dir() -> Path:
    override = _env_path("NETWORKMONITOR_DATA_DIR")
    if override:
        return override

    if sys.platform == "win32":
        base = _env_path("LOCALAPPDATA") or _env_path("APPDATA") or (Path.home() / "AppData" / "Local")
        return base / APP_NAME

    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / APP_NAME

    base = _env_path("XDG_DATA_HOME") or (Path.home() / ".local" / "share")
    return base / LINUX_APP_NAME


def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def copy_file_once(source: Path, target: Path) -> None:
    if target.exists() or not source.exists() or not source.is_file():
        return

    ensure_dir(target.parent)
    shutil.copy2(source, target)


def copy_tree_files_once(source_dir: Path, target_dir: Path, pattern: str = "*") -> None:
    if not source_dir.exists() or not source_dir.is_dir():
        return

    ensure_dir(target_dir)
    for source in source_dir.glob(pattern):
        if source.is_file():
            copy_file_once(source, target_dir / source.name)


def package_dir() -> Path:
    return PACKAGE_DIR


def assets_dir() -> Path:
    return PACKAGE_DIR / "assets"


def icons_dir() -> Path:
    return assets_dir() / "icons"


def bundled_iocs_dir() -> Path:
    return PACKAGE_DIR / "data" / "iocs"


def bundled_profiles_dir() -> Path:
    return LEGACY_CONFIG_DIR / "profiles"


def user_config_dir() -> Path:
    return ensure_dir(_platform_config_dir())


def user_data_dir() -> Path:
    return ensure_dir(_platform_data_dir())


def profiles_dir() -> Path:
    target = ensure_dir(user_config_dir() / "profiles")
    if not any(target.glob("*.json")):
        copy_tree_files_once(bundled_profiles_dir(), target, "*.json")
    return target


def settings_path() -> Path:
    target = user_config_dir() / "settings.json"
    copy_file_once(LEGACY_CONFIG_DIR / "settings.json", target)
    return target


def secrets_path() -> Path:
    return user_config_dir() / "secrets.local.json"


def database_path() -> Path:
    target = user_data_dir() / "traffic_data.db"
    copy_file_once(LEGACY_STORAGE_DIR / "traffic_data.db", target)
    return target


def models_dir() -> Path:
    target = ensure_dir(user_data_dir() / "models")
    copy_tree_files_once(LEGACY_STORAGE_DIR / "models", target, "*.joblib")
    return target


def reports_dir() -> Path:
    return ensure_dir(user_data_dir() / "reports")
