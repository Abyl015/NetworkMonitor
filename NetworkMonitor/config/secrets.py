from __future__ import annotations

import json
import os
from typing import Any

from NetworkMonitor.core.paths import secrets_path


SECRETS_FILE = secrets_path()


def _read_local_secrets() -> dict[str, str]:
    if not SECRETS_FILE.exists():
        return {}

    try:
        data: Any = json.loads(SECRETS_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}

    if not isinstance(data, dict):
        return {}

    return {
        str(key): str(value)
        for key, value in data.items()
        if isinstance(key, str) and isinstance(value, str) and value.strip()
    }


def _write_local_secrets(secrets: dict[str, str]) -> None:
    SECRETS_FILE.parent.mkdir(parents=True, exist_ok=True)
    if not secrets:
        try:
            SECRETS_FILE.unlink()
        except FileNotFoundError:
            pass
        return

    tmp_path = SECRETS_FILE.with_name("secrets.local.json.tmp")
    tmp_path.write_text(
        json.dumps(secrets, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    tmp_path.replace(SECRETS_FILE)


def get_secret(name: str) -> str | None:
    key = str(name or "").strip()
    if not key:
        return None

    env_value = os.environ.get(key, "").strip()
    if env_value:
        return env_value

    return _read_local_secrets().get(key)


def set_secret(name: str, value: str) -> None:
    key = str(name or "").strip()
    secret_value = str(value or "").strip()
    if not key or not secret_value:
        return

    secrets = _read_local_secrets()
    secrets[key] = secret_value
    _write_local_secrets(secrets)


def delete_secret(name: str) -> None:
    key = str(name or "").strip()
    if not key:
        return

    secrets = _read_local_secrets()
    if key in secrets:
        del secrets[key]
        _write_local_secrets(secrets)


def has_secret(name: str) -> bool:
    return bool(get_secret(name))


def has_local_secret(name: str) -> bool:
    key = str(name or "").strip()
    return bool(key and key in _read_local_secrets())
