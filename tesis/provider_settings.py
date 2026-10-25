"""Save API-key provider settings without embedding credentials in YAML."""

from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path
from typing import Any, Mapping

from dotenv import dotenv_values, set_key
from filelock import FileLock

from tesis.config_loader import dump_yaml_config, load_and_resolve_config


def resolved_provider_key(entry: Mapping[str, Any], config_path: Path,
                          pending: Mapping[str, str]) -> str:
    value = str(entry.get("api_key") or "")
    match = re.fullmatch(r"\$\{([A-Za-z_][A-Za-z0-9_]*)}", value)
    if not match:
        return value
    name = match.group(1)
    key = pending.get(name) or os.environ.get(name)
    if key is None:
        key = dotenv_values(config_path.with_name(".env")).get(name)
    if not key:
        raise ValueError("The provider API key is unavailable. Enter a key before fetching models.")
    return str(key)


def _stage(path: Path, text: str, *, mode: int) -> Path:
    descriptor, filename = tempfile.mkstemp(prefix=f".{path.name}-", dir=path.parent)
    staged = Path(filename)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            os.fchmod(handle.fileno(), mode)
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        staged.unlink(missing_ok=True)
        raise
    return staged


def save_provider_settings(config_path: Path, payload: dict[str, Any], pending: Mapping[str, str]) -> None:
    """Validate first, then atomically replace each file, restoring env on failure.

    Keep unrelated dotenv assignments/comments intact. New keys become visible
    to the running process only after both files have been saved successfully.
    """
    config_path = Path(config_path)
    env_path = config_path.with_name(".env")
    refs = {str(entry.get("api_key")) for entry in (payload.get("api_providers") or {}).values()
            if isinstance(entry, Mapping)}
    keys = {name: value for name, value in pending.items() if f"${{{name}}}" in refs}
    if any(not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) or any(c in value for c in "\r\n\0")
           for name, value in keys.items()):
        raise ValueError("API keys must be single-line values.")
    staged_config = None
    staged_env = None
    with FileLock(str(config_path) + ".lock", timeout=3):
        if env_path.is_symlink():
            raise ValueError("Refusing to write API keys through a symlinked .env file.")
        original_env = env_path.read_text(encoding="utf-8") if env_path.exists() else None
        try:
            staged_config = _stage(config_path, dump_yaml_config(payload), mode=0o600)
            load_and_resolve_config(config_path=str(staged_config), cli_args={}, secret_overrides=keys)
            if keys:
                staged_env = _stage(env_path, original_env or "", mode=0o600)
                for name, value in keys.items():
                    set_key(staged_env, name, value, quote_mode="always")
                os.chmod(staged_env, 0o600)
                with staged_env.open("rb") as handle:
                    os.fsync(handle.fileno())
                os.replace(staged_env, env_path)
            try:
                os.replace(staged_config, config_path)
            except BaseException:
                if keys:
                    if original_env is None:
                        env_path.unlink(missing_ok=True)
                    else:
                        restored = _stage(env_path, original_env, mode=0o600)
                        os.replace(restored, env_path)
                raise
        finally:
            if staged_config:
                staged_config.unlink(missing_ok=True)
            if staged_env:
                staged_env.unlink(missing_ok=True)
    os.environ.update(keys)
