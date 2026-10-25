"""Screen-local configuration caches for inexpensive terminal redraws.

The canonical loader still validates every execution. These caches only reuse
unchanged UI projections; configuration paths are read from tui_state at use time.
"""

from __future__ import annotations

import json
import os
from copy import deepcopy
from pathlib import Path
from typing import Any, Callable

from tesis import tui_state
from tesis.config_loader import load_and_resolve_config, load_yaml_config, parse_yaml_config
from tesis.provider_registry import expanded_model_sections, model_profile_labels


def _file_stamp(path: Path) -> tuple[int, int, int, int, int] | None:
    try:
        stat = path.stat()
        return stat.st_dev, stat.st_ino, stat.st_mtime_ns, stat.st_ctime_ns, stat.st_size
    except OSError:
        return None


class TuiConfigCache:
    """Reuse the latest resolved configuration until its inputs change.

    Source YAML, colocated dotenv, referenced scoring JSON, process environment,
    CLI overrides, and loader identity participate in invalidation. Cached objects
    are read-only UI data. Start requests explicitly bypass this cache.
    """

    def __init__(self) -> None:
        self._raw_key: Any = None
        self._raw: dict[str, Any] = {}
        self._raw_error: Exception | None = None
        self._resolved_key: Any = None
        self._resolved: Any = None
        self._resolved_error: Exception | None = None

    def raw(self, *, loader: Callable = load_yaml_config) -> dict[str, Any]:
        path = Path(tui_state.CONFIG_PATH)
        key = (path, _file_stamp(path), loader)
        if key != self._raw_key:
            self._raw_key, self._raw_error = key, None
            self._raw = {}
            try:
                self._raw = loader(path)
            except Exception as exc:
                self._raw_error = exc
        if self._raw_error is not None:
            raise self._raw_error.with_traceback(None)
        return self._raw

    def _key(self, cli_args: dict[str, Any], loader: Callable) -> tuple:
        path = Path(tui_state.CONFIG_PATH)
        raw = self.raw()
        dependencies = []
        for name in ("scoring_profile", "scoring_oracles"):
            for value in (raw.get(name), cli_args.get(name), os.environ.get(f"TESIS_{name.upper()}")):
                if isinstance(value, str) and value:
                    dependency = Path(os.path.expandvars(value))
                    if not dependency.is_absolute():
                        dependency = path.parent / dependency
                    dependencies.append((dependency, _file_stamp(dependency)))
        # Keys and credentials stay private to the cache; never log this tuple.
        return (path, _file_stamp(path), _file_stamp(path.with_name(".env")),
                tuple(dependencies), tuple(sorted(os.environ.items())),
                json.dumps(cli_args, sort_keys=True, default=str), loader)

    def resolve(self, cli_args: dict[str, Any] | None = None, *,
                loader: Callable = load_and_resolve_config, fresh: bool = False) -> Any:
        args = cli_args or {}
        key = self._key(args, loader)
        if fresh or key != self._resolved_key:
            self._resolved_key, self._resolved_error = key, None
            self._resolved = None
            try:
                self._resolved = loader(config_path=str(tui_state.CONFIG_PATH), cli_args=args)
                # Loading dotenv may populate process environment variables.
                after = self._key(args, loader)
                self._resolved_key = (*key[:4], after[4], *key[5:])
            except Exception as exc:
                self._resolved_error = exc
        if self._resolved_error is not None:
            raise self._resolved_error.with_traceback(None)
        return self._resolved


class DraftConfigCache:
    """Parse an editor revision once; give mutating actions their own copy."""

    def __init__(self) -> None:
        self._text: str | None = None
        self._payload: dict[str, Any] = {}
        self._error: Exception | None = None
        self._projection: tuple[dict, dict] | None = None

    def read(self, text: str) -> dict[str, Any]:
        if text != self._text:
            self._text, self._error, self._projection = text, None, None
            self._payload = {}
            try:
                self._payload = parse_yaml_config(text)
            except Exception as exc:
                self._error = exc
        if self._error is not None:
            raise self._error.with_traceback(None)
        return self._payload

    def edit(self, text: str) -> dict[str, Any]:
        return deepcopy(self.read(text))

    def profiles(self, text: str) -> tuple[dict, dict]:
        payload = self.read(text)
        if self._projection is None:
            self._projection = expanded_model_sections(payload), model_profile_labels(payload)
        return self._projection
