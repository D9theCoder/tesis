"""UI-independent discovery and indexing of experiment artifacts.

The command-line runner has produced a few generations of JSON artifacts over
the life of the project.  This module intentionally keeps the presentation
layer out of that compatibility work: callers receive small metadata records
and can decide whether to render them in a terminal, a web page, or a test.

The repository is read-only.  It never rewrites an artifact and a bad file is
treated as an absent file rather than making the whole artifact directory
unusable.
"""

from __future__ import annotations

import json
import logging
import os
import re
import uuid
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import date, datetime, timezone
from hashlib import sha256
from pathlib import Path
from types import MappingProxyType
from typing import Any, Final
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


LOGGER = logging.getLogger(__name__)

_FINGERPRINT_PREFIX: Final[str] = "sha256:"

# Keys which carry credentials or transient authentication state.  Matching
# is performed on a normalised key, so ``apiKey`` and ``api-key`` are covered
# as well as the snake-case spelling used by the runner.
_SECRET_KEY_PARTS: Final[frozenset[str]] = frozenset(
    {
        "access_key",
        "access_token",
        "api_key",
        "apikey",
        "key",
        "auth",
        "auth_header",
        "authorization",
        "bearer",
        "client_secret",
        "cookie",
        "credential",
        "credentials",
        "dvwa_password",
        "id_token",
        "jwt",
        "passphrase",
        "passwd",
        "password",
        "private_key",
        "refresh_token",
        "secret",
        "session_cookie",
        "session_token",
        "token",
    }
)

# These values describe the invocation or its output, not the effective
# engagement setup.  They are deliberately excluded recursively so a nested
# ``execution`` or ``model`` object cannot make repeated runs look unique.
_EXECUTION_ONLY_KEYS: Final[frozenset[str]] = frozenset(
    {
        "artifact_id",
        "artifact_path",
        "created",
        "created_at",
        "creation_time",
        "completed",
        "completed_at",
        "duration",
        "duration_ms",
        "elapsed",
        "elapsed_ms",
        "ended",
        "ended_at",
        "end_time",
        "event_time",
        "execution",
        "execution_id",
        "filename",
        "file_name",
        "finished_at",
        "finished",
        "generated_at",
        "id",
        "job_id",
        "log_dir",
        "log_path",
        "output",
        "output_dir",
        "output_file",
        "output_path",
        "output_root",
        "repeat",
        "repeats",
        "repeat_count",
        "repeat_index",
        "attempt",
        "attempt_index",
        "execution_name",
        "run_name",
        "report_dir",
        "report_path",
        "result_dir",
        "result_path",
        "run_id",
        "session_id",
        "start_time",
        "started",
        "started_at",
        "stderr",
        "stdout",
        "status",
        "thread_id",
        "time",
        "timestamp",
        "trace_id",
        "updated_at",
        "updated",
        "date",
        "execution_date",
        "uuid",
    }
)

# A few output objects are not useful as setup even though they do not have a
# suffix such as ``_path``.  They commonly occur when a whole run artifact is
# accidentally passed to ``config_fingerprint``.
_OUTPUT_OBJECT_KEYS: Final[frozenset[str]] = frozenset(
    {
        "artifact",
        "artifacts",
        "config_fingerprint",
        "configuration_fingerprint",
        "events",
        "logs",
        "execution_log",
        "final_state",
        "manual_scoring_evidence",
        "report",
        "response_evidence",
        "error",
        "schema_version",
        "selected_method",
        "verifier_decision",
        "telemetry",
        "timing",
    }
)

_TIMESTAMP_KEYS: Final[tuple[str, ...]] = (
    "updated_at",
    "ended_at",
    "finished_at",
    "completed_at",
    "created_at",
    "started_at",
    "timestamp",
    "time",
)

_MATRIX_KEYS: Final[frozenset[str]] = frozenset(
    {
        "artifacts",
        "children",
        "entries",
        "executions",
        "items",
        "records",
        "results",
        "runs",
    }
)

_NESTED_RECORD_KEYS: Final[tuple[str, ...]] = (
    "artifact",
    "data",
    "execution",
    "metadata",
    "record",
    "result",
    "run",
    "timing",
)

_SIDECAR_SUFFIXES: Final[tuple[str, ...]] = (
    ".events.json",
    ".failure.json",
    ".rich.json",
)

_MISSING: Final[object] = object()


def _normalise_key(value: object) -> str:
    """Return a case- and punctuation-insensitive configuration key."""

    text = str(value)
    # Make common camelCase keys comparable with snake_case keys.
    text = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", text)
    text = re.sub(r"[^A-Za-z0-9]+", "_", text)
    return text.strip("_").casefold()


def _is_secret_key(key: object) -> bool:
    """Whether a key names a credential or authentication value."""

    normalised = _normalise_key(key)
    if normalised in _SECRET_KEY_PARTS:
        return True
    parts = set(normalised.split("_"))
    return bool(
        parts
        & {
            "apikey",
            "authorization",
            "bearer",
            "credential",
            "credentials",
            "password",
            "passwd",
            "secret",
            "token",
        }
    ) or ("key" in parts and parts & {"access", "api", "client", "private", "secret", "signing"})


def _is_execution_only_key(key: object) -> bool:
    """Whether a key identifies a particular execution or its output."""

    normalised = _normalise_key(key)
    if normalised in _EXECUTION_ONLY_KEYS or normalised in _OUTPUT_OBJECT_KEYS:
        return True
    # Cover output_dir, report_file, artifact_filename, and similar variants
    # without excluding meaningful setup values such as ``output_mode``.
    suffixes = (
        "_artifact_path",
        "_file_path",
        "_log_path",
        "_output_dir",
        "_output_path",
        "_report_path",
    )
    return normalised.endswith(suffixes)


def _as_mapping(value: object) -> Mapping[str, Any] | None:
    """Convert mapping-like values, dataclasses, and simple model objects."""

    if isinstance(value, Mapping):
        return value
    if is_dataclass(value) and not isinstance(value, type):
        try:
            converted = asdict(value)
        except (TypeError, ValueError):
            return None
        return converted if isinstance(converted, Mapping) else None
    if hasattr(value, "model_dump") and callable(value.model_dump):
        try:
            converted = value.model_dump()
        except Exception:  # pragma: no cover - defensive for third-party models
            return None
        return converted if isinstance(converted, Mapping) else None
    if hasattr(value, "dict") and callable(value.dict):
        try:
            converted = value.dict()
        except Exception:  # pragma: no cover - defensive for third-party models
            return None
        return converted if isinstance(converted, Mapping) else None
    return None


def _canonical_url(value: str) -> str:
    """Remove URL credentials and secret query parameters before hashing."""

    try:
        parsed = urlsplit(value)
    except ValueError:
        return value
    if not parsed.scheme or not parsed.netloc:
        return value

    # ``hostname`` can raise for malformed bracketed IPv6 addresses.
    try:
        hostname = parsed.hostname or ""
        port = parsed.port
    except ValueError:
        return value
    netloc = hostname
    if ":" in hostname and not hostname.startswith("["):
        netloc = f"[{hostname}]"
    if port is not None:
        netloc = f"{netloc}:{port}"

    query: list[tuple[str, str]] = []
    for key, item in parse_qsl(parsed.query, keep_blank_values=True):
        if _is_secret_key(key):
            continue
        query.append((key, item))
    query.sort()
    return urlunsplit((parsed.scheme.casefold(), netloc, parsed.path, urlencode(query), ""))


def _canonicalise(value: object, *, _seen: set[int] | None = None) -> object:
    """Build a JSON-compatible, deterministic, secret-free representation."""

    seen = _seen if _seen is not None else set()
    mapping = _as_mapping(value)
    if mapping is not None:
        object_id = id(value)
        if object_id in seen:
            return "<cycle>"
        seen.add(object_id)
        result: dict[str, object] = {}
        for key, item in mapping.items():
            if _is_secret_key(key) or _is_execution_only_key(key):
                continue
            canonical_value = _canonicalise(item, _seen=seen)
            result[str(key)] = canonical_value
        seen.discard(object_id)
        return {key: result[key] for key in sorted(result, key=_normalise_key)}

    if value is None or isinstance(value, (str, bool, int)):
        if isinstance(value, str) and ("url" in _normalise_key(value) or "://" in value):
            # Only URL-shaped strings are normalised.  Ordinary user-provided
            # strings must retain their exact value in the effective setup.
            return _canonical_url(value) if "://" in value else value
        return value
    if isinstance(value, float):
        if value != value:
            return "<nan>"
        if value == float("inf"):
            return "<infinity>"
        if value == float("-inf"):
            return "<-infinity>"
        return value
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    if isinstance(value, Path):
        return value.as_posix()
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).hex()
    if isinstance(value, MappingProxyType):
        return _canonicalise(dict(value), _seen=seen)
    if isinstance(value, (set, frozenset)):
        values = [_canonicalise(item, _seen=seen) for item in value]
        return sorted(values, key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")))
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_canonicalise(item, _seen=seen) for item in value]
    # Keep unusual scalar values deterministic without ever serialising object
    # addresses (which would make a fingerprint change between processes).
    return str(value)


def _effective_config(config: object) -> object:
    """Unwrap a complete artifact when it is passed instead of its config."""

    mapping = _as_mapping(config)
    if mapping is None:
        return config
    nested = _mapping_get(mapping, "config", default=_MISSING)
    if _as_mapping(nested) is not None:
        marker_keys = {
            "run_id",
            "execution_id",
            "status",
            "final_state",
            "report",
            "schema_version",
            "artifacts",
            "runs",
        }
        normalised_keys = {_normalise_key(key) for key in mapping}
        if normalised_keys & marker_keys:
            # Reuse the same legacy/new extraction used by repository records
            # so top-level setup fields (provider, surface, target URL, etc.)
            # are retained alongside the nested config.
            return _config_from_record(mapping)
    return config


def config_fingerprint(config: object) -> str:
    """Return a deterministic SHA-256 fingerprint of effective run setup.

    Configuration mappings are canonicalised recursively: mapping keys are
    sorted, set values are made deterministic, and JSON-compatible values are
    retained.  Credentials, execution identity, timing, output paths, and
    repeat indexes are omitted at every nesting level, allowing repeated runs
    of the same setup to be grouped without putting secrets in the fingerprint
    input or output.

    Args:
        config: A mapping, dataclass, model object, or a complete artifact
            containing a nested ``config`` mapping.

    Returns:
        A ``sha256:``-prefixed hexadecimal digest.
    """

    canonical = _canonicalise(_effective_config(config))
    encoded = json.dumps(canonical, ensure_ascii=True, sort_keys=True, separators=(",", ":"), default=str)
    return _FINGERPRINT_PREFIX + sha256(encoded.encode("utf-8")).hexdigest()


def new_execution_id() -> str:
    """Create a unique, filename-safe execution identifier."""

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    return f"exec-{timestamp}-{uuid.uuid4().hex}"


def _mapping_get(mapping: Mapping[str, Any], key: str, *, default: object = None) -> object:
    """Get a mapping value using normalised key matching."""

    wanted = _normalise_key(key)
    for candidate, value in mapping.items():
        if _normalise_key(candidate) == wanted:
            return value
    return default


def _first_value(mapping: Mapping[str, Any] | None, keys: Iterable[str]) -> object:
    """Return the first present value among normalised keys."""

    if mapping is None:
        return _MISSING
    for key in keys:
        value = _mapping_get(mapping, key, default=_MISSING)
        if value is not _MISSING and value is not None:
            return value
    return _MISSING


def _nested_values(mapping: Mapping[str, Any], keys: Iterable[str]) -> Iterable[object]:
    """Yield direct and common nested record values for a metadata field."""

    direct = _first_value(mapping, keys)
    if direct is not _MISSING:
        yield direct
    for container_key in _NESTED_RECORD_KEYS:
        nested = _as_mapping(_mapping_get(mapping, container_key, default=None))
        if nested is None:
            continue
        value = _first_value(nested, keys)
        if value is not _MISSING:
            yield value


def _string_value(value: object) -> str | None:
    """Convert scalar metadata values to clean strings."""

    if value is _MISSING or value is None or isinstance(value, (Mapping, Sequence)) and not isinstance(value, str):
        return None
    text = str(value).strip()
    return text or None


def _parse_timestamp(value: object) -> float | None:
    """Parse common JSON timestamp representations into UTC epoch seconds."""

    if value is None or value is _MISSING or isinstance(value, (Mapping, Sequence)) and not isinstance(value, str):
        return None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    if isinstance(value, datetime):
        parsed = value
    else:
        text = str(value).strip()
        if not text:
            return None
        try:
            numeric = float(text)
        except ValueError:
            numeric = None
        if numeric is not None:
            return numeric
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def _record_timestamp(record: Mapping[str, Any]) -> float | None:
    """Find the latest meaningful timestamp in a run record."""

    values: list[float] = []
    for value in _nested_values(record, _TIMESTAMP_KEYS):
        parsed = _parse_timestamp(value)
        if parsed is not None:
            values.append(parsed)
    return max(values) if values else None


def _deep_merge(base: Mapping[str, Any] | None, override: Mapping[str, Any] | None) -> dict[str, Any]:
    """Merge matrix-level setup with an individual run's setup."""

    result: dict[str, Any] = dict(base or {})
    for key, value in (override or {}).items():
        existing = result.get(key)
        if isinstance(existing, Mapping) and isinstance(value, Mapping):
            result[key] = _deep_merge(existing, value)
        else:
            result[key] = value
    return result


def _config_from_record(record: Mapping[str, Any], parent: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Extract effective setup from legacy and new record layouts."""

    parent_config = _as_mapping(_mapping_get(parent or {}, "config", default=None)) if parent else None
    own_config_value = _first_value(record, ("config", "setup", "settings", "run_config", "engagement_config"))
    own_config = _as_mapping(own_config_value) if own_config_value is not _MISSING else None
    if own_config is None:
        # Newer envelopes sometimes put the run record under ``data`` or
        # ``metadata`` and keep its setup one level below that envelope.
        for container_key in _NESTED_RECORD_KEYS:
            nested = _as_mapping(_mapping_get(record, container_key, default=None))
            if nested is None:
                continue
            nested_value = _first_value(
                nested,
                ("config", "setup", "settings", "run_config", "engagement_config"),
            )
            nested_config = _as_mapping(nested_value) if nested_value is not _MISSING else None
            if nested_config is not None:
                own_config = nested_config
                break

    # A few early artifacts put configuration fields at the top level.  Keep
    # only setup-like fields so result/report payloads do not become setup.
    setup: dict[str, Any] = {}
    setup_keys = {
        "candidate_budget",
        "coverage_target",
        "evasion_cooldown_threshold",
        "evasion_enabled",
        "evasion_max_retries",
        "evasion_mode",
        "iterations",
        "max_iterations",
        "model",
        "model_config",
        "payload_mode",
        "provider",
        "repeat_policy",
        "security_level",
        "stop_policy",
        "surface",
        "target_method",
        "target_url",
    }
    for key, value in (parent or {}).items():
        if _normalise_key(key) in setup_keys:
            setup[str(key)] = value
    for key, value in record.items():
        if _normalise_key(key) in setup_keys:
            setup[str(key)] = value

    # Merge in order from broadest fallback to most specific run values.  In
    # particular, new artifacts may repeat scalar metadata at the top level
    # while putting credentials and optional settings inside ``config``.
    return _deep_merge(_deep_merge(parent_config, setup), own_config)


def _metadata_value(
    record: Mapping[str, Any],
    parent: Mapping[str, Any] | None,
    keys: Iterable[str],
) -> object:
    """Look up metadata on a run, then fall back to its matrix container."""

    for source in (record, parent):
        if source is None:
            continue
        value = _first_value(source, keys)
        if value is not _MISSING:
            # ``execution: {execution_id: ...}`` and ``result: {status: ...}``
            # are both used by newer writers.  A mapping found under a field
            # name is a container, not the scalar value the caller requested.
            nested_value = _first_value(_as_mapping(value), keys)
            if nested_value is not _MISSING:
                return nested_value
            if _as_mapping(value) is None:
                return value
        for container_key in _NESTED_RECORD_KEYS:
            nested = _as_mapping(_mapping_get(source, container_key, default=None))
            if nested is not None:
                value = _first_value(nested, keys)
                if value is not _MISSING:
                    return value
    return _MISSING


def _looks_like_record(value: object) -> bool:
    """Whether a JSON object contains recognizable artifact markers."""

    mapping = _as_mapping(value)
    if mapping is None:
        return False
    marker_keys = {
        "config",
        "execution_id",
        "provider",
        "payload_mode",
        "run_id",
        "schema_version",
        "security_level",
        "status",
        "surface",
    }
    keys = {_normalise_key(key) for key in mapping}
    if keys & marker_keys:
        return True
    return any(_as_mapping(_mapping_get(mapping, key, default=None)) is not None for key in _NESTED_RECORD_KEYS)


def _matrix_children(value: Mapping[str, Any]) -> tuple[str, Sequence[object]] | None:
    """Return the first recognized matrix child collection, if present."""

    for key, children in value.items():
        if _normalise_key(key) not in _MATRIX_KEYS:
            continue
        if isinstance(children, Sequence) and not isinstance(children, (str, bytes, bytearray)):
            return str(key), children
        if isinstance(children, Mapping):
            # Some matrix writers index runs by run ID instead of emitting a
            # list.  Mapping values are the records in that representation.
            values = list(children.values())
            if values and all(_as_mapping(item) is not None for item in values):
                return str(key), values
    # ``matrix: [...]`` is a common wrapper spelling and is intentionally
    # checked separately from the boolean ``matrix: true`` config flag.
    matrix = _mapping_get(value, "matrix", default=None)
    if isinstance(matrix, Sequence) and not isinstance(matrix, (str, bytes, bytearray)):
        return "matrix", matrix
    if isinstance(matrix, Mapping):
        nested = _matrix_children(matrix)
        if nested is not None:
            return "matrix", nested[1]
    return None


@dataclass(frozen=True, slots=True)
class ArtifactMetadata:
    """Metadata for one single-run artifact or one matrix member.

    ``path`` identifies the JSON file on disk.  For matrix members,
    ``item_index`` identifies the member within the source collection and
    ``artifact_kind`` is ``"matrix"``.  The original JSON object is available
    through ``raw`` for detail views, while the scalar fields are safe for
    filtering and list displays.
    """

    path: Path
    execution_id: str | None = None
    run_id: str | None = None
    status: str = "unknown"
    provider: str | None = None
    surface: str | None = None
    security_level: str | None = None
    payload_mode: str | None = None
    config_fingerprint: str | None = None
    artifact_kind: str = "single"
    item_index: int | None = None
    schema_version: str | None = None
    timestamp: float | None = None
    modified_at: float = 0.0
    config: Mapping[str, Any] = field(default_factory=dict, repr=False, compare=False)
    raw: Mapping[str, Any] = field(default_factory=dict, repr=False, compare=False)

    @property
    def artifact_type(self) -> str:
        """Compatibility alias for :attr:`artifact_kind`."""

        return self.artifact_kind

    @property
    def kind(self) -> str:
        """Short alias for :attr:`artifact_kind`."""

        return self.artifact_kind

    @property
    def is_matrix(self) -> bool:
        """Whether this record originated in a matrix artifact."""

        return self.artifact_kind == "matrix"

    @property
    def artifact_path(self) -> Path:
        """Compatibility alias for :attr:`path`."""

        return self.path

    @property
    def file_path(self) -> Path:
        """Compatibility alias for :attr:`path`."""

        return self.path

    @property
    def source_path(self) -> Path:
        """Compatibility alias for :attr:`path`."""

        return self.path

    @property
    def filename(self) -> str:
        """The source filename without requiring a UI-specific path type."""

        return self.path.name

    @property
    def relative_path(self) -> str:
        """Return the path as a stable display string."""

        return str(self.path)

    @property
    def identifier(self) -> str | None:
        """Return the new ID when present, otherwise the legacy run ID."""

        return self.execution_id or self.run_id

    @property
    def id(self) -> str | None:
        """Compatibility alias for :attr:`identifier`."""

        return self.identifier

    @property
    def raw_artifact(self) -> Mapping[str, Any]:
        """Compatibility alias for :attr:`raw`."""

        return self.raw

    @property
    def artifact(self) -> Mapping[str, Any]:
        """Compatibility alias for the original JSON record."""

        return self.raw

    @property
    def sort_timestamp(self) -> float:
        """Timestamp used for newest-first ordering."""

        return self.timestamp if self.timestamp is not None else self.modified_at

    @property
    def mtime(self) -> float:
        """Compatibility alias for :attr:`modified_at`."""

        return self.modified_at

    @property
    def last_modified(self) -> float:
        """Compatibility alias for :attr:`modified_at`."""

        return self.modified_at


def _metadata_from_record(
    path: Path,
    record: Mapping[str, Any],
    *,
    parent: Mapping[str, Any] | None,
    artifact_kind: str,
    item_index: int | None,
    modified_at: float,
    retain_raw: bool,
) -> ArtifactMetadata:
    """Build a metadata record from a legacy/new run mapping."""

    config = _config_from_record(record, parent)
    own_run = _metadata_value(record, None, ("run_id", "legacy_run_id", "id"))
    execution_id = _string_value(
        _metadata_value(record, parent, ("execution_id", "execution", "execution_uuid"))
    )
    run_id = _string_value(
        own_run
        if own_run is not _MISSING
        else _metadata_value(record, parent, ("run_id", "legacy_run_id", "id"))
    )
    status = _string_value(_metadata_value(record, parent, ("status", "run_status", "state"))) or "unknown"
    provider = _string_value(_metadata_value(record, parent, ("provider", "llm_provider")))
    surface = _string_value(_metadata_value(record, parent, ("surface", "current_surface", "target_surface")))
    security_level = _string_value(
        _metadata_value(record, parent, ("security_level", "security", "level"))
    )
    payload_mode = _string_value(_metadata_value(record, parent, ("payload_mode", "payload_kind")))
    schema_version = _string_value(_metadata_value(record, parent, ("schema_version", "schema")))
    timestamp = _record_timestamp(record) or (_record_timestamp(parent) if parent else None)

    explicit_fingerprint = _string_value(
        _metadata_value(record, parent, ("config_fingerprint", "configuration_fingerprint"))
    )
    fingerprint = explicit_fingerprint or (config_fingerprint(config) if config else None)

    # Keep the records useful when provider/surface/etc. only occur in the
    # nested config mapping, as is the case for the original runner output.
    provider = provider or _string_value(_first_value(config, ("provider", "llm_provider")))
    surface = surface or _string_value(_first_value(config, ("surface", "current_surface")))
    security_level = security_level or _string_value(_first_value(config, ("security_level", "level")))
    payload_mode = payload_mode or _string_value(_first_value(config, ("payload_mode", "payload_kind")))

    return ArtifactMetadata(
        path=path,
        execution_id=execution_id,
        run_id=run_id,
        status=status,
        provider=provider,
        surface=surface,
        security_level=security_level,
        payload_mode=payload_mode,
        config_fingerprint=fingerprint,
        artifact_kind=artifact_kind,
        item_index=item_index,
        schema_version=schema_version,
        timestamp=timestamp,
        modified_at=modified_at,
        config=MappingProxyType(dict(config)),
        raw=MappingProxyType(dict(record)) if retain_raw else MappingProxyType({}),
    )


def _flatten_records(
    path: Path,
    value: object,
    *,
    parent: Mapping[str, Any] | None,
    artifact_kind: str,
    item_index: int | None,
    modified_at: float,
    retain_raw: bool,
) -> list[ArtifactMetadata]:
    """Flatten single, list, and matrix artifact layouts."""

    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        records: list[ArtifactMetadata] = []
        for index, child in enumerate(value):
            records.extend(
                _flatten_records(
                    path,
                    child,
                    parent=parent,
                    artifact_kind="matrix",
                    item_index=index,
                    modified_at=modified_at,
                    retain_raw=retain_raw,
                )
            )
        return records

    mapping = _as_mapping(value)
    if mapping is None:
        return []
    children = _matrix_children(mapping)
    if children is not None:
        child_key, child_values = children
        child_parent = dict(parent or {})
        # Include root setup/identity fields as fallback for child records,
        # while avoiding a nested child collection being treated as setup.
        for key, child_value in mapping.items():
            if _normalise_key(key) == _normalise_key(child_key):
                continue
            child_parent[key] = child_value
        records = []
        for index, child in enumerate(child_values):
            records.extend(
                _flatten_records(
                    path,
                    child,
                    parent=child_parent,
                    artifact_kind="matrix",
                    item_index=index,
                    modified_at=modified_at,
                    retain_raw=retain_raw,
                )
            )
        # An empty matrix still deserves a file-level metadata entry when it
        # contains run identity/setup markers.
        if records or not _looks_like_record(mapping):
            return records
    if not _looks_like_record(mapping) and parent is not None:
        # A matrix member may be a tiny object such as ``{"status": ...}``;
        # if it has no markers, parent metadata is still enough to classify it
        # only when it explicitly contains a run-like scalar.
        return []
    return [
        _metadata_from_record(
            path,
            mapping,
            parent=parent,
            artifact_kind=artifact_kind,
            item_index=item_index,
            modified_at=modified_at,
            retain_raw=retain_raw,
        )
    ]


class ArtifactRepository:
    """Read-only repository for recursively discovered JSON run artifacts."""

    def __init__(
        self,
        root: str | os.PathLike[str] = ".",
        *,
        artifact_root: str | os.PathLike[str] | None = None,
        include_sidecars: bool = False,
    ) -> None:
        """Create a repository rooted at a file or directory."""

        self.root = Path(artifact_root if artifact_root is not None else root)
        self.include_sidecars = bool(include_sidecars)
        self._cache: tuple[ArtifactMetadata, ...] = ()

    def _json_paths(self) -> list[Path]:
        """Return readable candidates without failing on missing directories."""

        try:
            is_file = self.root.is_file()
            is_dir = self.root.is_dir()
        except OSError as exc:
            LOGGER.debug("Ignoring artifact root %s: %s", self.root, exc)
            return []

        if is_file:
            candidates = [self.root] if self.root.suffix.casefold() == ".json" else []
        elif is_dir:
            candidates = []

            def _ignore_walk_error(error: OSError) -> None:
                LOGGER.debug("Ignoring artifact directory: %s", error)

            try:
                for directory, _, filenames in os.walk(self.root, onerror=_ignore_walk_error):
                    for filename in filenames:
                        if filename.casefold().endswith(".json"):
                            candidates.append(Path(directory) / filename)
            except OSError as exc:
                LOGGER.debug("Ignoring artifact root %s: %s", self.root, exc)
        else:
            return []

        unique: dict[str, Path] = {}
        for path in candidates:
            if not self.include_sidecars and path.name.casefold().endswith(_SIDECAR_SUFFIXES):
                continue
            try:
                unique[str(path)] = path
            except (OSError, ValueError):
                continue
        return sorted(unique.values(), key=lambda item: str(item))

    @staticmethod
    def _read_json(path: Path) -> object | None:
        """Read one JSON file, converting malformed/unreadable files to None."""

        try:
            with path.open("r", encoding="utf-8") as handle:
                return json.load(handle)
        except (OSError, UnicodeError, json.JSONDecodeError, TypeError) as exc:
            LOGGER.debug("Ignoring unreadable artifact %s: %s", path, exc)
            return None

    @staticmethod
    def _mtime(path: Path) -> float:
        """Get a file modification time without making stat failures fatal."""

        try:
            return path.stat().st_mtime
        except OSError:
            return 0.0

    def scan(
        self,
        filters: Mapping[str, object] | None = None,
        *,
        status: object = None,
        provider: object = None,
        surface: object = None,
        security_level: object = None,
        payload_mode: object = None,
        retain_raw: bool = True,
    ) -> list[ArtifactMetadata]:
        """Recursively scan and return newest-first artifact metadata.

        Args:
            filters: Optional mapping containing any supported filter names.
            status: Case-insensitive status filter.
            provider: Case-insensitive provider filter.
            surface: Case-insensitive surface filter.
            security_level: Case-insensitive DVWA security-level filter.
            payload_mode: Case-insensitive payload-mode filter.
            retain_raw: Keep each complete artifact record in returned metadata.
                List-only callers can disable this to substantially reduce memory.

        Malformed JSON, decode errors, missing files, and permission errors are
        ignored individually.  A matrix JSON document is flattened into one
        metadata item per run member.
        """

        options: dict[str, object] = dict(filters or {})
        for key, value in {
            "status": status,
            "provider": provider,
            "surface": surface,
            "security_level": security_level,
            "payload_mode": payload_mode,
        }.items():
            if value is not None:
                options[key] = value

        items: list[ArtifactMetadata] = []
        for path in self._json_paths():
            payload = self._read_json(path)
            if payload is None:
                continue
            modified_at = self._mtime(path)
            items.extend(
                _flatten_records(
                    path,
                    payload,
                    parent=None,
                    artifact_kind="matrix" if isinstance(payload, list) else "single",
                    item_index=None,
                    modified_at=modified_at,
                    retain_raw=retain_raw,
                )
            )

        items.sort(key=lambda item: (-item.sort_timestamp, str(item.path), item.item_index or -1))
        self._cache = tuple(items)
        return [item for item in items if _matches_filters(item, options)]

    def refresh(
        self,
        filters: Mapping[str, object] | None = None,
        **kwargs: object,
    ) -> list[ArtifactMetadata]:
        """Alias for :meth:`scan` useful to callers that prefer cache wording."""

        return self.scan(filters, **kwargs)

    def list_artifacts(
        self,
        filters: Mapping[str, object] | None = None,
        **kwargs: object,
    ) -> list[ArtifactMetadata]:
        """Return artifact metadata using the same filters as :meth:`scan`."""

        return self.scan(filters, **kwargs)

    def list_runs(
        self,
        filters: Mapping[str, object] | None = None,
        **kwargs: object,
    ) -> list[ArtifactMetadata]:
        """Return run metadata, including flattened matrix members."""

        return self.scan(filters, **kwargs)

    def discover(
        self,
        filters: Mapping[str, object] | None = None,
        **kwargs: object,
    ) -> list[ArtifactMetadata]:
        """Alias for :meth:`scan` used by discovery-oriented callers."""

        return self.scan(filters, **kwargs)

    def load(
        self,
        filters: Mapping[str, object] | None = None,
        **kwargs: object,
    ) -> list[ArtifactMetadata]:
        """Alias for :meth:`scan` used by repository-oriented callers."""

        return self.scan(filters, **kwargs)

    def all(
        self,
        filters: Mapping[str, object] | None = None,
        **kwargs: object,
    ) -> list[ArtifactMetadata]:
        """Return all readable records, optionally filtered."""

        return self.scan(filters, **kwargs)

    def list(
        self,
        filters: Mapping[str, object] | None = None,
        **kwargs: object,
    ) -> list[ArtifactMetadata]:
        """Return readable artifact metadata using a concise method name."""

        return self.scan(filters, **kwargs)

    def get_artifacts(
        self,
        filters: Mapping[str, object] | None = None,
        **kwargs: object,
    ) -> list[ArtifactMetadata]:
        """Alias for :meth:`scan`."""

        return self.scan(filters, **kwargs)

    @property
    def artifacts(self) -> tuple[ArtifactMetadata, ...]:
        """Return the most recently scanned unfiltered metadata snapshot."""

        if not self._cache:
            self.scan()
        return self._cache

    def filter(self, items: Iterable[ArtifactMetadata] | None = None, **filters: object) -> list[ArtifactMetadata]:
        """Apply supported filters to an existing snapshot or fresh scan."""

        source = list(items) if items is not None else list(self.artifacts)
        return [item for item in source if _matches_filters(item, filters)]

    def find_by_execution_id(self, execution_id: str) -> ArtifactMetadata | None:
        """Find the newest record with a new-style execution ID."""

        wanted = str(execution_id)
        return next((item for item in self.scan() if item.execution_id == wanted), None)

    def find_by_run_id(self, run_id: str) -> ArtifactMetadata | None:
        """Find the newest record by legacy ``run_id``."""

        wanted = str(run_id)
        return next((item for item in self.scan() if item.run_id == wanted), None)

    def get_by_execution_id(self, execution_id: str) -> ArtifactMetadata | None:
        """Alias for :meth:`find_by_execution_id`."""

        return self.find_by_execution_id(execution_id)

    def get_by_run_id(self, run_id: str) -> ArtifactMetadata | None:
        """Alias for :meth:`find_by_run_id`."""

        return self.find_by_run_id(run_id)

    def find_all_by_execution_id(self, execution_id: str) -> list[ArtifactMetadata]:
        """Find all records sharing an execution ID, newest first."""

        wanted = str(execution_id)
        return [item for item in self.scan() if item.execution_id == wanted]

    def find_all_by_run_id(self, run_id: str) -> list[ArtifactMetadata]:
        """Find all records sharing a legacy run ID, newest first."""

        wanted = str(run_id)
        return [item for item in self.scan() if item.run_id == wanted]

    def lookup(self, identifier: str) -> ArtifactMetadata | None:
        """Look up an execution ID first, then a legacy run ID."""

        return self.find_by_execution_id(identifier) or self.find_by_run_id(identifier)

    def find_by_id(self, identifier: str) -> ArtifactMetadata | None:
        """Alias for :meth:`lookup`."""

        return self.lookup(identifier)

    def get(
        self,
        identifier: str | None = None,
        *,
        execution_id: str | None = None,
        run_id: str | None = None,
    ) -> ArtifactMetadata | None:
        """Alias for :meth:`lookup`."""

        return self.find(identifier, execution_id=execution_id, run_id=run_id)

    def find(
        self,
        identifier: str | None = None,
        *,
        execution_id: str | None = None,
        run_id: str | None = None,
    ) -> ArtifactMetadata | None:
        """Find a record by execution ID, legacy run ID, or either identifier."""

        if execution_id is not None:
            return self.find_by_execution_id(execution_id)
        if run_id is not None:
            return self.find_by_run_id(run_id)
        return self.lookup(identifier) if identifier is not None else None

    def duplicate_config_fingerprints(
        self,
        items: Iterable[ArtifactMetadata] | None = None,
    ) -> dict[str, list[ArtifactMetadata]]:
        """Group configuration fingerprints occurring in at least two runs."""

        source = list(items) if items is not None else list(self.artifacts)
        groups: dict[str, list[ArtifactMetadata]] = {}
        for item in source:
            fingerprint = item.config_fingerprint
            if not fingerprint:
                continue
            groups.setdefault(fingerprint, []).append(item)
        return {key: value for key, value in groups.items() if len(value) > 1}

    def group_by_config_fingerprint(
        self,
        items: Iterable[ArtifactMetadata] | None = None,
        *,
        duplicates_only: bool = False,
    ) -> dict[str, list[ArtifactMetadata]]:
        """Group records by fingerprint, optionally retaining duplicates only."""

        source = list(items) if items is not None else list(self.artifacts)
        groups: dict[str, list[ArtifactMetadata]] = {}
        for item in source:
            if item.config_fingerprint:
                groups.setdefault(item.config_fingerprint, []).append(item)
        if duplicates_only:
            return {key: value for key, value in groups.items() if len(value) > 1}
        return groups

    # A compact name is convenient for UI adapters and keeps compatibility
    # with callers that call this operation simply ``duplicates``.
    duplicates = duplicate_config_fingerprints
    duplicate_groups = duplicate_config_fingerprints


def _matches_filter(value: str | None, requested: object) -> bool:
    """Case-insensitive scalar or collection filter matching."""

    if requested is None:
        return True
    if isinstance(requested, str):
        values = {requested.casefold().strip()}
    elif isinstance(requested, Iterable) and not isinstance(requested, (bytes, bytearray, Mapping)):
        values = {str(item).casefold().strip() for item in requested}
    else:
        values = {str(requested).casefold().strip()}
    if not values or "*" in values:
        return True
    return value is not None and value.casefold().strip() in values


def _matches_filters(item: ArtifactMetadata, filters: Mapping[str, object]) -> bool:
    """Return whether an item satisfies all supported metadata filters."""

    aliases = {
        "security": "security_level",
        "level": "security_level",
        "payload": "payload_mode",
        "payloadmode": "payload_mode",
    }
    for key, requested in filters.items():
        normalised = _normalise_key(key)
        normalised = aliases.get(normalised, normalised)
        if normalised not in {"status", "provider", "surface", "security_level", "payload_mode"}:
            continue
        if not _matches_filter(getattr(item, normalised), requested):
            return False
    return True


__all__ = [
    "ArtifactMetadata",
    "ArtifactRecord",
    "ArtifactRepository",
    "RunArtifactMetadata",
    "config_fingerprint",
    "new_execution_id",
]


# Lightweight naming aliases keep integrations from having to care whether a
# caller calls the returned value a metadata record or an artifact record.
ArtifactRecord = ArtifactMetadata
RunArtifactMetadata = ArtifactMetadata
