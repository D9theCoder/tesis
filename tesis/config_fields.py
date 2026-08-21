"""Declarative configuration fields used by the runtime settings forms.

The runtime configuration is intentionally a plain YAML mapping.  This module
describes that mapping without coupling it to a UI toolkit: a field has a
configuration path, a value type, optional choices, and validation metadata.
The same descriptions can therefore be used by a settings editor, a single
engagement form, or the matrix form.

There are two details worth calling out here:

* Choices for providers, surfaces, security levels, payload modes, and methods
  are taken from the runtime registries.  Keeping those values in one place
  prevents a form from quietly drifting out of scope.
* ``FieldSpec.aliases`` describes legacy spellings (for example
  ``evasion_enabled`` versus the nested ``evasion.enabled``).  The nested path
  helpers use an existing alias when updating a legacy document, so editing an
  older config does not unexpectedly change its shape.

No Textual (or other UI) dependency is imported here.
"""

from __future__ import annotations

import logging
import math
import re
from collections.abc import Callable, Iterable, Mapping, MutableMapping, Sequence
from dataclasses import dataclass, field, replace
from enum import StrEnum
from typing import Any, TypeAlias
from urllib.parse import urlparse

from core.state import (
    ALL_METHOD_AGENTS,
    METHODS_BY_SURFACE,
    PAYLOAD_MODES as STATE_PAYLOAD_MODES,
    SECURITY_LEVELS as CANONICAL_SECURITY_LEVELS,
    SURFACES as CANONICAL_SURFACES,
)
from llm.provider import SUPPORTED_PROVIDERS
from tesis.model_config import EVASION_MODES, PAYLOAD_MODES as MODEL_PAYLOAD_MODES


# ---------------------------------------------------------------------------
# Canonical option registries
# ---------------------------------------------------------------------------

# These are snapshots of the framework registries, rather than hand-written
# widget options.  The small helper functions below read the registries again
# when callers need a fresh view (which is useful for tests and extensions).
PROVIDER_CHOICES: tuple[str, ...] = tuple(str(item) for item in SUPPORTED_PROVIDERS)
SURFACE_CHOICES: tuple[str, ...] = tuple(str(item) for item in CANONICAL_SURFACES)
SECURITY_LEVEL_CHOICES: tuple[str, ...] = tuple(str(item) for item in CANONICAL_SECURITY_LEVELS)

# ``model_config.PAYLOAD_MODES`` is the typed-config registry.  The state
# registry is retained as a fallback for older checkouts where that constant
# was not exported by model_config yet.  The state list supplies stable UI
# ordering when the typed registry is a frozenset.
_PAYLOAD_MODE_REGISTRY: Sequence[str] = MODEL_PAYLOAD_MODES or STATE_PAYLOAD_MODES


def _ordered_registry_values(primary: Iterable[str], preferred_order: Iterable[str]) -> tuple[str, ...]:
    allowed = {str(item) for item in primary}
    ordered = [str(item) for item in preferred_order if str(item) in allowed]
    ordered.extend(item for item in allowed if item not in ordered)
    return tuple(ordered)


PAYLOAD_MODE_CHOICES: tuple[str, ...] = _ordered_registry_values(
    _PAYLOAD_MODE_REGISTRY,
    STATE_PAYLOAD_MODES,
)

# Experiment conditions were added after the original EngagementConfig.  A
# later model_config can provide the registry; the fallback keeps this module
# usable with the current backward-compatible checkout.
try:  # pragma: no cover - the fallback is exercised on older checkouts only
    from tesis.model_config import EXPERIMENT_CONDITIONS as _MODEL_EXPERIMENT_CONDITIONS
except ImportError:  # pragma: no cover - import behavior depends on checkout
    _MODEL_EXPERIMENT_CONDITIONS = ()

EXPERIMENT_CONDITIONS: tuple[str, ...] = tuple(
    str(item) for item in (_MODEL_EXPERIMENT_CONDITIONS or ("linear_hybrid", "akg_guided_hybrid"))
)


def _ordered_methods() -> tuple[str, ...]:
    """Return method IDs in the canonical surface-registry order.

    ``ALL_METHOD_AGENTS`` is authoritative for the complete set.  Walking
    ``METHODS_BY_SURFACE`` first preserves the user-facing surface order while
    still retaining a method that an extension may have registered only in the
    flat list.
    """

    ordered: list[str] = []
    for surface in CANONICAL_SURFACES:
        for method in METHODS_BY_SURFACE.get(surface, ()):
            if method not in ordered:
                ordered.append(method)
    for method in ALL_METHOD_AGENTS:
        if method not in ordered:
            ordered.append(method)
    return tuple(str(method) for method in ordered)


METHOD_CHOICES: tuple[str, ...] = _ordered_methods()


def provider_choices() -> tuple[str, ...]:
    """Return the currently registered LLM provider IDs."""

    return tuple(str(item) for item in SUPPORTED_PROVIDERS)


def surface_choices() -> tuple[str, ...]:
    """Return the currently registered vulnerability surfaces."""

    return tuple(str(item) for item in CANONICAL_SURFACES)


def security_level_choices() -> tuple[str, ...]:
    """Return the currently registered DVWA security levels."""

    return tuple(str(item) for item in CANONICAL_SECURITY_LEVELS)


def payload_mode_choices() -> tuple[str, ...]:
    """Return payload modes from the typed-config/state registries."""

    # Prefer model_config, but fall back to state for compatibility with the
    # pre-Stage-7 model module.
    values = MODEL_PAYLOAD_MODES or STATE_PAYLOAD_MODES
    return _ordered_registry_values(values, STATE_PAYLOAD_MODES)


def method_choices(surface: str | None = None) -> tuple[str, ...]:
    """Return canonical methods, optionally narrowed to one surface."""

    if surface is None or not str(surface).strip():
        return _ordered_methods()
    return tuple(str(item) for item in METHODS_BY_SURFACE.get(str(surface).strip().lower(), ()))


def methods_for_surface(surface: str | None = None) -> tuple[str, ...]:
    """Backward-compatible alias for :func:`method_choices`."""

    return method_choices(surface)


def _methods_for_config(config: Mapping[str, Any] | None = None) -> tuple[str, ...]:
    """Resolve method choices for a single-run config mapping."""

    surface = config.get("surface") if isinstance(config, Mapping) else None
    return method_choices(str(surface) if surface else None)


def _model_profile_choices(config: Mapping[str, Any] | None = None) -> tuple[str, ...]:
    """Resolve selectable named model profiles from a resolved config."""

    if not isinstance(config, Mapping):
        return ()
    models = config.get("models")
    if not isinstance(models, Mapping):
        return ()
    return tuple(str(name) for name in models if str(name).strip())


def _matrix_methods_for_config(config: Mapping[str, Any] | None = None) -> tuple[str, ...]:
    """Resolve the union of methods selected by matrix surfaces."""

    if not isinstance(config, Mapping):
        return method_choices()
    surfaces = config.get("surfaces")
    if isinstance(surfaces, str):
        surfaces = [surfaces]
    if not isinstance(surfaces, Sequence):
        return method_choices()

    selected: list[str] = []
    for surface in surfaces:
        for method in method_choices(str(surface)):
            if method not in selected:
                selected.append(method)
    return tuple(selected) if selected else method_choices()


def _logging_choices() -> tuple[str, ...]:
    """Return standard logging names in increasing severity order."""

    # Looking up names by the stdlib numeric constants avoids maintaining a
    # second list of logging values in the form schema.
    levels = (logging.DEBUG, logging.INFO, logging.WARNING, logging.ERROR, logging.CRITICAL)
    return tuple(str(logging.getLevelName(level)).lower() for level in levels)


LOG_VERBOSITY_CHOICES: tuple[str, ...] = _logging_choices()
LOG_LEVEL_CHOICES = LOG_VERBOSITY_CHOICES


# ---------------------------------------------------------------------------
# Field model and categories
# ---------------------------------------------------------------------------


class FieldCategory(StrEnum):
    """Stable categories shared by settings, single-run, and matrix forms."""

    TARGET = "target"
    RUN = "run"
    MATRIX = "matrix"
    REPORTING = "reporting"
    LOGGING = "logging"
    GUARDRAIL_RETRY = "guardrail_retry"
    MODEL = "model"
    COMPATIBILITY = "compatibility"


FIELD_CATEGORIES: tuple[str, ...] = tuple(category.value for category in FieldCategory)
CATEGORIES = FIELD_CATEGORIES

FORM_SETTINGS = "settings"
FORM_SINGLE = "single"
FORM_MATRIX = "matrix"
FORM_SINGLE_RUN = "single_run"
FORM_MATRIX_RUN = "matrix_run"
FORM_NAMES: tuple[str, ...] = (FORM_SETTINGS, FORM_SINGLE, FORM_MATRIX)

ChoiceSource: TypeAlias = Sequence[Any] | Callable[..., Iterable[Any]]
FieldType: TypeAlias = type[Any] | str
FieldValidator: TypeAlias = Callable[[Any], Any]
FieldCoercer: TypeAlias = Callable[[Any], Any]


@dataclass(frozen=True, slots=True)
class FieldSpec:
    """Typed, UI-neutral description of one config value.

    ``path`` uses dot notation (``models.{provider}.api_key`` is a supported
    template).  ``kind`` is a rendering hint only; callers are free to map it
    to any UI toolkit.  ``value_type`` is what the coercion and validation
    helpers enforce.
    """

    path: str
    label: str = ""
    category: str = FieldCategory.RUN.value
    value_type: FieldType = str
    kind: str = "text"
    default: Any = None
    choices: ChoiceSource | None = None
    required: bool = False
    secret: bool = False
    multiple: bool = False
    item_type: FieldType = str
    allow_none: bool = False
    min_value: int | float | None = None
    max_value: int | float | None = None
    min_items: int | None = None
    max_items: int | None = None
    aliases: tuple[str, ...] = ()
    forms: tuple[str, ...] = FORM_NAMES
    description: str = ""
    normalize: str | None = None
    validator: FieldValidator | None = None
    coercer: FieldCoercer | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.path or not isinstance(self.path, str):
            raise ValueError("FieldSpec.path must be a non-empty string")
        if not self.label:
            object.__setattr__(self, "label", _humanize_path(self.path))
        object.__setattr__(self, "category", str(self.category))
        object.__setattr__(self, "forms", tuple(str(form) for form in self.forms))
        object.__setattr__(self, "aliases", tuple(str(alias) for alias in self.aliases))

    @property
    def key(self) -> str:
        """Alias for ``path`` used by form code that calls fields keys."""

        return self.path

    @property
    def name(self) -> str:
        """Return the final path component as a convenient display name."""

        return self.path.rsplit(".", 1)[-1]

    @property
    def type(self) -> FieldType:
        """Alias for ``value_type`` (kept for small form adapters)."""

        return self.value_type

    @property
    def field_type(self) -> FieldType:
        return self.value_type

    @property
    def widget(self) -> str:
        """Alias for the UI-neutral rendering hint ``kind``."""

        return self.kind

    @property
    def is_secret(self) -> bool:
        return self.secret

    @property
    def is_multi_select(self) -> bool:
        return self.multiple or self.kind in {"multi_select", "multiselect"}

    @property
    def is_template(self) -> bool:
        return "{" in self.path and "}" in self.path

    def choice_values(self, config: Mapping[str, Any] | None = None) -> tuple[Any, ...]:
        """Resolve this field's choice source for an optional config context."""

        if self.choices is None:
            return ()
        if callable(self.choices):
            return _call_choice_source(self.choices, config)
        return tuple(self.choices)

    def for_provider(self, provider: str) -> "FieldSpec":
        """Expand a model field template for one provider."""

        context = {"provider": provider}
        return replace(
            self,
            path=expand_config_path(self.path, context),
            aliases=tuple(expand_config_path(alias, context) for alias in self.aliases),
        )

    def coerce(self, value: Any, *, config: Mapping[str, Any] | None = None) -> Any:
        return coerce_field_value(self, value, config=config)

    def validate(self, value: Any, *, config: Mapping[str, Any] | None = None) -> Any:
        return validate_field_value(self, value, config=config)


ConfigField = FieldSpec
TypedFieldSpec = FieldSpec


class ConfigPathError(ValueError):
    """Raised when a dotted configuration path cannot be traversed."""


class FieldValidationError(ValueError):
    """Raised when a value does not satisfy a :class:`FieldSpec`."""

    def __init__(self, field_spec: FieldSpec | str, message: str) -> None:
        self.field_spec = field_spec
        super().__init__(f"{_field_path(field_spec)}: {message}")


def _humanize_path(path: str) -> str:
    name = path.rsplit(".", 1)[-1]
    name = re.sub(r"\{([^}]+)\}", r"\1", name)
    name = name.replace("_", " ").replace("-", " ")
    return name[:1].upper() + name[1:]


def _field_path(field_or_path: FieldSpec | str) -> str:
    return field_or_path.path if isinstance(field_or_path, FieldSpec) else str(field_or_path)


def _call_choice_source(source: Callable[..., Iterable[Any]], config: Mapping[str, Any] | None) -> tuple[Any, ...]:
    """Call a choice resolver while accepting zero- or one-argument hooks."""

    try:
        values = source(config)
    except TypeError:
        values = source()
    return tuple(values)


# ---------------------------------------------------------------------------
# Declarative field definitions
# ---------------------------------------------------------------------------


_COMMON_FORMS = (FORM_SETTINGS, FORM_SINGLE, FORM_MATRIX)
_SINGLE_FORMS = (FORM_SETTINGS, FORM_SINGLE)
_MATRIX_FORMS = (FORM_SETTINGS, FORM_MATRIX)
_SETTINGS_ONLY = (FORM_SETTINGS,)


def _field(path: str, **kwargs: Any) -> FieldSpec:
    return FieldSpec(path=path, **kwargs)


TARGET_URL = _field(
    "target_url",
    label="Target URL",
    category=FieldCategory.TARGET.value,
    value_type=str,
    kind="url",
    required=True,
    forms=_COMMON_FORMS,
    description="Authorized DVWA base URL.",
)
PROVIDER = _field(
    "provider",
    label="Provider",
    category=FieldCategory.RUN.value,
    value_type=str,
    kind="select",
    choices=PROVIDER_CHOICES,
    required=True,
    forms=_SINGLE_FORMS,
    normalize="lower",
    aliases=("llm_provider",),
)
SECURITY_LEVEL = _field(
    "level",
    label="Security level",
    category=FieldCategory.RUN.value,
    value_type=str,
    kind="select",
    choices=SECURITY_LEVEL_CHOICES,
    required=True,
    forms=_SINGLE_FORMS,
    normalize="lower",
    aliases=("security_level",),
)
SURFACE = _field(
    "surface",
    label="Surface",
    category=FieldCategory.RUN.value,
    value_type=str,
    kind="select",
    choices=SURFACE_CHOICES,
    required=True,
    forms=_SINGLE_FORMS,
    normalize="lower",
)
PAYLOAD_MODE = _field(
    "payload_mode",
    label="Payload mode",
    category=FieldCategory.RUN.value,
    value_type=str,
    kind="select",
    choices=PAYLOAD_MODE_CHOICES,
    required=True,
    forms=_SINGLE_FORMS,
    normalize="lower",
)
EXPERIMENT_CONDITION = _field(
    "experiment_condition",
    label="Experiment condition",
    category=FieldCategory.RUN.value,
    value_type=str,
    kind="select",
    choices=EXPERIMENT_CONDITIONS,
    default="akg_guided_hybrid",
    required=True,
    forms=_SINGLE_FORMS,
    normalize="lower",
)
TARGET_METHOD = _field(
    "target_method",
    label="Target method",
    category=FieldCategory.RUN.value,
    value_type=str,
    kind="select",
    choices=_methods_for_config,
    allow_none=True,
    forms=_SINGLE_FORMS,
    normalize="lower",
    description="Optional explicit method for method-level evaluation.",
)
MODEL_PROFILE = _field(
    "model_profile",
    label="Model profile",
    category=FieldCategory.MODEL.value,
    value_type=str,
    kind="select",
    choices=_model_profile_choices,
    allow_none=True,
    forms=_COMMON_FORMS,
    description="Optional run-time profile applied to both standard LLM roles.",
)
CANDIDATE_BUDGET = _field(
    "candidate_budget",
    label="Candidate budget",
    category=FieldCategory.RUN.value,
    value_type=int,
    kind="integer",
    default=5,
    min_value=1,
    forms=_COMMON_FORMS,
)
ITERATIONS = _field(
    "iterations",
    label="Iterations",
    category=FieldCategory.RUN.value,
    value_type=int,
    kind="integer",
    default=30,
    min_value=1,
    forms=_COMMON_FORMS,
    aliases=("max_iterations",),
)
REPEATS = _field(
    "repeats",
    label="Repeats",
    category=FieldCategory.RUN.value,
    value_type=int,
    kind="integer",
    default=1,
    min_value=1,
    forms=_COMMON_FORMS,
)
OUTPUT_DIR = _field(
    "output_dir",
    label="Output directory",
    category=FieldCategory.RUN.value,
    value_type=str,
    kind="directory",
    default="results",
    forms=_COMMON_FORMS,
)
MATRIX = _field(
    "matrix",
    label="Matrix mode",
    category=FieldCategory.MATRIX.value,
    value_type=bool,
    kind="boolean",
    default=False,
    forms=_COMMON_FORMS,
)

# Matrix selectors.  The list fields intentionally use the same canonical
# registries as their single-value counterparts.
PROVIDERS = _field(
    "providers",
    label="Providers",
    category=FieldCategory.MATRIX.value,
    value_type=list,
    item_type=str,
    kind="multi_select",
    multiple=True,
    choices=PROVIDER_CHOICES,
    min_items=1,
    forms=_MATRIX_FORMS,
    normalize="lower",
)
LEVELS = _field(
    "levels",
    label="Security levels",
    category=FieldCategory.MATRIX.value,
    value_type=list,
    item_type=str,
    kind="multi_select",
    multiple=True,
    choices=SECURITY_LEVEL_CHOICES,
    min_items=1,
    forms=_MATRIX_FORMS,
    normalize="lower",
)
SURFACES = _field(
    "surfaces",
    label="Surfaces",
    category=FieldCategory.MATRIX.value,
    value_type=list,
    item_type=str,
    kind="multi_select",
    multiple=True,
    choices=SURFACE_CHOICES,
    min_items=1,
    forms=_MATRIX_FORMS,
    normalize="lower",
)
PAYLOAD_MODES = _field(
    "payload_modes",
    label="Payload modes",
    category=FieldCategory.MATRIX.value,
    value_type=list,
    item_type=str,
    kind="multi_select",
    multiple=True,
    choices=PAYLOAD_MODE_CHOICES,
    min_items=1,
    forms=_MATRIX_FORMS,
    normalize="lower",
)
EXPERIMENT_CONDITIONS_FIELD = _field(
    "experiment_conditions",
    label="Experiment conditions",
    category=FieldCategory.MATRIX.value,
    value_type=list,
    item_type=str,
    kind="multi_select",
    multiple=True,
    choices=EXPERIMENT_CONDITIONS,
    min_items=1,
    forms=_MATRIX_FORMS,
    normalize="lower",
)
TARGET_METHODS = _field(
    "target_methods",
    label="Target methods",
    category=FieldCategory.MATRIX.value,
    value_type=list,
    item_type=str,
    kind="multi_select",
    multiple=True,
    choices=_matrix_methods_for_config,
    forms=_MATRIX_FORMS,
    normalize="lower",
)

# Reporting/run controls retained from EngagementConfig/config.yaml.
REPORT_FORMAT = _field(
    "report_format",
    label="Report format",
    category=FieldCategory.REPORTING.value,
    value_type=str,
    kind="select",
    choices=("json", "markdown", "both"),
    default="both",
    forms=_COMMON_FORMS,
    normalize="lower",
    aliases=("format",),
)
ENRICHED_REPORTING = _field(
    "enriched_reporting",
    label="Enriched reporting",
    category=FieldCategory.REPORTING.value,
    value_type=bool,
    kind="boolean",
    default=False,
    forms=_COMMON_FORMS,
)
STOP_POLICY = _field(
    "stop_policy",
    label="Stop policy",
    category=FieldCategory.REPORTING.value,
    value_type=str,
    kind="select",
    choices=("impact", "coverage"),
    default="impact",
    forms=_COMMON_FORMS,
    normalize="lower",
)
COVERAGE_TARGET = _field(
    "coverage_target",
    label="Coverage target",
    category=FieldCategory.REPORTING.value,
    value_type=float,
    kind="decimal",
    default=0.70,
    min_value=0.0,
    max_value=1.0,
    forms=_COMMON_FORMS,
)
DIAGNOSE = _field(
    "diagnose",
    label="Diagnostics",
    category=FieldCategory.REPORTING.value,
    value_type=bool,
    kind="boolean",
    default=False,
    forms=_COMMON_FORMS,
)
LOG_VERBOSITY = _field(
    "log_verbosity",
    label="Log verbosity",
    category=FieldCategory.LOGGING.value,
    value_type=str,
    kind="select",
    choices=LOG_VERBOSITY_CHOICES,
    default="info",
    forms=_COMMON_FORMS,
    normalize="lower",
    aliases=("log_level", "verbosity"),
)

# The YAML currently stores retry controls under ``evasion``.  These aliases
# cover both the old flattened names and the newer guardrail-retry vocabulary.
EVASION_ENABLED = _field(
    "evasion.enabled",
    label="Guardrail retry enabled",
    category=FieldCategory.GUARDRAIL_RETRY.value,
    value_type=bool,
    kind="boolean",
    default=False,
    forms=_COMMON_FORMS,
    aliases=("evasion_enabled", "guardrail_retry_enabled"),
)
EVASION_MODE = _field(
    "evasion.mode",
    label="Guardrail retry mode",
    category=FieldCategory.GUARDRAIL_RETRY.value,
    value_type=str,
    kind="select",
    choices=tuple(str(item) for item in EVASION_MODES),
    default="reactive",
    forms=_COMMON_FORMS,
    normalize="lower",
    aliases=("evasion_mode", "evasion_strategy", "guardrail_retry_mode"),
)
EVASION_MAX_RETRIES = _field(
    "evasion.max_retries",
    label="Guardrail retry maximum",
    category=FieldCategory.GUARDRAIL_RETRY.value,
    value_type=int,
    kind="integer",
    default=3,
    min_value=1,
    forms=_COMMON_FORMS,
    aliases=("evasion_max_retries", "evasion_attempts_max", "guardrail_retry_max"),
)
EVASION_COOLDOWN_THRESHOLD = _field(
    "evasion.cooldown_threshold",
    label="Guardrail retry cooldown",
    category=FieldCategory.GUARDRAIL_RETRY.value,
    value_type=int,
    kind="integer",
    default=5,
    min_value=1,
    forms=_COMMON_FORMS,
    aliases=("evasion_cooldown_threshold", "guardrail_retry_cooldown_threshold"),
)

# Legacy top-level defaults and optional DVWA credentials remain editable so a
# settings form can round-trip existing config.yaml documents faithfully.
DEFAULT_SECURITY_LEVEL = _field(
    "default_security_level",
    label="Default security level",
    category=FieldCategory.COMPATIBILITY.value,
    value_type=str,
    kind="select",
    choices=SECURITY_LEVEL_CHOICES,
    forms=_SETTINGS_ONLY,
    normalize="lower",
)
DEFAULT_LLM_PROVIDER = _field(
    "default_llm_provider",
    label="Default LLM provider",
    category=FieldCategory.COMPATIBILITY.value,
    value_type=str,
    kind="select",
    choices=PROVIDER_CHOICES,
    forms=_SETTINGS_ONLY,
    normalize="lower",
)
DEFAULT_MAX_ITERATIONS = _field(
    "default_max_iterations",
    label="Default max iterations",
    category=FieldCategory.COMPATIBILITY.value,
    value_type=int,
    kind="integer",
    min_value=1,
    forms=_SETTINGS_ONLY,
)
SECURITY_LEVELS_FIELD = _field(
    "security_levels",
    label="Available security levels",
    category=FieldCategory.COMPATIBILITY.value,
    value_type=list,
    item_type=str,
    kind="multi_select",
    multiple=True,
    choices=SECURITY_LEVEL_CHOICES,
    forms=_SETTINGS_ONLY,
    normalize="lower",
)
LLM_PROVIDERS = _field(
    "llm_providers",
    label="Available LLM providers",
    category=FieldCategory.COMPATIBILITY.value,
    value_type=list,
    item_type=str,
    kind="multi_select",
    multiple=True,
    choices=PROVIDER_CHOICES,
    forms=_SETTINGS_ONLY,
    normalize="lower",
)
DVWA_USERNAME = _field(
    "dvwa_username",
    label="DVWA username",
    category=FieldCategory.TARGET.value,
    value_type=str,
    kind="text",
    forms=_SETTINGS_ONLY,
)
DVWA_PASSWORD = _field(
    "dvwa_password",
    label="DVWA password",
    category=FieldCategory.TARGET.value,
    value_type=str,
    kind="secret",
    secret=True,
    forms=_SETTINGS_ONLY,
)

# Provider model settings use a path template.  ``model_field_specs`` expands
# these templates for a concrete provider before a form reads/writes them.
MODEL_PROVIDER = _field(
    "models.{provider}.provider",
    label="Model provider",
    category=FieldCategory.MODEL.value,
    value_type=str,
    kind="select",
    choices=PROVIDER_CHOICES,
    forms=_SETTINGS_ONLY,
    normalize="lower",
)
MODEL_NAME = _field(
    "models.{provider}.model_name",
    label="Model name",
    category=FieldCategory.MODEL.value,
    value_type=str,
    kind="text",
    forms=_SETTINGS_ONLY,
    aliases=("models.{provider}.model",),
)
MODEL_API_KEY = _field(
    "models.{provider}.api_key",
    label="API key",
    category=FieldCategory.MODEL.value,
    value_type=str,
    kind="secret",
    secret=True,
    forms=_SETTINGS_ONLY,
)
MODEL_BASE_URL = _field(
    "models.{provider}.base_url",
    label="Model base URL",
    category=FieldCategory.MODEL.value,
    value_type=str,
    kind="url",
    allow_none=True,
    forms=_SETTINGS_ONLY,
)
MODEL_TEMPERATURE = _field(
    "models.{provider}.temperature",
    label="Temperature",
    category=FieldCategory.MODEL.value,
    value_type=float,
    kind="decimal",
    min_value=0.0,
    forms=_SETTINGS_ONLY,
)
MODEL_MAX_TOKENS = _field(
    "models.{provider}.max_tokens",
    label="Max tokens",
    category=FieldCategory.MODEL.value,
    value_type=int,
    kind="integer",
    allow_none=True,
    min_value=1,
    forms=_SETTINGS_ONLY,
)
MODEL_TIMEOUT = _field(
    "models.{provider}.timeout",
    label="Request timeout",
    category=FieldCategory.MODEL.value,
    value_type=int,
    kind="integer",
    default=60,
    min_value=1,
    forms=_SETTINGS_ONLY,
)
MODEL_SYSTEM_PROMPT = _field(
    "models.{provider}.system_prompt",
    label="System prompt",
    category=FieldCategory.MODEL.value,
    value_type=str,
    kind="textarea",
    allow_none=True,
    forms=_SETTINGS_ONLY,
)


MODEL_FIELDS: tuple[FieldSpec, ...] = (
    MODEL_PROVIDER,
    MODEL_NAME,
    MODEL_API_KEY,
    MODEL_BASE_URL,
    MODEL_TEMPERATURE,
    MODEL_MAX_TOKENS,
    MODEL_TIMEOUT,
    MODEL_SYSTEM_PROMPT,
)


def model_field_specs(provider: str | None = None) -> tuple[FieldSpec, ...]:
    """Return model field templates or fields expanded for ``provider``."""

    if provider is None:
        return MODEL_FIELDS
    return tuple(spec.for_provider(str(provider)) for spec in MODEL_FIELDS)


def fields_for_provider(provider: str | None = None) -> tuple[FieldSpec, ...]:
    """Alias for :func:`model_field_specs`."""

    return model_field_specs(provider)


# Shared run fields are deliberately listed once and reused by both forms.
TARGET_FIELDS: tuple[FieldSpec, ...] = (TARGET_URL,)
SINGLE_RUN_FIELDS: tuple[FieldSpec, ...] = (
    TARGET_URL,
    PROVIDER,
    MODEL_PROFILE,
    SECURITY_LEVEL,
    SURFACE,
    PAYLOAD_MODE,
    EXPERIMENT_CONDITION,
    TARGET_METHOD,
    CANDIDATE_BUDGET,
    ITERATIONS,
    REPEATS,
    OUTPUT_DIR,
    REPORT_FORMAT,
    ENRICHED_REPORTING,
    STOP_POLICY,
    COVERAGE_TARGET,
    DIAGNOSE,
    LOG_VERBOSITY,
    EVASION_ENABLED,
    EVASION_MODE,
    EVASION_MAX_RETRIES,
    EVASION_COOLDOWN_THRESHOLD,
)
MATRIX_FIELDS: tuple[FieldSpec, ...] = (
    TARGET_URL,
    MATRIX,
    MODEL_PROFILE,
    PROVIDERS,
    LEVELS,
    SURFACES,
    PAYLOAD_MODES,
    EXPERIMENT_CONDITIONS_FIELD,
    TARGET_METHODS,
    REPEATS,
    OUTPUT_DIR,
    REPORT_FORMAT,
    ENRICHED_REPORTING,
    STOP_POLICY,
    COVERAGE_TARGET,
    DIAGNOSE,
    LOG_VERBOSITY,
    EVASION_ENABLED,
    EVASION_MODE,
    EVASION_MAX_RETRIES,
    EVASION_COOLDOWN_THRESHOLD,
)
COMPATIBILITY_FIELDS: tuple[FieldSpec, ...] = (
    DEFAULT_SECURITY_LEVEL,
    DEFAULT_LLM_PROVIDER,
    DEFAULT_MAX_ITERATIONS,
    SECURITY_LEVELS_FIELD,
    LLM_PROVIDERS,
    DVWA_USERNAME,
    DVWA_PASSWORD,
)


def _unique_fields(*groups: Iterable[FieldSpec]) -> tuple[FieldSpec, ...]:
    """Merge field groups by path without relying on FieldSpec hashability."""

    unique: list[FieldSpec] = []
    seen: set[str] = set()
    for group in groups:
        for spec in group:
            if spec.path in seen:
                continue
            seen.add(spec.path)
            unique.append(spec)
    return tuple(unique)


ALL_FIELDS: tuple[FieldSpec, ...] = _unique_fields(
    SINGLE_RUN_FIELDS,
    MATRIX_FIELDS,
    COMPATIBILITY_FIELDS,
    MODEL_FIELDS,
)

# Common alternate names make the schema straightforward to consume without
# forcing every caller to know whether it wants a tuple or a path lookup.
RUN_FIELDS = SINGLE_RUN_FIELDS
SINGLE_FIELDS = SINGLE_RUN_FIELDS
MATRIX_RUN_FIELDS = MATRIX_FIELDS
MATRIX_MULTISELECT_FIELDS: tuple[FieldSpec, ...] = (
    PROVIDERS,
    LEVELS,
    SURFACES,
    PAYLOAD_MODES,
    EXPERIMENT_CONDITIONS_FIELD,
    TARGET_METHODS,
)
SETTINGS_FIELDS = ALL_FIELDS
CONFIG_FIELDS = ALL_FIELDS
SETTINGS_FORM_FIELDS = ALL_FIELDS
SINGLE_FORM_FIELDS = SINGLE_RUN_FIELDS
MATRIX_FORM_FIELDS = MATRIX_FIELDS
RUN_CONTROL_FIELDS = SINGLE_RUN_FIELDS
MATRIX_MULTI_SELECT_FIELDS = MATRIX_MULTISELECT_FIELDS
MULTISELECT_FIELDS = MATRIX_MULTISELECT_FIELDS

FORM_FIELDS: dict[str, tuple[FieldSpec, ...]] = {
    FORM_SETTINGS: ALL_FIELDS,
    FORM_SINGLE: SINGLE_RUN_FIELDS,
    FORM_SINGLE_RUN: SINGLE_RUN_FIELDS,
    FORM_MATRIX: MATRIX_FIELDS,
    FORM_MATRIX_RUN: MATRIX_FIELDS,
}

CATEGORY_FIELDS: dict[str, tuple[FieldSpec, ...]] = {
    category: tuple(spec for spec in ALL_FIELDS if spec.category == category)
    for category in FIELD_CATEGORIES
}
FIELDS_BY_CATEGORY = CATEGORY_FIELDS
FIELD_GROUPS = CATEGORY_FIELDS

# Canonical path lookup.  Aliases are resolved by get_field_spec rather than
# duplicated in this mapping, which keeps iteration deterministic.
FIELD_SPECS: dict[str, FieldSpec] = {spec.path: spec for spec in ALL_FIELDS}
CONFIG_FIELD_SPECS = FIELD_SPECS
ALL_FIELD_SPECS = FIELD_SPECS
FIELD_ALIASES: dict[str, str] = {
    alias: spec.path for spec in ALL_FIELDS for alias in spec.aliases
}


def get_field_spec(field_or_path: FieldSpec | str) -> FieldSpec:
    """Resolve a canonical field or one of its backward-compatible aliases."""

    if isinstance(field_or_path, FieldSpec):
        return field_or_path
    path = str(field_or_path)
    try:
        return FIELD_SPECS[path]
    except KeyError:
        canonical = FIELD_ALIASES.get(path)
        if canonical is not None:
            return FIELD_SPECS[canonical]
    raise KeyError(f"Unknown configuration field: {path}")


def fields_for_form(form: str = FORM_SETTINGS) -> tuple[FieldSpec, ...]:
    """Return declarative fields for a settings/single/matrix form."""

    normalized = str(form).strip().lower().replace("-", "_")
    if normalized not in FORM_FIELDS:
        raise KeyError(f"Unknown configuration form: {form}")
    return FORM_FIELDS[normalized]


def fields_for_category(category: str | FieldCategory) -> tuple[FieldSpec, ...]:
    """Return fields in one declarative category."""

    normalized = str(category.value if isinstance(category, FieldCategory) else category)
    try:
        return CATEGORY_FIELDS[normalized]
    except KeyError:
        raise KeyError(f"Unknown configuration field category: {category}") from None


def iter_fields(*, form: str | None = None, category: str | FieldCategory | None = None) -> Iterable[FieldSpec]:
    """Iterate fields with optional form/category filtering."""

    fields: Iterable[FieldSpec] = fields_for_form(form) if form else ALL_FIELDS
    if category is not None:
        normalized = str(category.value if isinstance(category, FieldCategory) else category)
        fields = (spec for spec in fields if spec.category == normalized)
    return fields


# ---------------------------------------------------------------------------
# Nested config paths
# ---------------------------------------------------------------------------


_MISSING = object()
_PATH_PART = re.compile(r"([^.\[\]]+)|\[([^\]]+)\]")


def split_config_path(path: str | Sequence[str]) -> tuple[str, ...]:
    """Split dotted paths and simple bracket notation into components."""

    if isinstance(path, Sequence) and not isinstance(path, str):
        return tuple(str(part) for part in path)
    raw = str(path).strip()
    if not raw:
        raise ConfigPathError("Configuration path must not be empty")
    components: list[str] = []
    for match in _PATH_PART.finditer(raw):
        part = match.group(1) if match.group(1) is not None else match.group(2)
        if part is None:
            continue
        part = part.strip().strip("'\"")
        if part:
            components.append(part)
    if not components:
        raise ConfigPathError(f"Invalid configuration path: {path}")
    return tuple(components)


def expand_config_path(
    path: str | Sequence[str],
    context: Mapping[str, Any] | None = None,
    **values: Any,
) -> str:
    """Expand ``{provider}``-style path placeholders without changing keys."""

    raw = ".".join(str(part) for part in path) if not isinstance(path, str) else path
    substitutions = dict(context or {})
    substitutions.update(values)
    if "{" not in raw:
        return raw
    try:
        return raw.format_map(substitutions)
    except KeyError as exc:
        raise ConfigPathError(f"Missing path template value: {exc.args[0]}") from exc


def _read_component(container: Any, component: str) -> Any:
    if isinstance(container, Mapping):
        return container.get(component, _MISSING)
    if isinstance(container, Sequence) and not isinstance(container, (str, bytes, bytearray)):
        try:
            return container[int(component)]
        except (ValueError, IndexError):
            return _MISSING
    return _MISSING


def get_nested(
    config: Mapping[str, Any],
    path: FieldSpec | str | Sequence[str],
    default: Any = None,
    *,
    context: Mapping[str, Any] | None = None,
    **values: Any,
) -> Any:
    """Read a dotted value from a nested mapping without mutating it."""

    raw_path = _field_path(path) if isinstance(path, FieldSpec) else path
    expanded = expand_config_path(raw_path, context, **values)
    current: Any = config
    for component in split_config_path(expanded):
        current = _read_component(current, component)
        if current is _MISSING:
            return default
    return current


def _path_exists(
    config: Mapping[str, Any],
    path: str,
    *,
    context: Mapping[str, Any] | None = None,
    **values: Any,
) -> bool:
    return get_nested(config, path, _MISSING, context=context, **values) is not _MISSING


def set_nested(
    config: MutableMapping[str, Any],
    path: FieldSpec | str | Sequence[str],
    value: Any,
    *,
    context: Mapping[str, Any] | None = None,
    create: bool = True,
    **values: Any,
) -> MutableMapping[str, Any]:
    """Set a dotted value, creating missing mapping levels by default.

    The root mapping is returned as a convenience; it is the same object that
    was passed in.  Existing list indices are supported, but missing list
    elements are intentionally not synthesized.
    """

    if not isinstance(config, MutableMapping):
        raise TypeError("config must be a mutable mapping")
    raw_path = _field_path(path) if isinstance(path, FieldSpec) else path
    expanded = expand_config_path(raw_path, context, **values)
    components = split_config_path(expanded)
    current: Any = config
    for component in components[:-1]:
        if isinstance(current, MutableMapping):
            child = current.get(component, _MISSING)
            if child is _MISSING or child is None:
                if not create:
                    raise ConfigPathError(f"Missing configuration path: {expanded}")
                child = {}
                current[component] = child
            elif not isinstance(child, (MutableMapping, list)):
                raise ConfigPathError(f"Cannot traverse scalar at {component!r} in {expanded}")
            current = child
            continue
        if isinstance(current, list):
            try:
                current = current[int(component)]
            except (ValueError, IndexError) as exc:
                raise ConfigPathError(f"Cannot traverse list component {component!r} in {expanded}") from exc
            continue
        raise ConfigPathError(f"Cannot traverse configuration path: {expanded}")

    final = components[-1]
    if isinstance(current, MutableMapping):
        current[final] = value
    elif isinstance(current, list):
        try:
            current[int(final)] = value
        except (ValueError, IndexError) as exc:
            raise ConfigPathError(f"Cannot set list component {final!r} in {expanded}") from exc
    else:
        raise ConfigPathError(f"Cannot set configuration path: {expanded}")
    return config


get_nested_value = get_nested
set_nested_value = set_nested
get_path = get_nested
set_path = set_nested


def get_config_value(
    config: Mapping[str, Any],
    field_or_path: FieldSpec | str | Sequence[str],
    default: Any = None,
    *,
    context: Mapping[str, Any] | None = None,
    **values: Any,
) -> Any:
    """Read a field and fall back to its legacy aliases when needed."""

    if not isinstance(field_or_path, FieldSpec):
        return get_nested(config, field_or_path, default, context=context, **values)
    spec = field_or_path
    result = get_nested(config, spec.path, _MISSING, context=context, **values)
    if result is not _MISSING:
        return result
    for alias in spec.aliases:
        result = get_nested(config, alias, _MISSING, context=context, **values)
        if result is not _MISSING:
            return result
    return default


def set_config_value(
    config: MutableMapping[str, Any],
    field_or_path: FieldSpec | str | Sequence[str],
    value: Any,
    *,
    context: Mapping[str, Any] | None = None,
    preserve_alias: bool = True,
    create: bool = True,
    **values: Any,
) -> MutableMapping[str, Any]:
    """Set a field, preserving an existing legacy path when one is present."""

    if not isinstance(field_or_path, FieldSpec):
        return set_nested(config, field_or_path, value, context=context, create=create, **values)
    spec = field_or_path
    target_path = spec.path
    if preserve_alias and not _path_exists(config, spec.path, context=context, **values):
        for alias in spec.aliases:
            if _path_exists(config, alias, context=context, **values):
                target_path = alias
                break
    return set_nested(config, target_path, value, context=context, create=create, **values)


get_config_path = get_config_value
set_config_path = set_config_value
get_value = get_config_value
set_value = set_config_value


# ---------------------------------------------------------------------------
# Coercion and validation
# ---------------------------------------------------------------------------


_TRUE_VALUES = frozenset({"1", "true", "yes", "on", "y", "t"})
_FALSE_VALUES = frozenset({"0", "false", "no", "off", "n", "f"})


def _type_name(expected: FieldType) -> str:
    if isinstance(expected, str):
        return expected.lower()
    return getattr(expected, "__name__", str(expected)).lower()


def _coerce_scalar(value: Any, expected: FieldType, *, allow_none: bool = False) -> Any:
    if value is None:
        if allow_none:
            return None
        raise ValueError("value is required")
    name = _type_name(expected)
    if name in {"str", "string", "text"}:
        return str(value)
    if name in {"bool", "boolean"}:
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in _TRUE_VALUES:
                return True
            if normalized in _FALSE_VALUES:
                return False
            raise ValueError(f"invalid boolean value: {value!r}")
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return bool(value)
        raise ValueError(f"invalid boolean value: {value!r}")
    if name in {"int", "integer"}:
        if isinstance(value, bool):
            raise ValueError("boolean is not a valid integer")
        if isinstance(value, float) and not value.is_integer():
            raise ValueError(f"invalid integer value: {value!r}")
        return int(value)
    if name in {"float", "decimal", "number"}:
        if isinstance(value, bool):
            raise ValueError("boolean is not a valid number")
        result = float(value)
        if not math.isfinite(result):
            raise ValueError("number must be finite")
        return result
    try:
        return expected(value) if callable(expected) else value
    except (TypeError, ValueError) as exc:
        raise ValueError(f"invalid {_type_name(expected)} value: {value!r}") from exc


def _normalize_scalar(value: Any, spec: FieldSpec) -> Any:
    if isinstance(value, str):
        value = value.strip()
        if spec.normalize == "lower":
            value = value.lower()
    return value


def coerce_field_value(
    field_or_spec: FieldSpec | str,
    value: Any,
    *,
    config: Mapping[str, Any] | None = None,
) -> Any:
    """Coerce raw form input to the type declared by a field."""

    spec = get_field_spec(field_or_spec)
    if value is None and spec.allow_none:
        return None
    try:
        if spec.coercer is not None:
            result = spec.coercer(value)
        elif spec.is_multi_select or _type_name(spec.value_type) in {"list", "sequence", "tuple", "set"}:
            raw_items: Iterable[Any]
            if value is None and spec.allow_none:
                return None
            if isinstance(value, str):
                raw_items = (part.strip() for part in value.split(","))
            elif isinstance(value, Iterable) and not isinstance(value, (str, bytes, bytearray, Mapping)):
                raw_items = value
            else:
                raw_items = (value,)
            result_list: list[Any] = []
            for item in raw_items:
                if isinstance(item, str) and not item.strip():
                    continue
                coerced_item = _coerce_scalar(item, spec.item_type)
                if isinstance(coerced_item, str):
                    coerced_item = _normalize_scalar(coerced_item, spec)
                if coerced_item not in result_list:
                    result_list.append(coerced_item)
            result = result_list
        else:
            result = _coerce_scalar(value, spec.value_type, allow_none=spec.allow_none)
            result = _normalize_scalar(result, spec)
    except (TypeError, ValueError) as exc:
        raise FieldValidationError(spec, str(exc)) from exc
    return result


def coerce_value(value: Any, field_or_type: FieldSpec | str | FieldType, *, config: Mapping[str, Any] | None = None) -> Any:
    """Flexible alias accepting either a field/path or a bare Python type."""

    if isinstance(field_or_type, FieldSpec):
        return coerce_field_value(field_or_type, value, config=config)
    if isinstance(field_or_type, str):
        try:
            return coerce_field_value(field_or_type, value, config=config)
        except KeyError:
            return _coerce_scalar(value, field_or_type)
    return _coerce_scalar(value, field_or_type)


def _validate_choices(spec: FieldSpec, value: Any, config: Mapping[str, Any] | None) -> None:
    choices = spec.choice_values(config)
    if not choices or value is None:
        return
    if spec.is_multi_select:
        invalid = [item for item in value if item not in choices]
        if invalid:
            raise FieldValidationError(spec, f"unsupported choice(s): {', '.join(map(str, invalid))}")
    elif value not in choices:
        raise FieldValidationError(spec, f"unsupported choice: {value}")


def validate_field_value(
    field_or_spec: FieldSpec | str,
    value: Any,
    *,
    config: Mapping[str, Any] | None = None,
) -> Any:
    """Coerce and validate one field value, returning the normalized value."""

    spec = get_field_spec(field_or_spec)
    coerced = coerce_field_value(spec, value, config=config)
    if coerced is None and spec.allow_none:
        return None
    if spec.required:
        empty = coerced is None or (isinstance(coerced, str) and not coerced.strip())
        empty = empty or (spec.is_multi_select and not coerced)
        if empty:
            raise FieldValidationError(spec, "value is required")
    _validate_choices(spec, coerced, config)
    if spec.min_value is not None and coerced is not None and not spec.is_multi_select:
        if coerced < spec.min_value:
            raise FieldValidationError(spec, f"must be >= {spec.min_value}")
    if spec.max_value is not None and coerced is not None and not spec.is_multi_select:
        if coerced > spec.max_value:
            raise FieldValidationError(spec, f"must be <= {spec.max_value}")
    if spec.min_items is not None and spec.is_multi_select and len(coerced) < spec.min_items:
        raise FieldValidationError(spec, f"must contain at least {spec.min_items} item(s)")
    if spec.max_items is not None and spec.is_multi_select and len(coerced) > spec.max_items:
        raise FieldValidationError(spec, f"must contain at most {spec.max_items} item(s)")
    if spec.validator is not None:
        try:
            result = spec.validator(coerced)
        except (TypeError, ValueError) as exc:
            raise FieldValidationError(spec, str(exc)) from exc
        if result is False:
            raise FieldValidationError(spec, "value failed validation")
        if isinstance(result, str) and result:
            raise FieldValidationError(spec, result)
    if spec.kind == "url" and coerced:
        parsed = urlparse(str(coerced))
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise FieldValidationError(spec, "must be an http(s) URL")
    return coerced


def validate_value(
    value: Any,
    field_or_type: FieldSpec | str | FieldType,
    *,
    config: Mapping[str, Any] | None = None,
) -> Any:
    """Flexible validation alias accepting a field or a bare Python type."""

    if isinstance(field_or_type, FieldSpec):
        return validate_field_value(field_or_type, value, config=config)
    if isinstance(field_or_type, str):
        try:
            return validate_field_value(field_or_type, value, config=config)
        except KeyError:
            return _coerce_scalar(value, field_or_type)
    return _coerce_scalar(value, field_or_type)


def is_valid_field_value(
    field_or_spec: FieldSpec | str,
    value: Any,
    *,
    config: Mapping[str, Any] | None = None,
) -> bool:
    """Return ``True`` when a value can be coerced and passes validation."""

    try:
        validate_field_value(field_or_spec, value, config=config)
    except (KeyError, TypeError, ValueError):
        return False
    return True


def coerce_and_set(
    config: MutableMapping[str, Any],
    field_or_spec: FieldSpec | str,
    value: Any,
    *,
    context: Mapping[str, Any] | None = None,
    preserve_alias: bool = True,
) -> Any:
    """Validate/coerce a value and write it to the supplied config mapping."""

    spec = get_field_spec(field_or_spec)
    normalized = validate_field_value(spec, value, config=config)
    set_config_value(config, spec, normalized, context=context, preserve_alias=preserve_alias)
    return normalized


def validate_config(
    config: Mapping[str, Any],
    fields: Iterable[FieldSpec] | None = None,
    *,
    form: str | None = None,
) -> dict[str, str]:
    """Validate available values and return ``path -> error`` diagnostics.

    Missing optional fields are ignored.  Missing required fields are reported
    using each field's default when one is not present in the mapping.
    """

    selected = tuple(fields or iter_fields(form=form))
    errors: dict[str, str] = {}

    def _validate_one(spec: FieldSpec, *, context: Mapping[str, Any] | None = None) -> None:
        raw = get_config_value(config, spec, _MISSING, context=context)
        if raw is _MISSING:
            if spec.default is not None:
                raw = spec.default() if callable(spec.default) else spec.default
            elif not spec.required:
                return
            else:
                raw = None
        try:
            validate_field_value(spec, raw, config=config)
        except (KeyError, TypeError, ValueError) as exc:
            path = spec.path
            if context and spec.is_template:
                path = expand_config_path(path, context)
            errors[path] = str(exc)

    for spec in selected:
        if spec.is_template:
            # Model fields are templates.  Validate each configured model
            # section when possible; an absent models block is valid because
            # the loader supplies provider defaults later.
            models = config.get("models")
            if not isinstance(models, Mapping):
                continue
            for provider in models:
                _validate_one(spec.for_provider(str(provider)), context={"provider": str(provider)})
            continue
        _validate_one(spec)
    return errors


def is_secret_field(field_or_path: FieldSpec | str) -> bool:
    """Return whether a field/path should be masked in a form or log."""

    if isinstance(field_or_path, FieldSpec):
        return field_or_path.secret
    path = str(field_or_path).lower()
    try:
        return get_field_spec(path).secret
    except KeyError:
        return path.endswith(".api_key") or path.endswith(".api-key") or path in {
            "api_key",
            "dvwa_password",
        }


is_secret = is_secret_field
coerce_field = coerce_field_value
validate_field = validate_field_value

# Naming aliases used by small form adapters.
PROVIDERS_CHOICES = PROVIDER_CHOICES
SURFACES_CHOICES = SURFACE_CHOICES
SECURITY_CHOICES = SECURITY_LEVEL_CHOICES
LEVEL_CHOICES = SECURITY_LEVEL_CHOICES
PAYLOAD_CHOICES = PAYLOAD_MODE_CHOICES
METHODS_CHOICES = METHOD_CHOICES


def secret_fields(fields: Iterable[FieldSpec] | None = None) -> tuple[FieldSpec, ...]:
    """Return secret fields from the supplied set (all fields by default)."""

    return tuple(spec for spec in (fields or ALL_FIELDS) if spec.secret)


SECRET_FIELD_PATHS: tuple[str, ...] = tuple(spec.path for spec in secret_fields())
SECRET_API_KEY_FIELDS = tuple(spec for spec in MODEL_FIELDS if spec.path.endswith(".api_key"))


__all__ = [
    "ALL_FIELDS",
    "ALL_FIELD_SPECS",
    "CATEGORIES",
    "CATEGORY_FIELDS",
    "CONFIG_FIELDS",
    "CONFIG_FIELD_SPECS",
    "FIELD_GROUPS",
    "ConfigField",
    "ConfigPathError",
    "DVWA_PASSWORD",
    "EVASION_COOLDOWN_THRESHOLD",
    "EVASION_ENABLED",
    "EVASION_MAX_RETRIES",
    "EVASION_MODE",
    "EXPERIMENT_CONDITION",
    "EXPERIMENT_CONDITIONS",
    "EXPERIMENT_CONDITIONS_FIELD",
    "FIELD_ALIASES",
    "FIELD_CATEGORIES",
    "FIELD_SPECS",
    "FORM_FIELDS",
    "FORM_MATRIX",
    "FORM_MATRIX_RUN",
    "FORM_NAMES",
    "FORM_SETTINGS",
    "FORM_SINGLE",
    "FORM_SINGLE_RUN",
    "FieldCategory",
    "FieldSpec",
    "FieldValidationError",
    "ITERATIONS",
    "LEVELS",
    "LLM_PROVIDERS",
    "LOG_LEVEL_CHOICES",
    "LOG_VERBOSITY",
    "LOG_VERBOSITY_CHOICES",
    "MATRIX",
    "MATRIX_FIELDS",
    "MATRIX_FORM_FIELDS",
    "MATRIX_MULTI_SELECT_FIELDS",
    "MATRIX_MULTISELECT_FIELDS",
    "MATRIX_RUN_FIELDS",
    "METHOD_CHOICES",
    "METHODS_CHOICES",
    "MODEL_API_KEY",
    "MODEL_FIELDS",
    "MODEL_PROFILE",
    "MODEL_NAME",
    "MODEL_PROVIDER",
    "OUTPUT_DIR",
    "PAYLOAD_MODE",
    "PAYLOAD_MODE_CHOICES",
    "PAYLOAD_MODES",
    "PROVIDER_CHOICES",
    "PROVIDERS_CHOICES",
    "PROVIDER",
    "PROVIDERS",
    "REPEATS",
    "RUN_FIELDS",
    "RUN_CONTROL_FIELDS",
    "SECURITY_LEVEL",
    "SECURITY_LEVEL_CHOICES",
    "SECURITY_CHOICES",
    "SECURITY_LEVELS_FIELD",
    "SECRET_API_KEY_FIELDS",
    "SECRET_FIELD_PATHS",
    "SETTINGS_FIELDS",
    "SETTINGS_FORM_FIELDS",
    "SINGLE_FIELDS",
    "SINGLE_FORM_FIELDS",
    "SINGLE_RUN_FIELDS",
    "SURFACE_CHOICES",
    "SURFACES_CHOICES",
    "SURFACE",
    "SURFACES",
    "TARGET_METHOD",
    "TARGET_METHODS",
    "TARGET_URL",
    "TARGET_FIELDS",
    "LEVEL_CHOICES",
    "PAYLOAD_CHOICES",
    "MULTISELECT_FIELDS",
    "coerce_and_set",
    "coerce_field",
    "coerce_field_value",
    "coerce_value",
    "expand_config_path",
    "fields_for_category",
    "fields_for_form",
    "fields_for_provider",
    "get_config_path",
    "get_config_value",
    "get_path",
    "get_value",
    "get_field_spec",
    "get_nested",
    "get_nested_value",
    "is_secret_field",
    "is_secret",
    "is_valid_field_value",
    "iter_fields",
    "method_choices",
    "methods_for_surface",
    "model_field_specs",
    "payload_mode_choices",
    "provider_choices",
    "security_level_choices",
    "secret_fields",
    "set_config_path",
    "set_config_value",
    "set_path",
    "set_value",
    "set_nested",
    "set_nested_value",
    "split_config_path",
    "surface_choices",
    "validate_config",
    "validate_field_value",
    "validate_field",
    "validate_value",
]
