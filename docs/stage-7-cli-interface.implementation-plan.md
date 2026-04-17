# Stage 7 Implementation Plan — CLI Interface and Config-Driven Execution

## Manifest

- `module_name`: `stage-7-cli-interface`
- `output_filename`: `stage-7-cli-interface.implementation-plan.md`
- `repo_root`: `.`
- `language`: `python`
- `test_command`: `pytest -q`
- `ruleset_files`:
  - `AGENTS.md`
  - `docs/tasks.md`
  - `docs/summary.md`
  - `docs/stage-2-implementation-plan.md`
  - `docs/stage-3-implementation-plan.md`
  - `docs/stage-4-execution-runtime.implementation-plan.md`
  - `docs/stage-5-vulnerability-agents.implementation-plan.md`
  - `docs/stage-6-scoring-evaluation-and-tests.implementation-plan.md`
- `files_to_create`:
  - `tesis/__init__.py`
  - `tesis/__main__.py`
  - `tesis/cli.py`
  - `tesis/config_loader.py`
  - `tesis/model_config.py`
  - `tesis/report_formatters.py`
  - `tests/test_cli.py`
  - `tests/test_config_loader.py`
  - `tests/test_report_formatters.py`
  - `docs/stage-7-cli-interface.implementation-plan.md`
- `files_to_modify`:
  - `pyproject.toml`
  - `evaluation/multi_llm_runner.py`
  - `evaluation/reporter.py`
  - `llm/provider.py`
  - `README.md`
  - `docs/summary.md`
  - `AGENTS.md`
- `tests_to_add`:
  - `tests/test_cli.py`
  - `tests/test_config_loader.py`
  - `tests/test_report_formatters.py`

## Short summary

This plan implements Stage 7 as a user-facing interface layer over the existing Stage 6 runtime and evaluation stack, without changing exploitation logic or LangGraph control flow. The CLI will provide reproducible single/matrix execution, config merging (`yaml + env + flags`), structured artifacts, and report formatting for thesis-grade outputs. The design is intentionally additive and compatibility-first: current APIs in `evaluation/runner.py`, `evaluation/multi_llm_runner.py`, and `evaluation/reporter.py` remain callable with existing signatures. All snippets below are outline-level by request.

## Inputs & preconditions

1. **Canonical runtime/state contracts are fixed and must remain compatible**
   - `core/state.py`: `ExploitationState`, `MODULE_NAMES`, `SECURITY_LEVELS`, score labels.
   - `AGENTS.md`: immutable partial-update behavior, chain semantics, scoring rubric.

2. **Existing Stage 6 evaluation APIs are available and reused**
   - `evaluation.runner.run_single_engagement(...)`
   - `evaluation.multi_llm_runner.run_provider_matrix(...)`
   - `evaluation.reporter.write_json_report(...)` and `write_markdown_report(...)`

3. **Current provider support is limited**
   - `llm/provider.py` currently has `SUPPORTED_PROVIDERS = ["gemini"]`.
   - Stage 7 should be architected for multi-provider configs but must not break current behavior.

4. **Packaging baseline**
   - Repository currently has no `tesis/` package directory.
   - `pyproject.toml` has no `[project.scripts]` entry yet.

## Design & architecture

### Knowledge pack (constraints distilled)

- Stage 7 is interface/config/reporting only; do not alter core exploitation semantics.
- Precedence must be deterministic: $\text{CLI flags} > \text{TESIS_* env vars} > \text{config.yaml defaults}$.
- Preserve artifact schema compatibility (`schema_version: "stage6.v1"` for run artifacts).
- Ensure deterministic execution ordering in matrix runs (already sorted in Stage 6).
- Never expose secrets in stdout/logs/artifacts.

### Provider scope for Stage 7

- Stage 7 implementation is **runtime-compatible with current gemini-only support**.
- Multi-provider config structures are introduced as forward-compatible scaffolding.
- Actual multi-provider execution remains gated by what `llm/provider.py` supports at runtime.

### Secrets policy (explicit)

1. Prefer environment references (e.g., `${GEMINI_API_KEY}`), not plaintext API keys in `config.yaml`.
2. Mask secrets in all outputs/logs (`****`), including verbose mode.
3. If plaintext persistence is ever needed for local experimentation, require explicit opt-in flag and warning banner.
4. Never serialize raw API keys into run artifacts or report files.

### Proposed architecture layers

1. **Execution layer (unchanged behavior)**
   - `core/*`, `agents/*`, `foundation/*`, `evaluation/runner.py`

2. **Stage 7 façade layer (new)**
   - `tesis/cli.py`: argparse commands and dispatch
   - `tesis/config_loader.py`: config load/merge/validate
   - `tesis/model_config.py`: model/provider config dataclasses
   - `tesis/report_formatters.py`: ASCII/markdown tables for reports

3. **Artifact/output integration layer (extend existing)**
   - `evaluation/reporter.py` (extend with matrix helpers)
   - `evaluation/multi_llm_runner.py` (add aggregate summary output)

### CLI flow (high-level)

```python
# outline only
def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    setup_logging(verbose=args.verbose, quiet=args.quiet)
    return args.handler(args)
```

### Config resolution flow

```python
# outline only
def resolve_config(cli_args) -> EngagementConfig:
    yaml_cfg = load_yaml(cli_args.config_path or "config.yaml")
    env_cfg = load_env_overrides(prefix="TESIS_")
    merged = deep_merge(yaml_cfg, env_cfg)
    merged = apply_cli_overrides(merged, cli_args)
    return validate_config(merged)
```

### Artifact flow

```python
# outline only
if run_mode == "single":
    artifact = run_single_engagement(...)
    write_json_report(output_dir / "runs" / f"{artifact['run_id']}.json", artifact)
elif run_mode == "matrix":
    artifacts, aggregate = run_provider_matrix(...)
    # persist all per-run and aggregate files
```

## Files to create

### 1) `tesis/__init__.py`

**Purpose:** Mark `tesis` as importable package for `python -m tesis` and entrypoint use.

**Outline snippet:**

```python
"""Stage 7 CLI package for tesis framework."""

__all__ = ["cli"]
```

### 2) `tesis/__main__.py`

**Purpose:** Allow `python -m tesis ...` invocation.

**Outline snippet:**

```python
from tesis.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
```

### 3) `tesis/model_config.py`

**Purpose:** Typed model/provider config abstraction for `config` subcommand and provider wiring.

**Outline snippet:**

```python
from dataclasses import dataclass, field
from typing import Any

@dataclass(slots=True)
class ModelConfig:
    provider: str
    api_key: str
    model_name: str
    temperature: float = 0.0
    max_tokens: int | None = None
    timeout: int = 60
    extra: dict[str, Any] = field(default_factory=dict)
```

### 4) `tesis/config_loader.py`

**Purpose:** Load `config.yaml`, resolve `${ENV_VAR}` values, apply env and CLI precedence, validate.

**Outline snippet:**

```python
def load_config(config_path: str = "config.yaml") -> dict:
    ...

def load_env_overrides(prefix: str = "TESIS_") -> dict:
    ...

def merge_config(yaml_cfg: dict, env_cfg: dict, cli_cfg: dict) -> dict:
    # precedence: yaml < env < cli
    ...

def validate_config(cfg: dict) -> None:
    # URL/provider/level/ranges
    ...
```

### 5) `tesis/report_formatters.py`

**Purpose:** Render human-readable tables for `report` command (`--show-rejections`, `--show-scores`, `--show-chains`).

**Outline snippet:**

```python
def format_rejection_table(artifacts: list[dict]) -> str:
    # Provider | Context | Guardrails | Total Calls | Rejection Rate
    ...

def format_score_table(artifact: dict, show_chains: bool = False) -> str:
    # Module | Score | Label | Chain?
    ...
```

### 6) `tesis/cli.py`

**Purpose:** Main argparse interface (`run`, `info`, `config`, `report`) with proper exit codes.

**Outline snippet:**

```python
EXIT_OK = 0
EXIT_RUNTIME_ERROR = 1
EXIT_CONFIG_ERROR = 2
EXIT_TARGET_UNREACHABLE = 3

def build_parser():
    ...

def handle_run(args) -> int:
    ...

def handle_info(args) -> int:
    ...

def handle_config(args) -> int:
    ...

def handle_report(args) -> int:
    ...
```

### 7) `tests/test_config_loader.py`

**Purpose:** precedence and validation tests.

**Outline snippet:**

```python
def test_cli_overrides_env_and_yaml(...): ...
def test_invalid_url_returns_config_error(...): ...
def test_env_var_resolution_for_model_keys(...): ...
```

### 8) `tests/test_cli.py`

**Purpose:** command dispatch, API wiring, dry-run, exit code behavior.

**Outline snippet:**

```python
def test_run_single_calls_run_single_engagement(...): ...
def test_run_matrix_calls_run_provider_matrix(...): ...
def test_info_prints_modules_providers_schema(...): ...
def test_dry_run_does_not_execute_runtime(...): ...
```

### 9) `tests/test_report_formatters.py`

**Purpose:** formatting of rejection and score tables for single and matrix artifacts.

**Outline snippet:**

```python
def test_rejection_table_handles_missing_guardrail_data(...): ...
def test_score_table_includes_distribution_and_highest_outcome(...): ...
def test_matrix_provider_comparison_table(...): ...
```

### 10) `docs/stage-7-cli-interface.implementation-plan.md`

**Purpose:** docs copy of this plan for consistency with existing `docs/stage-*.implementation-plan.md` convention.

> Note: This root plan is the primary deliverable for this request; this docs file is a follow-up mirror for repository consistency.

## Files to modify

### 1) `pyproject.toml`

**Specific edits:** add script entrypoint.

**Patch outline:**

```diff
[project.scripts]
tesis = "tesis.cli:main"
```

### 2) `evaluation/multi_llm_runner.py`

**Specific edits:** extend return payload to include matrix aggregate summary while preserving existing run artifact list compatibility.

**Patch outline:**

```python
def run_provider_matrix(..., include_aggregate: bool = False):
    ...
    aggregate = {
        "schema_version": "stage6.v1",
        "totals": ...,
        "by_provider_level": ...,
    }
    return (artifacts, aggregate) if include_aggregate else artifacts
```

### 3) `evaluation/reporter.py`

**Specific edits:** add helpers to write matrix JSON/Markdown aggregates and keep existing APIs unchanged.

**Patch outline:**

```python
def write_matrix_reports(output_dir: Path, run_id: str, aggregate: dict) -> dict[str, Path]:
    ...
```

### 4) `llm/provider.py`

**Specific edits:** keep existing `get_llm(provider_name: str, **kwargs)` unchanged and add adapter for typed model config.

**Patch outline:**

```python
def get_llm(provider_name: str, **kwargs):
    ...

def get_llm_from_model_config(config: ModelConfig, **kwargs):
    # bridge typed Stage 7 config into existing provider path
    ...
```

### 5) `README.md`

**Specific edits:** add CLI usage sections for:
- `python -m tesis run`
- `python -m tesis info`
- `python -m tesis config --interactive`
- `python -m tesis report --show-rejections --show-scores`

### 6) `docs/summary.md`

**Specific edits:** add Stage 7 coverage update and reference CLI output for reproducibility in rubric/evaluation section.

### 7) `AGENTS.md`

**Specific edits:** append checklist item under Agent Development Checklist:
- `Has CLI flag mapping and reproducible run invocation documented`.

## Public API and interface definitions

### `tesis/cli.py`

```python
def main(argv: list[str] | None = None) -> int: ...
def build_parser() -> argparse.ArgumentParser: ...
def handle_run(args: argparse.Namespace) -> int: ...
def handle_info(args: argparse.Namespace) -> int: ...
def handle_config(args: argparse.Namespace) -> int: ...
def handle_report(args: argparse.Namespace) -> int: ...
```

### `tesis/config_loader.py`

```python
@dataclass(slots=True)
class EngagementConfig:
    target_url: str
    provider: str
    level: str
    iterations: int
    repeats: int
    output_dir: str
    models: dict[str, ModelConfig]

def load_and_resolve_config(*, config_path: str, cli_args: dict) -> EngagementConfig: ...
def validate_target_url(url: str) -> None: ...
```

### `tesis/report_formatters.py`

```python
def parse_artifact_or_matrix(path: str) -> dict: ...
def format_rejection_table(data: dict, *, verbose: bool = False) -> str: ...
def format_module_scores_table(data: dict, *, show_chains: bool = False, module_filter: str | None = None) -> str: ...
def format_provider_comparison_table(matrix_data: dict) -> str: ...
```

### `evaluation/multi_llm_runner.py`

```python
def run_provider_matrix(..., include_aggregate: bool = False) -> list[dict] | tuple[list[dict], dict]: ...
```

### `llm/provider.py`

```python
def get_llm(provider_name: str, **kwargs): ...
def get_llm_from_model_config(config: ModelConfig, **kwargs): ...
```

## Tests to add

### `tests/test_config_loader.py`

1. `test_yaml_roundtrip_to_dataclass()`
2. `test_env_override_target_url()`
3. `test_cli_override_has_highest_priority()`
4. `test_invalid_provider_raises_validation_error()`
5. `test_invalid_level_raises_validation_error()`
6. `test_env_reference_resolution_for_model_api_key()`

### `tests/test_cli.py`

1. `test_run_single_invokes_runner_with_expected_args()`
2. `test_run_matrix_invokes_matrix_runner_with_expected_args()`
3. `test_dry_run_skips_runtime_invocation()`
4. `test_info_subcommand_outputs_schema_modules_providers()`
5. `test_exit_code_2_for_config_error()`
6. `test_exit_code_1_for_runtime_error()`
7. `test_exit_code_0_for_success()`
8. `test_exit_code_3_for_target_unreachable()`

### `tests/test_report_formatters.py`

1. `test_show_rejections_no_guardrail_data_message()`
2. `test_rejection_rate_aggregation_by_provider_and_context()`
3. `test_score_table_renders_module_label_and_chain()`
4. `test_score_table_distribution_summary()`
5. `test_matrix_cross_provider_table_layout()`

## How to run and validate

1. **Unit tests for new Stage 7 modules**

```bash
pytest -q tests/test_config_loader.py tests/test_cli.py tests/test_report_formatters.py
```

2. **Regression checks for Stage 6 compatibility**

```bash
pytest -q tests/test_evaluation_runner.py tests/test_evaluation_multi_llm_runner.py tests/test_evaluation_reporter.py tests/test_provider.py
```

3. **Full suite**

```bash
pytest -q
```

4. **Manual smoke checks (post-implementation)**

```bash
python -m tesis info
python -m tesis run --dry-run --config ./config.yaml
python -m tesis report ./results/runs/<sample>.json --show-scores --show-rejections
```

Expected outcomes:
- Stage 7 tests pass.
- Existing Stage 6 tests stay green.
- Artifacts include stable schema/version and deterministic naming.

## Backwards compatibility and migration steps

1. Add Stage 7 files as additive modules (`tesis/*`) without replacing `main.py` initially.
2. Keep existing `evaluation.runner` and `evaluation.reporter` functions callable with old signatures.
3. Extend `run_provider_matrix` with optional aggregate mode instead of hard signature break (recommended).
4. Keep `llm.provider.get_llm("gemini")` behavior unchanged while adding optional model-config path.
5. Preserve `schema_version: "stage6.v1"` in run artifacts until explicit schema migration is introduced.

## Error handling and edge cases

1. Invalid URL scheme or malformed target URL → config error (`exit 2`).
2. Unreachable target host/timeouts during preflight check → target unreachable (`exit 3`).
3. Unsupported provider or security level → config error (`exit 2`).
4. Missing `guardrail_activations` or `messages` in artifact → print fallback message, no crash.
5. Matrix artifact with mixed statuses (`success/error/skipped`) → summarize all statuses explicitly.
6. API keys in config/logs/output → always masked (`****`), even in verbose mode.
7. Missing output directories → auto-create.
8. Broken JSON artifact input to `report` command → graceful parse error + `exit 2`.

## Rollback plan and failure-mode handling

1. If Stage 7 introduces regressions, rollback sequence:
   - Remove `[project.scripts] tesis = ...` entry.
   - Revert `tesis/*` new package files.
   - Revert additive changes in `evaluation/multi_llm_runner.py`, `evaluation/reporter.py`, and `llm/provider.py`.
2. Keep Stage 6 core APIs untouched so rollback does not impact runtime/exploitation logic.
3. If only formatter issues occur, disable `report` subcommand paths while retaining `run`/`info`.

## Acceptance criteria

- [ ] `python -m tesis run` supports single mode, matrix mode, dry-run, and output-dir.
- [ ] Config precedence works exactly as `CLI > TESIS_* env > YAML`.
- [ ] `info` shows providers, modules, security levels, schema version.
- [ ] `config` supports list/set/interactive behavior and masks secrets.
- [ ] `report` renders rejection-rate and score tables from single and matrix artifacts.
- [ ] Stage 7 writes expected artifacts under `runs/` and `reports/` with deterministic names.
- [ ] Exit codes are correctly mapped (`0`, `1`, `2`, `3`).
- [ ] Existing Stage 6 tests remain green.
- [ ] Docs are updated (`README.md`, `docs/summary.md`, `AGENTS.md`, docs stage-7 plan file).

## Suggested git branch name and commit message

- **Branch:** `feat/stage7-cli-config-reporting`
- **Commit message:** `feat(stage7): add thesis CLI, config loader, and report formatting with deterministic artifacts`

## Optional follow-up issues and improvements

1. Add JSON schema files for run/matrix artifacts and strict schema validation on read.
2. Add rich terminal table rendering fallback (`plain` vs `color`) for CI/non-TTY.
3. Add `--no-summary` for matrix batch mode and machine-oriented quiet output.
4. Add compatibility adapters for additional providers once provider layer officially supports them.

## Optional review summary

Reviewer pass completed and applied:

- Removed breaking signature-change example for `run_provider_matrix`.
- Locked compatibility approach to additive optional aggregate mode.
- Clarified provider migration strategy: keep `get_llm(str)` stable and add `get_llm_from_model_config(...)` adapter.
- Added explicit secrets policy section (masking, env-first, no secret serialization).

Review status: **Pass after amendments**.
