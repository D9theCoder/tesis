# Stage 8.1 Implementation Plan — Jailbreak Integration to Main Program

## Manifest

- `module_name`: `stage-8.1-jailbreak-integration`
- `output_filename`: `docs/stage-8.1-jailbreak-integration.md`
- `repo_root`: `.`
- `language`: `python`
- `test_command`: `pytest -q`
- `ruleset_files`:
  - `AGENTS.md`
  - `docs/summary.md`
  - `docs/tasks.md`
  - `docs/stage-8-adversarial-prompt-evasion.implementation-plan.md`
- `files_to_create`:
  - `tests/test_evasion_integration.py`
- `files_to_modify`:
  - `tesis/cli.py`
  - `tesis/config_loader.py`
  - `tesis/model_config.py`
  - `evaluation/runner.py`
  - `evaluation/multi_llm_runner.py`
  - `evaluation/contracts.py`
  - `core/scorer.py`
  - `tesis/report_formatters.py`
- `tests_to_add`:
  - `tests/test_evasion_integration.py`

## Short Summary

Stage 8 implemented the **Adversarial Evasion Layer** (`llm/evasion/`) and integrated it into the `orchestrator` agent. However, the evasion layer is not yet connected to the **main program flow**: CLI argument parsing, configuration loading, runner state initialization, and report formatting.

Stage 8.1 closes this gap by wiring the evasion settings through the full execution pipeline:

```
CLI flags  ->  Config loader  ->  EngagementConfig  ->  Runner  ->  Init State  ->  Orchestrator  ->  Reports
```

This ensures that a user can enable/disable evasion and select strategies entirely through `config.yaml` or CLI flags, and that evasion metrics appear in all evaluation artifacts.

## Inputs & Preconditions

1. **Evasion Layer Exists**: `llm/evasion/pipeline.py` (LangGraph subgraph) and `llm/evasion/deepteam_adapters.py` are fully implemented.
2. **Orchestrator Integration Exists**: `agents/orchestrator.py` already reads `evasion_enabled`, `evasion_strategy`, `evasion_attempts`, and `successful_evasions` from state.
3. **State Schema Exists**: `core/state.py` already defines `evasion_enabled`, `evasion_strategy`, `evasion_attempts`, and `successful_evasions`.
4. **Config Skeleton Exists**: `config.yaml` already has a Stage 8 section with `evasion_enabled` and `evasion_strategy`.
5. **CLI Exists**: `tesis/cli.py` implements `run`, `info`, `config`, and `report` subcommands.

## Design & Architecture

### Integration Pipeline

```
config.yaml (evasion_enabled, evasion_strategy)
      |
      v
+---------------+
|  Env vars     |  TESIS_EVASION_ENABLED, TESIS_EVASION_STRATEGY
|  CLI flags    |  --evasion-enabled, --evasion-strategy
+---------------+
      |
      v
+---------------+
| Config Loader |  Parse into EngagementConfig.evasion_enabled
|               |  Parse into EngagementConfig.evasion_strategy
+---------------+
      |
      v
+---------------+
|   CLI run     |  Pass evasion settings to runner
+---------------+
      |
      v
+---------------+
|    Runner     |  Inject evasion_enabled / evasion_strategy
|               |  into LangGraph init_state
+---------------+
      |
      v
+---------------+
|  Orchestrator |  Read from state; apply evasion if enabled
+---------------+
      |
      v
+---------------+
|    Scorer     |  Extract evasion metrics from final state
+---------------+
      |
      v
+---------------+
|    Reports    |  Include evasion_attempts, success_rate, etc.
+---------------+
```

### Backwards Compatibility

- `evasion_enabled` defaults to `False` everywhere.
- When `False`, the framework behaves exactly as Stage 7.
- All new CLI flags are optional.
- All new dataclass fields have safe defaults.

## Files to Modify

### 1) `tesis/model_config.py`

**Purpose**: Add evasion fields to the engagement configuration dataclass.

**Changes**:

```python
@dataclass(slots=True)
class EngagementConfig:
    target_url: str
    provider: str
    level: str
    iterations: int = 30
    repeats: int = 1
    output_dir: str = "results"
    matrix: bool = False
    providers: list[str] = field(default_factory=list)
    levels: list[str] = field(default_factory=list)
    report_format: str = "both"
    enriched_reporting: bool = False
    stop_policy: str = "impact"
    coverage_target: float = 0.70
    diagnose: bool = False
    models: dict[str, ModelConfig] = field(default_factory=dict)

    # Stage 8.1 — Evasion integration
    evasion_enabled: bool = False
    evasion_strategy: str = "pipeline"  # "pipeline" | "prompt_injection" | "roleplay"
```

### 2) `tesis/config_loader.py`

**Purpose**: Parse evasion settings from YAML, environment variables, and CLI overrides.

**Changes**:

A. Extend `load_env_overrides()` mapping:

```python
mapping: dict[str, str] = {
    # ... existing mappings ...
    "EVASION_ENABLED": "evasion_enabled",
    "EVASION_STRATEGY": "evasion_strategy",
}
```

Add coercion in the env override loop:

```python
elif mapped == "evasion_enabled":
    value = _parse_bool(raw_value)
```

B. Extend `_extract_cli_overrides()`:

```python
key_mapping: dict[str, str] = {
    # ... existing mappings ...
    "evasion_enabled": "evasion_enabled",
    "evasion_strategy": "evasion_strategy",
}
```

Add bool flag handling:

```python
bool_flags = {"matrix", "enriched_reporting", "diagnose", "evasion_enabled"}
```

C. Extend `load_and_resolve_config()` to build `EngagementConfig` with evasion fields:

```python
config = EngagementConfig(
    # ... existing fields ...
    evasion_enabled=_coerce_bool(merged.get("evasion_enabled", False)),
    evasion_strategy=str(merged.get("evasion_strategy", "pipeline")).strip().lower(),
)
```

D. Add validation in `_validate_engagement_config()`:

```python
_VALID_Evasion_STRATEGIES = {"pipeline", "prompt_injection", "roleplay"}
if config.evasion_strategy not in _VALID_Evasion_STRATEGIES:
    raise ConfigError(
        f"Unsupported evasion strategy: {config.evasion_strategy}. "
        f"Must be one of: {', '.join(sorted(_VALID_Evasion_STRATEGIES))}"
    )
```

### 3) `tesis/cli.py`

**Purpose**: Expose evasion controls via CLI flags.

**Changes**:

A. Add arguments to `run_parser` in `build_parser()`:

```python
run_parser.add_argument("--evasion-enabled", action="store_true", help="Enable adversarial prompt evasion layer")
run_parser.add_argument(
    "--evasion-strategy",
    choices=["pipeline", "prompt_injection", "roleplay"],
    help="Evasion strategy when evasion is enabled",
)
```

B. Wire evasion config through `handle_run()` to the runners:

In single-run mode:

```python
artifact = run_single_engagement(
    # ... existing args ...
    evasion_enabled=config.evasion_enabled,
    evasion_strategy=config.evasion_strategy,
)
```

In matrix mode:

```python
result = run_provider_matrix(
    # ... existing args ...
    evasion_enabled=config.evasion_enabled,
    evasion_strategy=config.evasion_strategy,
)
```

C. Add `--show-evasion` to `report_parser`:

```python
report_parser.add_argument("--show-evasion", action="store_true", help="Render evasion statistics table")
```

D. Update `handle_report()` to call `format_evasion_table()` when `--show-evasion` is set.

### 4) `evaluation/runner.py`

**Purpose**: Accept evasion settings and inject them into the LangGraph initial state.

**Changes**:

A. Extend `run_single_engagement()` signature:

```python
def run_single_engagement(
    *,
    target_url: str,
    security_level: str,
    llm_provider: str,
    max_iterations: int = 30,
    repeat_index: int = 0,
    stop_policy: str = "impact",
    coverage_target: float = 0.70,
    enriched_reporting: bool = False,
    diagnose: bool = False,
    output_dir: str | None = None,
    evasion_enabled: bool = False,
    evasion_strategy: str = "pipeline",
) -> dict:
```

B. Inject evasion settings into `init_state`:

```python
init_state = {
    **new_default_state(),
    "target_url": target_url,
    "security_level": security_level,
    "llm_provider": llm_provider,
    "max_iterations": max_iterations,
    "stop_policy": stop_policy,
    "coverage_target": coverage_target,
    "evasion_enabled": evasion_enabled,
    "evasion_strategy": evasion_strategy,
}
```

C. Persist evasion fields in the returned artifact:

```python
return {
    # ... existing fields ...
    "config": {
        # ... existing config ...
        "evasion_enabled": evasion_enabled,
        "evasion_strategy": evasion_strategy,
    },
    "final_state": {
        # ... existing final_state ...
        "evasion_attempts": final_state.get("evasion_attempts", 0),
        "successful_evasions": final_state.get("successful_evasions", 0),
    },
}
```

### 5) `evaluation/multi_llm_runner.py`

**Purpose**: Propagate evasion settings across matrix runs and aggregate evasion metrics.

**Changes**:

A. Extend `run_provider_matrix()` signature:

```python
def run_provider_matrix(
    *,
    target_url: str,
    providers: list[str] | None = None,
    security_levels: list[str] | None = None,
    repeats: int = 1,
    max_iterations: int = 30,
    stop_policy: str = "impact",
    coverage_target: float = 0.70,
    enriched_reporting: bool = False,
    diagnose: bool = False,
    output_dir: str | None = None,
    include_aggregate: bool = False,
    evasion_enabled: bool = False,
    evasion_strategy: str = "pipeline",
) -> list[dict] | tuple[list[dict], dict[str, Any]]:
```

B. Pass evasion settings to `run_single_engagement()`:

```python
artifacts.append(
    run_single_engagement(
        # ... existing args ...
        evasion_enabled=evasion_enabled,
        evasion_strategy=evasion_strategy,
    )
)
```

C. Extend `_build_matrix_aggregate()` to include evasion metrics:

In both `by_provider_level` and `by_provider` initialization dicts, add:

```python
"evasion_attempts": 0,
"successful_evasions": 0,
"evasion_strategy": evasion_strategy,
```

In the success-path aggregation block:

```python
evasion_attempts = int(final_state.get("evasion_attempts", 0) or 0)
successful_evasions = int(final_state.get("successful_evasions", 0) or 0)

provider_level["evasion_attempts"] += evasion_attempts
provider_level["successful_evasions"] += successful_evasions

provider_summary["evasion_attempts"] += evasion_attempts
provider_summary["successful_evasions"] += successful_evasions
```

In the per-provider finalization loop, compute:

```python
payload["evasion_success_rate"] = (
    round(payload["successful_evasions"] / max(payload["evasion_attempts"], 1) * 100, 2)
)
```

### 6) `evaluation/contracts.py`

**Purpose**: Add evasion metrics to the typed score summary.

**Changes**:

```python
@dataclass(frozen=True, slots=True)
class ScoreSummary:
    llm_provider: str
    security_level: str
    total_modules_tested: int
    score_distribution: dict[int, int]
    chain_exploits_achieved: int
    highest_impact_outcome: str | None
    guardrail_activations: int
    total_iterations_used: int
    longest_chain: str | None

    # Stage 8.1 — Evasion metrics
    evasion_attempts: int = 0
    successful_evasions: int = 0
    evasion_strategy: str = "pipeline"
```

Update `ScorerReport.to_dict()` to include the new fields in the summary dict.

### 7) `core/scorer.py`

**Purpose**: Extract evasion metrics from final state when building score reports.

**Changes**:

In `build_score_report()`, extend `ScoreSummary(...)` instantiation:

```python
summary = ScoreSummary(
    # ... existing fields ...
    evasion_attempts=int(state.get("evasion_attempts", 0) or 0),
    successful_evasions=int(state.get("successful_evasions", 0) or 0),
    evasion_strategy=str(state.get("evasion_strategy", "pipeline")),
)
```

### 8) `tesis/report_formatters.py`

**Purpose**: Render evasion statistics in report output.

**Changes**:

A. Add `format_evasion_table()`:

```python
def format_evasion_table(data: Mapping[str, Any], *, verbose: bool = False) -> str:
    runs = _extract_runs(data)
    if not runs:
        return "No run artifacts found for evasion analysis."

    rows: list[list[str]] = []
    for run in runs:
        config = run.get("config", {})
        final_state = run.get("final_state", {})
        report_summary = run.get("report", {}).get("summary", {})
        provider = str(config.get("provider") or report_summary.get("llm_provider") or "unknown")
        strategy = str(config.get("evasion_strategy") or report_summary.get("evasion_strategy") or "pipeline")
        attempts = int(final_state.get("evasion_attempts") or report_summary.get("evasion_attempts", 0))
        successes = int(final_state.get("successful_evasions") or report_summary.get("successful_evasions", 0))
        rate = f"{(successes / max(attempts, 1) * 100):.1f}%" if attempts > 0 else "N/A"
        guardrails = int(report_summary.get("guardrail_activations", 0))
        prevented = str(max(guardrails - (attempts - successes), 0)) if attempts > 0 else "N/A"
        rows.append([provider, strategy, str(attempts), str(successes), rate, prevented])

    headers = ["Provider", "Strategy", "Attempts", "Successes", "Success Rate", "Guardrails Prevented"]
    return _as_table(headers, rows)
```

B. Update `format_provider_comparison_table()` to include evasion columns when any run has evasion enabled.

C. Update `format_module_scores_table()` tail to include evasion summary lines when present.

## Files to Create

### 1) `tests/test_evasion_integration.py`

**Purpose**: End-to-end integration tests for the evasion config-to-state pipeline.

```python
import pytest
from tesis.config_loader import load_and_resolve_config
from tesis.model_config import EngagementConfig


class TestEvasionConfigLoading:
    def test_evasion_defaults_false(self, tmp_path):
        config_path = tmp_path / "config.yaml"
        config_path.write_text("target_url: http://localhost/dvwa\n")
        config = load_and_resolve_config(config_path=str(config_path), cli_args={})
        assert config.evasion_enabled is False
        assert config.evasion_strategy == "pipeline"

    def test_evasion_from_yaml(self, tmp_path):
        config_path = tmp_path / "config.yaml"
        config_path.write_text(
            "target_url: http://localhost/dvwa\n"
            "evasion_enabled: true\n"
            "evasion_strategy: prompt_injection\n"
        )
        config = load_and_resolve_config(config_path=str(config_path), cli_args={})
        assert config.evasion_enabled is True
        assert config.evasion_strategy == "prompt_injection"

    def test_evasion_cli_override(self, tmp_path):
        config_path = tmp_path / "config.yaml"
        config_path.write_text("target_url: http://localhost/dvwa\n")
        config = load_and_resolve_config(
            config_path=str(config_path),
            cli_args={"evasion_enabled": True, "evasion_strategy": "roleplay"},
        )
        assert config.evasion_enabled is True
        assert config.evasion_strategy == "roleplay"

    def test_invalid_evasion_strategy_raises(self, tmp_path):
        config_path = tmp_path / "config.yaml"
        config_path.write_text(
            "target_url: http://localhost/dvwa\n"
            "evasion_strategy: invalid_strategy\n"
        )
        with pytest.raises(Exception):
            load_and_resolve_config(config_path=str(config_path), cli_args={})


class TestEvasionStatePropagation:
    def test_runner_injects_evasion_into_state(self, monkeypatch):
        from evaluation.runner import run_single_engagement
        from core.graph_builder import build_framework

        # Mock the LangGraph framework to capture init_state
        captured_states = []

        def mock_build_framework(*, llm_provider):
            class FakeApp:
                def invoke(self, state):
                    captured_states.append(state)
                    return {
                        "iteration_count": 1,
                        "confirmed_vulns": [],
                        "achieved_outcomes": [],
                        "guardrail_activations": [],
                        "telemetry_events": [],
                        "evasion_attempts": 2,
                        "successful_evasions": 1,
                    }
            return FakeApp()

        monkeypatch.setattr("evaluation.runner.build_framework", mock_build_framework)
        monkeypatch.setattr("evaluation.runner.build_score_report", lambda state: type("R", (), {"to_dict": lambda self: {"summary": {}, "module_scores": {}}})())

        artifact = run_single_engagement(
            target_url="http://localhost/dvwa",
            security_level="low",
            llm_provider="gemini",
            evasion_enabled=True,
            evasion_strategy="prompt_injection",
        )

        assert len(captured_states) == 1
        init_state = captured_states[0]
        assert init_state["evasion_enabled"] is True
        assert init_state["evasion_strategy"] == "prompt_injection"
        assert artifact["config"]["evasion_enabled"] is True
        assert artifact["final_state"]["evasion_attempts"] == 2


class TestEvasionReportFormatting:
    def test_format_evasion_table(self):
        from tesis.report_formatters import format_evasion_table

        data = {
            "runs": [
                {
                    "config": {"provider": "gemini", "evasion_strategy": "prompt_injection"},
                    "final_state": {"evasion_attempts": 3, "successful_evasions": 2},
                    "report": {"summary": {"guardrail_activations": 1}},
                }
            ]
        }
        table = format_evasion_table(data)
        assert "gemini" in table
        assert "prompt_injection" in table
        assert "3" in table
        assert "2" in table
```

## Public API and Interface Definitions

No new public APIs are introduced. Existing interfaces are extended:

- `EngagementConfig` gains `evasion_enabled: bool` and `evasion_strategy: str`.
- `run_single_engagement()` gains `evasion_enabled` and `evasion_strategy` keyword arguments.
- `run_provider_matrix()` gains `evasion_enabled` and `evasion_strategy` keyword arguments.
- `ScoreSummary` gains `evasion_attempts`, `successful_evasions`, and `evasion_strategy`.
- CLI `run` subcommand gains `--evasion-enabled` and `--evasion-strategy`.
- CLI `report` subcommand gains `--show-evasion`.

## Tests to Add

- `tests/test_evasion_integration.py`:
  - Config loading: YAML defaults, CLI override, env override, invalid strategy rejection.
  - Runner propagation: Verify evasion settings reach `init_state` and return in artifact.
  - Report formatting: Verify `format_evasion_table` renders correctly with mock artifacts.

## How to Run and Validate

1. Install dependencies (no new deps required — `deepteam` already in `pyproject.toml`).
2. Run tests: `pytest -q tests/test_evasion_integration.py`
3. Validate CLI dry-run:
   ```bash
   python -m tesis run --dry-run --evasion-enabled --evasion-strategy prompt_injection
   ```
4. Validate report:
   ```bash
   python -m tesis report results/runs/gemini-low-0.json --show-evasion
   ```

## Backwards Compatibility and Migration Steps

- All evasion fields default to disabled/off.
- Existing `config.yaml` files without Stage 8 sections remain valid.
- Existing run artifacts without evasion fields are handled gracefully by report formatters (show "N/A" or omit).
- No breaking changes to `ExploitationState` — the schema already contains evasion fields.

## Error Handling and Edge Cases

- **Invalid strategy**: `load_and_resolve_config()` raises `ConfigError` with a clear message listing valid strategies.
- **Missing DeepTeam**: `llm/evasion/deepteam_adapters.py` already defensively falls back to the original prompt when DeepTeam is unavailable. Stage 8.1 does not change this.
- **Evasion graph failure**: `agents/orchestrator.py` already catches exceptions from `build_evasion_graph()` and falls back to the baseline prompt.
- **Report on old artifacts**: `format_evasion_table()` gracefully handles missing evasion fields by reading from both `config` and `report.summary` with safe defaults.

## Rollback Plan

If evasion integration causes issues:

1. Remove `--evasion-enabled` and `--evasion-strategy` from CLI invocations.
2. Set `evasion_enabled: False` in `config.yaml`.
3. The framework immediately reverts to Stage 7 behavior because the orchestrator only applies evasion when `_coerce_bool(state.get("evasion_enabled"))` is `True`.

## Acceptance Criteria

- [ ] `python -m tesis run --evasion-enabled --evasion-strategy prompt_injection --dry-run` resolves config without error.
- [ ] `EngagementConfig` includes `evasion_enabled` and `evasion_strategy` with correct defaults.
- [ ] `run_single_engagement()` injects evasion settings into `init_state`.
- [ ] `run_provider_matrix()` passes evasion settings to every single engagement.
- [ ] Matrix aggregate includes per-provider evasion attempt/success counts.
- [ ] `ScoreSummary` and `ScorerReport` include evasion metrics.
- [ ] `python -m tesis report <artifact> --show-evasion` renders an evasion statistics table.
- [ ] All new code has unit tests in `tests/test_evasion_integration.py`.
- [ ] Existing tests continue to pass (`pytest -q`).

## Suggested Git Branch Name and Commit Message

- **Branch:** `feat/stage-8.1-jailbreak-integration`
- **Commit message:** `feat(stage 8.1): wire adversarial evasion layer through CLI, config, runner, and reports`
