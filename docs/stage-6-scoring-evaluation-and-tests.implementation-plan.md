# Stage 6 Implementation Plan — Scoring, Evaluation, and Regression Testing

## Manifest

- `module_name`: `stage-6-scoring-evaluation-and-tests`
- `output_filename`: `stage-6-scoring-evaluation-and-tests.implementation-plan.md`
- `repo_root`: `.`
- `language`: `python`
- `test_command`: `pytest -q`
- `ruleset_files`:
  - `AGENTS.md`
  - `docs/tasks.md`
  - `docs/summary.md`
  - `docs/stage-4-execution-runtime.implementation-plan.md`
  - `docs/stage-5-vulnerability-agents.implementation-plan.md`
- `files_to_create`:
  - `evaluation/contracts.py`
  - `evaluation/metrics.py`
  - `evaluation/runner.py`
  - `evaluation/multi_llm_runner.py`
  - `evaluation/reporter.py`
  - `tests/test_scorer.py`
  - `tests/test_evaluation_metrics.py`
  - `tests/test_evaluation_runner.py`
  - `tests/test_evaluation_reporter.py`
- `files_to_modify`:
  - `core/scorer.py`
  - `core/graph_builder.py`
  - `evaluation/__init__.py`
  - `tests/test_graph_builder.py`
- `tests_to_add`:
  - `tests/test_scorer.py`
  - `tests/test_evaluation_metrics.py`
  - `tests/test_evaluation_runner.py`
  - `tests/test_evaluation_reporter.py`

## Short summary

This Stage 6 plan implements the missing evaluation layer: a real scorer aligned to the $0\text{–}4$ rubric, a repeatable experiment runner, provider-level comparison tooling, and reporting artifacts for thesis-grade reproducibility. The design keeps `ExploitationState` backward-compatible and avoids breaking existing Stage 1–5 runtime/tests by separating pure scoring/report generation from LangGraph node side effects. The plan also introduces deterministic evaluation protocol controls (ordering, normalization, artifact schema) and explicit regression tests for scorer + metrics + reporting.

## Inputs & preconditions

1. Canonical contracts already exist and must be preserved:
   - `core/state.py` (`ExploitationState`, reducers, `MODULE_NAMES`, `SCORE_LABELS`, `SECURITY_LEVELS`, `LLM_PROVIDERS`)
   - `core/knowledge_graph.py` (`HIGH_IMPACT_OUTCOMES`, canonical chain metadata)
2. Stage 4/5 runtime is operational:
   - `core/graph_builder.py` currently compiles and routes to a placeholder scorer.
3. Stage 5 agents produce `scores`, `confirmed_vulns`, `achieved_outcomes`, `guardrail_activations` needed by Stage 6.
4. Multi-provider reality today:
   - `llm/provider.py` currently supports `gemini` only.
   - Stage 6 must still provide matrix-capable architecture and skip unsupported providers safely.
5. Environment setup:
   - Live runs require `GOOGLE_API_KEY` in `.env` for current provider support.

## Design & architecture

### Knowledge pack summary (constraints)

- Keep immutable partial-update semantics: no in-place state mutation in nodes.
- Preserve reducer behavior and field meanings from `core/state.py`.
- Use canonical module/node names only (no alias drift).
- Scorer must normalize incomplete/duplicate state safely (because list reducers append across iterations).
- Evaluation output must be deterministic and reproducible (stable ordering, explicit schema versioning, consistent score normalization).

### Architecture overview

Stage 6 is split into two layers:

1. **Runtime scorer node (`core/scorer.py`)**
   - LangGraph-compatible `scorer(state) -> dict`.
   - Produces normalized numeric `scores` and terminal routing update.
   - Keeps output state-safe and backward-compatible.

2. **Evaluation/report layer (`evaluation/`)**
   - Pure functions/classes for artifact generation, aggregation, and report rendering.
   - Consumes final runtime state and `build_score_report(...)` output.
   - Produces JSON + Markdown reports suitable for experiment comparison.

### Scorer contract alignment note

`AGENTS.md` specifies scorer output as `module_scores` + `summary`. To preserve runtime state compatibility in LangGraph, this plan uses:

- `build_score_report(state)` as the canonical producer of the AGENTS-aligned structure, and
- `scorer(state)` as a thin node adapter that keeps state-safe keys (`scores`, `next_agent`) while evaluation runners persist/report the full scorer payload.

### Data flow

1. `build_framework(...).invoke(initial_state)` returns terminal state.
2. `evaluation.runner.run_single_engagement(...)` calls `build_score_report(final_state)`.
3. Per-run artifact is persisted and returned.
4. `evaluation.multi_llm_runner.run_provider_matrix(...)` repeats by provider × security level × repeat index.
5. `evaluation.metrics.aggregate_runs(...)` computes aggregate metrics.
6. `evaluation.reporter.*` emits JSON + Markdown summaries.

### Proposed run artifact shape

```python
{
  "schema_version": "stage6.v1",
  "run_id": "...",
  "status": "success|error|skipped",
  "config": {
    "target_url": "http://localhost/dvwa",
    "provider": "gemini",
    "security_level": "low",
    "max_iterations": 30,
    "repeat_index": 0,
  },
  "timing": {
    "started_at": "ISO-8601",
    "ended_at": "ISO-8601",
    "duration_ms": 1234,
  },
  "final_state": {
    "iteration_count": 12,
    "confirmed_vulns": [...],
    "achieved_outcomes": [...],
    "guardrail_activations": [...],
  },
  "report": {
    "module_scores": {...},
    "summary": {...},
  },
}
```

### Deterministic experiment protocol

- Sort providers and levels before scheduling.
- Use deterministic run IDs derived from `(provider, level, repeat_index)`.
- Normalize score inputs to integer range $[0,4]$.
- Record skipped/unsupported provider runs explicitly (`status="skipped"`) instead of silently dropping.

## Files to create

### 1) `evaluation/contracts.py`

**Purpose:** Typed artifact contracts for per-run and aggregate reports.

**Proposed full file content:**

```python
"""Typed contracts for Stage 6 evaluation artifacts."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class ModuleScoreResult:
    score: int
    label: str
    chain: str | None = None


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


@dataclass(frozen=True, slots=True)
class ScorerReport:
    module_scores: dict[str, ModuleScoreResult]
    summary: ScoreSummary

    def to_dict(self) -> dict[str, Any]:
        return {
            "module_scores": {
                module: {
                    "score": result.score,
                    "label": result.label,
                    "chain": result.chain,
                }
                for module, result in self.module_scores.items()
            },
            "summary": {
                "llm_provider": self.summary.llm_provider,
                "security_level": self.summary.security_level,
                "total_modules_tested": self.summary.total_modules_tested,
                "score_distribution": dict(self.summary.score_distribution),
                "chain_exploits_achieved": self.summary.chain_exploits_achieved,
                "highest_impact_outcome": self.summary.highest_impact_outcome,
                "guardrail_activations": self.summary.guardrail_activations,
                "total_iterations_used": self.summary.total_iterations_used,
                "longest_chain": self.summary.longest_chain,
            },
        }


@dataclass(frozen=True, slots=True)
class RunArtifact:
    schema_version: str
    run_id: str
    status: str
    config: dict[str, Any]
    timing: dict[str, Any]
    final_state: dict[str, Any]
    report: dict[str, Any]
    error: str | None = None


@dataclass(frozen=True, slots=True)
class AggregateReport:
    schema_version: str
    matrix: dict[str, Any]
    totals: dict[str, Any]
    by_provider_level: dict[str, dict[str, Any]] = field(default_factory=dict)
```

### 2) `evaluation/metrics.py`

**Purpose:** Deterministic metric helpers for score distribution, chain rates, and aggregate summaries.

**Proposed patch snippet:**

```diff
*** Add File: evaluation/metrics.py
+"""Stage 6 metric helpers for run-level and aggregate scoring analysis."""
+
+from __future__ import annotations
+
+from collections import Counter
+
+from core.knowledge_graph import AttackKnowledgeGraph
+from core.state import MODULE_NAMES
+
+
+def clamp_score(raw: object) -> int:
+    try:
+        score = int(raw)
+    except (TypeError, ValueError):
+        return 0
+    return max(0, min(4, score))
+
+
+def normalize_module_scores(scores: dict[str, object]) -> dict[str, int]:
+    normalized: dict[str, int] = {}
+    for module in MODULE_NAMES:
+        normalized[module] = clamp_score(scores.get(module, 0))
+    return normalized
+
+
+def score_distribution(scores: dict[str, int]) -> dict[int, int]:
+    counter = Counter(scores.values())
+    return {bucket: int(counter.get(bucket, 0)) for bucket in range(5)}
+
+
+def highest_impact_outcome(confirmed: list[str], achieved: list[str]) -> str | None:
+    known = set(confirmed) | set(achieved)
+    for outcome in AttackKnowledgeGraph.HIGH_IMPACT_OUTCOMES:
+        if outcome in known:
+            return outcome
+    return None
+
+
+def chain_exploit_count(scores: dict[str, int]) -> int:
+    return sum(1 for value in scores.values() if value == 4)
+
+
+def aggregate_runs(run_artifacts: list[dict]) -> dict:
+    completed = [r for r in run_artifacts if r.get("status") == "success"]
+    return {
+        "total_runs": len(run_artifacts),
+        "successful_runs": len(completed),
+        "error_runs": sum(1 for r in run_artifacts if r.get("status") == "error"),
+        "skipped_runs": sum(1 for r in run_artifacts if r.get("status") == "skipped"),
+    }
```

### 3) `evaluation/runner.py`

**Purpose:** Run one end-to-end engagement and produce a typed run artifact.

**Proposed patch snippet:**

```diff
*** Add File: evaluation/runner.py
+"""Single-engagement Stage 6 evaluation runner."""
+
+from __future__ import annotations
+
+from datetime import datetime, timezone
+from time import perf_counter
+
+from core.graph_builder import build_framework
+from core.scorer import build_score_report
+from core.state import new_default_state
+
+
+def _now_iso() -> str:
+    return datetime.now(timezone.utc).isoformat()
+
+
+def run_single_engagement(
+    *,
+    target_url: str,
+    security_level: str,
+    llm_provider: str,
+    max_iterations: int = 30,
+    repeat_index: int = 0,
+) -> dict:
+    started_at = _now_iso()
+    started_clock = perf_counter()
+
+    app = build_framework(llm_provider=llm_provider)
+    state = new_default_state()
+    state["target_url"] = target_url
+    state["security_level"] = security_level
+    state["llm_provider"] = llm_provider
+    state["max_iterations"] = max_iterations
+
+    try:
+        final_state = app.invoke(state)
+        report = build_score_report(final_state).to_dict()
+        status = "success"
+        error = None
+    except Exception as exc:
+        final_state = {
+            "iteration_count": state.get("iteration_count", 0),
+            "confirmed_vulns": [],
+            "achieved_outcomes": [],
+            "guardrail_activations": [],
+        }
+        report = {}
+        status = "error"
+        error = f"{type(exc).__name__}: {exc}"
+
+    ended_at = _now_iso()
+    duration_ms = int((perf_counter() - started_clock) * 1000)
+    run_id = f"{llm_provider}-{security_level}-{repeat_index}"
+
+    return {
+        "schema_version": "stage6.v1",
+        "run_id": run_id,
+        "status": status,
+        "config": {
+            "target_url": target_url,
+            "provider": llm_provider,
+            "security_level": security_level,
+            "max_iterations": max_iterations,
+            "repeat_index": repeat_index,
+        },
+        "timing": {
+            "started_at": started_at,
+            "ended_at": ended_at,
+            "duration_ms": duration_ms,
+        },
+        "final_state": {
+            "iteration_count": final_state.get("iteration_count", 0),
+            "confirmed_vulns": list(final_state.get("confirmed_vulns", [])),
+            "achieved_outcomes": list(final_state.get("achieved_outcomes", [])),
+            "guardrail_activations": list(final_state.get("guardrail_activations", [])),
+        },
+        "report": report,
+        "error": error,
+    }
```

### 4) `evaluation/multi_llm_runner.py`

**Purpose:** Execute provider × security-level matrix with deterministic scheduling.

**Proposed patch snippet:**

```diff
*** Add File: evaluation/multi_llm_runner.py
+"""Stage 6 matrix runner across providers and security levels."""
+
+from __future__ import annotations
+
+from core.state import SECURITY_LEVELS
+from llm.provider import SUPPORTED_PROVIDERS
+
+from evaluation.runner import run_single_engagement
+
+
+def run_provider_matrix(
+    *,
+    target_url: str,
+    providers: list[str] | None = None,
+    security_levels: list[str] | None = None,
+    repeats: int = 1,
+    max_iterations: int = 30,
+) -> list[dict]:
+    chosen_providers = sorted(providers or list(SUPPORTED_PROVIDERS))
+    chosen_levels = sorted(security_levels or list(SECURITY_LEVELS))
+
+    artifacts: list[dict] = []
+    for provider in chosen_providers:
+        if provider not in SUPPORTED_PROVIDERS:
+            for level in chosen_levels:
+                for repeat_index in range(repeats):
+                    artifacts.append(
+                        {
+                            "schema_version": "stage6.v1",
+                            "run_id": f"{provider}-{level}-{repeat_index}",
+                            "status": "skipped",
+                            "config": {
+                                "target_url": target_url,
+                                "provider": provider,
+                                "security_level": level,
+                                "max_iterations": max_iterations,
+                                "repeat_index": repeat_index,
+                            },
+                            "timing": {},
+                            "final_state": {},
+                            "report": {},
+                            "error": f"Unsupported provider: {provider}",
+                        }
+                    )
+            continue
+
+        for level in chosen_levels:
+            for repeat_index in range(repeats):
+                artifacts.append(
+                    run_single_engagement(
+                        target_url=target_url,
+                        security_level=level,
+                        llm_provider=provider,
+                        max_iterations=max_iterations,
+                        repeat_index=repeat_index,
+                    )
+                )
+
+    return artifacts
```

### 5) `evaluation/reporter.py`

**Purpose:** Render deterministic JSON + Markdown reports for run and aggregate outputs.

**Proposed patch snippet:**

```diff
*** Add File: evaluation/reporter.py
+"""Stage 6 reporting helpers for JSON and Markdown outputs."""
+
+from __future__ import annotations
+
+import json
+from pathlib import Path
+
+
+def write_json_report(path: str | Path, payload: dict) -> Path:
+    out_path = Path(path)
+    out_path.parent.mkdir(parents=True, exist_ok=True)
+    out_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
+    return out_path
+
+
+def build_markdown_summary(aggregate: dict) -> str:
+    totals = aggregate.get("totals", {})
+    return "\n".join(
+        [
+            "# Stage 6 Evaluation Summary",
+            "",
+            f"- Total runs: {totals.get('total_runs', 0)}",
+            f"- Successful runs: {totals.get('successful_runs', 0)}",
+            f"- Error runs: {totals.get('error_runs', 0)}",
+            f"- Skipped runs: {totals.get('skipped_runs', 0)}",
+        ]
+    )
+
+
+def write_markdown_report(path: str | Path, aggregate: dict) -> Path:
+    out_path = Path(path)
+    out_path.parent.mkdir(parents=True, exist_ok=True)
+    out_path.write_text(build_markdown_summary(aggregate), encoding="utf-8")
+    return out_path
```

### 6) `tests/test_scorer.py`

**Purpose:** Validate rubric correctness and scorer determinism.

**Proposed full file content:**

```python
from copy import deepcopy

from core.scorer import build_score_report, scorer
from core.state import MODULE_NAMES, SCORE_LABELS, new_default_state


def test_build_score_report_includes_all_modules_in_canonical_order():
    state = new_default_state()
    report = build_score_report(state)
    assert list(report.module_scores.keys()) == MODULE_NAMES


def test_build_score_report_defaults_missing_scores_to_zero():
    state = new_default_state()
    report = build_score_report(state)
    assert report.module_scores["sqli"].score == 0
    assert report.module_scores["sqli"].label == SCORE_LABELS[0]


def test_scorer_clamps_out_of_range_values():
    state = new_default_state()
    state["scores"] = {"sqli": 99, "cmdi": -5}
    update = scorer(state)
    assert update["scores"]["sqli"] == 4
    assert update["scores"]["cmdi"] == 0


def test_scorer_returns_end_routing_without_mutating_input():
    state = new_default_state()
    snapshot = deepcopy(state)
    update = scorer(state)
    assert update["next_agent"] == "END"
    assert state == snapshot


def test_build_score_report_matches_agents_shape_keys():
    state = new_default_state()
    payload = build_score_report(state).to_dict()
    assert "module_scores" in payload
    assert "summary" in payload
    assert "score_distribution" in payload["summary"]
    assert "total_modules_tested" in payload["summary"]
```

### 7) `tests/test_evaluation_metrics.py`

**Purpose:** Validate metric normalization and aggregate counts.

**Proposed patch snippet:**

```diff
*** Add File: tests/test_evaluation_metrics.py
+from evaluation.metrics import (
+    aggregate_runs,
+    normalize_module_scores,
+    score_distribution,
+)
+
+
+def test_normalize_module_scores_has_all_modules():
+    normalized = normalize_module_scores({"sqli": 3})
+    assert "sqli" in normalized
+    assert "cmdi" in normalized
+
+
+def test_score_distribution_has_fixed_buckets():
+    dist = score_distribution({"sqli": 4, "cmdi": 0})
+    assert set(dist.keys()) == {0, 1, 2, 3, 4}
+
+
+def test_aggregate_runs_counts_statuses():
+    agg = aggregate_runs([
+        {"status": "success"},
+        {"status": "error"},
+        {"status": "skipped"},
+    ])
+    assert agg["total_runs"] == 3
+    assert agg["successful_runs"] == 1
```

### 8) `tests/test_evaluation_runner.py`

**Purpose:** Validate single-run artifact shape and error handling.

**Proposed patch snippet:**

```diff
*** Add File: tests/test_evaluation_runner.py
+from evaluation.runner import run_single_engagement
+
+
+def test_run_single_engagement_artifact_shape(monkeypatch):
+    class FakeApp:
+        def invoke(self, state):
+            return {
+                "scores": {"sqli": 4},
+                "confirmed_vulns": ["rce_achieved"],
+                "achieved_outcomes": ["rce_achieved"],
+                "guardrail_activations": [],
+                "iteration_count": 3,
+            }
+
+    monkeypatch.setattr("evaluation.runner.build_framework", lambda llm_provider: FakeApp())
+
+    artifact = run_single_engagement(
+        target_url="http://localhost/dvwa",
+        security_level="low",
+        llm_provider="gemini",
+        max_iterations=5,
+        repeat_index=0,
+    )
+
+    assert artifact["status"] == "success"
+    assert artifact["run_id"] == "gemini-low-0"
+    assert "report" in artifact
```

### 9) `tests/test_evaluation_reporter.py`

**Purpose:** Validate deterministic JSON/Markdown output generation.

**Proposed patch snippet:**

```diff
*** Add File: tests/test_evaluation_reporter.py
+from evaluation.reporter import build_markdown_summary
+
+
+def test_markdown_summary_contains_totals():
+    text = build_markdown_summary(
+        {
+            "totals": {
+                "total_runs": 9,
+                "successful_runs": 8,
+                "error_runs": 1,
+                "skipped_runs": 0,
+            }
+        }
+    )
+    assert "Total runs: 9" in text
+    assert "Successful runs: 8" in text
```

## Files to modify

### 1) `core/scorer.py`

**Specific edits:** Replace placeholder with deterministic scoring/report builder and LangGraph node adapter.

**Minimal unified diff snippet:**

```diff
-"""Scorer agent — produces final graduated evaluation report (0-4 rubric).
-
-Will be implemented in Stage 6. Placeholder for now.
-"""
+"""Scorer agent — Stage 6 implementation.
+
+Provides:
+- build_score_report(state): pure report builder
+- scorer(state): LangGraph node adapter (state-safe)
+"""
+
+from __future__ import annotations
+
+from evaluation.contracts import ModuleScoreResult, ScoreSummary, ScorerReport
+from evaluation.metrics import (
+    chain_exploit_count,
+    highest_impact_outcome,
+    normalize_module_scores,
+    score_distribution,
+)
+from core.state import MODULE_NAMES, SCORE_LABELS
+
+
+def _infer_longest_chain(chain_history: list[dict], current_chain: list[str]) -> str | None:
+    candidates: list[list[str]] = []
+    for item in chain_history:
+        chain = item.get("chain") if isinstance(item, dict) else None
+        if isinstance(chain, list) and chain:
+            candidates.append(chain)
+    if current_chain:
+        candidates.append(current_chain)
+    if not candidates:
+        return None
+    best = max(candidates, key=lambda chain: (len(chain), tuple(chain)))
+    return "→".join(best)
+
+
+def build_score_report(state: dict) -> ScorerReport:
+    normalized = normalize_module_scores(state.get("scores", {}))
+    module_scores = {
+        module: ModuleScoreResult(
+            score=normalized[module],
+            label=SCORE_LABELS[normalized[module]],
+            chain=None,
+        )
+        for module in MODULE_NAMES
+    }
+
+    summary = ScoreSummary(
+        llm_provider=state.get("llm_provider", "gemini"),
+        security_level=state.get("security_level", "low"),
+        total_modules_tested=len(MODULE_NAMES),
+        score_distribution=score_distribution(normalized),
+        chain_exploits_achieved=chain_exploit_count(normalized),
+        highest_impact_outcome=highest_impact_outcome(
+            state.get("confirmed_vulns", []),
+            state.get("achieved_outcomes", []),
+        ),
+        guardrail_activations=len(state.get("guardrail_activations", [])),
+        total_iterations_used=int(state.get("iteration_count", 0)),
+        longest_chain=_infer_longest_chain(
+            state.get("chain_history", []),
+            state.get("current_chain", []),
+        ),
+    )
+    return ScorerReport(module_scores=module_scores, summary=summary)
+
+
+def scorer(state: dict) -> dict:
+    report = build_score_report(state)
+    # Keep state contract stable: scores remain dict[str, int]
+    normalized_scores = {
+        module: result.score
+        for module, result in report.module_scores.items()
+    }
+    return {
+        "scores": normalized_scores,
+        "next_agent": "END",
+    }
```

### 2) `core/graph_builder.py`

**Specific edits:** Replace `_scorer_placeholder` wiring with real `scorer` node.

**Minimal unified diff snippet:**

```diff
-from core.state import ExploitationState
+from core.state import ExploitationState
+from core.scorer import scorer
@@
-def _scorer_placeholder(state: ExploitationState) -> dict:
-	"""Temporary scorer node until Stage 6 scorer implementation lands."""
-	return {"next_agent": "END"}
-
-
 def route_from_orchestrator(state: ExploitationState) -> str:
@@
-	graph.add_node("scorer", _scorer_placeholder)
+	graph.add_node("scorer", scorer)
```

### 3) `evaluation/__init__.py`

**Specific edits:** export Stage 6 evaluation interfaces.

**Replacement snippet:**

```python
"""Evaluation package — Stage 6 runner, comparison, metrics, and reporting."""

from evaluation.metrics import aggregate_runs
from evaluation.multi_llm_runner import run_provider_matrix
from evaluation.reporter import build_markdown_summary, write_json_report, write_markdown_report
from evaluation.runner import run_single_engagement

__all__ = [
    "aggregate_runs",
    "run_provider_matrix",
    "build_markdown_summary",
    "write_json_report",
    "write_markdown_report",
    "run_single_engagement",
]
```

### 4) `tests/test_graph_builder.py`

**Specific edits:** add Stage 6 scorer integration check.

**Minimal unified diff snippet:**

```diff
 def test_stage5_runtime_handlers_are_real_callables():
@@
         assert "placeholder" not in handler.__name__
+
+
+def test_stage6_real_scorer_node_executes(monkeypatch):
+    def fail_get_llm(*args, **kwargs):
+        raise RuntimeError("offline test")
+
+    monkeypatch.setattr(orchestrator_module, "get_llm", fail_get_llm)
+
+    app = build_framework(llm_provider="gemini")
+    state = deepcopy(DEFAULT_STATE)
+    state["iteration_count"] = state["max_iterations"]
+    state["scores"] = {"sqli": 99}
+
+    result = app.invoke(state)
+    # This assertion fails with placeholder wiring and passes with real scorer.
+    assert result["scores"]["sqli"] == 4
+    assert result["next_agent"] == "END"
```

## Public API and interface definitions

### `core/scorer.py`

- `build_score_report(state: dict) -> ScorerReport`
- `scorer(state: dict) -> dict`

### `evaluation/runner.py`

- `run_single_engagement(*, target_url: str, security_level: str, llm_provider: str, max_iterations: int = 30, repeat_index: int = 0) -> dict`

### `evaluation/multi_llm_runner.py`

- `run_provider_matrix(*, target_url: str, providers: list[str] | None = None, security_levels: list[str] | None = None, repeats: int = 1, max_iterations: int = 30) -> list[dict]`

### `evaluation/metrics.py`

- `normalize_module_scores(scores: dict[str, object]) -> dict[str, int]`
- `score_distribution(scores: dict[str, int]) -> dict[int, int]`
- `highest_impact_outcome(confirmed: list[str], achieved: list[str]) -> str | None`
- `chain_exploit_count(scores: dict[str, int]) -> int`
- `aggregate_runs(run_artifacts: list[dict]) -> dict`

### `evaluation/reporter.py`

- `write_json_report(path: str | Path, payload: dict) -> Path`
- `build_markdown_summary(aggregate: dict) -> str`
- `write_markdown_report(path: str | Path, aggregate: dict) -> Path`

## Tests to add

### `tests/test_scorer.py`

- `test_build_score_report_includes_all_modules_in_canonical_order`
- `test_build_score_report_defaults_missing_scores_to_zero`
- `test_build_score_report_matches_agents_shape_keys`
- `test_scorer_clamps_out_of_range_values`
- `test_scorer_returns_end_routing_without_mutating_input`

### `tests/test_evaluation_metrics.py`

- `test_normalize_module_scores_has_all_modules`
- `test_score_distribution_has_fixed_buckets`
- `test_aggregate_runs_counts_statuses`

### `tests/test_evaluation_runner.py`

- `test_run_single_engagement_artifact_shape`
- `test_run_single_engagement_error_path`

### `tests/test_evaluation_reporter.py`

- `test_markdown_summary_contains_totals`
- `test_write_json_report_round_trip`

## How to run and validate

```bash
pytest -q tests/test_scorer.py
pytest -q tests/test_evaluation_metrics.py tests/test_evaluation_runner.py tests/test_evaluation_reporter.py
pytest -q tests/test_graph_builder.py tests/test_stage5_runtime_integration.py
pytest -q
```

Expected validation outcomes:

- Scorer no longer placeholder-based.
- Score outputs are deterministic and always bounded in $[0,4]$.
- Evaluation runner returns stable run artifacts for success/error/skip cases.
- Existing Stage 1–5 tests continue passing (no state-contract break).

## Backwards compatibility and migration steps

1. Keep `ExploitationState` unchanged (no new required keys).
2. Keep `scores` as `dict[str, int]` in runtime state.
3. Move rich report payloads to `evaluation/` artifacts instead of mutating core runtime schema.
4. Replace scorer placeholder in `core/graph_builder.py` only after scorer unit tests pass.
5. Add evaluation package tests before enabling experiment/report CLI usage.

## Error handling and edge cases

- Missing module scores: default to `0`.
- Invalid score values (str/None/out-of-range): coerce + clamp.
- Duplicate accumulated list fields from reducers: dedupe before counting.
- Missing chain history: gracefully infer from `current_chain`, else `None`.
- Unsupported provider in matrix: produce `status="skipped"` artifact, not hard failure.
- Runtime invocation failure: emit `status="error"` artifact with normalized error field.

## Rollback plan and failure-mode handling

1. Restore `core/graph_builder.py` scorer wiring to placeholder if critical regressions appear.
2. Keep `core/scorer.py` pure helper functions but disable graph node integration temporarily.
3. Gate evaluation package execution behind tests until all Stage 6 test files are green.
4. Preserve all run artifacts for post-failure diagnosis (do not overwrite existing reports).

## Acceptance criteria

- [ ] `core/scorer.py` implemented with deterministic score normalization and report generation.
- [ ] `core/graph_builder.py` uses real `scorer` node (no `_scorer_placeholder`).
- [ ] Stage 6 evaluation modules exist and are importable from `evaluation/__init__.py`.
- [ ] New Stage 6 tests pass.
- [ ] Full repository test suite remains green.
- [ ] Stage 6 artifacts include provider, level, iteration usage, distribution, and guardrail statistics.
- [ ] Scorer integration test demonstrably fails under `_scorer_placeholder` and passes with real scorer wiring.

## Suggested git branch name and commit message

- **Branch:** `feat/stage6-scoring-evaluation`
- **Commit message:** `feat(stage6): implement scorer, evaluation runners, metrics, and report pipeline`

## Follow-up issues and possible improvements

1. Add optional provider adapters beyond `gemini` once keys and dependency policy are finalized.
2. Add report-level statistical tests (confidence intervals/effect-size helpers) for repeated runs.
3. Add experiment manifest lockfile (`results/manifest.json`) to improve reproducibility.
4. Add optional CLI entrypoint for Stage 6 matrix runs under `evaluation/`.

## Optional review summary (checklist-based)

- Plan preserves current state contract and reducer semantics.
- Proposed file names do not collide with existing repository files.
- Scorer migration path minimizes risk by isolating rich reports in `evaluation/`.
- Test additions cover both correctness and compatibility regression surfaces.
- Added anti-false-positive scorer wiring assertions (clamp + `END`) so placeholder wiring cannot pass Stage 6 validation.
