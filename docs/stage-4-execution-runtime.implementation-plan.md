# Stage 4 Execution Runtime Implementation Plan

## Manifest

- `module_name`: `stage-4-execution-runtime`
- `output_filename`: `stage-4-execution-runtime.implementation-plan.md`
- `repo_root`: `.`
- `language`: `python`
- `test_command`: `pytest -q`
- `files_to_create`:
  - `llm/prompts/orchestrator_prompt.py`
  - `llm/guardrail_monitor.py`
  - `tests/test_graph_builder.py`
  - `tests/test_orchestrator.py`
  - `tests/test_chaining_coordinator.py`
- `files_to_modify`:
  - `core/graph_builder.py`
  - `agents/orchestrator.py`
  - `core/chaining_coordinator.py`
- `tests_to_add`:
  - `tests/test_graph_builder.py`
  - `tests/test_orchestrator.py`
  - `tests/test_chaining_coordinator.py`

## Short summary

This plan implements Stage 4 from `docs/tasks.md`: the execution runtime that wires LangGraph flow `recon -> orchestrator -> agent -> chaining/scorer`. It is designed to be compatible with the current repository state where Stage 2 (foundation) and Stage 3 (knowledge graph) are implemented, while Tier 1/2/3 agent modules are not yet fully implemented. The plan preserves all existing contracts in `core/state.py`, uses canonical AKG metadata keys from `core/knowledge_graph.py`, and keeps `main.py` behavior unchanged to avoid regressions in current tests.

## Inputs & preconditions

1. **Canonical state contract exists** (`core/state.py`)
   - Must preserve all current fields and reducer semantics.
2. **Recon node exists and is callable** (`foundation/recon.py::recon`)
   - Returns `endpoints`, `input_vectors`, `security_level`, `next_agent="orchestrator"`.
3. **Knowledge graph exists and is deterministic** (`core/knowledge_graph.py`)
   - Must use canonical action keys: `source`, `target`, `is_chain`, `preconditions`, `target_agent`.
4. **Stage 4 placeholders exist**
   - `core/graph_builder.py`, `agents/orchestrator.py`, `core/chaining_coordinator.py` are currently placeholders and are the primary implementation targets.
5. **Provider reality**
   - Current provider support is `gemini` only (`llm/provider.py`). Runtime must include deterministic fallback behavior when LLM invocation fails.

## Design & architecture

### Runtime flow (Stage 4 target)

1. **START -> `recon`**
2. **`recon` -> `orchestrator`**
3. **`orchestrator` chooses next node**
   - If budget exhausted or critical outcome reached -> `scorer`
   - Else -> selected Tier node or chain node
4. **After Tier node execution -> `route_after_agent` (chaining coordinator)**
   - If chain preconditions satisfied -> direct route to chain agent
   - Else -> `orchestrator`
5. **`scorer` -> END**

### Compatibility-first runtime strategy

Because Tier agent files are not fully present yet, Stage 4 runtime should be **compilable now** with one of these safe approaches:

- Register real nodes for available functions (`recon`, `orchestrator`, `scorer` placeholder wrapper).
- Register **no-op placeholder nodes** for missing Tier/Chain agents that return a safe partial update (increment iteration, bounce back to orchestrator).

This keeps Stage 4 testable without prematurely implementing Stage 5 exploitation logic.

### Routing contract mapping

- Orchestrator uses `AttackKnowledgeGraph.get_viable_chains(...)` to compute candidate plans.
- Orchestrator maps knowledge-graph state nodes to executable runtime node names before setting `next_agent`.
- Chaining coordinator uses `AttackKnowledgeGraph.get_next_actions(node)` and checks:
  - `edge["is_chain"] is True`
  - `set(edge["preconditions"]) ⊆ set(state["confirmed_vulns"])`
  - route to `edge["target_agent"]`.

### State update policy by node

- `orchestrator` returns only delta keys: `next_agent`, `current_chain`, `messages`, optionally `guardrail_activations`.
- `route_after_agent` returns string route only (conditional edge function).
- Placeholder Tier nodes return minimal safe update, e.g.:
  - `iteration_count += 1`
  - `next_agent = "orchestrator"`

## Files to create

### 1) `llm/prompts/orchestrator_prompt.py`

**Purpose:** Centralized prompt builder for orchestration decisions; keeps prompt logic out of control-flow code.

**Full content (proposed):**

```python
"""Prompt builder for orchestration decisions."""

from __future__ import annotations


def build_orchestrator_prompt(
    *,
    confirmed_vulns: list[str],
    achieved_outcomes: list[str],
    viable_paths: list[list[str]],
    security_level: str,
    iteration_count: int,
    max_iterations: int,
) -> str:
    remaining = max(max_iterations - iteration_count, 0)
    top_paths = viable_paths[:5]

    return (
        "You are the orchestrator for a DVWA exploitation workflow.\n"
        f"Security level: {security_level}\n"
        f"Confirmed vulnerabilities: {confirmed_vulns}\n"
        f"Achieved outcomes: {achieved_outcomes}\n"
        f"Remaining iteration budget: {remaining}\n"
        f"Candidate paths: {top_paths}\n"
        "Return strict JSON: {\"next_agent\": \"<agent_name>\"}."
    )
```

### 2) `llm/guardrail_monitor.py`

**Purpose:** Reusable refusal detection and logging payload construction for orchestrator fallback handling.

**Full content (proposed):**

```python
"""Guardrail/refusal detection helpers for LLM responses."""

from __future__ import annotations

REFUSAL_PATTERNS = (
    "i can't assist",
    "i cannot assist",
    "i can't help",
    "i cannot help",
    "i must decline",
    "i'm unable to",
    "not able to help with",
)


def is_guardrail_refusal(text: str) -> bool:
    lowered = (text or "").lower()
    return any(p in lowered for p in REFUSAL_PATTERNS)


def make_guardrail_event(provider: str, context: str, response: str) -> dict:
    return {
        "provider": provider,
        "context": context,
        "snippet": (response or "")[:200],
    }
```

### 3) `tests/test_graph_builder.py`

**Purpose:** Validate graph compile, node registration, and conditional edge routing behavior.

**Full content (proposed):**

```python
from core.graph_builder import build_framework, route_from_orchestrator
from core.state import DEFAULT_STATE


def test_build_framework_compiles():
    app = build_framework(llm_provider="gemini")
    assert app is not None


def test_runtime_starts_from_recon():
    app = build_framework(llm_provider="gemini")
    result = app.invoke(DEFAULT_STATE)
    assert "next_agent" in result


def test_route_from_orchestrator_unknown_agent_defaults_to_scorer():
    state = {"next_agent": "not_a_real_node"}
    assert route_from_orchestrator(state) == "scorer"
```

### 4) `tests/test_orchestrator.py`

**Purpose:** Validate deterministic fallback and budget stop behavior without requiring live LLM calls.

**Full content (proposed):**

```python
from agents.orchestrator import orchestrator


def test_orchestrator_stops_when_budget_exhausted():
    state = {
        "confirmed_vulns": [],
        "achieved_outcomes": [],
        "iteration_count": 30,
        "max_iterations": 30,
        "security_level": "low",
        "llm_provider": "gemini",
    }
    update = orchestrator(state)
    assert update["next_agent"] == "scorer"


def test_orchestrator_returns_next_agent_key():
    state = {
        "confirmed_vulns": ["sqli_confirmed"],
        "achieved_outcomes": [],
        "iteration_count": 1,
        "max_iterations": 30,
        "security_level": "low",
        "llm_provider": "gemini",
    }
    update = orchestrator(state)
    assert "next_agent" in update
```

### 5) `tests/test_chaining_coordinator.py`

**Purpose:** Validate `route_after_agent` routing for chain hit, fallback, and budget exit.

**Full content (proposed):**

```python
import pytest

from core.chaining_coordinator import route_after_agent


@pytest.mark.parametrize("level", ["low", "medium", "high"])
def test_route_after_agent_parametrized(level):
    state = {
        "security_level": level,
        "confirmed_vulns": ["sqli_confirmed", "credentials_extracted"],
        "achieved_outcomes": [],
        "iteration_count": 2,
        "max_iterations": 30,
    }
    nxt = route_after_agent(state)
    assert nxt in {"sqli_to_creds_chain", "orchestrator", "scorer"}


def test_route_after_agent_budget_exhausted_goes_to_scorer():
    state = {
        "confirmed_vulns": [],
        "achieved_outcomes": [],
        "iteration_count": 30,
        "max_iterations": 30,
    }
    assert route_after_agent(state) == "scorer"
```

## Files to modify

### 1) `core/graph_builder.py`

**Specific edits:** Replace placeholder with StateGraph assembly and conditional routing functions.

**Minimal patch snippet (proposed):**

```diff
-"""LangGraph workflow assembly.
-
-Will be implemented in Stage 4. Placeholder for now.
-"""
+"""LangGraph workflow assembly (Stage 4)."""
+
+from __future__ import annotations
+
+from langgraph.graph import END, START, StateGraph
+
+from core.state import ExploitationState
+from foundation.recon import recon
+from agents.orchestrator import orchestrator
+from core.chaining_coordinator import route_after_agent
+
+
+def _scorer_placeholder(state: ExploitationState) -> dict:
+    return {"next_agent": "END"}
+
+
+def _agent_placeholder(name: str):
+    def _run(state: ExploitationState) -> dict:
+        return {
+            "next_agent": "orchestrator",
+            "iteration_count": state.get("iteration_count", 0) + 1,
+        }
+
+    _run.__name__ = f"{name}_placeholder"
+    return _run
+
+
+RUNTIME_AGENT_NODE_NAMES = {
+    "sqli_agent", "sqli_blind_agent", "xss_reflected_agent", "xss_stored_agent",
+    "xss_dom_agent", "cmdi_agent", "brute_agent", "lfi_agent", "upload_agent",
+    "csrf_agent", "weak_session_agent", "idor_agent",
+    "sqli_to_creds_chain", "upload_to_rce_chain", "xss_to_csrf_chain", "lfi_to_rce_chain",
+}
+
+
+def route_from_orchestrator(state: ExploitationState) -> str:
+    next_agent = state.get("next_agent", "scorer")
+    if next_agent in RUNTIME_AGENT_NODE_NAMES or next_agent == "scorer":
+        return next_agent
+    return "scorer"
+
+
+def build_framework(llm_provider: str = "gemini"):
+    graph = StateGraph(ExploitationState)
+    graph.add_node("recon", recon)
+    graph.add_node("orchestrator", orchestrator)
+    graph.add_node("scorer", _scorer_placeholder)
+
+    # Temporary placeholders until Stage 5 agent implementations land
+    for name in [
+        "sqli_agent", "sqli_blind_agent", "xss_reflected_agent", "xss_stored_agent",
+        "xss_dom_agent", "cmdi_agent", "brute_agent", "lfi_agent", "upload_agent",
+        "csrf_agent", "weak_session_agent", "idor_agent",
+        "sqli_to_creds_chain", "upload_to_rce_chain", "xss_to_csrf_chain", "lfi_to_rce_chain",
+    ]:
+        graph.add_node(name, _agent_placeholder(name))
+        graph.add_conditional_edges(name, route_after_agent)
+
+    graph.add_edge(START, "recon")
+    graph.add_edge("recon", "orchestrator")
+    graph.add_conditional_edges("orchestrator", route_from_orchestrator)
+    graph.add_edge("scorer", END)
+
+    return graph.compile()
```

### 2) `agents/orchestrator.py`

**Specific edits:** Implement orchestrator decision logic with deterministic fallback if LLM is unavailable/refuses.

**Minimal patch snippet (proposed):**

```diff
-"""Orchestrator agent — LLM-driven path planning over knowledge graph.
-
-Will be implemented in Stage 4. Placeholder for now.
-"""
+"""Orchestrator agent — Stage 4 implementation."""
+
+from __future__ import annotations
+
+import json
+from typing import Any
+
+from core.knowledge_graph import AttackKnowledgeGraph
+from llm.provider import get_llm
+from llm.prompts.orchestrator_prompt import build_orchestrator_prompt
+from llm.guardrail_monitor import is_guardrail_refusal, make_guardrail_event
+from langchain_core.messages import HumanMessage, AIMessage
+
+
+CRITICAL_OUTCOMES = {
+    "admin_session_obtained",
+    "rce_achieved",
+    "user_compromised",
+    "data_exfiltrated",
+    "session_hijack",
+}
+
+KG_NODE_TO_AGENT = {
+    "sqli_confirmed": "sqli_agent",
+    "blind_sqli_confirmed": "sqli_blind_agent",
+    "xss_reflected_confirmed": "xss_reflected_agent",
+    "xss_stored_confirmed": "xss_stored_agent",
+    "xss_dom_confirmed": "xss_dom_agent",
+    "cmd_injection_confirmed": "cmdi_agent",
+    "brute_force_confirmed": "brute_agent",
+    "lfi_confirmed": "lfi_agent",
+    "file_upload_confirmed": "upload_agent",
+    "csrf_confirmed": "csrf_agent",
+    "weak_session_confirmed": "weak_session_agent",
+    "idor_confirmed": "idor_agent",
+    "credentials_extracted": "sqli_to_creds_chain",
+    "admin_session_obtained": "upload_to_rce_chain",
+    "log_access_confirmed": "lfi_to_rce_chain",
+    "user_compromised": "xss_to_csrf_chain",
+}
+
+STARTER_AGENT_ORDER = ["sqli_agent", "brute_agent", "xss_reflected_agent"]
+
+
+def _fallback_next_agent(
+    viable_paths: list[list[str]],
+    confirmed_vulns: list[str],
+) -> tuple[str, list[str]]:
+    confirmed = set(confirmed_vulns)
+
+    if viable_paths:
+        chosen = viable_paths[0]
+        first_unmet = next((node for node in chosen if node not in confirmed), None)
+        mapped = KG_NODE_TO_AGENT.get(first_unmet or "")
+        if mapped:
+            return mapped, chosen
+
+    # Fresh-state fallback: do not terminate immediately.
+    if not confirmed:
+        return STARTER_AGENT_ORDER[0], []
+
+    return "scorer", []
+
+
+def orchestrator(state: dict[str, Any]) -> dict[str, Any]:
+    if state.get("iteration_count", 0) >= state.get("max_iterations", 0):
+        return {"next_agent": "scorer"}
+
+    achieved = set(state.get("achieved_outcomes", []))
+    if achieved & CRITICAL_OUTCOMES:
+        return {"next_agent": "scorer"}
+
+    kg = AttackKnowledgeGraph()
+    viable_paths = kg.get_viable_chains(
+        confirmed_vulns=state.get("confirmed_vulns", []),
+        achieved_outcomes=state.get("achieved_outcomes", []),
+        max_paths=5,
+    )
+
+    fallback_agent, fallback_chain = _fallback_next_agent(
+        viable_paths,
+        state.get("confirmed_vulns", []),
+    )
+
+    prompt = build_orchestrator_prompt(
+        confirmed_vulns=state.get("confirmed_vulns", []),
+        achieved_outcomes=state.get("achieved_outcomes", []),
+        viable_paths=viable_paths,
+        security_level=state.get("security_level", "low"),
+        iteration_count=state.get("iteration_count", 0),
+        max_iterations=state.get("max_iterations", 30),
+    )
+
+    try:
+        llm = get_llm(state.get("llm_provider", "gemini"))
+        resp = llm.invoke([HumanMessage(content=prompt)])
+        raw = getattr(resp, "content", "")
+        text = raw if isinstance(raw, str) else str(raw)
+
+        if is_guardrail_refusal(text):
+            return {
+                "next_agent": fallback_agent,
+                "current_chain": fallback_chain,
+                "guardrail_activations": [
+                    make_guardrail_event(state.get("llm_provider", "gemini"), "orchestrator", text)
+                ],
+                "messages": [HumanMessage(content=prompt), AIMessage(content=text)],
+            }
+
+        parsed = json.loads(text)
+        next_agent = parsed.get("next_agent", fallback_agent)
+        return {
+            "next_agent": next_agent,
+            "current_chain": fallback_chain,
+            "messages": [HumanMessage(content=prompt), AIMessage(content=text)],
+        }
+    except Exception:
+        return {
+            "next_agent": fallback_agent,
+            "current_chain": fallback_chain,
+        }
```

### 3) `core/chaining_coordinator.py`

**Specific edits:** Implement deterministic chain routing against AKG canonical keys.

**Minimal patch snippet (proposed):**

```diff
-"""Chaining Coordinator — conditional edge routing function.
-
-Will be implemented in Stage 4. Placeholder for now.
-"""
+"""Chaining Coordinator — conditional edge routing function (Stage 4)."""
+
+from __future__ import annotations
+
+from core.knowledge_graph import AttackKnowledgeGraph
+
+
+HIGH_IMPACT_OUTCOMES = set(AttackKnowledgeGraph.HIGH_IMPACT_OUTCOMES)
+
+
+def critical_outcome_achieved(state: dict) -> bool:
+    achieved = set(state.get("achieved_outcomes", []))
+    confirmed = set(state.get("confirmed_vulns", []))
+    return bool((achieved | confirmed) & HIGH_IMPACT_OUTCOMES)
+
+
+def route_after_agent(state: dict) -> str:
+    if state.get("iteration_count", 0) >= state.get("max_iterations", 0):
+        return "scorer"
+
+    if critical_outcome_achieved(state):
+        return "scorer"
+
+    confirmed = set(state.get("confirmed_vulns", []))
+    kg = AttackKnowledgeGraph()
+
+    for node in sorted(confirmed):
+        for edge in kg.get_next_actions(node):
+            if not edge.get("is_chain"):
+                continue
+            preconditions = set(edge.get("preconditions", []))
+            if preconditions.issubset(confirmed):
+                target_agent = edge.get("target_agent")
+                if target_agent:
+                    return target_agent
+
+    return "orchestrator"
```

## Public API and interface definitions

### `core/graph_builder.py`

- `build_framework(llm_provider: str = "gemini") -> CompiledStateGraph`
- `route_from_orchestrator(state: ExploitationState) -> str`

### `agents/orchestrator.py`

- `orchestrator(state: dict[str, Any]) -> dict[str, Any]`
- `_fallback_next_agent(viable_paths: list[list[str]], confirmed_vulns: list[str]) -> tuple[str, list[str]]`

### `core/chaining_coordinator.py`

- `critical_outcome_achieved(state: dict) -> bool`
- `route_after_agent(state: dict) -> str`

### `llm/prompts/orchestrator_prompt.py`

- `build_orchestrator_prompt(...) -> str`

### `llm/guardrail_monitor.py`

- `is_guardrail_refusal(text: str) -> bool`
- `make_guardrail_event(provider: str, context: str, response: str) -> dict`

## Tests to add

1. **`tests/test_graph_builder.py`**
   - `test_build_framework_compiles`
   - `test_runtime_starts_from_recon`
    - `test_route_from_orchestrator_unknown_agent_defaults_to_scorer`
2. **`tests/test_orchestrator.py`**
   - `test_orchestrator_stops_when_budget_exhausted`
   - `test_orchestrator_critical_outcome_routes_to_scorer`
   - `test_orchestrator_fallback_when_llm_fails`
   - `test_orchestrator_uses_canonical_viable_paths`
3. **`tests/test_chaining_coordinator.py`**
   - `test_route_after_agent_parametrized_levels`
   - `test_route_after_agent_returns_chain_agent_when_preconditions_met`
   - `test_route_after_agent_budget_exhausted_goes_to_scorer`
   - `test_route_after_agent_fallback_orchestrator_when_no_chain`

## How to run and validate

Use project root `/home/kevin/Coding (WSL)/tesis`.

```bash
pytest -q
pytest -q tests/test_state.py tests/test_knowledge_graph.py tests/test_recon.py
pytest -q tests/test_graph_builder.py tests/test_orchestrator.py tests/test_chaining_coordinator.py
```

Expected outcomes:

- Existing Stage 1–3 tests remain green.
- New Stage 4 tests pass and validate runtime flow plus conditional routing.
- No schema drift in `ExploitationState`.

## Backwards compatibility and migration steps

1. **Do not modify** `main.py` behavior in Stage 4.
   - Current tests assert sample-query CLI behavior.
2. Keep `core/state.py` and `core/knowledge_graph.py` contracts unchanged.
3. Add Stage 4 runtime as new implementation behind existing placeholder module paths.
4. Keep temporary placeholder Tier node registration until Stage 5 modules are implemented.
5. Once Stage 5 ships, replace placeholder node callables in `build_framework` with actual agent callables.

## Error handling and edge cases

- **No viable path from AKG with empty `confirmed_vulns`** -> select deterministic starter Tier agent (do not terminate early).
- **No viable path from AKG with non-empty `confirmed_vulns`** -> fallback to `scorer` only when no candidate action remains.
- **LLM unavailable / API key missing / provider error** -> deterministic fallback to shortest viable path.
- **Guardrail refusal text** -> log `guardrail_activations` and use fallback route.
- **Unknown `next_agent` value** -> graph builder should default to `scorer` route for safety.
- **Budget exhausted** (`iteration_count >= max_iterations`) -> immediate `scorer`.
- **Any high-impact outcome already achieved** (`admin_session_obtained`, `rce_achieved`, `user_compromised`, `data_exfiltrated`, `session_hijack`) -> immediate `scorer`.

## Rollback plan and failure-mode handling

1. Revert three Stage 4 implementation files to placeholder versions:
   - `core/graph_builder.py`
   - `agents/orchestrator.py`
   - `core/chaining_coordinator.py`
2. Keep new helper files/tests on branch for iterative re-enable.
3. If runtime graph compile fails, temporarily disable Stage 4 test files and restore compile smoke test from `tests/test_state.py` only.
4. Re-introduce changes incrementally in this order:
   - chaining coordinator
   - orchestrator fallback mode
   - graph wiring

## Acceptance criteria

- [ ] `build_framework()` compiles a LangGraph app with `recon`, `orchestrator`, and `scorer` paths.
- [ ] Orchestrator returns `next_agent` deterministically even when LLM invocation fails.
- [ ] Chaining coordinator uses canonical AKG keys (`is_chain`, `preconditions`, `target_agent`) only.
- [ ] Budget and critical-outcome short-circuit routing to `scorer` is implemented.
- [ ] New Stage 4 tests pass.
- [ ] Existing tests (`test_state`, `test_knowledge_graph`, `test_recon`, `test_main`, `test_provider`) remain green.
- [ ] No public API break for Stage 1–3 modules.

## Suggested git branch name and commit message

- **Branch:** `feat/stage4-execution-runtime-langgraph`
- **Commit message:** `feat(stage4): implement LangGraph runtime orchestration and chaining coordinator`

## Follow-up issues and improvements (optional)

1. Replace placeholder Tier node registration with dynamic module discovery once Stage 5 agents exist.
2. Add structured tracing for each routing decision (`orchestrator`, `route_after_agent`) to support evaluation metrics.
3. Add benchmark tests for routing determinism and iteration budget utilization.
4. Expand provider abstraction for additional LLM backends only after compatibility tests are added.

## Optional review summary (code-reviewer)

Compatibility review completed for this plan document. Adjustments made:

- Added KG-node -> runtime-agent mapping in orchestrator fallback logic.
- Prevented fresh-state early termination by adding deterministic starter-agent fallback.
- Aligned `messages` examples with `AnyMessage` (`HumanMessage`/`AIMessage`) reducer contract.
- Added `route_from_orchestrator` unknown-node safety fallback to `scorer`.
- Aligned critical-outcome checks with canonical AKG high-impact outcomes.
