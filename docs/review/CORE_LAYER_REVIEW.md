# Core Runtime Layer — Comprehensive Correctness Review

**Reviewer:** code-reviewer subagent  
**Scope:** `core/knowledge_graph.py`, `core/state.py`, `core/chaining_coordinator.py`, `core/graph_builder.py`, `core/scorer.py`  
**Lenses:** langgraph-docs, python-anti-patterns, python-design-patterns, python-testing-patterns  
**Date:** 2026-05-01  
**Test Result:** 81/81 tests pass (baseline healthy)

---

## Executive Summary

The core runtime layer is architecturally sound and all existing tests pass. However, several **HIGH** severity issues were identified around state reducer safety, chain precondition consistency, and scorer defaults that could lead to incorrect behavior in production runs. The most significant concerns are:

1. **`scores` and `tried_payloads` lack LangGraph reducers** — agents rely on a helper (`make_update`) to merge dicts manually. Any deviation silently overwrites prior agent data.
2. **`chaining_coordinator` excludes `achieved_outcomes` from chain preconditions** while `get_viable_chains` includes them, creating a behavioral split between routing and reporting.
3. **`scorer` defaults `task_result` to `"SUCCESS"`** when no result was recorded, mislabeling failed or incomplete runs.
4. **`graph_builder` does not configure a checkpointer** despite the spec requiring `MemorySaver` and `thread_id` usage.

---

## File: `core/knowledge_graph.py`

### Summary
Static NetworkX DiGraph representing the 3-surface attack domain. Well-structured with validation hooks and deterministic traversal. All graph nodes and edges match the intended architecture, but precondition keys drift from documentation.

### Issues Found

#### 🔴 Critical
*No critical issues found.*

#### 🟡 High

1. **`METHOD_PRECONDITIONS` keys drift from `summary.md` documentation** (lines 44–53)
   - `sqli_union` uses `union_select_possible`; docs say `union_select_possible`
   - `ac_vertical_escalation` uses `role_based_access_present`; docs say `role_based_access_present`
   - `bf_spray` uses `[no_rate_limit, low_priv_session_available]`; docs say `no_rate_limit`
   - **Why it matters:** If `recon.py` produces keys matching the documentation, `get_viable_methods` will never mark these methods as viable, causing orchestrator fallback failures and false negatives.
   - **Recommended fix:** Audit `recon.py` and `foundation/verifier.py` to confirm which observation keys are actually produced. Align `METHOD_PRECONDITIONS`, documentation, and recon output to a single canonical set.

2. **Inconsistent precondition scope between `get_viable_chains` and `chaining_coordinator`** (lines 290–303)
   - `get_viable_chains` includes `achieved_outcomes` in `known_nodes`
   - `chaining_coordinator.evaluate_chain_route` explicitly excludes `achieved_outcomes` (`known = confirmed`)
   - **Why it matters:** `get_viable_chains` may report paths as "viable" that the runtime router will never actually traverse. This breaks any reporting or orchestrator logic that relies on `get_viable_chains` for path previews.
   - **Recommended fix:** Decide whether `achieved_outcomes` satisfies chain preconditions. If not, remove the `achieved_outcomes` parameter from `get_viable_chains` or rename it to `additional_nodes` with a docstring warning.

#### 🟠 Medium

3. **Redundant re-normalization in `get_next_actions`** (lines 232–258)
   - Edge metadata was already normalized in `_build_graph`. Re-wrapping it into `RawTransition` and calling `_normalize_transition` again is unnecessary and adds noise.
   - **Recommended fix:** Return the stored metadata directly, or extract a lightweight formatter that doesn't re-validate.

4. **Multi-step chain edges have redundant second edges** (lines 138–174)
   - Each cross-surface chain has two edges with the same `target_agent` (e.g., `brute_force_confirmed → authenticated_session → ac_idor`, both targeting `ac_idor`).
   - The second edge (`authenticated_session → ac_idor`) requires `authenticated_session` in `known`, but no agent appends this intermediate node to `confirmed_vulns`.
   - **Why it matters:** The second edge is dead code for routing. It may mislead consumers of `get_viable_chains` into thinking a two-step chain is viable when the intermediate is not recorded in state.
   - **Recommended fix:** Either (a) have `chaining_router_node` append intermediate chain targets to `confirmed_vulns`/`achieved_outcomes`, or (b) collapse each chain to a single edge and document intermediates as conceptual steps only.

5. **`get_viable_chains` may return paths through non-chain edges that don't represent real exploit chains**
   - `_path_is_viable` only validates chain edges, but `nx.all_simple_paths` traverses all edges. A path could include discovery edges (e.g., `sqli → sqli_union → sqli_union_confirmed`) mixed with chain edges, producing a "viable chain" that is really just normal method execution.
   - **Recommended fix:** Filter paths to require at least one chain edge, or restrict `all_simple_paths` to a subgraph containing only chain edges and confirmed-to-outcome edges.

#### 🟢 Low

6. **Orphan outcome nodes: `rce_achieved` and `user_compromised`** (line 29)
   - Listed in `HIGH_IMPACT_OUTCOMES` but no edges in the graph lead to them. This causes no runtime harm because `highest_impact_outcome` iterates severity order, but they are dead schema surface area.
   - `data_exfiltrated` is **not** orphan — it has incoming edges from `sqli_confirmed` and `access_control_confirmed`.
   - **Recommended fix:** Remove `rce_achieved` and `user_compromised` from `HIGH_IMPACT_OUTCOMES` and `_IMPACT_SEVERITY_ORDER`.

7. **Lazy import inside `_validate_agent_kg_node_mappings`** (line 214)
   - The module already imports `METHODS_BY_SURFACE` from `core.state` at the top of the file. Importing `MODULE_TO_KG_NODE` and `ALL_METHOD_AGENTS` inside the method is inconsistent.
   - **Recommended fix:** Move imports to the top of the file.

### Positive Findings
- Comprehensive validation suite (`_validate_chain_metadata`, `_validate_preconditions_known`, `_validate_high_impact_nodes_exist`, `_validate_agent_kg_node_mappings`) catches an entire class of graph construction bugs at import time.
- `_as_preconditions` robustly handles `str`, `list[str]`, and `None`.
- `Transition` dataclass is frozen and slotted, providing immutability guarantees.

---

## File: `core/state.py`

### Summary
TypedDict schema for LangGraph state with custom reducers. Comprehensive default state template. Strong test coverage for reducer behavior. However, two critical dict fields lack reducers, creating overwrite hazards.

### Issues Found

#### 🔴 Critical

1. **`tried_payloads` and `scores` are plain `dict` without reducers** (lines 45, 57)
   - LangGraph overwrites non-annotated fields with the last node's output. If any agent returns a partial dict (e.g., `{"scores": {"sqli_union": 3}}`), it wipes all prior agents' scores.
   - The framework mitigates this via `make_update`/`merge_scores`/`merge_tried_payloads`, but this is a convention, not an enforcement. A single agent that bypasses the helper will corrupt state.
   - **Why it matters:** Violates AGENTS.md rules 3 and 6 (track tried payloads, no redundant retries). Also breaks scoring if an agent forgets to merge.
   - **Recommended fix:** Add custom reducers:
     ```python
     def _merge_scores(a: dict[str, int], b: dict[str, int]) -> dict[str, int]:
         merged = dict(a)
         for k, v in b.items():
             merged[k] = max(merged.get(k, 0), v)
         return merged

     def _merge_tried_payloads(a: dict[str, list[str]], b: dict[str, list[str]]) -> dict[str, list[str]]:
         merged = {k: list(v) for k, v in a.items()}
         for k, payloads in b.items():
             existing = set(merged.get(k, []))
             merged[k] = merged.get(k, []) + [p for p in payloads if p not in existing]
         return merged
     ```
     Then annotate:
     ```python
     scores: Annotated[dict[str, int], _merge_scores]
     tried_payloads: Annotated[dict[str, list[str]], _merge_tried_payloads]
     ```

#### 🟡 High

2. **`akg_path` lacks a reducer** (line 62)
   - Spec shows accumulation: `akg_path + [decision.next_agent]`. Without `Annotated[list[str], add]`, each node must read the full list and return it.
   - **Recommended fix:** Add `Annotated[list[str], add]` or a custom deduplicating reducer.

3. **Missing `evasion_strategy` field; test expects it** (not in schema, but in `test_state.py` OPTIONAL_FIELDS)
   - `scorer.py` reads `state.get("evasion_mode")` and passes it as `evasion_strategy` to `ScoreSummary`. The field name mismatch is confusing.
   - **Recommended fix:** Either add `evasion_strategy: NotRequired[str]` to the schema, or rename `evasion_mode` to `evasion_strategy` everywhere.

#### 🟠 Medium

4. **`MODULE_TO_KG_NODE` inconsistency for `ac_vertical_escalation`** (lines 147–148)
   - Maps to `ac_vertical_escalation_confirmed` (method-specific), while all others map to surface-confirmed nodes. `_derive_surface_confirmed` treats this as a surface-confirmed mapping but it is not.
   - **Why it matters:** The function docstring says "Map method-confirmed nodes to surface-confirmed nodes", but for this agent it returns the method node itself. This is intentional due to the chain edge, but the naming is misleading.
   - **Recommended fix:** Rename the helper to `_derive_chain_confirmed` or add a code comment explaining the exception.

5. **`NotRequired` fields are always present in `DEFAULT_STATE`** (lines 79–113)
   - Fields like `evasion_enabled`, `evasion_max_retries` are `NotRequired` but populated in the default template. This negates the type-level optionality.
   - **Recommended fix:** Remove `NotRequired` if the field is always expected, or remove them from `DEFAULT_STATE` to make them truly optional.

#### 🟢 Low

6. **Unused accumulation fields: `blocked_patterns`, `successful_bypasses`** (lines 48–49)
   - Declared in schema with `add` reducers but not referenced in any core file.
   - **Recommended fix:** Remove if dead, or document their intended use in AGENTS.md.

7. **`KG_NODES` includes legacy nodes not in the AKG graph** (lines 154–181)
   - Nodes like `xss_reflected_confirmed`, `lfi_confirmed` are listed for backward compatibility but do not exist in `AttackKnowledgeGraph`.
   - **Recommended fix:** Add a comment block separating legacy nodes from active nodes.

### Positive Findings
- `_merge_dicts` correctly implements monotonic boolean merging (True is never downgraded to False).
- `new_default_state()` returns deep copies, preventing test pollution.
- Excellent test coverage for reducer behavior and schema completeness.

---

## File: `core/chaining_coordinator.py`

### Summary
Conditional edge router implementing fallback loops and cross-surface chain detection. Logic is mostly correct, but the ordering of termination checks and the treatment of `achieved_outcomes` create edge cases.

### Issues Found

#### 🔴 Critical
*No critical issues found.*

#### 🟡 High

1. **`critical_outcome_achieved` is checked AFTER the fallback loop** (lines 126–135)
   - If the last agent failed (`BLOCKED` or `EXECUTION_FAILURE`) but a critical outcome was achieved earlier, the router enters fallback instead of terminating.
   - Per AGENTS.md pseudocode (section 5.5), critical outcome should route to scorer immediately.
   - **Why it matters:** Wastes iterations on fallback methods after already achieving the highest-possible outcome.
   - **Recommended fix:** Move the `critical_outcome_achieved` check before the fallback loop (before line 102).

2. **Chain precondition split: `known = confirmed` ignores `achieved_outcomes`** (line 76)
   - The comment says this is intentional, but it means outcome nodes added to `achieved_outcomes` (e.g., by agents that separate outcomes from vulns) will not satisfy chain preconditions.
   - Combined with `get_viable_chains` using `achieved_outcomes`, this creates a runtime-vs-reporting mismatch.
   - **Recommended fix:** Document the design decision explicitly in a module-level docstring, and consider unifying to `known = confirmed | achieved` if the separation is not load-bearing.

#### 🟠 Medium

3. **Fallback second pass ignores method preconditions** (lines 111–122)
   - After exhausting viable methods, the router tries any unattempted method on the surface regardless of whether its preconditions are met.
   - **Why it matters:** May dispatch `sqli_time_blind` even when `response_delay_measurable=False`, wasting iterations.
   - **Recommended fix:** Keep the second pass but log a warning, or gate it behind a `fallback_depth` threshold.

4. **`route_after_agent` discards telemetry event** (lines 67–69)
   - `evaluate_chain_route` returns a rich event dict, but `route_after_agent` drops it. LangGraph conditional edge functions can only return strings, so the event is lost at the graph level.
   - **Why it matters:** `chaining_router_node` re-computes the route to capture the event, which is redundant and could diverge if state changes between calls.
   - **Recommended fix:** Merge `chaining_router_node` logic into the graph so the event is computed once and stored atomically.

#### 🟢 Low

5. **Fresh `AttackKnowledgeGraph()` instantiated per call** (line 82)
   - The graph is static; constructing it on every route evaluation is wasteful.
   - **Recommended fix:** Use a module-level singleton or cache.

### Positive Findings
- `_find_next_unvisited` correctly deduplicates against both `attempted` and `blocked`.
- `_derive_surface_confirmed` handles both direct mappings and `_confirmed` suffix stripping robustly.
- Deduplication of `attempted_agents` via `dict.fromkeys` correctly handles the `Annotated[list, add]` duplicate accumulation issue.

---

## File: `core/graph_builder.py`

### Summary
LangGraph `StateGraph` assembly for the 3-surface runtime. Clean registration of all 9 method agents. All conditional edges wired correctly. Missing checkpointer and unused parameters are the main issues.

### Issues Found

#### 🔴 Critical
*No critical issues found.*

#### 🟡 High

1. **`build_framework` ignores `llm_provider` and `surface` parameters** (lines 46–47)
   - Both are accepted but immediately discarded (`_ = llm_provider`). The function signature implies per-provider/per-surface graph customization that does not exist.
   - **Why it matters:** Misleading API. Callers may expect different graph shapes for different surfaces.
   - **Recommended fix:** Remove both parameters, or wire `surface` into an initial-state setter and `llm_provider` into the orchestrator node's closure.

2. **No checkpointer configured** (not present)
   - AGENTS.md tech stack lists `MemorySaver`. The spec requires thread IDs like `f"{provider}-{surface}-{level}"`.
   - Without a checkpointer, `thread_id` in `config={"configurable": {...}}` has no effect on state persistence.
   - **Why it matters:** No checkpointing means no resumable runs, no human-in-the-loop, and no thread-scoped memory.
   - **Recommended fix:** Add `from langgraph.checkpoint.memory import MemorySaver` and `graph.compile(checkpointer=MemorySaver())`.

#### 🟠 Medium

3. **Silent fallback to `scorer` for unknown `next_agent` values** (lines 50–59)
   - `route_from_orchestrator` returns `"scorer"` for any unknown node name. This hides typos or orchestrator hallucinations.
   - **Recommended fix:** Log a warning when falling back to scorer due to an unknown agent name.

4. **`scorer` imported inside `build_framework`** (line 46)
   - Lazy import is likely to avoid a circular dependency, but it masks the dependency graph.
   - **Recommended fix:** Add a comment explaining the circular dependency, or restructure imports to avoid it.

#### 🟢 Low

5. **Extra orchestrator hop in fallback loop**
   - Fallback routing goes: `method_agent → chaining_router → orchestrator → method_agent`. The orchestrator hop is unnecessary for simple fallback — the chaining router could route directly to the next method.
   - **Recommended fix:** Not required by spec, but could save one LLM call per fallback iteration.

### Positive Findings
- `RUNTIME_AGENT_NODE_NAMES` and `RUNTIME_AGENT_HANDLERS` are kept in sync via the test `test_stage5_runtime_handlers_are_real_callables`.
- All 9 method agents are registered and connected to `chaining_router`.
- Graph compiles successfully and tests verify bounded iteration behavior.

---

## File: `core/scorer.py`

### Summary
Terminal node that computes scores, metrics, and summary reports. Correctly clamps out-of-range scores. But the default `task_result` and ad-hoc metric placement are problematic.

### Issues Found

#### 🔴 Critical
*No critical issues found.*

#### 🟡 High

1. **`task_result` defaults to `"SUCCESS"` when `None`** (lines 126–128)
   ```python
   existing_result = state.get("task_result")
   task_result = existing_result or "SUCCESS"
   ```
   - If the run never set `task_result` (e.g., budget exhausted with no exploits), scorer labels it `"SUCCESS"`.
   - **Why it matters:** Misleading telemetry and reports. A run with all-zero scores should not be "SUCCESS".
   - **Recommended fix:** Default to `"INCOMPLETE"` or preserve the `incomplete_reason` mapping:
     ```python
     if existing_result is None:
         task_result = "INCOMPLETE" if state.get("incomplete_reason") else "SUCCESS"
     ```

2. **Metrics computed in `scorer` but omitted from `ScoreSummary` contract** (lines 90–99 vs `evaluation/contracts.py`)
   - `method_selection_accuracy`, `adaptation_rate`, `mean_attempts_to_success` are computed in `scorer` and added to the raw `summary` dict, but `ScoreSummary` dataclass does not declare them.
   - **Why it matters:** Schema inconsistency. Consumers of `ScorerReport.to_dict()` may not expect these keys, and consumers of the dataclass don't get them.
   - **Recommended fix:** Add the three metrics fields to `ScoreSummary` in `evaluation/contracts.py` with defaults, or remove them from `scorer` and keep them in a separate metrics module.

#### 🟠 Medium

3. **`surface_scores["adapted"]` is globally, not per-surface** (lines 115–118)
   ```python
   adapted = bool(state.get("failure_agents", [])) and best_score >= 3
   ```
   - Any failure in any surface makes every surface appear "adapted".
   - **Why it matters:** `adapted` is a per-surface metric in the nested dict, but it uses global `failure_agents`.
   - **Recommended fix:** Compute per-surface failures:
     ```python
     surface_failures = [a for a in state.get("failure_agents", []) if a in methods]
     adapted = bool(surface_failures) and best_score >= 3
     ```

4. **Redundant clamp in `build_score_report`** (lines 31–33)
   - `successful_evasions = min(...)` duplicates the validation already in `ScoreSummary.__post_init__`.
   - **Recommended fix:** Remove the clamp and rely on the dataclass validation.

5. **`akg_path` duplicated into every surface score** (line 120)
   - The full `akg_path` is included in each surface's dict. For 3 surfaces, it's triplicated in the output.
   - **Recommended fix:** Move `akg_path` to the top-level summary only.

#### 🟢 Low

6. **String chain parsing in `_parse_chain_candidates` is likely dead code** (lines 45–55)
   - `chain_history` items are always dicts in current agents. The `"→"` split branch is untested and unused.
   - **Recommended fix:** Remove the string branch or add a test for it.

7. **`next_agent: "END"` is a string, not the LangGraph `END` sentinel** (line 132)
   - The graph uses `graph.add_edge("scorer", END)`, so `route_from_chaining_router` never sees `"END"`. It works by accident because scorer is terminal.
   - **Recommended fix:** Use `from langgraph.graph import END` and return `END` instead of `"END"`.

### Positive Findings
- `normalize_method_scores` correctly clamps all out-of-range values to [0, 4].
- `scorer` does not mutate input state (verified by test).
- `build_score_report` produces deterministic output for all agents in canonical order.
- `highest_impact_outcome` uses a sensible severity ranking (`rce_achieved` > `admin_session_obtained` > ...).

---

## Cross-Cutting Concerns

### LangGraph Patterns
- **Reducers:** Most list fields use `Annotated[..., add]` correctly. The missing reducers for `scores`, `tried_payloads`, and `akg_path` are the primary LangGraph compliance gaps.
- **Conditional Edges:** Both `route_from_orchestrator` and `route_from_chaining_router` correctly return node name strings. No missing nodes.
- **StateGraph Compilation:** `build_framework` compiles and passes integration tests. No circular dependency issues at runtime.

### Type Safety
- No bare `except` clauses in the core layer.
- No mutable default arguments.
- `TypedDict` uses `Annotated` and `NotRequired` correctly (Python 3.12+).

### Test Coverage Gaps
- No test for `scores` overwrite behavior when two agents run sequentially.
- No test for `tried_payloads` accumulation across multiple agents.
- No test verifying that `task_result` defaults to `"INCOMPLETE"` on empty runs.
- No test for `critical_outcome_achieved` routing priority relative to fallback.
- No test for `get_viable_chains` returning paths that require intermediate nodes not in `known`.

---

## Recommended Priority Order

1. **Add reducers to `scores` and `tried_payloads`** (state.py — CRITICAL if agents deviate from `make_update`)
2. **Fix `task_result` default in scorer** (scorer.py — HIGH, prevents false success labels)
3. **Add `MemorySaver` checkpointer** (graph_builder.py — HIGH, required by spec)
4. **Move `critical_outcome_achieved` check before fallback** (chaining_coordinator.py — HIGH)
5. **Align `METHOD_PRECONDITIONS` with recon output** (knowledge_graph.py — HIGH)
6. **Unify `achieved_outcomes` treatment** between `get_viable_chains` and `chaining_coordinator` (knowledge_graph.py + chaining_coordinator.py — HIGH)
7. **Add `method_selection_accuracy`, `adaptation_rate`, `mean_attempts_to_success` to `ScoreSummary`** (evaluation/contracts.py — MEDIUM)
8. **Fix per-surface `adapted` metric** (scorer.py — MEDIUM)
9. **Remove or document dead parameters in `build_framework`** (graph_builder.py — MEDIUM)
10. **Add missing reducer to `akg_path`** (state.py — MEDIUM)
