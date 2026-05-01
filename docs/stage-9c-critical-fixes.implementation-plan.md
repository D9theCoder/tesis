# Stage 9C Implementation Plan — Critical Pipeline Fixes

## Manifest

- `module_name`: `stage-9c-critical-fixes`
- `output_filename`: `stage-9c-critical-fixes.implementation-plan.md`
- `repo_root`: `.`
- `language`: `python`
- `test_command`: `pytest -q`
- `ruleset_files`:
  - `AGENTS.md`
  - `docs/summary.md`
  - `docs/stage-9a-code-review-report.md`
- `files_to_modify`:
  - `core/state.py`
  - `foundation/recon.py`
  - `agents/state_utils.py`
  - `agents/sqli/sqli_union_agent.py`
  - `agents/sqli/sqli_error_agent.py`
  - `agents/sqli/sqli_boolean_blind_agent.py`
  - `agents/sqli/sqli_time_blind_agent.py`
  - `agents/access_control/ac_idor_agent.py`
  - `agents/access_control/ac_vertical_escalation_agent.py`
  - `agents/access_control/ac_force_browse_agent.py`
  - `agents/brute_force/bf_dictionary_agent.py`
  - `agents/brute_force/bf_spray_agent.py`
- `tests_to_add`:
  - `tests/test_sqli_boolean_blind_agent.py` (update assertions)
  - `tests/test_sqli_time_blind_agent.py` (update assertions)
  - `tests/test_recon.py` (extend)
  - `tests/test_state_utils.py` (extend)
  - `tests/test_state_reducers.py` (extend)

## Short summary

This plan fixes 3 critical bugs and 1 high-priority gap discovered in the post-Stage-9B deep audit of the red teaming pipeline. Two bugs silently break exploitation paths (blind/time SQLi chains unreachable, ac_idor never dispatched). One bug makes the fallback loop and adaptation metric permanently dead. One gap lets observation corruption propagate.

## Inputs & preconditions

1. `core/state.py` — `MODULE_TO_KG_NODE` maps `sqli_boolean_blind` and `sqli_time_blind` to `"blind_sqli_confirmed"`, but the AKG has no node with that name.
2. `foundation/recon.py` — `DVWA_MODULE_HINTS` has no `"authbypass"` entry, so `object_ids_enumerable` is always `False`.
3. `agents/state_utils.py` — `make_update()` has no `failure_agents` parameter; no agent ever populates `state["failure_agents"]`.
4. `core/state.py` — `_merge_dicts()` reducer uses `dict.update()` which overwrites `True` with `False`.

## Design & architecture

### Fix 1: Remap blind/time SQLi confirmed nodes (state.py + tests)

**Problem:** `MODULE_TO_KG_NODE` maps `sqli_boolean_blind` → `"blind_sqli_confirmed"` and `sqli_time_blind` → `"blind_sqli_confirmed"`. The AKG has no `blind_sqli_confirmed` node — it has `sqli_boolean_blind_confirmed` and `sqli_time_blind_confirmed`. When an agent appends `"blind_sqli_confirmed"` to `confirmed_vulns`, `kg.get_next_actions("blind_sqli_confirmed")` returns `[]` because the node doesn't exist in the graph. Chain 2 (`sqli_confirmed → credentials_extracted → brute_force_confirmed`) is unreachable from blind/time SQLi.

**Per `docs/summary.md` Section 7**: ALL 4 SQLi methods output `sqli_confirmed` as their Chain Output node. `sqli_union` and `sqli_error` already map correctly. The fix is to remap `sqli_boolean_blind` and `sqli_time_blind`.

**Fix in `core/state.py`** (line 202-203):
```python
# Before:
"sqli_boolean_blind": "blind_sqli_confirmed",
"sqli_time_blind": "blind_sqli_confirmed",
# After:
"sqli_boolean_blind": "sqli_confirmed",
"sqli_time_blind": "sqli_confirmed",
```

The AKG already has edges from `sqli_confirmed`:
- `sqli_confirmed → credentials_extracted` (non-chain, priority 30)
- `sqli_confirmed → data_exfiltrated` (non-chain, priority 30)
- `sqli_confirmed → credentials_extracted` (chain, `target_agent="bf_dictionary"`)
- `sqli_boolean_blind_confirmed → sqli_confirmed` (non-chain, priority 40)
- `sqli_time_blind_confirmed → sqli_confirmed` (non-chain, priority 40)

**Test updates:** `tests/test_sqli_boolean_blind_agent.py` line 84 and `tests/test_sqli_time_blind_agent.py` line 82 assert `"blind_sqli_confirmed" in result.get("confirmed_vulns", [])`. Change to `"sqli_confirmed"`.

### Fix 2: Add `"authbypass"` to DVWA_MODULE_HINTS (recon.py)

**Problem:** `DVWA_MODULE_HINTS` has no entry for the authbypass endpoint (`/vulnerabilities/authbypass/`), which is the endpoint used by all 3 access control agents. The `infer_module_name()` function returns `"unknown"` for this path. The recon observation `object_ids_enumerable` checks `"idor" in module_names`, which is always `False` — so the AKG never marks `ac_idor` as viable.

**Fix in `foundation/recon.py`** (after line 43, inside `DVWA_MODULE_HINTS`):
```python
# Before:
    "brute": "brute",
}
# After:
    "brute": "brute",
    "authbypass": "idor",
}
```

Note: `"authbypass"` is 10 characters long, which is shorter than `"sqli_blind"` (10) but matches before the generic `"sqli"` (4) pattern. The sort-by-length-descending logic in `infer_module_name()` handles this correctly.

Also update the observation derivation in recon (around the line that checks `"idor" in module_names`):
```python
# Before (current):
observations["object_ids_enumerable"] = "idor" in module_names
# After — no change needed if DVWA_MODULE_HINTS is fixed; the check is already correct
```

### Fix 3: Wire `failure_agents` through `make_update()` and all 9 agents

**Problem:** `make_update()` has no `failure_agents` parameter. No agent ever populates `state["failure_agents"]`. Three subsystems break:
1. **Chaining coordinator fallback loop** — `last_agent in failure_agents → EXECUTION_FAILURE` never triggers
2. **Orchestrator LLM prompt** — `failure_agents={...}` is always empty; LLM may re-select failing agents
3. **Scorer adaptation metric** — `adapted = bool(state.get("failure_agents", [])) and best_score >= 3` is always `False`

**Fix in `agents/state_utils.py`** — Add `failure_agents` parameter to `make_update()`:

Change the signature (line 136-147):
```python
def make_update(
    *,
    state: dict[str, Any],
    module_name: str,
    score: int,
    tried_payloads: list[str],
    confirmed_vulns: list[str] | None = None,
    achieved_outcomes: list[str] | None = None,
    found_credentials: list[dict[str, str]] | None = None,
    next_agent: str = "orchestrator",
    telemetry_events: list[dict] | None = None,
    failure_agents: list[str] | None = None,    # NEW
) -> dict[str, Any]:
```

Add to the update dict body (after line 153):
```python
    # Only add failure_agents if provided (uses Annotated[list, add] reducer)
    if failure_agents:
        update["failure_agents"] = [
            a for a in failure_agents
            if a not in state.get("failure_agents", [])
        ]
```

**Fix in all 9 agents** — In every agent's `except Exception` block, pass `failure_agents=[AGENT_ID]`:

Example for `sqli_union_agent.py` (around line 130):
```python
# Before:
except Exception as exc:
    logger.warning("[%s] Session or execution failed: %s", AGENT_ID, exc)
    return make_update(state=state, module_name=AGENT_ID, score=0, tried_payloads=[])
# After:
except Exception as exc:
    logger.warning("[%s] Session or execution failed: %s", AGENT_ID, exc)
    return make_update(
        state=state, module_name=AGENT_ID, score=0, tried_payloads=[],
        failure_agents=[AGENT_ID]
    )
```

Same pattern for the `session.login()` failure return and the `session.set_security_level()` try/except in every agent.

### Fix 4: Fix `_merge_dicts` reducer to never overwrite True with False

**Problem:** The docstring says "without overwriting existing keys to False" but `dict.update()` unconditionally overwrites. If any agent returns `{key: False}` after another agent set it to `True`, the observation is permanently lost.

**Fix in `core/state.py`** (lines 11-15):
```python
# Before:
def _merge_dicts(a: dict, b: dict) -> dict:
    """Reducer for observations: merge b into a without overwriting existing keys to False."""
    merged = dict(a)
    merged.update(b)
    return merged
# After:
def _merge_dicts(a: dict, b: dict) -> dict:
    """Reducer for observations: merge b into a; never overwrite True with False."""
    merged = dict(a)
    for key, value in b.items():
        if key not in merged or not merged[key]:
            merged[key] = value
    return merged
```

This preserves `True` observations while allowing `False` → `True` transitions.

## Files to modify

### 1. `core/state.py`

Two changes:
- **Line 11-15:** Replace `_merge_dicts` with the safe version (Fix 4)
- **Line 202-203:** Change `"blind_sqli_confirmed"` → `"sqli_confirmed"` for `sqli_boolean_blind` and `sqli_time_blind` (Fix 1)

### 2. `foundation/recon.py`

One change:
- **Line 43:** Add `"authbypass": "idor"` to `DVWA_MODULE_HINTS` (Fix 2)

### 3. `agents/state_utils.py`

Two changes:
- **Line 136-147:** Add `failure_agents: list[str] | None = None` parameter to `make_update()` signature
- **After line 153:** Add `failure_agents` filter + assign block in the update dict

### 4–12. All 9 agent files

In each agent, find the `except Exception` block (after `session.login()` or `session.set_security_level()`) and add `failure_agents=[AGENT_ID]` to the `make_update()` call. Specific locations per agent:

| Agent | Lines to change |
|---|---|
| `sqli_union_agent.py` | Login failure return (~line 120-125), except block (~line 130-132) |
| `sqli_error_agent.py` | Same pattern |
| `sqli_boolean_blind_agent.py` | Same pattern |
| `sqli_time_blind_agent.py` | Same pattern |
| `ac_idor_agent.py` | Same pattern |
| `ac_vertical_escalation_agent.py` | Same pattern |
| `ac_force_browse_agent.py` | Same pattern |
| `bf_dictionary_agent.py` | Same pattern |
| `bf_spray_agent.py` | Same pattern |

## Tests to update / add

### Update existing tests

**`tests/test_sqli_boolean_blind_agent.py`** (line 84):
```python
# Before:
assert "blind_sqli_confirmed" in result.get("confirmed_vulns", [])
# After:
assert "sqli_confirmed" in result.get("confirmed_vulns", [])
```
And line 88-90 (docstring references):
```python
# Before:
"""blind_sqli_confirmed is not in the AKG graph, so chain check cannot..."""
base_state["confirmed_vulns"] = ["blind_sqli_confirmed"]
# After:
"""sqli_confirmed is in the AKG graph, so chain check can find credentials_extracted."""
base_state["confirmed_vulns"] = ["sqli_confirmed"]
```

**`tests/test_sqli_time_blind_agent.py`** — same changes at lines 82, 86-88.

**`tests/test_state.py`** (line 282) — update `"blind_sqli_confirmed"` reference if it asserts module mappings.

### New tests

**`tests/test_recon.py`** — extend with:
```python
def test_authbypass_maps_to_idor():
    from foundation.recon import infer_module_name
    assert infer_module_name("/vulnerabilities/authbypass/") == "idor"

def test_object_ids_enumerable_after_authbypass_fix():
    from foundation.recon import DVWA_MODULE_HINTS
    assert "authbypass" in DVWA_MODULE_HINTS
    assert DVWA_MODULE_HINTS["authbypass"] == "idor"
```

**`tests/test_state_utils.py`** — extend with:
```python
def test_make_update_handles_failure_agents():
    state = new_default_state()
    update = make_update(
        state=state, module_name="sqli_union", score=0,
        tried_payloads=[], failure_agents=["sqli_union"],
    )
    assert "failure_agents" in update
    assert update["failure_agents"] == ["sqli_union"]

def test_make_update_no_failure_agents_when_none():
    state = new_default_state()
    update = make_update(
        state=state, module_name="sqli_union", score=0,
        tried_payloads=[],
    )
    assert "failure_agents" not in update
```

**`tests/test_state_reducers.py`** — extend with (or add to existing state tests):
```python
def test_merge_dicts_preserves_true_over_false():
    from core.state import _merge_dicts
    a = {"key1": True, "key2": False}
    b = {"key1": False, "key3": True}
    result = _merge_dicts(a, b)
    assert result["key1"] is True   # True preserved over False
    assert result["key2"] is False
    assert result["key3"] is True
```

## How to Run and Validate

1. Run updated agent tests:
```bash
pytest -q tests/test_sqli_boolean_blind_agent.py tests/test_sqli_time_blind_agent.py
```

2. Run recon tests:
```bash
pytest -q tests/test_recon.py
```

3. Run state utils tests:
```bash
pytest -q tests/test_state_utils.py tests/test_state.py
```

4. Run affected agent tests:
```bash
pytest -q tests/test_ac_idor_agent.py tests/test_sqli_union_agent.py tests/test_bf_dictionary_agent.py
```

5. Full regression:
```bash
pytest -q
```

Expected: all 402 existing tests remain green; new tests validate fixes.

## Backwards Compatibility and Migration Steps

1. **`blind_sqli_confirmed` removal**: The `MODULE_TO_KG_NODE` key `"sqli_blind"` (legacy) still maps to `"blind_sqli_confirmed"` — leave it for backward compatibility with any old code that uses the legacy module name. The `KG_NODES` list still contains `"blind_sqli_confirmed"` — leave it as a legacy alias.
2. **`failure_agents` parameter**: `make_update()` defaults to `None` — existing callers that don't pass it get no `failure_agents` key (unchanged behavior).
3. **`_merge_dicts` behavior**: The new reducer is strictly less destructive than the old one. Any test that relied on `True → False` overwrite was testing buggy behavior.
4. **DVWA_MODULE_HINTS**: Additive change — existing entries unchanged, one new entry added.

## Error Handling and Edge Cases

- **Empty failure_agents list**: `make_update()` with `failure_agents=[]` produces no `failure_agents` key (same as `None`).
- **Already-failed agent retry**: The deduplication filter `if a not in state.get("failure_agents", [])` prevents appending the same agent twice.
- **`_merge_dicts` with empty dict**: Returns a copy of `a` unchanged.
- **`infer_module_name` with authbypass**: The sort-by-length ensures `"authbypass"` (10 chars) is checked before `"sqli_blind"` (10 chars, same length) — tie-breaking is stable in Python's `sorted()`.

## Rollback Plan

1. Revert `core/state.py` `MODULE_TO_KG_NODE` to `"blind_sqli_confirmed"`.
2. Revert `core/state.py` `_merge_dicts` to `merged.update(b)`.
3. Remove `"authbypass"` from `DVWA_MODULE_HINTS` in `recon.py`.
4. Remove `failure_agents` parameter from `make_update()` and all agent calls.
5. Revert test assertion changes.

## Acceptance Criteria

- [ ] `MODULE_TO_KG_NODE` maps `sqli_boolean_blind` and `sqli_time_blind` to `"sqli_confirmed"`.
- [ ] Blind/time SQLi agents' chain check can reach `credentials_extracted` via `sqli_confirmed`.
- [ ] `DVWA_MODULE_HINTS` includes `"authbypass": "idor"`.
- [ ] `infer_module_name("/vulnerabilities/authbypass/")` returns `"idor"`.
- [ ] `make_update()` accepts and processes `failure_agents` parameter.
- [ ] All 9 agents pass `failure_agents=[AGENT_ID]` in their except blocks.
- [ ] `_merge_dicts` never overwrites `True` with `False`.
- [ ] All updated tests pass.
- [ ] Full test suite (402+) remains green.

## Estimated effort

- Overall: **Medium** (~5–7 hours).
- Breakdown:
  - `blind_sqli_confirmed` remap + tests: **1h**
  - `DVWA_MODULE_HINTS` fix + tests: **0.5h**
  - `failure_agents` wiring (state_utils + 9 agents): **2–3h**
  - `_merge_dicts` fix + tests: **0.5h**
  - Test updates and verification: **1h**

