# Stage 9A Code Review Report

**Scope:** 11 files — 9 method agents, `state_utils.py`, `payload_library.py`
**Date:** 2026-05-01
**Branch:** stage-9-refactor-agent
**Tests:** 78/78 passed (but several critical paths uncovered)

---

## Executive Summary

The Stage 9A agents correctly implement the PROBE -> EXPLOIT -> CHAIN CHECK pipeline and pass all existing unit tests. However, there are **3 critical bugs** that will cause false negatives, state corruption, or dead chain edges in a live LangGraph runtime loop:

1. **Chain check never triggers on first confirmation** because `_chain_check` reads `confirmed_vulns` from input state (pre-run) instead of including the vuln just discovered by the current agent.
2. **Observations are overwritten on re-runs** because agents return `{obs_key: False}` even when probes were skipped due to `already_tried`, and the `_merge_dicts` reducer blindly overwrites.
3. **`ac_force_browse_agent` uses incorrect DVWA paths** (`/dvwa/setup.php` resolves to `http://localhost/dvwa/dvwa/setup.php`) and completely ignores the payload library.

Additionally, `bf_dictionary` and `bf_spray` probes ignore payload-library payloads, return incorrect scores on precondition failure, and produce false positives on cached probes.

---

## Critical Issues

### C1. `_chain_check` cannot trigger on first confirmation (ALL 9 agents)

**Files:** Every agent file (lines vary, function `_chain_check`)

Every agent calls:
```python
chain_score, chain_achieved = _chain_check(confirmed_vulns[0], state)
```

Inside `_chain_check`:
```python
confirmed_set = set(state.get("confirmed_vulns", []))
```

This reads the **input state** before the current agent run. The vulnerability just confirmed by this agent (e.g., `sqli_confirmed`) is in the local `confirmed_vulns` list but **NOT** in `state["confirmed_vulns"]` yet. Therefore, any chain precondition that requires the newly confirmed node will never be satisfied on the first confirmation.

**Example:** If `sqli_union_agent` confirms `sqli_confirmed`, the AKG chain to `credentials_extracted` requires `sqli_confirmed`. `_chain_check` looks at `state.get("confirmed_vulns", [])` (empty on first run) and misses it. The agent returns score 3 instead of 4.

**Why it matters:** Chains only trigger if the precondition vuln was confirmed by a **previous** agent run. Score 4 becomes impossible on the first successful exploitation.

**Recommended fix:** Pass the local `confirmed_vulns` into `_chain_check` and union it with state's confirmed set:
```python
def _chain_check(confirmed_node: str, state: ExploitationState, local_confirmed: list[str]) -> tuple[int, list[str]]:
    confirmed_set = set(state.get("confirmed_vulns", [])) | set(local_confirmed)
    ...
```

---

### C2. Observations corrupted on agent re-runs (ALL 9 agents + `core/state.py`)

**Files:** All agents (PROBE return paths) + `core/state.py` line 23

All agents return `observations = {_PROBE_OBSERVATION_KEY: False}` when probes fail or are skipped. The state reducer `_merge_dicts` blindly overwrites:

```python
def _merge_dicts(a: dict, b: dict) -> dict:
    merged = dict(a)
    merged.update(b)  # overwrites True with False
    return merged
```

On a second run, if all probe payloads are in `already_tried`, the agent skips all probes and returns `{key: False}`, **overwriting a previously True observation**.

**Why it matters:** In a LangGraph loop, the orchestrator uses `observations` to decide viable methods. A True observation that flips to False will cause the orchestrator to skip viable agents, leading to false negatives and incomplete runs.

**Recommended fix (two-part):**
1. **Agents:** Only return observation keys that were actually tested. If all probes are skipped, return an empty observations dict (or the prior observation value).
2. **Reducer:** Change `_merge_dicts` to never overwrite `True` with `False`:
```python
def _merge_dicts(a: dict, b: dict) -> dict:
    merged = dict(a)
    for key, value in b.items():
        if key not in merged or not merged[key]:
            merged[key] = value
    return merged
```

---

### C3. `ac_force_browse_agent` uses incorrect absolute paths and ignores payload library

**File:** `agents/access_control/ac_force_browse_agent.py`

**Path bug (lines 45-50):**
```python
probe_paths = [
    "/dvwa/setup.php",
    "/dvwa/phpinfo.php",
    ...
]
resp = session.get(path)
```

`DVWASession.get()` -> `HTTPClient.get()` -> `urljoin(base_url, path.lstrip("/"))`. With `base_url="http://localhost/dvwa/"`:
- `path = "/dvwa/setup.php"` -> `lstrip` -> `"dvwa/setup.php"` -> `urljoin` -> `"http://localhost/dvwa/dvwa/setup.php"`

These are **404 paths**. The agent will never detect force-browseable pages in a real DVWA instance.

**Payload library bug (lines 42-90):**
`_probe_preconditions` and `_attempt_exploit` accept `payloads` but **never use them**. They use hardcoded `probe_paths` and `exploit_paths` instead. The payload library entries for `ac_force_browse` are completely ignored.

**Why it matters:** The agent is non-functional against real DVWA. It will always return score 0.

**Recommended fix:**
```python
# Use relative paths, not absolute /dvwa/...
probe_paths = ["setup.php", "phpinfo.php", "security.php", "vulnerabilities/view_source.php"]
```
And integrate payload library payloads as path suffixes or alternatives.

---

### C4. `bf_dictionary` and `bf_spray` probes ignore payload library and return wrong score on precondition failure

**Files:** `agents/brute_force/bf_dictionary_agent.py`, `agents/brute_force/bf_spray_agent.py`

**Payload library ignored (lines 56-76 in both):**
`_probe_preconditions` accepts `payloads` but never iterates over them. It always sends hardcoded `username=test&password=test` requests with synthetic keys (`rate_probe_0`, `spray_probe_0`, etc.). The payload library probe payloads (e.g., `admin:password`) are never sent.

**Wrong score on precondition failure (lines 140-145 in bf_dictionary, 138-143 in bf_spray):**
When rate limiting is detected (`probe_ok = False`), the agents return:
```python
update = make_update(..., score=1, ...)
```

Per AGENTS.md rubric, precondition unmet = **score 0**.

**False positive on cached probes (lines 56-76):**
If all `probe_key` values are in `already_tried` from a previous run, the loop body never executes. `probe_elapsed` is ~0, which is `< _RATE_LIMIT_THRESHOLD`, so the function returns `probe_ok = True` (no rate limit) **without sending any requests**.

**Why it matters:**
1. Wasted payload library entries.
2. Precondition-unmet scenarios are scored as "Identified" (score 1) instead of "Not Found" (score 0), inflating metrics.
3. Rate limit status is assumed from cache without verification, causing false positives in long-running graphs.

**Recommended fix:**
1. Use `payloads` for the actual credential probes (or document why synthetic probes are used).
2. Return `score=0` when `probe_ok` is False.
3. If all probes are cached, return the prior observation from state instead of blindly assuming no rate limit:
```python
if not any(f"rate_probe_{i}" not in already_tried for i in range(3)):
    cached = state.get("observations", {}).get(_PROBE_OBSERVATION_KEY, False)
    return cached, [], {"no_rate_limit": cached}, []
```

---

## Warning Issues

### W1. AKG method-confirmed chain edge is dead code

**File:** `core/knowledge_graph.py` (lines 158-164)

The AKG defines a chain edge:
```python
{
    "source": "ac_vertical_escalation_confirmed",
    "target": "sqli_union",
    "is_chain": True,
    "preconditions": ["ac_vertical_escalation_confirmed"],
    "target_agent": "sqli_union",
}
```

But **no agent appends `ac_vertical_escalation_confirmed`** to `confirmed_vulns`. All access-control agents append `access_control_confirmed` (via `MODULE_TO_KG_NODE`). Therefore, this chain precondition is never satisfied and the edge is unreachable.

**Recommended fix:** Either:
- Update the AKG chain source to `access_control_confirmed`, OR
- Have `ac_vertical_escalation_agent` append `ac_vertical_escalation_confirmed` (and update `MODULE_TO_KG_NODE` and tests accordingly).

---

### W2. Massive code duplication across agents

**Files:** All 9 agent files

Every agent has identical boilerplate:
- Session setup (lines ~55-70)
- `already_tried` computation
- `make_update` return structure
- `_chain_check` function (exact same implementation in all 9 files)

**Recommended fix:** Extract `_chain_check` to `agents/state_utils.py` and provide a shared `run_agent_pipeline(session_factory, probe_fn, exploit_fn, chain_fn)` helper. This reduces the duplication surface where bugs can hide.

---

### W3. `sqli_boolean_blind` probe has redundant condition and unused import

**File:** `agents/sqli/sqli_boolean_blind_agent.py` (line 56)

```python
if "1=1" in payload or "1=1" in payload:
```

The `or` clause is identical — harmless but indicates copy-paste sloppiness.

Also, `Verifier` is imported but never used in this file.

**Recommended fix:** Remove the redundant `or` clause and unused import.

---

### W4. `ac_vertical_escalation_agent` probe always sends identical requests

**File:** `agents/access_control/ac_vertical_escalation_agent.py` (lines 50-58)

The probe iterates over `payloads` but always sends `userId=1` regardless of payload value. This sends N identical requests and wastes probe budget.

**Recommended fix:** Use the payload value as `userId`, or change the probe to send a single request.

---

### W5. `bf_dictionary` / `bf_spray` share ~95% identical code

**Files:** `agents/brute_force/bf_dictionary_agent.py`, `agents/brute_force/bf_spray_agent.py`

These two files are nearly identical. The only meaningful differences are default payloads and probe key prefixes. Maintaining both independently invites drift.

**Recommended fix:** Extract a shared `bf_agent_base` module with configurable defaults.

---

### W6. `make_update` does not merge `observations`

**File:** `agents/state_utils.py` (lines 131-175)

`make_update` handles scores, tried_payloads, confirmed_vulns, achieved_outcomes, found_credentials, attempted_agents, and telemetry_events — but **not observations**. Every agent manually patches `update["observations"] = observations` after calling `make_update`. This is error-prone and inconsistent.

**Recommended fix:** Add an `observations: dict[str, bool] | None = None` parameter to `make_update` and let it handle the merge logic (or at least include it in the returned dict).

---

### W7. Missing `failure_agents` / `blocked_agents` updates on internal errors

**Files:** All 9 agent files

When `session.login()` fails or session setup throws, agents return `score=0` but do **not** append themselves to `failure_agents`. The orchestrator/chaining coordinator relies on these lists for fallback logic. An agent that consistently fails (e.g., due to DVWA being down) will be retried indefinitely instead of being marked as failed.

**Recommended fix:** Return `failure_agents` update on error paths:
```python
return make_update(..., score=0, ...) | {"failure_agents": [AGENT_ID]}
```

---

### W8. `PayloadLibrary` bypass payloads for `ac_force_browse` are semantically wrong

**File:** `foundation/payload_library.py` (line 85-89)

```python
"ac_force_browse": PayloadSet(
    probe=["setup.php", "phpinfo.php"],
    exploit=["vulnerabilities/view_source.php", "security.php"],
    bypass={"medium": ["setup.php"], "high": ["setup.php"]},
),
```

The bypass payloads are just filenames without context (absolute vs relative, query params, etc.). Since the agent ignores them anyway, this is moot, but if fixed, the payloads need proper path semantics.

---

## Nitpick Issues

### N1. Unused `Verifier` imports

**Files:**
- `agents/sqli/sqli_boolean_blind_agent.py` — `Verifier` imported but never used
- `agents/sqli/sqli_time_blind_agent.py` — does not import `Verifier` (correct, since not needed)

### N2. Inconsistent `time` import aliasing

**Files:** `bf_dictionary_agent.py`, `bf_spray_agent.py`

Both import `time as time_mod` to avoid shadowing, but `sqli_time_blind_agent.py` imports `time` directly without aliasing. No actual shadowing occurs in any of these files, so the alias is unnecessary.

### N3. `ac_idor_agent` exploit re-tests baseline user ID

**File:** `agents/access_control/ac_idor_agent.py`

The probe skips `userId=1` to avoid false positives, but `_attempt_exploit` does not skip it. This means the exploit stage may "confirm" IDOR by accessing the admin's own data.

### N4. Missing docstrings on `_parse_credential`

**Files:** `bf_dictionary_agent.py`, `bf_spray_agent.py`

The helper `_parse_credential` has a docstring but no handling for empty password segments (returns `""` for both if no `:`).

---

## Test Coverage Gaps

The following scenarios are **not covered** by existing tests:

1. **Agent re-run with cached payloads** — no test verifies that `already_tried` skipping preserves prior observations.
2. **Medium/High security level adaptations** — all tests use `"low"`. Bypass payloads, comment styles, and token handling are untested.
3. **Network exception during PROBE/EXPLOIT** — exception paths log warnings but behavior is untested.
4. **`_chain_check` with newly confirmed local vuln** — tests pre-seed `confirmed_vulns` in state, masking the C1 bug.
5. **Real HTTP path resolution** — `ac_force_browse` mock tests pass because mocks intercept before path resolution, hiding the C3 bug.
6. **Rate limit threshold edge case** — `bf_dictionary` probe tests don't verify behavior at exactly 2.0s elapsed.
7. **Observation reducer overwrite** — no test asserts that `observations` reducer preserves True over False.
8. **Payload library empty-set fallback** — agents use `list(payload_set.probe) or [...]` defaults; no test verifies fallback behavior.

---

## Positive Findings

1. **Consistent pipeline structure** — All 9 agents follow the same PROBE -> EXPLOIT -> CHAIN CHECK pattern, making the codebase predictable.
2. **Proper state immutability** — Agents never mutate input state directly; they always return partial dicts.
3. **Telemetry coverage** — Every HTTP request emits a structured telemetry event via `probe_event` / `exploit_event`.
4. **Payload deduplication** — `make_update` and `merge_tried_payloads` correctly deduplicate against existing state.
5. **Defensive copying in PayloadLibrary** — `get()` returns fresh lists, preventing accidental mutation of the internal database.
6. **Score capping** — Agents use `score = max(score, N)` correctly to preserve the highest score reached across stages.
7. **LangGraph reducer compliance** — `confirmed_vulns`, `achieved_outcomes`, `found_credentials`, `attempted_agents`, and `telemetry_events` all correctly return only new items for `Annotated[..., add]` reducers.

---

## Recommended Priority Order

| Priority | Issue | Files | Effort |
|---|---|---|---|
| P0 | Fix `_chain_check` to include local confirmed vulns | All 9 agents | Low |
| P0 | Fix observation reducer or agent return logic | `core/state.py` + all agents | Low |
| P0 | Fix `ac_force_browse` paths and payload integration | `ac_force_browse_agent.py` | Low |
| P1 | Fix bf probe score on failure + caching bug | `bf_dictionary_agent.py`, `bf_spray_agent.py` | Medium |
| P1 | Fix dead AKG chain edge | `core/knowledge_graph.py` | Low |
| P2 | Extract shared `_chain_check` and pipeline runner | `agents/state_utils.py` + all agents | Medium |
| P2 | Deduplicate `bf_dictionary` / `bf_spray` | `agents/brute_force/` | Medium |
| P3 | Add tests for re-run, medium/high, network errors | `tests/` | High |
