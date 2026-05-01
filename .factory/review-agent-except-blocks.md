# Review: Agent `except Exception` Blocks — Stage 9C Changes

**Reviewer:** code-reviewer subagent (python-anti-patterns + python-design-patterns lenses)
**Date:** 2026-05-01
**Scope:** All 9 method agents + `make_update()` in `agents/state_utils.py` + consumers (`chaining_coordinator.py`, `scorer.py`, `orchestrator.py`)
**Change under review:** Adding `failure_agents=[AGENT_ID]` to the `except Exception` block in each agent's main function.

---

## Files Reviewed

| File | Lines | Role |
|---|---|---|
| `agents/sqli/sqli_union_agent.py` | 209 | Representative SQLi agent |
| `agents/access_control/ac_idor_agent.py` | 220 | Representative Access Control agent |
| `agents/brute_force/bf_dictionary_agent.py` | 257 | Representative Brute Force agent |
| `agents/state_utils.py` | 205 | `make_update()` with `failure_agents` param |
| `foundation/session_manager.py` | 307 | `DVWASession` login/close lifecycle |
| `core/chaining_coordinator.py` | 165 | `failure_agents` consumer |
| `core/scorer.py` | 167 | `failure_agents` consumer (adaptation metric) |
| All 6 remaining agents | — | Consistency verification (grep) |

---

## Finding 1: Bare `except Exception` Anti-Pattern

### 🟡 MEDIUM — `except Exception` is overly broad but intentional here

**Location:** Every agent, main function outer `try/except`. Example: `sqli_union_agent.py:191`, `ac_idor_agent.py:210`, `bf_dictionary_agent.py:248`.

```python
    except Exception as exc:
        logger.warning("[%s] Session or execution failed: %s", AGENT_ID, exc)
        return make_update(..., failure_agents=[AGENT_ID])
```

**Analysis (python-anti-patterns lens):**

Catching bare `Exception` is a well-documented Python anti-pattern. It catches:
- Programming bugs (`AttributeError`, `KeyError`, `NameError`, `TypeError`, `IndexError`)
- Runtime errors (`ValueError`, `ZeroDivisionError`, `FileNotFoundError`)
- External failures (`httpx.HTTPError`, `OSError`, `socket.timeout`)
- All of the above indiscriminately

However, this pattern **pre-existed Stage 9C** — the change only added `failure_agents=[AGENT_ID]`. The rationale is defensible: these are top-level agent entry points invoked by LangGraph, and any unhandled exception should be converted to a graceful state update rather than crashing the graph. The `logger.warning` preserves the trace.

**Risk:** Programming bugs (e.g., a typo in a variable name causing `NameError`) will be silently converted to `failure_agents` entries. A developer debugging a broken agent would see "Session or execution failed: name 'x' is not defined" in logs and the agent marked as failed, but might waste time investigating session/network issues before realizing it's a code bug.

**Recommendation:** Narrow the catch to known recoverable exceptions. At minimum, differentiate programming errors from operational failures:

```python
    except (httpx.HTTPError, OSError, RuntimeError, ValueError) as exc:
        # Operational failures — network, session, parsing
        logger.warning("[%s] Session or execution failed: %s", AGENT_ID, exc)
        return make_update(..., failure_agents=[AGENT_ID])
    except Exception as exc:
        # Unexpected programming errors — log at ERROR, still fail gracefully
        logger.error("[%s] Unexpected error: %s", AGENT_ID, exc, exc_info=True)
        return make_update(..., failure_agents=[AGENT_ID])
```

**Verdict:** Not a regression from Stage 9C. Worth fixing but out of scope for this specific change.

---

## Finding 2: Security Implications of Catching All Exceptions

### 🟢 LOW — No significant security implications

**Analysis:**

1. **No information leakage:** The `except` block only logs `AGENT_ID` and `str(exc)`. No response bodies, credentials, tokens, or session cookies are logged. This is correct.

2. **No credential exposure:** The `make_update()` return does not include `found_credentials`, `confirmed_vulns`, or `achieved_outcomes`. Only `score=0`, `tried_payloads=[]`, and `failure_agents=[AGENT_ID]`. This is correct.

3. **Resource cleanup is guaranteed:** `finally: session.close()` always executes, preventing socket leaks. See Finding 5 for a minor edge case.

4. **Silent failure masking:** While not a direct security vulnerability, catching all exceptions could mask an attacker-in-the-middle scenario (TLS verification failure) or a malformed response injection. These would be caught as generic `Exception` and logged without differentiation. Low severity in this context (DVWA is a local test target).

**Verdict:** No security regressions from Stage 9C. The `failure_agents` parameter doesn't change the security posture.

---

## Finding 3: Consistency Across All 9 Agents

### 🟢 LOW — Pattern is fully consistent

**Verification:** grep for `failure_agents=[AGENT_ID]` across the entire `agents/` directory:

| Agent | Line | Pattern |
|---|---|---|
| `sqli_union` | 193 | `failure_agents=[AGENT_ID]` |
| `sqli_error` | 205 | `failure_agents=[AGENT_ID]` |
| `sqli_boolean_blind` | 213 | `failure_agents=[AGENT_ID]` |
| `sqli_time_blind` | 217 | `failure_agents=[AGENT_ID]` |
| `ac_idor` | 214 | `failure_agents=[AGENT_ID]` |
| `ac_force_browse` | 199 | `failure_agents=[AGENT_ID]` |
| `ac_vertical_escalation` | 203 | `failure_agents=[AGENT_ID]` |
| `bf_dictionary` | 250 | `failure_agents=[AGENT_ID]` |
| `bf_spray` | 246 | `failure_agents=[AGENT_ID]` |

All 9 agents have the identical 3-line `except Exception` block:

```python
    except Exception as exc:
        logger.warning("[%s] Session or execution failed: %s", AGENT_ID, exc)
        return make_update(
            state=state, module_name=AGENT_ID, score=0, tried_payloads=[],
            failure_agents=[AGENT_ID],
        )
```

All 9 agents also have the identical `finally: session.close()` block immediately after.

**Verdict:** The pattern is perfectly consistent. The stage-9c implementation plan's checklist item "All 9 agents pass `failure_agents=[AGENT_ID]` in their except blocks" is satisfied.

---

## Finding 4: `session.login()` Failure Does NOT Add `failure_agents`

### 🔴 CRITICAL — Inconsistency between `session.login()` failure and `except Exception`

**Location:** All 9 agents. Representative: `sqli_union_agent.py:124-125`, `ac_idor_agent.py:145-146`, `bf_dictionary_agent.py:176-177`.

```python
    session = DVWASession(target_url)
    try:
        if not session.login():
            return make_update(state=state, module_name=AGENT_ID, score=0, tried_payloads=[])
        session.set_security_level(security_level)
        ...
    except Exception as exc:
        logger.warning("[%s] Session or execution failed: %s", AGENT_ID, exc)
        return make_update(
            state=state, module_name=AGENT_ID, score=0, tried_payloads=[],
            failure_agents=[AGENT_ID],
        )
    finally:
        session.close()
```

**The problem:**

There are two failure paths leaving the `try` block:

| Failure Path | Returns `failure_agents`? | Orchestrator sees it as failed? | Chaining coordinator fallback triggers? |
|---|---|---|---|
| `session.login()` returns `False` | **NO** | **NO** | **NO** |
| Any unhandled exception in `try` | YES | YES | YES |
| `if not target_url` (before `try`) | NO | NO | NO (correct — config error, not execution failure) |

When `session.login()` fails (wrong credentials, DVWA down, network error that is caught inside `login()` and returns `False`), the agent returns successfully with `score=0` but does **not** register itself in `failure_agents`. This has three concrete consequences:

1. **Orchestrator may re-select the agent.** The orchestrator's prompt receives `failure_agents={...}` (line 180 of `orchestrator.py`). If the agent isn't in the list, the orchestrator may attempt it again in a subsequent iteration — wasting budget and potentially causing an infinite loop.

2. **Chaining coordinator fallback doesn't trigger.** In `chaining_coordinator.py:93`, the fallback loop checks `elif last_agent in failure_agents`. If `session.login()` fails, `last_agent` won't be in `failure_agents`, so the coordinator won't redirect to the next unexplored method. It will return `"orchestrator"` instead, which may re-select the same agent.

3. **Scorer adaptation metric is wrong.** In `scorer.py:126`, `adapted = bool(state.get("failure_agents", [])) and best_score >= 3`. A login failure won't count toward adaptation, under-reporting the agent's resilience.

**Why this matters:** The `session.login()` failure is arguably the *most common* failure mode in real execution. If DVWA is down, ALL agents will fail at `session.login()` and none will be tracked as failures.

**Recommended fix:** Add `failure_agents=[AGENT_ID]` to the `session.login()` early return in all 9 agents:

```python
        if not session.login():
            return make_update(
                state=state, module_name=AGENT_ID, score=0, tried_payloads=[],
                failure_agents=[AGENT_ID],
            )
```

This makes the login-failure path symmetric with the exception-handling path. Both represent "the agent was dispatched, ran, and failed to execute."

**Verdict:** This is a genuine bug introduced by the Stage 9C implementation. The implementation plan says "In every agent's `except Exception` block, pass `failure_agents=[AGENT_ID]`" — but the `session.login()` failure is also an execution failure that should be tracked.

---

## Finding 5: `finally: session.close()` Edge Case

### 🟡 MEDIUM — `NameError` if `DVWASession()` constructor raises

**Location:** All 9 agents. Pattern:

```python
    session = DVWASession(target_url)
    try:
        ...
    except Exception as exc:
        ...
    finally:
        session.close()
```

**Analysis:**

If `DVWASession(target_url)` raises during construction (e.g., `target_url` is invalid, or memory allocation fails), the variable `session` is never bound, and `finally: session.close()` raises `NameError`. This `NameError` would propagate up through LangGraph, likely crashing the graph run.

However, this is an extreme edge case:
- `DVWASession.__init__` only calls `HTTPClient(base_url)` which is unlikely to fail
- `target_url` has a default of `"http://localhost/dvwa"` and is validated earlier (`if not target_url: return ...`)
- The constructor doesn't make network calls

**Existing test coverage:** The test file `test_state_utils.py` has tests for `failure_agents` deduplication and handling (lines 41-67) but no test for the `session` unbound edge case.

**Verdict:** Extremely unlikely in practice, but worth documenting. The `finally` block executes correctly for all normal execution paths (login success, login failure, exception, normal return).

---

## Finding 6: `make_update()` Deduplication Has a Subtle Logic Gap

### 🟢 LOW — `failure_agents` deduplication works correctly but edge case exists

**Location:** `agents/state_utils.py:197-202`

```python
    if failure_agents:
        existing_failures = set(state.get("failure_agents", []))
        new_failures = [a for a in failure_agents if a not in existing_failures]
        if new_failures:
            update["failure_agents"] = new_failures
```

**Analysis:**

This is correctly implemented. The deduplication uses a set for O(1) lookups and returns only new entries (since `failure_agents` uses `Annotated[list[str], add]` reducer in LangGraph). 

There is one edge case: if an agent is called multiple times and fails each time, only the first failure is recorded. This is arguably correct behavior (it only needs to be recorded once as "failed"), but it means the total `len(failure_agents)` does not reflect retry count. This is a design choice, not a bug.

**Verdict:** Implementation is correct and consistent with other reducers (`confirmed_vulns`, `achieved_outcomes`, `attempted_agents`).

---

## Summary of Findings

| # | Severity | Title | File(s) | Stage 9C Regression? |
|---|---|---|---|---|
| 1 | 🟡 MEDIUM | Bare `except Exception` anti-pattern | All 9 agents | No (pre-existing) |
| 2 | 🟢 LOW | No security implications | All 9 agents | No |
| 3 | 🟢 LOW | Pattern is fully consistent | All 9 agents | N/A (positive finding) |
| 4 | 🔴 CRITICAL | `session.login()` failure doesn't add `failure_agents` | All 9 agents | **Yes** |
| 5 | 🟡 MEDIUM | `NameError` edge case if `DVWASession()` constructor fails | All 9 agents | No (pre-existing) |
| 6 | 🟢 LOW | `make_update()` deduplication is correct | `state_utils.py` | N/A (positive finding) |

---

## Recommended Actions (Priority Order)

1. **🔴 CRITICAL — Fix `session.login()` failure path (Finding 4):** Add `failure_agents=[AGENT_ID]` to the `session.login()` early return in all 9 agents. This is a one-line change per agent and completes the Stage 9C implementation.

2. **🟡 MEDIUM — Narrow `except Exception` (Finding 1):** Differentiate programming errors from operational failures. Use `logger.error` with `exc_info=True` for unexpected exceptions. Can be done in a follow-up.

3. **🟡 MEDIUM — Guard `finally: session.close()` (Finding 5):** Wrap in `if 'session' in locals()` or initialize `session = None` before the assignment. Can be done in a follow-up.
