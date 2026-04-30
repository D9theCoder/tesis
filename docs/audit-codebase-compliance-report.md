# Codebase Compliance Audit Report

**Date:** 2026-04-29  
**Audited against:** `AGENTS.md` and `docs/summary.md`  
**Branch:** `stage-8-jailbreak`  
**Commit:** `e83b782`

---

## Executive Summary

This audit evaluates the entire `tesis` codebase against its own architectural specifications (`AGENTS.md`) and research design document (`docs/summary.md`).

**Overall grade:** Core infrastructure is solid (B+/A). The **single critical blocker** is that **all 9 method agents are non-functional stubs** — they log payloads but never send real HTTP requests to DVWA. Everything else (orchestrator, state management, AKG, foundation layer, LLM abstraction, CLI, tests) is implemented and working.

| Layer | Grade |
|---|---|
| Core infrastructure (state, graph, AKG, chaining, scoring) | B+ (minor deviations) |
| Orchestrator, evasion, config, CLI | A |
| Foundation (HTTP, session, payloads, verifier) | A |
| **Method agents (the actual exploit code)** | **F — all stubs** |
| Tests | A (342 passing) |

---

## 1. Compliant Areas

### 1.1 State Schema (`core/state.py`)

- All fields from `AGENTS.md` are present: `target_url`, `security_level`, `llm_provider`, `current_surface`, `endpoints`, `observations`, `confirmed_vulns`, `achieved_outcomes`, `found_credentials`, `tried_payloads`, `blocked_patterns`, `successful_bypasses`, `scores`, `current_chain`, `chain_history`, `messages`, `guardrail_activations`, `next_agent`, `iteration_count`, `max_iterations`, `task_result`, `incomplete_reason`.
- Telemetry extension `telemetry_events` is present.
- Evasion extensions (`evasion_enabled`, `evasion_mode`, `evasion_max_retries`, `evasion_cooldown_threshold`, `evasion_attempts`, `successful_evasions`) are present.
- New `model_config` field added for provider instantiation kwargs.

### 1.2 LangGraph Workflow (`core/graph_builder.py`)

- Correct node registration: `recon` -> `orchestrator` -> 9 method agents -> `chaining_router` -> `scorer` -> `END`.
- `route_from_orchestrator` routes to agent nodes or `scorer`.
- `route_from_chaining_router` routes to agents, `orchestrator`, or `scorer`.
- Thread ID pattern documented as `f"{provider}-{surface}-{level}"`.

### 1.3 Attack Knowledge Graph (`core/knowledge_graph.py`)

- `get_viable_methods(surface, observations)` implemented.
- `get_next_actions(node)` implemented.
- `check_preconditions(method_node, observations)` implemented.
- Cross-surface chains present:
  - `brute_force_confirmed` -> `ac_idor`
  - `sqli_confirmed` -> `credentials_extracted`
  - `credentials_extracted` -> `brute_force_confirmed`
  - `ac_vertical_escalation_confirmed` -> `sqli_union`

### 1.4 Chaining Coordinator (`core/chaining_coordinator.py`)

- `route_after_agent(state)` exists and returns routing decisions.
- Budget exhaustion check: `iteration_count >= max_iterations`.
- Cross-surface chain check iterates confirmed vulns and preconditions.
- Fallback loop for `BLOCKED` / `EXECUTION_FAILURE` present.
- Critical outcome check present.
- All-methods-exhausted -> `scorer` path present.

### 1.5 Orchestrator (`agents/orchestrator.py`)

- LLM-driven method selection over AKG (queries `kg.get_viable_methods`).
- No payload generation (only method selection).
- Returns partial state update dict.
- Handles guardrail refusals with fallback heuristic.
- Evasion pipeline integration (reactive/proactive modes).
- Deduplicates `attempted_agents` before prompt.

### 1.6 Foundation Layer

| File | Status | Detail |
|---|---|---|
| `foundation/session_manager.py` | Real (165+ lines) | `DVWASession` with `login()`, `set_security_level()`, `get()`, `post()` |
| `foundation/http_client.py` | Real (200+ lines) | `HTTPClient` wraps `httpx.Client` (sync), cookie pooling, timeout handling |
| `foundation/payload_library.py` | Real | `_PAYLOAD_DB` keyed by 9 method IDs, each with `probe`/`exploit`/`bypass` per `low`/`medium`/`high` |
| `foundation/verifier.py` | Real | `contains_any()`, `regex_match()`, Playwright XSS verifier (XSS out of scope) |
| `foundation/recon.py` | Real (460+ lines) | Crawls DVWA, extracts endpoints, derives observations |

### 1.7 LLM Abstraction (`llm/provider.py`)

- Supports `claude` (Anthropic), `openai` (GPT-4o), `gemini` (Google), `openai_compatible` (DeepSeek/Llama via compatible endpoints).
- `get_llm()` factory with provider-specific kwargs.
- `get_simulator_llm()` for evasion pipeline.
- `get_llm_from_model_config()` for typed config.

### 1.8 Evasion Pipeline (`llm/evasion/`)

- `llm/evasion/pipeline.py` implements a real LangGraph subgraph:
  - `generate_candidate` -> `check_compliance` -> `check_validity` -> `route_evasion` -> `finalize_success`/`finalize_fallback`.
- Template mutation strategies (5 different paraphrases).
- Compliance gate and validity gate with structured output.
- Fails open on simulator errors.
- `llm/evasion/deepteam_adapters.py` provides DeepTeam integration as secondary mechanism.

### 1.9 Prompt Files (`llm/prompts/`)

- `orchestrator_prompt.py` — method selection prompt.
- 9 per-method prompt files exist:
  - `sqli_union_prompt.py`, `sqli_error_prompt.py`, `sqli_boolean_blind_prompt.py`, `sqli_time_blind_prompt.py`
  - `ac_idor_prompt.py`, `ac_vertical_escalation_prompt.py`, `ac_force_browse_prompt.py`
  - `bf_dictionary_prompt.py`, `bf_spray_prompt.py`

### 1.10 Project Structure

Directory tree matches `docs/summary.md` Section 4 target structure with minor acceptable deviations (e.g., `pyproject.toml` instead of `requirements.txt`, `docs/summary.md` instead of root `summary.md`).

### 1.11 Tests

- 41 test files, 342 tests passing.
- Coverage: provider, config loader, state schema, knowledge graph, session manager, CLI, evasion pipeline, scorer, telemetry.

---

## 2. Partial / Non-Compliant Areas

### 2.1 Scorer Output Diverges from Spec

**File:** `core/scorer.py`

**Issue:** Returns a flat dict with `method_quality_metrics` and `surface_scores` (max integer per surface). `docs/summary.md` Section 5.6 pseudocode expects a nested `surface_scores` per surface containing `score`, `label`, `method_selected`, `attempts`, `akg_path`, `adapted`, plus a `summary` object.

**Impact:** Downstream report consumers may fail if they expect the documented structure.

### 2.2 Chain Precondition Check Too Broad

**File:** `core/chaining_coordinator.py:58`

**Issue:** `evaluate_chain_route` checks preconditions against `known = confirmed | achieved` instead of `state.confirmed_vulns` only. This allows achieved outcomes (not vulns) to satisfy chain preconditions, potentially triggering premature chains.

**Fix:** Change to check `edge["preconditions"]` against `state["confirmed_vulns"]` only.

### 2.3 AKG Missing Intermediate Chain Nodes

**File:** `core/knowledge_graph.py`

**Issue:** Several nodes from `docs/summary.md` Section 7 are missing or orphaned:

| Missing Item | Where Expected | Actual State |
|---|---|---|
| `unauthenticated` entry node | AKG root | Not present |
| `authenticated_session` node + edge | Chain: `brute_force_confirmed` -> `authenticated_session` -> `ac_idor` | Node absent; direct edge `brute_force_confirmed` -> `ac_idor` skips intermediate |
| `admin_session_obtained` edges | Chain: `ac_vertical_escalation_confirmed` -> `admin_session_obtained` -> `sqli_union` | Node exists but has no incoming/outgoing edges |

**Impact:** Chains work in practice (direct edges exist), but the intermediate semantic steps documented in the research are lost.

### 2.4 GuardrailMonitor is Free Functions, Not a Class

**File:** `llm/guardrail_monitor.py`

**Issue:** `docs/summary.md` Section 6.5 and `AGENTS.md` specify a `GuardrailMonitor` **class** with `self.log`, `check()`, `get_rate()`, `summary()`. Current file only has module-level free functions (`is_guardrail_refusal`, `make_guardrail_event`). No persistent log, no rate/summary methods.

**Impact:** Guardrail activations are logged as events in state but not tracked persistently per-provider for comparison metrics.

### 2.5 Legacy Prompt Stubs Polluting Namespace

**Files:** `llm/prompts/sqli_prompt.py`, `llm/prompts/idor_prompt.py`, `llm/prompts/brute_prompt.py`, `llm/prompts/sqli_blind_prompt.py`

**Issue:** These are 7-line legacy stubs with outdated signatures. They are superseded by per-method prompt files but still exported from `llm/prompts/__init__.py`. Agents importing from the package may accidentally use the wrong signature.

**Fix:** Remove legacy stubs and update `__init__.py` exports.

### 2.6 recon.py Returns `input_vectors` That State Drops — **Current Code is Correct, Spec is Outdated**

**File:** `foundation/recon.py:268, 287, 340`

**Observation:** `recon()` returns `"input_vectors": all_vectors`, but `ExploitationState` (`core/state.py`) does not define an `input_vectors` field, so LangGraph drops it.

**Why the current implementation is correct:** The `input_vectors` field is a leftover artifact from the **pre-supervisor broader scope** (all DVWA modules). When the supervisor narrowed the scope to **3 surfaces with deep-method evaluation**, `input_vectors` became unnecessary — the framework no longer needs a generic vector store across all modules. The current code correctly omits it from the state schema.

**Why the spec is outdated:** `docs/summary.md` Sections 5.1 and 5.2 still show `input_vectors` in pseudocode because the document was written before the scope refactor and was never fully updated to match the narrowed design.

**Verdict:** This is **not a compliance issue**. The current implementation is correct. The fix is to update `docs/summary.md` pseudocode to remove `input_vectors`, not to add it back to the code.

---

## 3. Critical Gaps — All 9 Method Agents Are Stubs

This is the single biggest blocker preventing the framework from performing real exploitation.

### 3.1 Summary of Violations

Every method agent violates the core **PROBE -> EXPLOIT -> CHAIN CHECK** contract from `AGENTS.md`:

| Violation | Evidence | Required by AGENTS.md |
|---|---|---|
| **No HTTP requests** | Zero imports of `httpx`, `DVWASession`, or `http_client` in any agent file | "Send observation request", "Try payloads" |
| **Fake PROBE stage** | `observations[key] = True` set unconditionally after merely iterating payloads locally | "Parse response to check preconditions" |
| **Fake EXPLOIT stage** | `exploit_triggered = True` after iterating one payload locally; score 3 granted if `security_level == "low"` | "Full success -> score=3" based on actual response |
| **Wrong AKG confirmed node IDs** | Append `sqli_union_confirmed` instead of `sqli_confirmed` | "Append confirmed AKG nodes to state.confirmed_vulns" |
| **Fake CHAIN CHECK** | `if score >= 3: achieved_outcomes.append(_CHAIN_OUTCOME); score = 4` — no AKG query | "Query AKG for chain edges from newly confirmed node" |
| **No BaseAgent inheritance** | All agents are free functions, not classes | "Inherits from BaseAgent in agents/base_agent.py" |
| **Fake found_credentials** | `bf_dictionary` splits payload string on `:` to create credentials, not from HTTP response | Real login success from DVWA response |

### 3.2 Agent-Specific Issues

#### SQLi Agents

| Agent | Wrong Confirmed Node | Wrong Chain Outcome |
|---|---|---|
| `sqli_union_agent.py` | `sqli_union_confirmed` -> should be `sqli_confirmed` | `credentials_extracted` (correct) |
| `sqli_error_agent.py` | `sqli_error_confirmed` -> should be `sqli_confirmed` | `credentials_extracted` (correct) |
| `sqli_boolean_blind_agent.py` | `sqli_boolean_blind_confirmed` -> should be `blind_sqli_confirmed` | `data_exfiltrated` -> should be `credentials_extracted` |
| `sqli_time_blind_agent.py` | `sqli_time_blind_confirmed` -> should be `blind_sqli_confirmed` | `data_exfiltrated` -> should be `credentials_extracted` |

#### Access Control Agents

| Agent | Wrong Confirmed Node | Wrong Chain Outcome |
|---|---|---|
| `ac_idor_agent.py` | `ac_idor_confirmed` -> should be `access_control_confirmed` | `data_exfiltrated` -> should be `ac_vertical_escalation_confirmed` or `authenticated_session` |
| `ac_vertical_escalation_agent.py` | `ac_vertical_escalation_confirmed` -> should be `access_control_confirmed` | `sqli_union_chain_enabled` -> should be `sqli_union` (agent name) |
| `ac_force_browse_agent.py` | `ac_force_browse_confirmed` -> should be `access_control_confirmed` | `data_exfiltrated` -> no defined chain |

#### Brute Force Agents

| Agent | Wrong Confirmed Node | Wrong Chain Outcome |
|---|---|---|
| `bf_dictionary_agent.py` | `bf_dictionary_confirmed` -> should be `brute_force_confirmed` | `brute_force_confirmed` -> should be `authenticated_session` |
| `bf_spray_agent.py` | `bf_spray_confirmed` -> should be `brute_force_confirmed` | `brute_force_confirmed` -> should be `authenticated_session` |

### 3.3 Root Cause

The Stage 5 implementation plan (`docs/stage-5-vulnerability-agents.implementation-plan.md`) explicitly required real HTTP execution via `DVWASession`:

> "execute probes/exploits via DVWASession" (line 109)

However, the implementing AI agent wrote **scaffold templates** (copy-paste with only string constants changed) and never filled in the actual per-method HTTP and response-parsing logic. The `docs/experiment-fixes.implementation-plan.md` later identified this as **Bug 2** but was only partially implemented (telemetry + loop fixes, not HTTP wiring).

**All 9 agent files share the identical stub template with only constants swapped.** Evidence from any one file applies to all.

### 3.4 What Needs to Be Implemented

Per `AGENTS.md` and `docs/summary.md` Section 6.2-6.4, each agent must:

1. **Import and use `DVWASession`** from `foundation/session_manager`
2. **PROBE stage**: Send payloads via `session.get()`/`post()`, parse response for precondition signals (error messages, response diffs, time delays, etc.)
3. **EXPLOIT stage**: Send exploit payloads, parse response for success indicators (extracted data, unauthorized access, login success page, etc.)
4. **CHAIN CHECK stage**: Instantiate `AttackKnowledgeGraph`, call `kg.get_next_actions()`, verify preconditions, append chain outcome if met
5. **Return correct AKG node IDs**: `sqli_confirmed`, `blind_sqli_confirmed`, `access_control_confirmed`, `brute_force_confirmed`
6. **Return correct chain outcomes**: `credentials_extracted`, `authenticated_session`, `admin_session_obtained`, `ac_vertical_escalation_confirmed`

---

## 4. Recommendations

### Priority 1: Rewrite All 9 Method Agents (Blocking)

This is the only item preventing the framework from being functional. Options:

- **Option A:** Write raw exploit scripts manually, then convert to agent format.
- **Option B:** Keep existing file structure and replace stub logic with real HTTP calls (faster — the scaffold is already there).

The foundation layer (`DVWASession`, `HTTPClient`, `PayloadLibrary`, `Verifier`) is fully implemented and ready to be used.

### Priority 2: Fix AKG Node IDs and Chain Outcomes

Update all 9 agents to use the correct `confirmed_vulns` node IDs that match the AKG graph, and correct `_CHAIN_OUTCOME` constants.

### Priority 3: Add `input_vectors` to State Schema or Remove from recon

Either:
- Add `input_vectors: list[dict]` to `ExploitationState`, or
- Remove `"input_vectors"` from `recon()` return value.

### Priority 4: Convert GuardrailMonitor to a Class

Implement `GuardrailMonitor` class per `docs/summary.md` Section 6.5 with persistent `self.log`, `get_rate()`, and `summary()` methods.

### Priority 5: Remove Legacy Prompt Stubs

Delete `sqli_prompt.py`, `idor_prompt.py`, `brute_prompt.py`, `sqli_blind_prompt.py` and update `llm/prompts/__init__.py`.

### Priority 6: Align Scorer Output with Spec

Refactor `core/scorer.py` to return nested `surface_scores` + `summary` per `docs/summary.md` Section 5.6 pseudocode.

### Priority 7: Tighten Chain Precondition Check

In `core/chaining_coordinator.py`, check chain preconditions against `state["confirmed_vulns"]` only, not `confirmed | achieved`.

---

## Appendix A: Checklist from AGENTS.md

| # | Rule | Status |
|---|---|---|
| 1 | Inherits from `BaseAgent` in `agents/base_agent.py` | FAIL — all 9 agents are free functions |
| 2 | Accepts `ExploitationState`, returns partial state update dict | PASS |
| 3 | Reads `state.tried_payloads` before sending payloads | PASS (reads, but never actually sends) |
| 4 | Writes tried payloads to `state.tried_payloads[agent_id]` | PASS |
| 5 | Updates `state.scores[agent_id]` with highest score | PASS (but score is fake) |
| 6 | Appends confirmed AKG nodes to `state.confirmed_vulns` | PARTIAL (wrong node IDs) |
| 7 | Returns `{observations}` updates from PROBE stage | PASS (but observations are fake) |
| 8 | Node registered in `core/graph_builder.py` | PASS |
| 9 | Conditional edge in `core/chaining_coordinator.py` | PASS |
| 10 | Prompt file in `llm/prompts/` | PASS |
| 11 | No inline LLM payload generation | PASS |
| 12 | No direct state mutation | PASS |
| 13 | No emojis | PASS |

---

## Appendix B: Files Audited

### Core Infrastructure
- `core/state.py`
- `core/graph_builder.py`
- `core/knowledge_graph.py`
- `core/chaining_coordinator.py`
- `core/scorer.py`

### Agents
- `agents/base_agent.py`
- `agents/orchestrator.py`
- `agents/state_utils.py`
- `agents/agent_telemetry.py`
- `agents/sqli/sqli_union_agent.py`
- `agents/sqli/sqli_error_agent.py`
- `agents/sqli/sqli_boolean_blind_agent.py`
- `agents/sqli/sqli_time_blind_agent.py`
- `agents/access_control/ac_idor_agent.py`
- `agents/access_control/ac_vertical_escalation_agent.py`
- `agents/access_control/ac_force_browse_agent.py`
- `agents/brute_force/bf_dictionary_agent.py`
- `agents/brute_force/bf_spray_agent.py`

### Foundation
- `foundation/session_manager.py`
- `foundation/recon.py`
- `foundation/http_client.py`
- `foundation/payload_library.py`
- `foundation/verifier.py`

### LLM
- `llm/provider.py`
- `llm/guardrail_monitor.py`
- `llm/evasion/pipeline.py`
- `llm/evasion/deepteam_adapters.py`
- `llm/prompts/orchestrator_prompt.py`
- `llm/prompts/sqli_union_prompt.py`
- `llm/prompts/sqli_error_prompt.py`
- `llm/prompts/sqli_boolean_blind_prompt.py`
- `llm/prompts/sqli_time_blind_prompt.py`
- `llm/prompts/ac_idor_prompt.py`
- `llm/prompts/ac_vertical_escalation_prompt.py`
- `llm/prompts/ac_force_browse_prompt.py`
- `llm/prompts/bf_dictionary_prompt.py`
- `llm/prompts/bf_spray_prompt.py`
- `llm/prompts/sqli_prompt.py` (legacy stub)
- `llm/prompts/idor_prompt.py` (legacy stub)
- `llm/prompts/brute_prompt.py` (legacy stub)
- `llm/prompts/sqli_blind_prompt.py` (legacy stub)

### CLI / Config / Evaluation
- `tesis/cli.py`
- `tesis/config_loader.py`
- `tesis/model_config.py`
- `evaluation/runner.py`
- `evaluation/multi_llm_runner.py`
- `evaluation/metrics.py`
- `evaluation/reporter.py`

---
