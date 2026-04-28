# Stage 8.2 Dependency Mapping Report

**Generated:** 2026-04-28  
**Task:** Map dependencies for Stage 8.2 changes across 16 files (12 modify, 4 create)

---

## Category
**New Feature + Infrastructure** — Progress reporting, enhanced telemetry, validation layers, and test coverage for orchestrator fallback and evasion effectiveness.

---

## Files to Read

| File | Key Symbols | Relevance |
|------|-------------|-----------|
| `llm/prompts/orchestrator_prompt.py` | `build_orchestrator_prompt` | Core prompt builder consumed by orchestrator; defines LLM interface contract |
| `llm/provider.py` | `get_llm`, `get_simulator_llm`, `get_llm_from_model_config`, `ModelConfig` | LLM provider abstraction; simulator model used by evasion layer |
| `tesis/model_config.py` | `ModelConfig`, `EngagementConfig`, `EVASION_STRATEGIES` | Typed configuration schema; evasion strategy constants |
| `tesis/config_loader.py` | `load_and_resolve_config`, `ConfigError`, `_parse_model_configs` | Config validation; merges YAML/env/CLI; parses simulator model config |
| `config.yaml` | `models.simulator`, `evasion_enabled`, `evasion_strategy`, `max_concurrency` | Runtime configuration; simulator model for DeepTeam attacks |
| `agents/orchestrator.py` | `orchestrator`, `KG_NODE_TO_AGENT`, `_fallback_next_agent`, `build_evasion_graph` | Central orchestrator with evasion integration; fallback logic; telemetry emission |
| `llm/evasion/pipeline.py` | `EvasionState`, `build_evasion_graph`, `generate_candidate`, `check_compliance`, `check_validity` | LangGraph evasion subgraph; compliance/validity gates |
| `llm/evasion/deepteam_adapters.py` | `enhance_with_deepteam`, `normalize_strategy`, `_build_deepeval_model`, `max_concurrency` | DeepTeam attack integration; concurrency control |
| `core/state.py` | `ExploitationState`, `MODULE_NAMES`, `DEFAULT_STATE`, `new_default_state` | Shared state schema; all agents read/write this contract |
| `agents/state_utils.py` | `make_update`, `merge_scores`, `merge_tried_payloads`, `prepare_agent_session` | Shared state mutation helpers; ensures immutability pattern |
| `agents/base_agent.py` | `BaseAgent`, `enhance_prompt` | Abstract base class; evasion enhancement helper for all agents |
| `agents/tier2/upload_agent.py` | `UploadAgent`, `upload_agent` | Tier 2 agent; example of state mutation via `make_update` |
| `agents/tier1/cmdi_agent.py` | `CommandInjectionAgent`, `cmdi_agent` | Tier 1 agent; pattern for all vulnerability agents |
| `agents/tier1/sqli_agent.py` | `SQLiAgent`, `sqli_agent` | Tier 1 agent; chain enablement via `credentials_extracted` |
| `evaluation/runner.py` | `run_single_engagement`, `RunTelemetry` | Single engagement runner; telemetry collection; evasion config passthrough |
| `evaluation/telemetry.py` | `RunTelemetry`, `TelemetryEvent`, `stable_sha256` | Telemetry event schema; JSONL serialization |

---

## Files to Modify

| File | What to Change | Symbols Affected |
|------|----------------|------------------|
| `llm/prompts/orchestrator_prompt.py` | Add telemetry tracking context to prompt (optional); document stop policy enforcement | `build_orchestrator_prompt` |
| `llm/provider.py` | Add simulator model concurrency parameter passthrough; enhance error logging | `get_simulator_llm`, `get_llm_from_model_config` |
| `tesis/model_config.py` | Add `progress_report_interval`, `telemetry_enabled` fields to `EngagementConfig` | `EngagementConfig`, `EVASION_STRATEGIES` |
| `tesis/config_loader.py` | Parse new progress/telemetry config fields; validate intervals | `_parse_model_configs`, `_validate_engagement_config`, `load_and_resolve_config` |
| `config.yaml` | Add `progress_report_interval`, `telemetry_enabled` defaults | N/A (YAML config) |
| `agents/orchestrator.py` | Integrate progress reporter; enhance telemetry events with evasion metrics; improve fallback logging | `orchestrator`, `_fallback_next_agent`, telemetry event emission |
| `llm/evasion/pipeline.py` | Add telemetry events to evasion state; track gate failures | `EvasionState`, `generate_candidate`, `check_compliance`, `check_validity` |
| `core/state.py` | Add `progress_reporter_state`, `telemetry_enabled` to `ExploitationState` | `ExploitationState`, `new_default_state` |
| `agents/state_utils.py` | Add telemetry event merging helper | `make_update` (add telemetry_events merge) |
| `agents/base_agent.py` | Enhance `enhance_prompt` to capture telemetry; add validation hooks | `BaseAgent.enhance_prompt`, new `validate_prerequisites` hook |
| `agents/tier2/upload_agent.py` | Add telemetry event emission for upload attempts/results | `upload_agent.run` |
| `agents/tier1/cmdi_agent.py` | Add telemetry event emission for command injection attempts | `cmdi_agent.run` |
| `agents/tier1/sqli_agent.py` | Add telemetry event emission for SQLi probes; credential extraction tracking | `sqli_agent.run` |
| `evaluation/runner.py` | Wire progress reporter; ensure telemetry persistence across repeats | `run_single_engagement` |
| `tesis/cli.py` | Add CLI flags for progress/telemetry; display progress during runs | `handle_run`, `build_parser` |
| `pyproject.toml` | Add optional dependencies for progress reporting (e.g., `rich` enhancements) | N/A (dependencies) |

---

## Files to Create

| File | Purpose | Must Implement |
|------|---------|-----------------|
| `tesis/progress_reporter.py` | Real-time progress tracking during engagement runs | `EngagementProgressReporter` class with methods: `__init__`, `update`, `render_progress`, `write_summary`; integration with `rich` or `tqdm`; thread-safe event buffering |
| `tests/test_orchestrator_fallback.py` | Test orchestrator fallback under various failure modes | Tests for: LLM unavailability, guardrail refusals, evasion failures, chain precondition failures, budget exhaustion |
| `tests/test_evasion_effectiveness.py` | Measure evasion success rates across strategies | Tests for: strategy normalization, DeepTeam integration, compliance gate bypass rates, validity gate accuracy, concurrency control |
| `tests/test_agent_telemetry.py` | Validate telemetry event emission from agents | Tests for: event schema conformance, monotonic sequencing, JSONL serialization, state event merging |
| `tests/test_agent_validation.py` | Test agent input validation and error handling | Tests for: state validation, payload validation, session preparation failures, timeout handling |

---

## Test Files (Already Exist)

| Test File | Covers | Depends On |
|-----------|--------|------------|
| `tests/test_orchestrator.py` | Orchestrator decision logic, fallback, guardrail detection | `agents/orchestrator.py`, `core/state.py` |
| `tests/test_evasion_pipeline.py` | Evasion subgraph, compliance/validity gates | `llm/evasion/pipeline.py` |
| `tests/test_evasion_integration.py` | End-to-end evasion integration with config | `llm/evasion/`, `tesis/config_loader.py` |
| `tests/test_deepteam_adapters.py` | DeepTeam adapter layer | `llm/evasion/deepteam_adapters.py` |
| `tests/test_state.py` | State schema, reducers, defaults | `core/state.py` |
| `tests/test_reporting_telemetry.py` | Telemetry event serialization | `evaluation/telemetry.py` |
| `tests/test_base_agent.py` | Base agent contract | `agents/base_agent.py` |
| `tests/test_state_utils.py` | State mutation helpers | `agents/state_utils.py` |
| `tests/test_tier1_agents.py` | Tier 1 agent pipelines | `agents/tier1/*.py` |
| `tests/test_tier2_agents.py` | Tier 2 agent pipelines | `agents/tier2/*.py` |
| `tests/test_runner.py` | Engagement runner | `evaluation/runner.py` |
| `tests/test_config_loader.py` | Config parsing/validation | `tesis/config_loader.py` |
| `tests/test_cli.py` | CLI interface | `tesis/cli.py` |

---

## Shared Contracts & Interfaces

| Contract | Location | Direction |
|----------|----------|-----------|
| `ExploitationState` | `core/state.py` | **Consumed & Produced** — All agents read/write this schema |
| `ModelConfig` | `tesis/model_config.py` | **Consumed** — Config loader produces; LLM provider consumes |
| `EngagementConfig` | `tesis/model_config.py` | **Consumed** — Config loader produces; CLI/runner consume |
| `EvasionState` | `llm/evasion/pipeline.py` | **Consumed & Produced** — Evasion subgraph internal state |
| `TelemetryEvent` | `evaluation/telemetry.py` | **Produced** — Runner/orchestrator produce; JSONL writer consumes |
| `RunTelemetry` | `evaluation/telemetry.py` | **Produced** — Runner accumulates; reporter consumes |
| `BaseAgent` | `agents/base_agent.py` | **Consumed** — All vulnerability agents inherit |
| `make_update` | `agents/state_utils.py` | **Consumed** — All agents use for state mutation |

---

## Dependency Chain

```
config.yaml
    ↓ (parsed by)
tesis/config_loader.py
    ↓ (produces)
tesis/model_config.py (EngagementConfig, ModelConfig)
    ↓ (consumed by)
tesis/cli.py ←→ evaluation/runner.py
    ↓ (initializes)
core/state.py (ExploitationState)
    ↓ (consumed by)
agents/orchestrator.py
    ↓ (invokes)
llm/evasion/pipeline.py (EvasionState)
    ↓ (uses)
llm/evasion/deepteam_adapters.py
    ↓ (calls)
llm/provider.py (get_simulator_llm)
    ↓ (returns to)
agents/orchestrator.py
    ↓ (emits events to)
evaluation/telemetry.py (RunTelemetry)
    ↓ (serialized by)
evaluation/reporter.py

agents/base_agent.py
    ↓ (inherited by)
agents/tier1/*.py, agents/tier2/*.py
    ↓ (use helpers from)
agents/state_utils.py
    ↓ (read/write)
core/state.py (ExploitationState)
```

---

## Import Cycles Analysis

**No circular imports detected.** The dependency graph is acyclic:

```
tesis/ (config, CLI)
    ↓
core/ (state, graph)
    ↓
agents/ (base, utils, tier1/2/3)
    ↓
foundation/ (http, session, payloads)
    
llm/ (provider, evasion)
    ↑ (called by agents and orchestrator, no reverse deps)
```

**Key observation:** `core/state.py` is the central contract — imported by virtually everything but imports nothing from `agents/` or `llm/`, preventing cycles.

---

## Breaking Changes Risk Areas

### HIGH RISK
1. **`ExploitationState` schema changes** (`core/state.py`)
   - Adding required fields breaks all agents
   - **Mitigation:** Use `NotRequired` for optional fields; provide defaults in `new_default_state()`

2. **`make_update` signature** (`agents/state_utils.py`)
   - All 12+ agents call this function
   - **Mitigation:** Use `**kwargs` for new optional parameters; maintain backward compatibility

3. **`EngagementConfig` fields** (`tesis/model_config.py`)
   - Config loader and CLI both depend on this schema
   - **Mitigation:** Add defaults; make fields optional with `field(default_factory=...)`

### MEDIUM RISK
4. **Orchestrator telemetry event schema** (`agents/orchestrator.py`)
   - Report formatters parse these events
   - **Mitigation:** Add new event types; don't remove existing ones

5. **EvasionState fields** (`llm/evasion/pipeline.py`)
   - Orchestrator invokes evasion graph with specific keys
   - **Mitigation:** Use `.get(key, default)` pattern; avoid direct dict access

6. **`get_simulator_llm` parameters** (`llm/provider.py`)
   - Called by evasion adapters and orchestrator
   - **Mitigation:** Use `**kwargs`; document new parameters

### LOW RISK
7. **Prompt builder signature** (`llm/prompts/orchestrator_prompt.py`)
   - Only called by orchestrator
   - **Mitigation:** Coordinate changes in same PR

8. **Test helper signatures** (`tests/*.py`)
   - Internal to test suite
   - **Mitigation:** Update tests alongside implementation

---

## Missing Files Referenced

| Referenced File | Expected Location | Status |
|-----------------|-------------------|--------|
| `tesis/progress_reporter.py` | `tesis/progress_reporter.py` | **MISSING** — Referenced in `docs/stage-8.2-evasion-fix.md` line 652 |
| `tests/test_orchestrator_fallback.py` | `tests/test_orchestrator_fallback.py` | **MISSING** — Requested for creation |
| `tests/test_evasion_effectiveness.py` | `tests/test_evasion_effectiveness.py` | **MISSING** — Requested for creation |
| `tests/test_agent_telemetry.py` | `tests/test_agent_telemetry.py` | **MISSING** — Requested for creation |
| `tests/test_agent_validation.py` | `tests/test_agent_validation.py` | **MISSING** — Requested for creation |

---

## Warnings

### Breaking Change Risks
- **`ExploitationState` modifications require careful defaults** — Any agent that doesn't get updated will break if required fields are added without defaults
- **Telemetry event schema is parsed by report formatters** — Adding new event types is safe; removing or renaming existing types breaks reports

### Ordering Constraints
1. **Create `tesis/progress_reporter.py` first** — Orchestrator and CLI depend on it
2. **Update `core/state.py` before agents** — Agents import state schema
3. **Update `tesis/model_config.py` before `tesis/config_loader.py`** — Config loader imports config types
4. **Create test files after implementation** — Tests import the modules they test

### Missing Dependencies
- **`rich` library** — May need to be added to `pyproject.toml` for progress reporting (check if already installed)
- **`deepteam`** — Already in `pyproject.toml` but is optional at runtime; ensure graceful fallback

### Backwards Compatibility Issues
- **CLI flags** — New flags must be optional with sensible defaults to avoid breaking existing scripts
- **Config YAML** — New config fields must be optional; old configs without them must still work
- **Test suite** — Existing tests must continue to pass; new tests should be additive

### Special Considerations
- **Concurrency control in `deepteam_adapters.py`** — Uses global semaphore; thread-safe but requires careful initialization
- **Evasion strategy normalization** — Multiple aliases supported (`prompt-injection`, `prompt_injection`, `Prompt Injection`)
- **Simulator model config** — Can come from `models.simulator` or fall back to `models.openai`; ensure precedence is documented

---

## Recommended Implementation Order

1. ✅ **Create `tesis/progress_reporter.py`** — Foundation for progress tracking
2. ✅ **Update `core/state.py`** — Add new state fields with defaults
3. ✅ **Update `tesis/model_config.py`** — Add config fields
4. ✅ **Update `tesis/config_loader.py`** — Parse new config
5. ✅ **Update `config.yaml`** — Add defaults
6. ✅ **Update `agents/base_agent.py`** — Add validation hooks
7. ✅ **Update `agents/state_utils.py`** — Telemetry merging
8. ✅ **Update agents (`upload`, `cmdi`, `sqli`)** — Add telemetry emission
9. ✅ **Update `llm/evasion/pipeline.py`** — Telemetry tracking
10. ✅ **Update `agents/orchestrator.py`** — Wire progress reporter, enhance telemetry
11. ✅ **Update `evaluation/runner.py`** — Progress reporter integration
12. ✅ **Update `tesis/cli.py`** — CLI flags, progress display
13. ✅ **Update `pyproject.toml`** — Dependencies if needed
14. ✅ **Create test files** — Comprehensive test coverage
15. ✅ **Update `llm/prompts/orchestrator_prompt.py`** — Documentation only
16. ✅ **Update `llm/provider.py`** — Minor enhancements

---

## Summary

**Total Files Analyzed:** 16  
**Existing Test Files Found:** 12 (covering core modules)  
**Files to Create:** 5 (progress reporter + 4 test files)  
**Circular Dependencies:** None detected  
**High-Risk Breaking Changes:** 3 (state schema, `make_update`, config schema)  
**Recommended Order:** Sequential (state → config → agents → orchestrator → tests)

All dependencies are well-structured with clear separation of concerns. The central `ExploitationState` contract in `core/state.py` is the critical integration point — all changes must maintain backward compatibility with this schema.
