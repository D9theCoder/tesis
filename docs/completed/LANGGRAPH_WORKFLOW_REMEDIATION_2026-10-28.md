# LangGraph workflow remediation, 2026-10-28

Status: all nine findings and four optimization opportunities implemented, with all three subsequent review findings corrected. Current review-fix acceptance includes focused checks, mocked replay/chain E2E, and one live saved-input replay. Initial live DVWA/River AI and browser acceptance belongs to the earlier source epoch described below. Implementation and review acceptance are complete in both repositories.

The largest risks are accumulated state crossing execution boundaries, validation history controlling later execution queues, and configuration that does not reach routing decisions. The compiled topology itself follows the documented stages.

The original review inspected the checkout at TESIS `9a08554a895bf84e90641bc8dab62a32236d593c` and TESIS Web `c28f7fcf0fce8b5bbe12d6a0a859db64e0940942`, installed LangGraph 1.2.1, existing tests, and official documentation. The findings below preserve that baseline and its original line references. The implementation and acceptance evidence added afterwards are recorded here.

## Delivered behavior

| Finding | Resolution |
| --- | --- |
| F01 | Fresh durable executions use unique graph threads; metadata keeps the coordinate-to-thread binding for explicit resume. |
| F02 | Versioned coordinate fingerprints include effective role/model settings, retry limits, scoring inputs, fixture, protocol and workflow version. |
| F03 | Validation receipts are scoped to method visits; the current ordered accepted IDs live in `active_payload_candidates` and control routing/execution. |
| F04 | Shared policy implements impact and fixed-denominator method coverage stopping, including a zero coverage target. |
| F05 | Resume restores call receipts and sequence identity without new provider events or requests; deterministic infeasibility preserves its own stop reason. |
| F06 | Automatic selection excludes exhausted, blocked and failed methods. Preparation failure is recorded and cannot immediately select the same chain again. |
| F07 | Both routing paths share condition-aware deterministic fallback. |
| F08 | Every selection reserves one method visit, including chains and fallback; execution does not charge twice. |
| F09 | The graph retains scorer report fields and the runner preserves the enriched output. |
| O01 | Chain preflight checks destination viability, supported consumption adapters, and route-bound source material; plaintext-derived pairs pass the normal validator and budget. |
| O02 | Runtime consumers reuse a frozen prevalidated AKG with independent profile copies. |
| O03 | Durable checkpoints store audit entries once in an adjacent content-addressed store and verify/restore them; frozen method inputs avoid an extra deep copy. |
| O04 | Conditional route domains are explicit through literal types and a validator route map. |

A further acceptance finding was fixed: completed replay writes a `checkpoint-resume.v1` receipt rather than another primary run artifact with the same execution ID. Both TESIS and TESIS Web catalogs exclude `.resume.json` sidecars. This preserves original primary bytes and prevents source-identity ambiguity.

TESIS Web validates the optional `workflow.v2` object, shows method visits, method coverage, stop policy and stop reason in completed results and live journal views, keeps child progress out of matrix parents, and rejects inconsistent progress without inventing values. Legacy artifacts retain legacy iteration interpretation. Projection export/import also carries the optional contract. The shared configuration field now labels the budget as **Method visits** in both clients.

## Initial acceptance evidence

All generated evidence is under `results/validation/workflow-remediation/`.

| Scope | Result | Receipt |
| --- | --- | --- |
| Selected Python checks, including offline graph continuations | 294 distinct selected testcases passed, using the latest acceptance receipt for each; no full suite | `python-checks-summary.json` and its listed JUnit files |
| Focused saved-input/routing E2E | 12 passed, 258 deselected; all transport and providers mocked | `offline-e2e.xml`, `offline-e2e.log`, `offline/` |
| TESIS Web tests | 51 passed across workflow, artifact, results, live-shell and metrics files; 29 passed in resolver/workflow follow-up, with 6 overlapping workflow checks | `web/tests.log`, `web/resolver-tests.log` |
| TESIS Web static/build checks | Typecheck passed; final webpack build passed; lint passed with the two existing unused-symbol warnings in `lib/formatters.ts` | `web/typecheck.log`, `web/lint.log`, `web/build-final.log` |
| Live DVWA and provider E2E | Eight completed executions, 12 River AI logical model calls, no failed executions or scope-violation events | `live/manifest.json`, `live/acceptance.json`, individual run artifacts and event sidecars |
| Checkpoint live controls | Fresh threads isolated, completed replay uses zero new nodes/calls, changed coverage configuration refused | `live/acceptance.json` |
| Browser with real saved live artifacts | Artifact API 200; desktop/mobile result fields and live-journal progress passed; no browser errors | `browser-acceptance.json`, `web-results-desktop.png`, `web-results-mobile.png`, `web-live-journal.png` |
| Serialized checkpoint volume | 18 checkpoints: 601,012 expanded channel bytes versus 411,208 stored channel/audit bytes, a 31.6% reduction | `checkpoint-size.json` |

The size comparison excludes SQLite metadata, pending-write storage and filesystem overhead. It establishes serialized storage reduction, not lower latency.

Live scope was DVWA at `http://172.19.48.1/dvwa`, security level low, hybrid payloads, generated-candidate budget one, and one reserved method visit per run. The two additional coverage checks allowed two visits and stopped after one at `coverage_target_reached`. Only the River AI profile `river-ai__deepseek-ai-deepseek-v4-1-flash-1017_15efb2abf693`, model `deepseek-ai/DeepSeek-V4.1-Flash-1017`, endpoint host `api.river.ai` was used. Final score review was left to human review; no independent AI-evaluator calls were made.

Six SQLi executions were confirmed. Access Control and Brute Force remained `fixture_limited` because independent oracle evidence was unavailable. All eight execution lifecycles completed. Five external navigation links per recon were discarded and recorded as `discarded_navigation`; no request followed them. These are containment telemetry, not executed scope violations.

Commands used the existing runner/artifact writer through:

```bash
PYTHONPATH=. .venv/bin/python results/validation/workflow-remediation/run_live.py
node results/validation/workflow-remediation/browser.cjs
```

The live script saves its declared case/config scope before execution and reuses completed artifacts rather than replaying provider calls. The first six runs preceded the completed-resume receipt publication fix in `evaluation/runner.py`; the two coverage runs and final replay controls followed it. That change affects the completed-replay branch, so the earlier fresh-execution evidence was reused. The manifest hashes describe the final acceptance invocation, not each historical execution; the pre-fix runner hash was not retained. `source_epoch_evidence` records this limitation. Focused resume/catalog checks and zero-call replay controls passed after the fix. Initial acceptance-script assertion failures remain in diagnostic receipts; the final acceptance files identify the passing scope. The browser server used port 3189 with controls disabled and only the generated live artifact root configured. It was stopped after validation.

## Review follow-up

Three regressions identified by review were reproduced by source tracing and corrected:

| Review finding | Resolution |
| --- | --- |
| R1: replay loses validation visit ownership | Revalidated receipts retain the saved active visit ID. The validation reducer preserves earlier-visit receipt indices, subset replay narrows only active IDs, and unvalidated/mismatched active visits stop before HTTP. |
| R2: SQLi-to-dictionary chain cannot establish `no_rate_limit` | A proved, consumable plaintext source may trigger one destination reconnaissance attempt before eligibility checking. At most two benign controls target the fixed DVWA brute-force module through the shared HTTP gate; observations and probe/containment receipts are retained. Negative/unavailable evidence never unlocks a visit. |
| R3: TUI scanner lists resume sidecars as unknown runs | `ArtifactRepository` now excludes `.resume.json`, matching `ArtifactCatalog` and TESIS Web. |

TESIS Web's production consumer already handles these event and sidecar contracts. A new reducer regression verifies that destination reconnaissance stays visible in the journal without changing selected method, method visits, attempts, successes, or confirmed findings. The existing resolver regression still proves resume sidecars cannot create ambiguous sources.

Post-review evidence is under `results/validation/workflow-review-fixes/`:

- 117 selected Python checks passed, including negative/unknown rate probes, containment/session cleanup, receipt history, TUI discovery, graph routing and HTTP serialization (`focused.xml`).
- Nine focused mocked graph/replay checks passed, with 346 deselected: saved queues, generated subset replay, three surfaces' saved probe controls, redaction, tampered-input refusal, fresh plaintext routing and sanitized source-binding replay (`offline-e2e.xml`, `offline/`). No live transport or provider was used by these checks.
- 30 TESIS Web workflow/resolver checks and typechecking passed (`web/tests.log`, `web/typecheck.log`). Production Web source is unchanged by this follow-up, so the earlier build/browser evidence is reused.
- One live saved `sqli_union` input was revalidated and executed against the already authorized DVWA target `http://172.19.48.1/dvwa` at low security. It produced two fresh response rows, confirmed `sqli_union`, retained the source bytes, had no validation rejections, and made zero fresh provider calls (`live-replay/manifest.json`, `live-replay/replay.json`, `live-replay/acceptance.json`). The replay API forbids provider invocation.

`acceptance.json` records exact commands and current source hashes. The live replay command is `PYTHONPATH=. .venv/bin/python results/validation/workflow-review-fixes/live_replay.py`; focused mocked E2E uses `offline_checks.py` in the same folder. Initial diagnostic failures remain separately named; final receipts above passed. The mocked harness emits one pytest plugin rewrite warning because it imports the existing fixture before pytest starts.

The earlier eight live executions and 12 River AI calls predate these review fixes and are not attributed to the current source hashes. No fresh model/provider calls were made in this follow-up. A positive plaintext SQLi-to-brute-force chain was verified with mocked responses; the actual DVWA fixture returns password hashes, which remain ineligible as plaintext source material.

## Protocol and operational notes

The contract stamps are `workflow.v2`, `state.v3`, `checkpoint.v2`, and `graph.v2`. Old graph checkpoints fail closed. Existing historical artifacts remain readable. Keep `checkpoint-audit/` beside its SQLite database: missing or corrupt audit entries refuse restoration. Method coverage is unique entered methods divided by the configured surface's entire canonical method set, or one explicit target. Preparation failures consume a reservation without claiming execution coverage. The changed iteration semantics define a new experiment epoch.

Durable guidance was updated in `docs/reference/architecture.md`, `docs/reference/summary_en.md`, and `docs/reference/summary_id.md`. No repository configuration or credentials were changed. Validation did not push, merge, or deploy either repository.

## Original analysis

## Workflow traced

The existing [runtime diagram](../diagrams/langgraph-implementation.mmd) matches the node wiring in [graph_builder.py](../../core/graph_builder.py#L145). Verification remains inside the nine static method agents.

| Stage | Next stage | Decision owner |
| --- | --- | --- |
| Recon | Orchestrator | Fixed edge |
| Orchestrator | Candidate builder or scorer | `route_from_orchestrator` |
| Candidate builder | Validator | Fixed edge |
| Validator | Selected method, chaining router, or scorer | `route_from_payload_validator` |
| Method agent | Chaining router | Fixed edge |
| Chaining router | Candidate builder, orchestrator, or scorer | `route_from_chaining_router` |
| Scorer | END | Fixed edge |

In particular, a chain or deterministic fallback can return directly to candidate construction. It does not have to pass through the orchestrator again. This affects iteration accounting, feasibility checks, and the empty-queue path.

## Findings

### F01, P1: a fresh checkpointed execution can inherit an earlier execution's state

Evidence: [runner.py:519](../../evaluation/runner.py#L519), [runner.py:615](../../evaluation/runner.py#L615), [runner.py:824](../../evaluation/runner.py#L824), [runner.py:860](../../evaluation/runner.py#L860), [checkpoint_store.py:184](../../core/checkpoint_store.py#L184), and [state.py:143](../../core/state.py#L143).

When durable checkpointing is enabled, `graph_thread_id` is the stable coordinate ID even when `resume=False`. `save_started()` replaces the metadata row, but does not remove or replace the corresponding LangGraph thread. The subsequent `stream(init_state)` uses that existing thread. Empty initial lists and dictionaries merge with the saved values through the accumulating reducers; they do not clear them.

Trigger: run the same coordinate again with the same checkpoint store and experiment ID, without requesting resume. Previous observations, confirmations, tried payloads, evidence, candidate history, and score maxima can survive. The new execution can skip requests or report findings backed by the earlier execution.

Suggested fix: keep the stable coordinate identity in metadata, but allocate a fresh graph thread for every new execution and record that thread ID for later resume. An explicit reset of an existing thread is another option, with care around concurrent executions and preserving historical evidence. Resetting only the metadata row is insufficient.

Existing coverage inspected: completed-receipt replay and crash recovery. These do not cover two fresh real-graph executions against the same durable coordinate.

### F02, P1: resume identity omits effective model and scoring configuration

Evidence: [checkpoint_store.py:93](../../core/checkpoint_store.py#L93), [runner.py:496](../../evaluation/runner.py#L496), and [runner.py:588](../../evaluation/runner.py#L588).

`coordinate_fingerprint()` hashes a subset of setup, including a top-level model name. It omits effective per-role provider/model settings, reasoning effort, response mode, generation settings, scoring rubric/profile/oracles, fixture/protocol identity, and some retry settings. Several of these already exist in the runner's coordinate dictionary, but are not included in the fingerprint; resolved role settings are not supplied to it.

Trigger: request resume after changing one of those omitted settings while leaving the hashed fields unchanged. A completed receipt can be returned as compatible, or a partial graph can continue under a changed setup.

Suggested fix: build a versioned fingerprint from canonical effective execution settings and content hashes for scoring/fixture inputs. Exclude secret values while preserving non-secret provider endpoint and role identity. Treat incompatible fingerprints as a new execution or refuse resume explicitly.

### F03, P1: the validation reducer preserves old executable decisions across visits

Evidence: [state.py:70](../../core/state.py#L70), [state.py:155](../../core/state.py#L155), [payload_validator.py:307](../../foundation/payload_validator.py#L307), and [state_utils.py:107](../../agents/state_utils.py#L107).

`payload_validation_results` uses `_merge_payload_maps`, which retains the first row for a candidate ID and ignores subsequent rows with that ID. However, the validator recalculates validity and ranking on each visit. `validated_payload_candidates()` builds the executable queue from the accumulated results rather than the latest visit's ranked IDs.

Trigger: revisit a method while its generated candidate set grows. If ranking displaces a previously accepted candidate, the old `valid=True` remains authoritative. Conversely, a previously budgeted-out candidate cannot become executable later. The active queue can become the union of candidates accepted on different visits and exceed the latest ranking budget. Its order also reflects earlier validation passes.

Suggested fix: separate the append-only candidate and validation audit history from a replaceable active queue keyed by method and visit. Routing and execution should consume only the current visit's accepted IDs. Keep all previous decisions as evidence with explicit visit identity.

Existing coverage inspected: single-pass candidate rejection, ranking, and direct queue filtering. Those checks do not demonstrate reducer behavior across successive graph visits.

### F04, P1: configured coverage stopping does not affect execution

Evidence: [config.yaml:71](../../config.yaml#L71), [runner.py:808](../../evaluation/runner.py#L808), [state.py:224](../../core/state.py#L224), [orchestrator.py:307](../../agents/orchestrator.py#L307), and [chaining_coordinator.py:142](../../core/chaining_coordinator.py#L142).

The configuration describes `coverage` as continuing until `coverage_target` or budget exhaustion. The runner supplies both fields, but neither is declared in `ExploitationState`, so graph input processing drops them. Independently, the routing code does not consult either setting: high-impact stopping is unconditional and no coverage threshold is calculated.

Trigger: select `stop_policy=coverage` and change `coverage_target`. These changes do not alter routing. The checked-in configuration currently selects coverage with a target of 0.70.

Suggested fix: define the fields in graph state and implement one deterministic stop-policy decision shared by orchestrator and chaining router. Specify the coverage denominator and interaction with an explicit target method before changing behavior. Merely adding the missing fields will not implement the policy.

### F05, P2: provider-call accounting rejects legitimate zero-call continuation and infeasibility paths

Evidence: [runner.py:665](../../evaluation/runner.py#L665), [runner.py:830](../../evaluation/runner.py#L830), [runner.py:976](../../evaluation/runner.py#L976), [runner.py:1144](../../evaluation/runner.py#L1144), and [orchestrator.py:362](../../agents/orchestrator.py#L362).

`llm_required` describes the original run mode, but the completion gate counts only provider events captured during the current invocation.

Two affected paths are visible:

1. A model-backed partial run resumes at the router or scorer after its provider work already completed. Historical provider receipts are not restored into the new call context. If the continuation needs no new model call, it reaches `LLM_NOT_CALLED`.
2. An automatic AKG run with no viable methods intentionally stops before calling the model and records `NO_VIABLE_METHODS`. The runner's zero-call gate replaces that explanation with `LLM_NOT_CALLED` and classifies an execution failure.

Suggested fix: distinguish calls required by remaining work from calls required by the whole execution. Restore and validate prior call receipts on resume, with original execution identity. Preserve explicit infeasibility outcomes. Do not suppress the zero-call gate for ordinary model-backed execution.

Existing partial-resume runner coverage uses an explicit target with static-only payloads, which makes `llm_required=False` and misses the first case.

### F06, P2: eligibility permits repeated work and has an unbounded empty-chain cycle

Evidence: [orchestrator.py:322](../../agents/orchestrator.py#L322), [orchestrator.py:465](../../agents/orchestrator.py#L465), [orchestrator.py:572](../../agents/orchestrator.py#L572), [chaining_coordinator.py:125](../../core/chaining_coordinator.py#L125), and [graph_builder.py:100](../../core/graph_builder.py#L100).

The orchestrator's schema and final allowed-method check include attempted, blocked, and failed methods. The prompt only prefers an unattempted method. A valid model response can therefore select an exhausted method, pay for candidate generation again, and reach an agent whose payloads have already been tried. Some SQLi probes then return `False` when no untried probe remains, preventing even a newly generated exploit from running; see [sqli_time_blind_agent.py:94](../../agents/sqli/sqli_time_blind_agent.py#L94) and [sqli_union_agent.py:65](../../agents/sqli/sqli_union_agent.py#L65).

A related conditional liveness defect exists for AKG chains: if the validator has no executable candidates, it routes to the chaining router without marking the destination attempted or recording a failed preparation. The router can select the same still-ready chain again. Candidate builder, validator, and router do not increment `iteration_count`, so this cycle can continue until LangGraph's separate recursion limit. This second scenario depends on reaching an empty queue; ordinary static-seed fallback often avoids it.

Suggested fix: define executable eligibility from remaining candidates and visit state. Permit revisits only with an explicit reason and suitable probe/session semantics. Record preparation failure as a visit disposition so the same chain cannot immediately retry without a bounded retry budget. Route to scoring when no eligible work remains.

### F07, P2: linear fallback unexpectedly applies AKG viability filtering

Evidence: [orchestrator.py:195](../../agents/orchestrator.py#L195) and [chaining_coordinator.py:152](../../core/chaining_coordinator.py#L152).

The orchestrator deliberately distinguishes conditions: linear fallback uses canonical surface order, while AKG fallback uses observed viability. The chaining router's blocked/failed-method branch always uses `kg.get_viable_methods()`, regardless of condition.

Trigger: a linear run's last method is blocked or fails and no remaining method has a true AKG observation. The chain router stops with `ALL_METHODS_FAILED`, even though canonical unattempted methods remain. If some methods are viable, the branch still applies a different selection rule from the linear fallback in the orchestrator.

Suggested fix: share a condition-aware fallback selector and record deterministic substitutions in fallback evidence. Preserve the intended difference between the two primary experiment conditions.

### F08, P2: iteration limits can overshoot and charge equivalent visits differently

Evidence: [orchestrator.py:291](../../agents/orchestrator.py#L291), [orchestrator.py:353](../../agents/orchestrator.py#L353), [orchestrator.py:622](../../agents/orchestrator.py#L622), [state_utils.py:664](../../agents/state_utils.py#L664), and [chaining_coordinator.py:99](../../core/chaining_coordinator.py#L99).

An orchestrator selection increments `iteration_count`; method completion increments it again. Direct chain/fallback selections bypass the first increment. The validator does not check remaining budget before dispatching a method.

Trigger: with `max_iterations=1`, an initial method selection increments to one and its method can still execute, incrementing to two. More generally, the same number of method executions consumes different iteration budgets depending on the route used. The orchestrator's limit check also excludes states with existing confirmed nodes or outcomes.

Suggested fix: specify whether the budget measures method visits, planning decisions, requests, or graph steps. Maintain separate counters where needed and enforce the execution budget immediately before dispatch. Keep the graph recursion limit as a separate emergency bound. Changes to counting must be recorded as an experiment-protocol change.

### F09, P2: scorer output fields are silently discarded by LangGraph

Evidence: [scorer.py:314](../../core/scorer.py#L314), [state.py:126](../../core/state.py#L126), [state.py:345](../../core/state.py#L345), and [runner.py:1195](../../evaluation/runner.py#L1195).

`scorer()` returns `summary` and `surface_scores`, but neither field is declared in `ExploitationState`. The installed LangGraph implementation filters node dictionary updates to declared channels. The artifact-only inventory does not declare channels, so listing these fields there does not preserve them.

Impact: raw graph results and graph checkpoints lose those scorer-specific report fields. The runner reconstructs a report through `build_score_report()`, which retains some reporting, but it does not restore the scorer's complete enriched summary and nested `surface_scores` structure.

Suggested fix: declare explicit output fields/schema if these are part of the graph contract, or move report construction wholly outside graph state and have one shared reporting function. Avoid maintaining two partially different report builders.

## Optimization candidates

These are source-supported opportunities, not measured speedups.

### O01: filter chain opportunities by consumable source material

Evidence: [chaining_coordinator.py:128](../../core/chaining_coordinator.py#L128), [state_utils.py:43](../../agents/state_utils.py#L43), [payload_validator.py:407](../../foundation/payload_validator.py#L407), and [chaining_coordinator.py:250](../../core/chaining_coordinator.py#L250).

Routing checks proved graph-node prerequisites but does not require target-method viability or consumable source material. Selection scoring can assign grade one for missing prerequisites and still dispatch. A `credentials_extracted` outcome containing only password hashes still schedules dictionary generation and execution; the coordinator can only explain afterwards that a hash was not consumable as plaintext.

Another case is the registered `ac_vertical_escalation_confirmed` or `admin_session_obtained` route to `sqli_union`. The UNION agent creates its own configured session and does not attach source-consumption evidence. With the current adapter, that route cannot satisfy `_complete_routed_visit()`'s dependency-credit requirement even if the independent SQLi execution succeeds. The original vulnerability finding can remain valid while chain credit stays unverified.

Preflight each eligible edge against supported source-to-destination bindings and payload feasibility. Record unavailable bindings as unverified or infeasible, and avoid spending provider/HTTP work on a dependency the current adapter cannot demonstrate. Keep verifier evidence and final chain scoring authoritative.

### O02: reuse the static validated AKG and its profiles

Evidence: [knowledge_graph.py:83](../../core/knowledge_graph.py#L83), [payload_validator.py:44](../../foundation/payload_validator.py#L44), and [payload_validator.py:135](../../foundation/payload_validator.py#L135).

Every `AttackKnowledgeGraph()` rebuilds and validates the entire NetworkX graph. This happens in planning, selection receipts, candidate construction, validation, and even `allowed_target_params()` once per candidate. The chain router already reuses a singleton.

Use a shared immutable validated representation or pass the current profile into validation helpers. Preserve isolation from mutation: `get_payload_profile()` currently returns only a shallow copy. This reduces repeated CPU work without changing the research decision rules, though provider and HTTP latency may still dominate.

### O03: reduce audit data carried through every checkpoint and snapshot

Evidence: [state.py:339](../../core/state.py#L339), [graph_builder.py:163](../../core/graph_builder.py#L163), [runner.py:861](../../evaluation/runner.py#L861), and [runner.py:933](../../evaluation/runner.py#L933).

The persistent/artifact-only inventory is explicitly design-only. Actual graph checkpoints retain accumulating messages, prompts, telemetry, and evidence. The runner streams full state values and deep-copies most accumulated state again for each frozen method input. Cost grows with evidence volume and visit count.

Measure serialized checkpoint size, frozen-input copy time, and peak memory before refactoring. Store large immutable audit payloads once in artifacts and retain durable references plus the compact state needed to continue. Resume, manual scoring, and saved-input replay must be able to reload the evidence. Changing stream mode alone does not reduce persisted channel size.

### O04: declare conditional route domains explicitly

Evidence: [graph_builder.py:75](../../core/graph_builder.py#L75), [graph_builder.py:92](../../core/graph_builder.py#L92), and [graph_builder.py:158](../../core/graph_builder.py#L158).

The routers return plain `str` and conditional edges have no `path_map`. This limits static checking and makes LangGraph's inferred visualization less precise than the actual runtime routes. Use `Literal` return types or explicit maps covering each router's real domain. This improves diagnostics and graph inspection; it is not expected to improve runtime latency materially.

## Suggested implementation order

1. Fix fresh-run checkpoint isolation and effective-configuration fingerprints, F01 and F02.
2. Separate current execution queues from append-only audit history, F03.
3. Define and enforce stop-policy and budget semantics, F04 and F08.
4. Unify eligibility, bounded preparation failure, condition-aware fallback, and chain feasibility, F06, F07, and O01.
5. Repair continuation call accounting and report output contracts, F05 and F09.
6. Measure and then optimize AKG construction and checkpoint volume, O02 and O03. Add explicit route domains with O04.

Any subsequent validation should follow the user's chosen scope. The smallest meaningful checks would target the concrete triggers above: fresh same-coordinate execution isolation, resume configuration drift, multi-visit validation replacement, coverage stopping, model-backed zero-call continuation, exhausted-method handling, linear fallback, a one-iteration budget, and scorer output survival. These checks are proposed only. E2E remains opt-in, including offline graph E2E.

Keep the matrix HTTP lease, containment checks, method-local verification, and append-only research evidence. Optimize decision eligibility and data handling while preserving those invariants. Do not introduce concurrent DVWA method execution as a generic latency optimization.

## Framework references

Official [Graph API documentation](https://docs.langchain.com/oss/python/langgraph/graph-api) describes reducer merging, graph state, and conditional routing. Official [checkpointer documentation](https://docs.langchain.com/oss/python/langgraph/checkpointers) describes thread-scoped state and checkpoint continuation. For version-sensitive behavior, this review also inspected the installed 1.2.1 implementation, including `graph/state.py`'s filtering of node update keys.
