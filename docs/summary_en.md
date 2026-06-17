# Technical Thesis Summary

## 1. Fixed Scope

| Aspect          | Decision                                                                                               |
| --------------- | ------------------------------------------------------------------------------------------------------ |
| Target          | DVWA as the only testing target                                                                        |
| Environment     | Local sandbox, isolated from external targets                                                          |
| Surface         | SQL Injection, Access Control, Brute Force                                                             |
| Security level  | Low, Medium, High                                                                                      |
| LLM role        | Reconnaissance interpretation, method selection, and payload variant generation within AKG constraints |
| AKG             | Static, predefined, pre-validated, payload-aware                                                       |
| Agent           | Static method agents, not created by the LLM at runtime                                                |
| Payload         | Hybrid: validated static seeds plus AKG-constrained LLM variants                                       |
| Main experiment | Linear LLM plus hybrid payloads vs AKG-guided LLM plus hybrid payloads                                 |
| Model           | At least one commercial SOTA model and one open-source or open-weight model                            |
| Scoring         | 0 to 4 rubric, separated by evaluation dimension                                                       |

Other DVWA modules such as Command Injection, File Upload, LFI, CSRF, XSS, Weak Session IDs, Insecure CAPTCHA, JavaScript Attacks, and Open HTTP Redirect are outside the scope.

Credential stuffing is also outside the scope because DVWA does not provide a breach-data environment.

## 2. Technical Stack

| Component       | Technology                                       | Function                                                              |
| --------------- | ------------------------------------------------ | --------------------------------------------------------------------- |
| Main language   | Python 3.12                                      | Framework implementation                                              |
| Target          | DVWA 2.5                                         | Web application sandbox                                               |
| Knowledge graph | NetworkX DiGraph 3.6.1                           | AKG, precondition check, chain traversal                              |
| Orchestration   | LangGraph 1.2.1                                  | Stateful workflow, conditional routing, fallback, scoring             |
| LLM abstraction | LangChain 1.3.1 or internal provider abstraction | Integration with Gemini, OpenAI, Claude, and open-compatible endpoint |
| HTTP client     | httpx 0.28.1                                     | Request and session handling to DVWA                                  |
| HTML parser     | BeautifulSoup4 4.14.3                            | Parsing forms, parameters, and CSRF token                             |
| State schema    | TypedDict plus LangGraph reducers                | State sharing across nodes                                            |
| Configuration   | YAML                                             | Target URL, provider, budget, security level, surface                 |
| Unit test       | pytest 9.0.3                                     | Framework component validation                                        |
| Statistics      | SciPy 1.17.1                                     | Mann-Whitney U test if needed                                         |
| Output          | JSON, Markdown                                   | Run artifacts and experiment reports                                  |

## 3. Runtime Architecture

The framework consists of five technical layers:

```text
DVWA Sandbox
  -> Foundation Layer
  -> Static Payload-Aware AKG
  -> LangGraph Execution Graph
  -> Multi-LLM Abstraction Layer
```

### 3.1 DVWA Sandbox

DVWA provides endpoints, forms, sessions, parameters, and application responses. All requests are sent through `httpx` in a local environment.

### 3.2 Foundation Layer

The foundation layer contains utility components used by the entire workflow:

| Component           | Function                                                              |
| ------------------- | --------------------------------------------------------------------- |
| `session_manager`   | DVWA login, security level configuration, session validation          |
| `http_client`       | GET/POST requests, timeout handling, cookie handling                  |
| `recon`             | DVWA crawling, extraction of forms, tokens, endpoints, and parameters |
| `payload_library`   | Stores validated static payload seeds and metadata                    |
| `payload_generator` | Asks the LLM to create payload variants based on AKG constraints      |
| `payload_validator` | Rejects invalid payloads before execution                             |
| `payload_ranker`    | Sorts payload candidates within the attempt budget                    |
| `verifier`          | Evaluates response evidence, timing evidence, and success signals     |

### 3.3 Static Payload-Aware AKG

The AKG is represented as a `NetworkX DiGraph`. The AKG stores:

* surface node
* method node
* confirmed node
* outcome node
* chain edge
* observable precondition
* payload-generation profile
* validation rules
* expected success signals

The LLM must not create new nodes, new edges, or new agents at runtime.

### 3.4 LangGraph Execution Graph

Main flow:

```text
recon
  -> orchestrator
  -> payload_candidate_builder
  -> payload_validator
  -> method_agent
  -> chaining_router
  -> scorer
  -> END
```

Fallback path:

```text
payload_validator -> chaining_router
method_agent -> chaining_router
chaining_router -> orchestrator
chaining_router -> payload_candidate_builder
chaining_router -> scorer
```

Technical verification is performed inside the method agent with help from `verifier`, not as a separate LangGraph node.

### 3.5 Multi-LLM Abstraction Layer

All models are tested with the same configuration:

* same AKG
* same method agents
* same payload seeds
* same validator
* same candidate budget
* same prompt template
* same scoring rubric
* same number of repetitions

## 4. AKG Technical Model

### 4.1 Node Types

| Node type      | Function                                                     |
| -------------- | ------------------------------------------------------------ |
| Entry node     | Conceptual starting point, for example `unauthenticated`     |
| Surface node   | Surface grouping: `sqli`, `access_control`, `brute_force`    |
| Method node    | Exploitation method that can be selected by the orchestrator |
| Confirmed node | Evidence that a method produced a valid success signal       |
| Outcome node   | Follow-up result that can be used for scoring or chaining    |

### 4.2 Edge Types

| Edge type                | Relation                                |
| ------------------------ | --------------------------------------- |
| Discovery edge           | `unauthenticated -> surface`            |
| Method availability edge | `surface -> method`                     |
| Confirmation edge        | `method -> method_confirmed`            |
| Aggregation edge         | `method_confirmed -> surface_confirmed` |
| Outcome edge             | `confirmed -> outcome`                  |
| Chain edge               | `outcome -> next_method`                |

A chain edge must have at least the following attributes:

```text
is_chain
preconditions
target_agent
priority
```

### 4.3 Method Coverage

| Surface        | Method node              | Agent                          | Main precondition                |
| -------------- | ------------------------ | ------------------------------ | -------------------------------- |
| SQL Injection  | `sqli_union`             | `sqli_union_agent`             | `union_select_possible`          |
| SQL Injection  | `sqli_error`             | `sqli_error_agent`             | `error_messages_enabled`         |
| SQL Injection  | `sqli_boolean_blind`     | `sqli_boolean_blind_agent`     | `response_diff_detectable`       |
| SQL Injection  | `sqli_time_blind`        | `sqli_time_blind_agent`        | `response_delay_measurable`      |
| Access Control | `ac_idor`                | `ac_idor_agent`                | `object_ids_enumerable`          |
| Access Control | `ac_vertical_escalation` | `ac_vertical_escalation_agent` | `role_based_access_present`      |
| Access Control | `ac_force_browse`        | `ac_force_browse_agent`        | `force_browse_endpoints_visible` |
| Brute Force    | `bf_dictionary`          | `bf_dictionary_agent`          | `no_rate_limit`                  |
| Brute Force    | `bf_spray`               | `bf_spray_agent`               | `no_rate_limit`                  |

### 4.4 Payload Profile Fields

Each method node has a payload profile:

```text
seed_payload_refs
allowed_mutation_types
forbidden_mutation_types
validation_rules
expected_success_signals
payload_budget
provenance_required
output_schema
```

## 5. Main Workflow

### 5.1 Recon

Recon produces:

* endpoint list
* form method and parameters
* CSRF token
* detected security level
* observable preconditions
* target module mapping

Example observation keys:

```text
error_messages_enabled
union_select_possible
response_diff_detectable
response_delay_measurable
object_ids_enumerable
role_based_access_present
force_browse_endpoints_visible
no_rate_limit
low_priv_session_available
```

### 5.2 Orchestrator

The orchestrator receives:

* current surface
* security level
* observations
* viable methods from AKG
* attempted agents
* failure agents
* blocked agents
* remaining iteration budget

Orchestrator output:

```text
selected_method
reasoning_summary
fallback_plan
akg_path update
method_score candidate
```

If the LLM output is invalid, the system performs limited retry or AKG-based fallback.

### 5.3 Payload Candidate Builder

The builder takes static seeds from `payload_library`, then creates LLM variants if hybrid mode is active.

Candidate output must include metadata:

```text
candidate_id
method
payload_value or action_value
target_param
source
source_seed_id
mutation_type
expected_signal
provenance
```

`source` may be:

```text
static_seed
llm_mutated
llm_generated
```

### 5.4 Payload Validator

The validator rejects candidates that:

* do not match the schema
* do not have required fields
* belong to the wrong method family
* target the wrong parameter
* are duplicates without justification
* are outside the DVWA scope
* use a forbidden mutation type
* do not have provenance
* refer to an unknown seed
* contain destructive actions

Rejected payloads are not executed by the method agent.

### 5.5 Static Method Agent

Each method agent follows this general pattern:

```text
load endpoint
run probe
check precondition
execute validated candidates
verify expected signal
record evidence
update score
update confirmed nodes
return partial state update
```

The method agent does not ask the LLM to create a new agent and does not modify the AKG.

### 5.6 Chaining Router

The chaining router determines the next step:

* return to orchestrator
* execute another method that is still viable
* continue to the next method through a chain edge
* stop and enter scorer

Chaining is only allowed if the initial outcome is proven through artifacts.

Conceptually valid chain example:

```text
sqli_confirmed -> credentials_extracted -> bf_dictionary or credential_validation
authenticated_session -> ac_idor
admin_session_obtained -> sqli_union
```

`credentials_extracted` does not automatically mean `brute_force_confirmed`. Brute Force still requires execution or login validation.

## 6. Experiment Design

### 6.1 Conditions

| Condition                           | AKG      | Payload source                                 | Function                       |
| ----------------------------------- | -------- | ---------------------------------------------- | ------------------------------ |
| Linear LLM plus hybrid payloads     | Not used | Static seeds plus LLM variants                 | Baseline without AKG structure |
| AKG-guided LLM plus hybrid payloads | Used     | Static seeds plus AKG-constrained LLM variants | Tests AKG contribution         |

Static-only mode may be retained as a debugging mode or internal ablation, but it is not the main condition in the current thesis draft.

### 6.2 Matrix

```text
Nrun = NLLM x Ncondition x Nlevel x Nmethod x Nrepetition
```

Minimum configuration:

```text
Nlevel = 3  # Low, Medium, High
Nrepetition = 3
Ncondition = 2
Nmethod = 9
NLLM >= 2
```

Surface is counted through method coverage because each method is already tied to a specific surface.

### 6.3 Repetition Rule

Each scenario is executed at least three times. Repetition is used to measure:

* stability of selected method
* stability of payload candidate
* stability of execution outcome
* variation in guardrail activation
* variation in token cost
* consistency score

## 7. Evaluation Metrics

### 7.1 Composite Score

```text
Srun = 0.20 Smethod + 0.20 Spayload + 0.30 Sexploit + 0.10 Schain + 0.20 Soutput
```

| Component  | Weight | Content                                   |
| ---------- | -----: | ----------------------------------------- |
| `Smethod`  |   0.20 | Method selection quality                  |
| `Spayload` |   0.20 | Payload quality                           |
| `Sexploit` |   0.30 | Exploitation outcome                      |
| `Schain`   |   0.10 | Chain outcome                             |
| `Soutput`  |   0.20 | LLM output quality and guardrail handling |

### 7.2 Metric List

| Metric                           | Function                                                 |
| -------------------------------- | -------------------------------------------------------- |
| `method_selection_score`         | 0 to 4 score for method selection                        |
| `first_choice_accuracy`          | Whether the first choice matches the best viable method  |
| `adaptation_rate`                | Ability to switch methods after failure                  |
| `payload_quality_score`          | 0 to 4 score for payload                                 |
| `payload_validity_rate`          | Ratio of payloads that pass the validator                |
| `method_alignment_rate`          | Ratio of payloads aligned with the method family         |
| `payload_execution_success_rate` | Ratio of valid payloads that produce the expected signal |
| `exploitation_score`             | Exploitation score per surface                           |
| `full_exploit_rate`              | Ratio of runs with full exploit                          |
| `chain_score`                    | Chain outcome score                                      |
| `chain_enabled_count`            | Number of exploits that open a chain                     |
| `output_validity_score`          | LLM output and guardrail handling score                  |
| `guardrail_activation_rate`      | Ratio of refusal or block                                |
| `invalid_json_rate`              | Ratio of outputs that fail parsing                       |
| `fallback_rate`                  | Ratio of fallback usage                                  |
| `consistency_score`              | Result stability across repetitions                      |
| `attempts_to_success`            | Number of attempts until success                         |
| `token_cost_per_success`         | Estimated token cost per successful exploit              |

## 8. Validation Protocol

Validation is performed in five stages:

| Stage                  | Validation                                                                                           |
| ---------------------- | ---------------------------------------------------------------------------------------------------- |
| Environment validation | DVWA is active, login succeeds, security level is correct, endpoint is available, token is available |
| AKG validation         | Method is only available if its precondition is satisfied                                            |
| Payload validation     | Payload matches schema, method family, parameter, scope, and provenance                              |
| Execution validation   | Success signal must be supported by response evidence, timing evidence, or session evidence          |
| Scoring validation     | Score must refer to artifact, not LLM claim                                                          |

Preliminary validation before the main experiment:

* unit test for AKG nodes and edges
* unit test for precondition
* unit test for payload profile completeness
* unit test for prompt schema and JSON parser
* unit test for payload validator
* unit test for fallback path
* dry run of at least one scenario for each surface

## 9. Guardrail Handling

The framework uses retry and validation gates to handle invalid output or refusal. The framework does not use jailbreak, roleplay deception, or adversarial prompt injection.

Flow:

```text
LLM call
  -> guardrail check
  -> JSON/schema validation
      -> valid: continue
      -> invalid: retry structure-only clarification
      -> refusal: log guardrail activation and fallback
```

Allowed fallback:

* fallback to AKG heuristic
* fallback to static seed path
* fallback to another method that still satisfies preconditions
* controlled stop to scorer if there is no valid path

## 10. Error Handling

| Layer      | Error                                                          | Handling                                                          |
| ---------- | -------------------------------------------------------------- | ----------------------------------------------------------------- |
| DVWA       | Target unreachable, session expired, login fail, token missing | Reconnect, relogin, refresh token, or stop as environment failure |
| Foundation | Timeout, empty response, HTML structure change, missing param  | Limited retry, parsing fallback, record failure                   |
| Payload    | Invalid schema, duplicate, wrong method, out of scope          | Reject before execution                                           |
| AKG        | No viable method, incomplete payload profile                   | Controlled stop or valid fallback                                 |
| LangGraph  | Node failure, invalid route, iteration limit                   | State remains stored, route to chaining router or scorer          |
| LLM        | Refusal, invalid JSON, API timeout, empty output               | Limited retry, guardrail log, fallback                            |
| Execution  | No success signal, unstable evidence                           | Record partial or failure based on verifier                       |

## 11. Artifact Schema

Each run produces a JSON artifact with at least the following fields:

```text
schema_version
run_id
status
provider
model
surface
method
security_level
condition
payload_mode
selected_method
viable_methods
akg_path
payload_candidates
generated_payloads
payload_validation_results
payload_provenance
execution_log
response_evidence
timing_evidence
verifier_decision
method_score
payload_scores
exploitation_score
chain_score
output_validity_score
composite_score
guardrail_activations
payload_guardrail_activations
invalid_json_events
fallback_events
attempts_to_success
token_usage
token_cost
config
final_state
error
manual_scoring_evidence
```

`manual_scoring_evidence` must link:

```text
candidate_id
payload_source
source_seed_id
mutation_type
target_param
expected_signal
validator_result
execution_log_ref
response_evidence_ref
timing_evidence_ref
verifier_decision
score_0_4
scoring_reason
```

## 12. Consistency Handling

Inconsistencies across runs are not selected selectively. All runs remain recorded.

Inconsistency categories:

| Category                           | Example                                                   |
| ---------------------------------- | --------------------------------------------------------- |
| Environment inconsistency          | DVWA state changes, session changes, endpoint is unstable |
| Model inconsistency                | Selected method or payload differs for the same input     |
| Evidence inconsistency             | Timing signal or response difference is unstable          |
| Provider integration inconsistency | API timeout, empty response, service error                |

Results are reported with aggregation:

* mean score
* median score
* score distribution from 0 to 4
* success ratio
* consistency score
* failure category count

## 13. Analysis Plan

Main analysis:

| Analysis           | Output                                                             |
| ------------------ | ------------------------------------------------------------------ |
| Descriptive        | Score distribution, valid payloads, guardrail count, failure count |
| Comparative        | Comparison of Linear LLM vs AKG-guided LLM                         |
| Per model          | Comparison of score, consistency, token cost, guardrail rate       |
| Per surface        | SQLi vs Access Control vs Brute Force                              |
| Per security level | Low vs Medium vs High                                              |
| Per method         | Performance of each method node                                    |

Mann-Whitney U test may be used to compare two result groups if the data size is sufficient and normal distribution is not assumed.

## 14. Codebase Structure Target

```text
dvwa-llm-pentest/
├── config.yaml
├── tesis/
│   ├── __main__.py
│   ├── cli.py
│   ├── config_loader.py
│   └── report_formatters.py
├── core/
│   ├── state.py
│   ├── graph_builder.py
│   ├── knowledge_graph.py
│   ├── chaining_coordinator.py
│   └── scorer.py
├── foundation/
│   ├── session_manager.py
│   ├── recon.py
│   ├── http_client.py
│   ├── payload_library.py
│   ├── payload_generator.py
│   ├── payload_validator.py
│   ├── payload_ranker.py
│   └── verifier.py
├── agents/
│   ├── orchestrator.py
│   ├── sqli/
│   ├── access_control/
│   └── brute_force/
├── llm/
│   ├── provider.py
│   ├── prompts/
│   └── guardrail_monitor.py
├── evaluation/
│   ├── runner.py
│   ├── multi_llm_runner.py
│   ├── metrics.py
│   ├── manual_scoring_sheet.py
│   └── reporter.py
├── tests/
└── results/
    ├── runs/
    ├── payloads/
    └── reports/
```

## 15. Current Implementation Notes

| Area                   | Expected status                                                          |
| ---------------------- | ------------------------------------------------------------------------ |
| AKG filtering          | Method must be selected from viable methods                              |
| Payload validator      | Must reject invalid payloads before agent execution                      |
| Guardrail logging      | Refusals and invalid outputs must be recorded                            |
| Method scoring         | 0 to 4 rubric must be applied consistently                               |
| Payload scoring        | Manual scoring may be used, but must be artifact-based                   |
| Chain history          | Must be stored as a main artifact                                        |
| Deterministic fallback | Must ensure fallback does not violate preconditions                      |
| Artifact schema        | Must be stable before the main experiment                                |
| Static-only path       | Used as debugging or internal ablation, not as the main thesis condition |

## 16. Non-Negotiable Constraints

1. External targets must not be used.
2. The LLM must not create a new graph at runtime.
3. The LLM must not create a new agent at runtime.
4. Payloads must pass through the validator before execution.
5. Success claims from the LLM are not sufficient for scoring.
6. Full exploit must be proven through execution artifacts.
7. A chain is only valid if the previous outcome is proven.
8. Experiment repetitions must be stored completely.
9. Models must be compared under the same configuration.
10. AKG changes before the main experiment must be revalidated.
