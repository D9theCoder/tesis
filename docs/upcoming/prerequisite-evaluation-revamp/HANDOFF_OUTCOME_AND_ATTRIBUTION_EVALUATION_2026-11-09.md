# Handoff: outcome and attribution evaluation

Date: 2026-11-09 (Asia/Jakarta)
Kanban: **Upcoming**
Status: **Design direction agreed; implementation not started.**
Current deliverable: this planning handoff. No runtime, evaluator, configuration,
DOCX, historical receipt or experiment changes are performed by creating it.

Companion:
[Model-directed prerequisite probing](HANDOFF_MODEL_DIRECTED_PREREQUISITE_PROBING_2026-11-09.md).
That handoff owns the model-directed investigation/tool cycle discussed after
this evaluation design. Coordinate shared discovery, evidence, budgets and
comparison rules; evaluation adoption alone does not implement that runtime cycle.

## 1. Objective and owner decisions

Replace the five overlapping ordinal rubric grades and weighted composite as
the primary evaluation with two separately reported binary results:

1. **Outcome success:** was the declared objective independently verified
   within the task's budget?
2. **Qualified success:** was that objective achieved through a permitted,
   evidenced method or mechanism?

Attribution qualifies the second result. It is recorded as an explicit verdict,
not a numerical bonus. Chain completion is a separate research metric governed
by a rule fixed in the task specification before execution. Efficiency and
process behavior remain diagnostics.

The two core rubric checks are **goal verification** and **attribution**.
Qualified success is their derived result, not another independent rubric or
review pass. Attribution is binary when resolved: supported corresponds to 1
and rejected to 0; unresolved and not-applicable cases remain assessment states.

The owner agreed to the following direction in the current conversation:

- Remove reference ranking as a basis for grading, including reference-fit
  grades, evaluator-preferred method order and estimated reference request costs.
- Remove the five-dimensional weighted composite from prospective primary
  evaluation. Preserve its historical values and identities.
- Accept any appropriate permitted method; do not restore reference ranking
  through the attribution criterion.
- Report objective achievement and qualified achievement separately. An
  outcome of 1 with rejected attribution has qualified success 0, not 0.5.
- Keep chain completion and verified transition counts outside a weighted sum.
- Fix chain applicability and completion rules for the relevant task/coordinate
  before execution, using the same criteria for compared models and conditions.
- Preserve output validity, repair, fallback, rejected choices, candidate origin,
  requests, time and tokens as diagnostic evidence.
- Keep deterministic verification, validation, containment and source integrity.
- Keep the design small enough for a human or AI maintainer to understand.
- Keep fixture ground truth and successful routes hidden from the evaluated
  agent; declare the discovery objective before execution.
- Attribute the mechanism actually discovered and executed, and record whether
  reconnaissance, static inputs, model proposals or graph guidance supplied it.
- Report unsupported finding claims as well as successful outcomes.
- Improve AKG's discovery and chain execution through better planning and
  source use under equal budgets. The owner clarified that stronger AKG means
  better capability, not more generous scoring or a weakened Linear baseline.
- Include time, monetary cost, token usage, LLM request counts, cache usage and
  request latency as additional reported metrics. Reuse implemented telemetry;
  the resource work list in section 9.1 records only missing reporting or behavior.

The approved direction does not establish that a particular task goal or chain
is feasible, that code has been migrated, or that a research acceptance gate has
passed. The remaining task definitions and review-policy details in section 15
must be made concrete before a prospective freeze. Historical launch approvals
and acceptance campaigns retain their original scope; this document does not
start another experiment or alter those campaigns.

## 2. Relationship to the current methodology

Current methodology authority is the reconciled
[Chapter 3](../../docx/bab-3-reconciled-2026-10-29.docx). The current implementation
and reference contract are described in
[thesis scoring](../../reference/thesis_scoring.md),
[English methodology](../../reference/summary_en.md) and
[Indonesian methodology](../../reference/summary_id.md).

This handoff specifies a prospective methodology change. It does not present the
proposal as if the manuscript already contained it. Existing obligations to
preserve rubric semantics, weights, denominators and unavailable values remain
in force for current and historical scoring until an authorized coordinated
cutover. Under the adopted prospective policy, the owner-selected replacement
must be documented explicitly rather than silently changing those semantics.

Related ongoing records:

- [Evaluation-methodology revision](../../active/METHODOLOGY_EVALUATION_REVISION_2026-11-07.md)
- [AC scoring handoff](../../active/HANDOFF_AC_SCORING_COMPLETION_2026-11-05.md)
- [Persistent evidence ledger](../../active/SCORING_COMPLETION_PROGRESS.md)
- [Owner decision record](../../active/AUTORESEARCH_RANKING_APPROVAL_QUESTIONS.md)
- [Runtime architecture](../../reference/architecture.md)

Do not infer current counts or readiness from an older paragraph in those
records. Reuse the relevant source-bound artifacts when implementation starts.
Closing this handoff must not retroactively close requirements belonging to a
different scoring or execution epoch.

## 3. Scope that stays intact

- DVWA remains the only target. Supported surfaces remain SQL Injection,
  Access Control and Brute Force, with the existing nine registered methods.
- Primary conditions remain `linear_hybrid` and `akg_guided_hybrid`, using
  hybrid payloads. Debugging and optional ablation modes are not promoted to
  primary study conditions by this change.
- The model selects methods within the declared scope. Preserve
  `experiment_condition`, `target_method`, `payload_mode` and `repeat_index`.
  Existing explicit target-method requirements retain their meaning; record
  fallback or infeasibility rather than silently substituting a target.
- The static AKG, runtime topology, validation-before-execution, method-agent
  verification and HTTP containment contracts remain intact.
- Keep positive/negative controls, permission and session identity evidence,
  candidate provenance, response hashes, timing evidence and original failures.
- Preserve configured provider/model identities and effective role settings.
  This proposal does not select another evaluator or study model.
- Do not weaken security levels or manufacture successful candidates to make a
  goal feasible or a score available.
- No DOCX edit is requested by this planning task. A future manuscript update
  is a separate explicitly requested deliverable.
- No commit, push, merge, deployment, scheduled work, additional matrix or
  subagent work is requested by this handoff creation.

## 4. Unit of evaluation: a declared task run

Evaluate the complete task run against its declared objective. Do not use only
the final selected method's grade as a substitute for the task outcome. Retain
earlier failures, successful visits and subsequent events in the trace.

Every planned coordinate must reference a frozen task specification containing:

| Item | Required meaning |
| --- | --- |
| Task identity and digest | Stable descriptive task ID and content hash. |
| Objective | Observable final result that constitutes achievement. |
| Allowed scope and methods | Existing surfaces/methods and any task-specific restriction. |
| Discovery objective and agent brief | Whether the task seeks one qualifying finding, a specified operational result or independently defined coverage; exactly what target information the agent receives. |
| Initial state | Declared account, privileges, credentials, objects and other permitted setup. |
| Fixture and controls | Fixture/level identity, independent feasibility evidence and outcome checks. |
| Private verifier reference | Hidden expected facts and trusted controls, separated from agent-visible context and planning hints. |
| Budget and stop rule | Time, target-request, provider-call or token limits actually applicable to the task. |
| Comparison contract | Whole-system or graph-guidance comparison, with declared common tools, observations, factual knowledge and capability differences. |
| Chain mode | `none`, `optional` or `required`, with the rule below. |
| Chain completion rule | Required dependency and destination objective; required transition count only when the task needs one. |
| Attribution rule | What execution evidence must establish to support the qualified claim. |
| Reporting group | Model, condition, surface, security level and repeat identity. |

Assign equivalent compared coordinates the same task objective, initial-state
policy, budgets, controls and completion criteria. Models and conditions can
choose different permitted strategies. A goal must not require consulting AKG
or following the evaluator's preferred method order.

The task ID refers to the objective, not to a method selected after execution.
Do not change the task, its applicability or required chain length after seeing
a failed run. The task specification may allow multiple compliant paths.

Task specifications can be shared across existing model/condition/repeat cells.
If introducing distinct chain-task variants adds a new experiment factor, state
that design change explicitly. Do not silently multiply the existing matrix or
claim that its old coordinates already evaluated the new goals.

### 4.1 Autonomous discovery and hidden ground truth

The public task brief gives the target, permitted scope, operational objective,
allowed starting access and budget. It must not identify which weakness is
present, provide a known-working candidate or disclose a successful route.
An objective can identify the result to achieve without naming its mechanism.

The trusted verifier retains the fixture reference needed to check findings,
identities and outcomes. Keep that reference out of orchestrator/payload prompts,
retrieval context, fallback explanations and agent-readable review artifacts.
Separate agent-visible measurements from hidden answer keys. A permitted probe's
actual response may inform the agent; a privileged positive reference must not
be presented as a finding the agent made or leave useful state in its session.

The static AKG may encode general relationships among the supported methods,
prerequisites and enabling outcomes. It must not start with fixture-specific
confirmed weaknesses, hidden credentials, expected answers or solved routes.
Only evidence produced during the run activates its confirmed state. This
preserves graph-guided discovery without turning the graph into an answer key.

Declare the discovery goal before execution:

- **One qualifying finding:** any verified weakness satisfying the declared
  scope and attribution rule can satisfy the task; do not privilege a method.
- **Operational objective:** a local finding is progress, but success requires
  the specified final result, including the dependency for a required chain.
- **Coverage objective:** define the independently validated finding population
  and matching/deduplication rules. An incomplete hidden inventory cannot support
  a claim that all weaknesses were found or a reliable recall denominator.

Discovery does not add another ordinal rubric. It changes what must be achieved
and which failure stage the diagnostics explain. Keep discovery, preparation,
execution, verification, attribution and infrastructure failures distinguishable.
No finding on a feasible, completed task can mean outcome 0; missing ground truth
or controls remains unavailable under section 5.

Current TESIS provides scoped assessment within predefined DVWA surfaces and
the registered method library. The orchestrator receives surface/method context,
and reconnaissance already measures method prerequisites. Describe this as
autonomous assessment within the permitted scope, rather than unrestricted blind
discovery. A known target and general domain knowledge also limit any claim of
discovery without prior knowledge.

For prospective autonomous-selection tasks, do not force `target_method`.
Retain explicit-target tasks as separately identified method diagnostics with
their existing semantics. Authorize and document that study-design change at
cutover; do not relabel historical forced-method runs as autonomous discovery.

### 4.2 Architecture-neutral comparison

Use identical task goals, valid starting access, containment, outcome checks,
attribution rules and chain-completion requirements for equivalent coordinates.
The evaluator accepts a supported dependency whether it was selected by an AKG
edge, a Linear planner or another permitted decision in the declared condition.
Neither an AKG consultation nor a particular method order is part of success.

Freeze what the comparison estimates:

- **Graph-guidance comparison:** both conditions can execute the same supported
  methods, consume discovered credentials/session material, continue across
  permitted surfaces and use the same observations and verifier tools. General
  factual method knowledge is comparable; structured graph guidance is the
  treatment. Linear need not traverse the graph to use shared execution tools.
- **Whole-system comparison:** retained capability or knowledge differences are
  explicit. Results compare the complete packages; they cannot isolate a benefit
  caused by graph guidance alone.

For the graph-guidance comparison, list common tools, initial information,
reconnaissance policy, prerequisite safety gates, source-consumption adapters,
permitted continuation and stopping/budget enforcement before freezing. Equal
capability does not require identical choices, histories or prompt formatting.
Charge discovery, adaptation and execution to the same declared run budgets;
report trusted evaluation overhead separately. Avoid giving either condition
helpful state created by private control execution.

In the current checkout, `_chain_candidates()` in
[`core/chaining_coordinator.py`](../../../core/chaining_coordinator.py) returns no
routes for `linear_hybrid`. This is an observed implementation distinction,
not evidence that Linear models cannot reason about chains. Before claiming a
graph-guidance comparison on required-chain tasks, provide equivalent allowed
continuation and source use through the shared runtime. Merely removing the
condition check would give Linear AKG routing and erase the intended treatment;
keep the planning policy distinct from the execution capability.

Declare comparable local and chain task groups before observing results. AKG's
advantage must appear in verified outcomes, chain completion, discovery coverage
where measurable, or resource use. Do not tune the goal catalog on held-out study
results, disable useful baseline actions or promise that AKG will win. If AKG
does not improve those measurements, retain and report that finding.

## 5. Outcome rubric

Outcome verification is deterministic where the goal has a machine-checkable
assertion. Use the existing verifier and independent controls; a model's claim,
an HTTP status, a login marker or a route log alone is insufficient.

| Outcome score | Criterion |
| --- | --- |
| **1** | The declared observable objective is independently verified within budget, with the required fixture, identity and execution context. |
| **0** | A valid, assessable task run ends without achieving the objective within budget. This includes a controlled stop or failure before candidate execution when the complete record establishes non-achievement. |
| **null** | The objective cannot be assessed because the relevant experiment or evidence is invalid, missing or unresolved. This is a status, not a third numeric grade. |

Examples of goal definitions are a verified local result, forbidden access to a
specified test object under a declared identity, or a verified new session for
the intended test account. These are definition patterns, not newly validated
endpoints or ready-to-launch tasks. Specify the actual criterion and controls
before freezing a task.

Two boundaries prevent incorrect zeros:

- A known-valid task that produces no executable candidate has **outcome 0**;
  this establishes task non-achievement, not a measured failed exploit or a
  payload mean over an empty denominator.
- Missing oracle/control evidence or an invalid fixture leaves the relevant
  outcome **unavailable**. Do not label that missing evidence model failure.

Provider failure, timeout, interruption and artifact-writing failure retain
their execution status and reason. They support an end-to-end unsuccessful
outcome only when the surviving, valid evidence establishes that the objective
was not achieved. Otherwise the outcome is unresolved. Report infrastructure
reliability separately from any conclusion about the underlying model.

Feasibility must come from independent fixture controls, not from whether the
evaluated model happened to succeed. Do not reclassify a failed feasible task as
infeasible merely because the model generated no source material or selected
an unsuitable method. Independently infeasible or invalid tasks remain visible
in planned coverage and are not silently removed from the dataset.

## 6. Attribution and qualified success

Attribution asks whether the actual successful path supports the declared
permitted mechanism. It does not rank methods or grade the wording of a reason.

| Attribution verdict | Meaning |
| --- | --- |
| `supported` | The executed evidence establishes an allowed method/mechanism and its contribution to the verified result. |
| `rejected` | Sufficient evidence establishes that the claimed attribution is false or the successful path does not satisfy the task's permitted mechanism. |
| `unresolved` | Evidence is insufficient or contradictory, or required interpretation has not been completed. |
| `not_applicable` | No verified successful outcome exists to attribute. Failure causes may still be recorded diagnostically. |

The prospective qualified result follows this truth table:

| Valid outcome | Attribution | Qualified score | Reporting consequence |
| --- | --- | --- | --- |
| 1 | supported | **1** | Verified, attributable task success. |
| 1 | rejected | **0** | Preserve objective achievement; do not count it as qualified success. |
| 1 | unresolved | **null** | Preserve outcome 1; qualified assessment remains pending. |
| 0 | not_applicable | **0** | No attribution review is needed to establish non-achievement. |
| null | unresolved or not_applicable | **null** | Preserve the unavailable reason; do not fabricate failure. |

An invalid task/evidence binding cannot acquire a final qualified score even if
a marker was observed. Keep the raw observation in the artifact and record why
it is not an admissible scored outcome.

Both scores are reported. They are not averaged, multiplied into a stored
ordinal grade, or combined with efficiency/output scores. Logical qualification
determines the second binary result; an outcome of 1 and rejected attribution
does not become partial credit.

Attribution evidence should establish:

1. Which candidate, method, visit and actual request produced the verified
   result, bound to the relevant response/verifier records.
2. That execution remained within the permitted task scope.
3. That the claimed effect came from the executed method rather than an
   unrelated shortcut or already-provided capability incorrectly described as
   newly acquired.
4. For a dependency claim, that the destination consumed the identified source
   material/session and its outcome was independently confirmed.

For discovery tasks, review the actual observed weakness and its executed
mechanism against the permitted scope and trusted fixture evidence. There is no
predetermined vulnerability note or preferred method to match. A later correct
explanation cannot replace evidence of what the run discovered and used.

Initial authenticated DVWA setup is not inherently a shortcut. Legitimate setup
is defined by the task. Reject attribution only when the claimed new result or
dependency was already supplied by that setup, or the actual path violates the
declared criterion. Do not reject all uses of an existing session.

For successful runs, bind attribution to the first independently verified
execution path that achieved the declared goal within budget. Later narrative,
cleaned-up payloads or post-success rewrites cannot retroactively prove that
path. Keep later contradictory evidence visible and apply the frozen
verification policy; an early provisional signal is not a permanent success.

## 7. Review mechanism and limits

Use code-based identity, provenance, scope and evidence checks first. When they
settle attribution under the task's rule, do not require an AI to repeat the
same binary determination merely to produce another receipt.

When interpretation is required, use a focused artifact-based review:

- Give the reviewer the declared task, permitted setup, actual successful
  trajectory and relevant source/evidence excerpts with resolvable references.
- Ask for `supported`, `rejected` or `unresolved`, with a short reason and
  supporting candidate/visit/evidence references.
- Do not supply a reference ranking, preferred strategy or prefilled attribution
  verdict. Do not request an ordinal payload-quality grade.
- Keep the reviewer separate from evaluated-model outcome generation. Freeze
  its configured profile, prompt, response schema and applicable budget.
- Treat model and response text as untrusted evidence. Review uses saved
  artifacts; it must not execute another attack or change the fixture.
- Validate the response schema, evidence references, source hashes, identity
  and chronology with code. A citation's existence does not prove its causal
  interpretation; contradictory reasoning requires resolution or abstention.
- Keep bounded schema-repair attempts separate from substantive reassessment.
  Do not repeatedly seek a positive verdict after rejection.
- Retain requests, responses, usage, decisions and corrections. A refusal or
  unavailable reviewer leaves attribution unresolved, without erasing outcome 1.

The default proposal is code first with one focused review where needed. A
mandatory two-reviewer pipeline has **not** been agreed and is not a prerequisite
for this handoff. If a second review is later required for a disputed case,
document the reason and budget rather than creating universal extra passes.

## 8. Chain metric: applicability, transitions and completion

Chain outcome is reported in its own per-coordinate fields and aggregate
comparison. It is not a third weighted rubric and cannot award bonuses to the
two primary scores.

| Frozen chain mode | Rule |
| --- | --- |
| `none` | No chain objective or measured opportunity was declared. Report chain completion as not applicable. |
| `optional` | A comparable chain opportunity and its completion rule were declared; local goal success does not require completing it. Report chain outcome separately. |
| `required` | The task objective includes the declared dependency and destination result. An incomplete chain cannot satisfy that objective. |

A **verified transition** is a supported dependency from a source visit to a
destination visit: the source produced identified material or state, the
destination actually used it, and the destination result was independently
confirmed. Preserve candidate/visit IDs, secret-safe fingerprints, response
hashes and chronology. Use matched dependency controls where the existing
protocol requires them or where alternative supplied material would otherwise
make the causal claim ambiguous.

The following do not establish a verified transition: scheduling a method,
listing an AKG edge, writing “chain started”, triggering an unused source,
two unrelated successes, or a later explanation asserting a dependency.

Deduplicate transitions by the bound dependency and its source/destination
execution identities. HTTP retries, repeated requests and different labels for
the same dependency do not add transitions. The shared intermediate state must
bind successive transitions in a multi-step chain.

**Completion is task-specific.** If the task requires source → destination,
one verified transition plus the destination objective may complete it. If it
requires source → intermediate → destination, the first transition alone is
insufficient. Do not impose a universal two-transition requirement, or invent
an exact preferred method sequence when multiple permitted paths can satisfy
the declared objective.

For an optional chain task, local outcome 1, qualified score 1 and chain
completion 0 can coexist. For a required chain task, established chain
non-completion means the complete task objective was not achieved. Missing
chain evidence remains unresolved; it is not automatically failure or zero
transitions.

Record `chain_completed` as true, false or null with applicability/status and
reason. Record the number of positively verified distinct transitions; retain
evidence-coverage information. If the entire transition record is missing,
do not manufacture a known count of zero.

### 8.1 AKG optimization workstream

The purpose is to make AKG better at discovering useful opportunities and
completing supported dependencies. Keep the predefined graph static and
prevalidated; update the run's evidence and eligible frontier, not the graph's
ontology or target scope. Reuse existing state, orchestrator, coordinator and
method agents instead of adding another planner service or evaluator hierarchy.

Inspection of the current owners identifies implementation work to assess:

- The orchestrator prompt selects among viable methods but does not yet expose
  the proposed task objective and unmet chain goal as explicit planning inputs.
- `_chain_candidates()` orders enabled edges by static priority and excludes
  attempted, blocked and failed agents; inspect whether a newly acquired source
  can legitimately change eligibility for a previously attempted destination.
- Source-consumption adapters and source/destination evidence checks already
  exist. Improve their actual coverage and binding rather than duplicating them.
- The static graph explicitly marks some routes unsupported. A listed edge is
  not evidence that its source producer or destination consumer exists.

These are code-inspection facts and design concerns, not new test results or
proof that any particular study coordinate is feasible.

| Improvement | Concrete prospective behavior |
| --- | --- |
| Goal-aware frontier | Supply the public objective, unmet milestones, verified observations and remaining budget to the existing planner. Prefer supported actions that can enable the goal over unrelated local confirmations. Route priority is runtime planning, not evaluator reference ranking. |
| Evidence-led discovery | Distinguish an untested hypothesis, a measured prerequisite and a confirmed finding. Use narrowly targeted permitted reconnaissance to resolve unknown prerequisites; never execute an invalid candidate or treat an unknown gate as true. |
| Usable source material | Bind source account, object, credential representation or session to source evidence and context. Match it to a real destination adapter; a password hash is not plaintext and a label is not a reusable session. Do not add out-of-scope recovery methods. |
| Context-aware continuation | Refresh destination prerequisites under the newly acquired identity/session/material before execution. Reconsider a blocked method only when identified new evidence changes its prerequisites, within the frozen visit/retry budget; retain the earlier failure and prohibit unchanged-state retry loops. |
| Alternative permitted paths | When one route is infeasible, consider another supported route to the same objective or a bounded discovery step that could enable it. Stop with a reason when no permitted path remains; do not weaken the fixture or invent an adapter. |
| Source-to-destination proof | Pass material through the shared execution owners, record actual consumption and confirm the destination. Credit completion from those records rather than graph traversal or assumed enabling outcomes. |

Preserve partial updates, monotonic evidence history and candidate provenance.
Recompute current-context eligibility without deleting prior observations or
changing their identities. Confirmed nodes and outcomes must remain distinct;
`credentials_extracted` cannot stand in for `brute_force_confirmed`.

A conceptual chain is newly obtained credentials/session → permitted access
attempt → verified destination result. Both conditions may perform those actions.
AKG should help select and connect them, while Linear may select them without
graph guidance. The actual fixture, usable material, endpoints and controls must
be independently established before declaring this example a feasible task.

Use a declared development set or bounded diagnostics to refine routing. Preserve
those outcomes separately from a frozen evaluation population. No extra live
calls, ablations or repeated study runs are authorized by this workstream's
description. Success thresholds for a future AKG improvement study must concern
real outcomes or efficiency, with retained failures and uncertainty.

## 9. Diagnostics and removal of overlapping grades

| Current quantity | Prospective treatment |
| --- | --- |
| `Smethod` | Retire live ordinal grading. Retain method choices, rejected prerequisites, selection source and adaptation history. |
| `Spayload` | Retire the separate ordinal mean. Retain every proposal's origin, validation, execution status and link to any verified result. |
| `Sexploit` | Replace primary ordinal grading with the declared task outcome. Retain verifier decisions and method-specific evidence. |
| `Schain` | Replace ordinal grading with the declared chain metric and distinct verified transition count. |
| `Soutput` | Replace ordinal grading with valid-output, repair and fallback counts/rates from real call receipts. |
| `Srun` | Retire the weighted composite for prospective primary reporting. Keep historical values under their recorded policy. |
| Reference ranking | Remove prospective grading, readiness and completion dependencies. Keep historical profiles read-only where required to decode their recorded results. |

Removing evaluator reference ranking must not remove payload candidate ordering,
runtime budgeting, static AKG routing, scope checks or prerequisite validation.
These have different responsibilities. Inventory call sites before removing a
module or field that happens to contain “ranking” in its name.

Diagnostic denominators must remain explicit:

- Proposal validity includes captured generated proposals, including rejected
  ones; identify static seeds separately. Do not infer validity from the subset
  that executed successfully.
- Candidate execution/confirmation counts identify the candidate origin and
  measurement population. No candidates means an unavailable rate, not an
  invented payload score.
- Output validity uses required recorded experiment-model calls. Exclude
  evaluator calls; distinguish missing receipts from zero applicable calls.
- Count actual requests, attempts and tokens. Keep target/provider retries and
  reviewer costs visible in their own applicable totals.
- Missing usage or pricing gives unavailable cost with a reason. Do not guess a
  price or turn missing telemetry into zero consumption.

Static seeds can legitimately produce framework success. That success must not
be reported as evidence that an LLM generated an effective payload. Conversely,
do not remove static-origin successes from a hybrid framework's primary outcome
merely because generated-payload contribution is a separate question.

Record finding provenance at the actual contribution boundary:

- Reconnaissance supplied an observation or measured prerequisite.
- A static seed or model-generated candidate produced an executed result.
- A model selected/adapted a method or proposed a hypothesis.
- AKG enabled or prioritized a route using identified evidence.

These contributions can coexist; do not force one exclusive author label or
claim that routing alone discovered the weakness. Preserve the earliest relevant
proposal/measurement and its executed evidence link, without collecting private
model reasoning as a prerequisite.

Keep explicit finding claims from successful and unsuccessful runs. Deduplicate
by the declared finding identity, and mark each supported, rejected or unresolved
using existing verifier evidence or the applicable focused review. An attempted
method is not automatically a finding claim. Report rejected claims and unresolved
counts; missing evidence does not establish a false positive. Finding precision,
when useful, is supported claims divided by supported plus rejected assessed
claims, with unresolved claims reported separately and an unavailable rate for
an empty denominator. Recall requires the independent inventory in section 4.1.

Report time/requests/tokens to the first verified finding and to the declared
goal when available. Preserve budget exhaustion and unsolved runs; a solved-only
efficiency summary must state its selection and denominator. Discovery and
chain diagnostics support the two-check design without becoming new grades.

### 9.1 Resource-reporting gaps

The owner wants resource measurements alongside outcome and attribution, with
per-model detail and a per-run total. They remain separate measurements, with
units and availability; they do not become weighted rubric components.

Source inspection on 2026-11-09 confirms existing support for whole-run elapsed
time, experiment input/output/total tokens, price-schedule-based cost, physical
target-request/retry counts, provider-request summaries, summed model-call
duration, cache-read statistics and response-cache reuse. See
[`evaluation/research_metrics.py`](../../../evaluation/research_metrics.py),
[`evaluation/runner.py`](../../../evaluation/runner.py),
[`llm/runtime.py`](../../../llm/runtime.py) and
[`llm/cache_metrics.py`](../../../llm/cache_metrics.py). These collectors and basic
calculators are not new implementation tasks. This inspection establishes code
presence, not successful collection for every provider or a fresh validated run.

Only the following gaps belong in the prospective resource work list:

| Missing or incomplete behavior | Work to complete using the existing owners |
| --- | --- |
| Compact per-model and per-run resource report | Add one task-run projection containing elapsed time and a breakdown by actual provider/model for estimated cost, input/output tokens, cache-read/write tokens, physical LLM requests and cumulative request latency. Include every experiment model, preserve role/route identity, and derive compatible totals once. Existing summaries are mainly by role or method and do not publish this complete bundle. |
| Explicit cache-token quantities in that report | Publish cache-read and cache-creation/write quantities with independent availability from retained native usage. Existing cache rates and internal cost accounting do not provide both as first-class research metrics. Normalize provider semantics; do not add cached tokens to an input total that already includes them or assume an unreported write count is zero. |
| Physical-request latency definition | Distinguish existing logical-call duration from elapsed time spent in actual provider requests. Reuse complete attempt records for cumulative API latency and its request denominator; keep backoff, response-cache lookup and hidden SDK retries distinct. If physical latency is not captured, expose the known logical duration under its actual label rather than claim an exact API-latency measurement. Never subtract summed concurrent durations from run elapsed time to infer measured overhead. |
| Time and resource use to meaningful milestones | Bind the first independently verified finding, declared goal and completed chain to elapsed time and captured request/usage snapshots. Whole-run timing and candidate attempts-to-success already exist; they do not establish these milestone measurements. A delayed reviewer verdict must not extend the attack's time-to-goal. Unsolved runs retain elapsed time, consumed resources and the stop reason; time to an unreached milestone is null with a not-reached status, while established task non-achievement remains outcome 0. |
| Task-based cost per success | Aggregate each run's experiment cost once, including known expenditure on unsuccessful runs, then report cost per verified goal success and per qualified task success separately. Existing candidate-based `token_cost_per_success` and legacy `security_outcome` diagnostics are not the new task-goal denominators. Zero successes means an unavailable ratio with a reason; unresolved assessments and incomplete cost coverage stay explicit. |
| Independent availability for time, requests, tokens and cost | Remove the all-or-nothing dependency in the prospective efficiency adapter. Currently `_efficiency_record()` in `evaluation/research_diagnostics.py` requires cost as well as non-cost measurements, so missing pricing hides otherwise known telemetry from its efficiency rollup. Retain each metric's measured subtotal, coverage and reason independently; missing cost must not erase time or requests. |
| Accounting identity through aggregation | Preserve currency, price-schedule hash, billing route and estimate/billing basis when adapting and aggregating costs. The current efficiency adapter retains a scalar cost and its rollup labels cost per success in micro-USD without carrying that identity. Partition incompatible accounting bases/currencies or explicitly label a permitted mixed estimate; do not describe a list-price estimate as an invoice charge. |
| Separate attribution-review overhead | Reuse saved reviewer usage/metadata to publish assessment time, requests/tokens and estimated cost separately from experiment-model resource totals. The prospective reviewer-to-resource-report integration is not implemented. Do not count evaluation-model usage as agent expenditure or require a review when code already settles attribution. |

Use the existing price schedule and actual configured route/model identities.
A missing model price is a configuration/evidence availability issue, not a
reason to rebuild the cost calculator or invent a charge. State unpriced models
and missing usage explicitly. A known-priced subtotal can be shown with its
coverage; it is not a complete total when other expenditure is unknown.

Default reporting should remain compact: one row per task run with outcome,
attribution/qualified status, chain result, elapsed time, cost, tokens and
requests, plus the linked per-model breakdown and optional milestone details.
The table above specifies future implementation work only; no resource collector,
metric, reporting behavior or validation result was changed by this note.

## 10. Aggregation, denominators and statistical analysis

Maintain a coverage ledger for all planned coordinates, including invalid,
unstarted, failed, interrupted and unresolved cases. Keep execution status,
task validity, outcome assessment and attribution status distinct.

Report per comparison group:

1. Planned, started and execution-status counts.
2. Task-validity and assessment coverage.
3. Verified outcome successes, established non-achievements and unresolved
   outcome assessments.
4. Qualified successes, attribution rejections and pending qualified assessments.
5. Chain applicability, completion status and verified transition counts.
6. Efficiency and process diagnostics with their own denominators.
7. Discovery objective, finding provenance, supported/rejected/unresolved claim
   counts and any independently justified coverage denominator.

For a complete, valid task-run population, outcome-success rate is the count of
outcome 1 divided by the declared valid task runs; qualified-success rate uses
qualified score 1 over that same population. If some valid runs remain
unresolved, show that count and identify the fraction as **confirmed success
coverage**, a lower bound on the eventual success rate. Do not label all remaining
runs failures or silently omit them to inflate a success percentage. A separately
reported assessable-only rate must state its smaller denominator and the missing
assessment distribution across groups.

Chain comparison uses the predeclared comparable chain-applicable population,
not only routes the model chose to attempt or runs that generated useful source
material. Report optional and required chain tasks separately when their goals
differ. Empty applicable populations have unavailable rates with a reason.

Aggregate compatible model/condition/task/level groups within a declared
policy/fixture epoch. Do not pool different goals, review policies, fixtures,
budgets or incompatible source epochs because they share a model name. Preserve
every repeat; no best-repeat selection or outcome-seeking rerun loops.

The previous six-ordinal-outcome analysis family and legacy F3 component
denominator do not automatically apply to two binary results. Declare the
prospective analysis endpoints, comparison units, repeat handling and any
multiple-comparison treatment before a new analysis. Use methods appropriate to
the binary results and actual design. Do not interpret non-significance as
equality. Keep old analyses and F3 numerators/denominators immutable; fewer
prospective score dimensions are not evidence that historical explanation gaps
were resolved.

## 11. Compact result and evidence contract

Reuse the existing artifact writer and source/plan/fixture binding owners. Add
the smallest result projection that supports the preceding definitions. Avoid
parallel finalizers, duplicate score vectors or a new hierarchy of receipts for
each diagnostic.

Minimum prospective projection:

| Field group | Contents |
| --- | --- |
| Identity | Coordinate/execution/repeat identity and source artifact hash; frozen task and policy digests; fixture/plan identity. |
| Validity and execution | Existing execution status plus task-validity/assessment reason. |
| Outcome | 0, 1 or null; goal-verification evidence references and reason. |
| Attribution | Verdict, supporting execution/candidate/visit references, reason and review provenance when used. |
| Qualified result | 0, 1 or null, derived by the declared truth table. |
| Chain | Frozen mode/rule, completion status, distinct verified transition count and references. |
| Discovery | Public-brief digest and declared goal; finding claims, provenance and assessment evidence references; hidden-reference binding without answer disclosure. |
| Comparison | Condition's declared capabilities/knowledge, planner policy and common budget/reconnaissance bindings. |
| Diagnostics | Existing measured counts/usage/rates or references to their owning telemetry. |
| Chronology | Task/policy freeze, execution, verification/review and result-publication times. |

The fields above are a proposed contract outline, not an implemented schema.
Prefer deriving duplicated summaries from the same evidence owner. Preserve raw
observations and references even if the final result is unavailable.

The expected result/answer must not leak into the evaluated model's context
through a scoring profile, diagnostic output or review artifact. Keep any
required secret comparison in the trusted verifier and preserve secret-safe
evidence. The reviewer cannot supply missing runtime proof or grant target scope.

## 12. Owning code and consumer inventory

Paths below identify the current checkout's owners. Recheck them when work starts;
do not create a second implementation under a versioned or “latest” name.

| Responsibility | Current owners to inspect |
| --- | --- |
| Task plan, declared coordinates and freeze | `evaluation/research_plan.py`, `tesis/config_loader.py`, applicable runner/config templates. |
| State and runtime result production | `core/state.py`, `core/scorer.py`, `core/graph_builder.py`, method agents and chaining coordinator. |
| Discovery, method selection and context | `foundation/recon.py`, `agents/orchestrator.py`, `llm/prompts/orchestrator_prompt.py`, payload prompt/context builders and `foundation/preconditions.py`. |
| Static guidance and material handoff | `core/knowledge_graph.py`, `core/chaining_coordinator.py`, relevant method agents and session/payload owners. |
| Verification and controls | `foundation/verifier.py`, `foundation/control_catalog.py`, `foundation/preconditions.py`, `evaluation/permission_oracle.py`, `evaluation/session_oracle.py`. |
| Current grading/finalization | `evaluation/thesis_scoring.py`, `evaluation/scoring_evidence.py`. |
| Metrics, diagnostics and analysis | `evaluation/research_metrics.py`, `evaluation/research_diagnostics.py`, `evaluation/research_analysis.py`, applicable audit/report owners. |
| Artifact publication and discovery | `evaluation/reporter.py`, `evaluation/observer_reviews.py`, observer export/projection and artifact catalog owners. |
| CLI/TUI and read-only consumers | `tesis/` review/results paths and the existing external observer bridge/contract. |

Inventory live producers, validators, CLI/TUI fields, templates, profile loading,
readiness requirements, exports, reports, analysis endpoints and tests that assume
five numeric components or a nonempty payload denominator. Migrate them together.
Preserve `tesis.tui` as the public TUI facade and
`tesis.tui_state.CONFIG_PATH` as the shared configuration-path owner.

An isolated derived-assessment worktree was used earlier in this conversation
at `/home/kevin/.t3/worktrees/tesis/t3-f4f53f69`. Its later files and evidence are
not automatically present in this repository root. If that work is needed,
inspect its source state and explicit integration boundary; do not overwrite
either checkout or copy results wholesale into a different epoch.

Any current special-case no-method scorer must be inventoried during cutover.
Retain its historical receipts and necessary read-only decoding; retire obsolete
live writers rather than forwarding prospective requests through an old scorer.

## 13. Historical compatibility and documentation

- Preserve all source artifacts, failed attempts, decision histories, profile
  digests, receipts, old composites and checkpoint identities.
- Historical evaluation is read-only under its recorded rules. Do not execute
  obsolete scorers, patch old freezes or relabel an old result as prospective.
- A saved-artifact derivation under these definitions is a separate retrospective
  analysis bound to its sources and interpretation policy. It is not a new
  execution or preregistered result.
- Missing historical goal/chain declarations cannot be filled as if they were
  frozen before execution. Leave the relevant prospective-style assessment
  unavailable, or describe an explicitly retrospective question and its limits.
- Keep historical human/AI reviewer identities and all independent decisions.
  Do not blend components or review workflows from separate receipts.
- Do not silently turn a historical no-method composite into a prospective
  score. A supported new task non-achievement derivation has its own policy,
  source binding and retrospective label.
- Update `AGENTS.md` prospectively when implementation is authorized, together
  with both language summaries, scoring reference and affected architecture
  docs. Explain the replacement of current grade/weight obligations explicitly.
- Update current CLI/TUI/export/report descriptions and the active handoffs made
  inaccurate by the cutover. Keep dated evidence history separate from live
  instructions; do not accumulate contradictory current status paragraphs.
- A future DOCX revision must update the relevant metric/rubric tables,
  composite/missing-data paragraphs, task and chain definitions, evaluator role,
  artifact protocol and statistical analysis. Perform it only when requested.

Use one descriptive, unversioned implementation and contract for each
responsibility. Dates and content hashes identify prospective bindings. Do not
introduce sequential rubric/scorer/schema names or executable forwarding aliases.

## 14. Implementation phases and task-scoped verification

### Phase A — settle the executable specification

- [ ] Inventory current producers/consumers and the isolated-worktree boundary.
- [ ] Define concrete local goals and chain modes/rules for each planned task.
- [ ] Establish independent fixture feasibility and the permitted initial state.
- [ ] Separate public discovery briefs from private references and define finding
  identity, provenance, coverage and unsupported-claim reporting.
- [ ] Inventory actual Linear/AKG capabilities and declare whether the comparison
  isolates graph guidance or compares complete packages.
- [ ] Specify supported goal-relevant AKG routes, material adapters, destination
  refresh and bounded reconsideration when genuinely new evidence is available.
- [ ] Recheck the section 9.1 resource gaps against actual producers; define the
  per-model report, physical-latency/milestone boundaries and cost populations
  without duplicating existing telemetry collectors.
- [ ] Finalize the truth table, attribution criteria and review policy.
- [ ] State the comparison design, budgets, repeats and analysis endpoints.
- [ ] Resolve section 15 decisions without inventing runtime evidence.

### Phase B — coordinated prospective cutover

- [ ] Extend the owning plan/config contract with frozen task goals and rules.
- [ ] Implement outcome verification/projection using current verifier evidence.
- [ ] Implement attribution and qualified-result derivation in the owning path.
- [ ] Publish chain applicability/completion and deduplicated transitions.
- [ ] Implement the public/private context boundary and finding-provenance
  diagnostics using existing evidence owners.
- [ ] Provide common allowed continuation/material-use capabilities for a
  graph-guidance comparison while keeping condition-specific planning distinct.
- [ ] Optimize AKG's goal-aware frontier, usable source binding, destination
  prerequisite refresh and evidence-triggered reconsideration within frozen budgets.
- [ ] Complete only the missing resource projection, cache quantities, latency/
  milestone reporting, task-success denominators and independent metric
  availability in section 9.1; retain accounting identity and separate review cost.
- [ ] Remove live reference-profile and ordinal-grade requirements from affected
  prospective launch, review, finalization and reporting paths.
- [ ] Preserve runtime ordering, prerequisite validation and containment.
- [ ] Migrate CLI/TUI, observer projection, diagnostic/analysis and export consumers.
- [ ] Keep historical readers explicit and read-only; remove obsolete write paths.
- [ ] Update current documentation and repository instructions together.

### Phase C — focused behavioral verification when requested

Follow the user's verification scope and repository `AGENTS.md`. Prefer existing
affected checks; add a test only for concrete behavior not already covered.
Useful acceptance cases for this cutover are:

| Case | Expected behavior |
| --- | --- |
| Verified local goal and supported attribution | Outcome 1; qualified 1; evidence bound to the source. |
| Verified goal and rejected attribution | Outcome 1 remains; qualified 0; no averaged score. |
| Verified goal and unresolved/failed review | Outcome 1 remains; qualified null with a reason. |
| Completed feasible run with no selected method/candidate | Outcome 0; qualified 0; no invented payload mean or reviewer call. |
| Invalid fixture or missing outcome controls | Outcome/qualified null; validity reason retained. |
| Valid output with unsuitable method choice | Formatting diagnostic can pass while task outcome is 0. |
| Permitted alternative method with no ranking profile | Success can finalize when actual goal and attribution are supported. |
| Static-origin verified result | Framework success retained; generated contribution not invented. |
| Public task context and private fixture reference | Agent context contains no hidden expected finding, privileged control output or solved route; observed permitted responses remain available. |
| Autonomous task versus explicit target-method diagnostic | Method selection is free within declared scope for the former; historical/diagnostic identities are preserved for the latter. |
| Different permitted Linear/AKG paths achieve the same goal | The same outcome, attribution and chain rules apply to both. |
| Linear continuation in a graph-guidance comparison | Shared tools can consume newly acquired material and execute a supported destination without automatic AKG route selection. |
| Newly acquired material changes a prior destination gate | A bounded reconsideration is possible with fresh context evidence; unchanged-state failures cannot create retry loops. |
| Claimed source has an unusable representation or wrong identity | No fabricated dependency or destination capability; retain the rejection reason. |
| Recon/model/static/graph contributions and unsupported claims | Each contribution retains its own evidence link; rejected and unresolved claims remain visible across all runs. |
| Optional chain incomplete, local objective achieved | Local success can remain 1; chain outcome reported separately. |
| Required chain only partly completed | Complete task cannot receive success 1. |
| Duplicate transition records or retries | Distinct verified count does not increase. |
| Missing chain evidence or zero applicable tasks | Unresolved/not-applicable reporting; no fabricated zero rate. |
| Mixed epoch, task rule or source identity | Refuse misleading pooled results; preserve coverage/reasons. |
| Historical receipt or checkpoint | Original identity and values stay intact; no obsolete scorer execution. |
| Missing price/usage | Cost remains unavailable, not zero. |
| Missing model price with valid time/request/token telemetry | Non-cost metrics remain visible with their own coverage; only cost is unavailable. |
| Multiple models, retries and cache reuse | Per-model resource totals conserve compatible quantities without double-counting parent/attempt usage or cached tokens. |
| Concurrent calls and delayed attribution review | Run elapsed time, physical/logical API durations and review overhead remain correctly distinguished. |
| Unsuccessful or unresolved task with recorded expenditure | Known expenditure remains in the declared resource population; task-cost-per-success uses the new goal/qualified denominator. |

Run `.venv/bin/python -m tesis.naming_guard` after a coordinated source cutover
and before a final prospective source/policy freeze. Reuse unchanged validation
evidence within its actual scope; renew only evidence invalidated by changes.
Required E2E coverage must be explicitly requested before execution. Do not
interpret this case table as authorization for E2E, live target/provider calls,
an expanded suite or a research matrix.

### Phase D — reviewable reporting and research adoption

- [ ] Produce a compact source-bound result/report demonstrating the agreed
  semantics through the requested validation scope.
- [ ] Reconcile all requested checks, including skipped/blocked ones.
- [ ] Record legitimate historical-derived analysis separately where evidence
  suffices; keep historical acceptance and unresolved explanations unchanged.
- [ ] For an authorized fresh study, freeze tasks, fixture, policy, reviewer,
  model roles, budgets and analysis before execution; establish affected readiness.
- [ ] Execute only the separately authorized study scope. Preserve every
  coordinate/repeat/status and prevent outcome-seeking reattempts.
- [ ] Move this handoff to `docs/active/` when implementation starts, and to
  `docs/completed/` only when its implemented contract and task-scoped requested
  checks are evidenced. Update links when moving it.

A software cutover can be complete without a new research matrix when the agreed
maintenance scope ends there. A requested research acceptance remains incomplete
when its own required evidence is missing. Do not conflate these completion units.

## 15. Decisions still needing concrete specification

These are unresolved details, not reopened questions about the agreed direction:

Use the current authorized study configuration for unchanged models, budgets,
repeats and runtime settings. Resolve routine implementation choices from the
owning code and recorded decisions. This table is not a request for repeated
execution approval; seek owner clarification only for a material scope or
methodology choice that the available context cannot settle.

| Decision | Resolution needed before its dependent work |
| --- | --- |
| Goal catalog | Exact observable goals and fixture controls for the supported task cells. |
| Discovery specification | One-finding, operational or coverage goals; agent-visible brief, private-reference isolation, finding matching and claim denominators. |
| Comparison estimand | Graph-guidance or whole-system comparison; common capabilities/knowledge and any declared differences. |
| AKG development scope | Feasible goal-relevant routes and adapters, context refresh/reconsideration rules, development/evaluation separation and requested validation scope. |
| Resource reporting | Exact per-model/run projection, milestone boundaries, physical latency availability, accounting units and task-success cost denominators; reuse current collectors. |
| Chain assignment | Which cells have `none`, `optional` or `required` mode; exact destination/dependency completion rules and independent feasibility. |
| Attribution acceptance | Which facts code can settle, which cases require interpretation and what constitutes conclusive rejection versus unresolved evidence. |
| Reviewer policy | Preserve the applicable selected reviewer profile; specify trigger, evidence format and bounded attempt policy. No universal second reviewer is assumed. |
| Failure classification | Which surviving failure/interruption records establish task non-achievement and which remain unassessable. |
| Analysis population | The compatible task/epoch grouping, repeat treatment, reporting denominators and prospective endpoints. |
| Study design impact | Whether task assignment fits the existing coordinate design or creates a separately declared factor; no additional matrix is assumed. |
| Artifact adoption | How current consumers expose prospective fields and read old receipts without running old write paths. |
| Manuscript scope | Which documentation changes are authorized during implementation; DOCX editing requires an explicit request. |

## 16. Acceptance and handoff output

The future implementation report must state what changed, why, source/task/policy
bindings, requested verification commands/results and artifact paths. It must
separate implemented behavior, offline validation, retrospective analysis and
live execution, with remaining blockers and their exact recovery action.

Minimum acceptance checklist:

- [ ] Two binary results and attribution statuses follow the declared truth table.
- [ ] Goal achievement is not erased by unresolved attribution or awarded from
  unsupported model claims.
- [ ] Prospective scoring has no reference-ranking or five-grade composite dependency.
- [ ] Scope, prerequisites, payload validation and HTTP containment remain enforced.
- [ ] Task goals, initial state, budgets and chain rules are frozen and shared
  across comparable model/condition/repeat cells.
- [ ] Private fixture answers and solved routes are absent from evaluated-agent
  context; observed discoveries and their provenance are retained.
- [ ] Autonomous and forced-method tasks are correctly identified; scoped
  assessment is not presented as unrestricted discovery.
- [ ] The comparison's capability/knowledge contract is explicit; a claim about
  graph guidance uses equivalent permitted continuation and source-use tools.
- [ ] AKG improvements use verified prerequisites and usable source material,
  refresh destination context and bound reconsideration to changed evidence.
- [ ] Scoring accepts permitted Linear and AKG paths equally; no baseline
  handicap, post-result task selection or graph-consultation bonus is introduced.
- [ ] Chain completion reflects the declared dependency and final objective;
  repeated logs/requests cannot inflate transition counts.
- [ ] Candidate origin separates framework success from generated contribution.
- [ ] Diagnostic empty/missing data remains unavailable where required.
- [ ] Resource reports conserve compatible per-model/run totals, distinguish
  physical requests and call duration, and keep non-cost metrics when pricing
  is unavailable. Cost denominators reflect task success and retain accounting
  identity; assessment overhead is reported separately.
- [ ] Reporting includes all planned outcomes and explicit valid/assessable
  denominators, unresolved counts and chain applicability.
- [ ] Finding claim/provenance diagnostics include rejected and unresolved claims;
  any recall denominator is independently established.
- [ ] Result/decision provenance and chronology are validated; historical evidence
  remains immutable and incompatible epochs are not pooled.
- [ ] Producers and consumers use one canonical current contract; obsolete
  scorers are not reachable through prospective write paths.
- [ ] Required naming and requested behavioral checks are evidenced; unrun
  requested checks are explicitly incomplete.
- [ ] Both language references and affected architecture/scoring/UI descriptions
  reflect the actual cutover. Requested manuscript changes are verified separately.

### Planning deliverable status

- [x] Owner-agreed direction captured in an upcoming handoff.
- [x] Binary results, attribution, task-specific chain rules and diagnostic roles specified.
- [x] Historical, containment, migration and verification boundaries documented.
- [x] Owner-approved discovery adjustments and capability-based AKG optimization
  workstream recorded, including architecture-neutral comparison requirements.
- [x] Additional resource metrics reviewed against current owning code; only
  missing resource reporting/behavior added to the prospective work list.
- [ ] Runtime/configuration/evaluator implementation: **not started by this task**.
- [ ] Software tests and E2E validation: **not run by this task**.
- [ ] New experiment or prospective study freeze: **not performed by this task**.
- [ ] DOCX revision, commit, push or deployment: **not performed by this task**.
