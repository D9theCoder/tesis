# Handoff: model-directed prerequisite probing

Date: 2026-11-09 (Asia/Jakarta)
Kanban: **Upcoming**
Status: **Brainstormed direction recorded; implementation not started.**
Deliverable: an implementation handoff. Creating this document does not change
runtime behavior, current methodology, configuration, experiment inputs or scores.

Companion:
[Outcome and attribution evaluation](HANDOFF_OUTCOME_AND_ATTRIBUTION_EVALUATION_2026-11-09.md).
This handoff owns prerequisite investigation and model/tool interaction. The
companion owns outcome/attribution reporting, chain metrics, resource reporting
and the prospective evaluation cutover. Coordinate their shared discovery,
evidence, budget and comparison contracts without creating duplicate planners.

## 1. Intended change

Give the evaluated model responsibility for choosing what to investigate, which
approved probe to request, and what to investigate next from the measured result.
Reuse the existing coded tools and initial predefined probe catalog.

The model controls investigation decisions. Tools execute requests and collect
measurements. Evidence-based code determines whether prerequisites and outcomes
are supported. An unsupported model assertion cannot set a prerequisite to true.

The owner requested this handoff after clarifying the following direction:

- Replace the fixed investigative sequence with model-directed use of existing
  approved reconnaissance/probe capabilities.
- Let the model choose the prerequisite, supported tool, order and follow-up.
- Initially retain predefined probe templates and their validation rules.
- Retain deterministic HTTP/session handling, measurement, verification,
  containment, budgets and evidence integrity.
- Support the same permitted investigation/execution tools for Linear and AKG;
  AKG supplies structured guidance about useful missing prerequisites and chains.

No implementation, new experiment, provider/target call, DOCX change, commit,
push or subagent work is requested by this documentation task. The remaining
specification choices in section 10 are open; they are not implied by the
high-level agreement.

## 2. Current behavior and owning code

The current reconnaissance is automated human-written code, not a human probing
the target during each run. It performs substantial investigation for the model:

- Establishes a DVWA session, sets/observes security level and crawls navigation.
- Extracts forms, parameters, tokens and declared handlers from fetched pages.
- Selects fixed catalog controls and invokes method-specific prerequisite probes.
- Records scoped observations, readiness and prerequisite status.
- Supplies those observations to method selection.

AKG selection currently filters methods to prerequisites measured as true.
Linear receives the canonical surface method list; execution gates still apply.
The gate rejects measured-false prerequisites and permits an unknown one only
when an approved detection control can measure it. A forced `target_method`
bypasses model method selection and keeps its diagnostic identity.

Current owners, inspected during the prerequisite discussion:

| Responsibility | Source to reuse |
| --- | --- |
| Reconnaissance, page/input discovery and initial/destination measurements | [`foundation/recon.py`](../../../foundation/recon.py) |
| Approved detection controls, safe replacements, validation and quarantine | [`foundation/control_catalog.py`](../../../foundation/control_catalog.py) |
| Scoped observation history and true/false/unknown derivation | [`foundation/preconditions.py`](../../../foundation/preconditions.py) |
| Session, level, endpoint and token readiness | [`foundation/readiness.py`](../../../foundation/readiness.py), `foundation/session_manager.py` |
| Model decisions and prompt context | [`agents/orchestrator.py`](../../../agents/orchestrator.py), `llm/prompts/orchestrator_prompt.py` |
| Eligibility, visits and stopping | [`core/workflow_policy.py`](../../../core/workflow_policy.py) |
| Static prerequisites, graph relationships and chain handoff | [`core/knowledge_graph.py`](../../../core/knowledge_graph.py), [`core/chaining_coordinator.py`](../../../core/chaining_coordinator.py) |
| Topology, state and method execution | `core/graph_builder.py`, `core/state.py`, `agents/sqli/`, `agents/access_control/`, `agents/brute_force/` |

Code inspection is not fresh behavioral validation. Recheck relevant owners when
implementation starts; preserve the shared worktree's unrelated changes.

## 3. Prerequisite inventory and responsibility

### 3.1 All currently declared method prerequisites

Eight unique keys cover the nine supported methods. Their present meanings and
gates remain in force until a separately specified coordinated change.

| Method | Existing prerequisite | Current measurement |
| --- | --- | --- |
| `sqli_union` | `union_select_possible` | Predefined UNION probe response contains a recognized signal. |
| `sqli_error` | `error_messages_enabled` | Syntax-breaking probes expose a recognized database-error signal. |
| `sqli_boolean_blind` | `response_diff_detectable` | Paired truthy/falsy probes return the expected distinguishable responses. |
| `sqli_time_blind` | `response_delay_measurable` | Delay probes exceed a measured baseline by the configured threshold. |
| `ac_idor` | `object_ids_enumerable` | Safe object controls establish addressable record behavior; this does not prove unauthorized access. |
| `ac_vertical_escalation` | `role_based_access_present` | Matched admin/non-admin controls establish a role boundary under a frozen permission protocol. |
| `ac_force_browse` | `force_browse_endpoints_visible` | A predefined path produces the recognized policy/access signal. |
| `bf_dictionary` | `no_rate_limit` | Bounded benign login probes measure throttling/delay indicators. |
| `bf_spray` | `no_rate_limit` | Method-scoped bounded benign login probes measure throttling/delay indicators. |

Measured status is true, false or unknown. A finite probe's negative result is
evidence about that measurement, not proof that every possible strategy fails.
Missing, failed or inapplicable measurements must not become false facts.

### 3.2 Setup, investigation and trusted references

| Task | Prospective responsibility |
| --- | --- |
| Target allowlist, authorized starting access and requested level | Operator/harness fixes the task; code verifies setup. |
| Fixture identity, restoration/isolation and comparison controls | Trusted experiment harness; not model-created attestations. |
| Page, form, handler and parameter extraction | Existing deterministic tools extract observations; the model chooses which permitted observations to investigate. |
| Cookie and required form-token handling | Existing session/transport tools. Normal token handling does not authorize a new attack surface. |
| Which prerequisite to investigate and which approved probe to request | Evaluated model, assisted by AKG guidance in its condition. |
| HTTP execution, response/timing measurement and scope enforcement | Existing deterministic tools and client. |
| Interpretation for the next planning decision | Model hypotheses informed by measured observations. |
| Authoritative prerequisite facts and final outcome proof | Evidence-based code, with focused interpretation review under the companion policy when needed. |
| Hidden ownership, permission, credential and positive-reference knowledge | Trusted verifier; never expose the answer key as the model's discovery. |

Split minimal experiment setup from investigative discovery. Initial login and
level verification must not run all method probes as a hidden preparation step
before giving control to the model. Conversely, an ordinary parsing or session
operation need not become an extra model call merely to appear autonomous.

For vertical applicability, the private matched-control protocol needs a clear
boundary: its result may validate task/claim evidence, but privileged reference
observations must not silently supply the model's investigation or chain state.
Specify agent-visible facts and evaluator-only facts before implementation.

### 3.3 Chain prerequisites and completion proof

Retain supported-route checks, verified source evidence, usable material of the
right representation/identity, implemented destination consumers, applicable
destination prerequisites and remaining budget.

Existing consumer mappings cover authenticated-session/brute-force sources to
IDOR/forced browsing, and extracted credentials to dictionary brute force.
Credential consumption requires usable data; a password hash is not plaintext.
Current AC session routes require the appropriate non-admin source identity.

The model may choose to measure an unknown destination prerequisite after a
source result. Record the source/context that motivated that measurement.
Actual source consumption and independently verified destination success remain
required to claim a completed transition, under the companion task-specific rule.

## 4. Proposed interaction contract

Expose a small validated interface over existing functions. The initial tool
catalog remains predefined, source-bound and shared across compared conditions.
The presence of a helper function today does not mean it is already callable by
the evaluated model; the adapter and action/response contract are upcoming work.

The model should be able to request:

1. Inspection of a permitted page/input using existing discovery capabilities.
2. Measurement of a named prerequisite using an approved catalog probe group.
3. Selection of an eligible method after the relevant evidence is available.
4. A controlled stop when no permitted useful action remains or budget is spent.

Requests identify the intended tool/prerequisite and allowed endpoint/context,
with bounded arguments and a short planning reason where useful. The tool layer
resolves approved probe IDs and session handles rather than accepting arbitrary
HTTP code or model-authored observations. Do not require private model reasoning.

Each returned measurement binds the requested action to actual execution status,
applicable observation facts, evidence references, context identity and resource
use. Failed transport, malformed requests and skipped measurements are explicit.
Present a compact result and allow retrieval of relevant saved excerpts rather
than copying the whole trajectory into every prompt.

The model can request another supported measurement or choose its next method.
It cannot overwrite measurements, bypass rejected candidates or mark a route
complete by assertion. Initially, no arbitrary model-generated probe templates,
new methods, unrestricted shell tools or new attack surfaces are introduced.

## 5. Runtime integration and limits

Extend the existing canonical owners rather than add a parallel reconnaissance
implementation, planner hierarchy or scoring workflow.

- Keep the orchestrator responsible for decisions, not direct HTTP execution.
- Dispatch approved measurements through the foundation/tool execution owner.
- Preserve verification inside method agents through `foundation/verifier.py`;
  no standalone verifier graph node is introduced by this proposal.
- Decide how the discovery action cycle fits the existing graph and checkpoint
  model before coding. Any needed topology/public-state change must be explicitly
  documented and migrated with its producer/consumer contracts.
- Preserve partial updates, immutable observation history, scoped current facts,
  candidate provenance and method/visit identity.
- Preserve scope and payload/client containment, including every redirect hop.
- Keep known-false and unknown distinct. A missing prerequisite must not make
  the discovery action itself unreachable merely because exploit selection is
  filtered to true prerequisites.
- Bound repeated probes by action/context identity and the declared budget.
  Reconsideration after new source material must identify the changed evidence;
  unchanged-state repetition must not create an outcome-seeking loop.
- Retain failures and controlled stops. A model refusal, invalid tool request or
  provider failure cannot silently invoke the entire old recon script as if it
  were the model's investigation. Any permitted fallback must be explicit and
  attributed under the frozen policy.

Current method agents may remeasure prerequisites internally. Inventory this
behavior to prevent duplicated probes after a model-requested measurement.
Reuse valid context-bound facts where permitted; refresh only when the context,
evidence applicability or declared verification policy requires it.

## 6. Fair Linear/AKG comparison and research claims

Both conditions receive the same permitted tools, initial task brief, access,
common observational data, validation rules and budgets. AKG supplies general
structured prerequisite/dependency guidance; it must not contain per-fixture
confirmed weaknesses or successful answers before execution.

Permit Linear to discover and consume the same source material and continue to
the same supported destinations without automatic graph-directed selection.
If capability differences are deliberately retained, label the comparison as
whole-system rather than evidence isolating graph guidance.

The model's extra agency should be visible in its requested investigations,
ordering, evidence-based follow-up and selected execution. Tool-authored probes
remain tool-authored; model selection of one does not establish that the model
invented the probe. Separate model-directed discovery from independent payload
generation and from deterministic setup/control contributions.

Keep framework success, generated-candidate contribution and graph guidance
separate in provenance. Do not remove legitimate static-origin hybrid successes
or change primary payload modes merely to increase the claimed model share.
Describe discovery within the predefined DVWA surface/method scope accurately;
the proposed control does not establish unrestricted discovery or no prior knowledge.

## 7. Evaluation, evidence and resource integration

Use the companion's outcome and attribution checks. Do not introduce a separate
ordinal prerequisite grade, reference ranking or bonus for consulting AKG.

Record each discovery action's model origin, selected tool/probe, endpoint,
method/prerequisite, context, actual request/response evidence, resulting facts,
failure/stop reason and resource measurements through the existing artifact writer.
Link enabling observations to the later candidate/visit and destination use.

Charge model-directed investigation to the declared run's request/time/token
budgets. Reuse implemented counters and cost calculators; complete only the
missing reporting in the companion resource section. Keep setup/control and
review overhead distinct, with declared accounting boundaries.

Unattempted probes are not failed probes. A complete feasible task that stops
without achievement can receive outcome 0, while an unmeasured prerequisite
remains unknown. Infrastructure failure and missing evidence retain their actual
status; they cannot automatically establish model failure.

## 8. Implementation sequence

- [ ] Define the minimum setup, agent-visible observation contract and private
  control boundary, especially for matched role/permission references.
- [ ] Inventory existing probe groups, callable helpers and internal re-probing.
- [ ] Specify a compact shared action/result schema and graph/checkpoint integration.
- [ ] Expose existing approved investigation functions through validated tools.
- [ ] Replace automatic bulk prerequisite probing with model-directed dispatch
  for the declared prospective discovery policy.
- [ ] Make unknown-prerequisite discovery reachable in both conditions while
  preserving method execution gates and condition-specific planning.
- [ ] Bind observations, source changes, budgets and tool provenance to existing
  state/artifact owners; implement bounded reuse/refresh/reconsideration.
- [ ] Integrate with the companion's task, attribution, chain and resource contracts.
- [ ] Update `AGENTS.md`, both language references and affected architecture,
  prompt, CLI/TUI/export descriptions during the authorized coordinated cutover.
- [ ] Preserve historical artifacts, hashes, epochs, forced-method identities,
  receipts and old scoring semantics; no cross-epoch statistical pooling.

## 9. Acceptance behavior and verification scope

Future task-scoped acceptance should establish:

- [ ] The model selects a permitted investigation and only its approved probe
  group executes, with an action-to-measurement evidence link.
- [ ] An unknown prerequisite is investigable without being asserted true.
- [ ] The model receives measurements and can select a supported follow-up;
  false facts, unsupported assertions and skipped probes are not promoted.
- [ ] Bulk method probing is not secretly completed before model control starts.
- [ ] Invalid/out-of-scope requests execute no prohibited probe and retain their
  rejection evidence; containment remains enforced in the HTTP client.
- [ ] Reused facts match the applicable identity/session/source context;
  changed contexts permit bounded refresh while unchanged requests cannot loop.
- [ ] Private fixture/reference answers stay outside model context and discovery
  credit; control execution does not provide helpful state to the evaluated run.
- [ ] Linear and AKG can investigate the same supported prerequisites and use
  the same allowed source/destination execution capabilities.
- [ ] Actual source consumption and destination verification determine chain
  completion; model/route assertions do not.
- [ ] Refusal, provider error, malformed action and exhausted budget produce an
  explicit outcome/stop/fallback record without fabricated model contribution.
- [ ] Duplicate internal probes do not inflate budgets, evidence or finding counts.
- [ ] All resource/claim denominators and unavailable values retain their meaning.
- [ ] Current producers/consumers use a single canonical contract and historical
  evidence is read-only under its recorded rules.

Follow the user's requested verification scope and repository instructions.
Do not automatically add/run software tests. When requested, choose focused
existing checks and add a test only for uncovered concrete behavior. E2E,
including mocked/offline E2E, requires an explicit request; for a major runtime
cutover ask about focused E2E unless already answered, and wait before executing it.
A handoff is not authorization for provider/DVWA calls or a matrix.

Run the required naming guard after coordinated source migration and before a
prospective freeze. Reuse unchanged validation evidence within its actual scope.
Research readiness, a frozen study and fresh execution are separate deliverables.

## 10. Remaining concrete design decisions

These choices do not reopen the agreed model-directed-tool approach:

| Decision | Required resolution |
| --- | --- |
| Minimum setup and discovery exposure | Which parsing/observations are provided initially and which inspections the model requests. |
| Public/private applicability facts | How role/permission controls validate the task without supplying privileged discovery answers or source state. |
| Tool interface and permitted arguments | Exact catalog groups, context handles, safe argument ranges, failure responses and evidence retrieval. |
| Graph and checkpoint integration | How request, dispatch, measurement and next decision fit the canonical runtime topology and resumability. |
| Budgets and reuse | Action/probe limits, context-bound freshness, fallback policy and evidence-triggered reconsideration. |
| Prerequisite semantics review | Whether `no_rate_limit`, prior endpoint visibility or positive method-probe signals remain execution gates or become bounded feasibility observations. No gate is weakened by this handoff. |
| Autonomous versus diagnostic tasks | Preserve explicit-target diagnostics; declare the prospective tasks using autonomous selection without rewriting historical identities. |

Resolve routine details from existing code and recorded scope. Seek owner input
only where a material policy/design choice cannot be settled from that context.
Do not invent successful fixtures, arbitrary probes or measured findings.

## 11. Handoff lifecycle and current deliverable

Keep this file Upcoming until implementation actually starts. Move it to Active
then, and to Completed only after its implementation and requested task-scoped
checks have source-bound evidence. Update companion and external links on moves.
The paired handoffs can progress separately when their shared contracts agree;
completion of one does not claim implementation of the other.

- [x] Model-directed prerequisite probing direction recorded.
- [x] Current prerequisite inventory, code/tool/evaluator boundaries and shared
  Linear/AKG capabilities documented.
- [x] Implementation tasks, open choices and future acceptance cases specified.
- [ ] Runtime/configuration/prompt implementation: **not started by this task**.
- [ ] Software tests, E2E, provider/target execution or prospective freeze:
  **not performed by this task**.
- [ ] DOCX changes, commit, push or subagent work: **not performed by this task**.
