# Codebase and experiment status

Snapshot: 2026-11-05 (Asia/Jakarta).

This is the dated status companion to [summary_en.md](summary_en.md) and
[summary_id.md](summary_id.md), which contain the enduring methodology.
Use owning code for implemented behavior, declarations for planned coordinates,
and the named run/review artifacts for measured results. This snapshot is not a
launch authorization, fresh validation report, or implementation backlog.

## Using status and past artifacts

Read past artifacts when they can help identify a failure's cause, reproduce an
input, verify a claim, or assess historical compatibility. Ask a specific question
and stop reading when it is answered; historical analysis need not precede every
implementation task. Old results cannot prove that changed code works.

Once the cause is sufficiently understood, implement the requested correction.
Follow the user's verification scope. If a fresh run is authorized and necessary,
execute the smallest affected flow using current code and a new output rather
than repeatedly analyzing old results or rebuilding missing historical inputs.
Do not request the same authorization again when its target/provider scope still
applies. Saved inputs may be enough for arithmetic or reporting corrections.
Never invent missing proof, overwrite original runs, bypass containment/readiness,
or launch unsolicited E2E/provider/DVWA experiments. Unrelated old gaps do not
prevent finishing an implementation task.

## Codebase snapshot

These are implementation observations and pointers, not claims that a live run
has passed on this snapshot date. Detailed mechanics remain in
[architecture.md](architecture.md), [thesis_scoring.md](thesis_scoring.md), and the
owning modules; consult only the area relevant to the task.

| Area | Implementation and owner |
| --- | --- |
| Packages | `core/` owns workflow/state/AKG/scoring; `foundation/` owns reusable attack tools. The proposed `engine/` and `attack_tools/` rename is still an [upcoming handoff](../upcoming/HANDOFF_PACKAGE_RENAME_2026-11-05.md), not an applied rename. |
| Workflow | `core/graph_builder.py` assembles recon, selection, candidate preparation/validation, nine static method agents, chaining, and scoring. |
| Shared state and visits | `core/state.py` and `core/workflow_policy.py` own state merging, visit identity, coverage/impact stopping policies, and method eligibility. Active queues are visit-bound; history is retained separately. |
| AKG | `core/knowledge_graph.py` owns the predefined graph, prerequisites, outcomes, and payload profiles; `core/chaining_coordinator.py` owns chain feasibility and source consumption. |
| Payload pipeline | `foundation/payload_generator.py`, `payload_validator.py`, and `payload_ranker.py` implement mode-specific generation, validation, generated-first hybrid ordering, and per-visit budgeting. Controls are separate from scored candidates. |
| Containment and sessions | `foundation/http_client.py`, `session_manager.py`, and `readiness.py` handle target limits, identities, session/security setup, and live readiness. Offline dry runs do not establish live availability. |
| Access Control | `agents/access_control/session.py` selects a documented non-admin session or validated route-bound non-admin credentials and records principal/object bindings. The former summary's blanket claim that all AC agents currently authenticate as admin is superseded; historical evidence limits still apply to the runs that produced them. |
| Verification | Method agents call `foundation/verifier.py`; session, permission, and dependency evidence support the applicable proof tiers. Successful HTTP transport or content visibility alone does not establish an unauthorized action. |
| Model integration | `llm/provider.py` and `llm/runtime.py` own clients, structured requests, attempts, local response caching, concurrency, and telemetry. Provider-specific response/reasoning support is described in architecture and provider references. |
| Interface | `tesis/cli.py` launches TUI/headless/dry-run modes; `tesis/tui.py` is the public facade. Companion `tui_*` modules own screens/forms/commands; `tesis.tui_state.CONFIG_PATH` owns the configuration path. |
| Launch and output | `tesis/headless.py` shares the resolved launch boundary; `evaluation/runner.py` and `multi_llm_runner.py` run single/matrix experiments. New runs use distinct execution IDs and dated result layouts with manifests/journals/descriptors. |
| Persistence and replay | `core/checkpoint_store.py` and `checkpoint_audit.py` preserve resumable state and audit entries. Saved-input replay in `evaluation/payload_replay.py` is a separate diagnostic operation with frozen queues and no new model generation. Missing historical inputs do not authorize inventing state. |
| Runtime versus thesis scores | `core/scorer.py` produces provisional runtime reports; `evaluation/thesis_scoring.py` reviews artifacts and emits separate final receipts. Metrics/contracts are shared evaluation helpers, not a second mandatory experiment. |
| Reporting and observers | `evaluation/reporter.py`, `observer_reviews.py`, and `observer_export.py` publish reports and source-bound projections. The fidelity ledger is an offline analysis tool, not a runner. |

At this snapshot's creation, source constants were `graph.v2`, `workflow.v2`,
`state.v3`, `checkpoint.v2`, `scoring.v4`, and `scoring-policy.v4.3`, with
provisional runtime scoring labelled `scoring.v2`. This is the retained
pre-cutover observation, not the current naming contract. The subsequent
[canonical cutover](</home/kevin/coding/tesis/docs/reference/canonical-contracts.md>)
has migrated graph/state/checkpoint/workflow, scoring/metrics and selected
reporting contracts; the full payload/oracle/study cutover remains in progress. Historical data and
its original labels remain unchanged. Dependency declarations and the lockfile
remain authoritative for external library versions.

Root [config.yaml](</home/kevin/coding/tesis/config.yaml>) now selects AI scoring
under `thesis-scoring`; original frozen configurations retain their recorded labels. Settings and model
profiles may change independently of this snapshot. The reconciled
[Chapter 3](../docx/bab-3-reconciled-2026-10-29.docx) and
[scoring reference](thesis_scoring.md) document the research rubric; earlier
revision proposals are not overriding methodology.
Chapter 3 is the methodology authority; software features and campaign declarations
do not silently amend it. The owner permits a human or AI reviewer interchangeably
for the report's manual-scoring role, using the same rubric and artifact evidence.
The thesis specifies surface-based scenarios with methods observed during the run,
and exploratory Mann-Whitney U analysis. Forced-method blocks and software-provided
paired/bootstrapped analyses are additional capabilities, not automatic amendments
to that protocol. Independent controls and final-score evidence remain required
regardless of reviewer type.

## Experiment declarations

- [Primary-study declaration](../../config/research/autoresearch-primary-study-2026-10-31.json):
  epoch `autoresearch-primary-2026-10-31`, selection block only, hybrid payloads,
  two conditions, three surfaces, three levels, three repeats, and two model
  profiles: DeepSeek-V4.1-Flash-1017 and GPT-6 Luna, both declared at max effort.
  Expected coordinates: 108. This is the frozen campaign definition, not an
  instruction to rerun it for maintenance.
- [General study declaration](../../config/research/chapter3_study.json): supports
  selection and forced-method blocks. Forced coverage is not model-selection
  evidence; campaign counts and findings from the two designs must stay separate.
- [Ranking draft](../../config/research/autoresearch-ranking-draft-2026-10-31.json):
  machine status is `draft_approved_unfrozen`, with `runtime_selector_eligible: false`.
  Owner approval metadata exists. The
  [decision record](../active/AUTORESEARCH_RANKING_APPROVAL_QUESTIONS.md) records
  approval of 23 numeric defaults and four AC nulls, but its table still describes
  the older unapproved machine status. Do not repeat settled owner questions or
  treat approval as proof that freezing or all evidence gates have passed.

## Recorded experiment results

The following facts are relocated from the summaries and their existing source
reports. They were not re-executed or independently re-audited on 2026-11-05.
Different campaigns, scoring epochs, and legacy status labels are not pooled.

| Campaign | Recorded result | Source |
| --- | --- | --- |
| August runtime acceleration, 18 coordinates | Historical baseline: 12 successful / 6 incomplete-error; accelerated: 9 successful / 9 incomplete-error. Summed model-call time fell from 838.14s to 332.08s (60.4%). Actual provider invalid/incomplete output was 2/99; peak model concurrency 2, DVWA-node concurrency 1; no actual containment failure. These are the report's legacy outcome labels. | [Historical acceptance](llm_runtime_acceptance.md) |
| October forced-method scoring acceptance, 108 coordinates | Historical record: 49 success / 59 error artifacts, 74 final AI receipts / 34 pending. Missing mutation-only replay inputs and independent permission/dependency proof limited acceptance. These findings concern that campaign's inputs and code. | [Acceptance and limits](thesis_scoring.md#acceptance-and-current-limits) |
| Primary selection-only study, 108 coordinates | Retained report: 96 confirmed / 12 unconfirmed, 72 final AI receipts / 36 pending AC reviews. Original epoch not converged; F6 = 0.1111. No statistically significant condition/model contrast reported at n=3. | [Completed handoff](../completed/HANDOFF_AUTORESEARCH_LOOP_2026-10-30.md) |
| Post-review historical attribution correction | Recorded audit: 313/539 causes closed (F3 = 0.5807), 226 explicit gaps. Payload deduction alone cannot establish a model-output cause; original artifacts and receipts remain unchanged. | [Review correction](thesis_scoring.md#review-corrections-2026-10-31) |

Original artifact locations cited by those records are not present in this
checkout at snapshot time:

- `results/validation/scoring-v4-live-acceptance-2026-10-10/score-table.csv`
- `results/validation/autoresearch-2026-10-31/analysis/epoch-report.md`
- `results/validation/review-fixes-2026-10-31/baseline-audit.json`

The counts above are therefore recorded documentation claims, not an independent
verification of those missing originals. Retrieve them only if the task needs
their proof; their absence does not prevent implementing an unrelated fix.

The old 18-coordinate invalid-JSON, concurrency, and wall-time acceptance criteria
belong to the acceleration campaign. They are not standing requirements to run
that matrix again. Likewise, the historical
[medium-SQLi plan](plan-sqli-medium.md) does not define current quarantine or
automatically authorize its probes and matrices.

## Limits and next-action boundaries

- Historical pending AC reviews, incomplete replay snapshots, unresolved causes,
  and ranking competitors remain limitations of their named artifacts. Do not
  assume they describe every new run or need to be closed before an unrelated fix.
- The approved ranking draft is not yet selector-eligible. Decide whether a task
  actually needs research-profile freezing before investigating that dependency.
- Profile/config/policy identity, prospective protocol approval, and fixture
  equivalence remain applicable research-readiness requirements. Correctly report
  missing proof rather than substituting old results for a new live observation.
- A fresh focused diagnostic run, saved-input replay, historical rescore, and
  full study collection answer different questions. Select the one matching the
  requested task; authorization for one does not silently expand into a matrix.
- No new live run, provider request, replay, or test suite was performed to create
  this status file. New behavior is not certified by the relocated historical
  counts. For a code fix, finish implementation and the requested checks, report
  remaining relevant limitations, then stop.

## Keeping this file useful

Update the relevant dated section when code status or a campaign changes. Keep
measured results bound to their source and distinguish code inspection, declared
plans, recorded historical results, and fresh execution. Do not append routine
logs or duplicate this status narrative in the methodology summaries. Keep
detailed acceptance records in their existing reports and handoffs.
