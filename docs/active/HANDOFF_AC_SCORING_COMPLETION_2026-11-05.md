# Active handoff: Access Control scores and scoring-methodology completion

Date: 2026-11-05
Status: Active tracking; the work below remains incomplete. This document records
remaining work, not completed implementation, validation, or a new execution.

Execution objective: [concise goal-mode prompt](../../GOAL_PROMPT.md).

## Settled scorer policy

**Manual scorer includes both human and AI scorers. An AI scorer is an
implementation of the manual scorer, not a reference-only or provisional
substitute for it.** The configured `scoring_mode=ai` remains the selected manual
scorer. Do not reopen that decision, require a separate human review, or discard
valid existing receipts solely because their scorer is AI.

In thesis/manuscript DOCX files, retain **manual scoring / manual assessment**.
Never introduce wording that says the study uses an AI scorer, AI reviewer, or
AI-assisted assessment. Internal configuration and artifact metadata may retain
`scoring_mode=ai` for traceability. Temporary manuscript values do not invalidate
existing receipts or create a requirement to regrade them with a human scorer.
This handoff makes no DOCX changes.

## Settled repository-wide naming policy

Use **one canonical unversioned implementation and contract per responsibility**.
Remove arbitrary project-authored version naming throughout this codebase, not
only evaluation. Ban new `v1`, `v2`, `v3`, `v4`, `v.x`, `.vN`, `_vN`, `-vN`,
and equivalent sequential-version names for project-owned files, modules,
symbols, APIs, CLI commands, schemas, prompts, policies, configuration, tests,
and newly emitted artifact labels. Do not force unrelated schemas to share a
meaningless common number or replace version suffixes with parallel `new`/`latest`
implementations. Keep one canonical descriptive name for each responsibility.

This supersedes the earlier instruction to retain live version identifiers.
Preserve current scoring semantics and behavior, including the rubric currently
called `scoring.v4`, while migrating its live name and every consumer together.
Old names may remain only as immutable historical facts or necessary read-only
historical parsing, never alternate executable scoring implementations.

Do not rewrite historical artifacts, frozen hashes, audit records, or historical
handoffs to conceal their original identity. Third-party package/release/model
versions, external protocol identifiers, and actual measured values are facts,
not project naming choices; do not falsify them. Use content hashes, source
identity, and explicit prospective epochs for reproducibility rather than
inventing replacement `vN` labels. Item 8 owns the migration and future guard.

## Retained experiment and evidence

The [completed autoresearch handoff](../completed/HANDOFF_AUTORESEARCH_LOOP_2026-10-30.md)
records 108 executed coordinates, 72 final SQLi/Brute Force receipts, and 36
pending Access Control reviews. AC methods exist and ran; the gap is scoring
evidence and candidate availability, not absence of AC implementation.

| Starting AC level | Runs | Recorded scoring blocker |
| --- | ---: | --- |
| Low | 12 | Missing component evidence, including unresolved ranking fits |
| Medium | 12 | Missing component evidence, including unresolved ranking fits |
| High | 12 | No assessable candidates; no nonempty payload-scoring denominator |

The [ranking decision record](AUTORESEARCH_RANKING_APPROVAL_QUESTIONS.md)
retains 23 supported reference decisions and four null fits: IDOR and vertical
escalation at low and medium. Broad anonymous exposure is not evidence of
candidate-specific IDOR or vertical escalation. These are evidence gaps, not
unanswered owner questions. `reference_fit` is not itself a thesis rubric score.

Existing result owners:

- Runs: `results/runs/autoresearch-primary-2026-10-31/selection/`.
- Scoring receipts: `results/reviews/autoresearch-primary-2026-10-31/`.
- Frozen inputs: `results/epochs/autoresearch-primary-2026-10-31/`.

The completed handoff's **post-review** audit supersedes its retained original
F3 figure: **313/539 causes closed, 226 explicit gaps (F3 = 0.5807)**, including
58 unclassified payload deductions and 29 payload grades without downstream-use
proof. The older 409/539, 130-gap result is historical, not the latest documented
audit. The linked `results/validation/review-fixes-2026-10-31/` audit and analysis
files are absent from this checkout at handoff creation. Recover them or
regenerate derived reports from the preserved sources before claiming current
audit verification. This documentation change does not re-audit or alter scores.

## Eight unfinished work items

### 1. Apply the settled manual-scorer contract consistently

- [ ] Check runtime, reporting, and handoff terminology for a false split between
      manual scoring and the selected AI implementation of the manual scorer.
- [ ] Keep valid receipts from the selected scorer eligible; do not require a
      second human receipt, human verification, or human sign-off.
- [ ] Preserve manual-scoring terminology in DOCX files. Any later requested
      manuscript sync must keep that terminology and the owner's red-text rule.

Acceptance: the scorer policy above is respected without changing score values,
relabelling existing provenance, or claiming a human review occurred. The policy
is settled; consistency checks remain, not a new scorer-selection decision.

### 2. Reconcile ranking-profile and oracle bindings

- [ ] Reconcile prospective approval-to-freeze identity. The completed handoff
      records approved draft digest `045f8d…` versus frozen profile `42127e…`,
      rejected by `ranking_profile_digest_mismatch` and
      `scoring_policy_epoch_ranking_digest_mismatch`.
- [ ] Bind the correct profile, source, fixture, protocol, budget, and scoring
      policy to a separately identified future epoch; do not rewrite historical
      approval metadata to make a new readiness gate pass.
- [ ] Check oracle source integrity and prospective protocol commitments.
      Distinguish preregistration from later candidate-specific attestations;
      a configured oracle or approved protocol is not collected proof.

Acceptance: prospective bindings validate and missing evidence remains explicit.
Existing approvals are not reopened and preregistration is never backdated.

### 3. Resolve AC ranking, candidate, and control evidence

- [ ] Resolve the four low/medium IDOR and vertical-escalation reference fits
      using method-specific candidate evidence. Keep them null until supported;
      broad exposure must remain a separate finding, not an assumed fit of 3.
- [ ] Inspect all 36 AC artifacts for the exact component and denominator gaps,
      reusing valid saved evidence before collecting anything new.
- [ ] Investigate the 12 AC/high empty candidate populations. Obtain legitimate,
      validated, executed exploit/bypass candidates where feasible; do not
      count probes, rejected, or unexecuted candidates to force a denominator.
- [ ] Supply applicable permission controls bound to principal, object, action,
      session, fixture, and exact candidate replay: an allowed control, an
      expected-denied control, and the candidate's observed result. A page
      loading or a model claim is not permission proof.
- [ ] Retain measured negatives or fixture infeasibility where supported. Do not
      force a successful bypass or turn absent candidates into a zero score.

Acceptance: AC components have source-bound evidence or precise unavailability
reasons. Numeric completion is not achieved by inventing fit values or controls.

### 4. Prepare and execute a prospective evidence-complete epoch

- [ ] Freeze corrected inputs before selections whose grading depends on them;
      satisfy applicable readiness, fixture-restoration, and containment gates.
- [ ] Preserve the full primary design: both models, both hybrid conditions,
      three surfaces, three levels, three repeats, model-selected methods,
      and the frozen generated-first/static-fallback policy: 108 coordinates.
- [ ] Collect needed candidate, permission/session, destination-prerequisite,
      source-consumption, and dependency-control evidence during execution.
- [ ] For one corrected, comparable 108-run dataset, use a fresh full epoch when
      treatment/profile changes require rerunning. An AC-only diagnostic or
      supplement must remain separate, not be silently pooled with the old 72.

Acceptance: new coordinates and frozen inputs reconcile, with all failures and
unavailable outcomes retained. This handoff does not itself launch a matrix or
expand existing execution scope; follow repository execution/verification rules.

### 5. Complete source-bound manual-scoring receipts

- [ ] Finalize eligible AC scores through the selected manual scorer, including
      its configured AI implementation, after the evidence gates are satisfied.
- [ ] Apply `Smethod`, `Spayload`, `Sexploit`, `Schain`, and `Soutput` consistently.
      Preserve final-method attribution except for run-scope `Schain`.
- [ ] Compute `Spayload` over distinct validated, executed final-method
      exploit/bypass candidates. Empty denominators or missing mandatory
      components leave the composite unavailable, not zero.
- [ ] Preserve the formula
      `Srun = 0.20*Smethod + 0.20*Spayload + 0.30*Sexploit + 0.10*Schain + 0.20*Soutput`,
      scorer identity, rubric/version, source hashes, evidence references,
      and candidate provenance. Do not overwrite historical receipts.
- [ ] Require complete five-level coverage for every final rubric dimension:
      `Smethod`, `Spayload`, `Sexploit`, `Schain`, and `Soutput` must each
      implement distinct, evidence-based criteria for levels **0, 1, 2, 3, and
      4**. A restricted scale such as `{0,3,4}` is a methodology defect, not a
      completed rubric. Coverage concerns possible grades, not the distribution
      of observed results; `Srun` remains the weighted composite and an averaged
      `Spayload` may be fractional. Implement any missing level in the owning
      rubric while preserving the published semantics; do not satisfy coverage
      by inventing evidence or relabelling an existing grade.

Acceptance: each of the 108 coordinates is accounted for by a valid final receipt
or a justified unavailable/failed status. Every final component rubric supports
all five levels. Reuse compatible valid receipts; a human regrade of all 108 is
not required. Report any remaining unscored AC coordinates explicitly rather
than claiming a fully numeric score set.

### 6. Complete the superseding audit, analysis, and reporting

- [ ] Recover or regenerate the missing post-review derived audit/analysis
      outputs, retaining source identity and original artifacts.
- [ ] Resolve F3 deductions/nulls using evidence-linked causes across all
      surfaces, not only AC. Preserve unresolved gaps; implementation completion
      alone does not establish F3 = 1.0.
- [ ] Reassess payload attribution/downstream-use proof, destination prerequisites,
      chain consumption, and independent dependency controls. Runtime route
      completion is not interchangeable with final rubric proof.
- [ ] Use the thesis-declared **exploratory Mann-Whitney U** analysis for
      compatible condition, model, or level groups. Report group sample sizes,
      medians, IQR, U, p-value, effect size, and the dependence/limited-repeat
      limitations. Holm-Bonferroni may accompany multiple comparisons.
      Software-provided paired tests and bootstrap intervals are supplementary;
      they do not replace the documented Mann-Whitney analysis without an
      explicit methodology revision.
- [ ] Recompute coordinate availability, scoring arithmetic, and outcome spread
      for the resulting epoch. Keep all repeats and missing outcomes; no
      best-of-N, epoch pooling, or null filling.
- [ ] Update reports with final/pending counts, reasons, provenance, containment,
      and evidence paths. Update manuscript numbers or interpretations only when
      requested; retain manual-scoring terminology and color changes red.

Acceptance: reported completeness, statistical method, and conclusions follow
the verified evidence and current methodology. Mann-Whitney results are present
or explicitly unavailable with reasons; supplementary paired/bootstrap outputs
are labelled as such. Any remaining AC score or F3 gap stays open with a concrete
reason; neither higher scores nor a completed matrix alone proves methodology
completion.

### 7. Remove obsolete scorer systems without changing current behavior

- [ ] Inventory scorer implementations, entry points, imports, configuration
      switches, reporting paths, tests, and historical artifact readers. Identify
      the current canonical scorer and distinguish obsolete implementations from
      active functionality using callers and behavior, not version names.
- [ ] Remove genuinely obsolete scorer implementations and unreachable branches,
      including old v2/v3/v4-labelled paths where obsolescence is demonstrated.
      Preserve the behavior of the current rubric while moving it to its
      canonical unversioned name under item 8. A versioned name alone is not
      evidence that the underlying functionality should be deleted.
- [ ] Migrate every live caller of removed code to the canonical implementation.
      Remove obsolete aliases, switches, tests, and comments together; do not
      introduce a second scorer or retain dead execution paths as compatibility
      shims. Do not delete unrelated user work.
- [ ] Preserve score dimensions, weights, evidence gates, denominators,
      unavailable-value semantics, selected manual-scorer authority, and current
      scoring/reporting behavior. Coordinate the required identifier migration
      with item 8 rather than retaining live versioned identifiers.
- [ ] Keep historical artifacts readable without executing obsolete scorers.
      Retain only necessary read-only historical parsing/labels with an explicit
      reason; never rewrite old artifacts, hashes, or receipts. Investigate
      existing source-hash and archived-script consumers before deleting files.
- [ ] Verify current scoring/reporting behavior with the smallest relevant
      existing checks and a saved-artifact smoke covering numeric components,
      pending/empty-denominator cases, receipt identity, and historical reading.
      Update affected documentation. Record removed paths, migrated callers,
      retained historical readers, and before/after evidence.

Acceptance: no demonstrated obsolete executable scoring path remains; current
scoring results and consumer-visible scoring behavior are preserved for supported
inputs whose rubric coverage is already satisfied. Any level missing under item 5
is implemented as a separate methodology correction and tested; behavior
preservation must not freeze a known rubric-coverage defect. The deliberate
identifier cutover in item 8 is not a rubric change. Necessary historical readers
remain documented and read-only.

Sequencing: complete this cleanup before the final prospective source/policy
freeze and primary matrix in item 4. Even behavior-preserving source edits can
change scoring-source digests; regenerate future bindings through the supported
freeze process, never patch historical hashes or bypass readiness checks.

### 8. Remove arbitrary version naming across the entire codebase

- [ ] Inventory all project-owned versioned names and contract identifiers:
      evaluation/scorers, runtime, providers, CLI/TUI, prompts, schemas, policies,
      configuration, checkpoints, reports, tests, scripts, and current docs.
      Identify each producer, consumer, persisted binding, and historical reader.
- [ ] Define one canonical unversioned descriptive name per responsibility and
      migrate every live caller, import, command, configuration value, emitted
      schema/policy identifier, fixture, and current documentation together.
      No parallel version implementations, deprecated aliases, or forwarding
      shims may remain as live entry points.
- [ ] Preserve intended implementation behavior and rubric semantics. This is a
      naming and obsolete-code cutover, not a reason to change weights, ceilings,
      thresholds, budgets, or results. Do not erase required 0-4 rubric levels
      while removing version labels; complete missing coverage under item 5.
- [ ] Preserve exact historical identities when reading saved artifacts,
      receipts, checkpoints, and frozen configurations. Keep necessary
      read-only historical decoding separate from the canonical write path;
      never relabel old data as newly emitted canonical data. Do not weaken
      compatibility, chronology, hash, or resume gates.
- [ ] Use source/content hashes and explicit prospective epoch bindings to
      detect contract drift. Update future freeze inputs and validate them
      before execution; do not blindly equate artifacts because version
      suffixes have been removed.
- [ ] Record the repository-wide ban in the maintained contributor/agent
      instructions and naming conventions. Add a focused lint/static guard
      against reintroducing project-owned version suffixes and emitted version
      labels. Scope it to naming locations so it does not reject payload data,
      historical records, dependencies, model identifiers, or numeric literals.
- [ ] Verify the coordinated cutover with relevant existing checks and actual
      import/CLI/scoring/reporting smoke scenarios, including historical
      artifact reading and required checkpoint compatibility. Record old-to-new
      mappings, any retained historical decoding, and verification evidence.

Acceptance: no arbitrary project-authored version name remains in active code,
current naming contracts, or newly emitted labels anywhere in the codebase;
each responsibility has one canonical implementation. Only documented
historical/external facts and necessary historical decoding retain old names.
The naming guard prevents new violations, existing scoring behavior is
preserved, and compatibility/evidence checks still distinguish incompatible data.

Sequencing: perform items 7 and 8 before the final prospective source/policy
freeze and matrix in item 4. No runtime or identifier migration is performed
merely by recording this policy in the handoff.


## Completion boundaries

Implementation subtasks may close independently once their scoped change and
requested checks pass. Record that evidence without waiting for unrelated
historical gaps, missing old reports, new experiment collection, or the overall
research goal.

The overall research goal remains open for its separate evidence and experiment
tasks: AC controls and candidate evidence, prospective bindings, authorized
execution, final receipts, audit recovery, methodology analysis, and reporting.
Do not claim AC scores or the full scoring methodology are complete merely
because an implementation subtask passed.

Conversely, an unresolved historical gap or blocked experiment does not make an
already verified implementation subtask incomplete. Report the exact state:
for example, “implementation verified; AC evidence collection blocked; overall
goal incomplete.” Do not use the overall goal to delay reachable implementation,
and do not narrow the overall goal to the easiest open subtask.

## Documentation-only change

No runtime code, configuration, scorer execution, experiment artifacts, or DOCX
files are changed by this handoff. No tests, dry runs, E2E, target requests, or
provider calls were run to create it. Move it to `docs/completed/` only after its
required work and requested acceptance checks have evidence, and update links.
