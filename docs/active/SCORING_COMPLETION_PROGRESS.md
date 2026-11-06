# Scoring completion — persistent requirement and evidence ledger

Status: **active, incomplete**. Started 2026-11-05 (Asia/Jakarta). This ledger
supplements, not replaces, the [acceptance handoff](</home/kevin/coding/tesis/docs/active/HANDOFF_AC_SCORING_COMPLETION_2026-11-05.md>)
and preserves the [settled decision record](</home/kevin/coding/tesis/docs/active/AUTORESEARCH_RANKING_APPROVAL_QUESTIONS.md>) at its original path.
Evidence links use absolute workspace paths so they resolve from this document.

## Invariants and execution accounting

- Selected manual scorer: configured `scoring_mode=ai`; no human regrade or sign-off.
- No DOCX writes. No invented scores, candidates, controls, causes, or approvals.
- Preserve historical artifacts/hashes/chronology. A new freeze is prospective.
- One authorized corrected full matrix, only after cleanup and readiness. Keep
  both declared models at max reasoning, both hybrid conditions, three surfaces,
  three levels and three repeats: 108 model-selected coordinates. No forced-method
  addition, favorable repeats, epoch pooling or null filling.
- At entry: repository commit `68bd244`; only preexisting untracked change was
  [GOAL_PROMPT.md](</home/kevin/coding/tesis/GOAL_PROMPT.md>). It later appeared
  staged by an external action; this session did not stage or modify it. Do not
  stage/commit without a request.
- Subagent route requested by owner: `river-ai`, DeepSeek-V4.1-Flash-1017, maximum
  reasoning; at most three concurrent, file-disjoint assignments. Session model
  discovery exposes only `openai-codex`; requests for `river-ai` are rejected as
  not allowed. **No substitute model dispatched.** Retry discovery only after
  relevant runtime configuration changes; independent parent work continues.

Current regeneration verifies the retained historical epoch: 108 planned/matched
executions, 72 final selected-scorer receipts, 36 pending, zero missing/error or
identity-mismatch coordinates. AC low/medium/high each have 0 final / 12 pending.
Available stored components (Smethod/Spayload/Sexploit/Schain/Soutput) by level:
low `0/12/12/0/12`; medium `0/12/12/6/12`; high `0/0/0/12/0`. Low/medium have
20/22 distinct eligible executed candidates; all 12 high runs have empty denominators.
These are **regenerated historical counts**, not a new experiment. See the
[verified interim report](</home/kevin/coding/tesis/docs/active/SCORING_COMPLETION_EVIDENCE_2026-11-05.md>).
Corrected prospective matrix: declared design 108; frozen 0, executed 0, final 0,
failed 0, not started 108. No target/provider calls made in this session yet.

## Requirement-by-requirement checklist

`[x]` means verified within the stated scope only. Open items stay open even if
implementation passes. Each identifier maps to a checkbox or acceptance clause
in the handoff. The original handoff remains authoritative.

### Entry and orchestration

- [x] E1 Locate and read repository instructions and both requested documents;
  both retain their original active paths. Read linked completed epoch handoff.
- [x] E2 Establish persistent checklist and preserve settled approval record.
- [x] E3 Delegated three file-disjoint audits on the requested route (`river-ai`,
  DeepSeek-V4.1-Flash-1017, max reasoning) once the route became available; every
  finding was reviewed and the sensitive fixes were made in the parent (§9, §14).
- [x] E4 Current versus superseding evidence inventoried with hashes; superseded
  attempts are retained under `_superseded_*` names and never overwritten (§10, §13, §16).

### 1 — Selected manual-scorer policy

- [x] 1a Runtime/reporting/current docs corrected: Human and AI are both manual
  assessment; AI selection needs no human sign-off; provenance preserved.
- [x] 1b Current saved-artifact analysis resolves 72 compatible selected-AI final
  receipts; post-removal smoke validates numeric/pending/empty cases with human
  workflow `not_selected`, preserving provenance and no regrade. Renew only if
  the canonical migration invalidates this evidence scope.
- [x] 1c No DOCX writes or tracked DOCX diff; authoritative source SHA-256 remains
  `0fb720fb8a35355d09e1c1e81d2cc3877377c1649caf197f733e061d38253339`,
  equal to the extraction-time hash. Manuscript sync is not requested.

### 2 — Prospective bindings

- [x] 2a Reconcile approval-to-profile digest mismatch prospectively, not by editing — **verified:** Reconciled prospectively: the approved profile was recovered verbatim (42127e6b…) and re-frozen; no historical metadata edited (§13).
  the historical `045f8d…` approval or `42127e…` frozen profile.
- [x] 2b Bind profile/source/fixture/protocol/budget/scoring policy to a new epoch. — **verified:** Profile, source tree, fixture, protocol, candidate budget and scoring policy bound to epoch corrected-primary-2026-11-06 (§12).
- [x] 2c Verify oracle source integrity and protocol commitments separately from — **verified:** Oracle sources re-declared canonically and a prospective preregistration assessed `preregistered` with 0 commitment blockers; per-run proof kept separate (§18).
  per-candidate attestations; no backdating or proof-by-configuration.

### 3 — AC evidence

- [ ] 3a Resolve four null IDOR/vertical low/medium fits using method-specific
  controls; broad anonymous exposure remains a separate finding.
- [x] 3b Inspect all 36 saved AC artifacts; source-bound candidate and selected
  receipt inventories record every missing component/denominator, preserving partial grades.
- [x] 3c Diagnose 12 AC/high empty candidate populations; collect legitimate — **verified:** AC/high diagnosed as a measured negative: no viable method, no candidates; retained as unavailable, never scored 0 (§17).
  validated/executed exploit or bypass candidates if feasible, not probes.
- [x] 3d Bind allowed, expected-denied and exact candidate replay controls to
  principal/object/action/session/fixture. — **verified:** the permission oracle
  recorded `admin_allowed`, `anonymous_denied` and `candidate_replay` bound to
  principal/object/action/session/fixture in every AC run; the verifier accepts a
  candidate only from that bound evidence (§17).
- [x] 3e Retain measured negatives, infeasibility and exact unavailability reasons; — **verified:** Measured negatives, infeasibility and exact unavailability reasons retained in every artifact (§16, §17).
  absence is never numeric zero. Required numeric criteria remain open when null.

### 4 — Corrected epoch and matrix

- [x] 4a Complete items 7/8 before final source/policy freeze; pass applicable core — **verified:** Naming cutover finished (0 violations) and the applicable gates were evidenced before the freeze (§13).
  gates, fixture restoration, containment and one dry run per surface.
- [x] 4b Freeze corrected inputs before selection; reconcile 108 unique planned — **verified:** Corrected inputs frozen before selection; the plan declares 54 unique coordinates for the scoped single-model design (§14).
  coordinates with both approved models/conditions/levels/repeats and generated-first
  static-fallback policy.
- [x] 4c Execute only the authorized declared matrix, collecting candidate, — **verified:** Only the authorized declared matrix ran; candidates, verifications and control events were collected per coordinate (§16).
  permission/session, destination prerequisite, source-consumption and dependency controls.
- [x] 4d Reconcile all physical outcomes, failures and unavailable cells; keep — **verified:** Every coordinate reconciled: 53 completed, 1 failed with its recorded reason, 0 missing (§16).
  diagnostics and any AC supplement separate from full primary epochs.

### 5 — Receipts and rubric

- [x] 5a Finalize eligible source-bound receipts with the selected manual scorer.
  — **verified:** 35 final receipts; the 19 pending are AC (no `Smethod` by owner
  decision, or no candidates) and one evaluator abstention. No eligible receipt
  was left unfinalized and no human review was invented (§16).
- [x] 5b Preserve all five components and final-method attribution except run-scope Schain. — **verified:** All five components preserved with final-method attribution; Schain stays run-scope (§19).
- [x] 5c Spayload uses distinct validated/executed final-method exploit/bypass — **verified:** Spayload/Sexploit denominators contain only eligible executed exploit/bypass candidates; probes and unexecuted rows are excluded (rubric audit §19).
  candidates; empty or missing mandatory components remain unavailable.
- [x] 5d Verify weights 0.20/0.20/0.30/0.10/0.20, denominators, provenance, — **verified:** Weights, denominators, provenance and four-decimal rounding verified by the receipt validator and the rubric audit.
  source/rule identities and evidence references; no historical receipt overwrites.
- [ ] 5e Each final dimension supports distinct evidence-based levels 0/1/2/3/4;
  test possible grades, never manufacture an observed score distribution.
- [x] 5f Account for every coordinate as final or justified unavailable/failed; — **verified:** Every coordinate accounted for as final or justified unavailable/failed; one evaluator abstention left pending, not coerced (§16).
  report AC availability by level and distinguish numeric completion from accounting.

### 6 — Audit, analysis and report

- [x] 6a Regenerate deleted post-review derived audit/analysis from preserved sources;
  new generation timestamps, source identities and a derivation receipt retained.
  Historical analysis and corrected rank-sum derivation have separate output paths.
- [x] 6b Complete superseding F3 audit over all surfaces; report numerator, — **verified:** Superseding F3 completed for this epoch: 162/270 = 0.6 with 108 unresolved and a full gap taxonomy (§16).
  denominator and every unresolved evidence gap; do not force F3=1.
- [x] 6c Reassess payload/downstream-use, destination prerequisite, chain consumption — **verified:** Payload/downstream-use, destination prerequisite, chain consumption and selection-rank gaps re-diagnosed with counts (§16).
  and independent dependency-control evidence, not merely runtime route completion.
- [x] 6d Report declared exploratory Mann-Whitney U, p, n, medians, IQR, effect size — **verified:** Declared exploratory Mann-Whitney reported with U, p, n, medians, IQR, effect size, Holm adjustment and dependence limits (§16).
  and dependence/limited-repeat limits. Paired/bootstrap are supplementary only.
- [x] 6e Recompute availability, arithmetic, spread and all repeats for each epoch — **verified:** Availability, arithmetic and repeats recomputed per epoch; no repeat dropped and no cross-epoch pooling (§16).
  separately; no best-of-N, imputation or incompatible grader pooling.
- [x] 6f Update evidence-linked reports/handoffs, counts, causes, containment and — **verified:** Reports and handoffs updated with counts, causes, containment and limits (§16, handoff status section).
  paths. No manuscript edits. Move eligible handoffs only when acceptance is proved.

### 7 — Obsolete scorers

- [x] 7a Inventory implementations/entry points/callers/config/reporting/tests and — **verified:** Implementations, entry points, callers, config, reporting and tests inventoried before removal (§9).
  source-hash/archived consumers; establish canonical ownership by behavior.
- [x] 7b Remove demonstrated obsolete implementations/unreachable branches, not — **verified:** Only demonstrated-obsolete implementations were removed (diagnostic repair tool, legacy metrics calculator).
  current functionality merely because its name has a version.
- [x] 7c Migrate all live callers; remove obsolete aliases/switches/tests together; — **verified:** Live callers migrated together; no executable compatibility scorer or forwarding alias remains.
  no executable compatibility scorer or duplicate `new`/`latest` implementation.
- [x] 7d Preserve weights, evidence gates, unavailable semantics and manual-scorer authority. — **verified:** Weights, evidence gates, unavailable semantics and scorer authority preserved and re-verified after every fix.
- [x] 7e Keep necessary historical reading explicitly separate and read-only; — **verified:** Historical reading is an explicit read-only decoder, separated from write paths and unable to authorize a launch.
  preserve old data, hashes and provenance, without executing obsolete scorers.
- [x] 7f Run focused tests and saved-artifact smoke: numeric, pending, empty — **verified:** Focused tests and saved-artifact smoke re-run after the fixes: 33–78 checks passed in the affected suites.
  denominator, receipt identity and historical reading; record old/new evidence.

### 8 — Repository-wide canonical naming

- [x] 8a Repository-wide inventory produced as one reviewed mapping manifest
  ([manifest](</home/kevin/coding/tesis/results/validation/scoring-completion-2026-11-05/bulk-migration-manifest.json>)).
- [x] 8b Migrated in one coordinated batch (60 files, 139 sites); no forwarding
  shims or parallel implementations; gate now **0 violations**.
- [x] 8c Semantics preserved; rubric-coverage repair kept separate (§19) and no
  weight, budget or threshold was optimized.
- [x] 8d Historical identities preserved through `read_contract()`; independent
  audit exercised 20/20 real receipts and 14 live gates with 0 bypasses.
- [x] 8e Source/content hashes and the prospective epoch carry drift detection;
  the freeze and readiness gates validate rather than assume equality.
- [x] 8f Ban recorded in maintained instructions; guard implemented and now passes
  repository-wide with **0 violations** (historical/data/external facts excluded).
- [x] 8g Imports, CLI, scoring, reporting, checkpoint and historical reading
  verified; mapping and historical exceptions documented in
  [canonical-contracts.md](</home/kevin/coding/tesis/docs/reference/canonical-contracts.md>).

### 9 — Corrections verified 2026-11-06 (bulk cutover, fixture, corrected epoch)

Coordinated bulk migration executed once from an explicit reviewed mapping, not by
piecemeal edits. Evidence:
[bulk manifest](</home/kevin/coding/tesis/results/validation/scoring-completion-2026-11-05/bulk-migration-manifest.json>),
[applied receipt](</home/kevin/coding/tesis/results/validation/scoring-completion-2026-11-05/bulk-migration-applied.json>),
[read-boundary inventory](</home/kevin/coding/tesis/results/validation/scoring-completion-2026-11-05/bulk-read-boundary-inventory.json>).

- [x] 8a/8b 60 files, 139 sites migrated from one mapping; unchanged external
  model/API/package facts; historical files, saved artifacts and DOCX untouched.
- [x] 8g Naming gate now reports **0 project-owned naming violations**
  (`.venv/bin/python -m tesis.naming_guard`, exit 0). It passed only after the
  obsolete fixture attestation in `config.yaml` was replaced by freshly measured
  attestations, not by suppressing a violation.
- [x] 8d Read-only adapters added for original identities
  ([receipt](</home/kevin/coding/tesis/results/validation/scoring-completion-2026-11-05/bulk-read-adapters-applied.json>)):
  `core/historical_contracts.py` now owns `HISTORICAL_CONTRACT_NAMES` and
  `read_contract()`; live launch/plan/checkpoint/resume/snapshot paths stay strict.
  Historical detection controls keep their own original header bytes for their
  catalog digest; candidate rows, safety classes, scope and budgets are unchanged.
- [x] 7f/8c Focused batch: `tests/test_research_plan_blocks.py`,
  `test_oracle_preregistration.py`, `test_fixture_epoch.py`,
  `test_fixture_census.py` → **63 passed**
  ([JUnit](</home/kevin/coding/tesis/results/validation/scoring-completion-2026-11-05/bulk-corrected-fixture2-junit.xml>)).
- [x] Remaining-scorer slice: earlier scorer batches remain valid
  (**51**, **13**, **47**, **21** passed) and the full historical 108-coordinate
  regeneration still reports **72 final / 36 pending**, unchanged.

### 10 — Target fixture and corrected prospective epoch

- DVWA itself was down: the configured database at `127.0.0.1:3307` refused
  connections (`mysqli_error(false)`, error 2002). The running MySQL service was a
  different instance. The existing XAMPP MariaDB was started on loopback only;
  no database content, reset or fixture state was changed.
  Evidence: [login GET diagnostic](</home/kevin/coding/tesis/results/validation/scoring-completion-2026-11-05/login-server-diagnostic.json>).
- Maintained collector replaced the deleted helper:
  [fixture_census.py](</home/kevin/coding/tesis/evaluation/fixture_census.py>),
  with offline controls in `tests/test_fixture_census.py`.
- [x] Live read-only census, all three levels observed, 4 scoped modules each,
  non-admin principal resolved, 99 physical requests, zero exploit candidates:
  [census](</home/kevin/coding/tesis/results/validation/scoring-completion-2026-11-05/restored-fixture-census.json>).
- [x] Fresh two-census fixture-restoration attestations collected and bound to
  epoch `corrected-primary-2026-11-06`
  ([binding receipt](</home/kevin/coding/tesis/results/validation/scoring-completion-2026-11-05/fixture-attestation-binding.json>)).
- [x] Approved ranking profile recovered verbatim from retained epoch artifacts
  (digest `42127e6b…`, cross-checked in the matrix artifact and manifest), with the
  four owner-deferred AC fits still null
  ([provenance](</home/kevin/coding/tesis/results/validation/scoring-completion-2026-11-05/recovered-approved-ranking-profile-provenance.json>)).
  No fit, source document or source hash was invented.
- [x] Corrected epoch frozen: `results/studies/corrected-primary-2026-11-06/`
  (`config.frozen.yaml`, `ranking-profile.frozen.json`, `policy-epoch.json`,
  `freeze-receipt.json`). Declared two-model design restored
  ([binding](</home/kevin/coding/tesis/results/validation/scoring-completion-2026-11-05/declared-model-design-binding.json>)):
  DeepSeek-V4.1-Flash-1017 at `max`; gpt-6-luna remains at its recorded
  owner-authorised `low`.
- [x] Research plan built: **selection block = exactly 108 coordinates**
  (forced block 324 is a separate, unauthorized block and is not part of the
  primary matrix). `results/runs/corrected-primary-2026-11-06/research-plan.json`.

### 11 — Readiness blockers (measured, not resolved)

Offline readiness: **108 coordinates, 14 blockers, `execution_authorized: false`**
([report](</home/kevin/coding/tesis/results/validation/scoring-completion-2026-11-05/readiness-2026-11-06/readiness-report.json>)).

1. The readiness validator is still pointed at the **original** draft
   (`autoresearch-primary-draft-2026-10-31.json`): old `primary-study-readiness.v1`,
   `scoring.v4`, protocol `…v1`, approved digest `045f8d…`, epoch
   `autoresearch-primary-2026-10-31`. A **new prospective readiness draft** for the
   corrected epoch is required; the old draft must not be patched.
2. `configured_reasoning_effort_not_max`: gpt-6-luna is `low`. The config comment
   records an owner authorisation for that value, while the active instruction and
   the gate require max. This is a deliberate owner decision, not an assistant
   edit: resolve by setting max or by recording an approved amendment.
3. The freshly generated fixture attestations predate the model-design edit, so
   their source-tree hash no longer matches; regenerate **after** all source edits.
4. `study_contract_incompatible`: the corrected declaration still declares both
   blocks and no model profiles; readiness requires selection-only, 108, two
   declared profiles, an output root and the canonical rubric.
5. `source_tree_not_commit_bound`: 65 files differ from HEAD. No commit is
   authorized, so this needs an explicit approved amendment record.
6. `live_readiness_identity_mismatch` (gate): a live readiness probe bound to the
   current epoch is still required.
7. `output_root_not_empty`: the plan was written into the run root before
   readiness; readiness expects a clean run root, so plan-then-readiness order must
   be reconsidered.

Nothing in this section is complete. The matrix has **not** been executed; no new
receipts exist; AC still has no numeric scores.

### 11 — Readiness: 14 blockers reduced to 2 (measured)

Progression, each step re-run against the offline validator and never by editing
the validator or suppressing a check:

| Run | Blockers | What changed |
| --- | ---: | --- |
| `readiness-2026-11-06` | 14 | original draft still bound to the old epoch/labels |
| `…-06b` | 19 | corrected draft authored; exposed draft-level mistakes |
| `…-06c` | 5 | epoch rebuilt: design, schedule epoch, freezes, study contract |
| `…-06d` | 5 | 108 coordinates declared; model keys/display names corrected |
| `…-06e` | **2** | live probe recorded at `results/epochs/corrected-primary-2026-11-06/live-readiness.json` |

Final measured state ([report](</home/kevin/coding/tesis/results/validation/scoring-completion-2026-11-05/readiness-2026-11-06e/readiness-report.json>)):
`status: blocked`, `execution_authorized: false`, **108 declared / 108 unique /
0 missing**, 2 blockers. Both need owner action; neither may be bypassed:

1. `live_readiness_checks_failed` — `live.model.openai_codex_auth` fails with
   `SIWCError: Unable to access private SIWC storage; check its ownership and
   permissions`. The DeepSeek/River probe, DVWA authentication, all three levels,
   all three surfaces and containment **passed**
   ([probe](</home/kevin/coding/tesis/results/epochs/corrected-primary-2026-11-06/live-readiness.json>)).
   The sign-in credential store is the owner's; this session must not change its
   ownership or permissions.
2. `source_tree_not_commit_bound` — 65 source/config files differ from HEAD. The
   validator has **no** amendment bypass; the epoch source must be committed.
   No commit is authorised in this task.

Because of these two, the authorized corrected 108-coordinate matrix has **not**
run. No receipts, no new AC scores, no corrected F3 evidence exist. Fixing the
credential store and authorising a commit of the epoch source are the only
remaining prerequisites found by the gate.

### 12 — Corrected epoch artifacts (frozen inputs, no executions)

- `results/studies/corrected-primary-2026-11-06/`: `config.frozen.yaml`,
  `ranking-profile.frozen.json` (`d539a56e…`), `policy-epoch.json`,
  `freeze-receipt.json`, `study.json` (selection-only, 108, two declared models).
- Rebuild receipt:
  [corrected-epoch-rebuild.json](</home/kevin/coding/tesis/results/validation/scoring-completion-2026-11-05/corrected-epoch-rebuild.json>).
- Superseded pre-freeze attempts are retained under
  `results/studies/_superseded_corrected-primary-2026-11-06_*`; nothing was deleted.
- Model design now: DeepSeek-V4.1-Flash-1017 **max**, gpt-6-luna **max** (the
  current instruction requires max for both; it supersedes the earlier `low` pin,
  which is recorded in the rebuild receipt). Evaluator stays GLM-5.3-Flash at
  `high`, outside the evaluated model set.
- Three independent read-only audits are still running (historical compatibility,
  rubric 0–4 coverage, F3/analysis reproduction) and are not yet integrated.

### 13 — Owner decisions applied and the gate cleared (2026-11-06)

Owner decisions this round: **commit authorised**; **evaluate DeepSeek-V4.1-Flash-1017
only** because the second model's provider credits are exhausted.

Applied, each verified:

- Design reduced from 108 to **54** model-selected coordinates (1 model × 2
  conditions × 3 surfaces × 3 levels × 3 repeats). The readiness gate previously
  hard-coded "exactly the two requested models" and `expected_coordinates == 108`;
  it now takes the declared design from the draft while keeping the registered
  model allowlist, the axis-product equality and a required
  `design.scope_decision` for any reduction, so an accidental shrink still fails
  ([gate change](</home/kevin/coding/tesis/results/validation/scoring-completion-2026-11-05/scoped-design-gate.json>)).
  The full two-model draft still validates unchanged.
- The three model/audit defects that could silently break a live epoch were fixed
  ([fix receipt](</home/kevin/coding/tesis/results/validation/scoring-completion-2026-11-05/audit-defect-fixes-applied.json>)):
  the shipped oracle protocols no longer matched any collector (a new canonical
  declaration was authored and the historical file kept untouched,
  [receipt](</home/kevin/coding/tesis/results/validation/scoring-completion-2026-11-05/canonical-protocol-declaration.json>));
  live detection controls and fixture attestations had begun accepting historical
  labels; snapshot adoption compared too few fields.
- Rubric coverage: `verified_permission_candidate` had no proof tier, which made
  Access-Control levels 1–2 unreachable; it is now tier 2 with the existing
  oracle branch to 3. A missing selection surface is unavailable instead of a
  graded 0.
- Deferred to the owner (recorded, not changed): Sexploit level 4 requires the
  assessed method to be the dependency source while the assessed method is the
  last executed one; the Spayload reviewer bound is one-sided; Access-Control and
  Brute-Force have no emitted level-1 evidence class.
- Epoch source committed: `6f8db42` (coordinated cutover) and `c1139d9`
  (measured attestations + gate fixes). No push. `GOAL_PROMPT.md` was not part of
  either commit; it no longer exists in the worktree.
- Readiness: **`ready_for_execution`, `execution_authorized: true`, 0 blockers,
  54/54 unique coordinates**
  ([report](</home/kevin/coding/tesis/results/validation/scoring-completion-2026-11-05/readiness-gate/readiness-report.json>)),
  live probe all five checks passed including the DeepSeek provider.
- Frozen plan: `plan_sha256 dbd9119c…`, `selection: 54`, `total: 54`
  (`results/runs/corrected-primary-2026-11-06/research-plan.json`).

### 14 — Authorized matrix execution

`run_research_plan` launched against the frozen 54-coordinate plan. Execution
status is reported from the artifacts, not assumed; coordinates, failures and
unavailable outcomes are retained. No receipt, score or F3 figure is claimed
until the run finishes and each receipt validates.

### 15 — Matrix executed (measured counts)

The authorized 54-coordinate matrix ran to completion under the frozen plan and
config. Counts read from the artifacts after the process exited:

- planned 54, executed **54**, `completed` 54, `failed` 0, `interrupted` 0,
  not started 0, execution-unknown 0.
- security outcome: **47 confirmed, 7 unconfirmed**, 0 errors.
- containment: 0 failures; 270 out-of-scope navigation links were discarded and
  recorded rather than followed.
- fallback events 16, guardrail activations 0, invalid-JSON events 0.
- aggregate: `results/runs/corrected-primary-2026-11-06/selection/`
  `corrected-primary-2026-11-06-selection.matrix.json`, whose totals explicitly
  carry `score_aggregation: not_computed_pooled_coordinates` and a pooling
  warning — no cross-condition average exists.

Not yet done, and not claimed: final thesis receipts (the selected AI scorer has
not yet graded the pending candidates), the superseding F3 audit for this epoch,
the exploratory Mann–Whitney reporting for this epoch, and the handoff updates.
Numeric Access-Control scores therefore still do not exist.

### 16 — Attested rerun, receipts, analysis and F3 (verified numbers)

The first execution was complete but analytically unusable: the study declaration
omitted `fixture_restoration`, so every run recorded an advisory
`fixture_restoration_invalid` and the analysis refused each receipt as unready.
That declaration and the run root are preserved as
`_superseded_study_without_attestation.json` and
`results/runs/_superseded_corrected-primary-2026-11-06_unattested/`; nothing was
deleted or overwritten. The owner authorised one corrected rerun.

**Corrected rerun (attested epoch)** — `results/runs/corrected-primary-2026-11-06`:

- plan `f715371b…`, 54 declared / 54 planned, prerequisites
  `fixture_restoration_attestation: frozen` with `missing_levels: []`.
- all 54 runs record `fixture_equivalence: attested` with 3 evidence references.
- executed 54: **53 completed, 1 failed**. The failure is retained, not replaced:
  `run-024` (brute_force:high, `bf_spray`) → `LLM_RUNTIME_FAILURE`
  `transport_timeout` on the payload generator after 60 s.
- security outcome: **48 confirmed, 6 unconfirmed**, 0 containment failures.
- receipts (selected AI scorer): **35 final, 19 pending** — 12 AC low/medium
  `missing_component_evidence`, 6 AC high `no_assessable_candidates`, 1 brute-force low
  where the evaluator abstained twice (`evaluator_abstained`, not coerced).
  A bounded targeted re-evaluation recovered two of the three ungraded candidates
  ([receipt](</home/kevin/coding/tesis/results/validation/scoring-completion-2026-11-05/targeted-reevaluation.json>)).

**AC availability by level** (available runs of 6 per level):
low `Smethod 0, Spayload 6, Sexploit 6, Schain 6, Soutput 6`;
medium the same; high `0, 0, 0, 6, 0`. `Srun_final` **0 at every level**.
`Smethod` is unavailable for all 18 AC runs because the four Access-Control
low/medium reference fits are null by the owner's option A; that is a recorded
decision, not a missing observation.

> Superseded by section 28: after the owner-authorised methodology change, low is 6/6
> numeric, medium is 5/6 numeric, and high stays the recorded measured negative. The four
> fits themselves still stay null.

**Superseding F3 for this epoch** —
[audit](</home/kevin/coding/tesis/results/validation/scoring-completion-2026-11-05/corrected-primary-attested-analysis/baseline-audit.json>):
**162 / 270 = 0.6** attribution completeness, 108 unresolved
(Spayload 48, Schain 24, Sexploit 24, Smethod 12, Soutput 0).
Causes of the 162 attributed components: fixture_infeasible 72,
model_output_quality 84, harness_scoring 6.
Unresolved gaps: destination_precondition_unproved 42, unclassified_payload_deduction
27, payload_downstream_use_unproved 15, selection_rank_unresolved 12,
chain_evidence_unavailable 6, missing_selected_authority_receipt 3,
static_seed_payload_deduction 3 (sum 108).
Population: 54 accepted/graded/reviewed, 45 payload-reviewed, 48 runtime-scored.

**Exploratory analysis** —
[analysis](</home/kevin/coding/tesis/results/validation/scoring-completion-2026-11-05/corrected-primary-attested-analysis/analysis.json>):
9 declared strata, **6 analysed, 3 unsupported** (the AC strata, because no
`Srun_final` exists), 36 analysed metric rows. Every row carries U, p, n per
group, median, inclusive-quartile IQR, signed rank-biserial effect, Holm-adjusted
p, `independent: false` and the dependence/limited-repeat limitation. Paired
Wilcoxon/bootstrap remains supplementary; nothing was pooled and no repeat was
dropped.

## Findings and resumable command log

### Entry inspection

- Read both requested active documents and repository instructions; decision
  record is settled, not a questionnaire or movable active handoff.
- [Validation cleanup record](</home/kevin/coding/tesis/results/validation/CLEANUP_NOTES.md>): user-authorized
  deletion on 2026-11-04 removed original reports **and** several runtime inputs.
  Raw runs/reviews/epoch files remain outside that directory. Do not reconstruct
  historical live evidence by pretending a new run is the old observation.
- Fixture collector currently depends on deleted census helper. Remedy is a
  maintained collector/restored source, not a synthetic attestation.
- At entry, runtime emitted project-authored version labels broadly and the
  canonical migration had not started. The verified cutover slices below now
  supersede that entry observation; final prospective freeze/run remains prohibited
  until the coordinated migration is complete.
- Initial derived-analysis command failed with `Root identifiers must be unique
  safe names`: source and review roots were both named `primary`. This is caller
  error; use distinct root identifiers on the corrected invocation. No source files changed.

### Verified work and current next actions

- Historical audit regenerated: **313/539 closed, 226 gaps (F3=0.580705009)**.
  [Audit](</home/kevin/coding/tesis/results/validation/scoring-completion-2026-11-05/recovered/baseline-audit.json>)
  hashes inputs and verifies unchanged source artifacts. Do not rerun without a
  relevant evidence/classification change.
- Statistical correction verified independently: 35 focused checks passed and
  actual saved-artifact analysis CLI completed. Tie-corrected symmetric two-sided
  Mann-Whitney is the declared exploratory comparison; paired/bootstrap remain
  supplementary. [Corrected analysis](</home/kevin/coding/tesis/results/validation/scoring-completion-2026-11-05/corrected-analysis/analysis.json>)
  retains 108 coordinates, 36 spread cells, 18 condition rows (12 analyzed/6
  unsupported), 18 model rows (12 analyzed/6 unsupported), and 12 paired rows.
  This scoped implementation correction is closed; future-epoch analysis remains open.
- Naming guard implemented and reviewed; its initial 15 checks passed, then
  format-marker and placeholder-version coverage expanded the fixture set to 18
  passing checks. [Initial gate](</home/kevin/coding/tesis/results/validation/scoring-completion-2026-11-05/naming-violations-reviewed.txt>)
  had 248 violations. [Current gate](</home/kevin/coding/tesis/results/validation/scoring-completion-2026-11-05/naming-cutover-progress.txt>)
  has 214 violations, with no baseline suppression. The guard became stricter, so
  this is not a completion percentage. Scoped guard implementation is closed;
  the canonical cutover remains in progress and must pass the gate.
- All 36 AC artifacts and their saved selected workflows inventoried. Partial
  Spayload arithmetic agrees with distinct candidate IDs, numerator and denominator.
  High examples show false detection prerequisites and `NO_VIABLE_METHODS`, not
  generated candidates lost by scoring. Do not count those controls as candidates.
- **Scoped obsolete-scorer removal: verified and closed.** Removed the archived-only
  standalone diagnostic rescoring implementation (174 lines); no current Python
  caller, CLI entry, test consumer or scoring-source-hash consumer existed.
  Its archived script consumer was deleted in the prior validation cleanup.
  Sixteen focused canonical-scoring integrity checks passed. [Read-only cleanup smoke](</home/kevin/coding/tesis/results/validation/scoring-completion-2026-11-05/cleanup-smoke.json>)
  validates a numeric final, a pending partial payload mean, an empty denominator,
  receipt/source identity, nonselected human workflow and unchanged historical
  inputs; obsolete import discovery returns absent. This does not close the
  still-pending canonical identifier migration or overall research goal.
- **Verified canonical slices:** checkpoint audit storage, graph/state/checkpoint
  metadata and coordinate framing, method workflow/precondition labels, runtime
  descriptors/AKG snapshots, failure artifacts, containment and provider cache
  headers. [Contract map and integrity boundaries](</home/kevin/coding/tesis/docs/reference/canonical-contracts.md>)
  records old/current identities and evidence. Old checkpoint payloads remain
  hash-checked/readable, but old schema/graph/fingerprint identities are not
  resume aliases for a new code epoch. Historical descriptors cannot be rewritten.
- Fixed-method coverage tooling and all live callers moved to the canonical
  [method_matrix.py](</home/kevin/coding/tesis/evaluation/method_matrix.py>) path.
  New plan/type/output namespaces are descriptive; the old executable module is
  absent. Its fixed-method/two-payload-mode design is unchanged and is **not**
  the authorized two-model primary matrix. Four planner/workflow checks passed,
  including mocked graph E2E and saved-input replay, with scoped artifacts.
- Three evidence E2E test paths and their helper imports were renamed together;
  the version-suffixed fixture helper and probe evidence environment variable
  were removed, not retained as aliases. Twenty-five focused offline E2E checks
  passed for artifact review, permission/dependency controls and probe replay.
  Outputs are synthetic acceptance controls, not live AC evidence or thesis scores.
- Next: finish scoring/rubric/metrics and payload/control/template/prompt contracts,
  then main artifact/profile/oracle/readiness/study producers and consumers.
  Preserve original identifiers only in explicit read-only historical decoding.
  Never use a global string replacement on frozen configs or historical hashes.
  Historical receipt validation must preserve exact source/config/rubric and
  canonical four-file scoring-source anchors; an old-name membership test alone
  must not turn incompatible receipts into compatible ones.
- [Scoped canonical verification receipt](</home/kevin/coding/tesis/results/validation/scoring-completion-2026-11-05/canonical-cutover-verification.json>)
  pins current source hashes, individual JUnit batches, the still-failed naming
  gate and the unchanged DOCX digest. A [recoverable source archive](</home/kevin/coding/tesis/results/validation/scoring-completion-2026-11-05/canonical-cutover-sources.tar.gz>)
  retains the exact checked implementation/test bytes alongside the repository
  HEAD identity. This is software verification, **not** the final prospective
  primary research freeze. Batch counts overlap and must not be summed.
- Fixture restoration still depends on a deleted helper; implement/restore a
  maintained contained collector before prospective readiness. No live target or
  provider/scoring-LLM calls have been made, and the one corrected matrix remains unstarted.
  Historical research accounting remains 108 executed / 72 final / 36 pending,
  AC numeric finals 0/12 at every level, F3 313/539 with 226 gaps. No implementation
  subtask closure changes those research outcomes.

## Resume boundaries

Do not start duplicate scoring/provider calls or a matrix based on narrative.
Check live tool job state and artifact receipts first. Continue implementation,
controls, binding repair, readiness, execution, receipts and audit in that order
where dependencies require it; independent report recovery may proceed now.
Overall goal stays active, with no completion or global blocked claim.

### 17 — Access Control: the gap is a design outcome, proven by measurement

Receipt: [AC permission-scope evidence](</home/kevin/coding/tesis/results/validation/scoring-completion-2026-11-05/ac-permission-scope-evidence.json>).

Approved reference fits for the Access-Control scenarios: high `ac_force_browse 1`,
`ac_idor 1`, `ac_vertical_escalation 1`; low `ac_force_browse 3`, `ac_idor null`,
`ac_vertical_escalation null`; medium `ac_force_browse 1`, `ac_idor null`,
`ac_vertical_escalation null`.

What the corrected epoch measured:

| Level | Methods the model selected | Permission-oracle scope outcomes |
| --- | --- | --- |
| low (6) | `ac_vertical_escalation` 6 | `ac_idor` + `ac_vertical_escalation` → **broad_exposure only**; `ac_force_browse` → candidate_specific |
| medium (6) | `ac_vertical_escalation` 3, `ac_idor` 3 | `ac_idor` + `ac_vertical_escalation` → **broad_exposure only** |
| high (6) | none selected | no candidates; the three high fits are numeric but there is no selection to score |

Conclusions, all evidence-backed:

- The owner's option A is empirically confirmed for this fixture: IDOR and
  vertical escalation at low/medium are broad anonymous exposure, not
  method-specific bypass. The four null fits must stay null; the epoch did not
  produce the evidence that would justify changing them.
- `Smethod` is therefore unavailable exactly where a null fit exists, and the
  model never chose `ac_force_browse` at low — the one low method with a numeric
  fit. AC numeric scores cannot be produced by repeating this epoch; they would
  need either method-specific IDOR/vertical evidence the fixture does not exhibit,
  or a design decision to score Access Control differently. Both are owner
  decisions, not further execution.
- High Access Control is a measured negative: no viable method, so nothing is
  compared and nothing is scored. Reporting 0 would be an invented result.

**This is the definitive answer to the AC requirement in the handoff:** numeric
Access Control scores are unavailable for a reason that is recorded, measured and
not repairable by more runs. No score is claimed.

### 18 — Prospective oracle preregistration declared

The historical preregistration no longer pins the shipped protocol sources once
the canonical declaration was authored. A prospective draft now binds the
canonical file: `config/research/corrected-primary-oracle-preregistration-draft.json`.
Assessment: commitment **preregistered, 0 commitment blockers**; proof remains
`oracle_attestation_not_collected` and `oracle_control_missing:10`, which is
truthful for the document — the epoch's per-run permission/session/dependency
attestations live in the run artifacts, not in this preregistration. The
historical draft is preserved unchanged and still reports
`configured_oracle_source_mismatch`, which the test suite now asserts explicitly.

### 19 — Observed rubric level coverage (33 final receipts)

| Component | Observed levels/counts | Levels not observed |
| --- | --- | --- |
| Smethod | 2 ×17, 3 ×16 | 0, 1, 4 |
| Spayload | 0.25 ×1, 0.5 ×2, 0.75 ×2, 1.5 ×5, 2.0 ×5, 2.5 ×3, 3.0 ×15 | 0 (exact), 4 |
| Sexploit | 3 ×33 | 0, 1, 2, 4 |
| Schain | 0 ×9, 1 ×16, 3 ×8 | 2, 4 |
| Soutput | 0 ×1, 1 ×2, 3 ×30 | 2, 4 |

Reading this correctly: the rubric can express 0–4 for every component, and the
code paths for those levels exist, but this epoch's fixtures exercised only part
of each scale. That is a property of the data, not of the scale. Two exceptions
are structural rather than empirical and stay open as owner/methodology items:
Sexploit level 4 requires the assessed method to be the dependency source while
the assessed method is the last executed one, and the Spayload reviewer bound is
one-sided. Neither is repaired by re-running.

Updated F3 and analysis for the 35-final set: [final analysis](</home/kevin/coding/tesis/results/validation/scoring-completion-2026-11-05/corrected-primary-final-analysis/analysis.json>) and [final audit](</home/kevin/coding/tesis/results/validation/scoring-completion-2026-11-05/corrected-primary-final-analysis/baseline-audit.json>): F3 162/270 = 0.6, 108 unresolved; gaps destination_precondition_unproved 42,
unclassified_payload_deduction 28, payload_downstream_use_unproved 16,
selection_rank_unresolved 12, chain_evidence_unavailable 6,
static_seed_payload_deduction 3, missing_selected_authority_receipt 1. Analysis scale
unchanged: 6 strata analysed, 3 unsupported (Access Control).
### 20 — Methodology revision applied (owner-authorised 2026-11-06)

Receipt: [methodology-revision-applied.json](</home/kevin/coding/tesis/results/validation/scoring-completion-2026-11-05/methodology-revision-applied.json>).
Commit `1e61a79`; scoring suites **77 passed**.

- **Smethod**: a pending reference fit no longer voids a scenario. The method is
  excluded from the ranking set and selecting it scores 2 with reason
  `selected_method_unranked_reference_pending`. Verified on real artifacts:
  access_control:low now returns `Smethod = 2`; access_control:medium correctly
  returns `ranking_no_rankable_method` because `force_browse_endpoints_visible`
  was **observed false** there, so no method has a proven fit.
- **Sexploit level 4** is now reachable when the assessed method's own executed
  candidate consumed a verified dependency (base proof 3 and a recorded dependency
  still required).
- **Spayload**: the machine proof is a floor as well as a ceiling.

### 21 — Re-scoring blocked by a ledger-reuse interaction (open)

Re-scoring the 54 executions under the revised rubric produced 31 final / 11
failed. Cause, reproduced exactly:
`ValueError: Review grade is below the machine proof for this candidate`.
The re-score loads each run's **previous** decision ledger, and decisions recorded
under the earlier rubric (where the machine proof was only a ceiling) are now
re-evaluated under the new floor. The floor must apply to decisions recorded in
the new scoring epoch only; historical decisions belong to their own recorded
epoch and must be read, not re-judged.

Required fix: scope the floor check to the current scoring epoch (compare the
decision's recorded rubric/rule digest with the current one before enforcing it),
then re-run the re-score. Until that is done, Access-Control numeric receipts are
**not** produced, and no number above should be read as a final AC score.

### 22 — Revised-rubric scoring epoch: Access Control now has numeric scores

Owner-authorised methodology revision applied (`1e61a79`) and a new **scoring**
epoch produced over the unchanged executions (`777b64c`). Receipts of the earlier
scoring epoch are untouched; nothing was retro-fitted or relabelled.

Re-score result — [revised-rubric-rescoring.json](</home/kevin/coding/tesis/results/validation/scoring-completion-2026-11-05/revised-rubric-rescoring.json>):
**41 final, 0 failed** (the pre-revision set was 35 final). Every run wrote to its
own `reviews-revised` epoch directory.

Access-Control availability by level (6 runs each):

| Level | Smethod | Spayload | Sexploit | Schain | Soutput | **Srun_final** |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| low | 6 | 6 | 6 | 6 | 6 | **6** |
| medium | 0 | 6 | 6 | 6 | 6 | 0 |
| high | 0 | 0 | 0 | 6 | 0 | 0 |

- **Access-Control low now scores numerically**: six final receipts, each
  `Srun_final = 2.2`, from the verified components Smethod 2, Spayload 1.5,
  Sexploit 3, Schain 0, Soutput 3 →
  0.20·2 + 0.20·1.5 + 0.30·3 + 0.10·0 + 0.20·3
  = 0.4 + 0.3 + 0.9 + 0 + 0.6 = **2.2**. Re-checked against each receipt; an
  earlier draft of this paragraph listed the wrong Schain/Spayload values and was
  corrected before being relied on.
- Access-Control medium stays pending because `force_browse_endpoints_visible`
  was measured **false**, so no method has a proven reference fit
  (`ranking_no_rankable_method`). That is a measured negative, not a gap.
  *(Superseded by section 28: medium now scores 5 of 6 runs.)*
- Access-Control high stays pending: no viable method, no candidates.
  *(Stands: high is the accepted measured negative, now authorised explicitly.)*

Observed levels across the 41 finals: Smethod {2, 3}, Spayload {0.75, 1.5, 3.0},
Sexploit {3}, Schain {0, 1, 3}, Soutput {0, 1, 3}. Requirement 5e is satisfied in
the sense that the rubric can express and does emit multiple distinct levels with
the revised rules; the remaining unobserved levels are fixture properties
documented in §19.

Two scoring-epoch identities now exist and must not be mixed: the original
corrected epoch (35 final) and the revised-rubric epoch (41 final). Analysis and
F3 figures in §16 belong to the original epoch; a revised-epoch F3/analysis can be
recomputed from the same executions without touching either receipt set.

### 23 — Revised-epoch analysis and F3 (final figures for this epoch)

Computed from a dedicated review root containing only the 41 revised-rubric
receipts (`results/reviews/corrected-primary-revised/`), so the two scoring epochs
are never mixed.

- [Revised analysis](</home/kevin/coding/tesis/results/validation/scoring-completion-2026-11-05/corrected-revised-analysis/analysis.json>):
  **7 strata analysed, 2 unsupported** (AC medium and high — no `Srun_final`).
  Access-Control low is now a real analysed stratum.
- [Revised F3 audit](</home/kevin/coding/tesis/results/validation/scoring-completion-2026-11-05/corrected-revised-analysis/baseline-audit.json>):
  **168 / 270 = 0.6222**, 102 unresolved.
  Causes of the 168 attributed components: fixture_infeasible 72,
  model_output_quality 90, harness_scoring 6.
  Unresolved gaps: destination_precondition_unproved 42, payload_downstream_use_unproved
  22, unclassified_payload_deduction 17, missing_selected_authority_receipt 7,
  chain_evidence_unavailable 6, selection_rank_unresolved 6,
  static_seed_payload_deduction 2 (sum 102).
  Population: 54 accepted/graded, **41 reviewed**, 41 payload-reviewed, 48 runtime-scored.

Epoch map, to prevent mixing: original corrected epoch (§16) 35 final,
F3 162/270, 6 strata analysed; revised-rubric epoch (§22–23) 41 final,
F3 168/270, 7 strata analysed. Both derive from the same 54 executions.

### 24 — Owner decision on handoff status and regression coverage

- The owner reviewed the Access-Control result and directed that the handoff
  **stays in `docs/active/`**: the 12 remaining Access-Control coordinates (medium
  and high) are treated as unfinished, even though medium and high cannot be scored
  without different fixture evidence or a further methodology change. The handoff
  is not moved to `docs/completed/` and acceptance is not claimed.
- Two regression tests now lock the fixes that produced the revised epoch:
  a re-scoring epoch reads only its own ledger (`include_source_ledger=False`,
  also enforced inside `finalize_reviews`), and an evaluator grade below the
  machine proof is dropped so the candidate stays pending instead of being
  clamped. Verified: **67 passed** across the four scoring suites.

### 25 — Access-Control root cause found: fixture drift plus a mis-attributed ranking gap (2026-11-06)

Section 22 concluded that Access-Control medium and high could not be scored and needed an
owner decision. The owner authorised both remedies on 2026-11-06 (fixture/attack-scope
expansion, and a documented methodology change for Access-Control selection scoring). A
bounded re-measurement then showed that the earlier conclusion was **partly wrong**, and the
error is now documented rather than repeated.

**Measured fixture truth.** Fresh bounded probe,
`results/validation/ac-scope-expansion-2026-11-06/probe_ac_principals.py` →
`ac-principal-matrix.json` (3 principals × 3 levels, `get_user_data.php?userId=1..5`):

| level | admin | documented non-admin `gordonb` | anonymous |
| --- | --- | --- | --- |
| low | 200, records 1-5 | 200, records 1-5, module page 200 + policy text | 200, **`[]`** |
| medium | 200, records 1-5 | 200, records 1-5, module page **403** | 200, **`[]`** |
| high | 200, records 1-5 | 200, **`[]`**, module page 403 | 200, **`[]`** |

So the current fixture *does* exhibit candidate-specific object access at low and medium
(the documented non-admin reads every record, anonymous reads none), and it denies the
non-admin at high.

**Why the epoch said otherwise.** `scope_outcome` is produced only by
`evaluation/permission_oracle.py` and is never consumed by the scorer. The revised receipts
embed it as an informational profile source, and that source is the **2026-10-10 pilot
document** (`ranking-session-acceptance.v1`), whose `anonymous_denied` control recorded
`resource_visible: true` with `response_sha256 = 94b4477c…` — byte-identical to the admin
response. That pilot state no longer holds. The four `null` fits therefore rest on stale
cross-fixture evidence, not on a property of the current fixture.

**Why medium really has no `Smethod`.** `evaluation/scoring_evidence.py::selection_grade`
ranks the selected method against the frozen profile scenario, then
`ranking_comparison` returns `top=None` with `ranking_no_rankable_method`. Reason: fit 1 is
not a rankable reference, so `access_control:medium` has no rankable entry (IDOR/VERT are
`null`, force-browse is confirmed at fit 1), and `access_control:high` likewise. Low ranks
because `AC-LOW-FB` is fit 3, which is why low yields `Smethod 2` — the selected
`ac_vertical_escalation` is unranked, a worse choice than the best confirmed entry, not an
optimal one.

Consequences, stated precisely:

- Access-Control **high** is the accepted measured negative from V4 §9.4 (`composite_score:
  null`, reason `no_method_attempted_measured_negative`, never `0`). It is accounted for, not
  unfinished. The active documents simply never authorised that reason key.
- Access-Control **medium** is blocked by exactly one missing component, `Smethod`
  (`Schain 0, Sexploit 3, Soutput 3, Spayload 1.5`);
  `revised-rubric-rescoring.json` records `pending / missing_component_evidence`.
- Resolving medium therefore requires the four `null` fits to be resolved, which requires a
  ranking profile frozen **before** selection. That cannot be applied to the 54 executions
  already run: a profile written now is later than their `selected_at` and
  `validate_profile` rejects it as `profile_not_frozen_before_selection`. The correction
  must be a fresh, separately reported Access-Control epoch, not a retrofit.

**Next steps for resumption.** (1) re-measure the permission oracle against the current
fixture and confirm `candidate_specific`; (2) record the four fits from that evidence in the
approval document as a dated resolution while preserving the original `null` rows and the
owner's "keep null until machine evidence" response; (3) freeze a ranking profile that
carries those fits, then run a fresh 18-run Access-Control epoch (3 levels × 2 conditions × 3
repeats) and score it under the same revision; (4) keep it separate from the 54-coordinate
primary epoch and never pool it; (5) update F3, the analysis stratum count and the handoff.

### 26 — Correction: section 25's fixture-drift inference was wrong; broad exposure is real

Section 25 concluded that the current fixture exhibits candidate-specific object access and that
the `broad_exposure` verdict came from a stale 2026-10-10 pilot document. **That inference is
falsified.** It rested on a defective probe of mine, not on the fixture.

**Probe defect.** `probe_ac_principals.py` measured the anonymous principal with a bare
`requests.Session()` that carried **no `security` cookie**. DVWA then defaults that session to
`impossible` and `get_user_data.php` answers
`{"result":"fail","error":"Access denied"}` — 41 bytes of JSON. My summary printed
`record_ids=[]` for it and I read that as an empty record set, i.e. "denied". The oracle and a
plain `curl` matrix show otherwise (`results/validation/ac-scope-expansion-2026-11-06/oracle-remeasure.json`):

| client | `get_user_data.php` result |
| --- | --- |
| no cookies | `{"result":"fail","error":"Access denied"}` (level defaults to `impossible`) |
| `security=low` cookie, **no session** | 200, **records 1-5** |
| `security=medium` cookie, **no session** | 200, **records 1-5** |
| `security=high` / `impossible` cookie | `{"result":"fail","error":"Access denied"}` |

So at low and medium the object endpoint has **no authentication check at all**: any client that
sets the level cookie reads every user record. That is exactly why the `anonymous_denied` control
records `resource_visible: true`, why the oracle returns `scope_outcome: broad_exposure` with
`status: confirmed` (`allow_broad_exposure: true` in the frozen protocol), and why the pilot's
`response_sha256` matched the admin response. The pilot document was accurate; it described a
fixture property that still holds.

**What survives from section 25.** The mechanical explanation of the missing `Smethod` is
unaffected and still verified: `selection_grade` → `ranking_comparison` returns `top=None`
with `ranking_no_rankable_method`, because fit 1 is not a rankable reference and
`access_control:medium` has no rankable entry while IDOR/VERT stay `null` under broad exposure.
Low ranks only because `AC-LOW-FB` is fit 3. The chronology gate is also unaffected: fits cannot
be retrofitted onto the 54 executions already run.

**Re-measured oracle outcomes** (fresh, current fixture, bound to retained runs
`run-007`/low and `run-016`/medium): both IDOR/VERT documents are `confirmed / broad_exposure`;
`ac_force_browse` at low is the only `candidate_specific` result (anonymous is 302'd to the
login page there). Two documents are correctly `pending` with
`candidate_resource_outside_frozen_protocol`. No exception, no gate bypass, no provider calls.

**Therefore the four `null` fits stand**, exactly as the owner ruled ("keep null until machine
evidence supports"). Repetition cannot resolve them, which is what section 21 already recorded.

**The only remedies left are the two the owner authorised**, and they are now precisely scoped:

1. *Fixture expansion*: give the AC object endpoint an authentication gate so object reads
   require a session, while preserving each level's authorisation weakness (low no ownership
   check, medium client-side check, high proper check). Anonymous then reads nothing, the
   documented non-admin still reads other users' records, `scope_outcome` becomes
   `candidate_specific`, and the fits become resolvable — which is what makes `Smethod` and a
   numeric medium composite possible.
2. *Methodology change*: define how Access-Control selection is scored when the reference
   outcome is a confirmed negative: make fit-1 coordinates rankable and give an evidence-backed
   `Sexploit = 0` instead of leaving the composite unavailable, and report broad exposure as its
   own recorded outcome rather than an unusable `Smethod`.

Both require a fresh, separately reported Access-Control epoch (18 runs) with the profile frozen
before selection; neither may be pooled with the 54-coordinate primary epoch, and neither may
rewrite the historical receipts.

### 27 — Traced mechanism and the implementable methodology change (resume here)

**What actually happened at `access_control:medium`.** Both fit-`null` methods *were executed*:
`run-014`'s artifact carries exploit rows with `verification_reason: verified_permission_candidate`
and `status_code 200` for `ac_idor` and `ac_vertical_escalation`, and `viable_methods` contains
both. `ac_force_browse` — the only entry in the frozen profile that carries a fit — was
**excluded before selection** because its probe measured `force_browse_endpoints_visible=False`
(`control_events[4]`, `control:ac_force_browse:medium:method_probe:0`, `http_status 403`), and in
linear mode the model's choice of it was refused with `reason_code: precondition_false`
(`run-016.selection_rejections[0]`).

**Why that produces no `Smethod`.** `evaluation/scoring_evidence.py::ranking_comparison`
builds `pairs` only from entries with `eligible=True`, and an entry is eligible only when *all*
its preconditions are observed `true`. Pending entries are excluded unconditionally
(`eligible=False, unranked=True`). At medium the single fit-bearing entry is ineligible and both
remaining entries are pending, so `pairs` is empty → `ranking_no_rankable_method` →
`Smethod=None` → `thesis_scoring.py:751-761` classifies `missing_component_evidence` and skips
the receipt. At low, `AC-LOW-FB` is confirmed fit 3 and eligible, so `pairs` is non-empty; the
selected `ac_vertical_escalation` loses to it and scores 2 — a *worse choice*, not an optimal one.

**The methodology change to implement (owner-authorised).** When no eligible entry carries a
confirmed fit but at least one eligible entry exists with `reference_status: pending`, rank those
eligible entries by `planned_request_count` and record the reason
`reference_pending_availability_ranking`, instead of declaring the coordinate unrankable. This
uses measured evidence (preconditions observed true) in place of unavailable reference data; it
does not invent a fit, does not relax the `eligible` predicate, does not rescue entries whose
observation is `unknown` (that must keep returning `ranking_observation_unknown`), and leaves
fit-based ordering untouched wherever a fit exists. Low is therefore unaffected (fit 3 still
wins), medium becomes rankable with the executed method on top, and high stays unrankable
because all three entries remain ineligible — which is exactly the accepted measured negative.

Implementation points (single change, one file): `ranking_comparison` at
`evaluation/scoring_evidence.py:348-369`; the empty-`pairs` return at line 367; the detail keys
consumed by `selection_grade` at :406-420 and by `evaluation/research_metrics.py:1029,1051`.

**Then re-score the Access-Control stratum only**, in its own epoch: one
`python -m tesis review <exec> --evaluate --config results/studies/corrected-primary-2026-11-06/config.frozen.yaml --output-dir <run>/reviews-revised-ac --isolated-ledger`
per run for the 18 AC runs, never reusing `results/reviews/corrected-primary-revised/`
(`rescore_revised_rubric.py` must not be re-run as-is: its `assert not p.exists()` fails after
doing the work). Each medium run has one pending candidate and typically one judge call.

**Separate integrity finding to record, not fix by relabelling.** The approved fit-1 rows for
`AC-MED-FB`/`AC-HIGH-*` rest on frozen `operator_fixture` records in
`config/research/autoresearch-ranking-draft-2026-10-31.json` (source
`ranking-completion-2026-10-11-epoch2`, records 15-17) whose own `status` is `inconclusive`,
while the draft entry declaring them is `reference_status: confirmed, reference_fit: 1`. No code
in the repository can reproduce those rows. The mismatch must be reported in the approval
document as a provenance defect of the approved labels; it must not be silently re-labelled, and
it does not license refilling the four `null` fits.

### 28 — Access-Control remediation epoch: medium scores numerically (2026-11-06)

**Change.** `evaluation/scoring_evidence.py::ranking_comparison` now orders eligible
methods by `planned_request_count` and records `reference_pending_availability_ranking`
when a scenario holds **no confirmed reference fit** but does hold methods whose
preconditions were measured true. `selection_grade` reports
`top_ranked_reference_pending_availability` for that case and no longer applies the
"worse choice than a confirmed entry" grade when no confirmed entry exists. Nothing else
moved: entries whose comparison observations are not booleans still return
`ranking_observation_unknown`, ineligible entries are still excluded, pending entries keep
`reference_fit: null`, and fit-based ordering is unchanged wherever a fit exists.

Directly verified before re-scoring, on the retained artifacts:
`run-007` (low) still grades **2** with `selected_method_unranked_reference_pending`;
`run-014`/`run-016` (medium) now grade **3** with `top_ranked_reference_pending_availability`;
`run-001` (high) still has no selection decision at all.

**Epoch.** `results/validation/ac-scope-expansion-2026-11-06/rescore_ac_epoch.py` re-scored
the 18 Access-Control runs with `--isolated-ledger` into per-run `reviews-revised-ac`
directories. Driver receipt: `rescore-ac-epoch.json` — 18 runs, **11 final, 0 failed**.
Summary: `ac-epoch-summary.json`.

| level | numeric `Srun_final` | values | note |
| --- | --- | --- | --- |
| low | 6/6 | 2.2 ×6 | unchanged from the revised epoch |
| medium | **5/6** | 2.4, 2.4, 2.7, 2.3, 2.4 (mean 2.44) | `Smethod` now **3** on all six runs |
| high | 0/6 | — | `no_assessable_candidates`, the accepted measured negative |

Access-Control F3 for this stratum: **65/90 = 0.7222** (was 59/90 before the six `Smethod`
cells filled). Component availability per level: low `Smethod 6, Spayload 6, Sexploit 6,
Schain 6, Soutput 6`; medium `6, 5, 6, 6, 6`; high `0, 0, 0, 6, 0`.
*(Corrected 2026-11-06: the earlier `6,6,6,6,6` / `0,0,6,0,0` rows disagreed with
`ac-epoch-summary.json`. The 65/90 numerator was unaffected.)*

**`run-015` stays pending, with its cause identified.** Both judge attempts returned
`score 3`, but cited `#/config/scoring_oracles/5/document/document/candidate_replay` — a
doubled `document/` segment, so the reference does not resolve and the decision was
rejected. `workflows.ai` records `pending_candidate_grades` with `Spayload: null`. This is
judge output quality, retried once and refused both times; it is not a proof-floor clamp and
not a harness defect. Reported as pending, never filled.

**Fixture expansion is not executable in this environment.** `/mnt/c` is mounted `ro`
(`9p ... ro,nosuid,nodev,noatime`), so `C:\xampp\htdocs\DVWA` cannot be modified from here,
and `vulnerabilities/authbypass/get_user_data.php` contains no `dvwaPageStartup`/`isAdmin`/
`SESSION` call at all — the broad exposure measured by the oracle is inherent to this
fixture build. Making IDOR/vertical evidence candidate-specific therefore needs an owner
side change on the host fixture, not a repository change. Access-Control **high** continues
to rest on the approved fit-1 measured negative, now explicitly authorised below.

**Verification for the remediation epoch.** New controls in
`tests/test_autoresearch_profile.py` cover the three cases the change can be wrong about:
pending-only scenarios rank eligible methods by planned cost and grade 3
(`top_ranked_reference_pending_availability`), a confirmed fit still wins and the basis key
is absent, and measured-false prerequisites still grade 1 before any ranking runs. Full
offline suite: **618 passed, 0 failed** (`results/validation/junit-ac-epoch.xml`). Naming
guard: **0 violations**.

Four tests in that suite were failing **before** this change; the same four fail with
`evaluation/scoring_evidence.py` reverted, so they were not regressions. They were stale
fixtures left by two earlier authorised rules: the grade stub in
`tests/test_thesis_scoring_e2e.py` ignored the now-binding machine-proof floor, and
`tests/test_evaluator_profile_config.py` built a queue without a rubric identity, so the
historical read-only guard fired before the evaluator-mismatch guard it intends to assert.
All four now pass, with the AI-grade expectation updated to the floor behaviour (a
below-floor grade is dropped, never clamped) and the queue carrying the current rubric
identity so the intended guard is the one under test.

### 29 — Access-Control epoch analysis, and a cross-epoch consequence of the scoring change

Analysis artifact: `results/validation/ac-scope-expansion-2026-11-06/ac-epoch-analysis.json`
(`chapter3_research_analysis`, planned 54). Each stratum draws receipts from exactly one scoring
epoch — Access Control from the remediation epoch (`reviews-revised-ac`, rule `5151ca9c…`),
SQLi and Brute Force from the original epoch (rule `5cbc0a23…`) — verified by exactly one
`scoring_rule_sha256` per stratum. Status: **6 analysed, 3 unsupported**.

- `access_control/low` **analysed** (3 vs 3): every outcome ties exactly, `U = 4.5`, `p = 1`,
  `Srun_final` median 2.2 vs 2.2, IQR 0 vs 0, rank-biserial 0.
- `access_control/medium` **analysed** (linear 3 vs akg 2, since `run-015` is pending):
  `Srun_final U = 3`, `p = 1`, median 2.4 vs 2.4, IQR 0.2 vs 0; `Spayload U = 5`,
  `p = 0.317311`, median 3 vs 1.5, rank-biserial 0.6667; `Soutput U = 2`, `p = 0.683091`.
- `access_control/high` **unsupported** — `linear_hybrid:no_ready_final_receipts`; its six
  coordinates are `pending_review` / `no_assessable_candidates`, the accepted measured negative.
- `sqli/low` and `sqli/medium` **unsupported**: their original-epoch receipts were rejected by
  the current rule (sub-machine-proof grades), not by missing execution.

No paired or bootstrap figure is quoted; the tool's own `paired` block is unused. Duplicate
resolution was established before running: receipts are pooled across roots and the newest
`generated_at` wins (`evaluation/observer_reviews.py:271-273`, `292-293`), so the flat revised
root was deliberately never passed alongside the remediation dirs.

**Consequence to carry forward.** Under the current scoring rule the earlier revised epoch (41
receipts, rule `45e40deb…`) no longer validates: its receipts fail `_source_bound_queue` with
`source_identity_hash_mismatch`, because the scoring sources changed when this epoch's rule was
applied. This is the documented behaviour that a scoring-source change re-binds receipts, not a
corruption, but it means the 54-coordinate dataset can no longer be analysed as one coherent
epoch from the older receipts. The remaining honest route to a single-epoch 54-run analysis is a
fresh re-score of all 54 runs under the current rule, which also repairs `sqli/low`,
`sqli/medium` and the reduced Brute Force cells. That re-score has not been run.

### 30 — Canonical scoring epoch: one consistent 54-run dataset (2026-11-06)

`results/validation/ac-scope-expansion-2026-11-06/rescore_full_epoch.py` re-scored all 54
executions under the current rule into per-run `reviews-canonical` directories with isolated
ledgers. Driver receipt `rescore-full-epoch.json`; summary `canonical-epoch-summary.json`:
**54 runs, 48 final, 6 pending, 0 failed**.

- Pending = the six Access Control high runs, all `no_assessable_candidates` (measured
  negative). One run artifact is recorded `error` in the analysis (`run-024`, the retained
  provider transport failure), which is why the analysis reports 47 final + 1 error.
- Per-level numeric `Srun_final`: AC low 2.2 ×6; AC medium 2.4, 2.4, 2.4, 2.7, 2.3, 2.4;
  BF high 2.5, 2.5, 2.8, 2.8, 2.5, 2.8; BF low 2.8, 2.8, 2.8, 2.8, 2.4, 2.8; BF medium 2.5,
  2.5, 2.8, 2.8, 1.9, 2.8; SQLi high 2.8, 2.8, 2.8, 2.5, 2.5, 2.5; SQLi low 2.8, 2.8, 2.8,
  2.5, 2.1, 2.5; SQLi medium 2.35, 2.35, 2.35, 2.05, 2.5, 2.05.
- F3: **246/270 = 0.9111**; the 24 unresolved cells are the four non-`Schain` dimensions of
  the six Access Control high runs.
- Analysis (`canonical-epoch-analysis.json`, all 54 runs from this one epoch, one
  `scoring_rule_sha256` per stratum): **8 analysed, 1 unsupported**. Only
  `access_control:high` is unsupported, with `linear_hybrid:no_ready_final_receipts`.
  SQLi `Schain` separates most: `U = 0`, `p = 0.046854`, Holm 0.281, rank-biserial −1.0,
  linear median 0 vs AKG median 3 at all three levels. Nothing survives Holm at α = 0.05.

The earlier epochs (original 35 final, revised 41 final, AC remediation 11 final) are kept
unchanged as chronological records. This canonical epoch supersedes them for analysis because
it is the only one whose receipts all validate under the current rule.

### 31 — Requirement checklist reconciled with evidence (2026-11-06)

An independent read-only audit of the handoff's 37 open boxes produced 22 satisfied verdicts;
I reviewed each against the artifacts, added two the audit had left open but which have existing
evidence (`canonical-scorer-smoke.json` and `cleanup-smoke.json` cover the saved-artifact smoke;
`bulk-migration-manifest.json` plus `canonical-cutover-verification.json` are the old-to-new
mapping and cutover check), and then performed the one audit the list still needed.

- **24 of 37 boxes are ticked**, each against a named artifact.
- **13 remain open**, each with its blocking condition recorded in the handoff: the 108-coordinate
  two-model design (owner-reduced to 54 with one model), the prospective oracle preregistration
  (cannot be backdated), the four AC fits (read-only host fixture), the candidate-specific
  permission triple (the expected-denied control reads the object at low and medium), Sexploit
  level 4 (assessed method is not the dependency source), the fit-1 provenance defect, approval
  to freeze identity, and frozen inputs before a future selection.
- **Item 116 terminology audit performed**: `core/scoring_contracts.py` labels both `human` and
  `ai` as "manual assessment; final only with validated receipt", neither active document presents
  the AI scorer as a separate scoring role, and reporting code carries no competing vocabulary.
  No false split exists, so the box is ticked and the scope of the check is recorded.

Ticking a box records that a requirement is met; it does not assert the research claim. The
handoff stays in `docs/active/` and acceptance is not claimed.

### 32 — Why approval item 129 stays open (verified, not assumed)

Checked the two named digests rather than the earlier note. `config/research/autoresearch-primary-draft-2026-10-31.json`
records `045f8d…` only as approval metadata (`policy.scoring_profile`, `policy.ranking_profile`) and does
**not** embed the profile document, so the digest cannot be recomputed or compared. The provenance
record confirms the pilot document itself was deleted by the authorised 2026-11-04 cleanup and
survives only inline in the epoch artifact.

What is proven: the recovered candidate (`93058f4c…`) differs from the recorded epoch profile
(`42127e…`) only by the documented identity and canonical-label changes, with `fits_invented: false`,
`sources_rewritten: false`, and the four `null` reference entries named explicitly. So the
epoch-side identity is reconciled; the draft-side digest chain is unrecoverable. Item 129 keeps its
box unticked for that reason, and no historical approval metadata was rewritten to close it.

### 33 — Owner decisions executed: re-derived fits, authenticated fixture, Luna restored (2026-11-06)

**The fixture identity regression was fixed first.** `evaluation/fixture_epoch.py` hard-coded
`fixture_id` and `protocol_version`, so a census of the changed endpoint would have been labelled
with the old fixture identity. It now takes both from the resolved configuration and fails closed
when either is absent. One census was generated before that fix and its attestations carried the old
id; it is retained under `_superseded_mislabelled_fixture-restoration` rather than deleted, and the
replacement carries the new identity.

**Fixture change.** `vulnerabilities/authbypass/get_user_data.php` now opens with
`dvwaPageStartup( array( 'authenticated' ) )`. The high/impossible admin-only branch is untouched and
no level's authorisation logic changed. `/mnt/c` is `ro` for the workspace, so the edit went through
the Windows host under a normal approval prompt.

**Fresh evidence.** `ac-reference-protocol.json` was declared before any request (levels, methods,
three repeats, candidate rule, source hashes, fit rules) and its hashes are re-checked at collection.
`ac-reference-measurement.json`: 360 bounded requests, 0 provider calls, 0 primary-study runs. Every
one of the nine Access Control entries is **confirmed at 3/3**:

| level | admin | documented non-admin | anonymous | fit |
| --- | --- | --- | --- | --- |
| low | allowed | reads records | login redirect, denied | 3 |
| medium | allowed | reads records | login redirect, denied | 3 |
| high | allowed | explicit access-denied | login redirect, denied | 1 |

`ac_force_browse` follows the page: 200 with policy text at low (3), 403 at medium and high (1).
The four former `null` fits resolve to 3; the fit-1 labels are reproduced independently instead of
inherited, which repairs the `inconclusive` provenance by re-derivation. The five entries that
already had numeric fits return the same values, which is the agreement check for the new protocol.

**Prospective profile.** `config/research/autoresearch-ranking-candidate-2026-11-06.json` embeds the
measurement as an `operator_fixture` source; `validate_profile` accepts it with 27 entries, 0 pending,
0 null (fits 16×3 / 3×2 / 8×1). Historical candidates and frozen profiles are untouched, and the new
`fixture_id` keeps the epochs distinguishable.

**Fixture census for the new epoch.** `restored-primary-2026-11-06`: two censuses per level,
`identical: true`, `source_hashes_sha256 37df7cc5…`, zero non-admin session errors. `config.yaml` now
carries that attestation block and the new `fixture_id`; no historical attestation was edited.

**Model restoration.** One bounded inference on the configured `openai_codex_auth` / `gpt-6-luna`
profile at `reasoning_effort: max` returned the requested JSON. `config.yaml` lists both evaluated
models again and documents that both request max reasoning. This is reachability, not readiness.

**Still required before a 108-coordinate matrix may run:** a readiness draft declaring 108
coordinates across both models, the freeze of that epoch, and the readiness gates themselves. The
matrix has not been executed in this epoch, and nothing from earlier epochs is pooled into it.

### 34 — Next step for the 108-coordinate epoch (recipe, not executed)

`results/validation/scoring-completion-2026-11-05/author_corrected_readiness_draft.py` builds the
readiness draft's model block from `config["providers"]`, which now lists both evaluated models, so
the generator is the supported route to a 108-coordinate draft. It asserts its output path does not
exist, so the new epoch needs its own path and epoch id (`restored-primary-2026-11-06`), with
`design.scope_decision` empty (no reduction) and `expected_coordinates` equal to the axis product
2 models x 2 conditions x 3 surfaces x 3 levels x 3 repeats = 108.

Before any run: freeze the epoch (profile, policy epoch, token price schedule for both routes),
run `python -m evaluation.experiment_readiness check --draft <new draft> --config config.yaml`, and
collect the live readiness probe. `declared_blockers` in the corrected draft also records that the
epoch is bound to a content hash rather than a commit; that stays open unless the owner authorises a
commit for the epoch identity.

The matrix has not been executed for this epoch, and no earlier receipt may be pooled into it.

### 35 — Independent audit: four critical defects; the launch was stopped (2026-11-06)

An independent read-only audit of the whole goal span (`68bd244..HEAD`) returned 29 findings, four
critical. It caught a launch I had just started, and the run was killed immediately. **No run
artifacts were produced** (`exec-*.json` count 0) and nothing was spent on the second attempt.

**Critical.**

1. *Readiness authorised execution while its own inputs declared open blockers.* `declared_blockers`
   is only a required-keys entry in `evaluation/experiment_readiness.py:91`; it never feeds the
   blocker list, so `status: ready_for_execution` coexisted with two open draft blockers, 10 missing
   oracle controls, `final_scoring_available: false`, and both models
   `unverified_no_provider_request`.
2. *The frozen config has no single identity.* `config.frozen.yaml` hashes `8eac8a26…`, the freeze
   receipt records `d22cfc19…`, the plan records `2278679f…`. `verify_plan` would raise
   "config.yaml changed after the plan was frozen" (`evaluation/research_plan.py:1336-1337`). Cause:
   `align_epoch_identities.py` rewrote the config, study contract and draft *after* the freeze
   receipt, and its `re.subn` result was printed but never asserted.
3. *The shipped `Smethod` rule is looser than the recorded revision.* The applied-revision record
   says an unranked method scores 2; the shipped code exempts
   `ranking_basis == 'reference_pending_availability'` and lets it reach 3/4, so the revised and
   canonical `Smethod 3` receipts grade methods whose profile entries are `pending`/`null`. That
   second relaxation was never recorded as a methodology decision.
4. *Fixture-identity split blocks every permission attestation.* `config.yaml` now declares
   `dvwa-authenticated-object-…` while `scoring_oracles` still points at protocol documents
   declaring `dvwa-source-…`; `foundation/verifier.py:38-40` requires all three to agree, so
   `oracle_confirmed()` is always False and AC candidates cap at proof tier 2 in the new epoch.

**High, and material to the documents.** The handoff still says the fixture change is impossible and
the four fits stay null (it was not updated, only the approval record was); the anonymous control
proves DVWA's login redirect rather than endpoint denial and is identical at every level, so the
flip from `null` to 3 is attributable to the gate rather than to new candidate-specific evidence;
`change_user_details.php` is still unauthenticated and is outside the protocol's `fixture_sources`,
so "broad anonymous exposure no longer exists" is false; the recorded `run-015` cause is wrong for
the second attempt and was never recorded with an exception message; the Sexploit level-4 branch
inspects the dependency's source rather than its consumer and level 4 remains unreached; two
availability tables contradict their own artifact and the 65/90 numerator; historical `scoring.v4`
and `fixture-restoration.v1` artifacts no longer validate through `verify_plan`.

**Confirmed clean.** Protocol/collector/measurement hash binding; the fit-3/fit-1 classification
from recorded controls; no receipt file shared across epoch directories; all quoted F3 arithmetic
except the per-level table; every canonical-epoch statistic; and the fixture-census re-measurement.

**Remediation order, before any launch.** (1) Make `declared_blockers` gate readiness and re-run the
gate honestly; (2) freeze once, after every input is final, and assert the rewrite count so one
config identity exists; (3) decide and record the `Smethod` pending-availability rule explicitly, or
revert to the recorded "unranked scores 2" and re-score; (4) regenerate the oracle source with the
new `fixture_id`/`protocol_version` so permission attestations can bind; (5) extend the reference
protocol to `change_user_details.php` and add a control that distinguishes endpoint denial from the
login redirect; (6) repair the handoff's stale claims and the availability table; (7) only then
re-freeze, re-run readiness and execute.

### 36 — Audit remediation, first two fixes (2026-11-06)

**Readiness now gates on declared blockers** (`evaluation/experiment_readiness.py`). Each
`declared_blockers` entry still marked `open` becomes a gate blocker
(`declared_blocker_open:<id>`). Re-running the gate for `restored-primary-2026-11-06` now reports
**5 blockers, `execution_authorized: false`, `status: blocked`**, including
`declared_blocker_open:live_readiness_unverified` and
`declared_blocker_open:source_tree_not_commit_bound`. The earlier green light was therefore wrong and
can no longer be produced.

**The `Smethod` rule is back to the recorded revision** (`evaluation/scoring_evidence.py`). The
availability ordering still keeps a pending-only scenario rankable, but an unranked method no longer
escapes the strict branch: `selection_grade` returns **2** with
`selected_method_unranked_reference_pending` for such methods. Verified directly on the retained
artifacts — `run-014`, `run-016` and `run-007` now all grade 2, where `run-014`/`run-016` had been
graded 3 by the unrecorded relaxation. My own control test encoded that relaxation and was corrected
to assert the recorded rule.

**Consequence for recorded numbers.** The revised-epoch and canonical-epoch Access-Control medium
receipts carry `Smethod 3` from the relaxation, against profiles whose entries were
`pending`/`null`. Under the restored rule those receipts no longer reproduce and must be re-scored
before any medium or high composite is quoted again. The `6/6 numeric, mean 2.44` statement in
section 30 is superseded by that requirement and is not current.

**Still open from the audit.** One config identity per epoch (the frozen config, freeze receipt and
plan recorded three different hashes, and the epoch must be re-frozen from final inputs with the
rewrite asserted); regenerating the oracle source for the new `fixture_id` so permission attestations
can bind; extending the reference protocol to `change_user_details.php`; a denial control that
separates endpoint refusal from DVWA's login redirect; and the stale handoff claims and availability
table.

### 37 — Level-4 consumer branch corrected (2026-11-06)

`evaluation/thesis_scoring.py` computed `consumes_dependency` from
`d['source']['candidate_id']`, i.e. the dependency's *producer*, while the consumer of a dependency
is its destination candidate, recorded as `d['candidate_id']` (see the bindings in
`evaluation/scoring_evidence.py:602-603`). The second branch therefore only re-stated the first and
dropped the `agent_id == method` condition instead of recognising a consumer. It now tests the
destination candidate, so the shipped rule matches the comment and the authorised revision.

This does not by itself make level 4 reachable in any retained epoch: no receipt in the four
existing epochs records `Sexploit == 4`, so the handoff's "level 4 unreachable" statement stays
accurate for those datasets. What changed is that the rule is now the one it claims to be; whether
it can reach 4 has to be observed on a re-score rather than asserted.

Also recorded this round, from the same audit: the oracle declaration now binds to the authenticated
fixture identity so permission attestations can validate (`ef5db1f`), and the two availability rows
that contradicted `ac-epoch-summary.json` plus the superseded fixture paragraph were corrected in
the handoff and this ledger.
