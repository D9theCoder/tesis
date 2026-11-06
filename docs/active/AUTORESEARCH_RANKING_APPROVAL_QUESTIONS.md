# Autoresearch ranking profile — owner decision record

**Owner decisions: complete.** The owner accepted the proposed defaults with
“I APPROVE EVERYTHING” and resolved the remaining interpretation with “yup i agree
with A”. No current questionnaire response, personal opinion or routine yes/no
approval remains outstanding. Do not ask these questions again. This record stays
at its original path because frozen ranking and execution metadata reference it;
it is not an active handoff.

**Unfinished scoring work:** [active AC scoring and methodology handoff](HANDOFF_AC_SCORING_COMPLETION_2026-11-05.md).
It owns the eight remaining work items; this file retains the settled ranking decisions.

**Artifacts:** [ranking draft JSON](../../config/research/autoresearch-ranking-draft-2026-10-31.json)
and [completed handoff](../completed/HANDOFF_AUTORESEARCH_LOOP_2026-10-30.md).
**Coverage:** 27 entries / 9 scenarios; 23 supported numeric defaults approved,
4 Access Control fits kept null by option A.

## 1. Decision binding and technical status

The table below retains the pre-execution draft status, not the current frozen
epoch status. The completed handoff records the executed epoch; the active
scoring handoff tracks its unresolved approval-to-freeze identity and evidence gaps.

| Field | Value |
| --- | --- |
| Draft | `autoresearch-ranking-draft-2026-10-31` / `ranking-draft.v1` |
| Canonical draft SHA-256 | `8bfaa786635fae6a22502bcdcdf7e8edf40dfbf725919ca5c84e258f24ebb12b` |
| On-disk file SHA-256 | `e2489e095b5a35612b7121afbd3e4714632c5da5a304d10e8822c1cb7c141ab4` |
| Fixture | `dvwa-source-fee264766667580e5352` |
| Protocol | `ranking-session-acceptance.v1` |
| Evidence cutoff | `2026-10-11T06:56:00+00:00` |
| Owner decision | Defaults approved; option A selected for the four pending AC entries |
| Machine JSON status | Still `draft_unapproved_unfrozen`; approval metadata not yet migrated |
| Freeze / selector eligibility | Not frozen; not a scoring profile or selector input |

Settled approval provenance must remain bound to the actual profile and evidence.
For a future epoch, reconcile approval-to-freeze identity and validate the resulting
bindings before selection. This bookkeeping is not another request for owner
approval; no approval date, evidence, or prospective freeze may be invented.

`reference_fit` is a ranking-reference level (1–3), not a rubric score. Approval of
the 23 supported defaults does not supply missing evidence for the remaining four.
**Manual scorer includes human and AI scorers.** The configured `scoring_mode=ai`
is the selected implementation of the manual scorer, not a reference-only
substitute. This choice is fixed and must not be asked again; no additional human
scorer, verifier, or human sign-off is required. Retain **manual scoring / manual
assessment** in thesis/manuscript DOCX files; never change that wording to say the
study uses an AI scorer, AI reviewer, or AI-assisted assessment. Internal scorer
metadata remains traceable, and valid existing receipts do not require human regrading.

## 2. Recorded responses

| Former question | Owner decision |
| --- | --- |
| Q1 — Access Control interpretation | **A:** report broad anonymous exposure separately. Require method-specific machine evidence for IDOR/vertical-escalation attribution; keep the four low/medium fits null until supported. Broad exposure is not method-specific fit 3. |
| Q2 — BF fit/count scope | Approved proposed fit 3 for all six entries and inclusion of session-control requests: 23 at low/medium, 26 at high. |
| Q3 — SQLi tiers/counts | Approved proposed entries: UNION 3; error 3 at low/medium but 1 at high; Boolean 2; time 1, with the per-entry counts below. High error remains fit 1 / 12 requests. |
| Q4 — Budget | Approved `candidate_budget=10`. |
| Q5 — Contract | Approved the listed AKG prerequisites/predicates and reference request-count scope; counts are not execution budgets or score weights. Keep `stop_after_target`, `stop_at_budget`, `continue_same_surface`; do not add a new `chain` plan kind. Existing run-scope `Schain` is unchanged. |
| Q6 — Administrative approval/freeze | Routine approval is settled. Machine-metadata migration, evidence validation and prospective freeze are assistant work; approval does not mean those steps have passed. |

The same blanket approval accepts the currently proposed measurement-protocol
defaults. As explained in [2C](../completed/HANDOFF_AUTORESEARCH_LOOP_2026-10-30.md#2c--what-approval-and-independent-evidence-mean),
prospective protocol commitment and later run-specific proof are separate states.
Missing machine evidence is not a request for manual verification or another opinion.

## 3. Entry decisions and evidence references

Evidence abbreviations: `CAL` = `ranking-calibration-cells-2026-10-11`;
`PROP` = `ranking-calibration-proposal-2026-10-11`;
`COMP` = `ranking-completion-2026-10-11-epoch2`;
`SESS` = `bf-session-validation-2026-10-11`;
`EXP` = `expanded-session-pilot-2026-10-10`. Source hashes remain in the draft.
Entry values and evidence pointers below are unchanged; only owner responses are
now recorded. A `pending` evidence status is not a pending owner decision.

### 3.1 Access Control — 9 entries (5 confirmed, 4 pending)

| Review ID | Scenario | Method | Actual `reference_fit` | Status | `planned_request_count` | Prereq / fit predicate `= true` | Evidence refs | Basis / decision note | Owner response |
| --- | --- | --- | --- | --- | ---: | --- | --- | --- | --- |
| `AC-HIGH-FB` | `access_control:high` | `ac_force_browse` | 1 | `confirmed` | 24 | `force_browse_endpoints_visible` | `COMP /records/24-26` | 3/3 exact candidate replays denied; admin control allowed; anonymous denied; no candidate bypass. | **APPROVED — proposed default** |
| `AC-HIGH-IDOR` | `access_control:high` | `ac_idor` | 1 | `confirmed` | 23 | `object_ids_enumerable` | `COMP /records/18-20` | 3/3 exact candidate replays denied; admin control allowed; anonymous denied; no candidate bypass. | **APPROVED — proposed default** |
| `AC-HIGH-VERT` | `access_control:high` | `ac_vertical_escalation` | 1 | `confirmed` | 23 | `role_based_access_present` | `COMP /records/21-23` | 3/3 exact candidate replays denied; admin control allowed; anonymous denied; no candidate bypass. | **APPROVED — proposed default** |
| `AC-LOW-FB` | `access_control:low` | `ac_force_browse` | 3 | `confirmed` | 24 | `force_browse_endpoints_visible` | `COMP /records/6-8` | 3/3 candidate replays expose the admin-only object to the documented non-admin; anonymous control denied. | **APPROVED — proposed default** |
| `AC-LOW-IDOR` | `access_control:low` | `ac_idor` | **null** (proposed 3) | `pending` | 23 | `object_ids_enumerable` | `COMP /records/0-2` | 3/3 records inconclusive for candidate-specific access: non-admin **and** anonymous expected-denied control both see the object. | **A — KEEP NULL; machine evidence required** |
| `AC-LOW-VERT` | `access_control:low` | `ac_vertical_escalation` | **null** (proposed 3) | `pending` | 23 | `role_based_access_present` | `COMP /records/3-5` | Same broad-exposure gap as `AC-LOW-IDOR`; candidate-specific permission behavior unproven. | **A — KEEP NULL; machine evidence required** |
| `AC-MED-FB` | `access_control:medium` | `ac_force_browse` | 1 | `confirmed` | 24 | `force_browse_endpoints_visible` | `COMP /records/15-17` | 3/3 exact candidate replays denied; admin control allowed; anonymous denied; no candidate bypass. | **APPROVED — proposed default** |
| `AC-MED-IDOR` | `access_control:medium` | `ac_idor` | **null** (proposed 3) | `pending` | 23 | `object_ids_enumerable` | `COMP /records/9-11` | 3/3 records inconclusive for candidate-specific access: non-admin **and** anonymous expected-denied control both see the object. | **A — KEEP NULL; machine evidence required** |
| `AC-MED-VERT` | `access_control:medium` | `ac_vertical_escalation` | **null** (proposed 3) | `pending` | 23 | `role_based_access_present` | `COMP /records/12-14` | Same broad-exposure gap as `AC-MED-IDOR`; candidate-specific permission behavior unproven. | **A — KEEP NULL; machine evidence required** |

#### 3.1a Dated resolution (2026-11-06) — the four nulls stand; how selection is scored

> **Superseded later the same day** by section 3.1b: the owner directed re-deriving the
> inconclusive fit-1 records and authorised the host fixture change, so the four fits are now
> confirmed from fresh candidate-specific evidence. The reasoning below stays as the record of
> what was true before that measurement.

The owner authorised both remaining remedies on 2026-11-06: a fixture/attack-scope
expansion capable of method-specific evidence, and a further documented methodology change
for how Access-Control selection is scored. Both were pursued. The table above is
unchanged; the outcomes are recorded here.

**The four `null` fits stay `null`.** Re-measuring the permission oracle against the current
fixture reproduces `scope_outcome: broad_exposure` with `status: confirmed` for both
`ac_idor` and `ac_vertical_escalation` at low and medium. The reason is a fixture property,
not a stale record: with the level cookie and no session at all, `get_user_data.php` returns
all five user records, so the anonymous expected-denied control genuinely reads the object.
Only `ac_force_browse` at low is `candidate_specific`. Option A therefore remains satisfied
on its own terms — broad exposure is not method-specific evidence — and the four entries
stay `pending` with `reference_fit: null`.

**The fixture expansion is not executable from the workspace.** The host fixture is mounted
read-only (`9p ... ro,nosuid,nodev,noatime` on `/mnt/c`), and
`vulnerabilities/authbypass/get_user_data.php` in that tree contains no `dvwaPageStartup`,
`isAdmin` or `SESSION` call. Producing candidate-specific IDOR or vertical evidence needs an
owner-side change to the host fixture; it cannot be done by changing this repository.

**The methodology change is applied and does not touch these fits.**
`evaluation/scoring_evidence.py` now orders eligible methods by `planned_request_count` and
records `reference_pending_availability_ranking` when a scenario holds no confirmed reference
fit but does hold methods whose preconditions were measured true. `reference_fit` is never
invented, pending entries stay pending, unknown comparison observations still fail closed, and
fit-based ordering is unchanged where a fit exists. Re-scoring the 18 Access-Control runs in
an isolated epoch (`reviews-revised-ac`, 11 final, 0 failed) gives numeric scores at low (6/6,
`Srun_final` 2.2) and medium (**5/6**, 2.3-2.7, `Smethod 3` throughout), with high left as the
accepted measured negative (0/6, `no_assessable_candidates`). The subsequent canonical epoch, which re-scores all 54 executions once
under the same rule, resolves medium to **6/6** and reports **F3 246/270 = 0.9111**;
the earlier 5/6 holdout was a judge citation defect, not a rule limit.

**One provenance defect is recorded rather than repaired.** The fit-1 labels on `AC-MED-FB`
and the three `AC-HIGH-*` entries rest on frozen `operator_fixture` records
(`ranking-completion-2026-10-11-epoch2`, records 15-17) whose own `status` is `inconclusive`,
while the draft declares them `confirmed`. No code in this repository reproduces those
records. The labels are reported as they stand; they are neither re-derived nor used to fill
the four `null` fits.

### 3.2 Brute Force — 6 entries (all confirmed)

| Review ID | Scenario | Method | Actual `reference_fit` | Status | `planned_request_count` | Prereq / fit predicate `= true` | Evidence refs | Basis / decision note | Owner response |
| --- | --- | --- | --- | --- | ---: | --- | --- | --- | --- |
| `BF-HIGH-DICT` | `brute_force:high` | `bf_dictionary` | 3 | `confirmed` | 26 | `no_rate_limit` | `SESS /records/12,14,16`; `EXP /records/12,14,16` | 3/3 session controls: login accepted, identity matches, session distinct, wrong credential rejected; count includes session controls. | **APPROVED — proposed default** |
| `BF-HIGH-SPRAY` | `brute_force:high` | `bf_spray` | 3 | `confirmed` | 26 | `no_rate_limit` | `SESS /records/13,15,17`; `EXP /records/13,15,17` | Same 3/3 confirmed-session basis; count includes session controls. | **APPROVED — proposed default** |
| `BF-LOW-DICT` | `brute_force:low` | `bf_dictionary` | 3 | `confirmed` | 23 | `no_rate_limit` | `SESS /records/0,2,4`; `EXP /records/0,2,4` | 3/3 confirmed-session basis; count includes session controls. | **APPROVED — proposed default** |
| `BF-LOW-SPRAY` | `brute_force:low` | `bf_spray` | 3 | `confirmed` | 23 | `no_rate_limit` | `SESS /records/1,3,5`; `EXP /records/1,3,5` | 3/3 confirmed-session basis; count includes session controls. | **APPROVED — proposed default** |
| `BF-MED-DICT` | `brute_force:medium` | `bf_dictionary` | 3 | `confirmed` | 23 | `no_rate_limit` | `SESS /records/6,8,10`; `EXP /records/6,8,10` | 3/3 confirmed-session basis; count includes session controls. | **APPROVED — proposed default** |
| `BF-MED-SPRAY` | `brute_force:medium` | `bf_spray` | 3 | `confirmed` | 23 | `no_rate_limit` | `SESS /records/7,9,11`; `EXP /records/7,9,11` | 3/3 confirmed-session basis; count includes session controls. | **APPROVED — proposed default** |

### 3.3 SQLi — 12 entries (all confirmed)

| Review ID | Scenario | Method | Actual `reference_fit` | Status | `planned_request_count` | Prereq / fit predicate `= true` | Evidence refs | Basis / decision note | Owner response |
| --- | --- | --- | --- | --- | ---: | --- | --- | --- | --- |
| `SQLI-HIGH-BOOL` | `sqli:high` | `sqli_boolean_blind` | 2 | `confirmed` | 4 | `response_diff_detectable` | `CAL /records/26,30,34`; `PROP /scenarios/sqli:high` | 3/3 matched true/false response separation; fit 2 follows predeclared tier. | **APPROVED — proposed default** |
| `SQLI-HIGH-ERROR` | `sqli:high` | `sqli_error` | **1** | `confirmed` | **12** | `error_messages_enabled` | `COMP /records/27-29`; `CAL /records/25,29,33` | **High-security exception:** 3/3 negative-confirmed; all static/updatexml candidates failed; UNION data excluded; 12 comparison requests. | **APPROVED — proposed default** |
| `SQLI-HIGH-TIME` | `sqli:high` | `sqli_time_blind` | 1 | `confirmed` | 6 | `response_delay_measurable` | `CAL /records/27,31,35`; `PROP /scenarios/sqli:high` | 3/3 measurable attack-versus-control delay; fit 1 follows predeclared tier. | **APPROVED — proposed default** |
| `SQLI-HIGH-UNION` | `sqli:high` | `sqli_union` | 3 | `confirmed` | 8 | `union_select_possible` | `CAL /records/24,28,32`; `PROP /scenarios/sqli:high` | 3/3 `db_hash_column=true` direct database data; fit 3 follows predeclared tier. | **APPROVED — proposed default** |
| `SQLI-LOW-BOOL` | `sqli:low` | `sqli_boolean_blind` | 2 | `confirmed` | 4 | `response_diff_detectable` | `CAL /records/2,6,10`; `PROP /scenarios/sqli:low` | 3/3 matched true/false response separation; fit 2. | **APPROVED — proposed default** |
| `SQLI-LOW-ERROR` | `sqli:low` | `sqli_error` | 3 | `confirmed` | 3 | `error_messages_enabled` | `CAL /records/1,5,9`; `PROP /scenarios/sqli:low` | 3/3 database error leak without UNION fallback; fit 3. | **APPROVED — proposed default** |
| `SQLI-LOW-TIME` | `sqli:low` | `sqli_time_blind` | 1 | `confirmed` | 6 | `response_delay_measurable` | `CAL /records/3,7,11`; `PROP /scenarios/sqli:low` | 3/3 measurable attack-versus-control delay; fit 1. | **APPROVED — proposed default** |
| `SQLI-LOW-UNION` | `sqli:low` | `sqli_union` | 3 | `confirmed` | 3 | `union_select_possible` | `CAL /records/0,4,8`; `PROP /scenarios/sqli:low` | 3/3 direct database data (`db_hash_column=true`); fit 3. | **APPROVED — proposed default** |
| `SQLI-MED-BOOL` | `sqli:medium` | `sqli_boolean_blind` | 2 | `confirmed` | 4 | `response_diff_detectable` | `CAL /records/14,18,22`; `PROP /scenarios/sqli:medium` | 3/3 matched true/false response separation; fit 2. | **APPROVED — proposed default** |
| `SQLI-MED-ERROR` | `sqli:medium` | `sqli_error` | 3 | `confirmed` | 3 | `error_messages_enabled` | `CAL /records/13,17,21`; `PROP /scenarios/sqli:medium` | 3/3 database error leak without UNION fallback; fit 3. | **APPROVED — proposed default** |
| `SQLI-MED-TIME` | `sqli:medium` | `sqli_time_blind` | 1 | `confirmed` | 6 | `response_delay_measurable` | `CAL /records/15,19,23`; `PROP /scenarios/sqli:medium` | 3/3 measurable attack-versus-control delay; fit 1. | **APPROVED — proposed default** |
| `SQLI-MED-UNION` | `sqli:medium` | `sqli_union` | 3 | `confirmed` | 3 | `union_select_possible` | `CAL /records/12,16,20`; `PROP /scenarios/sqli:medium` | 3/3 direct database data (`db_hash_column=true`); fit 3. | **APPROVED — proposed default** |

## 4. Remaining assistant work, not owner questions

The [active scoring-completion handoff](HANDOFF_AC_SCORING_COMPLETION_2026-11-05.md)
owns these eight unfinished items:

> **Status recorded 2026-11-06, restored epoch** (items above are listed as they
> were written when this record was created; see §3.1c for the run that produced
> these numbers): all eight items have verified evidence in the
> [progress ledger](SCORING_COMPLETION_PROGRESS.md). Canonical naming with a
> zero-violation guard, reconciled and re-frozen bindings, and a readiness-gated
> **108-coordinate** two-model execution: 108 planned, 108 reconciled, 0 failed,
> **96 final receipts** under the restored `Smethod` rule, and F3 **358/540 =
> 0.6630** with 16 of 18 model x surface x level strata analysed. Access Control
> low and medium score numerically with `Smethod` 3 in all 24 receipts; the 12
> `access_control:high` coordinates stay unavailable as measured negatives, which
> is the fixture's answer at that level, not missing work. The earlier
> 54-coordinate / 41-receipt / F3 168/270 figures belong to the superseded
> `corrected-primary-2026-11-06` epoch and must not be cited. The owner directed
> that the handoff remain active, so acceptance is not claimed. This note does not
> change any settled decision above.

1. Apply the settled manual-scorer contract consistently: human and AI scorers
   are both manual scorers; the selected AI scorer is not reference-only.
2. Reconcile prospective ranking-profile, approval, oracle, fixture, protocol,
   and epoch bindings without rewriting historical metadata.
3. Resolve the four null AC low/medium fits and AC candidate/control evidence,
   including the 12 high-level runs with no assessable candidates.
4. Prepare a corrected prospective epoch when required; keep any AC-only
   supplement separate from a comparable full 108-run primary dataset.
5. Finalize eligible source-bound manual-scoring receipts with the selected
   scorer; do not require a separate human review or fill unavailable scores.
6. Complete the superseding F3 audit, analysis, and reporting with evidence-linked
   causes and explicit remaining gaps.
7. Remove genuinely obsolete scorer implementations and migrate live callers
   without changing current scoring behavior or historical artifact readability.
   Preserve current rubric semantics while migrating its name under item 8.
8. Remove arbitrary project-authored version names across the entire codebase.
   Keep one canonical unversioned implementation/contract per responsibility,
   migrate all live consumers, and ban future `v1`/`vX` naming with a focused
   naming guard. Preserve historical identities and external version facts.

Preserve the four nulls and report broad exposure separately until method-specific
machine evidence supports a reference value. Do not fill them with zero or 3.
Preserve original artifacts and prospective epoch boundaries: no fabricated
receipt, historical profile retrofit, or backdated preregistration. The linked
handoff records current unfinished work; old draft-status fields above are not a
claim that the executed epoch had no frozen profile. These documentation changes
make no runtime, configuration, artifact, or DOCX changes.

#### 3.1b Re-derived reference fits (2026-11-06, owner-authorised)

The owner directed re-deriving the inconclusive fit-1 records, authorised adding authentication to the
host fixture's object endpoint while preserving each level's authorisation weakness, authorised rubric
changes, and asked for the GPT-6 Luna model to be retried so the study keeps its two-model design.

**Fixture change.** `vulnerabilities/authbypass/get_user_data.php` now begins with
`dvwaPageStartup( array( 'authenticated' ) )`. Its existing high/impossible admin-only branch is
untouched, and no level-specific authorisation logic was changed. The host mount is read-only from the
workspace, so the edit went through the Windows host with a normal approval prompt.

**Protocol declared before measuring.** `results/validation/two-model-restoration-2026-11-06/ac-reference-protocol.json`
fixes the levels, methods, three repeats, the candidate rule, the fixture source hashes, and the
fit rules before any request. Its `collector_sha256` and fixture hashes are re-checked at collection
time and the collection aborts if either moved.

**Measurement.** `ac-reference-measurement.json`: 360 bounded requests, 0 provider calls, 0 primary-study
runs. Every entry is three repeats of one validated static exploit candidate, with three principals:
verified admin, the fixture's documented non-admin, and an anonymous session carrying only the requested
level cookie.

| level | admin | documented non-admin | anonymous | fit |
| --- | --- | --- | --- | --- |
| low | 200, records visible | 200, records visible | redirected to login, no records | 3 |
| medium | 200, records visible | 200, records visible | redirected to login, no records | 3 |
| high | 200, records visible | explicit access-denied envelope | redirected to login, no records | 1 |

`ac_force_browse` follows the page rather than the API: 200 with the admin-only policy text at low
(fit 3), 403 at medium and high (fit 1). All nine Access Control entries are **confirmed at 3/3**;
none is pending.

**What this settles.**

- The four former `null` fits — `AC-LOW-IDOR`, `AC-LOW-VERT`, `AC-MED-IDOR`, `AC-MED-VERT` — are
  now confirmed at fit 3 from candidate-specific evidence. Broad anonymous exposure no longer exists
  in the fixture, so option A's own condition is met rather than overridden.
- The fit-1 labels on `AC-MED-FB` and the three `AC-HIGH-*` entries are **reproduced independently**
  rather than inherited: the same rule returns 1 on fresh 3/3 evidence, so the earlier
  `inconclusive` provenance defect is repaired by re-derivation, not by relabelling.
- The five Access Control entries that already carried numeric fits return the same values as the
  original approval. That agreement is the check that the new protocol measures the same thing.

**Prospective profile.** `config/research/autoresearch-ranking-candidate-2026-11-06.json` carries the
re-derived entries plus the measurement as an embedded `operator_fixture` source, and
`validate_profile` accepts it: 27 entries, 0 pending, 0 null, fits 16×3 / 3×2 / 8×1. The historical
`autoresearch-ranking-candidate-2026-10-31.json` and every frozen profile are unchanged, and the new
`fixture_id` reflects the changed endpoint, so the two epochs cannot be confused.

**Scope limitation, recorded.** IDOR and vertical escalation both read the same API and the fixture
exposes no per-object ownership rule, so what is proven is a principal/object policy breach by a
non-admin against an admin-only resource, not parameter-sensitive ownership enforcement and not a
state-changing privileged action. Both entries keep `action: read`.

**Model restoration.** One bounded inference on the configured `openai_codex_auth` / `gpt-6-luna`
profile at `reasoning_effort: max` completed and returned the requested JSON
(`results/validation/two-model-restoration-2026-11-06/luna-availability-*.json`). That establishes the
model is reachable again; it is not a study run and does not by itself constitute matrix readiness.

### 3.1c The ranking rule was applied in a full declared epoch (2026-11-06)

The owner's rubric authorization ("i authorize rubric changes", "proceed all including the rubric change
if needed") was used for one change only: `Smethod` now grades reference fit (fit 3/2/1 graded 3/2/1,
eligible-but-unranked graded 2) instead of the within-cell ranked position, which had demoted a uniquely
confirmed method. Weights, denominators, evidence gates and unavailable-value behaviour are unchanged.

The rule was then exercised on the whole declared design, not on a pilot cell:

- 108 coordinates executed and reconciled, 0 failed (`results/runs/restored-primary-2026-11-06/`).
- 96 receipts reached `final`; every one carries all five components.
- `Smethod` came out 3 in 60 receipts and 2 in 36, matching the oracle's reference fits: AC low/medium
  and brute force grade 3, sqli grades 2.
- The 12 `access_control` `high` coordinates produce no candidate at all. Each artifact records
  `measured_negative.complete = true` with every required precondition measured false, so those
  coordinates stay **unavailable** rather than being scored 0 or dropped.

**Consequences for the questions in this record.**

- Question 1 (AC ranking preference) is answered by measurement, not preference: at low and medium all
  three AC methods confirm with reference fit 3, so the ranking does not separate them and `Smethod` is 3
  for each. No owner choice between `ac_idor`, `ac_vertical_escalation` and `ac_force_browse` can change
  a score in those cells.
- Question 2 (which fits to publish) is answered for low/medium by the 9-entry re-derived measurement. The
  three `access_control:high` entries keep fit 1 (explicit non-admin denial) and are additionally backed
  by per-run measured negatives.
- The provisional `medium 6/6, mean 2.44` figure is retracted; it was produced under the previous rule and
  the ungated fixture. The AC medium mean in this epoch is 2.4-2.5 depending on the cell, computed from 12
  receipts.
- One label defect surfaced and is fixed at the producer: a complete measured negative was still written
  as `NO_CANDIDATE_CONFIRMATION` ("missing proof"). `core/run_status.py` now returns
  `no_finding`/`VERIFIED_NEGATIVE` for that case, with regression tests. This epoch's artifacts keep the
  old label, because frozen evidence is not rewritten; the audit reports the 12 disagreements for this
  epoch and they do not recur in later artifacts.

Nothing in this record authorises a new matrix run, a new target, or a new provider. The epoch above is
the single corrected run the owner authorised.
