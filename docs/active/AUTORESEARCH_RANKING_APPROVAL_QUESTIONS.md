# Autoresearch ranking profile — owner decision record

**Owner decisions: complete.** The owner accepted the proposed defaults with
“I APPROVE EVERYTHING” and resolved the remaining interpretation with “yup i agree
with A”. No current questionnaire response, personal opinion or routine yes/no
approval remains outstanding. Do not ask these questions again.

**Artifacts:** [ranking draft JSON](../../config/research/autoresearch-ranking-draft-2026-10-31.json)
and [active handoff](HANDOFF_AUTORESEARCH_LOOP_2026-10-30.md).
**Coverage:** 27 entries / 9 scenarios; 23 supported numeric defaults approved,
4 Access Control fits kept null by option A.

## 1. Decision binding and technical status

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

The assistant must transcribe the actual decision provenance into machine metadata,
validate the resulting document and freeze prospectively only when evidence gates
are satisfied. This bookkeeping is not another request for owner approval. No
approval date, evidence or frozen profile is invented by this record.

`reference_fit` is a ranking-reference level (1–3), not a rubric score. Approval of
the 23 supported defaults does not supply missing evidence for the remaining four.
Current scoring is **`scoring_mode=ai`**: no human scorer, verifier or manual artifact
sign-off is required. This choice is fixed and must not be asked again.

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
defaults. As explained in [2C](HANDOFF_AUTORESEARCH_LOOP_2026-10-30.md#2c--what-approval-and-independent-evidence-mean),
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

- Preserve the four nulls and report broad exposure separately until method-specific
  machine evidence supports a reference value. Do not fill them with zero or 3.
- Transcribe settled approvals, validate source/fixture/protocol/epoch bindings and
  distinguish preregistration readiness from later collected evidence.
- Complete implementation and technical readiness work under the existing scope.
  This record starts no run and relaxes no containment or evidence requirement.
- Preserve original artifacts and prospective epoch boundaries; no historical
  scoring retrofit, fabricated receipt or backdated preregistration.

The underlying JSONs remain unchanged by this documentation update. Their stale
approval fields need migration by the assistant, not a repeated owner questionnaire.
