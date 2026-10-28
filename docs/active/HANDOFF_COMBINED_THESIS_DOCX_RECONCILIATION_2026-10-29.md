# Handoff: combine the thesis rubric and metrics DOCX documents

Status: **planned; DOCX implementation has not started**.

This handoff records the owner's reconciliation decisions from the conversation
on 2026-10-29. The current task creates this plan only. It does not modify the
DOCX inputs, runtime, configuration, scoring rules, or experiment artifacts.

## 1. Deliverable and source boundaries

Produce one consolidated Indonesian DOCX from these two merge inputs:

1. [Chapter 3 rubric-table derivative](../active/bab-3-v4-rubric-tables-2026-10-28.docx).
2. [Thesis metrics document](../../metrik_penilaian_tesis.docx).

[Original Chapter 3](../../bab%203%20only.docx) is the comparison baseline for
identifying changed text and preserving the original research intent. It is
**not a third merge input** and must not be overwritten. Preserve both merge
inputs as well; write a new derived file.

Planned outputs when implementation is authorized:

- `docs/active/bab-3-reconciled-2026-10-29.docx`.
- `docs/active/bab-3-reconciled-2026-10-29.audit.json`.
- A source-to-output reconciliation inventory and document comparison evidence
  under `results/validation/docx-reconciliation-20261029/`.

Use the rubric-table derivative as the full-chapter structural base. Use the
older metrics document as the principal wording/detail source for overlapping
evaluation, evaluator, metric, final-score, receipt, and status explanations.
Merge their substantive additions into the appropriate chapter sections rather
than attaching two largely duplicate documents end to end.

## 2. Frozen input identities

These hashes were checked during handoff preparation:

| Role | File | SHA-256 |
| --- | --- | --- |
| Rubric/full-chapter input | `docs/active/bab-3-v4-rubric-tables-2026-10-28.docx` | `3bcccfeab704332e31068094b4732cb50aace2006de360827f5a1131e9dd5fad` |
| Detailed metrics input | `metrik_penilaian_tesis.docx` | `75dd6e877c504e2d7ce37ad8f74df54d0e198463f32b08b8111b00400c50e7d1` |
| Original comparison baseline | `bab 3 only.docx` | `8cc45f07b6e1952cb3a72218a43284ac209968d7c95e306d386c514e66dcfcb7` |

If an input changes before implementation, refresh the inventory and record
the new identity. Do not reuse a visual or comparison acceptance claim for a
different hash.

The [earlier comparison report](../../results/validation/docx-reconciliation-20261029/comparison.md)
and its sibling `comparison.json` contain extracted evidence. The report's
proposed remedies precede the owner's decisions below. In particular, its
recommendations to expand the Linear explanation, add two research blocks,
and include Template are **superseded for this consolidation**.

## 3. Owner decisions that govern the merge

### 3.1 Linear versus AKG: retain the existing explanation

Preserve the existing conceptual distinction and wording, including the
condition table. The owner accepts the original explanation as adequate for
the research. Do not replace it with an implementation-heavy explanation of
shared AKG profiles, validators, or scope machinery. Keep the main comparison
between `linear_hybrid` and `akg_guided_hybrid`, both using hybrid payloads.

### 3.2 Method selection: retain the original research intention

The model chooses the method during the main experiments. Manual
`target_method` remains a testing/diagnostic facility. Such manually targeted
runs do not establish independent model-selection ability.

Do not introduce a forced-method research block, require a second matrix, or
copy the two-block design from
[the revised Chapter 3 Markdown](../completed/CHAPTER_3_REVISED_2026-10-28.md).
The original DOCX, rather than that later design proposal, governs this point
for the consolidated thesis document.

A short clarification may identify manual targeting as diagnostic only. Ensure
matrix wording and any count illustration describe model-selected main runs:
do not simultaneously state that the method is assigned and independently
chosen. A selected method is an observed outcome in the autonomous design;
do not silently multiply run counts by forced target methods. Preserve three
repetitions and the declared study axes. Record any necessary correction to a
count illustration in the audit; do not launch or relabel experiments.

### 3.3 Template: exclude from this document

Do not add `llm_template`, neutral-template procedures, Template provenance,
or a Template ablation. The owner reserves Template for further research and
experimentation. Its availability in the code is not a reason to expand this
thesis document. Preserve the existing seed/hybrid research explanation.

### 3.4 Evaluator and metrics: use the older document as the main source

Retain the older document's thorough explanations of:

- `human`, `ai`, and `both` workflows and their independent results.
- Frozen evaluator configuration, isolation from DVWA tools, output limits,
  timeout, attempt limits, invalid-output handling, and evaluation telemetry.
- Candidate evidence requirements, proof ceilings, final-method scope, and
  the eligible candidate denominator.
- Source-bound receipts, append-only corrections, full-precision calculation,
  final rounding, and repeat comparison.
- Conditional metric availability and missing-input reasons.
- Independent execution status and security outcome, including their tables.

Keep the older document's natural Indonesian phrasing where the meaning is
equivalent to the newer tables. Do not discard detailed prose merely because
the other file has a later date.

Preserve evaluator identity and same-model limitations as a declared setup or
historical setup where supported. Do not turn a particular DeepSeek profile
into a universal requirement that every experiment and evaluator use the same
model. Reconcile the exact identifier against the declared experiment epoch;
configuration flexibility does not by itself authorize selecting a new model.

Describe metrics as available when the necessary evidence exists. Keep null
when it does not. Do not claim a metric is always unavailable merely because
earlier runs lacked its inputs, or always available because code can calculate
it. Retain the older discussion's detail rather than replacing it with a short
list of newly implemented functions.

### 3.5 NULL: explicitly document unavailable assessment

The owner currently accepts NULL because experiments still encounter missing
evidence. Add an explicit assessment-status entry or small companion table
alongside the numeric rubric explaining `null/pending` and `not_applicable`.
NULL is **not a sixth numeric grade**, a new weighted dimension, or a change
to the v4 formula. This is a documentation change; no runtime field or new
metric implementation is requested.

Use the following distinctions consistently:

| Situation | Documented treatment |
| --- | --- |
| Evidence supports a rubric grade | Assign the supported grade from 0 through 4. |
| A method prerequisite is known false | Applicable `Smethod` grade 1, rather than a claim of unknown evidence. |
| Required prerequisite evidence is unknown | `Smethod = null/pending` with the missing-evidence reason. |
| A valid executed candidate has sufficient verified negative evidence | Applicable numeric zero; absence of success alone is insufficient. |
| Required response, control, ranking, oracle, or review evidence is missing | Affected metric/component stays null/pending; retain independently assessable components. |
| A metric is genuinely outside the applicable measurement context | Record `not_applicable`; do not conflate it with failed evidence collection. |
| A required component or eligible denominator is unavailable | `Srun_final` stays null/pending; do not renormalize weights or replace missing values with zero. |

Missing operator, environment, or framework evidence is not automatically a
model failure. Properly recorded malformed model output remains assessable
under its own rubric. Keep partial positive proof distinct from entirely
missing or unassessable evidence; a missing oracle may cap an otherwise
supported partial score rather than erasing all observed evidence.

Report assessable, pending/unassessable, and not-applicable counts with their
reasons and the actual denominators. Never silently drop null observations
or count them as zero in means or success rates. State the denominator used
for each metric; do not impose one generic denominator on all metrics.
Corrected/repeated measurements retain the original attempt and its reason.
Do not invent missing observations, proof, or final scores.

## 4. Content combination map

| Content | Merge action |
| --- | --- |
| Full Chapter 3 structure, original research intent, unaffected prose, figures and equations | Retain from the full-chapter derivative; compare with the original baseline. |
| Tables 3.3–3.4 and surrounding research explanation | Preserve the owner's Linear/AKG interpretation; retain useful metrics-document detail and clarify only approved ambiguities. |
| Tables 3.5–3.11 | Keep one set of seven v4 tables, five numeric levels and four columns, with 35 illustrative examples. Use current reference semantics and the older wording where equivalent. Clarify false versus unknown prerequisites. |
| Repeated scoring.v3/v4 appendices | Integrate current substantive content once into the relevant sections. Label retained historical statements as historical; avoid contradictory duplicate instructions. |
| Payload averaging, eligible candidates, proof ceilings and independent oracles | Preserve the thorough metrics-document explanations and merge unique rubric-document details. |
| Human/AI evaluation and receipts | Preserve the older detailed workflow; retain separate receipts and experiment-model output assessment. |
| Execution and security outcome tables | Include both once; a completed run does not imply a confirmed exploit or final score. |
| Missing evidence and NULL | Add the explicit assessment-status explanation in section 3.5 and reconcile all related prose. |
| Guardrail handling and provider rate-limit retries | Retain their separate purposes. Avoid treating a recovered HTTP 429 as malformed model output or automatically assigning a repaired-output score. |
| Conceptual chain examples | Retain as illustrations of evidence requirements; do not imply an unsupported destination adapter was executed or verified. Avoid adding a new research condition. |
| Earlier acceptance statements and lifecycle links | Keep limitations tied to their actual epoch and update links. Offline verification and illustrative examples do not establish current live acceptance. |
| Template and a forced-method main-study block | Exclude, according to the owner's decisions. |

Preserve every score dimension and the existing weights:

```text
Srun = 0.20*Smethod + 0.20*Spayload + 0.30*Sexploit
     + 0.10*Schain + 0.20*Soutput
```

`Spayload_final` remains the mean of distinct executed valid exploit/bypass
candidate grades for the final method. Probes, rejected candidates and
unexecuted candidates do not enter that denominator. Human and AI workflows
remain separate. Changes to prose do not rewrite historical artifacts.

## 5. Implementation procedure

1. Recheck input hashes and extract document paragraphs, rubric cells,
   equations, drawings and package inventories without modifying the inputs.
2. Build a section-level inventory of both merge inputs. Identify unchanged,
   duplicate, unique, conflicting and historical content. Map every substantive
   unique passage to its retained location or explain why it was superseded.
3. Copy the full-chapter derivative to the new output. Merge the metrics
   document's unique material into the corresponding sections, applying the
   owner decisions above. Preserve intended numbering and cross-references.
4. Compare the combined text with `bab 3 only.docx`. Mark added/revised wording
   red (`FF0000`), including new or revised table-cell text. Inherited red/blue
   markings from the metrics document are not the comparison authority:
   recompute changes against the original baseline. Keep unchanged text in
   its original formatting. Record deleted/superseded text in the audit
   inventory so deletions are not lost merely because they are absent from the
   output. Do not add a second marked DOCX unless requested.
5. Use natural Indonesian matching the surrounding report. Keep appropriate
   English technical terms italicized. Preserve rubric meaning, mathematical
   notation, examples, page settings, figures and embedded objects. Adjust
   table geometry only where the inserted content requires it, and record it.
6. Write the audit with all three input hashes, the output hash, section
   provenance, deduplication/conflict decisions, change-color coverage, preserved
   package objects, and exact validation limitations. Do not claim visual
   acceptance from XML or ZIP checks.

The source code and [scoring reference](../reference/thesis_scoring.md) establish
implemented grading. The owner's decisions govern the consolidated document's
research presentation. In particular, do not blindly import the broader
two-block/Template plan from the earlier comparison report or revised Markdown.
If a remaining conflict requires a substantive rubric or runtime change,
record it explicitly rather than implementing that change during a DOCX merge.

## 6. Acceptance and handoff lifecycle

The reconciliation is complete when:

- One combined DOCX and its audit exist; all three inputs retain their original
  hashes.
- Every substantive unique passage has an inventory disposition. Duplicate
  appendices are integrated without losing useful evaluation/status detail.
- All five owner decisions are implemented, including autonomous main-study
  selection, diagnostic-only manual targets, no Template expansion, the older
  detailed evaluator/metrics account, and explicit NULL assessment.
- The seven rubric tables, 35 examples, score weights, candidate denominator,
  independent controls and separate Human/AI receipts retain their meaning.
- Changed wording is identified against the original DOCX, with a reviewable
  deletion/replacement record and no unexplained changes outside the merge.
- Equations, drawings, embedded objects and non-target document parts are
  preserved; additions have valid Word package relationships, numbering and
  cross-references. Visual review, when performed, covers the exact output
  hash and checks table readability, captions, equations and pagination.
- The final delivery states which checks actually ran. Any unperformed visual
  review remains explicitly unverified; do not call layout accepted.

Tests remain unrun under the current session instruction. This handoff does
not authorize tests, E2E, model calls, DVWA traffic, new experiments, or changes
to code/configuration. Document integrity/comparison checks belong to the later
authorized merge; their results must be reported separately from tests and
visual rendering.

Keep this handoff in `docs/upcoming/` until implementation begins, then move it
to `docs/active/` and fix links. Move it to `docs/completed/` when the document
merge and its required document acceptance are complete. Track any unresolved
layout review explicitly. Missing research evidence does not itself prevent
completion of a document that accurately records that limitation; it does
prevent claims that the experiment or research acceptance is complete.

At that point, move the new DOCX and audit together to their completed artifact
location and update links. Do not relocate the two source DOCX files as a side
effect of this merge. On 2026-10-29, after this plan was created, the owner
separately directed moving all non-DOCX documents from `docs/active/` into
`docs/completed/`. The existing implementation handoffs, revised Markdown and
source DOCX audit were archived accordingly; their scientific prerequisites
remain documented as pending. The source rubric DOCX stays active for this merge.
