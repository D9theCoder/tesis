# Handoff: scoring.v4 defect remediation and evidence capture

Status: **upcoming, 2026-10-11.**

Goal: repair demonstrated review, attribution and capture defects, then test
the repaired system in a fresh live DVWA experiment matrix. The
[completed audit](../completed/HANDOFF_SCORING_V4_REMAINING_EVIDENCE_2026-10-11.md)
accounted for historical evidence; saved-input replay and offline controls
alone cannot close this remediation.

## Issues, changes and proof

| Issue | Required change and acceptance evidence |
| --- | --- |
| 42 unresolved retry causes | Analyze saved sources with independent controls and offline fixtures. Distinguish defects, negatives, fixture limitations and missing evidence. Repair proven capture/review/scoring defects using identical saved-input before/after controls. Retain `insufficient_evidence` where historical proof is unavailable; classify every incomplete outcome in the fresh matrix from its own captured evidence. |
| 34 generated candidates negative/partial; 12 unexecuted | Preserve negatives. Record validation, selection and stop reasons for unexecuted candidates. These are candidate counts across 46 retries. Keep confirmation thresholds unchanged. |
| Three probe responses missing IDs | Fix evidence creation in `agents/state_utils.py` and export paths. Future responses need explicit candidate/control identity, method, visit, validation and request links. Independent controls stay outside exploit denominators; legacy missing IDs remain missing. |
| Three AI JSON failures | In `evaluation/thesis_scoring.py` and the response adapter, capture sanitized raw responses, hashes and available native metadata **before parsing**, including failures. Reproduce format failures offline and fix normalization without weakening schema/citation/proof validation. Keep the three frozen pairs in [completion status](../../results/validation/scoring-v4-completion-2026-10-11/completion-status.json) pending unless they receive valid source-bound decisions. In the fresh matrix, use `openai_compatible` with bounded retries and require a valid AI decision for every assessable candidate; no Human substitution or waiver. |
| 18 nulls; stale review joins | Integrate execution/hash-bound review-round resolution into reopening, discovery and reports. Recover historical pending or unassessable cases only from genuine source-bound evidence; eight no-eligible-candidate sources remain null. Verify historical joins, then independently verify every fresh matrix join, denominator, arithmetic result and separate Human/AI receipt. Never attach fresh evidence to a historical source. |
| Nine incomplete historical inputs | Record exact historical replay as irrecoverable; catalog replays remain diagnostic. Export every fresh matrix visit's validated queue/probes, provenance, order, request method/path/query/body structure, response hashes and sanitized session descriptors. Mark redaction explicitly; never log secrets or claim complete replay from incomplete captures. Prove new capture/replay offline with zero provider calls during replay, and verify the same capture fields in live matrix artifacts. |
| Unpinned Access Control policy | Obtain deployed `/security.php` source/version evidence and the expected principal/resource/action permission matrix. Bind imported controls to that fixture/action. Authenticated non-admin allow does not prove a role bypass. If no role restriction exists, record infeasibility instead of inventing one. |

The four historical probe-gate cases already have a repair; retain its positive
and negative regression controls. Frozen worklist:
[retry ledger](../../results/validation/scoring-v4-remaining-evidence-2026-10-11/audit-epoch2/retry-attribution.json),
[score ledger](../../results/validation/scoring-v4-remaining-evidence-2026-10-11/audit-epoch2/scoring-coverage.json)
and [original-nine disposition](../../results/validation/scoring-v4-remaining-evidence-2026-10-11/audit-epoch2/original-nine-disposition.json).

## Execution and completion gates

1. Freeze hashes and declare failure controls before implementation. Preserve
   the historical 108-run matrix, 49-run retry and prior receipts. Pin the new
   matrix's code, DVWA fixture/version, ranking profile, oracle, provider/model,
   configuration and output root in a fresh epoch. Use the same 108-coordinate
   scope: `linear_hybrid` and `akg_guided_hybrid` × nine explicit target methods
   × three security levels × two payload modes (`hybrid` and
   `llm_mutation_only`) × one repeat, with `openai_compatible` only. Keep
   `hybrid` as the primary payload mode for both thesis conditions.
2. Produce failing/passing E2E artifacts through the affected production paths.
   Cover malformed/truncated responses, incorrect joins, missing IDs, revisits
   and legitimate nulls. Retain the fixed formula, provenance and containment.
   Pass core validation and a dry run per surface before the live matrix; run
   the full offline suite with a fresh JUnit path.
3. Start a **new live DVWA experiment matrix** after repairs. Execute all 108
   planned coordinates with fresh execution IDs, live HTTP and provider calls,
   and a new output root under `results/`; do not resume or relabel historical
   runs. Record start/end manifests, config and source hashes, per-coordinate
   artifacts, transport/containment audit, candidate and probe capture, verifier
   evidence, review receipts and explicit incomplete or skipped outcomes.
4. Review the fresh matrix independently of the historical cohort. Reconcile
   108 planned coordinates to child artifacts and scoring joins; assess every
   eligible candidate with AI, retain legitimate nulls, and classify every
   incomplete result from its own evidence. Compare aggregate outcomes with
   the old matrix only after checking fixture, profile and configuration
   comparability. Saved-input replay remains a defect control, not the new
   experiment result.
5. Deliver `results/validation/scoring-v4-remediation-<epoch>/`: before/after
   controls, response telemetry, fixture provenance, historical dispositions,
   fresh matrix and review audits, capture controls and gate manifest. Record
   commands, expected/observed results, hashes and artifact paths. Close only
   when the fresh matrix and its source-bound scoring/capture checks pass,
   version-bound fixture policy is available, and historical irrecoverable gaps
   have explicit findings and proven prevention controls. Required
   evidence/service failures remain blockers.

Move to `docs/active/` on implementation and `docs/completed/` after all gates
pass; update links. Lost historical data and legitimate negatives/nulls cannot
be eliminated by software repair. Preserve those facts and prove prevention
of demonstrated defects.
