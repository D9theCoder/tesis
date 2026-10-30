# Completed — offline scoring and reporting fixes

**Completed:** 2026-10-31. **Scope:** offline implementation only; the full research loop is not complete.
**Next:** [remaining work and decisions](../active/HANDOFF_AUTORESEARCH_LOOP_2026-10-30.md).
**Rubric:** Tabel 3.5–3.11 in [reconciled Chapter 3](../docx/bab-3-reconciled-2026-10-29.docx); source DOCX unchanged.

## What changed

- **Trustworthy grading (T9/G24):** saved-artifact review is v4-only; conflicting versions are rejected. One canonical scoring digest (`scoring-policy.v4.3`) covers all four scoring/verifier sources; original artifact hashes remain intact.
- **Honest reports (T1):** graded components and pending reasons come first; runtime scores are explicitly legacy. Reports preserve workflow provenance and coordinates, never select best-of-N, and never score unexecuted runs.
- **Evidence rules (T3/G18, G21):** structural output repair—not recovered HTTP 429/network retries—affects output quality. An agent's boolean alone cannot establish partial AC/BF proof. Reviewed payload means can remain numeric while an incomplete composite stays null.
- **Metrics and frozen inputs (frontier F3–F9, F12/F19):** conserved request totals remain usable despite partial role attribution; empty denominators stay null; superseded runs are excluded. Diagnostic counts are measured. Frozen plans require and embed a non-empty resolved price schedule.
- **Offline ledger (P−1/P0/P1, FD1):** [fidelity ledger](../../evaluation/fidelity_ledger.py) records source hashes, component reasons, evidence-linked causes, fidelity metrics and hypothesis priorities. Missing causes remain unresolved; offline analysis cannot declare fresh-epoch convergence.
- **Profile mechanics (B1–B3):** synthetic fifteen-entry fixtures prove post-freeze grades 2/3/4 are reachable. They are not an authored research profile or real experiment results.

## What the saved artifacts show

| Finding | Result |
| --- | --- |
| Accepted baseline | 60 runs / 20 matrices; 48 eligible, 12 AC/high without selection snapshots |
| Automatic grades | `Sexploit 3` ×48; `Schain 0` ×60; `Soutput 3` ×44 and `1` ×4; other exploit/output values pending |
| Unavailable scores | `Smethod`, `Spayload` and `Srun_final` remain null in the saved-artifact projection |
| Request accounting | 8,045 captured requests; attribution still partial, with 4,290 unattributed |
| Selection diagnostic (FD1) | 48/48 final snapshots consistent; six non-final G16 metadata mismatches diagnosed, not repaired |
| Open evidence work | 300 deductions/nulls lack closed-cause decisions; sent-control checks flag label disagreements in 18/60 runs |

Recovered transport retries do **not** reduce the baseline output grades. FD1 is a diagnostic, not a score dimension; its AKG timestamp-provenance caveat remains attached (A2).

## Verification evidence

**110 focused offline checks passed:** [JUnit](../../results/validation/autoresearch-2026-10-31/focused-junit.xml).
The [saved-artifact smoke](../../results/validation/autoresearch-2026-10-31/offline-1814d68ac6/) blocked HTTP/provider access, preserved source hashes, generated the ledger/projection, rendered reports at 60/80 columns, and checked diagnostic counts with a synthetic 2/5 fixture—not a full historical audit.

No full suite, offline/live E2E, target replay or provider-backed epoch was run. No improved-harness or full-convergence claim is made. The owner-directed 108-run epoch is authorized only after the current discussion and technical/scope gates; it has not been launched.
