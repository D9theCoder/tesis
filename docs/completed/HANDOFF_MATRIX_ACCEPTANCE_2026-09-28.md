# Matrix handoff acceptance (2026-09-28)

Status: complete. The original quota block was lifted by the user. Only the
`openai_compatible` endpoint is authorized for these matrix runs. Local commits
were approved on 2026-09-29: evidence fixes in `478bb9c`, analysis notebook in
`f65fcd7`. Dated statements about uncommitted work below describe the original
validation steps. No push was performed.

This closes the live execution and artifact-audit work in R3 of
[the remaining-tasks handoff](../completed/HANDOFF_REMAINING_TASKS_2026-09-17.md).
The reasoning/Doctor handoff remains a frozen historical record. Its earlier
interrupted matrices are preserved and are not reused as successful evidence.

## Scope and resolved configuration

The documented R3 command expands to 18 acceptance coordinates:

- Provider: `openai_compatible` only; both roles resolve to that profile.
- Endpoint: `https://tokenharbor.ai/v1/`; model: `deepseek-v4.1-flash`.
- Requested reasoning effort: `low`; role output budgets: 8,192 tokens.
- Surfaces: `sqli`, `access_control`, `brute_force`.
- Security levels: `low`, `medium`, `high`.
- Payload modes: `hybrid` and the optional `static_only` ablation.
- Condition: `akg_guided_hybrid`; automatic method selection; repeat index 0.
- Candidate budget: 10; iteration limit: 10; coverage stop policy: 0.7.
- LLM concurrency: 2; cache scope: `run`; DVWA execution remains serialized.
- Target: the configured authorized DVWA at `http://172.19.48.1/dvwa`.

These are the existing handoff acceptance axes. The main thesis comparison
still requires explicit target methods, both primary conditions, hybrid
payloads, and the research repeat policy. This record does not substitute the
acceptance matrix for that research dataset.

`config.yaml` was not edited. No request was sent to the separately configured
`openai` profile. Inspecting a profile's configuration is an offline check.

## Validation record

Evidence directory: `results/validation/matrix-2026-09-28/` (gitignored).

| Gate | Expected | Observed |
| --- | --- | --- |
| Full offline suite before execution | No failures | 1,313 passed in 95.37 s |
| Dry runs per surface | All static candidates validate; graph compiles | SQLi: 24; access control: 18; brute force: 12 coordinates passed |
| Offline Doctor | All offline checks pass | 11 passed; five live checks explicitly skipped |
| Live Doctor with network access | All checks pass, both roles use the authorized profile | 16/16 passed, no skipped checks |
| Explicit-method hybrid smoke | Successful contained execution with live generation | `sqli_union`, low, hybrid: success; one successful payload-generator call |
| First full matrix | 18 terminal coordinate artifacts | 18/18 success; 84 provider calls; zero failed calls |
| Manual-evidence regression | Fails before fix; passes after fix | Before: missing `validator_result`; focused final suite: 33 passed |
| Second full matrix | 18 terminal coordinate artifacts | 18/18 success; 86 provider calls; one recovered native schema rejection; zero transport errors or containment failures |
| Fresh writer live smoke | Correct linked evidence in freshly generated artifacts | Explicit `bf_spray` smoke and automatic one-coordinate chain smoke both passed their artifact audits |
| Completed-artifact audit | Required fields, valid links, scores, routing, containment, hashes | Passed; 364 rows; zero issues |
| Final full offline suite | No failures | 1,314 passed in 92.02 s |

The first live Doctor attempt ran inside the restricted sandbox and could not
connect to the provider or DVWA. It is retained as
`doctor-live.json`; it is a network-access failure, not quota evidence. The
successful network-enabled report is `doctor-live-network.json`.

The first matrix is `results/runs/matrix-2026-09-28-3/`. Its raw artifact audit
found the missing manual-scoring reference fields in 362 rows. Its runtime
results are preserved; that schema audit was not presented as passing.

The second full matrix is `results/runs/matrix-2026-09-28-4/`, execution
`exec-20260928T151452668353Z-7345dc771bc4483bb99c8edbd387d708`. It completed
with terminal runtime status `finished`, a successful manifest, and all 18
coordinate artifacts. Its 90 containment events were external discovery links
discarded before requests; actual request/redirect containment failures: zero.
Its performance records include one `schema_rejected` native structured-output
response followed by successful recovery. Performance invalid-output rate:
1/93 records (1.08%); 86 provider-backed records plus seven cache hits. The
matrix's state-level `invalid_json_events` and `fallback_events` are both zero,
and its terminal `llm_activity.failed` count is zero. These counters measure
different layers; the recovered call failure remains in the raw records.
The raw audit recorded 25 remaining formatted-payload/duplicate reference
issues from the initially loaded writer; these are corrected in the separate
final evidence export, not silently rewritten in the original live files.

The final export is
`results/validation/matrix-2026-09-28/matrix-final-evidence/`; its audit is
`matrix-audit-final.json`. Selected-method exploitation scores are 3 for 13
coordinates, 1 for one coordinate, and 0 for four coordinates. The four zero
coordinates have no selected method. These results are retained alongside
their successful runtime terminal statuses.

The final writer's explicit-method smoke is
`results/runs/single-run-2026-09-28-7/` (one provider call, seven scoring rows,
zero audit issues). Its explicit target ends execution before chaining. The
automatic one-coordinate chain check is
`results/runs/matrix-2026-09-28-8/` (five provider calls, 21 scoring rows,
zero audit issues). It records valid links for `ac_idor_low_probe_1` and
`ac_idor_low_probe_2`, including the `userId=value` telemetry form. These are
fresh runtime artifacts from the final writer; they required no re-export.

Audit reports: `writer-smoke-audit.json`, `chain-writer-smoke-audit.json`, and
`matrix-audit-final.json`. Offline suite log: `offline-suite-final.log`;
JUnit evidence: `results/validation/junit.xml`.

## Artifact repair

`evaluation/manual_scoring_sheet.py` now links each validated candidate to its
validator result and matching execution, response, and timing records using
JSON Pointers. It accepts the recorded `target_param=value` form used by IDOR
and vertical access-control telemetry. Rejected duplicate candidates receive
no execution links. Scores remain the recorded values, unexecuted candidates
remain null, and manual scoring reasons remain blank for the reviewer.

The regression was written and observed failing before changing the helper.
Existing runner tests did not assert these links. Its concrete failure cases
are missing links, cross-method payload collisions, fabricated evidence for
unexecuted candidates, and input mutation. Both methodology translations now
describe the reference format.

The final evidence export preserves every raw live file. Each exported primary
artifact records its source path and SHA-256. Only `manual_scoring_evidence`
is rebuilt, with export provenance added; execution, responses, scores,
provider usage, and outcomes must compare equal to the source. Re-exporting
makes zero DVWA/provider calls. A fresh live smoke separately checks the final
writer used by a newly started runtime.

## Repeatable commands

Run from the repository root, with network access for live commands:

```bash
.venv/bin/python -m pytest -q --junitxml=results/validation/junit.xml
.venv/bin/python -m tesis doctor --config config.yaml --json
.venv/bin/python -m tesis doctor --config config.yaml --live --json
.venv/bin/python -m tesis run --headless --mode single --config config.yaml --provider openai_compatible --surface sqli --level low --payload-mode hybrid --target-method sqli_union --json
.venv/bin/python -m tesis run --headless --mode matrix --config config.yaml --providers openai_compatible --json
.venv/bin/python -m pytest -q tests/test_manual_scoring_evidence.py tests/test_evaluation_runner.py tests/test_evaluation_multi_llm_runner.py
.venv/bin/python -m tesis run --headless --mode single --config config.yaml --provider openai_compatible --surface brute_force --level low --payload-mode hybrid --target-method bf_spray --json
.venv/bin/python -m tesis run --headless --mode matrix --config config.yaml --providers openai_compatible --surfaces brute_force --levels low --payload-modes hybrid --json
.venv/bin/python results/validation/matrix-2026-09-28/export_evidence.py results/runs/matrix-2026-09-28-4 results/validation/matrix-2026-09-28/matrix-final-evidence
.venv/bin/python results/validation/matrix-2026-09-28/audit.py results/validation/matrix-2026-09-28/matrix-final-evidence results/validation/matrix-2026-09-28/matrix-audit-final.json
```

Use an unused destination directory when repeating the export. The scripts
live with the generated validation evidence; their output includes the source
hashes and all audit findings. CLI summary and stderr files are retained for
both matrices and both writer checks; no unsuccessful run was discarded.

For each surface dry run, copy the source YAML into a temporary private file,
set `matrix: true`, `providers: [openai_compatible]`, and restrict `surfaces`
to one surface. Preserve the three security levels and both payload modes.
Run `tesis run --dry-run --config TEMP_PATH`, then delete the temporary file.
The original YAML and credentials are not copied into the evidence folder.

## Evidence limits

Matrix `status=success` is the runtime's terminal status; it does not mean every
coordinate confirmed a vulnerability. Preserve the individual verifier
decisions and all six score dimensions when analyzing outcomes.

Both live Doctor role probes returned valid structured output and usage, but
neither reported reasoning tokens. Provider-side reasoning execution remains
unverified; requested effort and a successful response are not proof of it.
Unavailable cost/consistency metrics remain null with explicit reasons.

No manual scoring was performed, no main thesis comparison was claimed, and
no commit or push was made.

## Review repairs (2026-09-28)

The earlier zero-issue audit did not assert recovery of historical method
verifier decisions or agent-normalized paths. Review reproduced both omissions
offline. The stricter audit now reports 75 missing method-verifier decisions in
the prior export; that export and its earlier report remain preserved.

The exporter now indexes recorded `graph.state.data.latest_verifier` decisions
by method and keeps each method's most recent decision. The final top-level
verifier supplies the final method's decision. A candidate still requires
matching response evidence before receiving any method verifier. This restores
the recorded `bf_dictionary` confirmation when a later `bf_spray` confirmation
occupies the top-level field.

Force-browse evidence matching reuses the agent's `_normalize_probe_path`
helper, including whitespace removal and legacy double-slash normalization.
Other methods' payloads keep their literal representation; SQL whitespace is
not trimmed. Validation and cross-method evidence filtering remain enforced.

Regression checks were added before the repair: three failures reproduced the
historical verifier loss and the two normalized-path cases. After the repair,
all 38 focused tests pass, including the actual force-browse probe with a fake
session. This is offline/mocked validation, not an additional live experiment.
The final full offline suite passes 1,319 tests in 95.62 seconds; evidence is
`review-fixes/offline-suite.log` and `results/validation/junit.xml`.

The corrected export is
`results/validation/matrix-2026-09-28/review-fixes/matrix-evidence/`; the
stricter `review-fixes/matrix-audit.json` passes all 18 coordinates and 364
scoring rows with zero issues. `review-fixes/restored-verifiers.json` records
the 75 restored decisions. Original raw source hashes and execution/scoring
data compare unchanged. This repair makes zero DVWA/provider calls.

Repeat the repair validation from the repository root:

```bash
.venv/bin/python -m pytest -q tests/test_manual_scoring_evidence.py tests/test_evaluation_runner.py tests/test_evaluation_multi_llm_runner.py --junitxml=results/validation/matrix-2026-09-28/review-fixes/regression-after.xml
.venv/bin/python results/validation/matrix-2026-09-28/export_evidence.py results/runs/matrix-2026-09-28-4 results/validation/matrix-2026-09-28/review-fixes/matrix-evidence
.venv/bin/python results/validation/matrix-2026-09-28/audit.py results/validation/matrix-2026-09-28/review-fixes/matrix-evidence results/validation/matrix-2026-09-28/review-fixes/matrix-audit.json
.venv/bin/python -m pytest -q --junitxml=results/validation/junit.xml
```

Use a fresh export destination for repetition. The repair remains uncommitted.

## Candidate-identity review repairs (2026-09-29)

Normalized path equality could attach an executed seed's evidence to an unused
generated whitespace alias. Stripped access-control IDs could also lose their
recorded links. Both cases were reproduced offline before implementation.

The shared agent helper now retains the actual candidate ID in request,
response, and timing evidence. Force-browse records original attempted values
and normalizes only the request path. The exporter requires validated identity,
method, and stage; legacy aliases require a unique independently recorded
candidate score. Stripped IDOR/vertical ID telemetry is recognized, and SQL
remains literal. Both responses in a bounded brute-force token retry retain
the same candidate ID.

Focused offline checks: 80 passed. Full offline suite: 1,330 passed in 98.68 s.
Evidence: `results/validation/manual-evidence-2026-09-29/focused.xml`,
`offline-suite.log`, and `results/validation/junit.xml`.

The new offline export is
`results/validation/manual-evidence-2026-09-29/matrix-evidence/`; its
`matrix-audit.json` passes all 18 coordinates and 364 manual rows with zero
issues. Source hashes, execution data, and scores remain unchanged. No live
DVWA or provider calls were made for this repair.

The subsequent complete folder review found seven additional defects, with
offline reproductions in the [agents-review handoff](../upcoming/HANDOFF_AGENTS_REVIEW_2026-09-29.md).
Those findings remain open; the matrix audit validates artifact export and
preservation, not the outstanding verifier semantics.

### Follow-up: restrict formatted evidence aliases

The shared matcher previously synthesized `target_param=payload` for every
method. In a validated high/hybrid brute-force queue containing
`credential_pair=admin:unused` followed by `admin:unused`, this allowed the
first candidate's token retry to inherit the second candidate's ID. Both
methods actually emit literal credential candidate text.

Matching now accepts literal text by default. Only IDOR/vertical access
control adds its emitted raw/stripped `userId=` forms; force-browse adds its
normalized path. The unused target-parameter argument was removed from both
callers. Attack strategies, confirmation rules, and request submission are
unchanged.

Four regressions failed before the repair: both complete brute-force agents
reproduced the wrong retry ID, and legacy SQL/force-browse exports reproduced
unsupported prefix links. After repair, 84 focused checks and the full 1,334
test offline suite pass (101.12 s). The brute-force checks use real candidate
validation, fake high-security sessions, and fresh/legacy manual exports.
Captured credential requests, scores, and outcomes compare unchanged.

Evidence root: `results/validation/formatted-alias-2026-09-29/`:

- `before.xml`, `before-artifacts/`: failing regressions and original evidence.
- `focused.xml`, `offline-suite.log`, `results/validation/junit.xml`: passing
  offline checks; JUnit is at its repository-root path.
- `artifacts/`, `repair-audit.json`: corrected fresh/legacy links, preserved
  requests and scoring.
- `matrix-evidence/`, `matrix-audit.json`: separate re-export of all 18 raw
  matrix coordinates; 364 manual rows; zero issues; source hashes, execution,
  and scores preserved.

Repeat from the repository root:

```bash
.venv/bin/python -m pytest -q tests/test_manual_scoring_evidence.py -k 'literal_credentials or unemitted_parameter'
.venv/bin/python -m pytest -q --junitxml=results/validation/junit.xml
PYTHONPATH=. .venv/bin/python results/validation/matrix-2026-09-28/export_evidence.py results/runs/matrix-2026-09-28-4 results/validation/formatted-alias-2026-09-29/matrix-evidence-new
PYTHONPATH=. .venv/bin/python results/validation/matrix-2026-09-28/audit.py results/validation/formatted-alias-2026-09-29/matrix-evidence-new results/validation/formatted-alias-2026-09-29/matrix-audit-new.json
```

Use an unused export destination. No live DVWA/provider calls or notebook
changes were made for this repair. The seven separate agent-review findings
remain open. Nothing was committed or pushed.
