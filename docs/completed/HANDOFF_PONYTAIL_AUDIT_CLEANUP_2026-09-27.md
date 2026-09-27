# Ponytail audit cleanup — 2026-09-27

Status: completed for findings 3–11. Findings 1–2 remain deferred.
This handoff was written before implementation and moved here after acceptance.

## Authorized scope

Implement audit findings 3–11. Findings 1 (shared brute-force implementation)
and 2 (shared method execution sequences) are deferred at the user's request
because they could change method behavior. Do not edit the method agents for
this cleanup. No commit or push is authorized.

## Implementation checklist

- [x] 3: Remove unreferenced artifact discovery, metadata, and lookup aliases.
  Retain canonical operations, tested fingerprint grouping, historical JSON
  decoding, and the supported `tesis.tui` facade.
- [x] 4: Remove four unreferenced report helpers: `parse_artifact_or_matrix`,
  `format_evasion_table`, `format_rejection_table`, `format_rich_report_sections`.
  Preserve the score/provider formatters and their nullable-metric assertions.
- [x] 5: Remove `invoke_sample_query`, `get_simulator_llm`, and imports/constants
  used exclusively by them. Preserve the active provider factories.
- [x] 6: Remove unused AKG methods `check_preconditions`, `get_viable_chains`,
  and `_path_is_viable`. Preserve static AKG validation and active routing.
- [x] 7: Remove unused `validate_checkpoint_compatibility`. Preserve the active
  checkpoint identity/resume validators and their regression coverage.
- [x] 8: Remove unused `RunArtifact` and `AggregateReport` dataclasses.
- [x] 9: Remove the three unused cancellation aliases; preserve `check()`.
- [x] 10: Replace the runner's `write_rich_report` call with `write_json_report`
  and remove the duplicate writer. Keep sidecar filenames and JSON format.
- [x] 11: Remove SciPy from project requirements and doctor checks. Regenerate
  `uv.lock`; NumPy should disappear because only SciPy requires it.

## Failure cases and acceptance plan

Before deletion, check imports, calls, exports, decorators, and string-based
references. Potential failures are dangling imports/callers, missing artifact
discovery or lookup behavior, changed rich-sidecar bytes, lost checkpoint
validation, changed cancellation behavior, and dependency/lockfile drift.

Use existing coverage rather than adding deletion-mirroring unit tests. Do not
delete tests. Run from the repository root:

1. `UV_CACHE_DIR=/tmp/tesis-uv-cache uv lock --offline`, then
   `UV_CACHE_DIR=/tmp/tesis-uv-cache uv lock --check --offline`.
   Expected: a consistent lock with SciPy and NumPy removed and no unrelated
   dependency upgrades. If offline resolution fails, record the reason and
   resolve without upgrading the remaining packages.
2. `.venv/bin/python -m pytest -q --junitxml=results/validation/junit.xml`.
   Expected: the full offline/mocked suite passes, including artifact lookup,
   nullable metrics, rich sidecars, checkpoint resume, cancellation, and doctor.
   Save console output under `results/validation/ponytail-audit/`.
3. `.venv/bin/python -m tesis run --dry-run --config config.yaml`.
   Expected: local configuration, graph compilation, and static payload checks
   pass without HTTP/provider calls. Save output in the same evidence directory.
4. `git diff --check` and final reference/diff review. Expected: no dangling
   references in executable code, no method-agent changes, and no unrelated edits.

These checks are offline validation, not live DVWA/provider acceptance. Live
experiments are outside this cleanup. Move this handoff to `docs/completed/`
only when all required acceptance checks pass; otherwise record the remaining
gap here. Findings 1 and 2 remain deferred even after this scoped cleanup passes.

## Execution record

Findings 3–11 are implemented. Findings 1–2 remain deferred; no agent files or
tests were changed. The cleanup removes unused APIs rather than preserving
wrappers around removed APIs. Active artifact scan/filter/lookup/grouping,
score formatting, provider factories, checkpoint validation, and cancellation
remain covered by the existing suite.

- Reference checks found no repository consumers of the removed APIs. Artifact
  cleanup removes 13 metadata conveniences, eight discovery wrappers, eight
  unused lookup methods, two grouping aliases, and two metadata type aliases.
- The runner now calls the existing JSON writer for `.rich.json` sidecars;
  the removed writer had an identical body.
- The first offline lock attempt failed because the temporary cache was empty.
  Copied existing `simple-v20`, `simple-v24`, and `wheels-v6` cache entries from
  `/home/kevin/.cache/uv/` into `/tmp/tesis-uv-cache/` and retried successfully.
- `uv lock --offline`: resolved 76 packages; removed only NumPy 2.4.6 and
  SciPy 1.17.1. Parsed before/after lock records confirm every other third-party
  package is unchanged; only the local `tesis` requirement metadata changed.
- `uv lock --check --offline`: passed. Logs:
  `results/validation/ponytail-audit/lock.log` and `lock-check.log`.
- An additional `uv sync --locked --offline` attempt needed local build-cache
  archives. Copied the cached hatchling, packaging, pathspec, pluggy,
  trove-classifiers, tomlkit, and editables archives into the temporary cache.
  The retry passed: rebuilt the editable project and uninstalled SciPy/NumPy.
  Command: `UV_CACHE_DIR=/tmp/tesis-uv-cache uv sync --locked --offline`.
  Log: `results/validation/ponytail-audit/sync.log`.
- Repository-config dry run: passed, four payload coordinates; log:
  `results/validation/ponytail-audit/dry-run.log`.
- Full offline/mocked pytest suite before sync: 1,283 passed in 87.96 seconds;
  log: `results/validation/ponytail-audit/pytest-before-sync.log`.
- Final full suite after sync: **1,283 passed in 85.77 seconds** with SciPy and
  NumPy absent. Console: `results/validation/ponytail-audit/pytest.log`.
  Machine-readable report: `results/validation/junit.xml`.
- Repeated the repository-config dry run after sync: passed all four payload
  coordinates; `dry-run.log` contains this final result.
- `importlib.util.find_spec` confirms both removed packages are absent from
  `.venv`; output: `results/validation/ponytail-audit/dependencies.log`.
- `git diff --check`: passed. Final structural review confirms no agent or test
  changes, identical old/new rich-writer executable bodies, and no unrelated
  lockfile package changes. Evidence: `results/validation/ponytail-audit/review.json`.
- Net tracked reduction: 556 source/configuration lines and 124 lockfile lines,
  excluding this handoff. No tests were added or removed. No commit or push.
- Required acceptance is complete. Live DVWA/provider tests were not run; no
  claim of live acceptance is made. Findings 1–2 are still deferred.
