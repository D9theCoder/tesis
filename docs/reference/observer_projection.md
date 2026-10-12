# Offline observer projection v1

TESIS owns `observer-projection.v1`. The companion [web handoff](../upcoming/HANDOFF_TESIS_WEB_ARTIFACT_RETRIEVAL_2026-10-12.md) consumes this additive contract at its server boundary. Consumer implementation and browser acceptance remain separate gates.

An operator invokes `python -m tesis export-observer --source-root ID=PATH --review-root EPOCH=PATH --output results/observer.json`. Repeat root arguments as needed. Source and review identifiers are unique across both lists. Review roots are declared in oldest-to-newest epoch order. Only declared roots are read; references resolve by real path, including symlinks. Output must be a new file under `results/` and cannot replace an input. Export performs no requests, provider calls, review finalization, or source writes.

The top level has `schema_version`, `artifact_type=observer_projection`, `generated_at`, `code_epoch` (SHA-256 per relevant Python source), `selection`, `roots`, `sources`, `runs`, `matrices`, `coverage`, `metrics`, and `diagnostics`. Roots expose identifier/kind/epoch order, never server absolute paths. `sources` binds every read input to `{root_id, path, sha256}` using original bytes. Consumers must verify these bindings before trusting derived metadata.

Each run has these groups:

| Group | Fields and semantics |
| --- | --- |
| `identity` | `execution_id`, nullable `run_id`, `matrix_execution_id`, zero-based `coordinate_index`, `coordinate_index_base=0`, condition, target/selected method, mode, repeat, provider/model/profile, surface/level, fingerprint, stored timing fields |
| `source` | Root-relative original-byte binding, schema, original status/task result, JSON `pointer` (empty for standalone; `/runs/N` for embedded child) |
| `execution` | Canonical status or null and reason; observer connection/heartbeat is separate |
| `security` | Canonical outcome and reason; separately source-bound historical analysis where explicitly selected |
| `runtime_scores` | Stored provisional scores, rubric/status/source; absent dimensions stay null |
| `thesis_review` | Independent Human/AI workflows: status, reason, component pending reasons, nullable components/finals, grades, numerator/denominator, bound receipt/status/ledger, timestamp, rubric/rule hash |
| `metrics` | Value, available, unavailable reason for each availability-tracked metric |
| `detail` | Root-relative trace/journal/snapshot/child locations, ownership and fallback source, candidate/verifier/evidence JSON pointers and availability |
| `diagnostics` | Missing/schema-invalid/unreadable detail, missing or stale review bindings, missing identity and ambiguous copies |

Matrix entries preserve the parent identity, source, canonical coverage and provider/group summaries separately from stored legacy totals. Coverage uses `aggregate_runs`: completed is not confirmed; unknown and skipped remain visible. Planned/unstarted counts come from stored cancellation metadata, never from completion aliases. Matrix parents are not counted as coordinates. Embedded-only members use their own evidence and the enclosing file hash; absent execution IDs stay null. Conflicting standalone copies are diagnosed and excluded from unique coverage rather than chosen arbitrarily.

Final receipt selection is per `(execution_id, source_sha256, scoring_mode)`: validate source/path/ID, frozen method/config/rubric/selection, candidate eligibility/evidence, formula and four-decimal arithmetic before choosing the latest stored timestamp with root/path tie resolution. A newer pending or invalid receipt cannot erase a valid final. Rule hashes identify the receipt's original scoring epoch, not the exporter's current epoch. Pending statuses use the latest declared eligible epoch. Legacy statuses without identity/timestamp require a unique source hash and a contained, validated decision ledger; directory spelling is never identity proof. Missing, stale, and unselected workflows keep null finals.

`report.summary` wins for metrics, with the existing supported top-level fallback. Availability is explicit; null is not zero and legacy bare numeric placeholders are unavailable (`legacy_numeric`). Runtime scoring.v2 remains provisional. Final payload is the eligible distinct-candidate mean, with fractional components and the unchanged thesis formula. Security classification exclusively reuses `core/run_status.py`.

Optional `--historical-analysis ROOT:RELATIVE_PATH` retains audit classifications and their byte binding independently of canonical outcomes. It requires matching execution ID, source path and source hash. An analysis label never changes canonical counts. Original matrix totals and original run status/task result remain visible.

New manifests retain v1 and add zero/one index declarations, model/profile, repeat, parent ID, stored timing, and relative detail references. Shared journal/snapshot locations are published only when present and owned by that invocation. Review status files add source path, execution/run IDs, selection and UTC generation time. JSON publication uses a unique same-directory temporary file followed by atomic replacement; journals remain append-only.

The producer acceptance and exact commands are recorded in the [completed producer handoff](../completed/HANDOFF_TESIS_ARTIFACT_EXPORT_2026-10-12.md#7-implemented-producer-contract-and-acceptance). `tests/fixtures/observer_projection/epoch7-example.json` is a sanitized four-outcome metadata excerpt, including pending/final AI workflows and a fractional payload mean. Its original-byte bindings are retained; source files are not bundled, so a consumer must distinguish fixture normalization from filesystem/source revalidation. Human and AI fractional finals are covered independently by the producer's focused review controls.
