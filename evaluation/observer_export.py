"""Explicit offline observer projection; no experiments or reviews are run."""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path

from core.run_status import terminal_status, matrix_terminal_status
from evaluation.metrics import UNAVAILABLE_METRICS, aggregate_runs, artifact_summary, metric_reading
from evaluation.observer_reviews import discover_reviews
from evaluation.reporter import write_json_report
from tesis.artifact_catalog import ArtifactCatalog
from tesis.artifact_repository import config_fingerprint
from tesis.runtime_events import redact_secrets, _is_secret_key


SCHEMA_VERSION = "observer-projection.v1"
IDENTITY_FIELDS = (
    "execution_id", "run_id", "experiment_condition", "target_method", "selected_method",
    "payload_mode", "repeat_index", "provider", "model", "model_profile", "surface",
    "security_level", "created_at", "started_at", "finished_at", "generated_at", "duration_seconds",
)


def _identity(entry):
    record = entry.record
    state = record.get("final_state") or {}
    config = record.get("config") or {}
    identity = {key: next((owner[key] for owner in (record, state, config)
                          if owner.get(key) is not None), None) for key in IDENTITY_FIELDS}
    # Config and parent metadata never manufacture an execution identity.
    identity.update(execution_id=record.get("execution_id"), run_id=record.get("run_id"))
    timing = record.get("timing") or {}
    for key in ("started_at", "finished_at", "duration_seconds"):
        if identity[key] is None:
            identity[key] = timing.get(key)
    identity["model"] = identity["model"] or config.get("model_name")
    identity["timing"] = dict(timing)
    identity.update(matrix_execution_id=entry.parent_id, coordinate_index=entry.coordinate_index,
                    coordinate_index_base=0,
                    config_fingerprint=record.get("config_fingerprint") or (config_fingerprint(config) if config else None))
    return identity


def _statuses(catalog, entry):
    try:
        return terminal_status(entry.record)
    except (ValueError, TypeError, AttributeError, KeyError, IndexError):
        entry.diagnostics.append(catalog.diagnostic("invalid_status_schema", entry.path))
        return {"execution_status": None, "execution_reason": None,
                "security_outcome": None, "security_outcome_reason": None}


def _scores(entry):
    record = entry.record
    summary = artifact_summary(record)
    state = record.get("final_state") or {}
    vector = summary.get("composite_scores") or record.get("composite_scores") or state.get("composite_scores") or {}
    if not isinstance(vector, dict):
        vector = {}
    selected_method = record.get("selected_method") or state.get("selected_method") or summary.get("selected_method")
    decisions = state.get("scoring_decisions") or record.get("scoring_decisions") or []
    if selected_method and isinstance(decisions, list):
        decision = next((item for item in reversed(decisions)
                         if isinstance(item, dict) and item.get("dimension") == "Srun"
                         and item.get("method") == selected_method
                         and isinstance(item.get("components"), dict)), None)
        if decision is not None:
            # Runner composite_scores are method totals; the receipt retains
            # the exact component vector used for this method's stored total.
            vector = {**vector, **decision["components"], "Srun": decision.get("score")}
    # Keep stored dimensions only. Never derive a missing component from a
    # maximum candidate score or compute a partial final composite.
    aliases = {"Smethod": "method_score", "Spayload": "payload_score", "Sexploit": "exploitation_score",
               "Schain": "chain_score", "Soutput": "output_score", "Srun": "composite_score"}
    return {"components": {key: vector.get(key, summary.get(key, record.get(key, record.get(alias))))
                           for key, alias in aliases.items()},
            "method_scores": record.get("method_scores", state.get("method_scores")),
            "payload_scores": record.get("payload_scores", state.get("payload_scores")),
            "stored_composite": record.get("composite_score"),
            "rubric_version": record.get("runtime_scoring_rubric_version", "scoring.v2"),
            "status": record.get("composite_score_status", "historical_provisional_scoring.v2"),
            "thesis_scoring_status": record.get("thesis_scoring_status"), "source": entry.source}


def _details(entry):
    details = dict(entry.detail)
    for key in ("execution_log", "candidate_dispositions", "verifier_history", "response_evidence", "timing_evidence"):
        prefix = "" if key in entry.record else "/final_state"
        value = entry.record.get(key, (entry.record.get("final_state") or {}).get(key))
        details[key] = {"available": isinstance(value, list) and bool(value),
                        "source": entry.source, "pointer": entry.source["pointer"] + prefix + "/" + key}
    details["child_artifact"] = entry.source
    details["alternate_locations"] = entry.locations[1:]
    return details


def _historical_analysis(catalog, selectors):
    by_identity = {}
    for selector in selectors:
        root_id, separator, relative = selector.partition(":")
        if not separator or root_id not in catalog.source_roots or Path(relative).is_absolute():
            raise ValueError("Historical analysis needs SOURCE_ROOT:RELATIVE_PATH")
        root = catalog.source_roots[root_id]
        path = (root / relative).resolve()
        catalog.location(path, roots={root_id: root})
        audit = catalog.read(path)
        for row in audit.get("rows", []):
            if not all(row.get(key) for key in ("execution_id", "source_sha256", "source_path", "classification")):
                catalog.diagnostic("unbound_historical_analysis", path)
                continue
            # Historical paths can be repository-relative, unlike detail paths
            # which are always relative to their owning document.
            source = Path(row["source_path"])
            source = source.resolve() if source.exists() else catalog.resolve(source, owner=path)
            catalog.location(source, roots=catalog.source_roots)
            matches = [entry for entry in catalog.runs if entry.path == source
                       and entry.record.get("execution_id") == row["execution_id"]
                       and entry.source["sha256"] == row["source_sha256"]]
            if len(matches) != 1:
                catalog.diagnostic("stale_historical_analysis", path, execution_id=row["execution_id"])
                continue
            by_identity[(row["execution_id"], row["source_sha256"])] = {
                "classification": row["classification"], "source": catalog.binding(path),
                "artifact_type": audit.get("artifact_type"), "generated_at": audit.get("created_at_utc"),
                "source_epoch": root_id,
            }
    return by_identity


def _coverage(records, cancellation=None):
    totals = aggregate_runs(records)
    cancellation = cancellation or {}
    return {**totals, "represented_runs": len(records),
            "planned_runs": cancellation.get("total_runs"),
            "unstarted_runs": cancellation.get("not_started_runs"),
            "legacy_collected_runs": cancellation.get("completed_runs")}


def build_projection(catalog: ArtifactCatalog, *, historical_analysis=()):
    catalog.scan()
    history = _historical_analysis(catalog, historical_analysis)
    runs, normalized = [], []
    for entry in catalog.runs:
        fields = _statuses(catalog, entry)
        summary = artifact_summary(entry.record)
        metrics = {}
        for name in UNAVAILABLE_METRICS:
            value, available, reason = metric_reading(summary, name)
            metrics[name] = {"value": value, "available": available, "unavailable_reason": reason}
        workflows = discover_reviews(catalog, entry)
        runs.append({"identity": _identity(entry), "source": entry.source,
            "execution": {"status": fields["execution_status"], "reason": fields["execution_reason"],
                          "observer": entry.detail.get("observer")},
            "security": {"outcome": fields["security_outcome"], "reason": fields["security_outcome_reason"],
                         "historical_analysis": history.get((entry.record.get("execution_id"), entry.source["sha256"]))},
            "runtime_scores": _scores(entry), "thesis_review": workflows, "metrics": metrics,
            "detail": _details(entry), "diagnostics": entry.diagnostics, "ambiguous": entry.ambiguous})
        if not entry.ambiguous:
            # Invalid lifecycle enums must not reach aggregate_runs through a
            # nested final_state fallback. Keep that source visible as unknown.
            normalized_record = ({"status": "unknown", "final_state": {}, "report": {"summary": summary}}
                                 if fields["security_outcome"] is None else entry.record)
            normalized.append((entry, {**normalized_record, **fields}))
    matrices = []
    for parent in catalog.matrices:
        members = [(entry, record) for entry, record in normalized if entry.parent_source == parent.source]
        children = [record for _, record in members]
        parent_fields = _statuses(catalog, parent)
        if children and parent.record.get("security_outcome") is None:
            rolled_up = matrix_terminal_status(children)
            parent_fields.update({key: rolled_up[key] for key in ("security_outcome", "security_outcome_reason")})
        groups = {}
        for label, keys in (("by_provider", ("provider",)), ("by_provider_level", ("provider", "security_level")),
                            ("by_provider_surface_level", ("provider", "surface", "security_level"))):
            grouped = {}
            for entry, record in members:
                identity = _identity(entry)
                key = "/".join(str(identity[k] or "unknown") for k in keys)
                grouped.setdefault(key, []).append(record)
            groups[label] = {key: aggregate_runs(records) for key, records in grouped.items()}
        matrices.append({"identity": _identity(parent), "source": parent.source,
            "execution": {"status": parent_fields["execution_status"], "reason": parent_fields["execution_reason"],
                          "observer": parent.detail.get("observer")},
            "security": {"outcome": parent_fields["security_outcome"], "reason": parent_fields["security_outcome_reason"]},
            "ambiguous": parent.ambiguous,
            "coverage": _coverage(children, parent.record.get("cancellation")),
            "stored_legacy_totals": parent.record.get("totals"),
            "stored_legacy_status_counts": dict(Counter(child.get("status") for child in parent.record.get("runs", [])
                                                        if catalog.valid_matrix_child(child))),
            "groups": groups, "detail": parent.detail, "diagnostics": parent.diagnostics})
    records = [record for _, record in normalized]
    package_root = Path(__file__).resolve().parents[1]
    code_paths = ("core/run_status.py", "evaluation/metrics.py", "evaluation/observer_export.py",
                  "evaluation/observer_reviews.py", "tesis/artifact_catalog.py", "tesis/artifact_repository.py",
                  "evaluation/thesis_scoring.py", "evaluation/scoring_evidence.py", "foundation/verifier.py",
                  "evaluation/reporter.py", "evaluation/failure_logger.py", "tesis/artifact_layout.py",
                  "tesis/cli.py", "tesis/runtime_events.py")
    projection = {"schema_version": SCHEMA_VERSION, "artifact_type": "observer_projection",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "code_epoch": {name: sha256((package_root / name).read_bytes()).hexdigest() for name in code_paths},
        "selection": {"source_roots": list(catalog.source_roots), "review_roots": list(catalog.review_roots),
                      "review_epoch_policy": "declared_oldest_to_newest; latest_eligible_final_timestamp",
                      "historical_analysis": list(historical_analysis)},
        "roots": [{"id": key, "kind": "source"} for key in catalog.source_roots] + [
            {"id": key, "kind": "review", "epoch_order": order} for order, key in enumerate(catalog.review_roots)],
        "sources": [value[2] for _, value in sorted(catalog.inputs.items())],
        "runs": runs, "matrices": matrices, "coverage": _coverage(records),
        "metrics": aggregate_runs(records)["metrics"], "diagnostics": catalog.diagnostics}
    catalog.verify_unchanged()
    secrets = set()

    def collect_secrets(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if _is_secret_key(key) and isinstance(item, str) and item != "[REDACTED]":
                    secrets.add(item)
                else:
                    collect_secrets(item)
        elif isinstance(value, list):
            for item in value:
                collect_secrets(item)

    for entry in [*catalog.runs, *catalog.matrices]:
        collect_secrets(entry.record.get("config", {}))
    return redact_secrets(projection, known_secrets=secrets)


def _root_arguments(values):
    roots = {}
    for value in values:
        identifier, separator, path = value.partition("=")
        if not separator or not path or identifier in roots:
            raise ValueError("Roots require unique ID=PATH arguments")
        roots[identifier] = Path(path)
    return roots


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", action="append", required=True, metavar="ID=PATH")
    parser.add_argument("--review-root", action="append", default=[], metavar="EPOCH=PATH")
    parser.add_argument("--historical-analysis", action="append", default=[], metavar="ROOT:PATH")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        output = args.output.resolve()
        if not output.is_relative_to((Path.cwd() / "results").resolve()) or output.exists():
            raise ValueError("Projection output must be a new file under results/")
        catalog = ArtifactCatalog(_root_arguments(args.source_root), _root_arguments(args.review_root))
        projection = build_projection(catalog, historical_analysis=args.historical_analysis)
        if output in catalog.inputs:
            raise ValueError("Cannot overwrite an export input")
        write_json_report(output, projection)
        print(json.dumps({"output": str(args.output), "schema_version": SCHEMA_VERSION,
                          "represented_runs": projection["coverage"]["represented_runs"],
                          "diagnostics": len(projection["diagnostics"])}))
        return 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.exit(1, f"Observer export failed: {type(exc).__name__}: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
