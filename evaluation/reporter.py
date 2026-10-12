"""Stage 6 reporting helpers for JSON and Markdown outputs."""

from __future__ import annotations

import json
import math
import os
import stat
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from core.run_status import terminal_status


def link_exported_request_evidence(artifact: dict[str, Any]) -> None:
    """Bind response IDs and validation receipts to exported evidence records."""
    request_events: dict[str, list[tuple[int, dict[str, Any]]]] = {}
    events = artifact.get("execution_log")
    if not isinstance(events, list):
        events = []
    for index, event in enumerate(events):
        if not isinstance(event, dict):
            continue
        data = event.get("data")
        if not isinstance(data, dict):
            continue
        payload = data.get("payload")
        if not isinstance(payload, dict):
            payload = {}
        request_id = data.get("request_id") or payload.get("request_id")
        structure = data.get("request_structure") or payload.get("request_structure")
        if request_id is None or not isinstance(structure, dict):
            continue
        request_events.setdefault(str(request_id), []).append((index, structure))

    request_refs: dict[str, str] = {}
    for request_id, matches in request_events.items():
        if len(matches) != 1:
            continue
        index, structure = matches[0]
        pointer = f"#/execution_log/{index}/data/request_structure"
        request_refs[request_id] = pointer
        event_data = events[index]["data"]
        payload = event_data.get("payload")
        if isinstance(payload, dict):
            payload["request_ref"] = pointer
            payload["request_link_status"] = "linked"
        event_data["request_id"] = request_id
        event_data["request_structure"] = deepcopy(structure)
        event_data["request_ref"] = pointer
        event_data["request_link_status"] = "linked"

    method_inputs: dict[tuple[str, str], list[tuple[int, dict[str, Any]]]] = {}
    inputs = artifact.get("method_execution_inputs")
    if isinstance(inputs, list):
        for index, item in enumerate(inputs):
            if not isinstance(item, dict) or not isinstance(item.get("state"), dict):
                continue
            state = item["state"]
            method = str(item.get("method") or state.get("selected_method") or "")
            visit_id = str(state.get("selected_visit_id") or "")
            if method and visit_id:
                method_inputs.setdefault((method, visit_id), []).append((index, state))

    def validation_link(row: dict[str, Any]) -> tuple[str | None, str]:
        method = str(row.get("method") or "")
        visit_id = str(row.get("visit_id") or "")
        matches = method_inputs.get((method, visit_id), [])
        if not matches:
            # Diagnostic and historical exports can have a valid final-state
            # reference without a frozen visit snapshot. Keep that evidence.
            return row.get("validation_ref"), (
                "linked" if row.get("validation_ref") else "unresolved"
            )
        if len(matches) != 1:
            return None, "ambiguous"
        input_index, state = matches[0]
        candidate_id = row.get("candidate_id") or row.get("source_candidate_id")
        if candidate_id is None:
            return None, "unresolved"
        if row.get("identity_kind") == "independent_control":
            controls = state.get("probe_controls", {}).get(method)
            if not isinstance(controls, dict) or controls.get("visit_id") != visit_id:
                return None, "unresolved"
            validation_rows = controls.get("validation_results", [])
            prefix = f"#/method_execution_inputs/{input_index}/state/probe_controls/{method}/validation_results"
        else:
            validation_rows = state.get("payload_validation_results", {}).get(method, [])
            prefix = f"#/method_execution_inputs/{input_index}/state/payload_validation_results/{method}"
        found = [index for index, validation in enumerate(validation_rows)
                 if isinstance(validation, dict)
                 and str(validation.get("candidate_id")) == str(candidate_id)
                 and validation.get("valid") is True]
        if len(found) != 1:
            return None, "ambiguous" if found else "unresolved"
        return f"{prefix}/{found[0]}", "linked"

    def link_validation(row: dict[str, Any]) -> None:
        pointer, status = validation_link(row)
        row["validation_ref"] = pointer
        row["validation_link_status"] = status

    def link_rows(rows: Any) -> None:
        if not isinstance(rows, list):
            return
        for row in rows:
            if not isinstance(row, dict):
                continue
            request_id = row.get("request_id")
            pointer = request_refs.get(str(request_id)) if request_id is not None else None
            row["request_ref"] = pointer
            row["request_link_status"] = "linked" if pointer else (
                "ambiguous" if request_id is not None and len(request_events.get(str(request_id), [])) > 1
                else "unresolved"
            )
            link_validation(row)

    link_rows(artifact.get("response_evidence"))
    link_rows(artifact.get("timing_evidence"))
    # Do not rewrite evidence inside final_state or frozen method inputs here.
    # Those are execution snapshots used for saved-input replay; request links
    # live on the exported evidence rows and point to execution_log structures.


def build_candidate_dispositions(artifact: dict[str, Any]) -> None:
    """Export visit-scoped validation, selection, and stop outcomes.

    ``candidate_disposition_inputs`` contains immutable snapshots captured at
    each validator event. This pass joins those snapshots to response evidence
    after request pointers have been assigned. It only describes selection and
    execution; it does not change the validated queues or runtime behavior.
    """
    inputs = artifact.get("candidate_disposition_inputs")
    if not isinstance(inputs, list):
        artifact["candidate_dispositions"] = []
        return

    responses = artifact.get("response_evidence")
    if not isinstance(responses, list):
        responses = []

    task_result = artifact.get("task_result")
    incomplete_reason = artifact.get("incomplete_reason")
    run_status = artifact.get("status")
    run_error = artifact.get("error")
    canonical_reason = artifact.get("execution_reason") or artifact.get("security_outcome_reason")
    if isinstance(canonical_reason, dict):
        terminal_reason = canonical_reason["code"]
        terminal_reason_source = "artifact.execution_reason" if artifact.get("execution_reason") else "artifact.security_outcome_reason"
    elif incomplete_reason:
        terminal_reason = f"incomplete_reason:{incomplete_reason}"
        terminal_reason_source = "final_state.incomplete_reason"
    elif task_result:
        terminal_reason = f"task_result:{task_result}"
        terminal_reason_source = "final_state.task_result"
    elif run_status and run_status != "success":
        terminal_reason = f"run_status:{run_status}"
        terminal_reason_source = "artifact.status"
    elif run_error:
        terminal_reason = "run_error"
        terminal_reason_source = "artifact.error"
    else:
        terminal_reason = "graph_ended_without_candidate_execution_evidence"
        terminal_reason_source = "capture_observation"

    dispositions: list[dict[str, Any]] = []
    for input_index, snapshot in enumerate(inputs):
        if not isinstance(snapshot, dict):
            continue
        method = str(snapshot.get("method") or "")
        visit_id = str(snapshot.get("visit_id") or "")
        if not method or not visit_id:
            continue

        candidate_rows = snapshot.get("candidate_catalog")
        if not isinstance(candidate_rows, list):
            candidate_rows = []
        candidate_indices: dict[str, int] = {}
        candidates: dict[str, dict[str, Any]] = {}
        for index, candidate in enumerate(candidate_rows):
            if not isinstance(candidate, dict) or candidate.get("candidate_id") is None:
                continue
            candidate_id = str(candidate["candidate_id"])
            candidates[candidate_id] = candidate
            candidate_indices[candidate_id] = index

        queue = snapshot.get("validated_queue")
        if not isinstance(queue, list):
            queue = []
        queue_indices = {
            str(candidate.get("candidate_id")): index
            for index, candidate in enumerate(queue)
            if isinstance(candidate, dict) and candidate.get("candidate_id") is not None
        }

        validations = snapshot.get("validation_results")
        if not isinstance(validations, list):
            validations = []
        previously_tried = {
            str(candidate_id)
            for candidate_id in snapshot.get("previously_tried_candidate_ids", [])
        }
        provenance = snapshot.get("payload_provenance")
        if not isinstance(provenance, dict):
            provenance = {}

        for validation_index, validation in enumerate(validations):
            if not isinstance(validation, dict) or validation.get("candidate_id") is None:
                continue
            candidate_id = str(validation["candidate_id"])
            candidate = candidates.get(candidate_id, {})
            selected_index = queue_indices.get(candidate_id)
            selected = selected_index is not None
            is_valid = validation.get("valid") is True
            reason = str(validation.get("reason") or "")
            budgeted = reason == "candidate_budget_exceeded"
            candidate_response_indices = [
                index for index, response in enumerate(responses)
                if isinstance(response, dict)
                and str(response.get("method") or response.get("agent_id") or "") == method
                and str(response.get("visit_id") or "") == visit_id
                and candidate_id in {
                    str(response.get("candidate_id")) if response.get("candidate_id") is not None else "",
                    str(response.get("source_candidate_id")) if response.get("source_candidate_id") is not None else "",
                }
                and response.get("identity_kind") != "independent_control"
            ]
            executed = bool(candidate_response_indices)

            if not is_valid:
                disposition = "budgeted_out" if budgeted else "rejected"
                selection_status = "budgeted_out" if budgeted else "rejected"
                execution_status = "not_executed"
                stop_reason = reason or "validation_rejected"
                stop_reason_source = "validation_results"
            elif selected and executed:
                disposition = "selected_executed"
                selection_status = "selected"
                execution_status = "executed"
                stop_reason = None
                stop_reason_source = None
            elif selected and candidate_id in previously_tried:
                disposition = "already_tried"
                selection_status = "selected"
                execution_status = "not_executed"
                stop_reason = "already_tried_before_visit"
                stop_reason_source = "tried_payloads"
            else:
                disposition = "terminal_stop"
                selection_status = "selected" if selected else "not_selected"
                execution_status = "not_executed"
                if not selected:
                    stop_reason = "valid_candidate_not_present_in_validated_queue"
                    stop_reason_source = "selection_capture"
                else:
                    stop_reason = terminal_reason
                    stop_reason_source = terminal_reason_source

            row: dict[str, Any] = {
                "method": method,
                "visit_id": visit_id,
                "candidate_id": candidate_id,
                "candidate_ref": (
                    f"#/candidate_disposition_inputs/{input_index}/candidate_catalog/"
                    f"{candidate_indices[candidate_id]}"
                    if candidate_id in candidate_indices else None
                ),
                "validation": dict(validation),
                "validation_ref": (
                    f"#/candidate_disposition_inputs/{input_index}/validation_results/{validation_index}"
                ),
                "validation_status": "valid" if is_valid else "invalid",
                "selection_status": selection_status,
                "selected_queue_index": selected_index,
                "selected_queue_ref": (
                    f"#/candidate_disposition_inputs/{input_index}/validated_queue/{selected_index}"
                    if selected else None
                ),
                "execution_status": execution_status,
                "disposition": disposition,
                "stop_reason": stop_reason,
                "stop_reason_source": stop_reason_source,
                "provenance": {
                    **dict(provenance.get(candidate_id, {})),
                    **{
                        key: candidate[key]
                        for key in (
                            "method", "stage", "source", "source_seed_id",
                            "mutation_type", "target_param", "expected_signal",
                        )
                        if key in candidate
                    },
                },
                "response_refs": [f"#/response_evidence/{index}" for index in candidate_response_indices],
                "request_refs": [
                    responses[index].get("request_ref")
                    for index in candidate_response_indices
                    if responses[index].get("request_ref")
                ],
            }
            dispositions.append(row)

    artifact["candidate_dispositions"] = dispositions


def write_json_report(path: str | Path, payload: dict) -> Path:
    """Publish complete JSON atomically, retaining modes or honoring the umask."""
    out_path = Path(path)
    serialized = json.dumps(payload, indent=2, sort_keys=True)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        while True:
            candidate = out_path.with_name(f".{out_path.name}.{uuid4().hex}.tmp")
            try:
                # Let file creation apply the process umask without changing
                # that process-wide setting while other writers are active.
                descriptor = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o666)
            except FileExistsError:
                continue
            temporary = candidate
            break
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(serialized)
            handle.flush()
            try:
                destination_mode = stat.S_IMODE(out_path.stat().st_mode)
            except FileNotFoundError:
                pass
            else:
                os.chmod(temporary, destination_mode)
            os.fsync(handle.fileno())
        os.replace(temporary, out_path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return out_path


def _metric_lines(aggregate: dict) -> list[str]:
    """Render availability-tracked metric means without zero-filling unknowns."""
    from evaluation.metrics import UNAVAILABLE_METRICS

    totals = aggregate.get("totals", {}) if isinstance(aggregate.get("totals"), dict) else {}
    metrics = aggregate.get("metrics", totals.get("metrics", {}))
    if not isinstance(metrics, dict) or not metrics:
        return []
    # ponytail: mean=None renders N/A; unavailable counts labeled, never averaged as zero.
    lines = ["", "Availability-tracked metrics (unavailable excluded from means):"]
    for name in UNAVAILABLE_METRICS:
        entry = metrics.get(name)
        if not isinstance(entry, dict):
            continue
        mean = entry.get("mean")
        rendered = f"{mean:g}" if isinstance(mean, (int, float)) and not isinstance(mean, bool) and math.isfinite(mean) else "N/A"
        lines.append(
            f"- {name}: {rendered} "
            f"({entry.get('n_available', 0)}/{entry.get('n_available', 0) + entry.get('n_unavailable', 0)} available)"
        )
    return lines


def _runs_for_metrics(aggregate: dict) -> list[dict[str, Any]] | None:
    """Return constituent runs when the aggregate embeds them, else None."""
    for key in ("runs", "artifacts"):
        runs = aggregate.get(key)
        if isinstance(runs, list) and runs and all(isinstance(run, dict) for run in runs):
            return runs
    return None


def build_markdown_summary(aggregate: dict) -> str:
    """Builds markdown summary for framework execution.

    Args:
        aggregate: Value used by this function."""
    totals = aggregate.get("totals", {}) if isinstance(aggregate.get("totals"), dict) else {}
    lines = [
        "# Evaluation Summary",
        "",
        f"- Total runs: {totals.get('total_runs', 0)}",
        f"- Completed executions: {totals.get('completed_runs', totals.get('successful_runs', 0))}",
        f"- Error runs: {totals.get('error_runs', 0)}",
        f"- Skipped runs: {totals.get('skipped_runs', 0)}",
    ]
    for key, count in totals.get("security_outcome_counts", {}).items():
        lines.append(f"- Security outcome {key}: {count}")
    if totals.get("execution_unknown_runs"):
        lines.append(f"- Historical executions with unknown lifecycle: {totals['execution_unknown_runs']}")
    metrics_block = aggregate.get("metrics")
    if not isinstance(metrics_block, dict) or not metrics_block:
        metrics_block = totals.get("metrics", {})
    if isinstance(metrics_block, dict) and metrics_block:
        lines.extend(_metric_lines({"metrics": metrics_block}))
    else:
        runs = _runs_for_metrics(aggregate)
        if runs is not None:
            from evaluation.metrics import UNAVAILABLE_METRICS, aggregate_metric, artifact_summary

            summaries = [artifact_summary(run) for run in runs]
            lines.extend(_metric_lines({
                "metrics": {name: aggregate_metric(summaries, name) for name in UNAVAILABLE_METRICS},
            }))
    return "\n".join(lines)


def write_markdown_report(path: str | Path, aggregate: dict) -> Path:
    """Handles write markdown report behavior for this module.

    Args:
        path: Value used by this function.
        aggregate: Value used by this function."""
    out_path = Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(build_markdown_summary(aggregate), encoding="utf-8")
    return out_path


def write_matrix_reports(output_dir: str | Path, run_id: str, aggregate: dict) -> dict[str, Path]:
    """Handles write matrix reports behavior for this module.

    Args:
        output_dir: Value used by this function.
        run_id: Value used by this function.
        aggregate: Value used by this function."""
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    payload = {
        "schema_version": aggregate.get("schema_version", "stage6.v1"),
        "artifact_type": "matrix_aggregate",
        "generated_at": aggregate.get("generated_at", datetime.now(timezone.utc).isoformat()),
        **aggregate,
    }

    json_path = write_json_report(out_dir / f"matrix_{run_id}.json", payload)
    markdown_path = write_markdown_report(out_dir / f"matrix_{run_id}.md", payload)
    return {"json": json_path, "markdown": markdown_path}


def write_events_jsonl(path: str | Path, events: list[dict]) -> Path:
    """Handles write events jsonl behavior for this module.

    Args:
        path: Value used by this function.
        events: Value used by this function."""
    out_path = Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    lines = [json.dumps(event, sort_keys=True) for event in events]
    content = "\n".join(lines)
    if content:
        content += "\n"
    out_path.write_text(content, encoding="utf-8")
    return out_path
