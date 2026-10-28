"""Read-only source-bound Human/AI workflow discovery for observer exports."""
from __future__ import annotations

from datetime import datetime, timezone
import math

from evaluation.remaining_evidence import _check_grades
from evaluation.thesis_scoring import WEIGHTS, _validated_reviews, review_queue
from tesis.artifact_repository import config_fingerprint
from tesis.runtime_events import redact_secrets


def _timestamp(document):
    value = document.get("generated_at")
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return (parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)).timestamp()
    except ValueError:
        return None


def _empty(reason="missing_review"):
    return {"status": "missing", "reason": reason, "component_pending_reasons": {},
            "components": None, "Spayload_final": None, "Srun_final": None,
            "numerator": None, "denominator": None, "candidate_grades": [],
            "receipt": None, "review_status": None, "decision_ledger": None,
            "generated_at": None, "rubric_version": None, "scoring_rule_sha256": None}


def _binding_check(entry, document, queue, *, legacy=False):
    if document.get("source_sha256") != entry.source["sha256"]:
        raise ValueError("source_hash_mismatch")
    for key in ("execution_id", "run_id", "selection"):
        if key not in document and legacy:
            continue
        if document.get(key) != queue.get(key):
            raise ValueError(f"{key}_mismatch")
    if document.get("method") != queue["method"] or document.get("rubric_version") != queue["rubric_version"]:
        raise ValueError("method_or_rubric_mismatch")
    if config_fingerprint(document.get("config", {})) != config_fingerprint(queue["config"]):
        raise ValueError("config_mismatch")
    digest = document.get("scoring_rule_sha256")
    if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise ValueError("missing_scoring_epoch")
    policy = document.get("scoring_policy") or {}
    queue_policy = queue.get("scoring_policy") or {}
    if policy.get("policy_version") and queue_policy.get("policy_version") \
            and policy["policy_version"] != queue_policy["policy_version"]:
        raise ValueError("scoring_policy_epoch_mismatch")
    if document.get("metrics_epoch") and (queue.get("metrics") or {}).get("metrics_epoch") \
            and document["metrics_epoch"] != queue["metrics"]["metrics_epoch"]:
        raise ValueError("metrics_epoch_mismatch")


def _validated_receipt(catalog, entry, path, receipt, queue):
    _binding_check(entry, receipt, queue)
    if catalog.resolve(receipt["source_path"], owner=path) != entry.path:
        raise ValueError("source_path_mismatch")
    mode = receipt.get("scoring_mode")
    if mode not in {"human", "ai"} or queue["selection"] not in {mode, "both"} or receipt.get("status") != "final":
        raise ValueError("workflow_mismatch")
    if _timestamp(receipt) is None:
        raise ValueError("missing_receipt_timestamp")
    grades = receipt.get("candidate_grades")
    if not isinstance(grades, list) or not grades:
        raise ValueError("missing_candidate_grades")
    _check_grades(queue, entry.record, grades)
    history = _validated_reviews(queue, receipt.get("review_history"))
    for grade in grades:
        if grade.get("grade_origin") == "signal_gate":
            row = next(r for r in queue["candidates"] if r["candidate_id"] == grade["candidate_id"])
            if row["status"] != "signal_absent" or grade["score"] != 0:
                raise ValueError("invalid_signal_gate")
        else:
            decision = history.get((mode, grade["candidate_id"]))
            if not decision or decision["score"] != grade["score"] or decision["decision_id"] != grade["decision_id"]:
                raise ValueError("decision_binding_mismatch")
    vector = receipt.get("components")
    if not isinstance(vector, dict) or set(vector) != set(WEIGHTS) or any(
        isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) or not 0 <= v <= 4
        for v in vector.values()
    ):
        raise ValueError("invalid_components")
    if any(vector[key] != value for key, value in queue["components"].items()):
        raise ValueError("component_evidence_mismatch")
    if receipt.get("component_evidence_refs") != queue["component_evidence_refs"]:
        raise ValueError("component_reference_mismatch")
    numerator, denominator = sum(g["score"] for g in grades), len(grades)
    if any(isinstance(receipt.get(key), bool) or not isinstance(receipt.get(key), (int, float))
           or not math.isfinite(receipt[key]) for key in ("numerator", "Spayload_final", "Srun_final")):
        raise ValueError("invalid_final_numbers")
    if (type(receipt.get("denominator")) is not int or receipt["denominator"] != denominator
            or receipt.get("numerator") != numerator or receipt.get("formula") != WEIGHTS
            or vector["Spayload"] != numerator / denominator
            or receipt.get("Spayload_final") != round(numerator / denominator, 4)
            or receipt.get("Srun_final") != round(sum(vector[k] * w for k, w in WEIGHTS.items()), 4)):
        raise ValueError("receipt_arithmetic_mismatch")
    return {**_empty(None), "status": "final", "components": vector,
            **{key: receipt.get(key) for key in (
                "Spayload_final", "Srun_final", "candidate_grades", "numerator", "denominator",
                "generated_at", "rubric_version", "scoring_rule_sha256", "component_evidence_refs",
                "selection", "scoring_mode", "aggregation", "rounding",
                "selection_evidence", "output_reason", "scoring_policy", "metrics_epoch",
                "component_pending_reasons",
            )}, "receipt": catalog.binding(path)}


def _validated_status(catalog, entry, path, status, queue, source_hash_count):
    legacy = not status.get("execution_id") or not status.get("generated_at")
    _binding_check(entry, status, queue, legacy=legacy)
    if not legacy and (not status.get("source_path") or _timestamp(status) is None):
        raise ValueError("invalid_status_identity")
    if status.get("source_path") and catalog.resolve(status["source_path"], owner=path) != entry.path:
        raise ValueError("source_path_mismatch")
    if legacy and source_hash_count != 1:
        raise ValueError("ambiguous_legacy_source")
    ledger_path = catalog.resolve(status["decision_ledger_path"], owner=path)
    ledger = catalog.read(ledger_path)
    latest = _validated_reviews(queue, ledger)
    selected = {"human", "ai"} if queue["selection"] == "both" else {queue["selection"]}
    workflows = status.get("workflows")
    if not isinstance(workflows, dict) or set(workflows) != selected:
        raise ValueError("status_workflow_mismatch")
    for mode, workflow in workflows.items():
        grades = workflow.get("candidate_grades")
        _check_grades(queue, entry.record, grades)
        for grade in grades:
            decision = latest.get((mode, grade["candidate_id"]))
            if grade.get("grade_origin") == "signal_gate":
                row = next(r for r in queue["candidates"] if r["candidate_id"] == grade["candidate_id"])
                if row["status"] != "signal_absent" or grade["score"] != 0 or decision is not None:
                    raise ValueError("invalid_signal_gate")
            elif grade["score"] is None:
                if decision is not None:
                    raise ValueError("stale_pending_grade")
            elif not decision or decision["score"] != grade["score"] or decision["decision_id"] != grade["decision_id"]:
                raise ValueError("ledger_binding_mismatch")
        if workflow.get("status") == "pending":
            if workflow.get("Spayload_final") is not None or workflow.get("Srun_final") is not None:
                raise ValueError("pending_final_not_null")
            if not isinstance(workflow.get("reason"), str) or not workflow["reason"]:
                raise ValueError("missing_pending_reason")
        elif workflow.get("status") != "final":
            raise ValueError("invalid_workflow_status")
        if "components" in workflow:
            vector = workflow["components"]
            if (not isinstance(vector, dict) or set(vector) != set(WEIGHTS)
                    or any(vector[key] != value for key, value in queue["components"].items())
                    or (workflow["status"] == "pending" and vector["Spayload"] is not None)):
                raise ValueError("status_component_mismatch")
        if "denominator" in workflow and (type(workflow["denominator"]) is not int or workflow["denominator"] != len(grades)):
            raise ValueError("status_denominator_mismatch")
    return catalog.binding(ledger_path)


def discover_reviews(catalog, entry):
    result = {"human": _empty(), "ai": _empty()}
    if entry.ambiguous:
        return {mode: _empty("ambiguous_source") for mode in result}
    candidates = [(order, path, doc) for order, path, doc in catalog.reviews
                  if doc.get("source_sha256") == entry.source["sha256"]
                  or (entry.record.get("execution_id") and doc.get("execution_id") == entry.record["execution_id"])]
    if not candidates:
        return result
    if entry.source["pointer"]:
        return {mode: _empty("embedded_review_unavailable") for mode in result}
    try:
        queue = review_queue(entry.path)
        if queue["source_sha256"] != entry.source["sha256"]:
            raise ValueError("source_changed")
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        entry.diagnostics.append(catalog.diagnostic("review_source_incompatible", entry.path, reason=type(exc).__name__))
        return {mode: _empty("source_incompatible") for mode in result}
    finals, statuses = {}, {}
    hash_count = sum(e.source["sha256"] == entry.source["sha256"] for e in catalog.runs)
    for order, path, doc in candidates:
        try:
            if doc.get("artifact_type") == "thesis_score_receipt":
                workflow = _validated_receipt(catalog, entry, path, doc, queue)
                mode = doc["scoring_mode"]
                key = (_timestamp(doc), order, str(path))
                if mode not in finals or key > finals[mode][0]:
                    finals[mode] = (key, workflow)
            else:
                ledger = _validated_status(catalog, entry, path, doc, queue, hash_count)
                key = (order, _timestamp(doc) or 0, str(path))
                for mode, workflow in doc["workflows"].items():
                    if mode not in statuses or key > statuses[mode][0]:
                        statuses[mode] = (key, workflow, path, doc, ledger)
        except (OSError, ValueError, KeyError, TypeError, AttributeError, IndexError) as exc:
            reason = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
            entry.diagnostics.append(catalog.diagnostic("invalid_review_binding", path, reason=reason))
    for mode in result:
        if queue["selection"] not in {mode, "both"}:
            result[mode] = _empty("workflow_not_selected")
            result[mode]["status"] = "not_selected"
        elif mode in finals:
            result[mode] = finals[mode][1]
            if mode in statuses:
                _, workflow, path, status, ledger = statuses[mode]
                # A stale pending file never supplants a valid final receipt.
                if workflow["candidate_grades"] == result[mode]["candidate_grades"]:
                    result[mode].update(review_status=catalog.binding(path), decision_ledger=ledger)
        elif mode in statuses:
            _, workflow, path, status, ledger = statuses[mode]
            fields = {key: workflow[key] for key in (
                "status", "reason", "component_pending_reasons", "components", "candidate_grades", "Spayload_final", "Srun_final",
            ) if key in workflow}
            result[mode] = {**_empty(), **fields, "review_status": catalog.binding(path),
                "decision_ledger": ledger, "generated_at": status.get("generated_at"),
                "rubric_version": status["rubric_version"], "scoring_rule_sha256": status["scoring_rule_sha256"]}
            result[mode]["denominator"] = len(workflow["candidate_grades"])
            result[mode]["numerator"] = (sum(grade["score"] for grade in workflow["candidate_grades"])
                if workflow["candidate_grades"] and all(grade["score"] is not None for grade in workflow["candidate_grades"])
                else None)
            if workflow["status"] == "final":
                result[mode].update(status="stale", reason="missing_valid_receipt", Spayload_final=None, Srun_final=None)
        else:
            result[mode] = _empty("missing_or_invalid_review")
    return redact_secrets(result)
