"""Manual scoring sheet export helpers for payload evidence review."""

from __future__ import annotations

from typing import Any

from agents.state_utils import candidate_evidence_payloads


def manual_scoring_rows(artifact: dict[str, Any]) -> list[dict[str, Any]]:
    """Link each candidate to recorded evidence without inventing manual scores."""
    config = artifact.get("config", {}) if isinstance(artifact.get("config"), dict) else {}
    final_state = artifact.get("final_state", {}) if isinstance(artifact.get("final_state"), dict) else {}
    provenance = final_state.get("payload_provenance", {})
    if not isinstance(provenance, dict):
        return []

    verifiers: dict[str, dict[str, Any]] = {}
    verifiers_by_visit: dict[tuple[str, str], dict[str, Any]] = {}

    def remember_verifier(decision: Any) -> None:
        if not isinstance(decision, dict) or not decision.get("agent_id"):
            return
        method = str(decision["agent_id"])
        verifiers[method] = decision
        visit_id = decision.get("visit_id")
        if visit_id:
            verifiers_by_visit[(method, str(visit_id))] = decision

    for event in artifact.get("execution_log", []):
        if event.get("event_type") == "graph.state":
            decision = event.get("data", {}).get("latest_verifier")
            remember_verifier(decision)
    for decision in final_state.get("verifier_history", []):
        remember_verifier(decision)
    latest = artifact.get("verifier_decision")
    remember_verifier(latest)

    validated: dict[str, list[dict]] = {}
    for method, candidates in final_state.get("payload_candidates", {}).items():
        valid_ids = {
            item.get("candidate_id")
            for item in final_state.get("payload_validation_results", {}).get(method, [])
            if item.get("valid") is True
        }
        validated[method] = [item for item in candidates if item.get("candidate_id") in valid_ids]

    references: dict[str, dict[str, list[str]]] = {}
    legacy_links: dict[str, dict[str, list[str]]] = {}
    valid_ids_by_method = {method: {item.get("candidate_id") for item in rows}
                           for method, rows in validated.items()}
    for field in ("execution_log", "response_evidence", "timing_evidence"):
        records = artifact.get(field, [])
        ref_prefix = f"#/{field}"
        if (field != "execution_log" and artifact.get("kind") != "diagnostic_replay"
                and isinstance(final_state.get(field), list)):
            records = final_state[field]
            ref_prefix = f"#/final_state/{field}"
        for index, evidence in enumerate(records):
            record = evidence.get("data", {}) if field == "execution_log" else evidence
            method = record.get("agent_id") or record.get("method")
            stage = record.get("stage")
            if field == "execution_log" and evidence.get("event_type") in {"agent.probe.sent", "agent.exploit.sent"}:
                stage = "probe" if evidence["event_type"] == "agent.probe.sent" else "exploit"
            recorded_id = record.get("candidate_id")
            if recorded_id is not None and recorded_id in valid_ids_by_method.get(method, set()):
                # Trusted identity link; payload text is never the join key here.
                references.setdefault(recorded_id, {}).setdefault(f"{field}_ref", []).append(f"{ref_prefix}/{index}")
                continue
            matches = [
                item for item in validated.get(method, [])
                if item.get("payload_or_logic") is not None
                and (not stage or item.get("stage", stage) in ({"exploit", "bypass"} if stage == "exploit" else {stage}))
                and record.get("payload") in candidate_evidence_payloads(
                    method, item["payload_or_logic"],
                )
            ]
            if len(matches) > 1:
                # A recorded candidate score is execution evidence that can
                # disambiguate normalized aliases; without it the alias stays
                # ambiguous and no candidate may borrow the row.
                recorded_scores = final_state.get("payload_scores", {})
                scored = [item for item in matches
                          if isinstance(recorded_scores, dict)
                          and recorded_scores.get(item.get("candidate_id")) is not None]
                if len(scored) == 1:
                    matches = scored
            if len(matches) == 1:
                candidate_id = matches[0]["candidate_id"]
                # Legacy rows without candidate identity keep their payload alias
                # for audit only; they never establish execution or proof.
                references.setdefault(candidate_id, {}).setdefault(f"{field}_ref", []).append(f"{ref_prefix}/{index}")
                legacy_links.setdefault(candidate_id, {}).setdefault(f"{field}_ref", []).append(f"{ref_prefix}/{index}")

    rows: list[dict[str, Any]] = []
    for candidate_id, details in sorted(provenance.items()):
        details = details if isinstance(details, dict) else {}
        method = details.get("method")
        validation = next((
            item for item in final_state.get("payload_validation_results", {}).get(method, [])
            if item.get("candidate_id") == candidate_id
        ), None)
        links = {f"{field}_ref": references.get(candidate_id, {}).get(f"{field}_ref", [])
                 for field in ("execution_log", "response_evidence", "timing_evidence")}
        # Replay response evidence describes the fresh attempt; state also holds history.
        if artifact.get("kind") == "diagnostic_replay" and not links["response_evidence_ref"]:
            continue
        score = final_state.get("payload_scores", {}).get(candidate_id)
        decisions = artifact.get("scoring_decisions", final_state.get("scoring_decisions", []))
        candidate_decisions = [d for d in decisions if d.get("dimension") == "Spayload"
            and d.get("candidate_id") == candidate_id and d.get("method") == method]
        earning = next((d for d in candidate_decisions if d.get("score") == score), None)
        if artifact.get("kind") == "diagnostic_replay" and candidate_decisions:
            earning = max(candidate_decisions, key=lambda d: d['score'])
            score = earning['score']
        history = final_state.get("verifier_history", [])
        verifier = next((d for d in history if earning and d.get("verifier_id") == earning.get("verifier_id")), None)
        if earning and not verifier:
            legacy_ref = next((ref for ref in earning.get("evidence_refs", [])
                if ref.startswith("source:#/execution_log/") and ref.endswith("/data/latest_verifier")), None)
            if legacy_ref:
                verifier = artifact.get("execution_log", [])[int(legacy_ref.split('/')[2])].get("data", {}).get("latest_verifier")
        if not verifier and links["response_evidence_ref"]:
            linked_verifiers = []
            for ref in links["response_evidence_ref"]:
                try:
                    evidence_index = int(ref.rsplit("/", 1)[1])
                    evidence = artifact.get("response_evidence", [])[evidence_index]
                except (IndexError, TypeError, ValueError):
                    continue
                evidence_method = evidence.get("method") or evidence.get("agent_id") or method
                visit_id = evidence.get("visit_id")
                if visit_id:
                    decision = verifiers_by_visit.get((str(evidence_method), str(visit_id)))
                    if decision and all(item.get("verifier_id") != decision.get("verifier_id")
                                        for item in linked_verifiers):
                        linked_verifiers.append(decision)
            if linked_verifiers:
                verifier = linked_verifiers[-1]
            elif not decisions:
                verifier = verifiers.get(method)
        later = [d for d in history if earning and d.get("agent_id") == method
                 and d.get("visit_id") != earning.get("visit_id")
                 and history.index(d) > next((i for i, v in enumerate(history) if v is verifier), len(history))]
        from evaluation.scoring_evidence import candidate_execution_evidence, candidate_lifecycle_status
        execution_rows = candidate_execution_evidence(artifact, candidate_id, method)
        evidence_container = "final_state/" if isinstance(final_state.get("response_evidence"), list) else ""
        origin_ref = details.get("origin_ref") if isinstance(details.get("origin_ref"), dict) else {}
        rows.append({
            "run_id": artifact.get("run_id"),
            "provider": config.get("provider"),
            "surface": config.get("surface"),
            "security_level": config.get("security_level"),
            "payload_mode": config.get("payload_mode"),
            "method_node": details.get("method"),
            "candidate_id": candidate_id,
            "payload_source": details.get("source"),
            "origin_kind": details.get("origin_kind"),
            "origin_ref": origin_ref,
            "source_seed_id": details.get("source_seed_id"),
            "source_template_id": origin_ref.get("template_id"),
            "template_version": origin_ref.get("template_version"),
            "template_sha256": origin_ref.get("template_sha256"),
            "copy_of_supplied_seed": details.get("copy_of_supplied_seed"),
            "equals_canonical_seed_id": details.get("equals_canonical_seed_id"),
            "visit_id": details.get("visit_id"),
            "model_call_id": details.get("model_call_id"),
            "prompt_id": details.get("prompt_id"),
            "schema_version": details.get("schema_version"),
            "policy_version": details.get("policy_version"),
            "feasibility": details.get("feasibility"),
            "mutation_type": details.get("mutation_type"),
            "target_param": details.get("target_param"),
            "expected_signal": details.get("expected_signal"),
            "payload_score_0_4": score,
            "method_score_0_4": final_state.get("method_scores", {}).get(details.get("method")),
            "exploitation_score_0_4": final_state.get("exploitation_scores", {}).get(details.get("method")),
            "chain_score_0_4": final_state.get("chain_scores", {}).get(details.get("method")),
            "validator_result": validation,
            **links,
            "legacy_payload_alias_refs": {field: refs for field, refs in
                legacy_links.get(candidate_id, {}).items()},
            "executed": bool(execution_rows) and candidate_lifecycle_status(artifact, candidate_id, method)
                not in {"stopped_before_execution", "budget_excluded", "rejected", "conflicting"},
            "execution_refs": [f"#/{evidence_container}response_evidence/{index}"
                               for index, _row in execution_rows],
            "candidate_lifecycle_status": candidate_lifecycle_status(artifact, candidate_id, method),
            "verifier_decision": verifier,
            "scoring_decision": earning,
            "score_evidence_status": "linked_decision" if earning else ("legacy_unresolved" if score is not None else "unscored"),
            "scoring_decision_ref": f"#/scoring_decisions/{decisions.index(earning)}" if earning and artifact.get("scoring_decisions") is not None
                else (f"#/final_state/scoring_decisions/{decisions.index(earning)}" if earning else None),
            "later_verifier_decisions": later,
            "score_0_4": score,
            "scoring_reason": earning.get("reason", "") if earning else "",
        })
    return rows
