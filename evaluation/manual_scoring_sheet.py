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
    for event in artifact.get("execution_log", []):
        if event.get("event_type") == "graph.state":
            decision = event.get("data", {}).get("latest_verifier")
            if isinstance(decision, dict) and decision.get("agent_id"):
                verifiers[decision["agent_id"]] = decision
    latest = artifact.get("verifier_decision")
    if isinstance(latest, dict) and latest.get("agent_id"):
        verifiers[latest["agent_id"]] = latest

    validated: dict[str, list[dict]] = {}
    for method, candidates in final_state.get("payload_candidates", {}).items():
        valid_ids = {
            item.get("candidate_id")
            for item in final_state.get("payload_validation_results", {}).get(method, [])
            if item.get("valid") is True
        }
        validated[method] = [item for item in candidates if item.get("candidate_id") in valid_ids]

    references: dict[str, dict[str, list[str]]] = {}
    for field in ("execution_log", "response_evidence", "timing_evidence"):
        for index, evidence in enumerate(artifact.get(field, [])):
            record = evidence.get("data", {}) if field == "execution_log" else evidence
            method = record.get("agent_id")
            stage = record.get("stage")
            if field == "execution_log" and evidence.get("event_type") in {"agent.probe.sent", "agent.exploit.sent"}:
                stage = "probe" if evidence["event_type"] == "agent.probe.sent" else "exploit"
            matches = [
                item for item in validated.get(method, [])
                if item.get("payload_or_logic") is not None
                and (not stage or item.get("stage", stage) in ({"exploit", "bypass"} if stage == "exploit" else {stage}))
                and record.get("payload") in candidate_evidence_payloads(
                    method, item["payload_or_logic"],
                )
            ]
            if record.get("candidate_id"):
                matches = [item for item in matches if item.get("candidate_id") == record["candidate_id"]]
            elif len(matches) > 1:
                # Legacy normalized aliases need an independently recorded attempt.
                matches = [item for item in matches if final_state.get("payload_scores", {}).get(item["candidate_id"]) is not None]
            if len(matches) == 1:
                candidate_id = matches[0]["candidate_id"]
                references.setdefault(candidate_id, {}).setdefault(f"{field}_ref", []).append(f"#/{field}/{index}")

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
        if not decisions and links["response_evidence_ref"]:
            verifier = verifiers.get(method)
        later = [d for d in history if earning and d.get("agent_id") == method
                 and d.get("visit_id") != earning.get("visit_id")
                 and history.index(d) > next((i for i, v in enumerate(history) if v is verifier), len(history))]
        rows.append({
            "run_id": artifact.get("run_id"),
            "provider": config.get("provider"),
            "surface": config.get("surface"),
            "security_level": config.get("security_level"),
            "payload_mode": config.get("payload_mode"),
            "method_node": details.get("method"),
            "candidate_id": candidate_id,
            "payload_source": details.get("source"),
            "source_seed_id": details.get("source_seed_id"),
            "mutation_type": details.get("mutation_type"),
            "target_param": details.get("target_param"),
            "expected_signal": details.get("expected_signal"),
            "payload_score_0_4": score,
            "method_score_0_4": final_state.get("method_scores", {}).get(details.get("method")),
            "exploitation_score_0_4": final_state.get("exploitation_scores", {}).get(details.get("method")),
            "chain_score_0_4": final_state.get("chain_scores", {}).get(details.get("method")),
            "validator_result": validation,
            **links,
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
