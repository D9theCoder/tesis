"""Immutable labels used only to decode original historical bytes.

These are read-side facts, not alternate implementations or write contracts.
Membership alone never establishes source/hash, epoch, chronology or resume
compatibility: the owning reader must still enforce all of its integrity gates.
Do not use these values when constructing new runtime artifacts.
"""
from types import MappingProxyType


HISTORICAL_LABELS = MappingProxyType({
    # Content-addressed checkpoint audit manifests used this exact marker. The
    # existing per-entry SHA-256 verification applies before restoring any data.
    "checkpoint_audit": frozenset({"tesis.checkpoint.audit.v1"}),
    # Discovery preserves each descriptor/snapshot's original schema and bytes;
    # these labels classify input only, never authorize a rewrite or resume.
    "runtime_descriptor": frozenset({"runtime-descriptor.v1"}),
    "akg_snapshot": frozenset({"akg-snapshot.v1"}),
    # Metadata readers retain these original identities; resume must still
    # reject them against current source/schema/fingerprint contracts. They are
    # never aliases that authorize running an old checkpoint in a new epoch.
    "state_schema": frozenset({"state.v3"}),
    "checkpoint_schema": frozenset({"checkpoint.v2"}),
    "graph_build": frozenset({"graph.v2"}),
    # Same evidence-based rulebook, historical naming only. Earlier rubrics are
    # not executable alternatives and cannot select today's scoring algorithm.
    "thesis_rubric": frozenset({"scoring.v4"}),
    "runtime_rubric": frozenset({"scoring.v2"}),
    "obsolete_thesis_rubric": frozenset({"scoring.v3"}),
    "artifact_judge": frozenset({"judge.v1"}),
    "scoring_policy": frozenset({"scoring-policy.v4.3"}),
    "research_metrics": frozenset({"research-metrics.v2"}),
    "event_rates": frozenset({"event-rates.v2"}),
    "method_alignment": frozenset({"method-alignment.v1"}),
    "legacy_detection_controls": frozenset({"detection-controls.v1"}),
    "legacy_execution_report": frozenset({"stage6.v1"}),
})

# Original ordered digest input set. Historical receipts must match this exact
# construction AND independent source-epoch anchors; arbitrary subsets or file
# lists are not accepted. Current writes include the new shared contract owner.
HISTORICAL_SCORING_SOURCE_FILES = (
    "evaluation/thesis_scoring.py",
    "evaluation/scoring_evidence.py",
    "evaluation/research_metrics.py",
    "foundation/verifier.py",
)


# Exact known input identities only. Readers keep original values and hashes.
HISTORICAL_CONTRACT_NAMES = MappingProxyType({
    'artifact-manifest': frozenset(['artifact-manifest.v1']),
    'candidate-budget': frozenset(['candidate-budget.v2']),
    'candidate-order': frozenset(['candidate-order.v1']),
    'chain-assessment': frozenset(['chain-assessment.v1']),
    'checkpoint-resume': frozenset(['checkpoint-resume.v1']),
    'control-catalog': frozenset(['2.0.0']),
    'control-event': frozenset(['control-event.v1']),
    'credential-derivation': frozenset(['credential-derivation.v1']),
    'detection-controls': frozenset(['detection-controls.v2']),
    'doctor-probe': frozenset(['doctor-probe.v1']),
    'dvwa-control-catalog': frozenset(['dvwa-control-catalog.v2']),
    'dvwa-neutral-template': frozenset(['dvwa-neutral-template.v1']),
    'dvwa_candidate_permission': frozenset(['dvwa_candidate_permission.v1']),
    'dvwa_candidate_session': frozenset(['dvwa_candidate_session.v1']),
    'dvwa_causal_dependency': frozenset(['dvwa_causal_dependency.v1']),
    'enriched-execution': frozenset(['stage7.rich.v1']),
    'execution': frozenset(['tui.v1']),
    'experiment-flow': frozenset(['chapter3-flow.v2']),
    'fixture-restoration': frozenset(['fixture-restoration.v1']),
    'http-accounting': frozenset(['http-accounting.v1']),
    'live-readiness-probe': frozenset(['live-readiness-probe.v1']),
    'matrix-execution': frozenset(['stage8.v1']),
    'measured-negative-verdicts': frozenset(['measured-negative-verdicts.v1']),
    'method-selection-schema': frozenset(['orchestrator.v1', 'orchestrator.v2']),
    'neutral-template': frozenset(['v1']),
    'observer-projection': frozenset(['observer-projection.v1']),
    'oracle-preregistration-draft': frozenset(['oracle-preregistration-draft.v1']),
    'payload-policy': frozenset(['payload-policy.v2']),
    'payload-policy-snapshot': frozenset(['payload-policy-snapshot.v1']),
    'payload-template': frozenset(['payload-template.v1']),
    'payload-variants': frozenset(['payload-variants.v3']),
    'primary-study-readiness': frozenset(['autoresearch-primary-readiness.v1']),
    'prompt-evaluation': frozenset(['prompt-eval.v1']),
    'prompt-manifests': frozenset(['2.1.0']),
    'prompt-validator': frozenset(['validator.v1']),
    'ranking-draft': frozenset(['ranking-draft.v1']),
    'ranking-draft-freeze': frozenset(['ranking-draft-freeze.v1']),
    'ranking-session-acceptance': frozenset(['ranking-session-acceptance.v1']),
    'readiness': frozenset(['readiness.v1']),
    'source-identity': frozenset(['chapter3-source-identity.v1']),
    'study-analysis': frozenset(['chapter3-analysis.v3']),
    'study-config': frozenset(['chapter3-research-config.v1']),
    'study-design': frozenset(['chapter3-study-design.v1']),
    'study-live-readiness': frozenset(['autoresearch-live-readiness.v1']),
    'study-plan': frozenset(['chapter3-research-plan.v2']),
    'study-planned-manifest': frozenset(['autoresearch-planned-manifest.v1']),
    'study-readiness': frozenset(['autoresearch-readiness.v1']),
    'token-price-schedule': frozenset(['token-price-schedule.v1']),
})


def read_contract(value: object, canonical: str) -> bool:
    """Recognize a recorded schema; never authorize a live write or epoch.

    Callers retain original identifiers and enforce all source, scope,
    evidence, chronology and digest checks. No values are normalized.
    """
    return isinstance(value, str) and (value == canonical or
        value in HISTORICAL_CONTRACT_NAMES.get(canonical, frozenset()))
