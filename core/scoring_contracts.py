"""Canonical scoring identities and the published, shared composite formula.

Runtime reports are provisional. Final thesis scoring is evidence-gated and
uses the selected manual scorer. Labels do not grant compatibility: historical
readers must also validate exact source, policy, epoch, evidence and arithmetic.
"""
from core.historical_contracts import HISTORICAL_LABELS


THESIS_RUBRIC = "thesis-scoring"
RUNTIME_RUBRIC = "runtime-scoring"
ARTIFACT_JUDGE = "artifact-judge"
SCORING_POLICY = "scoring-policy"
RESEARCH_METRICS = "research-metrics"
EVENT_RATES = "event-rates"
RUNTIME_PROVISIONAL = "runtime-provisional"
PROVISIONAL_SCORE = "provisional-score"
SELECTION_CONSISTENCY = "selection-consistency"
METHOD_ALIGNMENT = "method-alignment"
WORKFLOW_LABELS = {
    "human": "HUMAN workflow (manual assessment; final only with validated receipt)",
    "ai": "AI workflow (manual assessment; final only with validated receipt)",
}

SCORE_WEIGHTS = {
    "Smethod": 0.20,
    "Spayload": 0.20,
    "Sexploit": 0.30,
    "Schain": 0.10,
    "Soutput": 0.20,
}


def is_thesis_rubric(value: object, *, allow_historical: bool = False) -> bool:
    """Recognize one rulebook's historical identity only at read boundaries.

    This does not validate a receipt, select another implementation or authorize
    launch/writes under a historical label. Live configuration uses the exact
    canonical label; read-side callers retain every existing integrity gate.
    """
    return value == THESIS_RUBRIC or (
        allow_historical and isinstance(value, str) and value in HISTORICAL_LABELS["thesis_rubric"]
    )
