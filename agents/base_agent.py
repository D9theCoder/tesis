"""Abstract base class for all method agents."""

from abc import ABC, abstractmethod
import logging
from typing import Any

from core.state import ExploitationState

logger = logging.getLogger(__name__)


def _coerce_bool(value: Any) -> bool:
    """Supports coerce bool behavior for this module."""
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off", ""}:
            return False
    if isinstance(value, (int, float)):
        return value != 0
    return bool(value)


class BaseAgent(ABC):
    """Abstract base class for all method agents.

    Every agent must:
    - Accept ExploitationState as input
    - Return a partial state dict (not modify state directly)
    - Update scores[agent_id] with highest score reached
    - Append confirmed knowledge graph nodes to confirmed_vulns
    - Write all tried payloads to tried_payloads[agent_id]
    """

    agent_id: str = ""
    surface: str = ""

    @abstractmethod
    def run(self, state: ExploitationState) -> dict[str, Any]:
        """Execute the agent's vulnerability testing pipeline."""
        ...

    def check_preconditions(self, state: ExploitationState) -> bool:
        """Check if prerequisite state conditions are met."""
        from core.knowledge_graph import AttackKnowledgeGraph
        kg = AttackKnowledgeGraph()
        return kg.check_preconditions(self.agent_id, state.get("observations", {}))

    def probe(self, state: ExploitationState) -> dict[str, Any]:
        """Default probe: return empty observations. Subclasses override."""
        return {"observations": {}}

    def _emit_telemetry(
        self,
        state: ExploitationState,
        event: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "telemetry_events": [{
                "node": self.agent_id,
                "iteration": state.get("iteration_count", 0),
                "event": event,
                "status": payload.get("status", "ok"),
                "payload": payload,
            }]
        }

    def enhance_prompt(self, state: ExploitationState, prompt: str) -> str:
        """No-op: evasion is handled reactively in orchestrator, not here."""
        return prompt
