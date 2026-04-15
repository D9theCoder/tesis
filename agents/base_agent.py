"""Abstract base class for all vulnerability agents.

All agents inherit from BaseAgent and follow the contract:
- Accept ExploitationState as input
- Return a dict (partial state update)
- Never modify state directly
"""

from abc import ABC, abstractmethod
from typing import Any

from core.state import ExploitationState


class BaseAgent(ABC):
    """Abstract base class for all vulnerability agents.

    Every agent must:
    - Accept ExploitationState as input
    - Return a partial state dict (not modify state directly)
    - Update scores[module_name] with highest score reached
    - Append confirmed knowledge graph nodes to confirmed_vulns
    - Write all tried payloads to tried_payloads
    """

    module_name: str = ""

    @abstractmethod
    def run(self, state: ExploitationState) -> dict[str, Any]:
        """Execute the agent's vulnerability testing pipeline.

        Args:
            state: The current exploitation state (read-only).

        Returns:
            A partial state update dict to be merged by LangGraph.
        """
        ...

    def check_prerequisites(self, state: ExploitationState) -> bool:
        """Check if prerequisite state conditions are met.

        Tier 2 and chain agents override this to check confirmed_vulns.
        Tier 1 agents always return True.
        """
        return True
