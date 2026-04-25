"""Abstract base class for all vulnerability agents.

All agents inherit from BaseAgent and follow the contract:
- Accept ExploitationState as input
- Return a dict (partial state update)
- Never modify state directly
"""

from abc import ABC, abstractmethod
import logging
from typing import Any

from core.state import ExploitationState

logger = logging.getLogger(__name__)


def _coerce_bool(value: Any) -> bool:
    """Parse bool-like values safely, including string forms."""
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

    def enhance_prompt(self, state: ExploitationState, prompt: str) -> str:
        """Enhance a prompt via the Stage 8 evasion layer if enabled.

        Subclasses that invoke LLMs for payload generation can call this
        helper to transparently apply adversarial prompt rewriting.

        Args:
            state: The current exploitation state.
            prompt: The baseline prompt to enhance.

        Returns:
            The enhanced prompt if evasion is enabled, otherwise the original.
        """
        if not _coerce_bool(state.get("evasion_enabled", False)):
            return prompt

        strategy = str(state.get("evasion_strategy", "pipeline")).strip().lower()
        simulator_model = state.get("simulator_model")
        simulator_provider = state.get("simulator_provider")
        max_concurrency = state.get("max_concurrency")
        if strategy in {"prompt_injection", "roleplay"}:
            from llm.evasion.deepteam_adapters import enhance_with_deepteam

            return enhance_with_deepteam(
                prompt,
                strategy=strategy,
                simulator_model=simulator_model,
                simulator_provider=simulator_provider,
                max_concurrency=max_concurrency,
            )

        from llm.evasion.pipeline import build_evasion_graph

        try:
            evasion_graph = build_evasion_graph()
            result = evasion_graph.invoke(
                {
                    "base_seed": prompt,
                    "retries": 0,
                    "max_retries": 3,
                    "evasion_strategy": strategy,
                    "simulator_model": simulator_model,
                    "simulator_provider": simulator_provider,
                    "max_concurrency": max_concurrency,
                }
            )
            return result.get("final_prompt", prompt)
        except Exception as exc:
            logger.warning(
                "BaseAgent evasion graph failed; returning original prompt",
                exc_info=exc,
            )
            return prompt
