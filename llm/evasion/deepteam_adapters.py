"""DeepTeam adapters for adversarial prompt evasion (Stage 8).

Wraps DeepTeam single-turn attacks so the framework can enhance prompts
before sending them to the target LLM.
"""

from __future__ import annotations

import importlib
import logging
from typing import Any, Callable

logger = logging.getLogger(__name__)

_STRATEGY_CLASS_NAMES: dict[str, str] = {
    "prompt_injection": "PromptInjection",
    "roleplay": "Roleplay",
    "base64": "Base64",
    "leetspeak": "Leetspeak",
    "rot13": "ROT13",
    "goal_redirection": "GoalRedirection",
    "adversarial_poetry": "AdversarialPoetry",
    "gray_box": "GrayBox",
    "math_problem": "MathProblem",
    "multilingual": "Multilingual",
    "context_poisoning": "ContextPoisoning",
    "input_bypass": "InputBypass",
    "permission_escalation": "PermissionEscalation",
    "linguistic_confusion": "LinguisticConfusion",
    "system_override": "SystemOverride",
}

DETERMINISTIC_STRATEGIES: set[str] = {
    "base64",
    "rot13",
    "leetspeak",
}


def normalize_strategy(strategy: str) -> str:
    """Normalize strategy names for tolerant lookup.

    Examples:
    - " Prompt_Injection " -> "prompt_injection"
    - "prompt-injection" -> "prompt_injection"
    - "prompt injection" -> "prompt_injection"
    """
    normalized = str(strategy or "").strip().lower().replace("-", "_").replace(" ", "_")
    while "__" in normalized:
        normalized = normalized.replace("__", "_")
    return normalized


def _load_strategy_map() -> dict[str, Callable[[], Any]]:
    """Load DeepTeam single-turn attacks without all-or-nothing imports."""
    try:
        module = importlib.import_module("deepteam.attacks.single_turn")
    except Exception as exc:  # pragma: no cover - optional dependency
        logger.warning("DeepTeam module unavailable; evasion adapters disabled", exc_info=exc)
        return {}

    strategy_map: dict[str, Callable[[], Any]] = {}
    for strategy, class_name in _STRATEGY_CLASS_NAMES.items():
        attack_cls = getattr(module, class_name, None)
        if attack_cls is None:
            logger.debug("DeepTeam attack class missing for strategy '%s' (%s)", strategy, class_name)
            continue
        strategy_map[strategy] = attack_cls

    return strategy_map


_STRATEGY_MAP: dict[str, Callable[[], Any]] = _load_strategy_map()
_DEEPTEAM_AVAILABLE = bool(_STRATEGY_MAP)


def _get_attack_instance(strategy: str) -> Any | None:
    """Instantiate the DeepTeam attack class for *strategy*.

    Returns ``None`` when the strategy is unknown or DeepTeam is not installed.
    """
    normalized_strategy = normalize_strategy(strategy)
    if not _DEEPTEAM_AVAILABLE:
        return None

    attack_cls = _STRATEGY_MAP.get(normalized_strategy)
    if attack_cls is None:
        logger.debug("Unsupported or unavailable DeepTeam strategy '%s'", normalized_strategy)
        return None

    try:
        # All single-turn attacks accept no required positional args.
        # PromptInjection only takes ``weight``; Roleplay takes
        # ``role``, ``persona``, ``weight``, ``max_retries``.  Calling
        # with no arguments uses sensible library defaults.
        return attack_cls()
    except Exception as exc:
        logger.warning("Failed to instantiate DeepTeam strategy '%s'", normalized_strategy, exc_info=exc)
        return None


def enhance_with_deepteam(base_prompt: str, strategy: str = "prompt_injection") -> str:
    """Enhance a baseline prompt using a DeepTeam attack strategy.

    Args:
        base_prompt: The original prompt to enhance.
        strategy: Attack strategy name.  See ``_STRATEGY_MAP`` for the full
            list of supported strategies (e.g. ``"prompt_injection"``,
            ``"roleplay"``, ``"base64"``, ``"leetspeak"``, ``"rot13"``,
            ``"goal_redirection"``, etc.).

    Returns:
        The enhanced prompt string, or the original prompt when the strategy
        is unsupported, DeepTeam is not installed, or the attack fails.
    """
    normalized_strategy = normalize_strategy(strategy)
    attack = _get_attack_instance(normalized_strategy)
    if attack is None:
        return base_prompt

    try:
        # DeepTeam's ``.enhance()`` takes exactly one positional argument:
        # the base attack string.  It returns the enhanced string.
        return attack.enhance(base_prompt)
    except Exception as exc:  # pragma: no cover - defensive fallback
        logger.warning("DeepTeam enhance failed for strategy '%s'", normalized_strategy, exc_info=exc)
        return base_prompt
