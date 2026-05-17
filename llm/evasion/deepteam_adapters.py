"""DeepTeam adapters for controlled retry prompt transformations (Stage 8).

Wraps DeepTeam single-turn attacks so the framework can enhance prompts
before sending them to the target LLM.
"""

from __future__ import annotations

import importlib
import logging
import os
import threading
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

_concurrency_lock: threading.Semaphore | None = None
_concurrency_limit: int | None = None


def _get_concurrency_sem(limit: int | None) -> threading.Semaphore | None:
    """Create or reuse a ``threading.Semaphore`` when *limit* > 0."""
    global _concurrency_lock, _concurrency_limit
    if limit is None or limit <= 0:
        return None
    if _concurrency_lock is None or _concurrency_limit != limit:
        _concurrency_lock = threading.Semaphore(limit)
        _concurrency_limit = limit
        logger.info("DeepTeam concurrency semaphore initialized with limit=%d", limit)
    return _concurrency_lock


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


def _build_deepeval_model(provider: str, model_name: str | None = None) -> Any | None:
    """Instantiate a native DeepEval LLM for the given provider.

    DeepTeam's ``initialize_model`` falls back to OpenAI when it receives
    an unrecognized model string.  By constructing the correct native
    class here (``GeminiModel``, ``GPTModel``, etc.) we bypass that
    fallback and ensure the configured provider is actually used.

    Returns ``None`` if the provider is unknown or the dependency is missing.
    """
    try:
        from deepeval.models import (
            DeepEvalBaseLLM,
            GeminiModel,
            GPTModel,
            AnthropicModel,
            AzureOpenAIModel,
            OllamaModel,
            LocalModel,
            AmazonBedrockModel,
            LiteLLMModel,
            KimiModel,
            GrokModel,
            DeepSeekModel,
        )
    except Exception as exc:
        logger.warning("deepeval models unavailable; cannot build native model", exc_info=exc)
        return None

    normalized = provider.strip().lower()
    kwargs: dict[str, Any] = {}
    if model_name:
        kwargs["model"] = model_name

    try:
        if normalized == "gemini":
            kwargs.setdefault("api_key", os.getenv("GOOGLE_API_KEY") or os.getenv("GEMINI_API_KEY"))
            return GeminiModel(**kwargs)
        if normalized == "openai":
            kwargs.setdefault("api_key", os.getenv("OPENAI_API_KEY"))
            return GPTModel(**kwargs)
        if normalized == "anthropic":
            kwargs.setdefault("api_key", os.getenv("ANTHROPIC_API_KEY"))
            return AnthropicModel(**kwargs)
        if normalized == "azure_openai":
            return AzureOpenAIModel(**kwargs)
        if normalized == "ollama":
            return OllamaModel(**kwargs)
        if normalized == "local":
            return LocalModel(**kwargs)
        if normalized in {"bedrock", "aws_bedrock"}:
            return AmazonBedrockModel(**kwargs)
        if normalized == "litellm":
            return LiteLLMModel(**kwargs)
        if normalized in {"kimi", "moonshot"}:
            return KimiModel(**kwargs)
        if normalized == "grok":
            return GrokModel(**kwargs)
        if normalized == "deepseek":
            return DeepSeekModel(**kwargs)
    except Exception as exc:
        logger.warning("Failed to instantiate deepeval model for provider '%s'", provider, exc_info=exc)
        return None

    logger.debug("No native deepeval model mapping for provider '%s'", provider)
    return None


def enhance_with_deepteam(
    base_prompt: str,
    strategy: str = "prompt_injection",
    simulator_model: str | None = None,
    simulator_provider: str | None = None,
    max_concurrency: int | None = None,
) -> str:
    """Enhance a baseline prompt using a DeepTeam attack strategy.

    Args:
        base_prompt: The original prompt to enhance.
        strategy: Attack strategy name.  See ``_STRATEGY_MAP`` for the full
            list of supported strategies (e.g. ``"prompt_injection"``,
            ``"roleplay"``, ``"base64"``, ``"leetspeak"``, ``"rot13"``,
            ``"goal_redirection"``, etc.).
        simulator_model: Optional model name (e.g. ``"gpt-4o-mini"``) or
            DeepEvalBaseLLM instance to use for LLM-driven attacks.
        max_concurrency: Optional maximum number of concurrent calls to
            ``attack.enhance`` across threads.  Only applies to LLM-driven
            strategies.

    Returns:
        The enhanced prompt string, or the original prompt when the strategy
        is unsupported, DeepTeam is not installed, or the attack fails.
    """
    normalized_strategy = normalize_strategy(strategy)
    attack = _get_attack_instance(normalized_strategy)
    if attack is None:
        return base_prompt

    try:
        # Deterministic strategies (base64, rot13, leetspeak) do not accept
        # simulator_model; LLM-driven strategies (prompt_injection, roleplay)
        # accept it as a keyword argument.
        if normalized_strategy in DETERMINISTIC_STRATEGIES:
            return attack.enhance(base_prompt)

        # DeepTeam's ``initialize_model`` defaults to OpenAI when given an
        # unrecognized string.  Pre-instantiate the correct native model so
        # the configured provider (gemini, openai, etc.) is actually used.
        model_for_attack = simulator_model
        if simulator_provider and isinstance(model_for_attack, str):
            native_model = _build_deepeval_model(simulator_provider, model_for_attack)
            if native_model is not None:
                model_for_attack = native_model

        sem = _get_concurrency_sem(max_concurrency)
        if sem is not None:
            logger.debug(
                "Acquiring DeepTeam semaphore (available=%s, limit=%s)",
                sem._value,
                max_concurrency,
            )
            with sem:
                logger.debug("DeepTeam semaphore acquired, running enhance")
                return attack.enhance(base_prompt, simulator_model=model_for_attack)
            # Note: semaphore is released on context-manager exit
        return attack.enhance(base_prompt, simulator_model=model_for_attack)
    except Exception as exc:  # pragma: no cover - defensive fallback
        logger.warning("DeepTeam enhance failed for strategy '%s'", normalized_strategy, exc_info=exc)
        return base_prompt
