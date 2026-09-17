"""Multi-LLM Layer utilities and prompts for framework decisions.

This module prepares provider integrations, guardrail handling, evasion retry
logic, or prompt text used by the LangGraph Execution Flow."""
import copy
import os
import logging
from typing import TYPE_CHECKING
from typing import Any, Mapping

from dotenv import load_dotenv
from langchain_core.messages import HumanMessage

SUPPORTED_PROVIDERS = ["gemini", "openai", "claude", "openai_compatible"]
SAMPLE_QUERY = "What model are you? Reply with your model name only."
# Provider APIs treat an omitted output limit as unbounded.  That is unsafe for
# streamed experiment calls: a model can keep the HTTP response open long
# enough to outlive the runner's per-request read timeout.  Callers may still
# override this explicitly through ``max_tokens`` (or ``max_output_tokens``
# where the provider uses that spelling).
DEFAULT_MAX_OUTPUT_TOKENS = 512
REASONING_EFFORTS = ("low", "medium", "high", "xhigh", "max")
logger = logging.getLogger(__name__)

# NOTE: Callers must load env vars before importing if needed (e.g. via load_dotenv())

if TYPE_CHECKING:
    from tesis.model_config import ModelConfig


def validate_reasoning_effort(value: Any) -> str | None:
    """Validate our portable control without assuming model capabilities."""
    if value is None or value == "":
        return None
    effort = str(value).strip().lower()
    if effort not in REASONING_EFFORTS:
        raise ValueError(f"reasoning_effort must be one of {', '.join(REASONING_EFFORTS)} or null")
    return effort


def _reasoning_kwargs(provider: str, kwargs: dict[str, Any]) -> None:
    effort = validate_reasoning_effort(kwargs.pop("reasoning_effort", None))
    if effort is None:
        return
    if provider not in {"openai", "openai_compatible"}:
        raise ValueError(
            f"reasoning_effort={effort!r} is not mapped for provider '{provider}'. "
            "Use null (provider default) and configure native thinking parameters in models.<profile>.extra, "
            "or select an OpenAI-compatible reasoning model."
        )

    # One canonical provider field owns an explicit effort. Legacy fields in
    # model_kwargs/extra_body are removed because the OpenAI SDK merges those
    # mappings into the request after typed fields and could otherwise override
    # the selected effort or reintroduce an incompatible temperature.
    legacy_reasoning = kwargs.pop("reasoning", None)
    for container_name in ("model_kwargs", "extra_body"):
        if container_name not in kwargs:
            continue
        container = dict(kwargs.get(container_name) or {})
        for key in ("reasoning", "reasoning_effort", "temperature"):
            container.pop(key, None)
        kwargs[container_name] = container

    if kwargs.get("use_responses_api"):
        reasoning = dict(legacy_reasoning) if isinstance(legacy_reasoning, Mapping) else {}
        reasoning["effort"] = effort
        kwargs["reasoning"] = reasoning
    else:
        kwargs["reasoning_effort"] = effort

    # Reasoning families commonly reject sampling controls. Omit temperature
    # from both the typed request and the raw/legacy mappings above.
    kwargs["temperature"] = None


def get_llm(provider_name: str, **kwargs):
    """Returns llm for framework callers.

    Args:
        provider_name: Value used by this function."""
    normalized_provider = provider_name.strip().lower()
    _reasoning_kwargs(normalized_provider, kwargs)
    if normalized_provider in {"openai", "openai_compatible", "claude"}:
        output_tokens = kwargs.pop("max_output_tokens", None)
        if output_tokens is not None and kwargs.get("max_tokens") is None:
            kwargs["max_tokens"] = output_tokens

    if normalized_provider == "gemini":
        from langchain_google_genai import ChatGoogleGenerativeAI
        temperature = kwargs.pop("temperature", 0)
        model_name = kwargs.pop("model_name", kwargs.pop("model", "gemini-3-flash-preview"))
        api_key = kwargs.pop("api_key", None) or os.getenv("GOOGLE_API_KEY") or os.getenv("GEMINI_API_KEY")
        system_prompt = kwargs.pop("system_prompt", None)
        constructor_kwargs = dict(kwargs)
        if system_prompt:
            constructor_kwargs["system_instruction"] = system_prompt
        return ChatGoogleGenerativeAI(
            model=model_name,
            temperature=temperature,
            google_api_key=api_key,
            **constructor_kwargs,
        )
    elif normalized_provider == "openai":
        from langchain_openai import ChatOpenAI
        temperature = kwargs.pop("temperature", 0)
        model_name = kwargs.pop("model_name", kwargs.pop("model", "gpt-4o-mini"))
        api_key = kwargs.pop("api_key", None) or os.getenv("OPENAI_API_KEY") or ""
        base_url = kwargs.pop("base_url", None)
        kwargs.pop("system_prompt", None)
        constructor_kwargs = dict(kwargs)
        if constructor_kwargs.get("max_tokens") is None:
            constructor_kwargs["max_tokens"] = DEFAULT_MAX_OUTPUT_TOKENS
        if base_url:
            constructor_kwargs["base_url"] = base_url
        # A configured timeout should bound one experiment call. LangChain's
        # default retries can otherwise multiply a 60-second timeout into a
        # multi-minute stall before the runner records a provider failure.
        if constructor_kwargs.get("max_retries") is None:
            constructor_kwargs["max_retries"] = 0
        return ChatOpenAI(
            model=model_name,
            temperature=temperature,
            api_key=api_key,
            **constructor_kwargs,
        )
    elif normalized_provider == "openai_compatible":
        from langchain_openai import ChatOpenAI
        temperature = kwargs.pop("temperature", 0)
        model_name = kwargs.pop("model_name", kwargs.pop("model", ""))
        api_key = kwargs.pop("api_key", None) or os.getenv("OPENAI_COMPATIBLE_API_KEY") or ""
        base_url = (kwargs.pop("base_url", None) or os.getenv("OPENAI_COMPATIBLE_BASE_URL") or "").strip()
        if not base_url:
            raise ValueError(
                "openai_compatible provider requires base_url. "
                "Set it in config.yaml models.openai_compatible.base_url "
                "or OPENAI_COMPATIBLE_BASE_URL environment variable."
            )
        kwargs.pop("system_prompt", None)
        if kwargs.get("max_tokens") is None:
            kwargs["max_tokens"] = DEFAULT_MAX_OUTPUT_TOKENS
        # Keep provider failures bounded by the configured timeout. Callers
        # that need retry semantics can pass an explicit ``max_retries``.
        if kwargs.get("max_retries") is None:
            kwargs["max_retries"] = 0
        return ChatOpenAI(
            model=model_name,
            temperature=temperature,
            api_key=api_key,
            base_url=base_url,
            **kwargs,
        )
    elif normalized_provider == "claude":
        from langchain_anthropic import ChatAnthropic
        temperature = kwargs.pop("temperature", 0)
        model_name = kwargs.pop("model_name", kwargs.pop("model", "claude-3-sonnet-20240229"))
        api_key = kwargs.pop("api_key", None) or os.getenv("ANTHROPIC_API_KEY") or ""
        return ChatAnthropic(
            model=model_name,
            temperature=temperature,
            anthropic_api_key=api_key,
            **kwargs,
        )
    else:
        raise ValueError(f"Unsupported LLM provider: {provider_name}")


def invoke_sample_query(provider_name: str, **kwargs) -> dict[str, str]:
    """Run the standalone provider smoke query used by development tests."""
    llm = get_llm(provider_name, **kwargs)
    response = llm.invoke([HumanMessage(content=SAMPLE_QUERY)])
    model = getattr(llm, "model_name", None) or getattr(llm, "model", "unknown")
    return {
        "provider": provider_name,
        "model": str(model),
        "query": SAMPLE_QUERY,
        "response": str(getattr(response, "content", response)),
    }


def get_simulator_llm(simulator_model: str = "gpt-4o-mini", provider: str | None = None, **kwargs):
    """Return a simulator LLM for the evasion pipeline.

    The simulator model rewrites baseline seeds into schema-preserving retry candidates.
    When *provider* is given, it is used directly; otherwise the function
    guesses from the model name and falls back to gemini.
    """
    if "temperature" not in kwargs:
        kwargs["temperature"] = 0.7

    if provider:
        try:
            kwargs_copy = copy.deepcopy(kwargs)
            return get_llm(provider, model_name=simulator_model, **kwargs_copy)
        except Exception as exc:
            logger.warning(
                "Simulator provider '%s' unavailable; falling back to gemini",
                provider,
                exc_info=exc,
            )
            kwargs_copy = copy.deepcopy(kwargs)
            return get_llm("gemini", model_name="gemini-3-flash-preview", **kwargs_copy)

    normalized = simulator_model.strip().lower()
    if "gpt" in normalized or normalized.startswith("openai"):
        try:
            kwargs_copy = copy.deepcopy(kwargs)
            return get_llm("openai", model_name=simulator_model, **kwargs_copy)
        except Exception as exc:
            logger.warning(
                "OpenAI simulator client unavailable; falling back to gemini simulator",
                exc_info=exc,
            )

    kwargs_copy = copy.deepcopy(kwargs)
    return get_llm(
        "gemini",
        model_name=kwargs_copy.pop("model_name", "gemini-3-flash-preview"),
        **kwargs_copy,
    )


def get_llm_from_model_config(config: "ModelConfig", **kwargs):
    """Build an LLM client from typed Stage 7 model configuration."""

    merged_kwargs: dict[str, Any] = dict(config.extra)
    merged_kwargs.update(kwargs)

    if "temperature" not in merged_kwargs:
        merged_kwargs["temperature"] = config.temperature
    if "reasoning_effort" not in kwargs and config.reasoning_effort is not None:
        merged_kwargs["reasoning_effort"] = config.reasoning_effort
    if "request_timeout" not in merged_kwargs and "timeout" not in merged_kwargs:
        merged_kwargs["request_timeout"] = config.timeout
    if config.max_tokens is not None and not any(
        key in merged_kwargs for key in ("max_tokens", "max_output_tokens")
    ):
        merged_kwargs["max_tokens"] = config.max_tokens
    if config.base_url:
        merged_kwargs.setdefault("base_url", config.base_url)
    if "system_prompt" in config.extra:
        merged_kwargs.setdefault("system_prompt", config.extra["system_prompt"])

    return get_llm(
        config.provider,
        model_name=config.model_name,
        api_key=config.api_key,
        **merged_kwargs,
    )
