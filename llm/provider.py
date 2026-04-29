import os
import logging
from typing import TYPE_CHECKING
from typing import Any

from dotenv import load_dotenv
from langchain_core.messages import HumanMessage

SAMPLE_QUERY = "What model do you use?"
SUPPORTED_PROVIDERS = ["gemini", "openai", "claude"]
logger = logging.getLogger(__name__)

# Load environment variables from .env file
load_dotenv()

if TYPE_CHECKING:
    from tesis.model_config import ModelConfig


def get_llm(provider_name: str, **kwargs):
    normalized_provider = provider_name.strip().lower()

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
        if base_url:
            constructor_kwargs["base_url"] = base_url
        return ChatOpenAI(
            model=model_name,
            temperature=temperature,
            api_key=api_key,
            **constructor_kwargs,
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


def get_simulator_llm(simulator_model: str = "gpt-4o-mini", provider: str | None = None, **kwargs):
    """Return a simulator LLM for the evasion pipeline.

    The simulator model rewrites baseline seeds into adversarial candidates.
    When *provider* is given, it is used directly; otherwise the function
    guesses from the model name and falls back to gemini.
    """
    if "temperature" not in kwargs:
        kwargs["temperature"] = 0.7

    if provider:
        try:
            return get_llm(provider, model_name=simulator_model, **kwargs)
        except Exception as exc:
            logger.warning(
                "Simulator provider '%s' unavailable; falling back to gemini",
                provider,
                exc_info=exc,
            )
            return get_llm("gemini", model_name="gemini-3-flash-preview", **kwargs)

    normalized = simulator_model.strip().lower()
    if "gpt" in normalized or normalized.startswith("openai"):
        try:
            return get_llm("openai", model_name=simulator_model, **kwargs)
        except Exception as exc:
            logger.warning(
                "OpenAI simulator client unavailable; falling back to gemini simulator",
                exc_info=exc,
            )

    return get_llm(
        "gemini",
        model_name=kwargs.pop("model_name", "gemini-3-flash-preview"),
        **kwargs,
    )


def get_llm_from_model_config(config: "ModelConfig", **kwargs):
    """Build an LLM client from typed Stage 7 model configuration."""

    merged_kwargs: dict[str, Any] = dict(config.extra)
    merged_kwargs.update(kwargs)

    if "temperature" not in merged_kwargs:
        merged_kwargs["temperature"] = config.temperature
    if "request_timeout" not in merged_kwargs and "timeout" not in merged_kwargs:
        merged_kwargs["request_timeout"] = config.timeout
    if config.max_tokens is not None and "max_output_tokens" not in merged_kwargs:
        merged_kwargs["max_output_tokens"] = config.max_tokens
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


def _resolve_model_name(llm: Any) -> str:
    return getattr(llm, "model_name", getattr(llm, "model", "unknown"))


def invoke_sample_query(provider_name: str, query: str = SAMPLE_QUERY, **kwargs) -> dict[str, str]:
    """
    Sends a hardcoded sample query to the requested provider using LangChain.
    Returns a normalized response payload for display in the program.
    """
    llm = get_llm(provider_name, **kwargs)
    response = llm.invoke([HumanMessage(content=query)])
    response_content = response.content if isinstance(response.content, str) else str(response.content)

    return {
        "provider": provider_name,
        "model": _resolve_model_name(llm),
        "query": query,
        "response": response_content,
    }
