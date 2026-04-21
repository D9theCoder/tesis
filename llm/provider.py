import os
from typing import TYPE_CHECKING
from typing import Any

from dotenv import load_dotenv
from langchain_core.messages import HumanMessage

SAMPLE_QUERY = "What model do you use?"
SUPPORTED_PROVIDERS = ["gemini"]

# Load environment variables from .env file
load_dotenv()

if TYPE_CHECKING:
    from tesis.model_config import ModelConfig


def get_llm(provider_name: str, **kwargs):
    """
    Returns a configured LangChain ChatModel based on the provider string.
    Current runtime support: "gemini".
    """
    normalized_provider = provider_name.strip().lower()

    if normalized_provider == "gemini":
        from langchain_google_genai import ChatGoogleGenerativeAI
        temperature = kwargs.pop("temperature", 0)
        model_name = kwargs.pop("model_name", kwargs.pop("model", "gemini-3-flash-preview"))
        api_key = kwargs.pop("api_key", None) or os.getenv("GOOGLE_API_KEY") or os.getenv("GEMINI_API_KEY")
        return ChatGoogleGenerativeAI(
            model=model_name,
            temperature=temperature,
            google_api_key=api_key,
            **kwargs,
        )
    else:
        raise ValueError(f"Unsupported LLM provider: {provider_name}")


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
