import os
from typing import Any

from dotenv import load_dotenv
from langchain_core.messages import HumanMessage

SAMPLE_QUERY = "What model do you use?"
SUPPORTED_PROVIDERS = ["gemini"]

# Load environment variables from .env file
load_dotenv()


def get_llm(provider_name: str, **kwargs):
    """
    Returns a configured LangChain ChatModel based on the provider string.
    Maps to AGENTS.md providers: "claude", "gpt4o", "gemini", "llama"
    """
    normalized_provider = provider_name.strip().lower()

    if normalized_provider == "gemini":
        from langchain_google_genai import ChatGoogleGenerativeAI
        temperature = kwargs.pop("temperature", 0)
        return ChatGoogleGenerativeAI(
            model="gemini-3-flash-preview",
            temperature=temperature,
            **kwargs,
        )
    else:
        raise ValueError(f"Unsupported LLM provider: {provider_name}")


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
