import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

def get_llm(provider_name: str, **kwargs):
    """
    Returns a configured LangChain ChatModel based on the provider string.
    Maps to AGENTS.md providers: "claude", "gpt4o", "gemini", "llama"
    """
    if provider_name == "gpt4o":
        from langchain_openai import ChatOpenAI
        return ChatOpenAI(model="gpt-4o", temperature=0, **kwargs)
        
    elif provider_name == "gemini":
        from langchain_google_genai import ChatGoogleGenerativeAI
        return ChatGoogleGenerativeAI(model="gemini-1.5-pro", temperature=0, **kwargs)
        
    elif provider_name == "claude":
        from langchain_anthropic import ChatAnthropic
        return ChatAnthropic(model="claude-3-5-sonnet-20241022", temperature=0, **kwargs)
        
    elif provider_name == "llama":
        from langchain_openai import ChatOpenAI
        base_url = os.getenv("OPENAI_API_BASE", "http://localhost:11434/v1")
        # For local models or OpenAI compatible APIs
        return ChatOpenAI(
            model="meta-llama/Meta-Llama-3-8B-Instruct", 
            base_url=base_url,
            temperature=0, 
            **kwargs
        )
        
    else:
        raise ValueError(f"Unsupported LLM provider: {provider_name}")
