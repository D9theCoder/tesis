from llm.provider import SAMPLE_QUERY, SUPPORTED_PROVIDERS, invoke_sample_query


def main() -> dict[str, dict[str, str]]:
    print("=== LLM Sample Query Runner ===")
    print(f'Hardcoded query: "{SAMPLE_QUERY}"')

    results: dict[str, dict[str, str]] = {}

    providers = SUPPORTED_PROVIDERS if isinstance(SUPPORTED_PROVIDERS, list) else [SUPPORTED_PROVIDERS]

    for provider in providers:
        try:
            result = invoke_sample_query(provider)
            success_payload = {"status": "success", **result}
            results[provider] = success_payload
            print(f"\n[{provider}] ({result['model']}): {result['response']}")
        except Exception as exc:
            error_payload = {
                "status": "error",
                "provider": provider,
                "model": "unknown",
                "query": SAMPLE_QUERY,
                "response": "",
                "error": str(exc),
            }
            results[provider] = error_payload
            print(f"\n[{provider}] Error: {exc}")

    return results


if __name__ == "__main__":
    all_responses = main()
    print("\n=== Response Map ===")
    print(all_responses)
