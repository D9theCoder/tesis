"""Stage 6 matrix runner across providers and security levels."""

from __future__ import annotations

from core.state import SECURITY_LEVELS
from llm.provider import SUPPORTED_PROVIDERS

from evaluation.runner import run_single_engagement


def run_provider_matrix(
    *,
    target_url: str,
    providers: list[str] | None = None,
    security_levels: list[str] | None = None,
    repeats: int = 1,
    max_iterations: int = 30,
) -> list[dict]:
    chosen_providers = sorted(providers or list(SUPPORTED_PROVIDERS))
    chosen_levels = sorted(security_levels or list(SECURITY_LEVELS))

    artifacts: list[dict] = []
    for provider in chosen_providers:
        if provider not in SUPPORTED_PROVIDERS:
            for level in chosen_levels:
                for repeat_index in range(repeats):
                    artifacts.append(
                        {
                            "schema_version": "stage6.v1",
                            "run_id": f"{provider}-{level}-{repeat_index}",
                            "status": "skipped",
                            "config": {
                                "target_url": target_url,
                                "provider": provider,
                                "security_level": level,
                                "max_iterations": max_iterations,
                                "repeat_index": repeat_index,
                            },
                            "timing": {},
                            "final_state": {},
                            "report": {},
                            "error": f"Unsupported provider: {provider}",
                        }
                    )
            continue

        for level in chosen_levels:
            for repeat_index in range(repeats):
                artifacts.append(
                    run_single_engagement(
                        target_url=target_url,
                        security_level=level,
                        llm_provider=provider,
                        max_iterations=max_iterations,
                        repeat_index=repeat_index,
                    )
                )

    return artifacts
