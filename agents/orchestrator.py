"""Orchestrator agent — method selection over AKG with reactive evasion."""

from __future__ import annotations

import json
import logging
from typing import Any

from langchain_core.messages import AIMessage, HumanMessage

from core.knowledge_graph import AttackKnowledgeGraph
from core.state import ALL_METHOD_AGENTS, METHODS_BY_SURFACE
from llm.guardrail_monitor import is_guardrail_refusal, make_guardrail_event
from llm.prompts.orchestrator_prompt import build_orchestrator_prompt
from llm.provider import get_llm

logger = logging.getLogger(__name__)

CRITICAL_OUTCOMES = set(AttackKnowledgeGraph.HIGH_IMPACT_OUTCOMES)


def _extract_response_text(raw_content: Any) -> str:
    if isinstance(raw_content, str):
        return raw_content
    if isinstance(raw_content, list):
        parts: list[str] = []
        for item in raw_content:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict):
                text = item.get("text")
                if isinstance(text, str):
                    parts.append(text)
        if parts:
            return "\n".join(parts)
    return str(raw_content)


def _parse_decision_payload(raw_text: str) -> dict[str, Any] | None:
    try:
        parsed = json.loads(raw_text)
        return parsed if isinstance(parsed, dict) else None
    except json.JSONDecodeError:
        start = raw_text.find("{")
        end = raw_text.rfind("}")
        if start == -1 or end == -1 or end <= start:
            return None
        try:
            parsed = json.loads(raw_text[start : end + 1])
            return parsed if isinstance(parsed, dict) else None
        except json.JSONDecodeError:
            return None


def _coerce_bool(value: Any) -> bool:
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


def _clip_text(text: str, limit: int = 1200) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + "...<truncated>"


def _sanitize_prompt_seed(text: str) -> str:
    replacements = {
        "exploitation workflow": "security assessment workflow",
        "exploit": "test",
        "attack": "assess",
        "orchestrator for a DVWA": "planner for a DVWA security test",
    }
    for bad, good in replacements.items():
        text = text.replace(bad, good)
    return text


def _fallback_next_agent(
    state: dict[str, Any],
) -> str:
    """Choose a deterministic next method agent without relying on LLM."""
    current_surface = state.get("current_surface", "sqli")
    attempted = set(state.get("attempted_agents", []))
    blocked = set(state.get("blocked_agents", []))
    failure_agents = set(state.get("failure_agents", []))
    observations = state.get("observations", {})
    scores = state.get("scores", {})
    
    kg = AttackKnowledgeGraph()
    viable = kg.get_viable_methods(current_surface, observations)
    
    # Prefer unattempted viable methods that have not previously failed
    for method in viable:
        if method not in attempted and method not in blocked and method not in failure_agents:
            return method

    # Try any unattempted method on this surface that has not failed
    for method in METHODS_BY_SURFACE.get(current_surface, []):
        if method not in attempted and method not in blocked and method not in failure_agents:
            return method
    
    # All exhausted
    return "scorer"


def _run_evasion_pipeline(prompt: str, evasion_max_retries: int) -> tuple[str, bool]:
    """LangGraph-native retry: restructure prompt wording + validity gate.

    Uses sentence-level restructuring rather than naive word replacement
    to avoid mangling technical terms (e.g. "exploitation" → "assessitation").
    """
    replacement_tiers: list[dict[str, str]] = [
        {
            "exploit the vulnerability": "test the security control",
            "attack the application": "evaluate the application",
            "perform an attack": "conduct a security test",
        },
        {
            "exploit": "verify",
            "attack": "assess",
            "payload to exploit": "payload to verify",
        },
    ]

    max_attempts = min(max(evasion_max_retries, 0), len(replacement_tiers))
    for attempt in range(max_attempts):
        candidate = prompt
        for old, new in replacement_tiers[attempt].items():
            candidate = candidate.replace(old, new)
        if candidate != prompt:
            return candidate, True
    return prompt, False


def orchestrator(state: dict[str, Any]) -> dict[str, Any]:
    iteration_count = state.get("iteration_count", 0)
    max_iterations = state.get("max_iterations", 30)
    confirmed_vulns = state.get("confirmed_vulns", [])
    achieved_outcomes = state.get("achieved_outcomes", [])
    # Deduplicate attempted_agents before passing to prompt and fallback logic.
    # attempted_agents uses Annotated[list[str], add] reducer, so duplicates
    # can accumulate if agents incorrectly return the full list.
    attempted_agents = list(dict.fromkeys(state.get("attempted_agents", [])))
    blocked_agents = state.get("blocked_agents", [])
    failure_agents = state.get("failure_agents", [])
    current_surface = state.get("current_surface", "sqli")
    observations = state.get("observations", {})
    scores = state.get("scores", {})
    consecutive_clean = state.get("consecutive_clean_responses", 0)
    
    evasion_enabled = _coerce_bool(state.get("evasion_enabled", False))
    evasion_mode = str(state.get("evasion_mode", "reactive")).strip().lower()
    evasion_max_retries = int(state.get("evasion_max_retries", 3))
    evasion_cooldown_threshold = int(state.get("evasion_cooldown_threshold", 5))
    
    telemetry_base = {
        "node": "orchestrator",
        "iteration": iteration_count,
    }
    telemetry_events: list[dict[str, Any]] = []
    
    if iteration_count >= max_iterations:
        return {
            "next_agent": "scorer",
            "iteration_count": iteration_count + 1,
            "telemetry_events": [{**telemetry_base, "event": "orchestrator.stop", "reason": "budget_exhausted"}],
        }

    if (set(confirmed_vulns) | set(achieved_outcomes)) & CRITICAL_OUTCOMES:
        return {
            "next_agent": "scorer",
            "iteration_count": iteration_count + 1,
            "telemetry_events": [{**telemetry_base, "event": "orchestrator.stop", "reason": "critical_outcome"}],
        }

    kg = AttackKnowledgeGraph()
    viable_methods = kg.get_viable_methods(current_surface, observations)
    
    fallback_agent = _fallback_next_agent(state)
    
    base_prompt = build_orchestrator_prompt(
        current_surface=current_surface,
        viable_methods=viable_methods,
        observations=observations,
        attempted_agents=attempted_agents,
        blocked_agents=blocked_agents,
        failure_agents=failure_agents,
        scores=scores,
        confirmed_vulns=confirmed_vulns,
        achieved_outcomes=achieved_outcomes,
        security_level=state.get("security_level", "low"),
        iteration_count=iteration_count,
        max_iterations=max_iterations,
    )
    prompt = _sanitize_prompt_seed(base_prompt)
    
    # Evasion logic
    evasion_triggered = False
    evasion_success = False
    retries_used = 0
    
    if evasion_enabled and evasion_mode != "disabled":
        if evasion_mode == "proactive":
            # Proactive: always run evasion
            prompt, evasion_success = _run_evasion_pipeline(prompt, evasion_max_retries)
            evasion_triggered = True
            retries_used = 1
            telemetry_events.append({
                **telemetry_base,
                "event": "orchestrator.evasion.triggered",
                "status": "ok" if evasion_success else "failed",
                "payload": {"mode": "proactive", "reason": "unconditional"},
            })
        else:
            # Reactive mode
            # 1. Cooldown check: suppress pre-check if enough clean responses
            if consecutive_clean >= evasion_cooldown_threshold:
                telemetry_events.append({
                    **telemetry_base,
                    "event": "orchestrator.evasion.skipped",
                    "status": "ok",
                    "payload": {"reason": "cooldown_active", "consecutive_clean": consecutive_clean},
                })
            else:
                # Reactive: no pre-check; guardrail detection happens after LLM call
                pass
    
    try:
        provider_name = state.get("llm_provider", "gemini")
        model_cfg = state.get("model_config", {})
        if model_cfg:
            kwargs = {k: v for k, v in model_cfg.items() if k != "provider"}
            extra = kwargs.pop("extra", {})
            if isinstance(extra, dict):
                kwargs.update(extra)
            llm = get_llm(provider_name, **kwargs)
        else:
            llm = get_llm(provider_name)
        response = llm.invoke([HumanMessage(content=prompt)])
        text = _extract_response_text(getattr(response, "content", ""))
        
        telemetry_events.append({
            **telemetry_base,
            "event": "orchestrator.llm.response",
            "status": "ok",
            "payload": {"response_text": _clip_text(text)},
        })
        
        # Reactive evasion check AFTER LLM response
        if evasion_enabled and evasion_mode == "reactive" and consecutive_clean < evasion_cooldown_threshold:
            if is_guardrail_refusal(text):
                evasion_triggered = True
                telemetry_events.append({
                    **telemetry_base,
                    "event": "orchestrator.evasion.triggered",
                    "status": "ok",
                    "payload": {"reason": "guardrail_refusal"},
                })
                retry_budget = max(evasion_max_retries, 0)
                for retry in range(retry_budget):
                    retries_used = retry + 1
                    new_prompt, success = _run_evasion_pipeline(prompt, evasion_max_retries)
                    if success:
                        prompt = new_prompt
                    response = llm.invoke([HumanMessage(content=prompt)])
                    text = _extract_response_text(getattr(response, "content", ""))
                    if not is_guardrail_refusal(text):
                        evasion_success = True
                        break
                
                if evasion_success:
                    telemetry_events.append({
                        **telemetry_base,
                        "event": "orchestrator.evasion.success",
                        "status": "ok",
                        "payload": {"retries_used": retries_used},
                    })
                else:
                    telemetry_events.append({
                        **telemetry_base,
                        "event": "orchestrator.evasion.failed",
                        "status": "fallback",
                        "payload": {"reason": "max_retries_exhausted", "retries_used": retries_used},
                    })
            else:
                # Clean response
                telemetry_events.append({
                    **telemetry_base,
                    "event": "orchestrator.evasion.skipped",
                    "status": "ok",
                    "payload": {"reason": "clean_response"},
                })
        
        if is_guardrail_refusal(text) and not evasion_success:
            # Do NOT add fallback_agent to blocked_agents — guardrail refusals
            # are about the orchestrator prompt, not the method agent. Blocking
            # the fallback would permanently disable viable methods.
            return {
                "next_agent": fallback_agent,
                "iteration_count": iteration_count + 1,
                "guardrail_activations": [make_guardrail_event(
                    provider=state.get("llm_provider", "gemini"),
                    context="orchestrator",
                    response=text,
                )],
                "telemetry_events": telemetry_events,
                "messages": [HumanMessage(content=prompt), AIMessage(content=text)],
                "consecutive_clean_responses": 0,
                "evasion_attempts": state.get("evasion_attempts", 0) + (1 if evasion_triggered else 0),
                "successful_evasions": state.get("successful_evasions", 0),
            }
        
        parsed = _parse_decision_payload(text)
        parse_ok = isinstance(parsed, dict) and isinstance(parsed.get("next_agent"), str)
        candidate = parsed["next_agent"] if parse_ok else fallback_agent
        next_agent = candidate if candidate in ALL_METHOD_AGENTS or candidate == "scorer" else fallback_agent
        used_fallback = not parse_ok or candidate != next_agent
        
        # Update consecutive_clean_responses
        new_clean_count = consecutive_clean + 1 if not evasion_triggered else 0
        
        telemetry_events.append({
            **telemetry_base,
            "event": "orchestrator.decision",
            "status": "ok",
            "payload": {"next_agent": next_agent, "used_fallback": used_fallback},
        })
        
        return {
            "next_agent": next_agent,
            "iteration_count": iteration_count + 1,
            "telemetry_events": telemetry_events,
            "messages": [HumanMessage(content=prompt), AIMessage(content=text)],
            "consecutive_clean_responses": new_clean_count,
            "evasion_attempts": state.get("evasion_attempts", 0) + (retries_used if evasion_triggered else 0),
            "successful_evasions": state.get("successful_evasions", 0) + (1 if evasion_success else 0),
        }
    except Exception as exc:
        # Harness node — crashing the graph is worse than logging a fallback.
        logger.exception("Orchestrator failed; applying deterministic fallback")
        return {
            "next_agent": fallback_agent,
            "iteration_count": iteration_count + 1,
            "telemetry_events": [
                *telemetry_events,
                {**telemetry_base, "event": "orchestrator.fallback.applied", "status": "fallback", "payload": {"error_type": type(exc).__name__, "next_agent": fallback_agent}},
            ],
            "messages": [HumanMessage(content=prompt), AIMessage(content=f"orchestrator_fallback:{type(exc).__name__}")],
            "evasion_attempts": state.get("evasion_attempts", 0) + (retries_used if evasion_triggered else 0),
            "successful_evasions": state.get("successful_evasions", 0) + (1 if evasion_success else 0),
        }
