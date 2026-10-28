"""Immutable payload policy, neutral-template, and prompt identity snapshot.

The snapshot is produced once when a study epoch is frozen and is persisted with
execution artifacts (``recorded_payload_policy``) so historical replay can
validate a recorded candidate against the registry/policy that actually produced
it.  Without it, replay would silently compare retained evidence with today's
mutable template registry and prompt manifests.

This module deliberately imports the live registries lazily and is imported only
by producers (the study plan, the runner) so no runtime module gains an import
cycle back through the payload pipeline.
"""

from __future__ import annotations

import json
from hashlib import sha256
from typing import Any

from core.payload_policy import (
    BUDGET_POLICY_VERSION,
    CONTROL_POLICY_VERSION,
    EXPERIMENT_POLICY_VERSION,
    MUTATION_PROMPT_ID,
    PAYLOAD_POLICY_VERSION,
    PAYLOAD_SCHEMA_VERSION,
    PAYLOAD_TEMPLATE_SCHEMA_VERSION,
    TEMPLATE_PROMPT_ID,
    TEMPLATE_REGISTRY_VERSION,
)

RECORDED_POLICY_SNAPSHOT_VERSION = "payload-policy-snapshot.v1"
PROMPT_IDENTITY_FIELDS = (
    "version",
    "template_hash",
    "input_schema_hash",
    "output_schema_hash",
    "output_schema_version",
    "validator_version",
    "validator_hash",
    "eval_suite_version",
)


def snapshot_hash(value: Any) -> str:
    """Return the canonical SHA-256 of a JSON-serializable snapshot."""
    return sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()


def payload_policy_snapshot() -> dict[str, Any]:
    """Return the immutable payload policy/template/prompt identity for an epoch.

    ``template_registry`` is keyed ``template.<method>.<level>`` so the exact
    JSON document can be passed straight to
    ``foundation.payload_templates.validate_template_reference`` as a recorded
    registry.  ``snapshot_sha256`` covers every other field.
    """
    from foundation.payload_templates import TEMPLATE_REGISTRY
    from llm.prompts.manifests import MANIFEST_VERSION, PROMPT_MANIFESTS

    template_registry = {
        f"template.{method}.{level}": {str(key): value for key, value in row.items()}
        for (method, level), row in sorted(TEMPLATE_REGISTRY.items())
    }
    prompt_manifests = {
        prompt_id: {field: manifest.get(field) for field in PROMPT_IDENTITY_FIELDS}
        for prompt_id, manifest in sorted(PROMPT_MANIFESTS.items())
    }
    snapshot: dict[str, Any] = {
        "snapshot_version": RECORDED_POLICY_SNAPSHOT_VERSION,
        "policy_version": PAYLOAD_POLICY_VERSION,
        "payload_policy_version": PAYLOAD_POLICY_VERSION,
        "control_policy_version": CONTROL_POLICY_VERSION,
        "budget_policy_version": BUDGET_POLICY_VERSION,
        "experiment_policy_version": EXPERIMENT_POLICY_VERSION,
        "mutation_prompt_id": MUTATION_PROMPT_ID,
        "template_prompt_id": TEMPLATE_PROMPT_ID,
        "mutation_schema_version": PAYLOAD_SCHEMA_VERSION,
        "template_schema_version": PAYLOAD_TEMPLATE_SCHEMA_VERSION,
        "template_registry_version": TEMPLATE_REGISTRY_VERSION,
        "template_registry": template_registry,
        "template_registry_sha256": snapshot_hash(template_registry),
        "prompt_manifest_version": MANIFEST_VERSION,
        "prompt_manifests": prompt_manifests,
        "prompt_manifests_sha256": snapshot_hash(prompt_manifests),
    }
    snapshot["snapshot_sha256"] = snapshot_hash(snapshot)
    return snapshot


def verify_payload_policy_snapshot(snapshot: Any) -> list[dict[str, Any]]:
    """Return issues describing why a recorded snapshot is unusable.

    An empty list means the snapshot is structurally complete and its own digest
    matches.  It does not compare with the live registry: replay is exactly what
    must stay independent from today's policy.
    """
    issues: list[dict[str, Any]] = []
    if not isinstance(snapshot, dict):
        return [{"valid": False, "reason": "recorded_policy_not_an_object"}]
    if snapshot.get("snapshot_version") != RECORDED_POLICY_SNAPSHOT_VERSION:
        issues.append({"valid": False, "reason": "recorded_policy_version_unsupported"})
    for field in ("policy_version", "payload_policy_version", "template_registry_version"):
        if not isinstance(snapshot.get(field), str) or not snapshot[field].strip():
            issues.append({"valid": False, "reason": f"recorded_policy_missing_{field}"})
    registry = snapshot.get("template_registry")
    if not isinstance(registry, dict) or not registry:
        issues.append({"valid": False, "reason": "recorded_template_registry_unavailable"})
    elif snapshot.get("template_registry_sha256") != snapshot_hash(registry):
        issues.append({"valid": False, "reason": "recorded_template_registry_hash_mismatch"})
    manifests = snapshot.get("prompt_manifests")
    if not isinstance(manifests, dict) or not manifests:
        issues.append({"valid": False, "reason": "recorded_prompt_manifests_unavailable"})
    elif snapshot.get("prompt_manifests_sha256") != snapshot_hash(manifests):
        issues.append({"valid": False, "reason": "recorded_prompt_manifests_hash_mismatch"})
    stored = snapshot.get("snapshot_sha256")
    expected = snapshot_hash({key: value for key, value in snapshot.items() if key != "snapshot_sha256"})
    if stored != expected:
        issues.append({"valid": False, "reason": "recorded_policy_snapshot_hash_mismatch"})
    return issues


__all__ = [
    "PROMPT_IDENTITY_FIELDS",
    "RECORDED_POLICY_SNAPSHOT_VERSION",
    "payload_policy_snapshot",
    "snapshot_hash",
    "verify_payload_policy_snapshot",
]
