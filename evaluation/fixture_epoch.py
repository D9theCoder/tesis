"""Collect fixture-restoration evidence for one study epoch.

Runs the existing read-only module census twice, compares the observed response
digests per level, and writes one ``fixture-restoration.v1`` operator
attestation per level.  The attestation is bound to the current source/config
epoch and the declared study epoch; it asserts only what the two censuses show:
the fixture was observed before and after the probe and no response changed.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections.abc import Mapping
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any

from evaluation.research_plan import source_identity

CENSUS_MODULE = "evaluation.fixture_census"
LEVELS = ("low", "medium", "high")
AUTHORIZED_PROTOCOL = (
    "docs/active/HANDOFF_AUTORESEARCH_LOOP_2026-10-30.md sections 2C/6: read-only "
    "fixture inventory and bounded detection controls only"
)


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(value: Any) -> str:
    return sha256(_canonical(value).encode("utf-8")).hexdigest()


def _http_status_available(value: Any) -> bool:
    """Return whether a census HTTP status is an observed valid status code."""
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 100 <= value <= 599
    )


def _row_observation(row: Mapping[str, Any]) -> dict[str, Any]:
    """Project one census row, retaining explicit unavailability evidence."""
    entry: dict[str, Any] = {
        "path": row.get("requested_path"),
        "status": row.get("status"),
        "content_sha256": row.get("content_sha256"),
    }
    unavailable: list[str] = []
    if row.get("error"):
        unavailable.append(f"row_error: {row.get('error')}")
    if not _http_status_available(row.get("status")):
        unavailable.append(f"http_status_unavailable: {row.get('status')!r}")
    if row.get("user_token_inputs") and row.get("content_sha256"):
        # DVWA regenerates the hidden CSRF token per session, so the body
        # digest is volatile while the fixture structure is not.
        entry["content_sha256"] = None
        entry["content_sha256_basis"] = "user_token_regenerated_per_session"
        entry["structure"] = {
            key: row.get(key)
            for key in (
                "content_length", "form_count", "form_actions",
                "form_methods", "form_inputs", "handler_kind",
                "user_token_inputs", "policy_text_present",
            )
        }
    elif not row.get("content_sha256"):
        unavailable.append("content_digest_missing")
    if row.get("error"):
        entry["error"] = row.get("error")
    view = row.get("nonadmin_view")
    if isinstance(view, dict):
        # The alternate-principal page embeds a fresh CSRF token on each
        # session; compare only its stable structural fields.
        entry["nonadmin_structure"] = {
            key: view.get(key)
            for key in (
                "status", "final_path", "handler_kind", "principal",
                "differs_from_admin", "content_length", "policy_text_present",
            )
        }
        if view.get("error"):
            unavailable.append(f"nonadmin_view_unavailable: {view.get('error')}")
        elif not _http_status_available(view.get("status")):
            unavailable.append(
                f"nonadmin_view_unavailable: http_status_unavailable: {view.get('status')!r}"
            )
    if unavailable:
        entry["available"] = False
        entry["unavailable_reason"] = "; ".join(unavailable)
    return entry


def _observed(census: Mapping[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """Return every observed row, never dropping failed or empty evidence.

    Failed probes have no ``content_sha256``.  They stay in the projection with
    ``available`` false so a partial census cannot compare equal to another
    partial census simply because both discarded the same failures.
    """
    observed: dict[str, list[dict[str, Any]]] = {}
    levels = census.get("levels")
    if not isinstance(levels, Mapping):
        levels = {}
    for level in LEVELS:
        document = levels.get(level)
        rows: list[dict[str, Any]] = []
        if isinstance(document, Mapping):
            raw_rows = document.get("rows")
            if isinstance(raw_rows, list):
                for row in raw_rows:
                    if not isinstance(row, Mapping):
                        rows.append({
                            "path": None,
                            "status": None,
                            "content_sha256": None,
                            "available": False,
                            "unavailable_reason": "row_not_an_object",
                        })
                        continue
                    rows.append(_row_observation(row))
        observed[level] = rows
    return observed


def _coverage_issues(
    census: Mapping[str, Any], observed: Mapping[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    """List missing, duplicate, or unavailable per-level fixture coverage."""
    issues: list[dict[str, Any]] = []
    levels = census.get("levels")
    level_documents = levels if isinstance(levels, Mapping) else {}
    nonadmin_errors = level_documents.get("nonadmin_session_errors")
    for level in LEVELS:
        document = level_documents.get(level)
        if not isinstance(document, Mapping):
            issues.append({"level": level, "reason": "level_missing"})
            continue
        if document.get("observed_level") != level:
            issues.append({
                "level": level,
                "reason": "level_not_observed",
                "detail": document.get("observed_level"),
            })
        nav_paths = document.get("index_nav_paths")
        if not isinstance(nav_paths, list) or not nav_paths:
            issues.append({"level": level, "reason": "module_inventory_missing"})
        if not document.get("nonadmin_principal"):
            issues.append({"level": level, "reason": "nonadmin_principal_missing"})
        if isinstance(nonadmin_errors, Mapping) and nonadmin_errors.get(level):
            issues.append({
                "level": level,
                "reason": "nonadmin_session_unavailable",
                "detail": nonadmin_errors.get(level),
            })
        raw_rows = document.get("rows")
        if not isinstance(raw_rows, list):
            issues.append({"level": level, "reason": "rows_not_a_list"})
            continue
        if not raw_rows:
            issues.append({"level": level, "reason": "empty_census"})
            continue
        seen: set[str] = set()
        for index, row in enumerate(raw_rows):
            if not isinstance(row, Mapping):
                issues.append({
                    "level": level, "reason": "row_not_an_object", "row_index": index,
                })
                continue
            path = row.get("requested_path")
            if not isinstance(path, str) or not path:
                issues.append({
                    "level": level, "reason": "row_path_missing", "row_index": index,
                })
            elif path in seen:
                issues.append({
                    "level": level, "reason": "duplicate_row", "path": path,
                })
            else:
                seen.add(path)
            if not row.get("module"):
                issues.append({
                    "level": level, "reason": "module_missing",
                    "path": path, "row_index": index,
                })
        missing_nav = sorted(
            str(path) for path in nav_paths
            if not isinstance(path, str) or path not in seen
        ) if isinstance(nav_paths, list) else []
        if missing_nav:
            issues.append({
                "level": level, "reason": "module_coverage_missing",
                "paths": missing_nav,
            })
        for entry in observed.get(level, []):
            if not entry.get("available", True):
                issues.append({
                    "level": level,
                    "reason": "observation_unavailable",
                    "path": entry.get("path"),
                    "detail": entry.get("unavailable_reason"),
                })
    return issues


def _run_census(output: Path, config_path: Path) -> dict[str, Any]:
    completed = subprocess.run(
        [sys.executable, "-m", CENSUS_MODULE, str(output.resolve()), "--config", str(config_path.resolve())],
        capture_output=True, text=True, check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"census failed ({completed.returncode}): {(completed.stderr or completed.stdout)[-800:]}"
        )
    return json.loads(output.read_bytes())


def build_attestations(
    *,
    epoch_id: str,
    repo_root: Path,
    output_dir: Path,
    config_path: Path,
) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    first_path = output_dir / "census-before.json"
    second_path = output_dir / "census-after.json"
    before = _run_census(first_path, config_path)
    after = _run_census(second_path, config_path)
    before_rows, after_rows = _observed(before), _observed(after)
    coverage = {
        "before": _coverage_issues(before, before_rows),
        "after": _coverage_issues(after, after_rows),
    }
    coverage_ready = not any(coverage.values())
    differences = {}
    for level in LEVELS:
        # Only complete successful observations can establish equivalence; the
        # coverage check below refuses an attestation when any are unavailable.
        before_map = {
            row["path"]: row for row in before_rows[level]
            if row.get("available", True)
        }
        after_map = {
            row["path"]: row for row in after_rows[level]
            if row.get("available", True)
        }
        differences[level] = {
            "before_only": sorted(set(before_map) - set(after_map)),
            "after_only": sorted(set(after_map) - set(before_map)),
            "changed": [
                path for path in sorted(set(before_map) & set(after_map))
                if before_map[path] != after_map[path]
            ],
        }
    identical = coverage_ready and all(
        not item["before_only"] and not item["after_only"] and not item["changed"]
        for item in differences.values()
    )
    no_mutation = {
        "artifact_type": "fixture_no_mutation_check",
        "epoch_id": epoch_id,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "census_before": str(first_path.relative_to(repo_root)),
        "census_after": str(second_path.relative_to(repo_root)),
        "identical": identical,
        "coverage_ok": coverage_ready,
        "coverage_issues": coverage,
        "differences": differences,
        "response_rows": {level: len(before_rows[level]) for level in LEVELS},
        "successful_response_rows": {
            level: sum(1 for row in before_rows[level] if row.get("available", True))
            for level in LEVELS
        },
        "observed_response_digest": _digest(before_rows),
        "note": "Two read-only censuses over the same instance; no reset or mutation was performed.",
    }
    no_mutation_path = output_dir / "no-mutation-check.json"
    no_mutation_path.write_text(json.dumps(no_mutation, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if not coverage_ready:
        raise RuntimeError("fixture census coverage is incomplete or unavailable; refusing isolated_equivalent attestation: " + json.dumps(coverage, sort_keys=True))
    if not identical:
        raise RuntimeError("fixture responses changed between the two censuses; refusing attestation")

    identity = source_identity(
        repository_root=repo_root.resolve(),
        config_path=str(config_path.resolve()),
    )
    observed_at = datetime.now(timezone.utc).isoformat()
    documents: dict[str, dict[str, Any]] = {}
    for level in LEVELS:
        document = {
            "policy_version": 'fixture-restoration',
            "evidence_id": f"fixture-restoration:dvwa:{level}:{epoch_id}",
            "kind": "operator_attestation",
            "fixture_id": "dvwa-source-fee264766667580e5352",
            "protocol_version": 'ranking-session-acceptance',
            "security_level": level,
            "epoch_id": epoch_id,
            "source_hashes_sha256": identity["source_hashes_sha256"],
            "restoration": "isolated_equivalent",
            "authorized_protocol": AUTHORIZED_PROTOCOL,
            "evidence_refs": [
                str(first_path.relative_to(repo_root)),
                str(second_path.relative_to(repo_root)),
                str(no_mutation_path.relative_to(repo_root)),
            ],
            "evidence_sha256": "",
            "observed_at": observed_at,
            "operator": "kevin (repository owner)",
        }
        document["evidence_sha256"] = _digest(
            {key: value for key, value in document.items() if key != "evidence_sha256"}
        )
        path = output_dir / f"fixture-restoration-{level}.json"
        path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        documents[level] = document
    envelope = {
        "artifact_type": "fixture_restoration_evidence_envelope",
        "epoch_id": epoch_id,
        "source_hashes_sha256": identity["source_hashes_sha256"],
        "levels": list(LEVELS),
        "by_level": documents,
        "no_mutation_check": str(no_mutation_path.relative_to(repo_root)),
        "note": "Read-only census evidence assembled by the assistant under the owner's approval.",
    }
    envelope_path = output_dir / "fixture-restoration-evidence.json"
    envelope_path.write_text(json.dumps(envelope, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {
        "envelope": str(envelope_path),
        "documents": {
            level: str(output_dir / f"fixture-restoration-{level}.json")
            for level in LEVELS
        },
        "no_mutation_check": str(no_mutation_path),
        "source_hashes_sha256": identity["source_hashes_sha256"],
        "identical": identical,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--epoch-id", required=True)
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--config", default="config.yaml")
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args(argv)
    result = build_attestations(
        epoch_id=args.epoch_id,
        repo_root=Path(args.repo_root),
        output_dir=Path(args.output_dir),
        config_path=Path(args.config),
    )
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry
    raise SystemExit(main())
