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
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any

from evaluation.research_plan import source_identity

CENSUS_SCRIPT = Path("results/validation/remediation-2026-10-30/census.py")
LEVELS = ("low", "medium", "high")
AUTHORIZED_PROTOCOL = (
    "docs/active/HANDOFF_AUTORESEARCH_LOOP_2026-10-30.md sections 2C/6: read-only "
    "fixture inventory and bounded detection controls only"
)


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(value: Any) -> str:
    return sha256(_canonical(value).encode("utf-8")).hexdigest()


def _observed(census: dict[str, Any]) -> dict[str, Any]:
    observed: dict[str, Any] = {}
    for level in LEVELS:
        rows = []
        for row in (census.get("levels", {}).get(level, {}) or {}).get("rows", []):
            if not isinstance(row, dict) or not row.get("content_sha256"):
                continue
            entry = {
                "path": row.get("requested_path"),
                "status": row.get("status"),
                "content_sha256": row.get("content_sha256"),
            }
            if row.get("user_token_inputs"):
                # DVWA regenerates the hidden CSRF token per session, so the
                # body digest is volatile while the fixture structure is not.
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
            rows.append(entry)
        observed[level] = rows
    return observed


def _run_census(output: Path) -> dict[str, Any]:
    completed = subprocess.run(
        [sys.executable, str(CENSUS_SCRIPT), str(output)],
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
    before = _run_census(first_path)
    after = _run_census(second_path)
    before_rows, after_rows = _observed(before), _observed(after)
    differences = {}
    for level in LEVELS:
        before_map = {row["path"]: row for row in before_rows[level]}
        after_map = {row["path"]: row for row in after_rows[level]}
        differences[level] = {
            "before_only": sorted(set(before_map) - set(after_map)),
            "after_only": sorted(set(after_map) - set(before_map)),
            "changed": [
                path for path in sorted(set(before_map) & set(after_map))
                if before_map[path] != after_map[path]
            ],
        }
    identical = all(
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
        "differences": differences,
        "response_rows": {level: len(before_rows[level]) for level in LEVELS},
        "observed_response_digest": _digest(before_rows),
        "note": "Two read-only censuses over the same instance; no reset or mutation was performed.",
    }
    no_mutation_path = output_dir / "no-mutation-check.json"
    no_mutation_path.write_text(json.dumps(no_mutation, indent=2, sort_keys=True) + "\n", encoding="utf-8")
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
            "policy_version": "fixture-restoration.v1",
            "evidence_id": f"fixture-restoration:dvwa:{level}:{epoch_id}",
            "kind": "operator_attestation",
            "fixture_id": "dvwa-source-fee264766667580e5352",
            "protocol_version": "ranking-session-acceptance.v1",
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
