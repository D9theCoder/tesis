"""Contained, original-byte catalog for transport-neutral observer exports."""
from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
import json
from pathlib import Path
import re
from typing import Any, Mapping


@dataclass
class CatalogEntry:
    path: Path
    source: dict[str, Any]
    record: dict[str, Any]
    parent_id: str | None = None
    coordinate_index: int | None = None
    locations: list[dict[str, Any]] = field(default_factory=list)
    detail: dict[str, Any] = field(default_factory=dict)
    diagnostics: list[dict[str, Any]] = field(default_factory=list)
    ambiguous: bool = False
    # Keep the enclosing byte/pointer binding even when its ID is absent or shared.
    parent_source: dict[str, Any] | None = None


class ArtifactCatalog:
    """Read only configured roots, retaining hashes and discovery diagnostics.

    Root insertion order is the explicitly selected review epoch order. A file
    root contains only that file; it does not grant access to its siblings.
    """

    def __init__(self, source_roots: Mapping[str, str | Path], review_roots: Mapping[str, str | Path]):
        if not source_roots:
            raise ValueError("At least one source root is required")
        identifiers = [*source_roots, *review_roots]
        if len(set(identifiers)) != len(identifiers) or any(
            not re.fullmatch(r"[A-Za-z0-9_.-]+", identifier) for identifier in identifiers
        ):
            raise ValueError("Root identifiers must be unique safe names")
        self.source_roots = {key: Path(value).resolve() for key, value in source_roots.items()}
        self.review_roots = {key: Path(value).resolve() for key, value in review_roots.items()}
        self.roots = {**self.source_roots, **self.review_roots}
        self.inputs: dict[Path, tuple[str, bytes, dict[str, Any]]] = {}
        self.runs: list[CatalogEntry] = []
        self.matrices: list[CatalogEntry] = []
        self.reviews: list[tuple[int, Path, dict[str, Any]]] = []
        self.diagnostics: list[dict[str, Any]] = []

    def location(self, path: str | Path, *, roots=None) -> dict[str, Any]:
        resolved = Path(path).resolve()
        for root_id, root in (roots if roots is not None else self.roots).items():
            if root.is_file():
                if resolved == root:
                    return {"root_id": root_id, "path": root.name}
            elif resolved.is_relative_to(root):
                return {"root_id": root_id, "path": resolved.relative_to(root).as_posix()}
        raise ValueError("Reference is outside the configured roots")

    def resolve(self, reference: str | Path, *, owner: Path) -> Path:
        path = Path(reference)
        resolved = (path if path.is_absolute() else owner.parent / path).resolve()
        self.location(resolved)
        return resolved

    def binding(self, path: str | Path) -> dict[str, Any]:
        path = Path(path).resolve()
        self.raw(path)
        return dict(self.inputs[path][2])

    def raw(self, path: str | Path) -> bytes:
        path = Path(path).resolve()
        location = self.location(path)
        if path not in self.inputs:
            raw = path.read_bytes()
            digest = sha256(raw).hexdigest()
            self.inputs[path] = (digest, raw, {**location, "sha256": digest})
        return self.inputs[path][1]

    def read(self, path: str | Path) -> Any:
        return json.loads(self.raw(path))

    def verify_unchanged(self) -> None:
        for path, (digest, _, _) in self.inputs.items():
            self.location(path)
            if sha256(path.read_bytes()).hexdigest() != digest:
                raise ValueError("An input changed during export")

    def diagnostic(self, code: str, path: Path, **detail) -> dict[str, Any]:
        try:
            location = self.location(path)
        except ValueError:
            location = {"path": path.name}
        item = {"code": code, "location": location, **detail}
        self.diagnostics.append(item)
        return item

    def paths(self, roots):
        for root_id, root in roots.items():
            if not root.exists():
                self.diagnostic("missing_root", root, root_id=root_id)
                continue
            candidates = [root] if root.is_file() else sorted(root.rglob("*.json"))
            for path in candidates:
                # Never follow a symlink outside the particular declared root.
                try:
                    self.location(path, roots={root_id: root})
                except ValueError:
                    self.diagnostic("scope_violation", path, root_id=root_id)
                    continue
                yield root_id, path

    def _entry(self, path, record, pointer="", parent_id=None, index=None, parent_source=None):
        source = {**self.binding(path), "pointer": pointer,
                  "schema_version": record.get("schema_version"),
                  "legacy_status": record.get("status"),
                  "legacy_task_result": record.get("task_result", (record.get("final_state") or {}).get("task_result"))}
        entry = CatalogEntry(path.resolve(), source, record, parent_id, index)
        entry.parent_source = parent_source
        entry.locations.append(source)
        if not record.get("execution_id"):
            entry.diagnostics.append(self.diagnostic("missing_execution_id", path, pointer=pointer))
        return entry

    @staticmethod
    def _family(record):
        if not isinstance(record, dict):
            return None
        kind, schema = record.get("artifact_type"), record.get("schema_version")
        if kind == "experiment_manifest":
            return "manifest"
        if kind in {"thesis_score_receipt", "thesis_review_status"}:
            return "review"
        if schema in {"stage8.v1"} or kind == "matrix_aggregate":
            return "matrix" if isinstance(record.get("runs"), list) else None
        if schema == "tui.v1" or (schema in {None, "stage6.v1"} and (
            isinstance(record.get("final_state"), dict) or (
                (record.get("execution_id") or record.get("run_id"))
                and record.get("status") in {"success", "error", "cancelled", "skipped", "completed", "failed", "interrupted"}
                and (isinstance(record.get("config"), dict) or isinstance(record.get("report"), dict))
            )
        )):
            return "run"
        return None

    @staticmethod
    def valid_matrix_child(record):
        return isinstance(record, dict) and all(
            key not in record or isinstance(record[key], dict) for key in ("config", "final_state", "timing")
        )

    def scan(self):
        self.runs, self.matrices, self.reviews = [], [], []
        manifests, descriptors = [], {}
        seen_paths = set()
        for _, path in self.paths(self.source_roots):
            if path.resolve() in seen_paths:
                continue
            seen_paths.add(path.resolve())
            try:
                record = self.read(path)
            except (OSError, ValueError, UnicodeError):
                self.diagnostic("unreadable_json", path)
                continue
            family = self._family(record)
            if family in {"run", "matrix"} and any(
                key in record and not isinstance(record[key], dict) for key in ("config", "final_state", "timing")
            ):
                self.diagnostic("invalid_artifact_schema", path)
                continue
            if path.name.endswith((".rich.json", ".failure.json", ".review-history.json", ".evaluator.json", ".resume.json")):
                continue
            if family == "manifest":
                manifests.append((path, record))
            elif family == "run":
                self.runs.append(self._entry(path, record))
            elif family == "matrix":
                parent = self._entry(path, record)
                self.matrices.append(parent)
                for index, child in enumerate(record["runs"]):
                    if self.valid_matrix_child(child):
                        self.runs.append(self._entry(path, child, f"/runs/{index}", record.get("execution_id"), index,
                                                     parent.source))
                    else:
                        self.diagnostic("invalid_matrix_child", path, coordinate_index=index)
            elif isinstance(record, dict) and record.get("schema_version") == "runtime-descriptor.v1":
                descriptors[path.parent.resolve()] = (path, record)
            elif (isinstance(record, dict) and (record.get("execution_id") or record.get("schema_version"))
                  and family != "review" and record.get("schema_version") != "akg-snapshot.v1"):
                self.diagnostic("unsupported_schema", path, schema_version=record.get("schema_version"))

        # Merge a standalone child with its exact embedded representation. Any
        # other duplicate identity remains ambiguous, including same-byte copies.
        grouped = {}
        for entry in self.runs:
            eid = entry.record.get("execution_id")
            grouped.setdefault(eid or (str(entry.path), entry.source["pointer"]), []).append(entry)
        merged = []
        for entries in grouped.values():
            standalone = [e for e in entries if not e.source["pointer"]]
            embedded = [e for e in entries if e.source["pointer"]]
            if len(standalone) == 1 and len(embedded) == 1 and standalone[0].record == embedded[0].record:
                chosen, member = standalone[0], embedded[0]
                chosen.parent_id, chosen.coordinate_index = member.parent_id, member.coordinate_index
                chosen.parent_source = member.parent_source
                chosen.locations.extend(member.locations)
                merged.append(chosen)
            elif len(entries) > 1:
                for entry in entries:
                    entry.ambiguous = True
                    entry.diagnostics.append(self.diagnostic("ambiguous_execution_id", entry.path,
                                                              execution_id=entry.record.get("execution_id")))
                merged.extend(entries)
            else:
                merged.extend(entries)
        self.runs = merged
        parent_ids = {}
        for entry in self.matrices:
            if entry.record.get("execution_id"):
                parent_ids.setdefault(entry.record["execution_id"], []).append(entry)
        for entries in parent_ids.values():
            if len(entries) > 1:
                for entry in entries:
                    entry.ambiguous = True
                    entry.diagnostics.append(self.diagnostic("ambiguous_matrix_identity", entry.path))
        self._apply_manifests(manifests)
        for entry in [*self.runs, *self.matrices]:
            descriptor = descriptors.get(entry.path.parent)
            if descriptor and descriptor[1].get("execution_id") == entry.record.get("execution_id"):
                entry.detail["observer"] = {**self.binding(descriptor[0]),
                    **{key: descriptor[1].get(key) for key in ("status", "heartbeat_at", "updated_at")}}
        for entry in [*self.runs, *self.matrices]:
            self._details(entry)
        for order, (_, root) in enumerate(self.review_roots.items()):
            for _, path in self.paths({list(self.review_roots)[order]: root}):
                if root.is_dir() and "history" in path.relative_to(root).parts:
                    continue
                try:
                    record = self.read(path)
                except (OSError, ValueError, UnicodeError):
                    self.diagnostic("unreadable_review", path)
                    continue
                if self._family(record) == "review":
                    self.reviews.append((order, path.resolve(), record))
        return self

    def _apply_manifests(self, manifests):
        for path, manifest in manifests:
            if not isinstance(manifest.get("runs", []), list) or not isinstance(manifest.get("aggregate") or {}, dict):
                self.diagnostic("invalid_manifest_schema", path)
                continue
            parent = (manifest.get("aggregate") or {}).get("execution_id")
            aggregate_path = (manifest.get("aggregate") or {}).get("artifact")
            parent_entry = None
            if aggregate_path:
                try:
                    declared = self.resolve(aggregate_path, owner=path)
                    for entry in self.matrices:
                        if entry.path == declared and entry.record.get("execution_id") == parent:
                            parent_entry = entry
                            entry.detail["manifest"] = self.binding(path)
                except (ValueError, TypeError):
                    self.diagnostic("invalid_manifest_path", path)
            for row in manifest.get("runs", []):
                if not isinstance(row, dict) or not row.get("artifact"):
                    continue
                try:
                    primary = self.resolve(row["artifact"], owner=path)
                except (ValueError, TypeError):
                    self.diagnostic("invalid_manifest_path", path)
                    continue
                entries = [e for e in self.runs if e.path == primary and not e.source["pointer"]
                           and e.record.get("execution_id") == row.get("execution_id")]
                if len(entries) != 1:
                    self.diagnostic("missing_or_ambiguous_primary", path, execution_id=row.get("execution_id"))
                    continue
                entry = entries[0]
                if (
                    (entry.parent_id and parent and entry.parent_id != parent)
                    or (entry.parent_source is not None and parent_entry is not None
                        and entry.parent_source != parent_entry.source)
                ):
                    entry.ambiguous = True
                    entry.diagnostics.append(self.diagnostic("ambiguous_parent", path))
                    continue
                entry.parent_id = parent or row.get("matrix_execution_id") or entry.parent_id
                if parent_entry is not None:
                    entry.parent_source = parent_entry.source
                index = row.get("index")
                if type(index) is int and index >= 1:
                    entry.coordinate_index = index - 1
                entry.detail["manifest"] = self.binding(path)
                details = row.get("detail") or manifest.get("detail") or {}
                if not isinstance(details, dict):
                    self.diagnostic("invalid_manifest_schema", path)
                    continue
                shared_owner_id = (parent_entry.record.get("execution_id") if parent_entry is not None
                                   else entry.parent_id or entry.record.get("execution_id"))
                for key in ("journal", "snapshot", "trace", "rich", "failure", "runtime"):
                    if details.get(key):
                        owner_id = (entry.record.get("execution_id") if key in {"trace", "rich", "failure"}
                                    else shared_owner_id)
                        self._detail_ref(entry, key, details[key], path, owner_id)

    def _detail_ref(self, entry, key, reference, owner, owner_id):
        try:
            path = self.resolve(reference, owner=owner)
            entry.detail[key] = {**self.binding(path), "owner_execution_id": owner_id}
        except (OSError, ValueError, TypeError):
            entry.diagnostics.append(self.diagnostic("unavailable_detail", owner, detail_kind=key))

    def _details(self, entry):
        # Supported adjacent sidecars and declared parent ownership only.
        own = entry.record.get("execution_id")
        for key, suffix in (("trace", ".events.jsonl"), ("rich", ".rich.json"), ("failure", ".failure.json")):
            path = entry.path.with_name(f"{own}{suffix}") if own else None
            if key not in entry.detail and path and path.is_file():
                self._detail_ref(entry, key, path, entry.path, own)
        parents = [e for e in self.matrices if e.source == entry.parent_source]
        owner_path = parents[0].path if len(parents) == 1 else entry.path
        owner_entry = parents[0] if len(parents) == 1 else entry
        invocation_known = bool(entry.detail.get("manifest") or owner_entry.detail.get("manifest")
                                or owner_entry.detail.get("observer"))
        for key, name in (("journal", "runtime.events.jsonl"), ("snapshot", "akg.snapshot.json")):
            path = owner_path.parent / name
            if key not in entry.detail and path.is_file() and invocation_known:
                owner_id = owner_entry.record.get("execution_id") if parents else entry.parent_id or own
                self._detail_ref(entry, key, path, owner_path, owner_id)
                if key in entry.detail:
                    entry.detail[key]["fallback_source"] = "supported_adjacent_layout"
            if key not in entry.detail:
                entry.detail[key] = None
                entry.diagnostics.append(self.diagnostic(f"absent_{key}", entry.path))
