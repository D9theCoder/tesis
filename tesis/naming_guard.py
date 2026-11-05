"""Check project-owned naming locations, not payloads or historical data.

Run ``python -m tesis.naming_guard`` before a prospective freeze. The default
scope is maintained Python code/tests and current configuration templates, not
saved results, frozen research inputs, dependency trees or historical handoffs.
No allowlist of existing violations is used: the coordinated cutover must pass.
"""
from __future__ import annotations

import argparse
import ast
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
import re

import yaml


VERSION_SUFFIX = re.compile(
    r"(?:^|[._\-\s])v[._]?(?:[0-9]+|[xn])(?:[._][0-9]+)*(?=$|[._\-\s])|V[0-9]+$",
    re.IGNORECASE,
)
NUMERIC_VERSION = re.compile(r"^[0-9]+(?:\.[0-9]+)+$")
SOURCE_ROOTS = ("agents", "core", "evaluation", "foundation", "llm", "tesis", "tests")
CURRENT_CONFIGS = ("config.yaml", "config/research/chapter3_study.json")
EXTERNAL_VERSION_FIELDS = frozenset({
    "api_version", "http_version", "tls_version", "python_version",
    "package_version", "model_version",
})
LABEL_FIELDS = frozenset({
    "version", "schema", "schema_version", "artifact_type", "kind", "format", "reference",
    "prompt_id", "contract_id", "catalog_id", "definition_version",
    "rubric_version", "metrics_epoch", "score_epoch", "provisional_label",
    "runtime_provisional_label", "legacy_label",
})


def _label_field(name: str) -> bool:
    normalized = name.lstrip("_").lower()
    return normalized not in EXTERNAL_VERSION_FIELDS and (
        normalized in LABEL_FIELDS or normalized.endswith((
            "_version", "_versions", "_schema", "_prompt_id", "_policy_id", "_contract_id",
        ))
    )


def _versioned(value: str, *, label: bool = False) -> bool:
    return bool(VERSION_SUFFIX.search(value) or (label and NUMERIC_VERSION.fullmatch(value)))


@dataclass(frozen=True)
class Finding:
    """One project-owned name requiring a canonical descriptive replacement."""

    path: str
    line: int
    location: str
    value: str


class _Names(ast.NodeVisitor):
    def __init__(self, path: Path) -> None:
        self.path = path
        self.findings: list[Finding] = []

    def check(self, value: str, node: ast.AST, location: str, *, label: bool = False) -> None:
        if _versioned(value, label=label):
            self.findings.append(Finding(str(self.path), getattr(node, "lineno", 1), location, value))

    def label(self, value: ast.AST, name: str) -> None:
        if _label_field(name):
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                self.check(value.value, value, "contract label", label=True)
            elif isinstance(value, ast.JoinedStr):
                pattern = "".join(part.value if isinstance(part, ast.Constant)
                                  and isinstance(part.value, str) else "x" for part in value.values)
                self.check(pattern, value, "dynamic contract label", label=True)
            elif isinstance(value, (ast.List, ast.Tuple, ast.Set)):
                for element in value.elts:
                    self.label(element, name)

    def generic_visit(self, node: ast.AST) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Name, ast.arg)):
            name = getattr(node, "name", None) or getattr(node, "id", None) or getattr(node, "arg", None)
            self.check(name, node, "symbol")
        elif isinstance(node, ast.Attribute):
            self.check(node.attr, node, "attribute")
        elif isinstance(node, ast.alias):
            self.check(node.name, node, "import")
            if node.asname:
                self.check(node.asname, node, "import alias")
        elif isinstance(node, ast.ImportFrom) and node.module:
            self.check(node.module, node, "import module")
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, (ast.Name, ast.Attribute)):
                    self.label(node.value, target.id if isinstance(target, ast.Name) else target.attr)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, (ast.Name, ast.Attribute)) and node.value:
            self.label(node.value, node.target.id if isinstance(node.target, ast.Name) else node.target.attr)
        elif isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                if isinstance(key, ast.Constant) and isinstance(key.value, str):
                    self.label(value, key.value)
        elif isinstance(node, ast.keyword) and node.arg:
            self.label(node.value, node.arg)
        elif isinstance(node, ast.arguments):
            positional = [*node.posonlyargs, *node.args]
            for argument, value in zip(positional[-len(node.defaults):], node.defaults):
                self.label(value, argument.arg)
            for argument, value in zip(node.kwonlyargs, node.kw_defaults):
                if value is not None:
                    self.label(value, argument.arg)
        elif isinstance(node, ast.Call):
            name = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", "")
            if name in {"get", "setdefault"} and len(node.args) >= 2:
                key = node.args[0]
                if isinstance(key, ast.Constant) and isinstance(key.value, str):
                    self.label(node.args[1], key.value)
            if name in {"add_argument", "add_parser"}:
                for argument in node.args:
                    if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
                        self.check(argument.value, argument, "CLI name")
        super().generic_visit(node)


def _config_labels(document: object, path: Path) -> Iterable[Finding]:
    if isinstance(document, dict):
        for name, value in document.items():
            if isinstance(name, str) and _label_field(name) and isinstance(value, str) and _versioned(value, label=True):
                yield Finding(str(path), 1, f"configuration label {name}", value)
            yield from _config_labels(value, path)
    elif isinstance(document, list):
        for value in document:
            yield from _config_labels(value, path)


def inspect_file(path: Path) -> list[Finding]:
    """Inspect names in one source/config file without treating all strings as names."""
    findings = [Finding(str(path), 1, "file name", path.name)] if _versioned(path.stem) else []
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".py":
        visitor = _Names(path)
        visitor.visit(ast.parse(text, filename=str(path)))
        findings.extend(visitor.findings)
    elif path.suffix in {".json", ".yaml", ".yml"}:
        findings.extend(_config_labels(yaml.safe_load(text), path))
    return sorted(set(findings), key=lambda row: (row.line, row.location, row.value))


def check_repository(root: Path) -> list[Finding]:
    """Check maintained source trees and current templates; never scan saved results."""
    paths = {path for name in SOURCE_ROOTS for path in (root / name).rglob("*.py")
             if "__pycache__" not in path.parts}
    paths.update(root / name for name in CURRENT_CONFIGS if (root / name).is_file())
    return [finding for path in sorted(paths) for finding in inspect_file(path)]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    findings = check_repository(args.root)
    for finding in findings:
        print(f"{finding.path}:{finding.line}: {finding.location}: {finding.value}")
    print(f"{len(findings)} project-owned naming violations")
    return int(bool(findings))


if __name__ == "__main__":
    raise SystemExit(main())
