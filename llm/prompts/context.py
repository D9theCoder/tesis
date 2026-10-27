"""Deterministic compact contexts with reusable fields before changing state."""

from __future__ import annotations

import json
from typing import Any


def context_json(stable: dict[str, Any], changing: dict[str, Any]) -> str:
    """Keep top-level field priority while canonicalizing nested dictionaries."""
    canonical = json.loads(json.dumps({**stable, **changing}, sort_keys=True))
    ordered = {key: canonical[key] for key in (*stable, *changing)}
    return json.dumps(ordered, separators=(",", ":"))
