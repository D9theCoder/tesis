# Mini handoff — TUI config-path patch seam (2026-09-23)

**Status:** completed; implementation and acceptance checks passed.

## Problem

After the TUI split, `tesis.tui_state.CONFIG_PATH` is the single source used by
forms, drawers, and the mission screen. `tesis.tui.CONFIG_PATH` remains an
import-compatible re-export, but assigning to that facade attribute does not
change the owner module's value. Repository tests already patch the owner.

## Goal

Close the compatibility ambiguity with the smallest maintainable change. Keep
`tui_state.CONFIG_PATH` as the canonical test patch point and retain the
facade export for import compatibility — it is a snapshot binding taken at
import, not a synchronized view of the owner. Do not add module-class
forwarding or duplicate path state for an unverified downstream monkeypatch
use case.

## Work and acceptance

- Audit TUI config-path reads and tests; readers use `tui_state.CONFIG_PATH`,
  and tests that redirect config files patch that owner.
- Add or keep one focused regression proving a patched owner path is used by a
  config read and write; avoid duplicating coverage already present in
  `tests/test_tui.py` and `tests/test_tui_performance.py`.
- Document that assigning `tesis.tui.CONFIG_PATH` is not a supported override.
  If a real downstream caller requires that behavior, stop and design an
  explicit config-path API in a separate change.
- Run focused TUI tests and the full suite; preserve the acyclic imports,
  Textual-free `tui_state`, and existing public import behavior.

Related implementation record: [completed TUI module split](../completed/HANDOFF_TUI_MODULE_SPLIT_2026-09-22.md).

## Implementation record

Owner patch point confirmed as-is; no production control flow changed.

- `tesis/tui_state.py`: comment on `CONFIG_PATH` marks it the canonical owner
  and states the facade re-export is read-compatible only.
- `tesis/tui.py`: facade docstring states re-exports are import-compatible
  snapshot bindings taken once at import (not synchronized views), that after
  an owner rebind a facade read still returns the original default, and that
  facade `CONFIG_PATH` assignment is unsupported (no `__getattr__`/
  `__setattr__`/module forwarding added).
- `docs/reference/architecture.md` §"TUI module boundaries": durable statement
  of the snapshot-binding facade contract, the `tui_state.CONFIG_PATH` owner
  and use-time reads, and the explicit `config_path` argument of
  `tesis.config_loader` as a direct-loader parameter only — not a TUI-wide
  override, since TUI readers pass `tui_state.CONFIG_PATH` themselves.
- `tests/test_tui.py::test_settings_two_save_literal_secret_warning`: extended
  rather than duplicated. Its fixture config now carries a unique
  `owner_patch_marker` value and the test asserts the editor loaded that value
  on mount before it edits and saves. The same test already patched
  `tui_state.CONFIG_PATH` and proved the write (`literal-secret-value` reaches
  the patched file on the acknowledged second save), so one test now proves
  owner-path read + write.

Audit result — readers of the config path (all `tui_state.CONFIG_PATH`, read at
use time): `tui_forms.py` (`LaunchDrawer._raw_config`, `_resolved_config`,
`SettingsDrawer.on_mount`, `_render_sections`, `save_settings`),
`tui_drawers.py` (`ResultsDrawer._output_dir`, `DoctorDrawer._config`,
`PlanDrawer` config lookup), `tui_mission.py`
(`MissionControlScreen._resolved_config`). `REPOSITORY_ROOT` also reads from
`tui_state`. No module holds a second copy of the path, and no test outside
`tests/test_tui.py`/`tests/test_tui_performance.py` redirects it.

## Verification

- `.venv/bin/pytest -q tests/test_tui.py tests/test_tui_performance.py` — 128 passed.
- `.venv/bin/pytest -q` — 1,559 passed (no baseline test removed; the extended
  settings test replaces no prior assertion).
- `.venv/bin/python -m tesis run --dry-run --config config.yaml` — 4 payload
  coordinates validated; AKG and runtime graph compiled.
- Import/cycle: `import tesis.tui, tesis.tui_state, tesis.tui_security,
  tesis.tui_commands, tesis.tui_forms, tesis.tui_drawers, tesis.tui_mission`
  clean; AST top-level TUI import graph still acyclic; `tui.CONFIG_PATH is
  tui_state.CONFIG_PATH`; `tui_state`/`tui_security` still import with Textual
  blocked.
- Falsification check (throwaway): assigning `tui.CONFIG_PATH = <tmp>` leaves
  `tui_state.CONFIG_PATH` untouched and the settings editor still loads the
  owner file — the documented behavior, not a silent near-miss.
- Snapshot semantics (throwaway, Post-Review): with an unpatched import
  `tui.CONFIG_PATH is tui_state.CONFIG_PATH`; after
  `tui_state.CONFIG_PATH = <tmp>` the readers followed the owner while
  `tui.CONFIG_PATH` still returned the original default; assigning
  `tui.CONFIG_PATH` changed neither the owner nor any reader. Matches the
  wording now in `architecture.md` and the facade docstring.
