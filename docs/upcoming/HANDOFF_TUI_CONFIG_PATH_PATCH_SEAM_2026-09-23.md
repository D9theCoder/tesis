# Mini handoff — TUI config-path patch seam (2026-09-23)

**Status:** upcoming; proposed, not implemented.

## Problem

After the TUI split, `tesis.tui_state.CONFIG_PATH` is the single source used by
forms, drawers, and the mission screen. `tesis.tui.CONFIG_PATH` remains an
import-compatible re-export, but assigning to that facade attribute does not
change the owner module's value. Repository tests already patch the owner.

## Goal

Close the compatibility ambiguity with the smallest maintainable change. Keep
`tui_state.CONFIG_PATH` as the canonical test patch point and retain the
facade export for reads. Do not add module-class forwarding or duplicate path
state for an unverified downstream monkeypatch use case.

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
