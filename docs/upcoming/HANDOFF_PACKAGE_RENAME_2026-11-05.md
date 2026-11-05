# Handoff: clarify engine and attack-tool package names

Date: 2026-11-05
Status: Upcoming; implementation and validation have not started.

## Objective

Replace the overlapping names `core/` and `foundation/` with names that explain
their responsibilities to someone learning the codebase.

Use the preferred pair discussed in chat as the proposed implementation target:

| Current package | Proposed package | Responsibility |
| --- | --- | --- |
| `core/` | `engine/` | Workflow graph, shared state, static AKG, routing, scoring, and checkpoints. |
| `foundation/` | `attack_tools/` | Reusable reconnaissance, payload, HTTP, session, and verification tools. |

`workflow/` was discussed as an alternative to `engine/`; this handoff uses
`engine/` because the existing package also owns scoring and persistence.
The current request authorizes this planning document, not the package rename.

## Scope and constraints

- Rename packages and update their consumers together, keeping existing file
  basenames unless a concrete compatibility issue requires otherwise.
- Preserve runtime behavior, graph topology and node names, method IDs, static
  AKG contents, payload policies and budgets, verifier decisions, score formulas,
  and experiment/artifact identity fields.
- Keep `agents/`, `evaluation/`, `llm/`, and `tesis/` in place. Preserve
  `tesis.tui` as the public facade and `tesis.tui_state.CONFIG_PATH` as the shared
  configuration-path owner.
- Keep this refactor separate from feature changes, scoring changes, and
  unrelated cleanup. Preserve pre-existing user edits and staged changes.
- Maintain all DVWA scope and containment requirements in repository `AGENTS.md`.
- Do not rewrite historical results or checkpoint files through a global text
  replacement.

## Implementation plan

1. Inspect the working tree and nested instructions before editing. Move this
   handoff to `docs/active/` when implementation starts and update its links.
2. Inventory references to both old packages: Python imports, lazy imports,
   dynamic import strings, monkeypatch/mock targets, resource lookups, filesystem
   paths, scripts, package/build configuration, and documentation. Use targeted
   searches; words such as “core” may occur in unrelated prose or dependencies.
3. Inspect packaging in `pyproject.toml` and the actual editable/distribution
   setup. Ensure both renamed packages remain discoverable without broadening
   package contents unintentionally. Do not hand-edit generated egg metadata.
4. Resolve the checkpoint compatibility questions below before choosing a clean
   break or compatibility adapters.
5. Move `core/` to `engine/` and `foundation/` to `attack_tools/`. Update imports
   and executable references throughout production code and tests, including
   imports inside functions. Keep graph registration names unchanged.
6. Update current navigation and architecture references in `AGENTS.md`,
   `README.md`, `guide.md`, `docs/reference/architecture.md`, and both
   `docs/reference/summary_en.md` and `docs/reference/summary_id.md`, plus other
   affected current documentation. Historical handoffs may retain old paths
   where those paths describe past work; distinguish those from current links.
7. Review the resulting diff for behavior changes and stale executable paths.
   Record compatibility decisions and requested validation evidence here.

Example import migration:

```python
# Before
from core.state import ExploitationState
from foundation.http_client import DVWASession

# After
from engine.state import ExploitationState
from attack_tools.http_client import DVWASession
```

## Checkpoint and artifact compatibility

Renaming a package does not by itself prove that old checkpoints will fail.
Determine whether stored values actually depend on the old Python module paths.

Inspect the current owners before making a compatibility claim:

- `core/checkpoint_store.py`: persistence, graph/build identity, and resume gates.
- `core/checkpoint_audit.py`: serializer behavior and checkpoint contract.
- `core/state.py`: checkpoint-safe state and any stored custom values.
- `core/graph_builder.py`: graph version, node registration, and checkpoint wiring.
- Existing checkpoint-recovery checks and representative historical artifacts,
  read without modifying the originals.

Check for stored qualified type names, serializer allowlists, module-path-based
identities, resource paths, and configuration/code fingerprints. Determine
whether existing resume gates would reject continuation even if deserialization
succeeds. Do not bypass those gates merely to accommodate the rename.

If compatibility is required and affected, prefer narrow adapters that re-export
the same canonical objects. Avoid loading the same source under two independent
module names, which can split class identity and module-level state. Document
which old imports or stored types are supported. If a clean break is appropriate,
record the limitation explicitly instead of claiming old checkpoints remain
resumable. Preserve historical JSON artifact readability and evidence references.

## Validation plan — requires requested verification scope

No tests, dry runs, E2E runs, or live requests are authorized by this handoff
alone. Follow `AGENTS.md` and the user's implementation-time verification scope.

When verification is requested, choose the smallest relevant existing non-E2E
checks for imports, graph assembly, state, checkpoint recovery, payload handling,
containment, CLI dispatch, and report/artifact compatibility. Inspect each check
before running it; filenames alone do not establish that a check is non-E2E.
Add a test only for a concrete uncovered behavior.

A requested local dry run can exercise configuration, imports, AKG construction,
graph compilation, and payload contracts without contacting DVWA or a provider:

```bash
.venv/bin/python -m tesis run --dry-run --config config.yaml
```

Keep generated verification evidence under `results/`. For this broad package
refactor, ask whether the user wants focused E2E coverage and wait for the answer
before running any E2E, including mocked/offline E2E. Live execution additionally
requires explicit target and provider scope. Do not launch a full experiment
matrix as rename validation.

## Acceptance criteria

- [ ] Canonical packages are `engine/` and `attack_tools/`, with working imports
      and package discovery.
- [ ] Executable references and current documentation use the new paths;
      remaining old references are explained compatibility or historical uses.
- [ ] Graph topology, method identities, containment, payload behavior, scoring,
      and artifact schemas retain their existing behavior.
- [ ] Checkpoint compatibility and resume-gate behavior are investigated and
      documented, including any intentional limitation.
- [ ] Requested acceptance checks pass, with commands, scope, results, and
      artifact paths recorded. Unrun requested checks remain incomplete.
- [ ] Unrelated user changes and historical artifacts remain intact.
- [ ] Move this handoff to `docs/completed/` and update links only after
      implementation and required acceptance checks pass.

## Current evidence

Planning only. Relevant package layout, imports, packaging configuration, and
checkpoint owners were inspected to prepare this document. No runtime files
were renamed or changed; no validation was run.
