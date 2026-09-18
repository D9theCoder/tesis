# Handoff: terminal-native TUI revamp (2026-09-19)

Status: design and repository review complete; implementation not started. This
handoff translates the visual/interaction research into an implementation plan
for the TESIS Textual UI. It is intentionally separate from
`HANDOFF_AI_HARNESS_ARCHITECTURE_TUI_2026-09-19.md`: this document owns the
presentation and operator workflow, while that document owns durable execution,
model-call, prompt, state, and evaluation architecture.

## Objective

Make TESIS feel like a modern terminal-native AI harness in the same broad class
as Codex CLI, Claude Code, OpenCode, and Hermes without copying their branding or
turning TESIS into a general-purpose chat agent.

The desired experience is:

- transcript/activity-first rather than menu/form-first;
- keyboard-first with discoverable slash commands and a command palette;
- dense, restrained, and terminal-native rather than a desktop form rendered in
  terminal widgets;
- progressively disclosed, with summaries by default and details on demand;
- responsive across narrow and wide terminals;
- honest about run state, provider activity, failures, cost, and unavailable
  information;
- compatible with the existing runner, event, artifact, containment, and
  experiment contracts.

## Compatibility disclaimer

Treat this as a staged UI migration, not a single rewrite. The TUI currently
contains working setup, runtime, cancellation, validation, results, export, and
configuration behavior. Visual replacement must not silently change the runtime
semantics behind those controls.

- Preserve current runner arguments, configuration precedence, validation,
  cancellation, event redaction, artifact paths, and result interpretation.
- Introduce a presentation/view-model layer over existing events before changing
  the event schema.
- Keep the existing screens reachable behind a temporary `legacy_ui` flag until
  the replacement reaches behavioral parity.
- Do not combine this revamp with checkpoint, retry, prompt, scoring, or graph
  migrations from the architecture handoff.
- Add the new shell before deleting old screens. Remove legacy paths only after
  keyboard, mouse, narrow-terminal, cancellation, and artifact flows are covered.
- Any change to cost or unavailable-value display must follow the versioned
  artifact semantics described in the architecture handoff.
- Final acceptance requires the full offline suite and TUI visual/interaction
  coverage. A real authorized DVWA/provider matrix remains required before the
  redesigned runtime view is accepted for main experiments.

## Current diagnosis

The current application behaves like a desktop administration panel translated
into Textual widgets:

- `MainMenuScreen` opens with a centered, bordered menu card.
- `RunSetupScreen` and `SettingsScreen` are long label/input/select/checkbox
  forms with three-row controls and explicit buttons.
- `RuntimeDashboardScreen` permanently divides the terminal into task, log, and
  telemetry/failure boxes.
- `Header` and `Footer` repeat across screens, including a clock that is not
  important to experiment operation.
- The central runtime surface is a generic `RichLog`, so domain events lack a
  clear semantic hierarchy.
- Configuration and result operations require screen navigation rather than a
  shared command surface.
- The hardcoded cyan/navy palette, uppercase headings, and rounded border on
  almost every region give all content equal visual weight.
- Compact mode stacks the same panels instead of reducing information to the
  highest-priority content.

Primary source areas:

- navigation and screens: `tesis/tui.py` (`MainMenuScreen`, `BaseTesisScreen`);
- setup and settings: `RunSetupScreen`, `SettingsScreen`;
- runtime presentation: `RuntimeDashboardScreen`;
- results and detail: `RecentResultsScreen`, `ResultDetailScreen`;
- validation: `ValidationScreen`;
- hardcoded styling: `TesisApp.CSS`;
- interaction coverage: `tests/test_tui.py`.

## Target interaction model

Open into one persistent run console rather than the current main menu. It should
contain four conceptual surfaces:

1. A compact context header.
2. A semantic run transcript/activity lane.
3. A bottom command composer.
4. A width-aware status line.

Wide terminals may add a fifth surface: an optional coordinate sidebar. Narrow
terminals must keep the transcript and composer, with secondary information
available through overlays.

Conceptual layout:

```text
 TESIS  matrix-2026-09-19-01                         RUNNING  7/36

 ✓ recon                                      0.8s
 ✓ orchestrator       openai/gpt-5.6-luna · 1,204 tok
 ✓ payload candidates 5 generated · 5 valid
 ● sqli_union         attempt 2 · 3.2s
   ↳ GET /dvwa/vulnerabilities/sqli/?id=...
   ↳ verifier: waiting for response
 ○ chaining
 ○ scoring

 ──────────────────────────────────────────────────────────────
 > Type / for commands or Ctrl+P for actions
 ──────────────────────────────────────────────────────────────
 manual  luna/high  hybrid  low  7/36  03:18  12.4k tok
```

This is not a conversational façade. The composer is primarily a deterministic
operator command surface. Natural-language model chat is out of scope unless a
future research requirement explicitly adds it.

## Information architecture

### Persistent shell

Create a `RunConsoleScreen` (name is provisional) as the default application
screen. It owns:

- `ContextHeader`: run name/ID, terminal status, and coordinate progress;
- `ActivityTranscript`: semantic, bounded, scrollable runtime entries;
- `CommandComposer`: input, history, slash completion, and contextual hints;
- `StatusLine`: compact effective configuration and live run summary;
- optional `CoordinateSidebar` on wide terminals;
- an overlay host for pickers, previews, details, help, failures, and settings.

Keep runtime execution outside view widgets. The shell consumes view-model
updates and emits typed operator intents.

### Commands

Initial command vocabulary:

```text
/run                 configure and start a single experiment
/matrix              configure and start a matrix
/plan                preview the fully resolved execution plan
/cancel              request graceful cancellation
/coordinates         inspect/filter matrix coordinates
/failure             inspect the active or most recent failure
/details             toggle expanded runtime details
/doctor              run offline Doctor; live mode requires explicit selection
/results             browse completed runs
/resume              reserved for durable resume when architecture support lands
/retry               reserved until safe targeted retry exists
/model               choose effective provider/model settings
/settings            edit validated configuration
/export              export the selected run/artifact
/help                commands and keybindings
/quit                exit safely
```

Commands that depend on future architecture (`/resume`, `/retry`) must remain
disabled with an explanatory message until the underlying safety contracts are
implemented. Do not implement UI controls that imply unsupported behavior.

### Command palette

Use Textual's command-palette provider API for `Ctrl+P`. Commands should be
context-sensitive and searchable by title and synonyms. Examples:

- Start matrix experiment
- Preview resolved plan
- Open current failure
- Toggle verbose details
- Filter failed coordinates
- Run Doctor offline
- Export current artifact
- Change theme
- Open legacy interface (migration only)

Slash commands and palette actions must dispatch the same typed intents so their
behavior cannot drift.

### Overlays instead of navigation screens

Convert existing screens incrementally into modal overlays or drawers:

- run/matrix setup -> guided setup overlay;
- settings -> searchable settings overlay;
- results -> run picker, then result detail overlay/drawer;
- validation -> Doctor/action picker plus structured result overlay;
- failure content -> structured failure inspector;
- coordinate table -> responsive sidebar or full overlay;
- help/keybindings -> searchable help overlay.

During migration, overlay actions may delegate to existing screen controllers.

## Runtime transcript design

Do not render raw runtime events directly. Introduce a pure adapter such as
`RuntimeEventPresenter`:

```text
RunEvent + current coordinate/run summary -> zero or more ActivityEntry values
```

An `ActivityEntry` should contain stable presentation data, for example:

```text
entry_id
timestamp
coordinate_id
node
kind
status
summary
detail_rows
duration_ms
token_usage
failure_class
expandable
default_expanded
```

It must contain no secrets and should use already-redacted runtime/artifact data.
Rendering must never become the new source of truth for experiment state.

Recommended semantic entry types:

- run/coordinate queued, started, completed, cancelled, or failed;
- graph node started/completed;
- model call started/completed/failed;
- payload batch generated/validated/ranked;
- method attempt and bounded HTTP evidence;
- verifier decision;
- chain transition;
- scoring result;
- containment, guardrail, invalid-JSON, and fallback event;
- structured failure/remediation;
- artifact written/exported.

Use a small consistent state vocabulary:

```text
○ queued
● active
✓ completed
! warning
× failed
↳ child detail
▸ collapsed
▾ expanded
```

Default transcript rows should answer what happened and whether action is
required. Provider payloads, request IDs, hashes, raw evidence, and verbose
telemetry belong in expandable detail or a dedicated inspector.

### Progressive disclosure example

Collapsed:

```text
✓ Orchestrator selected sqli_union                         1.8s
```

Expanded:

```text
▾ Orchestrator selected sqli_union                         1.8s
  provider       openai
  model          gpt-5.6-luna
  reasoning      high
  viable         sqli_union, sqli_error
  reason         METHOD_PRECONDITIONS_SATISFIED
  prompt         sha256:...
  call           exec-...:orchestrator:1
```

Never display private chain-of-thought. Show only explicit decision summaries,
reason codes, tool/runtime activity, and artifact evidence intended for audit.

## Setup and plan preview

Replace the long setup form with a compact guided overlay. The default view
should show essential choices and a live resolved summary:

```text
Run matrix

Condition       akg_guided_hybrid
Providers       openai, openai_compatible
Surfaces        all 3 selected
Levels          low, medium, high
Methods         all applicable
Repeats         1

36 coordinates · expected model calls: 72-144

▸ Advanced model settings
▸ Budgets and stopping policy
▸ Output and diagnostics

[Enter] Start    [P] Preview plan    [Esc] Cancel
```

Before start, `/plan` must display the resolved values rather than raw inputs:

- every coordinate and repeat;
- effective provider/model/profile per role;
- reasoning effort and structured-output mode;
- budgets, concurrency, timeout, and current retry configuration;
- target scope and containment summary;
- output directory and config fingerprint;
- unsupported or ambiguous combinations;
- estimated calls labeled as estimates, never guarantees.

Starting remains disabled until validation passes. Preserve the existing
method-level evaluation and target-method behavior.

## Coordinate and failure views

### Coordinate sidebar/table

At wide widths, show an optional sidebar with one compact row per coordinate:

```text
 07  sqli / low      active   orchestrator
 08  sqli / medium   queued
 09  access / low    failed   timeout
```

Support filtering by status, provider, surface, level, mode, and failure class.
At medium/narrow widths, `/coordinates` opens the table as an overlay.

### Failure inspector

Render the canonical failure envelope as labeled fields:

- failure class and remediation first;
- provider, model, profile, and role;
- run/coordinate/call IDs;
- sanitized endpoint;
- attempt, retry, timeout, and elapsed information;
- HTTP status and provider request ID when present;
- parse status and bounded provider message;
- links/actions to copy redacted JSON and jump to transcript/artifact evidence.

The one-line failure summary remains useful in the transcript. Do not dump the
entire failure object into the activity lane.

## Visual system

### Principles

- Use whitespace, indentation, and dim separators before borders.
- Reserve borders for the active composer, modal overlays, and rare focus states.
- Remove the permanent clock and decorative global header.
- Avoid large centered branding after the first frame.
- Avoid uppercase headings everywhere; use sentence case for normal hierarchy.
- Keep single-line controls one row high where practical.
- Use one restrained accent color and semantic success/warning/error colors.
- Ordinary content uses the terminal/theme foreground, not the accent.
- Avoid animation except a subtle active-state spinner/progress indicator.
- Preserve native terminal selection and copying behavior where Textual permits.

### Theme tokens

Move the inline `TesisApp.CSS` to a dedicated TCSS file and replace literal
colors with Textual theme variables plus a small TESIS semantic layer:

```text
$tesis-accent
$tesis-muted
$tesis-surface
$tesis-selection
$tesis-running
$tesis-success
$tesis-warning
$tesis-error
$tesis-border-subtle
```

Support at minimum:

- terminal-derived or restrained dark default;
- light theme;
- monochrome/high-contrast-friendly mode.

Do not make theme selection a dependency for functional use. Color may reinforce
state but must never be the only state indicator.

### Density

Default to compact rows and bounded details. Optional density settings may be
added later, but the initial redesign should have one intentional, consistent
density rather than per-widget spacing decisions.

## Responsive behavior

Define explicit presentation modes:

### Wide (`>=120` columns)

- transcript and composer remain primary;
- coordinate sidebar may be visible;
- full status segments where available;
- modal width remains bounded and centered.

### Standard (`80-119` columns)

- transcript fills the content width;
- coordinate view moves to an overlay;
- status line shortens model/run identifiers;
- details remain expandable inline.

### Narrow (`<80` columns)

- no permanent sidebar or decorative panels;
- compact symbols and abbreviated secondary values;
- one-line contextual header and status where possible;
- setup becomes a one-choice-per-step wizard;
- essential failure/remediation text wraps; low-priority fields move to detail.

Use Textual responsive/breakpoint support or a single centralized layout policy.
Do not scatter width checks throughout event handlers.

## Interaction conventions

Suggested defaults:

```text
Ctrl+P          command palette
/               slash-command completion in an empty composer
Enter           invoke/send selected command
Shift+Enter     newline when multiline input is active
Esc             close overlay; otherwise interrupt/return according to state
Ctrl+C          graceful cancel; second confirmed action closes
Ctrl+O          toggle transcript detail/inspector
?               contextual shortcut help when composer is empty
Up/Down         completion/history or row navigation according to focus
Tab             accept completion or move focus when no completion is open
```

Do not copy bindings blindly from another product. Centralize commands and
keybindings so help, footer hints, slash commands, and the palette are generated
from the same registry.

Mouse support is secondary but expected for selection, scrolling, expansion,
table rows, tabs, and overlay buttons. Every action must remain keyboard
accessible.

## Perceived performance and background work

- Paint the shell and a loading state immediately before loading configuration
  or result indexes.
- Use Textual workers for long-running TUI work and deliver typed progress,
  cancellation, success, and failure messages to the UI thread.
- Keep existing bounded event ingestion and backpressure behavior.
- Coalesce high-frequency token/progress updates before rendering.
- Do not rebuild the full transcript or table for every event.
- Preserve a bounded transcript in memory while artifacts retain the complete
  auditable record.
- Ensure terminal resize does not block active execution or lose the current
  selection/composer draft.

## Proposed component/module structure

Avoid continuing to grow the single `tesis/tui.py` module. A possible incremental
structure is:

```text
tesis/tui/
  app.py
  commands.py
  intents.py
  theme.tcss
  view_models.py
  presenters/
    runtime_events.py
    results.py
  screens/
    run_console.py
    legacy.py
  widgets/
    activity_entry.py
    activity_transcript.py
    command_composer.py
    context_header.py
    coordinate_table.py
    failure_inspector.py
    status_line.py
  overlays/
    run_setup.py
    plan_preview.py
    result_picker.py
    settings.py
    doctor.py
    help.py
```

This is a target direction, not permission for a big-bang file move. Extract one
tested component at a time and keep the existing public `TesisApp` / `run_tui`
entry points stable.

## Implementation phases

### Phase 0 — Baseline and visual contract

- Capture the current behavior and screenshots at representative terminal sizes.
- Inventory every existing screen action, binding, runner call, and output.
- Define typed operator intents and activity view models.
- Add a `legacy_ui`/new-shell opt-in switch.
- Add snapshot infrastructure before restyling.

Exit condition: current functionality has an explicit parity checklist and
baseline screenshots.

### Phase 1 — New shell, no runtime behavior change

- Add `RunConsoleScreen`, context header, empty transcript, composer, and status
  line.
- Add command registry, slash completion, `Ctrl+P`, and contextual help.
- Route commands to existing screens/actions where necessary.
- Keep the legacy main menu accessible.

Exit condition: every old top-level action is reachable from the new shell, and
no runner/config behavior changed.

### Phase 2 — Semantic runtime transcript

- Add the pure event presenter and `ActivityEntry` widget.
- Map graph, model, payload, method, verifier, score, fallback, containment, and
  failure events.
- Add expand/collapse and details mode.
- Preserve bounded ingestion and cancellation.

Exit condition: an active single run can be operated without the old dashboard,
and all important runtime states are visible without opening raw logs.

### Phase 3 — Matrix and failure operations

- Add responsive coordinate sidebar/table and filters.
- Add structured failure inspector and transcript jump/copy actions.
- Add aggregate progress and honest unavailable/estimate states.

Exit condition: mixed success/failure matrices can be understood and triaged
without inspecting raw files manually.

### Phase 4 — Setup, results, settings, and Doctor overlays

- Replace long setup forms with guided overlays and resolved-plan preview.
- Replace result navigation with picker/detail overlays.
- Add searchable settings and structured Doctor results.
- Preserve explicit live-Doctor confirmation and configuration validation.

Exit condition: the new shell reaches behavioral parity with every old screen.

### Phase 5 — Visual consolidation and legacy removal

- Move styles to TCSS and semantic themes.
- Remove redundant borders/header/footer chrome.
- Complete responsive and accessibility behavior.
- Remove the legacy UI only after parity, snapshot, and integration gates pass.

Exit condition: new shell is the default, old UI removal is isolated and
reversible by commit, and documentation reflects the final bindings/workflows.

## Testing requirements

### Behavioral tests

- every command and palette action dispatches the expected typed intent;
- slash completion and help derive from the command registry;
- setup values resolve identically to the current loader path;
- validation failures prevent start and remain redacted;
- graceful cancel, repeated cancel, back, and exit states are deterministic;
- runtime event presentation is pure and deterministic;
- transcript limits/backpressure do not lose terminal events or failures;
- filter, selection, expansion, copy, export, and overlay-close behavior;
- narrow-terminal keyboard access to every essential action;
- theme/color is not required to identify status.

### Snapshot matrix

Capture and review SVG snapshots for at least:

- first frame/loading;
- idle console;
- slash completion and command palette;
- single run active and complete;
- matrix run with queued/active/success/error/cancelled coordinates;
- structured provider failure and containment violation;
- setup and resolved-plan overlays;
- results and Doctor overlays;
- long model, endpoint, run, and method names;
- empty/no-results and malformed-config states;
- `160x48`, `120x36`, `100x30`, `80x24`, and a supported `<80` size;
- default dark, light, and monochrome/high-contrast-friendly themes.

Use `App.run_test()` / `Pilot` for interaction coverage and
`pytest-textual-snapshot` for reviewed SVG output. Snapshot updates must be
manually reviewed rather than accepted blindly.

### Acceptance gates

- Full existing offline suite remains green.
- New behavioral and snapshot suites pass.
- `git diff --check` passes.
- No secret appears in transcript, clipboard actions, overlay details, or
  screenshots.
- All current setup, run, cancel, validation, results, detail, and export flows
  have parity evidence.
- UI remains usable at the minimum supported terminal size.
- Manual PTY verification confirms focus, resize, selection, copy, and terminal
  restoration after exit.
- One real single-run slice verifies live event rendering without semantic
  changes.
- Final acceptance uses the full authorized DVWA/provider matrix plus artifact
  audit, as required by project policy.

## Explicit non-goals

- No new vulnerability surfaces, methods, or changes to the canonical graph.
- No general-purpose AI chat mode.
- No exposure of hidden chain-of-thought.
- No implementation of resume/retry before their architecture is safe.
- No runtime AKG mutation or dynamically created agents.
- No change to containment or verifier semantics.
- No imitation of another product's logo, brand, exact palette, or proprietary
  presentation.
- No rewrite from Textual solely for visual novelty; Textual already provides the
  required palette, theme, responsive, worker, testing, and widget primitives.

## Research references

- OpenAI Codex CLI repository and splash:
  <https://github.com/openai/codex>
- Codex TUI interaction hints:
  <https://github.com/openai/codex/blob/main/codex-rs/tui/tooltips.txt>
- Codex configurable status line:
  <https://github.com/openai/codex/blob/main/codex-rs/tui/src/bottom_pane/status_line_setup.rs>
- Claude Code interactive mode:
  <https://code.claude.com/docs/en/interactive-mode>
- OpenCode TUI:
  <https://opencode.ai/v2/docs/cli/tui/>
- OpenCode appearance, input, session, and keybinding configuration:
  <https://opencode.ai/v2/docs/cli/config>
- Hermes official TUI implementation notes:
  <https://github.com/NousResearch/hermes-agent/blob/main/ui-tui/README.md>
- Textual command palette:
  <https://textual.textualize.io/guide/command_palette/>
- Textual theme system:
  <https://textual.textualize.io/guide/design/>
- Textual testing and SVG snapshots:
  <https://textual.textualize.io/guide/testing/>

## Recommended first implementation slice

Implement only Phase 0 and the shell portion of Phase 1:

1. Add snapshot-test infrastructure and baseline states.
2. Define the command registry, operator intents, and empty run-console shell.
3. Add `/run`, `/matrix`, `/doctor`, `/results`, `/settings`, `/help`, and
   `/quit`, initially delegating to existing screens.
4. Add the composer, command palette, compact context header, and status line.
5. Put the new shell behind an opt-in flag and keep the old UI unchanged.

Do not restyle or remove the existing runtime dashboard in this slice. Its event
behavior should be replaced only after the semantic event presenter and parity
tests exist.
