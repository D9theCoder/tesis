# TUI keyboard audit and oh-my-pi menu research

Status: implemented; authorized focused keyboard, draft, and widget acceptance passed.
E2E, PTY, live provider, and DVWA execution are excluded from this implementation acceptance.

The research and findings sections record the original audit at the pinned
revisions below. Current implementation and scoped acceptance are recorded in
the final section.

## Recommendation

Use selectable setting rows, searchable choice pickers, and child pages within
one Settings workspace. Give the active child exclusive ownership of its keys,
and restore the exact originating row when it closes. Fix command routing,
editing shortcuts, and draft handling alongside the widget changes.

Keep Textual, the experiment dashboard, full-window Settings, and centered Help.
Use the existing configuration schema and canonical resolver. A framework
replacement is unnecessary for these changes.

## Original audit scope and evidence

- TESIS inspected at `bcf0638`, including the newly committed account controls.
- oh-my-pi inspected at `0b5c27ab24719c86a5986b95ee55f4e75bc1aaa0`, whose
  latest commit is dated 2026-10-22. A shallow source checkout was read under
  `/tmp/tesis-oh-my-pi-audit-20261026`; no upstream scripts or dependencies ran.
- Installed TESIS framework source: Textual 8.2.8.
- Evidence consists of source inspection, a static selector inventory, upstream
  test-source inspection, and official framework documentation. No interactive
  TUI, render capture, keyboard harness, PTY, E2E, provider, or DVWA check ran.
- Findings below describe source-confirmed mechanisms and their interaction
  risks. They are not reports of reproduced terminal failures or measured input
  latency. The original audit changed documentation only; implementation evidence is recorded below.

Textual Select supports Enter, arrows, Space, and typed matching. A mouse is
not required. Its open list has an implicit search query that resets after
0.7 seconds in the installed version; it jumps to a substring match without a
visible persistent query or filtered result set. The problem here is the
dropdown-heavy composition and inconsistent input ownership.
Sources: [Select documentation](https://textual.textualize.io/widgets/select/#bindings),
[typed matching](https://textual.textualize.io/widgets/select/#type-to-search),
installed `textual/widgets/_select.py:48-171, 280-297, 631-686`.

There are **16 Select construction sites** across the TUI: nine in
`tui_forms.py`, four in `tui_drawers.py`, two in `tui_providers.py`, and one
in `tui_reasoning.py`. This is a static call-site count, not a visible-widget
count. Schema-generated launch fields, two five-filter loops, and repeated
ReasoningControl instances produce additional controls at runtime.

## What oh-my-pi actually does

| Mechanism | Observed upstream behavior | TESIS application |
| --- | --- | --- |
| Settings rows | Each row has identity, label, current value, optional description, and a cycle or submenu action. Enter/Space cycles simple values. | Make settings navigable as rows; expand an editor only for the active value. |
| Child ownership | An open submenu receives input before tab switching, section navigation, and global search. Text editors receive arrows and Tab. | Remove the need for each screen to guess which child should receive a key. |
| Searchable choices | SelectFormField preselects the current value and presents a searchable SelectList/choice sheet. | Reuse one picker for models, providers, profiles, candidates, and large enums. |
| Search across settings | Typing on setting rows searches across categories; arrows still move results. Search exit returns to the selected setting's category. | Find a setting directly instead of traversing categories and tab stops. |
| Return state | Closing a submenu restores its origin by stable item ID, including after the parent data changes. | Preserve originating row, query, scroll, and draft through editing. |
| Menu lifecycle | Primary menus are registered while opening and while open. Repeated requests focus or raise the existing menu. | Prevent duplicate Settings/Run/Results roots and competing drafts. |
| Context hints | Footers change for row browsing, section navigation, search, and child editing; hints use binding definitions. | Show what the next key will do in the current context. |
| Layout stability | Settings reserves a stable viewport; opening a child does not resize the overall panel. | Avoid focus or scroll jumps while controls appear and disappear. |

The implementation distinguishes cycling boolean/enum rows, explicit submenu
choices, text editors, and multi-select editors. It also has a native settings
renderer that can use a small popup menu for at most 12 submenu choices and
a picker for larger sets. That threshold belongs to its native rendering path;
it is not a universal terminal-menu rule or a reason to ban every small selector.

TESIS needs its own persistence policy. Upstream setting callbacks can persist
changes immediately, and some upstream multi-select changes take effect before
the submenu closes. TESIS should retain a configuration draft and explicit
Save, while keeping authentication actions clearly immediate. Upstream's
preview rollback for certain appearance settings is separate from persistence.

Pinned primary sources:

- [SettingsList: row model, submenu input, cycling, return by identity](https://github.com/can1357/oh-my-pi/blob/0b5c27ab24719c86a5986b95ee55f4e75bc1aaa0/packages/tui/src/components/settings-list.ts#L999),
  plus definitions at lines 39-59 and stable-height rendering at 611-641.
- [SettingsSelector: child input takes precedence over parent navigation](https://github.com/can1357/oh-my-pi/blob/0b5c27ab24719c86a5986b95ee55f4e75bc1aaa0/packages/tui/src/overlays/settings-selector.ts#L1913),
  search exit at 1388, native menu policy at 74 and 914, and hints at 107.
- [SelectFormField: current choice, searchable sheet, submit/cancel callbacks](https://github.com/can1357/oh-my-pi/blob/0b5c27ab24719c86a5986b95ee55f4e75bc1aaa0/packages/tui/src/components/form.ts#L413).
- [SelectList: navigation, filtering, and activation](https://github.com/can1357/oh-my-pi/blob/0b5c27ab24719c86a5986b95ee55f4e75bc1aaa0/packages/tui/src/components/select-list.ts#L489).
- [MenuSelection: stable keys and disabled-item semantics](https://github.com/can1357/oh-my-pi/blob/0b5c27ab24719c86a5986b95ee55f4e75bc1aaa0/packages/tui/src/components/menu-selection.ts#L3).
- [SelectorController: one instance per menu and focus restoration](https://github.com/can1357/oh-my-pi/blob/0b5c27ab24719c86a5986b95ee55f4e75bc1aaa0/packages/coding-agent/src/modes/controllers/selector-controller.ts#L198).
- [Upstream singleton-menu regression tests](https://github.com/can1357/oh-my-pi/blob/0b5c27ab24719c86a5986b95ee55f4e75bc1aaa0/packages/coding-agent/test/selector-controller-settings-single.test.ts#L94)
  and [SettingsList test source](https://github.com/can1357/oh-my-pi/blob/0b5c27ab24719c86a5986b95ee55f4e75bc1aaa0/packages/tui/test/settings-list.test.ts).
  These test files were read, not executed.

## TESIS findings

### F01, P1: Ctrl+C bypasses the local operation and text selection

`BaseDrawer.BINDINGS` makes Ctrl+C a priority action. Its handler delegates to
the mission screen; when no experiment is active, that screen exits the app.
This overrides Textual Input/TextArea copy bindings and gives account login,
provider editing, and unsaved Settings no local interrupt policy. The new
account widget offers a Cancel button, but has no Ctrl+C override at the owner
screen. A focused child binding alone cannot beat the ancestor priority binding.

Change: route interrupt through the active local context. Selected text gets
copy; an active cancelable local operation gets cancellation; an active
experiment retains cooperative cancellation. Exit remains explicit when idle.
Show the resulting behavior in the footer. Keep a deliberate force-exit path.

Evidence: `tesis/tui_commands.py:119-124, 185-193`,
`tesis/tui_mission.py:1075-1083`, `tesis/tui_auth.py:228-242`, installed
`textual/widgets/_input.py:139` and `_text_area.py:381`.
Framework contract: [priority bindings](https://textual.textualize.io/guide/input/#priority-bindings).

### F02, P1: Commands can stack duplicate workspaces and separate drafts

An overlay can open the command launcher. Dispatch pops only that launcher,
then constructs a new requested screen. From Settings, choosing `/settings`
therefore pushes another Settings screen rather than returning to the existing
draft. The same general mechanism repeats Run, Results, and other roots.
`_return_to_mission()` assumes at most four layers despite unbounded pushes.

Change: introduce one navigation owner for named workspaces. Reopening a root
focuses its existing instance and draft; child navigation happens within it.
Unwind by screen identity rather than a fixed layer count. Handle an outgoing
dirty editor before changing workspaces.

Evidence: `tesis/tui_commands.py:176-177, 282-302, 338-341, 358-367`.

### F03, P1: Save and dirty detection omit unapplied form edits

Settings dirty detection compares only the YAML editor text. Evaluator controls
and ChatGPT model controls become YAML only after their separate Apply action.
Ctrl+S saves that YAML, so a visible form edit can be omitted from Save and
from the close warning. A later draft refresh can reload widget values from
YAML. Provider editors have an additional child Apply and Cancel boundary.

Change: use a single typed configuration draft. A confirmed field edit updates
that draft; Save validates and writes it once. Track unconfirmed text editors
too, so Save and Back cannot silently drop them. Retain temporary child drafts
for multi-field provider edits, with explicit commit/cancel into the parent.

Evidence: `tesis/tui_forms.py:903-915, 965-995, 1087-1126, 1421-1451,
1455-1468`; `tesis/tui_providers.py:45-46, 98-105`.

### F04, P2: Screen shortcuts and pane rules compete with editing

Settings binds Ctrl+E and Left/Right with priority. It special-cases Input,
TextArea, action rows, and expanded Select for pane arrows. Ctrl+E has no
corresponding editing guard and replaces the native end-of-line action with
opening YAML. Left can return from some controls to the category rail while
remaining a caret key or action-row key elsewhere. Right can consume a key
without moving anywhere when the evaluator context is hidden.

Change: preserve text editing keys while an editor owns input. Use one explicit
section-navigation command, and normal Tab/Shift+Tab for switching focus zones.
Arrows browse the active list or edit the active value. Choose a discoverable
nonconflicting shortcut for Advanced YAML.

Evidence: `tesis/tui_forms.py:627-632, 842-898`, installed
`textual/widgets/_input.py:117`, `_text_area.py:269`.

### F05, P2: Model selection uses incompatible search interactions

The command palette forwards navigation from its input to its list. Provider
model search uses ordinary Input and a separate table, with no equivalent
arrow/Enter forwarding. ChatGPT, evaluator, and role profiles use Select and
its transient implicit matching. Operators must learn different focus steps
for essentially the same search-and-pick operation.

Change: one visible-query picker. Typing filters, Up/Down navigates, Enter
confirms, Esc cancels, and zero matches cannot confirm. Include display name,
provider, model ID, and current selection. Multi-select shares search/navigation
but uses Space to toggle and a labeled Apply action. Keep manual IDs available.

Evidence: `tesis/tui_widgets.py:136-152`, `tesis/tui_providers.py:88-100,
189-203`, `tesis/tui_forms.py:287-295, 720-727, 745-746`.

### F06, P2: Provider catalog refresh preserves a row number, not its identity

`_render_models()` clears the table and restores `cursor_row` after filtering.
That index can identify a different model when the result set changes. It also
rebuilds the per-model reasoning selector during the same rendering operation.
The data's stable model IDs are available but are not used to restore the
highlighted catalog model.

Change: retain the highlighted model ID through filtering and data refresh;
use a deterministic neighboring fallback if it disappears. Keep marked models
independent of the highlight. Reconfigure reasoning only when its context changes.

Evidence: `tesis/tui_providers.py:118-145, 189-203`.

### F07, P2: Settings frequently shows summaries where editing is expected

Target/defaults, runtime, and policy primarily show SettingValueRow summaries
and an Edit in YAML button. API provider navigation requires selecting a
provider, then tabbing to an Edit button, then using another dialog's form,
table, model selector, and reasoning selector. Value selection and navigation
are composed as independent GUI-style controls.

Change: rows such as `Target URL <value>`, `Provider <value>`, and `Candidate
budget <value>` open their own typed editor. API providers becomes a list;
Enter opens `Settings / API providers / <provider>` in the same workspace.
Models within that provider get a list or picker and a model detail page.
Advanced YAML remains available for unsupported/unknown fields.

Evidence: `tesis/tui_forms.py:670-693, 732-739, 764-775, 1167-1180`;
`tesis/tui_providers.py:62-106`.

### F08, P2: Narrow layout consumes space and changes action geometry only

Settings retains a 23-column category rail plus margin at 80 columns, and a
20-column rail below 80. At 80x24, the declared horizontal dimensions leave
about 47 content columns; at 60 columns they leave about 36, before scrollbars.
These are CSS arithmetic, not render measurements. Below 80, action rows stack
vertically, but KeyboardActions still binds only Left/Right to move buttons.

Change: at narrow sizes show one settings page with a compact breadcrumb and
a Categories action. Keep the category rail only when space supports it. Match
action keys to their actual orientation, or use a vertical action list. Keep
the focused row/editor and fixed Save/Back controls visible at 60x18.

Evidence: `tesis/tui.tcss:143-168, 178-191`,
`tesis/tui_widgets.py:82-91`.

### F09, P2: Launch navigation is a long form with button-only step changes

Run/Matrix has four steps, many schema-generated Select controls, and a nested
Advanced section. Next/Back require focusing action buttons; returning to a
step focuses its first control rather than the last edited field. Escape closes
the setup instead of first returning from a local editor or previous step.

Change: retain Scope, Coordinates, Runtime, and Review as a wizard, with
setting rows inside each step, visible step navigation, direct Next/Previous
bindings, and remembered row/scroll per step. Keep Start deliberate on Review;
Enter on a field must never unexpectedly launch an experiment. Make Advanced
a child page rather than a long hidden section inside the scroller.

Evidence: `tesis/tui_forms.py:195-217, 239-305, 467-504, 550-562`.

### F10, P2: Filter dropdowns interrupt results browsing

Coordinate and Results dialogs each generate five separate filter dropdowns.
Filtering is detached from the main table, and the coordinate inspector opens
another modal over data already present in the workspace. At small sizes the
filter row stacks and consumes scarce table space.

Change: one searchable table and a Filters action that opens a short filter
list with value pickers. Show active filters as concise text and expose Clear
filters. Use a Results workspace with list/detail child views and preserve
query, selected artifact identity, filters, and scroll on Back. Reuse the live
coordinate pane's state for inspection.

Evidence: `tesis/tui_drawers.py:37-61, 548-585`;
`tesis/tui_mission.py:1040-1061`.

### F11, P2: Evidence review repeats dropdown/form navigation per candidate

Review selects candidates and grades from separate dropdowns above text fields
and save actions. Candidate changes replace evidence but do not explicitly
reset the score and reason controls. This makes candidate identity and the
draft decision easy to separate during repeated grading.

Change: a candidate list with an evidence detail page, direct 0-4 grade keys
only while the grade control owns focus, visible candidate identity and proof
ceiling, and explicit Save/Next pending. Keep a decision draft per candidate
or deliberately clear it when switching. Never cycle or save research scores
through incidental list navigation.

Evidence: `tesis/tui_drawers.py:916-925, 958-1007`.

### F12, P2: Hints describe general navigation, not the current key owner

Help says text fields retain editing keys while priority Ctrl+E/Ctrl+C override
them. Form hints say arrows select without explaining whether a selector must
open or a search field must lose focus first. Action rows that become vertical
retain horizontal key hints. Some navigation/push failures are swallowed with
`except Exception: pass`, so an operator receives no explanation for a no-op.

Change: derive a short footer from the active context and enabled actions.
Distinguish Browse, Search, Edit, Pick, Multi-select, and Busy. Keep Help centered
and make its initial content relevant to that context. Report recoverable
navigation failures through a sanitized status message or diagnostic log.

Evidence: `tesis/tui_drawers.py:1313-1328`,
`tesis/tui_forms.py:305, 860-898`, `tesis/tui_widgets.py:85-91`,
`tesis/tui_commands.py:289-293`, `tesis/tui_mission.py:1028-1036`.

### F13, P2: Apply/Start can mean start a probe, then require another attempt

ReasoningControl.ensure_ready() can start a provider support check and raise
an error asking the operator to wait and apply again. Thus an apparently local
confirm operation sometimes becomes a network operation followed by a second
confirmation. The check button remains present even where the selected effort
already has authoritative catalog support.

Change: present capability state and an explicit Check support action before
confirmation. Show a clear pending/success/failure state and keep Apply/Start
blocked with a reason while required evidence is missing. Preserve the existing
capability requirements and distinguish catalog support from a live probe.
Navigation and ordinary field selection should not dispatch provider requests.

Evidence: `tesis/tui_reasoning.py:57-61, 113-134, 143-180`;
`tesis/tui_forms.py:558-570, 1103-1105, 1430-1432`.

## Proposed interaction contract

| Context | Typing | Up/Down | Enter | Escape | Tab/Shift+Tab |
| --- | --- | --- | --- | --- | --- |
| Setting rows | Search settings | Move row | Edit, open child, or cycle a clearly labeled short value | Clear search, then Back | Move major focus zones |
| Choice picker | Edit persistent query | Move result | Confirm into caller's draft | Cancel picker without changing caller | Optional details/actions; not required for selection |
| Multi-select | Edit query | Move result | Activate labeled Apply when chosen | Discard child selection draft | Move between list and actions; Space toggles a row |
| Text/number editor | Edit value | Native editing | Validate and stage value | Cancel edit and restore prior value | Defined editor/form traversal |
| Child settings page | Search or edit its own rows | Move row | Open next editor | One level Back, restoring parent state | Move major zones |
| Run Review | No global printable-key actions in text inputs | Navigate review/actions | Start only when Start is focused | Return to prior setup step | Review actions |
| Authentication progress | No editing of bound account | Navigate available local actions | Activate explicit action | Cancel pending login and return to account page | Available local actions |

For Ctrl+C, use the local-copy/local-cancel/experiment-cancel policy in F01.
An authentication callback may already have completed when cancellation is
requested; the UI must report saved account status rather than promise rollback.
Sign-out must continue to distinguish local clearing from remote revocation.

For small choices, use an in-row toggle/cycle or a short explicit value list.
Use a full picker for model catalogs, provider/profile IDs, and candidate lists.
Grades and experiment-start actions require explicit confirmation semantics.

## Structure and responsive plan

| Surface | Proposed structure | Back destination |
| --- | --- | --- |
| Settings | One full-window workspace; categories plus rows when wide, one page when narrow | Mission workspace |
| Provider editing | Child page inside Settings with connection rows and model list | Original provider row |
| Model/reasoning choice | Searchable child picker/editor with current value preselected | Exact calling row |
| ChatGPT accounts | Account list/detail, immediate auth actions, model picker | Account/profile row |
| Run/Matrix | Dedicated setup workspace with four retained steps | Prior step, then mission |
| Results/review | List and detail pages within one workspace | Original artifact/candidate row |
| Help | Centered context-aware popup | Exact prior focus |
| Small choice/confirmation | One bounded popup or inline child editor | Calling control |

At 120 columns and wider, retain a useful category/preview arrangement. At
80x24, prioritize the selected page and use a compact category strip or action.
At 60x18, use one page, one active list/editor, a breadcrumb, and fixed actions;
show descriptions for the selected row only. Below 60x18 retain the existing
truthful size notice and necessary help/exit/cancellation controls. Focused
controls and multiline identifiers must be inspectable at every supported size.

The border audit found the current Settings root already borderless and cards
usually add one frame, which is acceptable. The larger clutter cost is the
category rail consuming roughly a third of the inner width, labels/value/
description stacks for every row, and repeated Apply/Save/check controls.
Condense unselected settings to label/value rows, put the selected description
in one detail region, and use one persistent save state. Retain selection and
textual state cues for monochrome use.

## Implementation order and boundaries

1. **Navigation and draft correctness:** F01-F04. Define key ownership,
   singleton workspaces, dirty drafts, and Back restoration before migrating
   every control. Remove the fixed four-pop assumption.
2. **Shared primitives:** visible-query single/multi-choice picker, editable
   settings row, child-page return state, and contextual hints. Preserve values
   by stable IDs, including explicit null/inherit and unavailable saved IDs.
3. **Settings migration:** F05-F08 and F13. Start with provider/model/account
   and evaluator paths, then target/runtime/policy typed fields. Share one
   draft with the round-trip YAML editor and credential placeholders.
4. **Run and results:** F09-F11. Migrate launch, filters, and evidence review
   after the shared interactions are settled. Finish F12 across all contexts.
5. **Requested acceptance:** only run checks the user authorizes. Begin with
   focused navigation/selection/draft checks. For a major implementation, ask
   about E2E coverage before running it, including mocked E2E.

Keep `tesis.tui` as the public facade and `tesis.tui_state.CONFIG_PATH` as the
configuration-path owner. Preserve provider/profile/model identities, explicit
account labels, canonical validation, secret handling, model-catalog ordering,
research-score evidence and frozen review identity. Account credentials stay
outside YAML. Keep configuration Save explicit and experiment Start deliberate.
The audit proposes no changes to experiment topology, payload validation,
containment, scoring, or thesis scope.

Future acceptance should cover child key ownership; Ctrl+E and Ctrl+C inside
inputs; repeated root-menu opening; Escape at every depth; per-page focus/query/
scroll restoration; zero matches; stable IDs after async refresh; unsaved form
edits during Save/Back; multi-select cancel; launch Start; and candidate decision
identity. Include 160x48, 120x30, 80x24, 60x18, and below-floor layouts. Rendered
keyboard evidence and a real terminal remain separate from source inspection.
These are proposed acceptance cases, not executed or newly added tests.

## Implementation and focused acceptance

The user authorized focused navigation, draft, and widget checks only. No E2E,
PTY, live provider, or DVWA execution is part of this acceptance. The original
source audit above remains historical evidence; the changes below implement its
findings in the existing Textual architecture.

| Finding | Implemented behavior | Focused evidence |
| --- | --- | --- |
| F01 | Selection copy precedes local cancellation and experiment cancellation; idle exit is explicit, Ctrl+Q forces exit | Copy, local authentication cancellation, explicit reasoning check tests |
| F02 | Named roots reuse their screen/draft; identity-based unwinding has no depth limit; dirty editors refuse root changes | Repeated Settings opening and seven-child unwind tests |
| F03 | Typed edits stage into the round-trip draft; Save includes pending evaluator and ChatGPT form edits; Enter alone never saves | Pending-form Save, stage-without-save, Ctrl+S-on-child, and single-write tests |
| F04 | F4 opens YAML, F6 opens categories; arrows belong to the active row/editor and Ctrl+E stays native | Editor keys, child return, and step-navigation tests |
| F05 | Shared persistent-query single/multiple choice sheets; current values, explicit inherit, unavailable saved IDs, and manual IDs retained | Picker query, zero-match, Apply/Cancel, and provider/model tests |
| F06 | Catalog highlight uses model identity; marked models remain independent; filtering does not reset effort | Highlight/filter/effort and asynchronous catalog-generation tests |
| F07 | Target/runtime/policy rows have typed editors; provider/account lists and model detail pages retain parent drafts | Typed-row, provider model-detail, account model, and configuration round-trip tests |
| F08 | Categories become a single-page action below 120 columns; Save/Back stay fixed; below-floor notices retain drafts | 160x48, 120x30, 80x24, 60x18, 59x17 captures and resize recovery |
| F09 | Scope/Coordinates/Runtime/Review retain rows and scroll; F7/F8 navigate steps; Advanced has a child view; Start remains deliberate | Step/row restoration, Escape, Review visibility, and frozen-preview checks |
| F10 | Search plus a short Filters page replaces visible filter dropdown rows; list/detail Back retains state; live inspection shares mission coordinates | Results query/filter/identity/Back and coordinate-filter tests |
| F11 | Candidate decision drafts use stable IDs; grade keys are local; proof ceilings stay visible; Next pending uses validated workflow grades | Candidate-switch, local-grade-key, and validated-pending tests |
| F12 | Contextual footers and centered Help describe the active owner; recoverable navigation errors are reported safely | Picker/editor/context source checks and focused launcher navigation |
| F13 | Support checks require the explicit Check action; missing support blocks confirmation; accepted child checks survive staging | Explicit-probe, blocked-confirmation, model-detail, and no-implicit-request tests |

Runtime topology, payload validation, containment, scoring formulas, frozen review
identity, `tesis.tui`, and `tesis.tui_state.CONFIG_PATH` remain unchanged.
Credentials remain outside the configuration draft. Configuration persistence is
still explicit and uses the canonical validation/persistence path.

Validation commands, JUnit results, and pinned widget captures are saved under
`results/validation/keyboard-audit/`; the standard focused-suite JUnit path is
`results/validation/junit.xml`. These captures are headless Textual widget
renders, not real-terminal or physical-keyboard acceptance.

Final results: **70 focused checks passed** in the combined run. After the last
Advanced/Review Back correction and child-context hint cleanup, the **six
affected checks passed again** in two focused runs. Python compilation and Git whitespace checks passed. This is scoped
widget/navigation acceptance; no full repository suite, E2E, PTY, live provider,
or DVWA run was performed.

- Exact combined command: `results/validation/keyboard-audit/command.json`.
- Combined JUnit: `results/validation/keyboard-audit/junit.xml` (also at the
  standard `results/validation/junit.xml` path).
- Final affected wizard checks:
  `results/validation/keyboard-audit/step-return-junit.xml`.
- Final child-context checks:
  `results/validation/keyboard-audit/context-junit.xml`.
- Machine-readable scope, source hashes, and results:
  `results/validation/keyboard-audit/acceptance.json`.
- Settings widget captures: `settings-160x48.svg`, `settings-120x30.svg`,
  `settings-80x24.svg`, `settings-60x18.svg`, and `settings-59x17.svg` in that
  validation directory. Wide and minimum-size captures were also visually
  inspected after SVG rasterization.

The combined command runs the five focused keyboard/reasoning/provider/evaluator/
account test modules and 16 explicitly selected navigation/draft/layout checks
from `tests/test_tui.py`. It does not select experiment-start or E2E tests.
