# Terminal interface design

The TESIS TUI is a persistent experiment workspace. Its visual references are
the supplied Codex CLI and oh-my-pi screenshots and
[Codex's terminal styling guidance](https://github.com/openai/codex/blob/main/codex-rs/tui/styles.md).
It uses Textual's screen, focus, input, and terminal lifecycle support.

## Workspace

The header identifies the DVWA target and selected provider/model. After a
launch it follows the frozen run configuration, including overrides selected
in the launcher. The lifecycle status is shown at the upper right. The lower
status line carries coordinate progress, containment, method, and artifact
location. Plan previews the configuration for a future launch.

At wide sizes the pipeline occupies 28 percent of the workspace and spans its
height. The run table occupies the upper right. Run details/activity and
evidence share the lower right in a 3:2 ratio. The run table receives three
parts of the available height and the detail area two parts. There are no
invented preview coordinates or findings in the idle view.

Panels have one subtle frame. A focused panel uses an accent frame and a
selected row; inputs and commands use a compact surface. There is no outer
screen frame, no nested frame around each list, and no repeated marker on
every pipeline stage. Titles replace headings that were repeated inside the
same panel. One lifecycle label replaces repeated status glyphs and labels.
At 160x48, header, navigation, composer, and footer use ten rows; pane frames
use additional cells inside the workspace. Short terminals hide the composer.

`tesis-terminal` is the default dark theme. Shared styles use semantic theme
variables. `NO_COLOR` selects `tesis-mono`; focus and lifecycle remain readable
through selection, text, and borders. Truncated workspace values use terminal
cell widths and an explicit ellipsis. Inspection views retain full identifiers.

## Keyboard contract

| Key | Behavior |
| --- | --- |
| Tab / Shift+Tab | Next / previous interactive panel or control in the active screen |
| Up / Down | Move through the focused list, table, or viewport |
| Left / Right | Change tabs, move between action buttons, or scroll a wide row table |
| Enter | Open or activate the selected item; enter the selected tab's content |
| Escape | Close the current overlay; return to Pipeline from the workspace |
| `/` / Ctrl+P | Open the command palette |
| `?` | Open the keyboard help popup |
| PageUp / PageDown | Move a page in the focused list or viewport |
| Home / End | First / last row, option, tab, or viewport boundary |
| `1` / `2` / `3` / `4` | Pipeline / runs / evidence / activity |
| `r` / `m` / `p` / `d` | Run / Matrix / Plan / Doctor |
| `v` / `s` / `l` | Results / Settings / activity log |
| Ctrl+C | Copy selected text, cancel local work, or cancel an active experiment; a second experiment cancellation exits |
| Ctrl+Q | Deliberate force exit |
| F4 / F6 | Advanced YAML / Settings categories |
| F7 / F8 | Previous / next launch step |

Text inputs retain normal typing and caret navigation. The palette input is
the exception: Up/Down, PageUp/PageDown, and Home/End move its command selection
while typing focus stays in the input. Enter executes the highlighted enabled
command. A filter with no matches shows an empty state and executes nothing.
Disabled actions remain visible with a short explanation and are skipped by
list navigation. Tab can still move between the filter and command list.
The pipeline initially selects its first stage so Enter works immediately;
later updates preserve the operator's selection.

In Settings, arrows browse rows and Enter opens a typed child editor. F6 opens
categories; Tab and Shift+Tab move between focus zones. F4 opens Advanced YAML,
leaving Ctrl+E available for native text editing. Choice sheets keep a visible
query, current selection, match count, arrow navigation, and explicit cancellation.
Multiple selection uses Space to toggle and a labeled Apply action. A query
with zero matches cannot confirm a value.

Screen stacking keeps focus in the active overlay. Dismissing it restores the
previous context. Live coordinate updates preserve the selected table row and
scroll position; changing the column set during resize retains the row.

## Menus

Settings occupies the entire terminal. At 120 columns and above its category
rail accompanies the selected page. At 80x24 and 60x18 it shows one page and a
breadcrumb; F6 opens categories. Save and Back remain fixed outside the content
scroller. Below 60x18 a size notice replaces the content while retaining its
instance and draft. Resizing back restores the workspace. Help stays centered.

Rows show label/value pairs and the focused row's description. Enter opens the
active value's typed editor, picker, or child page. Printable text on a setting
row opens search across categories. Provider and account lists open their own
pages; provider models have a detail page for selection and reasoning effort.
Model IDs, profile IDs, explicit inherit values, unavailable saved IDs, and
catalog ordering remain intact. Manual model IDs remain available.

Confirmed fields stage into the round-trip configuration draft. Ctrl+S validates
and saves once, including pending evaluator and ChatGPT form values. Invalid
edits block Save and remain available for correction. Secret placeholders,
comments, and unknown YAML fields round-trip. Provider edits use a private child
draft with Apply/Cancel. Authentication changes credential storage immediately.
Escape cancels pending sign-in first, then returns through child pages. At the
Settings root, unsaved edits prompt for Save or a second Escape to discard.
Changing workspaces refuses an outgoing dirty editor. Reopening a root reuses
its instance and draft rather than creating another one.

Reasoning support is an explicit Check action. Catalog-supported choices need
no live probe. Unknown explicit efforts block confirmation with a reason until
a successful check; ordinary navigation, Apply, Save, and Start never initiate
that request. Accepted support does not establish internal reasoning.

Results has a searchable list, a short Filters page, Clear filters, and a detail
page. Back restores query, filters, selected artifact identity, and scroll.
Review binds each grade/reason draft to its candidate ID and displays the proof
ceiling. Grade keys 0-4 apply only while the grade row owns focus. Save / Next
pending is explicit; browsing never writes a research score.

Help is a centered popup whose initial text describes the originating context.
Footers distinguish browse, search, edit, pick, multi-select, and local busy
states. Ctrl+C copies a selection first, otherwise cancels local work before an
active experiment. Idle exit is explicit; Ctrl+Q is the force-exit path.

Run and Matrix retain Scope, Coordinates, Runtime, and Review with rows in each
step. F7/F8 change steps, and each step remembers its last focused field and
scroll. Escape returns from Advanced or to the previous step before closing.
Advanced runtime and role fields occupy their own child page. Start appears
only in Review and never receives focus merely because Review opened. Enter on
a field edits that field. Labels distinguish the primary model, matrix profiles,
and the optional override for both experiment roles.
Start closes all dialogs above the mission screen before beginning execution,
including Plan when it opened the launch setup.

Plan and launch Review share a summary built from approved configuration
fields. Plan's Details action reveals exact profile identities, effective
protocols, endpoints with credentials masked, and the full configuration
fingerprint. The fingerprint uses the complete resolved configuration, matching
the runtime's fingerprint input. Model objects and arbitrary connection mappings
are never rendered. Results starts with a concise execution/security/scoring
summary; Details reveals additional triage fields. Export retains the full
triage record. The Results detail viewport shares remaining height with the
table and scrolls, keeping the action row within the dialog at 80x24.

Doctor retains separate local and explicit service checks, fixed actions, and
optional technical detail. Logs have a focusable scroll area. Scrolling back
pauses follow; `f` toggles follow and End resumes the newest events. Pending
event counts use the monotonic notice version rather than bounded history size.

## Provider and protocol presentation

The UI follows the provider setup introduced by `fc8fce5`, `d60219b`, `02329b2`,
and `1ce875a`:

- API providers retain their explicit OpenAI Responses, OpenAI Chat Completions,
  or Anthropic Messages protocol. Catalog discovery and manual model selection
  remain in the provider editor. Selected model profiles retain their stored
  IDs and coordinate identities.
- ChatGPT sign-in has its own account/profile category and account-bound model
  catalog, with Sign in, Sign out, and Check status controls. Browser sign-in
  offers a copyable one-time URL and Cancel sign-in; leaving Settings stops the
  pending login. Account changes take effect immediately in private storage,
  separately from Save. Selecting a catalog model stages that profile without
  silently switching the experiment's primary provider. Unsupported output-token controls
  are disabled for a ChatGPT evaluator. Legacy model sections without an explicit
  provider infer the adapter from the profile key, matching the configuration
  loader for protocol labels and evaluator capabilities.
- Run and Matrix retain per-role profile and reasoning overrides. Matrix
  summaries identify inherited coordinate profiles without claiming a single
  model or token default for every coordinate.
- The independent evaluator uses registered provider/model IDs, while its
  runtime adapter and protocol remain distinct. Legacy inline evaluator
  configuration is still presented using its effective connection fields.

Workspace summaries abbreviate generated profile IDs to their provider part.
Selectors use the registry's provider/model labels. Exact identities remain in
inspection detail and artifacts. Protocols without an explicit OpenAI API-mode
setting are labeled as the SDK default rather than guessed.

## Responsive behavior

| Size | Intended layout |
| --- | --- |
| At least 120x24 | Pipeline, runs, details/activity, and evidence together |
| At least 80x20 | One selected pane; tabs and keys 1-4 switch panes |
| At least 60x18 | One pane with compact tabs and fewer run columns |
| Below 60x18 | Size notice with Help and exit/cancellation controls |

The composer hides below 22 rows. At 80x24 and in a 60-column split, secondary
run columns move to inspection detail. Pipeline rows remain scrollable. Help
shrinks to the available viewport. Settings uses a single page with a Categories
action below 120 columns, and its save/back row stays fixed.

## Responsiveness

Configuration parsing previously ran synchronously three times while building
the data for one idle redraw. Launch forms also rebuilt hidden Review content
on each field edit, and YAML edits rebuilt evaluator controls on every character.
Direct local profiling found about 39.6 ms of configuration work for an idle
redraw before terminal layout or painting.

`tesis.tui_config` provides screen-local caches for read-only configuration
and draft projections. Source YAML, colocated dotenv, referenced scoring JSON,
process environment, CLI overrides, and loader identity invalidate resolved
configuration. Draft mutations receive a copy so restoring credentials or
editing a section cannot alter a cached read projection. Start always performs
a fresh canonical resolution before freezing an execution.

Navigation changes pane visibility without rebuilding unrelated dashboard
content. Pipeline prompts and text update only when their content changes.
Run tables update changed cells, append new rows, and retain selection and
scroll position. All runtime events still enter the reducer in order; only
display refreshes and drawer notifications are coalesced to at most 30 Hz.
Logs read the notice version directly rather than formatting and redacting
history just to evaluate an unused fallback value.
Textual animation is disabled. Launch previews debounce for 150 ms and YAML
draft projections for 200 ms; typing and focus changes remain immediate.

The same direct idle-data operation measured about 0.3 ms after warm caching.
These are local data-method timings, not full terminal or keyboard latency.
Baseline and updated JSON timings and cProfile output are retained under
`results/validation/tui-performance/`. Profiling starts no app, experiments,
DVWA traffic, or provider calls.

## Implementation and validation scope

`tesis.tui_widgets` owns shared keyboard tables, tabs, action rows, the palette
input, and approved model/configuration summaries. Screen classes remain in
their existing modules and `tesis.tui` remains the public facade.
`tesis.tui_state.CONFIG_PATH` remains the configuration-path owner.

For this change, validation is limited to Python compilation/imports,
stylesheet parsing for the default, monochrome, and light themes, and Git
whitespace checks, plus the direct data-method profiling described above.
The user declined E2E checks. Interactive keyboard behavior,
visual rendering at the size bands, physical terminal lifecycle, and live
DVWA/provider execution have not been validated for this revision. No tests
were added or run. Generated static-check evidence belongs under
`results/validation/`.
