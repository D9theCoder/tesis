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
| Ctrl+C | Request cooperative cancellation; a second request exits |

Text inputs retain normal typing and caret navigation. The palette input is
the exception: Up/Down, PageUp/PageDown, and Home/End move its command selection
while typing focus stays in the input. Enter executes the highlighted enabled
command. A filter with no matches shows an empty state and executes nothing.
Disabled actions remain visible with a short explanation and are skipped by
list navigation. Tab can still move between the filter and command list.
The pipeline initially selects its first stage so Enter works immediately;
later updates preserve the operator's selection.

In Settings, Up/Down selects categories vertically. Right enters the content
pane; Left returns to the category rail. On wide evaluator pages, Right can
continue into the context pane and Left returns to the form. These keys keep
their normal caret behavior in text fields, their option behavior in an open
selector, and their button behavior in action rows. They do not advance the
settings category. Tab and Shift+Tab remain available between all controls.

Screen stacking keeps focus in the active overlay. Dismissing it restores the
previous context. Live coordinate updates preserve the selected table row and
scroll position; changing the column set during resize retains the row.

## Menus

Settings occupies the entire terminal. Its category rail selects Target &
defaults, API providers, ChatGPT accounts, LLM runtime, AI evaluator, Policy &
output, or Advanced YAML. The selected content scrolls independently while
Save and Close remain available. Enter enters the selected section. Ctrl+S
saves; Ctrl+E opens Advanced YAML. The YAML editor uses Tab for focus. Changes
are staged explicitly, and the page marks an edited YAML draft as unsaved.
Escape on an unsaved draft explains Save and discard, then a second Escape
discards it. A malformed configuration is not rendered as unmasked raw YAML.

Target & defaults uses a framed configuration section with individual label,
value, and description rows, followed by an Actions section. Runtime, policy,
and active-model summaries use the same rows. The evaluator separates Review
model and Evaluator limits into aligned label/control/explanation forms. At
160 columns and above, an independent context column previews the current
evaluator choices and describes draft persistence. Below 115 columns the form
fields and summary rows stack vertically.

Inputs, selectors, checkboxes, and action buttons occupy one terminal row.
Selectors open a plain list with the same row selection treatment as commands.
Boolean and multiple-selection controls use `[*]` for selected and `[-]` for
unselected, including the launch forms and provider model catalog. Native
Checkbox and SelectionList values and change events remain in use. Checkbox
labels are shown once alongside their marker.

The Add/Edit API provider dialog groups Connection fields above Models, with
Apply and Cancel aligned at the bottom. Its model list appears when models are
available; empty catalogs and filters display a short message. The selector,
filter, manual ID, and saved-key behavior retain their existing data contract.

Help is a centered popup with Navigation and Commands tabs. Its body scrolls
at small sizes. Plan, Run, Matrix, Doctor, results, review, failure, evidence,
and provider editing use centered dialogs. Inspections fill the terminal
below 80 columns; Help retains its bounded popup shape.

Run and Matrix use Scope, Coordinates, Runtime, and Review steps. Each step
scrolls independently and moves focus to its first control. Common execution
limits remain visible; extra runtime and role settings live under Advanced.
Start appears only in Review. Labels distinguish a primary provider/model,
matrix provider/model profiles, and the optional override for both model roles.
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
  catalog. Selecting a catalog model stages that profile without silently
  switching the experiment's primary provider. Unsupported output-token controls
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
shrinks to the available viewport. Settings retains its category rail and
scrollable content while its action row stays fixed.

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
