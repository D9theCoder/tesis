# TUI Mission Control Redesign Plan

## Context

The current default Textual shell is nominally the “new” TUI, but it is not a complete replacement. `TesisApp` launches `RunConsoleScreen`, then `/run`, `/matrix`, `/doctor`, `/results`, and `/settings` push legacy screens. Live execution still occurs in `RuntimeDashboardScreen`; the new shell’s transcript event methods have no production event-sink path. The resulting experience visibly switches between two design systems and the new home surface cannot actually serve as mission control.

Fresh screenshots from `TesisApp().run_test()` at 120×36, 80×24, 60×24, 48×16, and 40×12 are recorded at `local://tui-review-current-*.svg`. They show:

- the empty `RichLog` consuming roughly three quarters of the terminal while useful run state is absent;
- the same command guidance repeated in the empty state, permanent input placeholder, status line, and footer;
- a chat-like composer even though free prose is rejected;
- an idle scrollbar, top-left text-dump overlays, and no selectable/filterable coordinate or evidence surface;
- clipping below roughly 60 columns with no truthful minimum-size state.

Existing repository captures confirm that active rows still sit in a transcript-first shell rather than a pipeline/evidence dashboard. Current code also confirms that coordinate, failure, plan, and help overlays are static text rather than operator controls.

The approved product shape is:

- mission-control first, command console second;
- configure/start, observe, inspect/export, and cancel only; a started run is immutable;
- wide screens show pipeline, coordinates, and evidence together;
- launch is guided but every operation remains reachable from commands;
- the command surface is summoned with `/`, `:`, or Ctrl+P, never permanently focused;
- ongoing state is blue, successful state green, and degraded/failed state red, with text/glyphs so color is never the only signal;
- evidence/failure updates change counts and state but never steal focus;
- deep AKG visualization, longitudinal comparison, charts, and raw artifact exploration remain in the companion web app (`/home/kevin/coding/tesis-web`), whose graph-first dashboard and detailed result pages already own those jobs.

The interaction model borrows only proven terminal patterns: k9s-style command mode and Esc-back navigation (`https://k9scli.io/topics/commands/`), lazygit-style spatial panes and contextual keys (`https://github.com/jesseduffield/lazygit`), Claude Code’s stable fullscreen/focus and paused auto-follow behavior (`https://code.claude.com/docs/en/fullscreen`), and Codex’s explicit task/control state (`https://github.com/openai/codex`). It deliberately does not copy their chat-first composer.

## Approach
Before any code change, copy this approved plan into the active handoff location. Keep it active through implementation and verification; after every acceptance check passes, move the same document to its corresponding `docs/completed/` path and update inbound links.


### 1. Replace transcript state with one live operator-state contract

In `tesis/tui.py`, retain the public `TesisApp` and `run_tui()` entry points, existing config/artifact helpers, daemon-thread shutdown guarantees, cancellation token, bounded event queue, run journal, runtime descriptor, and runner calls. Replace the view-specific shell/legacy models with these exact UI contracts:

```python
RunStatus = Literal["ready", "running", "degraded", "succeeded", "failed", "cancelled"]
StageStatus = Literal["queued", "running", "succeeded", "warning", "failed"]

@dataclass(slots=True)
class StageRow: ...

@dataclass(slots=True)
class CoordinateRow: ...

@dataclass(slots=True)
class FailureSummary: ...

@dataclass(slots=True)
class TuiRunState: ...

def apply_run_event(state: TuiRunState, event: RunEvent) -> frozenset[str]: ...
```

`TuiRunState` owns the current execution ID, run mode, terminal status, elapsed/progress counts, canonical seven-stage pipeline, coordinate rows keyed by matrix index, selected coordinate, selected method, confirmed vulnerabilities, achieved outcomes, latest verifier decision, active failure, bounded semantic notices, unseen-evidence count, and dropped-event count. `apply_run_event` mutates only this UI model and returns dirty region names (`header`, `pipeline`, `coordinates`, `evidence`, `notices`) so the screen refreshes only affected widgets.

Map runtime events deterministically:

- `run.started` / `matrix.started` reset and enter blue `running`;
- node start/completion/failure events update the canonical stages `recon`, `orchestrator`, `payload_candidate_builder`, `payload_validator`, selected method agent, `chaining_router`, and `scorer`;
- `graph.state` updates selected method, candidate/validation counts, confirmed vulnerabilities, achieved outcomes, and verifier summary without rendering raw state as transcript text;
- coordinate events update only their indexed row;
- any coordinate failure or containment violation makes a continuing matrix red `degraded`; parent terminal failure makes it red `failed`; terminal success is green only when no coordinate failed; cancellation is labelled `cancelled` and uses warning styling;
- raw model output remains redacted and bounded in the trace drawer; chain-of-thought is never rendered.

Keep semantic notices bounded and coalesced with the current queue/backpressure rules. When the user has scrolled notices away from the bottom, stop auto-follow and show `N new`; incoming events must not change focus or selection.

### 2. Make coordinate identity and summaries sufficient for live triage

In `evaluation/multi_llm_runner.py`, keep runner semantics unchanged and add only additive UI-safe event fields:

- `matrix.run.started`: `coordinate_index` and `coordinate_execution_id`;
- `matrix.run.finished`: the same identity fields plus `run_id`, `selected_method`, redacted `confirmed_vulns`, redacted `achieved_outcomes`, `task_result`, and `failure_class` when present.

Use the existing canonical preparation index, not a second coordinate-order algorithm. Child `RunEvent.execution_id` values map to the coordinate execution ID. Add contract tests proving concurrent completion still updates the correct row and aggregate artifact ordering remains unchanged.

The main screen continues to execute the existing single/matrix runner on a daemon `Thread`; this preserves the documented second-Ctrl+C force-exit behavior when a provider or HTTP call is stuck. The thread may only enqueue events/results. All widget updates remain on Textual’s event loop.

### 3. Build the mission-control surface and summoned command launcher

Rename `RunConsoleScreen` to `MissionControlScreen` and make it the only root screen. Compose a compact one-row context bar, responsive body, one-row run-status strip, and contextual footer; do not mount a permanent `Input`, global clock, decorative banner, or empty full-screen log.

The canonical wide layout at width ≥120 and height ≥24 is:

```text
TESIS · target · condition · model                       ▌ ● RUNNING 7/36
Pipeline / recent notices (3fr)        Coordinates (2fr, upper)
                                        Evidence / failure (2fr, lower)
contained · selected method · elapsed · artifact path
r run · m matrix · / command · Tab focus · Enter inspect · Ctrl+C cancel
```

- `PipelinePane` renders seven stable stage rows with a status glyph, concise label, current attempt/detail, and selected method substituted into the method-agent row.
- `CoordinatePane` is a selectable `DataTable` with index, status, provider, surface, level, mode, target/selected method, finding count, and elapsed value; unavailable values render `—`, never fabricated zeros.
- `EvidencePane` shows verified findings, achieved outcomes, latest verifier decision, guardrail/containment/fallback counters, and the latest failure summary. New evidence increments a badge but does not open the pane.
- `NoticePane` shows only the most recent bounded semantic events below the pipeline; the full redacted stream lives in `TraceDrawer`.
- The idle body is a readiness summary—target scope, condition, provider/model, default coordinate count, config validity, containment status, and the four actions `r run`, `m matrix`, `p plan`, `d doctor`—rather than an empty transcript.

Responsive policy is fixed:

- width ≥120 and height ≥24: simultaneous pipeline/coordinates/evidence layout above;
- otherwise, width ≥80 and height ≥20: pipeline plus a one-line triage summary; coordinates and evidence open as full-height drawers;
- otherwise, width ≥60 and height ≥18: one focused pane, compact context/footer, abbreviated stage labels, and one launch step per screen;
- otherwise: replace the application body with `Terminal too small — need 60×18; current {width}×{height}` and expose only quit/help.

Use `CommandSpec(name, title, summary, keys, enabled_when)` and one `COMMANDS` registry for command launcher results, Ctrl+P palette entries, help text, and contextual footer hints. The exact commands are `run`, `matrix`, `plan`, `cancel`, `coordinates`, `evidence`, `failure`, `trace`, `doctor`, `results`, `settings`, `export`, `about`, `help`, and `quit`. Remove disabled `resume`/`retry` placeholders and the redundant `model` alias. `/run` and `/matrix` open the guided launcher; they never bypass review. While active, starting/configuration commands are disabled with an explicit reason and only inspect/export/cancel operations remain available.

`CommandLauncher` is a bottom-anchored modal with one input and filtered command list. `/`, `:`, and Ctrl+P open the same registry; Enter dispatches the selected typed intent; Esc closes and restores the prior focus. Global keys outside text inputs are `r` single launch, `m` matrix launch, `p` plan, `d` Doctor, `1/2/3` pipeline/coordinates/evidence, Tab/Shift+Tab focus traversal, Enter inspect, `?` help, and `q` quit only while idle. Ctrl+C requests graceful cancellation; a second Ctrl+C while cancellation is pending exits immediately, preserving the existing contract.

### 4. Replace every delegated legacy screen with focused drawers

All drawers use the same restrained shell, one border maximum, Esc-back behavior, responsive full-screen fallback below 80 columns, and the command registry. No drawer pushes a legacy screen.

- `LaunchDrawer(mode: Literal["single", "matrix"])` has four guided steps: Scope, Coordinates, Runtime, Review. Scope selects target, experiment condition, and target method. Coordinates selects provider/model profile, security level, surface, payload mode, and—only for matrices—multi-select axes and repeat count. Runtime preserves the current candidate budget, iteration/stop policy, coverage, guardrail, diagnostics/reporting/output, LLM concurrency/cache/reasoning, and role override controls behind one Advanced section. Review calls the existing config resolver, displays the exact effective values and coordinate count, and is the only place with Start. Start freezes the resolved request until terminal state.
- `SettingsDrawer` replaces the old full-screen settings form with collapsible Target & defaults, Model profile, LLM runtime, Policy & output, and Advanced YAML sections. Preserve round-trip YAML comments/order, environment placeholders, blank-secret preservation, temporary-file validation, concurrency range validation, and the two-save literal-secret warning exactly; never put a literal secret in a status, trace, screenshot, or export.
- `CoordinateDrawer` presents the same live `DataTable` with status/provider/surface/level/mode/method filtering and Enter-to-inspect.
- `EvidenceDrawer` and `FailureDrawer` present redacted, selectable summaries; Enter expands the chosen verifier/failure record. Failure remediation and request IDs remain visible when present.
- `TraceDrawer` provides the bounded redacted event/LLM trace and paused auto-follow; it is explicitly secondary to pipeline state.
- `ResultsDrawer` uses `ArtifactRepository.scan(..., retain_raw=False)` and the existing status/provider/surface/level/mode filters. Enter lazily loads one artifact and shows only triage data: identity/config; method score; the payload-score breakdown; exploitation, chain, output, and composite scores; selected/viable method; confirmed findings/outcomes; verifier/safety/failure summary; same-config executions; artifact path; and export actions. Missing score values render `—` and are never synthesized. Matrix children remain selectable. Deep JSON, AKG graphs, charts, and run comparison stay in the web app.
- `DoctorDrawer` keeps configuration, offline Doctor, live Doctor, target reachability, selected-agent, and all-agent checks. Live Doctor requires the existing explicit warning/confirmation. Results render as a structured check list with status, details, remediation, and summary counts.
- `PlanDrawer`, `HelpDrawer`, and `AboutDrawer` replace the current bordered text dumps with aligned sections, scrollable content, and keys/actions generated from the same registry.

Result scanning, artifact loading, Doctor checks, and active runs retain daemon background threads plus generation/closing guards so leaving a drawer or force-quitting cannot post into dead widgets or hold the process open.

### 5. Apply one restrained visual system

Move all styles to `tesis/tui.tcss` and set `TesisApp.CSS_PATH = "tui.tcss"`. Use Textual theme variables rather than hard-coded palette values:

- running status rail/text: `$primary` with `● RUNNING`;
- succeeded: `$success` with `✓ SUCCEEDED`;
- degraded/failed: `$error` with `! DEGRADED` / `× FAILED`;
- cancelled/warnings: `$warning` with explicit text;
- ready/secondary metadata: `$text-muted`.

Only the one-cell status rail, status label, active stage glyph, badges, and focused row receive semantic color; the whole screen never flashes or changes theme. Keep whitespace between sections, a single border around active modals, no nested boxes, no gradients, no ASCII art, and no “hacker” decoration. Long target/model/method text uses cell-aware ellipsis. Pointer actions may focus/select/scroll, but every action must remain keyboard-complete. Preserve dark, light, and `tesis-mono`; if `NO_COLOR` is set, select `tesis-mono` on startup.

### 6. Cut over completely and remove the second design system

Make `TesisApp()` always mount `MissionControlScreen`. Remove the `new_shell` constructor option, `TESIS_NEW_SHELL`, `MainMenuScreen`, `RunSetupScreen`, `RuntimeDashboardScreen`, `SettingsScreen`, `RecentResultsScreen`, `ResultDetailScreen`, `ValidationScreen`, `FrameworkInfoScreen`, their unused messages/widgets/CSS, and all old screen dispatch branches. Delete `tesis/tui_shell.py` and `tesis/tui_shell.tcss` after their reusable command/presenter logic is folded into `tesis/tui.py`; keep no compatibility shim.

Merge behavior-level shell tests into `tests/test_tui.py`, retarget `tests/test_tui_performance.py`, and delete legacy-isolation tests that only prove the removed dual-TUI path. Preserve tests for config round trips and secret masking, cancellation, bounded/coalesced events, generation guards, artifact laziness/truncation, matrix row correlation, command availability, focus restoration, responsive policy, and redaction. Add the ignored generated-capture path `/docs/tui_mission_control_*/` to `.gitignore`.

Update `README.md` and `guide.md` in the same cutover: describe mission-control panes, summoned commands, immutable active-run controls, and responsive minimum; remove transcript-first, legacy fallback, and response-stream instructions. Runtime topology, state schema, AKG semantics, artifact schema, runner behavior, and headless CLI remain unchanged, so the architecture/methodology reference documents require no semantic rewrite.

## Critical files and anchors

- `tesis/tui.py`: public app/entry, existing setup/runtime/settings/results/Doctor behavior, and the replacement `MissionControlScreen` plus drawers.
- `tesis/tui_shell.py`: current new-shell command/presenter logic to fold into `tesis/tui.py`, then delete.
- `tesis/tui.tcss`: single replacement stylesheet for responsive mission control and drawers.
- `evaluation/multi_llm_runner.py`: additive coordinate identity/summary event fields only.
- `tests/test_tui.py`: retained behavioral contracts plus mission-control interaction/responsive coverage.

## Verification

1. Run focused contracts:

   ```bash
   uv run pytest -q tests/test_tui.py tests/test_tui_performance.py
   ```

   Cover ready → running → degraded/succeeded/failed/cancelled transitions, out-of-order matrix completions, coordinate-to-child-event mapping, bounded notice/trace queues, paused auto-follow, command state gating, no focus stealing, literal-secret masking, and second-Ctrl+C shutdown.

2. Run the application’s non-network contract and full suite:

   ```bash
   uv run python -m tesis run --dry-run --config config.yaml
   uv run pytest -q
   ```

3. Launch the actual TUI in a PTY with `uv run python -m tesis run`; exercise `/` and `:` launcher open/close, Ctrl+P, keyboard-only launch review, responsive resize, mouse selection, results/Doctor/settings drawers, idle quit, and active graceful cancel/second-Ctrl+C. Confirm terminal state is restored after every exit path.

4. Using `App.run_test()` plus `export_screenshot()`, generate SVGs under `docs/tui_mission_control_<date>/` for 160×48, 120×36, 80×24, 60×18, and 59×17. Capture READY, single RUNNING, matrix RUNNING, DEGRADED with one failed coordinate, SUCCEEDED, FAILED, launch review, command launcher, coordinate detail, evidence, results, Doctor, settings, and too-small states in dark/light/mono themes. Inspect every image for:

   - all primary content visible without unexpected scroll;
   - pipeline/coordinates/evidence simultaneously visible at ≥120 columns;
   - exactly one command prompt only while launcher is open;
   - no repeated instructions, idle scrollbar, clipped footer, top-left orphan modal, nested borders, or low-contrast focus;
   - blue/green/red status distinction plus readable labels in monochrome;
   - no target credential, API key, cookie, bearer token, prompt secret, or unredacted endpoint query in any SVG.

5. Compare the final 120×36 and 80×24 captures against the current `local://tui-review-current-*.svg` set. Acceptance requires materially less dead space, one coherent design across every operation, and no route that opens a removed legacy screen.

6. If an authorized configured DVWA and provider credentials are available, run one single coordinate from the TUI and verify the live pipeline, evidence badge, artifact path, Results triage, export, cancellation boundary, and final artifact status against the produced artifact. If either external prerequisite is unavailable, do not substitute another target: complete the deterministic event-stream/runner-fake verification above and report live-run acceptance as explicitly unverified.

## Assumptions and contingencies

- Textual remains the renderer. Migrating this established Python application to Ink/OpenTUI would replace working runtime/config/artifact integrations without improving the requested UX.
- The supported interactive floor is 60×18. Smaller terminals receive a truthful size message rather than a compromised layout.
- The web companion remains the detailed read-only observer and artifact explorer; the TUI intentionally stops at operation and triage.
- All target interaction remains restricted to the configured authorized DVWA scope. No visual redesign may weaken containment, payload validation, redaction, or cancellation semantics.
