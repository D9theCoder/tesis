"""Focused keyboard/draft checks. No runner, provider, or DVWA execution."""
import asyncio

import pytest
from textual.app import App
from textual.binding import Binding
from textual.widgets import Button, Input, OptionList, Select, Static, TextArea

from tesis import tui_state
from tesis.config_loader import load_yaml_config, save_yaml_config
from tesis.tui_choices import ChoicePicker, ChoiceSelect
from tesis.tui_commands import CommandLauncher, open_workspace, request_quit
from tesis.tui_forms import SettingsDrawer


class WidgetApp(App):
    CSS_PATH = "../tesis/tui.tcss"
    ENABLE_COMMAND_PALETTE = False
    BINDINGS = [Binding("ctrl+q", "quit", priority=False)]

    def action_quit(self):
        request_quit(self.screen)

    def action_force_exit(self):
        self.exit()


@pytest.fixture
def mission_shell(monkeypatch):
    """Keep only the mission screen's identity and keyboard dispatch."""
    from tesis.tui_mission import MissionControlScreen
    monkeypatch.setattr(MissionControlScreen, "compose", lambda self: iter([Button("Mission", id="mission-anchor")]))
    monkeypatch.setattr(MissionControlScreen, "on_mount", lambda self: None)
    monkeypatch.setattr(MissionControlScreen, "on_resize", lambda *args: None)
    monkeypatch.setattr(MissionControlScreen, "on_screen_resume", lambda self: self.query_one(Button).focus())
    return MissionControlScreen


@pytest.mark.parametrize("size", [(160, 48), (120, 30), (80, 24), (60, 18)])
def test_picker_query_navigation_no_matches_and_cancel(size):
    async def scenario():
        app = WidgetApp()
        async with app.run_test(size=size) as pilot:
            result = []
            picker = ChoicePicker([("Alpha / provider-a / model-1", "a"), ("Beta / provider-b / model-2", "b")], current="b")
            app.push_screen(picker, result.append)
            await pilot.pause()
            assert picker.query_one(OptionList).highlighted == 1
            assert picker.query_one(Input).region.overlaps(app.screen.region)
            await pilot.press("a", "l", "p", "h", "a")
            await pilot.pause()
            assert picker.filtered_choices == [("Alpha / provider-a / model-1", "a")]
            await pilot.press("enter")
            await pilot.pause()
            assert result == [("a",)]
            app.push_screen(ChoicePicker([("Only", "one")]), result.append)
            await pilot.pause()
            await pilot.press("x", "enter")
            assert isinstance(app.screen, ChoicePicker)
            await pilot.press("escape")
            await pilot.pause()
            assert result[-1] is None
    asyncio.run(scenario())


def test_multiselect_cancel_and_explicit_apply():
    async def scenario():
        app = WidgetApp()
        async with app.run_test() as pilot:
            results = []
            for cancel in (True, False):
                app.push_screen(ChoicePicker([("A", "a"), ("B", "b")], current=["a"], multiple=True), results.append)
                await pilot.pause()
                await pilot.press("down", "space")
                await pilot.pause()
                if cancel:
                    await pilot.press("escape")
                else:
                    app.screen.query_one("#choice-apply", Button).focus()
                    await pilot.press("enter")
                await pilot.pause()
            assert results == [None, (["a", "b"],)]
    asyncio.run(scenario())


@pytest.fixture
def settings_path(tmp_path, monkeypatch):
    path = tmp_path / "config.yaml"
    monkeypatch.setattr(tui_state, "CONFIG_PATH", path)
    save_yaml_config(path, {"target_url": "http://localhost/dvwa", "provider": "saved",
                           "models": {"saved": {"provider": "openai", "model_name": "offline"}},
                           "scoring_mode": "ai", "scoring_evaluator": {"provider": "saved", "max_attempts": 2,
                                                                      "max_tokens": 1024, "timeout": 60}})
    return path


@pytest.mark.parametrize("size", [(120, 30), (80, 24), (60, 18)])
def test_settings_escape_keeps_mission_underneath(settings_path, mission_shell, size):
    async def scenario():
        app = WidgetApp()
        async with app.run_test(size=size) as pilot:
            mission = mission_shell()
            app.push_screen(mission)
            await pilot.pause()
            for via_launcher in (False, True):
                if via_launcher:
                    app.push_screen(CommandLauncher())
                    await pilot.pause()
                    app.screen._dispatch("settings")
                else:
                    open_workspace(app, SettingsDrawer())
                await pilot.pause()
                assert mission in app.screen_stack, "Workspace navigation must retain the mission screen"
                await pilot.press("escape")
                await pilot.pause()
                assert app.screen is mission
                anchor = mission.query_one("#mission-anchor")
                assert app.focused is anchor and anchor.region.width > 0
    asyncio.run(scenario())


def test_mission_actions_require_modifier_combinations(mission_shell, monkeypatch):
    shortcuts = [
        ("r", "ctrl+r", "launch_single"), ("m", "ctrl+alt+m", "launch_matrix"),
        ("p", "ctrl+o", "open_plan"), ("d", "ctrl+d", "open_doctor"),
        ("s", "ctrl+s", "open_settings"), ("v", "ctrl+v", "open_results"),
        ("l", "ctrl+l", "open_trace"), ("q", "ctrl+q", "quit_if_idle"),
        ("/", "ctrl+p", "open_launcher"), ("?", "ctrl+f1", "open_help"),
        ("1", "alt+1", "show_pipeline"), ("2", "alt+2", "show_coordinates"),
        ("3", "alt+3", "show_evidence"), ("4", "alt+4", "show_activity"),
    ]
    calls = []
    for _, _, action in shortcuts:
        monkeypatch.setattr(mission_shell, f"action_{action}", lambda self, name=action: calls.append(name))
    async def scenario():
        app = WidgetApp()
        async with app.run_test() as pilot:
            app.push_screen(mission_shell())
            await pilot.pause()
            await pilot.press(*(raw for raw, _, _ in shortcuts), ":")
            assert calls == []
            for _, combo, action in shortcuts:
                await pilot.press(combo)
                assert calls[-1] == action
            assert len(calls) == len(shortcuts)
    asyncio.run(scenario())


@pytest.mark.parametrize("size", [(160, 48), (120, 30), (80, 24), (60, 18)])
def test_settings_arrows_follow_controls_and_restore_section_focus(settings_path, size):
    async def scenario():
        app = WidgetApp()
        async with app.run_test(size=size) as pilot:
            drawer = SettingsDrawer()
            app.push_screen(drawer)
            await pilot.pause()
            first = drawer.query_one("#setting-target")
            second = drawer.query_one("#setting-primary-model")
            categories = drawer.query_one("#settings-categories", OptionList)
            first.focus()
            await pilot.press("up")
            assert app.focused is first, "Up at the first field must not wrap"
            await pilot.press("down")
            assert app.focused is second
            await pilot.press("left")
            assert app.focused is categories
            assert drawer.query_one("#settings-content").display == (size[0] >= 120)
            await pilot.press("down", "right")
            assert app.focused is drawer.query_one("#settings-api-add")
            await pilot.press("left", "up", "right")
            assert app.focused is second, "Returning to a category restores its last field"
            drawer.query_one("#setting-method").focus()
            await pilot.press("down")
            assert app.focused is drawer.query_one("#settings-save"), "Hidden legacy controls must be skipped"
            assert app.screen is drawer, "Arrows browse fields without opening a choice sheet"
            await pilot.press("end")
            assert app.focused is drawer.query_one("#settings-close")
            await pilot.press("down")
            assert app.focused is drawer.query_one("#settings-close"), "Down at the last action must not wrap"
            await pilot.press("home")
            assert app.focused is first
            await pilot.press("ctrl+f6")
            await pilot.resize_terminal(80, 24)
            await pilot.pause()
            assert app.focused is categories
            assert not drawer.query_one("#settings-content").display
            await pilot.press("escape")
            assert app.screen is drawer and app.focused is first
            await pilot.resize_terminal(160, 48)
            await pilot.pause()
            first.focus()
            await pilot.pause()
            await pilot.resize_terminal(80, 24)
            await pilot.pause()
            assert drawer.query_one("#settings-content").display
            assert app.focused is first
    asyncio.run(scenario())


def test_settings_arrows_preserve_text_editing_and_filtered_lists(settings_path):
    async def scenario():
        app = WidgetApp()
        async with app.run_test(size=(80, 24)) as pilot:
            drawer = SettingsDrawer()
            app.push_screen(drawer)
            await pilot.pause()
            categories = drawer.query_one("#settings-categories", OptionList)
            categories.highlighted = 4
            await pilot.pause()
            drawer.enter_section()
            row = drawer.query_one("#row-settings-evaluator-timeout")
            row.focus()
            await pilot.press("enter")
            field = app.screen.query_one(Input)
            field.value = "123"
            field.cursor_position = 2
            await pilot.press("left")
            assert field.cursor_position == 1
            assert app.focused is field
            await pilot.press("escape")
            drawer.action_edit_yaml()
            editor = drawer.query_one("#yaml-editor", TextArea)
            editor.move_cursor((1, 2))
            await pilot.press("up")
            assert app.focused is editor and editor.cursor_location[0] == 0
            await pilot.press("ctrl+f6", "home", "down", "right")
            query = drawer.query_one("#settings-provider-query", Input)
            query.focus()
            await pilot.press("down")
            assert app.focused is query and app.screen is drawer
    asyncio.run(scenario())


def test_quit_combinations_preserve_dirty_settings_and_active_runs(settings_path, mission_shell):
    async def scenario():
        app = WidgetApp()
        async with app.run_test() as pilot:
            mission = mission_shell()
            app.push_screen(mission)
            await pilot.pause()
            mission._run_active = True
            await pilot.press("ctrl+q")
            assert app.is_running and app.screen is mission
            mission._run_active = False
            open_workspace(app, SettingsDrawer())
            await pilot.pause()
            drawer = app.screen
            drawer.query_one("#yaml-editor", TextArea).text += "\n# unsaved\n"
            await pilot.press("ctrl+q")
            assert app.is_running and app.screen is drawer
            drawer.query_one("#setting-target").focus()
            await pilot.press("enter", "ctrl+q")
            assert app.is_running and app.screen is not drawer
            await pilot.press("escape")
            app.push_screen(ChoicePicker([("A", "a")]))
            await pilot.pause()
            await pilot.press("ctrl+q")
            assert app.is_running and isinstance(app.screen, ChoicePicker)
            await pilot.press("ctrl+alt+q")
            assert not app.is_running
    asyncio.run(scenario())


def test_save_includes_visible_unapplied_evaluator_edit(settings_path):
    async def scenario():
        app = WidgetApp()
        async with app.run_test(size=(80, 24)) as pilot:
            drawer = SettingsDrawer()
            app.push_screen(drawer)
            await pilot.pause()
            drawer.query_one("#settings-evaluator-timeout", Input).value = "37"
            await pilot.pause()
            assert drawer._forms_dirty()
            drawer.save_settings()
            for _ in range(100):
                await pilot.pause(0.01)
                if not drawer._saving:
                    break
            assert load_yaml_config(settings_path)["scoring_evaluator"]["timeout"] == 37
            assert "Saved config" in str(drawer.query_one("#settings-status", Static).content)
    asyncio.run(scenario())


def test_edit_keys_copy_and_singleton_preserve_dirty_draft(settings_path):
    async def scenario():
        app = WidgetApp()
        async with app.run_test(size=(80, 24)) as pilot:
            drawer = SettingsDrawer()
            app.push_screen(drawer)
            await pilot.pause()
            drawer.action_edit_yaml()
            editor = drawer.query_one("#yaml-editor", TextArea)
            await pilot.press("ctrl+e")
            assert app.focused is editor
            field = drawer.query_one("#settings-evaluator-timeout", Input)
            field.value = "39"
            drawer.query_one("#settings-categories", OptionList).highlighted = 4
            drawer.enter_section()
            field.focus()
            field.select_all()
            await pilot.press("ctrl+c")
            assert app.clipboard == "39"
            drawer.action_open_launcher()
            await pilot.pause()
            app.screen._dispatch("settings")
            await pilot.pause()
            assert app.screen is drawer
            assert field.value == "39"
            assert sum(isinstance(screen, SettingsDrawer) for screen in app.screen_stack) == 1
            drawer.action_back()
            assert app.screen is drawer
            assert "Unsaved changes" in str(drawer.query_one("#settings-status", Static).content)
    asyncio.run(scenario())


def test_choice_select_uses_sheet_and_restores_calling_control():
    class SelectApp(WidgetApp):
        def compose(self):
            yield ChoiceSelect([("A", "a"), ("B", "b")], value="b", allow_blank=False)
    async def scenario():
        app = SelectApp()
        async with app.run_test() as pilot:
            control = app.query_one(Select)
            control.focus()
            await pilot.press("enter")
            await pilot.pause()
            assert isinstance(app.screen, ChoicePicker)
            assert app.screen.query_one(OptionList).highlighted == 1
            await pilot.press("up", "enter")
            await pilot.pause()
            assert control.value == "a"
            assert app.focused is control
    asyncio.run(scenario())


@pytest.mark.parametrize("size", [(160, 48), (120, 30), (80, 24), (60, 18)])
def test_typed_setting_child_returns_to_row_and_save_remains_visible(settings_path, size):
    from pathlib import Path
    from tesis.tui_editors import FieldEditor
    async def scenario():
        app = WidgetApp()
        async with app.run_test(size=size) as pilot:
            original = settings_path.read_bytes()
            drawer = SettingsDrawer()
            app.push_screen(drawer)
            await pilot.pause()
            drawer.query_one("#settings-categories", OptionList).highlighted = 5
            drawer.enter_section()
            row = drawer.query_one("#setting-budget")
            row.focus()
            await pilot.press("enter")
            await pilot.pause()
            assert isinstance(app.screen, FieldEditor)
            field = app.screen.query_one(Input)
            field.value = "7"
            await pilot.press("enter")
            await pilot.pause()
            assert app.screen is drawer and app.focused is row
            from tesis.config_loader import parse_yaml_config
            assert parse_yaml_config(drawer.query_one("#yaml-editor", TextArea).text)["candidate_budget"] == 7
            assert settings_path.read_bytes() == original, "Staging a row must never save configuration"
            assert "Unsaved" in str(drawer.query_one("#settings-draft-state", Static).content)
            save = drawer.query_one("#settings-save", Button)
            assert save.region.bottom <= size[1]
            assert save.region.width > 0
            if size[0] < 120:
                assert not drawer.query_one("#settings-categories").display
            captures = Path("results/validation/keyboard-audit")
            captures.mkdir(parents=True, exist_ok=True)
            (captures / f"settings-{size[0]}x{size[1]}.svg").write_text(app.export_screenshot())
    asyncio.run(scenario())


def test_launch_steps_restore_row_and_escape_never_starts(settings_path):
    from tesis.tui_forms import LaunchDrawer
    from tesis.tui_editors import FieldEditor
    async def scenario():
        app = WidgetApp()
        async with app.run_test(size=(80, 24)) as pilot:
            drawer = LaunchDrawer()
            app.push_screen(drawer)
            await pilot.pause()
            row = drawer.query_one("#row-launch-field-target-url")
            row.focus()
            await pilot.press("enter")
            assert isinstance(app.screen, FieldEditor)
            await pilot.press("escape", "ctrl+f8")
            await pilot.pause()
            assert drawer._step == 1
            await pilot.press("escape")
            assert drawer._step == 0 and app.focused is row
            await pilot.press("ctrl+f8", "ctrl+f8", "ctrl+f8")
            assert drawer._step == 3 and drawer._frozen is None
            assert app.focused is not drawer.query_one("#launch-start")
            drawer._goto_step(2)
            drawer.open_advanced()
            await pilot.press("ctrl+f8", "escape")
            assert drawer._step == 2, "Review Back restores the prior Runtime child"
            await pilot.press("escape")
            assert drawer._step == 2 and drawer.query_one("#launch-advanced").collapsed
            await pilot.press("escape")
            assert drawer._step == 1
    asyncio.run(scenario())


def test_provider_filter_preserves_highlight_identity_and_effort(tmp_path):
    from tesis.tui_providers import ProviderDrawer
    from tesis.tui_reasoning import ReasoningControl
    from textual.widgets import DataTable
    async def scenario():
        app = WidgetApp()
        async with app.run_test(size=(80, 24)) as pilot:
            drawer = ProviderDrawer(config_path=tmp_path / "config.yaml", provider_id="gateway", entries={
                "gateway": {"base_url": "https://gateway.invalid/v1", "protocol": "openai_compatible",
                            "models": ["alpha", "beta", "gamma"]}})
            app.push_screen(drawer)
            await pilot.pause()
            table = drawer.query_one("#provider-models", DataTable)
            table.move_cursor(row=1)
            reasoning = drawer.query_one(ReasoningControl)
            reasoning.query_one(Select).value = "high"
            await pilot.pause()
            drawer.query_one("#provider-filter", Input).value = "beta"
            await pilot.pause()
            assert table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value == "beta"
            assert reasoning.query_one(Select).value == "high"
            drawer.query_one("#provider-filter", Input).value = ""
            await pilot.pause()
            assert table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value == "beta"
    asyncio.run(scenario())


def test_candidate_decisions_stay_with_identity_and_grade_keys_are_local(monkeypatch, tmp_path):
    from tesis.tui_drawers import GradeRow, ReviewDrawer
    monkeypatch.setattr(ReviewDrawer, "load_review", lambda self: None)
    async def scenario():
        app = WidgetApp()
        async with app.run_test(size=(80, 24)) as pilot:
            drawer = ReviewDrawer(tmp_path / "unused.json")
            app.push_screen(drawer)
            await pilot.pause()
            drawer.queue = {"candidates": [{"candidate_id": cid, "status": "pending_review", "proof_ceiling": 4,
                                            "candidate": {}, "evidence_refs": [], "evidence": {}} for cid in ("a", "b")]}
            picker = drawer.query_one("#review-candidate", Select)
            picker.set_options([("A", "a"), ("B", "b")])
            picker.value = "a"
            drawer.filter_candidates()
            drawer.open_candidate()
            await pilot.pause()
            assert app.focused is drawer.query_one(GradeRow)
            await pilot.press("3")
            assert drawer.query_one("#review-score", Select).value is Select.NULL
            await pilot.press("alt+3")
            drawer.query_one("#review-reason", Input).value = "Evidence for A"
            await pilot.pause()
            picker.value = "b"
            await pilot.pause()
            assert drawer.query_one("#review-score", Select).value is Select.NULL
            assert drawer.query_one("#review-reason", Input).value == ""
            reason = drawer.query_one("#review-reason", Input)
            reason.focus()
            await pilot.press("4")
            assert reason.value == "4"
            assert drawer.query_one("#review-score", Select).value is Select.NULL
            picker.value = "a"
            await pilot.pause()
            assert drawer.query_one("#review-score", Select).value == 3
            assert reason.value == "Evidence for A"
    asyncio.run(scenario())


def test_resize_below_floor_preserves_dirty_workspace_and_recovers(settings_path):
    from pathlib import Path
    async def scenario():
        app = WidgetApp()
        async with app.run_test(size=(80, 24)) as pilot:
            drawer = SettingsDrawer()
            app.push_screen(drawer)
            await pilot.pause()
            editor = drawer.query_one("#yaml-editor", TextArea)
            editor.text += "\n# retained draft\n"
            await pilot.resize_terminal(59, 17)
            await pilot.pause()
            assert app.screen is drawer
            assert drawer.has_class("too-small")
            assert drawer.query_one("#drawer-size-notice").region.height > 0
            assert not drawer.query_one("#settings-save").visible or drawer.query_one("#settings-save").region.width == 0
            captures = Path("results/validation/keyboard-audit")
            captures.mkdir(parents=True, exist_ok=True)
            (captures / "settings-59x17.svg").write_text(app.export_screenshot())
            await pilot.resize_terminal(80, 24)
            await pilot.pause()
            assert not drawer.has_class("too-small")
            assert "# retained draft" in editor.text
            assert drawer.query_one("#settings-save").region.width > 0
    asyncio.run(scenario())


def test_results_search_filters_and_detail_back_preserve_artifact_identity(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from textual.widgets import DataTable
    from tesis.tui_drawers import ResultsDrawer
    from tesis.tui_filters import FilterPage
    monkeypatch.setattr(ResultsDrawer, "refresh_scan", lambda self: None)
    monkeypatch.setattr(ResultsDrawer, "_load_artifact", lambda *_: {})
    async def scenario():
        app = WidgetApp()
        async with app.run_test(size=(60, 18)) as pilot:
            drawer = ResultsDrawer()
            app.push_screen(drawer)
            await pilot.pause()
            items = [SimpleNamespace(path=tmp_path / f"{name}.json", run_id=name, execution_id=name,
                                     provider=provider, surface="sqli", status="completed", security_level="low",
                                     payload_mode="hybrid") for name, provider in (("alpha", "one"), ("beta", "two"))]
            drawer._render_scan(drawer._scan_generation, items, None)
            table = drawer.query_one("#results-table", DataTable)
            assert table.row_count == 2
            table.move_cursor(row=1)
            identity = table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value
            query = drawer.query_one("#results-query", Input)
            query.value = "beta"
            await pilot.pause()
            assert table.row_count == 1
            assert table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value == identity
            query.focus()
            await pilot.press("enter")
            assert drawer._selected_item is items[1]
            await pilot.press("escape")
            assert query.value == "beta" and table.display
            drawer.open_filters()
            await pilot.pause()
            assert isinstance(app.screen, FilterPage)
            app.screen.query_one("#filter-provider", Select).value = "two"
            app.screen.apply()
            await pilot.pause()
            assert drawer._filters["provider"] == "two"
            assert table.row_count == 1
            drawer.clear_filters()
            assert not drawer._filters
    asyncio.run(scenario())


def test_ctrl_s_inside_field_editor_stages_and_saves_once(settings_path, monkeypatch):
    import tesis.provider_settings as persistence
    saves = []
    real_save = persistence.save_provider_settings
    def counted(*args, **kwargs):
        saves.append(1)
        return real_save(*args, **kwargs)
    monkeypatch.setattr(persistence, "save_provider_settings", counted)
    async def scenario():
        app = WidgetApp()
        async with app.run_test(size=(80, 24)) as pilot:
            drawer = SettingsDrawer()
            app.push_screen(drawer)
            await pilot.pause()
            drawer.query_one("#setting-target").focus()
            await pilot.press("enter")
            app.screen.query_one(Input).value = "http://localhost/updated-dvwa"
            await pilot.press("ctrl+s")
            for _ in range(100):
                await pilot.pause(0.01)
                if saves and not drawer._saving:
                    break
            assert saves == [1]
            assert load_yaml_config(settings_path)["target_url"] == "http://localhost/updated-dvwa"
    asyncio.run(scenario())


def test_review_next_pending_uses_validated_workflow_grades(tmp_path, monkeypatch):
    from tesis.tui_drawers import ReviewDrawer
    monkeypatch.setattr(ReviewDrawer, "load_review", lambda self: None)
    async def scenario():
        app = WidgetApp()
        async with app.run_test(size=(80, 24)) as pilot:
            drawer = ReviewDrawer(tmp_path / "unused.json")
            app.push_screen(drawer)
            await pilot.pause()
            queue = {"selection": "human", "evaluator": None, "rubric_version": "scoring.v4", "source_sha256": "frozen",
                     "component_pending_reasons": {}, "candidates": [
                         {"candidate_id": cid, "status": "pending_review", "proof_ceiling": 4,
                          "candidate": {}, "evidence_refs": [], "evidence": {}} for cid in ("a", "b")]}
            base = {"status": "pending", "Spayload_final": None, "Srun_final": None, "reason": "pending_candidate_grades"}
            initial = {"workflows": {"human": {**base, "candidate_grades": [{"candidate_id": cid, "score": None} for cid in ("a", "b")]}}}
            drawer._loaded(queue, [], initial)
            await pilot.pause()
            assert drawer._active_candidate == "a"
            drawer.query_one("#review-score", Select).value = 3
            drawer.query_one("#review-reason", Input).value = "A evidence"
            completed_a = {"workflows": {"human": {**base, "candidate_grades": [
                {"candidate_id": "a", "score": 3}, {"candidate_id": "b", "score": None}]}}}
            drawer._loaded(queue, [], completed_a)
            await pilot.pause()
            assert drawer._active_candidate == "b"
            assert drawer.query_one("#review-score", Select).value is Select.NULL
            assert drawer.query_one("#review-reason", Input).value == ""
    asyncio.run(scenario())


def test_reopening_root_unwinds_deep_children_by_identity(settings_path):
    from textual.widgets import Label
    from tesis.tui_commands import BaseDrawer
    class Child(BaseDrawer):
        def compose(self):
            yield Label("Child")
    async def scenario():
        app = WidgetApp()
        async with app.run_test() as pilot:
            root = SettingsDrawer()
            app.push_screen(root)
            await pilot.pause()
            editor = root.query_one("#yaml-editor", TextArea)
            editor.text += "\n# same draft\n"
            for _ in range(7):
                app.push_screen(Child())
                await pilot.pause()
            open_workspace(app, SettingsDrawer())
            await pilot.pause()
            assert app.screen is root
            assert "# same draft" in editor.text
            assert len(app.screen_stack) == 2
    asyncio.run(scenario())


def test_save_includes_chatgpt_manual_model_without_separate_apply(settings_path):
    async def scenario():
        app = WidgetApp()
        async with app.run_test() as pilot:
            drawer = SettingsDrawer()
            app.push_screen(drawer)
            await pilot.pause()
            drawer.query_one("#settings-chatgpt-manual", Input).value = "exact-future-model"
            await pilot.pause()
            drawer.save_settings()
            for _ in range(100):
                await pilot.pause(0.01)
                if not drawer._saving:
                    break
            saved = load_yaml_config(settings_path)
            assert saved["models"]["openai_codex_auth"]["model_name"] == "exact-future-model"
            assert saved["models"]["openai_codex_auth"]["extra"]["account"] == "default"
            assert saved["provider"] == "saved"
    asyncio.run(scenario())


def test_interrupt_cancels_local_auth_without_leaving_dirty_settings(settings_path, monkeypatch):
    from tesis.tui_auth import ChatGPTAuth
    from tesis.tui_commands import interrupt_context
    monkeypatch.setattr(ChatGPTAuth, "_start", lambda *_: None)
    async def scenario():
        app = WidgetApp()
        async with app.run_test() as pilot:
            drawer = SettingsDrawer()
            app.push_screen(drawer)
            await pilot.pause()
            drawer.query_one("#yaml-editor", TextArea).text += "\n# draft survives\n"
            auth = drawer.query_one(ChatGPTAuth)
            auth._action = "login"
            interrupt_context(drawer)
            await pilot.pause()
            assert not auth.busy and app.screen is drawer
            assert "# draft survives" in drawer.query_one("#yaml-editor", TextArea).text
    asyncio.run(scenario())


def test_model_detail_support_is_explicit_and_survives_staging(tmp_path, monkeypatch):
    from textual.widgets import DataTable
    from tesis.tui_providers import ModelDetailPage, ProviderDrawer
    from tesis.tui_reasoning import ReasoningControl
    calls = []
    monkeypatch.setattr("tesis.tui_reasoning.probe_reasoning", lambda *args: calls.append(args))
    async def scenario():
        app = WidgetApp()
        async with app.run_test(size=(80, 24)) as pilot:
            drafts = []
            drawer = ProviderDrawer(config_path=tmp_path / "config.yaml", provider_id="gateway", entries={"gateway": {
                "protocol": "openai_compatible", "base_url": "https://gateway.invalid/v1", "api_key": "offline",
                "models": ["unknown-model"]}})
            app.push_screen(drawer, drafts.append)
            await pilot.pause()
            drawer.query_one("#provider-models", DataTable).action_select_cursor()
            await pilot.pause()
            detail = app.screen
            assert isinstance(detail, ModelDetailPage)
            control = detail.query_one(ReasoningControl)
            control.query_one(Select).value = "high"
            await pilot.pause()
            assert not calls
            assert detail.query_one("#model-stage", Button).disabled
            control.check_support()
            for _ in range(100):
                await pilot.pause(0.01)
                if control._checked:
                    break
            assert len(calls) == 1
            detail.stage_model()
            await pilot.pause()
            drawer.apply_provider()
            await pilot.pause()
            assert drafts[0].entry["model_options"]["unknown-model"]["reasoning_effort"] == "high"
            assert len(calls) == 1
    asyncio.run(scenario())


def test_url_child_never_renders_query_secret_and_round_trips_on_stage(settings_path):
    from tesis.config_loader import parse_yaml_config
    async def scenario():
        app = WidgetApp()
        async with app.run_test() as pilot:
            drawer = SettingsDrawer()
            app.push_screen(drawer)
            await pilot.pause()
            original = settings_path.read_bytes()
            drawer.query_one("#setting-target").focus()
            await pilot.press("enter")
            editor = app.screen.query_one(Input)
            editor.value = "http://localhost/dvwa?token=private-url-fixture"
            await pilot.pause()
            assert "private-url-fixture" not in editor.value
            assert "private-url-fixture" not in app.export_screenshot()
            await pilot.press("enter")
            await pilot.pause()
            draft = parse_yaml_config(drawer.query_one("#yaml-editor", TextArea).text)
            from tesis.tui_security import _restore_yaml_secrets
            restored = _restore_yaml_secrets(draft, drawer.preserved_secret_placeholders)
            assert restored["target_url"] == "http://localhost/dvwa?token=private-url-fixture"
            assert settings_path.read_bytes() == original
    asyncio.run(scenario())


def test_choice_child_preserves_query_through_below_floor_resize():
    async def scenario():
        app = WidgetApp()
        async with app.run_test(size=(80, 24)) as pilot:
            picker = ChoicePicker([("Alpha", "a"), ("Beta", "b")])
            app.push_screen(picker)
            await pilot.pause()
            await pilot.press("b")
            await pilot.resize_terminal(59, 17)
            await pilot.pause()
            assert picker.has_class("too-small")
            assert picker.query_one("#choice-size-notice").region.height > 0
            assert picker.query_one(Input).value == "b"
            await pilot.resize_terminal(80, 24)
            await pilot.pause()
            assert app.screen is picker and app.focused is picker.query_one(Input)
            assert picker.filtered_choices == [("Beta", "b")]
    asyncio.run(scenario())


def test_plan_setup_reuses_existing_launch_draft(settings_path):
    from tesis.tui_drawers import PlanDrawer
    from tesis.tui_forms import LaunchDrawer
    async def scenario():
        app = WidgetApp()
        async with app.run_test(size=(80, 24)) as pilot:
            launch = LaunchDrawer()
            app.push_screen(launch)
            await pilot.pause()
            launch.query_one("#launch-field-target-url", Input).value = "http://localhost/retained-dvwa"
            await pilot.pause()
            plan = PlanDrawer(config=launch._resolved_config())
            app.push_screen(plan)
            await pilot.pause()
            plan.query_one("#plan-run", Button).press()
            await pilot.pause()
            assert app.screen is launch
            assert launch._cli_args()["target"] == "http://localhost/retained-dvwa"
            assert sum(isinstance(screen, LaunchDrawer) for screen in app.screen_stack) == 1
    asyncio.run(scenario())


def test_launch_explicit_role_inherit_clears_saved_profile(settings_path):
    from tesis.tui_forms import LaunchDrawer
    payload = load_yaml_config(settings_path)
    payload['llm_runtime'] = {'roles': {'orchestrator': {'model_profile': 'saved'}}}
    save_yaml_config(settings_path, payload)
    async def scenario():
        app = WidgetApp()
        async with app.run_test(size=(80, 24)) as pilot:
            drawer = LaunchDrawer()
            app.push_screen(drawer)
            await pilot.pause()
            drawer._goto_step(2)
            drawer.open_advanced()
            row = drawer.query_one('#row-launch-orchestrator-profile')
            row.focus()
            await pilot.press('enter', 'home', 'enter')
            await pilot.pause()
            assert app.screen is drawer
            assert drawer.query_one('#launch-orchestrator-profile', Select).value is Select.NULL
            assert drawer._resolved_config(fresh=True).llm_runtime.roles['orchestrator'].model_profile is None
    asyncio.run(scenario())
