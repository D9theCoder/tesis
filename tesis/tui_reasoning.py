"""Reusable effort selector with an explicit, asynchronous provider probe."""

from __future__ import annotations

from copy import deepcopy
from threading import Thread
from typing import Any

from textual import on
from textual.app import ComposeResult
from textual.containers import Vertical
from textual.message import Message
from textual.widgets import Button, Input, Select, Static

from llm.reasoning import FALLBACK_EFFORTS, validate_reasoning_effort


def probe_reasoning(profile: dict[str, Any], effort: str) -> None:
    """One harmless text request, through the same adapter as real inference."""
    from langchain_core.messages import HumanMessage
    from llm.provider import get_llm_from_model_config, supports_reasoning_effort
    from tesis.config_loader import _parse_model_configs

    provider = profile.get("provider", "")
    if not supports_reasoning_effort(provider):
        raise ValueError("This adapter cannot send reasoning effort; use provider default.")
    model = _parse_model_configs({"probe": profile})["probe"]
    get_llm_from_model_config(model, reasoning_effort=effort, max_retries=0,
        request_timeout=30, max_tokens=8192).invoke([HumanMessage(content="Reply with OK.")])


class ReasoningChecked(Message):
    def __init__(self, generation: int, error: str | None):
        super().__init__()
        self.generation, self.error = generation, error


class ReasoningControl(Vertical):
    """Unknown efforts require a successful probe for the current connection."""

    class Changed(Message):
        pass

    def __init__(self, *, id: str, modes: tuple[tuple[str, str], ...] = (("Provider default", "inherit"),)):
        super().__init__(id=id)
        self._modes = modes
        self._profiles: list[dict[str, Any]] = []
        self._efforts: list[str] | None = None
        self._generation = 0
        self._checked = False
        self._checking = False
        self._probe_closed = False
        self._reasoning_context: Any = None

    def compose(self) -> ComposeResult:
        yield Static("", markup=False, id=f"{self.id}-status")
        yield Select([*self._modes, *[(x, x) for x in FALLBACK_EFFORTS], ("Type another effort", "custom")],
                     value=self._modes[0][1], allow_blank=False, id=f"{self.id}-choice")
        yield Input(placeholder="Exact reasoning effort", id=f"{self.id}-custom")
        yield Button("Check reasoning support", id=f"{self.id}-check")

    def on_mount(self) -> None:
        self._update_visibility()

    @property
    def value(self) -> str | None:
        choice = self.query_one(Select).value
        if choice in {value for _, value in self._modes}:
            return None
        return validate_reasoning_effort(self.query_one(Input).value if choice == "custom" else choice)

    @property
    def mode(self) -> str:
        return str(self.query_one(Select).value)

    def configure(self, profiles: list[dict[str, Any]], efforts: list[str] | None,
                  *, value: str | None = None, reset: bool = False) -> None:
        profiles = [{key: item for key, item in profile.items()
                     if key not in {"reasoning_effort", "reasoning_efforts"}} for profile in profiles]
        context = (profiles, efforts)
        if context == self._reasoning_context and not reset:
            return
        self._reasoning_context = deepcopy(context)
        self._profiles, self._efforts = deepcopy(profiles), efforts
        picker = self.query_one(Select)
        old_mode = picker.value
        old_value = self.query_one(Input).value
        options = [*self._modes, *[(x, x) for x in (efforts if efforts is not None else FALLBACK_EFFORTS)],
                   ("Type another effort", "custom")]
        picker.set_options(options)
        if reset:
            picker.value = value if value in {v for _, v in options} else "custom" if value else self._modes[0][1]
            self.query_one(Input).value = value or ""
        else:
            picker.value = old_mode if old_mode in {v for _, v in options} else self._modes[0][1]
            self.query_one(Input).value = old_value
        self._invalidate()

    @on(Select.Changed)
    @on(Input.Changed)
    def effort_changed(self, event: Message) -> None:
        event.stop()
        self._invalidate()
        self.post_message(self.Changed())

    def _invalidate(self) -> None:
        self._generation += 1
        self._checked = self._checking = False
        self._update_visibility()
        self.query_one(Static).set_class(self._efforts is None, "unknown-model")
        self.query_one(Static).update("Unknown model, please set your own reasoning effort. Fallback choices are shown below; check support before applying."
                                      if self._efforts is None else "Model reasoning catalog loaded.")

    def _update_visibility(self) -> None:
        self.query_one(Input).display = self.mode == "custom"
        self.query_one(Button).disabled = self._checking or not self._profiles

    def ensure_ready(self) -> bool:
        effort = self.value
        if self.mode == "custom" and effort is None:
            raise ValueError("Enter a reasoning effort or choose provider default.")
        if effort is None or (self._efforts is not None and effort in self._efforts) or self._checked:
            return True
        if not self._checking:
            self.check_support()
        raise ValueError("Reasoning support check required. Wait for the result, then apply again.")

    @on(Button.Pressed)
    def check_support(self, event: Button.Pressed | None = None) -> None:
        if event:
            event.stop()
        try:
            effort = self.value
            if effort is None:
                self.query_one(Static).update("Choose or type an explicit effort to check.")
                return
            if not self._profiles:
                raise ValueError("Select a model with a configured connection first.")
        except ValueError as exc:
            self.query_one(Static).update(str(exc))
            return
        self._generation += 1
        generation, profiles = self._generation, deepcopy(self._profiles)
        self._checking, self._checked = True, False
        self._update_visibility()
        self.query_one(Static).update("Checking the selected model connection(s) with a short text request...")

        def check() -> None:
            error = None
            try:
                for profile in profiles:
                    if self._probe_closed or generation != self._generation:
                        return
                    probe_reasoning(profile, effort)
            except Exception as exc:
                status = getattr(exc, "status_code", None)
                error = (f"Provider did not confirm this effort (HTTP {status})." if status else
                         "Could not confirm this effort. Check model, effort, credentials, and connection.")
            if not self._probe_closed:
                self.post_message(ReasoningChecked(generation, error))

        Thread(target=check, daemon=True, name="tesis-reasoning-check").start()

    @on(ReasoningChecked)
    def checked(self, event: ReasoningChecked) -> None:
        event.stop()
        if self._probe_closed or event.generation != self._generation:
            return
        self._checking = False
        self._checked = event.error is None
        self._update_visibility()
        self.query_one(Static).set_class(bool(event.error), "unknown-model")
        self.query_one(Static).update(event.error or "Provider accepted the effort. Internal reasoning is unverified.")

    def on_unmount(self) -> None:
        self._probe_closed = True
        self._generation += 1
