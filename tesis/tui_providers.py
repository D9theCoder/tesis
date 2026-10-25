"""Guided API-key provider editor with asynchronous model discovery."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path
from threading import Thread
from typing import Any

from rich.text import Text
from textual import on
from textual.app import ComposeResult
from textual.containers import Horizontal, VerticalScroll
from textual.message import Message
from textual.widgets import Button, DataTable, Input, Label, Select, Static

from llm.model_catalog import fetch_models
from tesis.provider_registry import API_PROTOCOLS, provider_key_variable, validate_provider_entry
from tesis.provider_settings import resolved_provider_key
from tesis.tui_commands import BaseDrawer
from tesis.tui_security import _safe_url


@dataclass
class ProviderDraft:
    provider_id: str
    entry: dict[str, Any]
    keys: dict[str, str] = field(default_factory=dict, repr=False)


class CatalogLoaded(Message):
    def __init__(self, generation: int, models: list[dict[str, str]], error: str | None):
        super().__init__()
        self.generation, self.models, self.error = generation, models, error


class ModelCatalogTable(DataTable):
    BINDINGS = [("space", "select_cursor", "Toggle model")]


class ProviderDrawer(BaseDrawer):
    """A draft only. Settings Save commits the provider and its dotenv key."""

    def __init__(self, *, config_path: Path, entries: dict[str, Any], provider_id: str = "",
                 pending_keys: dict[str, str] | None = None):
        super().__init__()
        self._config_path = config_path
        self._entries = deepcopy(entries)
        self._provider_id = provider_id
        self._entry = dict(entries.get(provider_id) or {})
        self._pending_keys = dict(pending_keys or {})
        self._selected = set(self._entry.get("models") or [])
        self._models = {model: model for model in self._entry.get("models") or []}
        self._generation = 0
        self._closed = False
        self._url_seeds = {key: _safe_url(self._entry.get(key) or "") for key in ("base_url", "fetch_url")}

    def compose(self) -> ComposeResult:
        yield Label("Edit API provider" if self._provider_id else "Add API provider", classes="drawer-title")
        with VerticalScroll(id="provider-fields", classes="drawer-body"):
            yield Label("Provider ID (a-z, 0-9, _ or -; starts with a letter)")
            yield Input(value=self._provider_id, disabled=bool(self._provider_id), id="provider-id")
            yield Label("Display name (optional)")
            yield Input(value=str(self._entry.get("display_name") or ""), id="provider-name")
            yield Label("Base URL")
            yield Input(value=self._url_seeds["base_url"],
                        placeholder="https://gateway.example/v1", id="provider-url")
            yield Label("API protocol")
            yield Select([(label, value) for value, label in API_PROTOCOLS.items()],
                         value=self._entry.get("protocol", "openai_compatible"),
                         allow_blank=False, id="provider-protocol")
            yield Label("API key (saved to .env when Settings is saved)")
            yield Input(password=True, placeholder="Leave blank to keep saved key" if self._entry else "API key",
                        id="provider-key")
            yield Label("Fetch URL (optional; defaults to the protocol's models endpoint)")
            yield Input(value=self._url_seeds["fetch_url"],
                        placeholder="https://gateway.example/v1/models", id="provider-fetch-url")
            yield Button("Fetch available models", id="provider-fetch")
            yield Static("Fetch a catalog or add model IDs manually. Space/Enter toggles a row.",
                         id="provider-status", markup=False)
            yield Input(placeholder="Filter model IDs or names", id="provider-filter")
            yield ModelCatalogTable(id="provider-models", cursor_type="row", show_row_labels=False)
            with Horizontal(classes="provider-actions"):
                yield Button("Select shown", id="provider-select-shown")
                yield Button("Ignore shown", id="provider-ignore-shown")
            yield Static("", id="provider-selection", markup=False)
            yield Label("Manual model ID")
            yield Input(placeholder="Exact model ID", id="provider-manual")
            yield Button("Add model", id="provider-add-model")
        with Horizontal(classes="provider-actions", id="provider-footer"):
            yield Button("Apply provider", id="provider-apply", variant="primary")
            yield Button("Cancel", id="provider-cancel")

    def on_mount(self) -> None:
        self.query_one("#provider-models", DataTable).add_columns("Use", "Model")
        self._render_models()
        self.query_one("#provider-url" if self._provider_id else "#provider-id", Input).focus()

    def _status(self, text: str) -> None:
        self.query_one("#provider-status", Static).update(text)

    def _visible_models(self) -> list[str]:
        search = self.query_one("#provider-filter", Input).value.casefold().strip()
        return [model for model, display in self._models.items()
                if search in model.casefold() or search in display.casefold()]

    def _render_models(self) -> None:
        table = self.query_one("#provider-models", DataTable)
        table.clear()
        for model in self._visible_models():
            table.add_row("x" if model in self._selected else " ", Text(model), key=model)
        self.query_one("#provider-selection", Static).update(
            f"{len(self._selected)} selected; {len(self._visible_models())} shown. Unchecked models are ignored.")

    @on(Input.Changed, "#provider-filter")
    def filter_models(self) -> None:
        self._render_models()

    @on(DataTable.RowSelected, "#provider-models")
    def toggle_model(self, event: DataTable.RowSelected) -> None:
        model = str(event.row_key.value)
        if model in self._selected:
            self._selected.remove(model)
        else:
            self._selected.add(model)
        table = self.query_one("#provider-models", DataTable)
        table.update_cell(model, table.ordered_columns[0].key, "x" if model in self._selected else " ")
        self.query_one("#provider-selection", Static).update(f"{len(self._selected)} selected.")

    @on(Button.Pressed, "#provider-select-shown")
    def select_shown(self) -> None:
        self._selected.update(self._visible_models())
        self._render_models()

    @on(Button.Pressed, "#provider-ignore-shown")
    def ignore_shown(self) -> None:
        self._selected.difference_update(self._visible_models())
        self._render_models()

    @on(Button.Pressed, "#provider-add-model")
    @on(Input.Submitted, "#provider-manual")
    def add_model(self) -> None:
        widget = self.query_one("#provider-manual", Input)
        model = widget.value.strip()
        if not model or any(c.isspace() or ord(c) < 32 for c in model):
            self._status("Enter a nonempty model ID without spaces or control characters.")
            return
        self._models[model] = model
        self._selected.add(model)
        widget.value = ""
        self.query_one("#provider-filter", Input).value = ""
        self._render_models()

    def _draft(self) -> ProviderDraft:
        provider_id = self.query_one("#provider-id", Input).value.strip()
        entry = dict(self._entry)
        entry.update(display_name=self.query_one("#provider-name", Input).value.strip() or provider_id,
                     base_url=self.query_one("#provider-url", Input).value.strip(),
                     protocol=str(self.query_one("#provider-protocol", Select).value),
                     fetch_url=self.query_one("#provider-fetch-url", Input).value.strip(),
                     models=[model for model in self._models if model in self._selected])
        key = self.query_one("#provider-key", Input).value
        stored_key = str(self._entry.get("api_key") or "")
        if not key and stored_key and not stored_key.startswith("${"):
            key = stored_key
        for name in self._url_seeds:
            if entry[name] == self._url_seeds[name] and name in self._entry:
                entry[name] = self._entry[name]
        keys: dict[str, str] = {}
        if key:
            if any(c in key for c in "\r\n\0"):
                raise ValueError("API keys must be single-line values.")
            variable = provider_key_variable(provider_id)
            entry["api_key"] = f"${{{variable}}}"
            keys[variable] = key
        return ProviderDraft(provider_id, entry, keys)

    @on(Input.Changed, "#provider-url, #provider-fetch-url, #provider-key")
    @on(Select.Changed, "#provider-protocol")
    def connection_changed(self) -> None:
        self._generation += 1
        self.query_one("#provider-fetch", Button).disabled = False

    @on(Button.Pressed, "#provider-fetch")
    def fetch_catalog(self) -> None:
        try:
            draft = self._draft()
            # Validate URLs/protocol before starting the worker, allowing an empty draft model list.
            from llm.model_catalog import catalog_url
            catalog_url(draft.entry["base_url"], draft.entry["protocol"], draft.entry["fetch_url"])
        except ValueError as exc:
            self._status(str(exc))
            return
        self._generation += 1
        generation = self._generation
        self._status("Loading models from the configured fetch URL...")
        self.query_one("#provider-fetch", Button).disabled = True

        def fetch() -> None:
            models, error = [], None
            try:
                key = resolved_provider_key(draft.entry, self._config_path, {**self._pending_keys, **draft.keys})
                models = fetch_models(base_url=draft.entry["base_url"], protocol=draft.entry["protocol"],
                                      fetch_url=draft.entry["fetch_url"], api_key=key,
                                      cancelled=lambda: self._closed or generation != self._generation)
            except ValueError as exc:
                error = str(exc)
            except Exception:
                error = "Unable to load models. Retry or add model IDs manually."
            if not self._closed:
                self.post_message(CatalogLoaded(generation, models, error))

        Thread(target=fetch, daemon=True, name="tesis-api-models").start()

    @on(CatalogLoaded)
    def catalog_loaded(self, message: CatalogLoaded) -> None:
        if self._closed or message.generation != self._generation:
            return
        self.query_one("#provider-fetch", Button).disabled = False
        if message.error:
            self._status(message.error)
            return
        # Saved/manual IDs survive discovery. Only explicit selection persists a fetched model.
        self._models.update({model["id"]: model["display_name"] for model in message.models})
        self._render_models()
        self._status(f"{len(message.models)} models returned. Select models to keep; existing IDs are retained."
                     if message.models else "The endpoint returned no models. Add IDs manually.")

    @on(Button.Pressed, "#provider-apply")
    def apply_provider(self) -> None:
        try:
            draft = self._draft()
            if draft.provider_id in self._entries and draft.provider_id != self._provider_id:
                raise ValueError("This provider ID already exists. Edit the existing provider or choose a new ID.")
            validate_provider_entry(draft.provider_id, draft.entry)
        except ValueError as exc:
            self._status(str(exc))
            return
        self.query_one("#provider-key", Input).value = ""
        self.dismiss(draft)

    @on(Button.Pressed, "#provider-cancel")
    def cancel(self) -> None:
        self.dismiss(None)

    def prepare_shutdown(self) -> None:
        self._closed = True
        self._generation += 1

    def on_unmount(self) -> None:
        self.prepare_shutdown()
