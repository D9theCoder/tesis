"""Account controls backed by the same isolated OAuth commands as the CLI."""

from __future__ import annotations

import asyncio
import json
import sys
from typing import Any, Literal
from urllib.parse import urlsplit

from textual import on, work
from textual.app import ComposeResult
from textual.containers import Vertical
from textual.message import Message
from textual.widgets import Button, Label, Static, TextArea

from tesis import tui_state
from tesis.tui_security import redact_secrets
from tesis.tui_widgets import KeyboardActions


class ChatGPTAuth(Vertical):
    """Keep browser authorization and one-time URLs outside configuration drafts."""

    DEFAULT_CSS = """
    ChatGPTAuth { height: auto; margin-bottom: 1; }
    ChatGPTAuth Static { height: auto; }
    ChatGPTAuth .auth-url { height: 3; margin-top: 1; }
    """

    class Changed(Message):
        """The parent invalidates account-bound model catalogs on auth changes."""

    def __init__(self, account: str, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.account = account
        self._generation = 0
        self._action: str | None = None
        self._worker = None
        self._process: asyncio.subprocess.Process | None = None
        self._closing = False
        self._url = ""

    @property
    def busy(self) -> bool:
        return self._action in {"login", "logout"}

    @property
    def signing_out(self) -> bool:
        return self._action == "logout"

    def compose(self) -> ComposeResult:
        yield Static("Checking saved account...", id="chatgpt-auth-status", markup=False)
        with KeyboardActions(classes="compact-actions"):
            yield Button("Sign in", id="chatgpt-auth-login")
            yield Button("Sign out", id="chatgpt-auth-logout")
            yield Button("Check status", id="chatgpt-auth-check")
        yield Label("If the browser did not open, copy this URL into a browser on this computer.",
                    id="chatgpt-auth-url-label", classes="field-label")
        yield TextArea("", read_only=True, soft_wrap=False, id="chatgpt-auth-url", classes="auth-url")
        with KeyboardActions(id="chatgpt-auth-flow-actions", classes="compact-actions"):
            yield Button("Copy URL", id="chatgpt-auth-copy", disabled=True)
            yield Button("Cancel sign-in", id="chatgpt-auth-cancel", disabled=True)

    def on_mount(self) -> None:
        self._show_url("")
        self._start("status")

    def set_account(self, account: str) -> None:
        if account == self.account:
            return
        was_busy = self.busy
        self._stop()
        self.account = account
        self._start("status")
        if was_busy:
            self.post_message(self.Changed())

    def _status(self, text: str) -> None:
        self.query_one("#chatgpt-auth-status", Static).update(str(redact_secrets(text)))

    def _show_url(self, url: str) -> None:
        self._url = url
        self.query_one("#chatgpt-auth-url", TextArea).text = url
        self.query_one("#chatgpt-auth-url").display = bool(url)
        self.query_one("#chatgpt-auth-url-label").display = bool(url)
        self.query_one("#chatgpt-auth-copy", Button).display = bool(url)
        self.query_one("#chatgpt-auth-copy", Button).disabled = not url

    def _controls(self) -> None:
        for selector in ("login", "logout", "check"):
            self.query_one(f"#chatgpt-auth-{selector}", Button).disabled = self.busy or not self.account
        self.query_one("#chatgpt-auth-cancel", Button).disabled = self._action != "login"
        self.query_one("#chatgpt-auth-cancel").display = self._action == "login"
        self.query_one("#chatgpt-auth-flow-actions").display = self._action == "login" or bool(self._url)

    def _stop(self) -> None:
        self._generation += 1
        if self._process is not None and self._process.returncode is None:
            try:
                self._process.kill()
            except ProcessLookupError:
                pass
        if self._worker is not None:
            self._worker.cancel()
            self._worker = None
        self._action = None

    def _start(self, action: Literal["status", "login", "logout"]) -> None:
        self._stop()
        self._show_url("")
        if not self.account:
            self._status("Enter a local account label to sign in.")
            self._controls()
            return
        self._action = action
        self._controls()
        self._status({"status": "Checking saved account...", "login": "Starting browser sign-in...",
                      "logout": "Signing out and revoking the session..."}[action])
        if self.busy:
            self.post_message(self.Changed())
        self._worker = self._run(self._generation, action, self.account)

    @work(group="chatgpt-auth")
    async def _run(self, generation: int, action: str, account: str) -> None:
        process = None
        finished = False
        try:
            if action == "status":
                await asyncio.sleep(0.25)  # Coalesce account-label edits before starting a process.
            command = [sys.executable, "-m", "tesis", "auth", action, "--account", account]
            if action != "status":
                command.append("--json-events")
            if action == "login":
                command.append("--enable-plan-usage")
            process = await asyncio.create_subprocess_exec(
                *command, cwd=str(tui_state.REPOSITORY_ROOT),
                stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            if generation != self._generation or self._closing:
                return
            self._process = process
            async with asyncio.timeout(360 if action == "login" else 150):
                if action == "status":
                    output, _ = await process.communicate()
                    if process.returncode != 0:
                        raise ValueError("Account status unavailable")
                    self._render_account(json.loads(output)[account], account)
                    finished = True
                else:
                    async for line in process.stdout:
                        event = json.loads(line)
                        if generation != self._generation or self._closing:
                            return
                        kind = event.get("event")
                        if kind == "authorize":
                            url = str(event["url"])
                            parsed = urlsplit(url)
                            if parsed.scheme != "https" or parsed.netloc != "auth.openai.com":
                                raise ValueError("Unsafe authorization URL")
                            self._show_url(url)
                            self._status("Finish sign-in in your browser within five minutes. "
                                         "Approve TESIS and ChatGPT plan usage.")
                        elif kind == "complete":
                            self._render_account(event["accounts"][account], account)
                            finished = True
                        elif kind == "signed_out":
                            self._status(f"{account}: signed out." if event["remote_revoked"] else
                                         f"{account}: signed out locally. Remote revocation was not confirmed. "
                                         "Disconnect TESIS in ChatGPT Settings.")
                            finished = True
                        elif kind == "error":
                            self._status(str(event["message"]))
                            finished = True
                    await process.wait()
            if not finished:
                self._status("Account action could not finish. Check your connection and try again.")
        except asyncio.CancelledError:
            raise
        except TimeoutError:
            if generation == self._generation and not self._closing:
                self._status("Account action timed out. Check status before trying again.")
        except Exception:
            if generation == self._generation and not self._closing:
                self._status("Account action failed. Check your connection and private SIWC storage, then retry.")
        finally:
            if process is not None:
                if process.returncode is None:
                    try:
                        process.kill()
                    except ProcessLookupError:
                        pass
                await process.wait()
                if self._process is process:
                    self._process = None
            if generation == self._generation and not self._closing:
                changed = self.busy
                self._action = None
                self._worker = None
                self._show_url("")
                self._controls()
                if changed:
                    self.post_message(self.Changed())

    def _render_account(self, status: dict, account: str) -> None:
        if not status["signed_in"]:
            self._status(f"{account}: signed out. Choose Sign in to connect ChatGPT.")
        elif status["plan_usage"]:
            self._status(f"{account}: signed in. ChatGPT plan usage is enabled. Refresh models to choose one.")
        else:
            self._status(f"{account}: signed in. ChatGPT plan usage is disabled. "
                         "Sign in again and approve plan usage to use inference.")

    @on(Button.Pressed, "#chatgpt-auth-login")
    def login(self) -> None:
        if not self.busy:
            self._start("login")

    @on(Button.Pressed, "#chatgpt-auth-logout")
    def logout(self) -> None:
        if not self.busy:
            self._start("logout")

    @on(Button.Pressed, "#chatgpt-auth-check")
    def check_status(self) -> None:
        if not self.busy:
            self._start("status")

    @on(Button.Pressed, "#chatgpt-auth-copy")
    def copy_url(self) -> None:
        if self._url:
            self.app.copy_to_clipboard(self._url)

    @on(Button.Pressed, "#chatgpt-auth-cancel")
    def cancel_login(self) -> None:
        if self._action != "login":
            return
        self._stop()
        self._show_url("")
        self._controls()
        self._status("Sign-in canceled. Check status if browser approval had already finished.")
        self.post_message(self.Changed())

    def prepare_shutdown(self) -> None:
        self._closing = True
        self._stop()
        self._url = ""

    def on_unmount(self) -> None:
        self.prepare_shutdown()
