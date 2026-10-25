"""Explicit account-management commands for the official SIWC flow."""

from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import sys
import time
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
import webbrowser

from llm.siwc.oauth import SIWCSession
from llm.siwc.storage import SIWCError


def _without_identity_hint(url: str) -> str:
    """A manual browser URL must never expose a retained ID token."""
    parts = urlsplit(url)
    query = urlencode([(key, value) for key, value in parse_qsl(parts.query) if key != "id_token_hint"])
    return urlunsplit(parts._replace(query=query))


def browser_login(session: SIWCSession, account: str, *, port: int = 0,
                  no_browser: bool = False, consent: bool = False) -> dict:
    callbacks: list[str] = []

    class CallbackHandler(BaseHTTPRequestHandler):
        def log_message(self, *_args) -> None:
            pass  # The default request logger exposes authorization codes.

        def do_GET(self) -> None:
            if self.headers.get("Host") != f"127.0.0.1:{self.server.server_port}" or urlsplit(self.path).path != "/auth/callback":
                self.send_error(404)
                return
            callbacks.append(self.path)
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
            self.end_headers()
            self.wfile.write(b"Return to TESIS to see whether ChatGPT sign-in succeeded. You can close this tab.")

    class LoopbackServer(HTTPServer):
        def get_request(self):
            connection, address = super().get_request()
            connection.settimeout(2)
            return connection, address

    # Bind before constructing the authorize URL or opening the system browser.
    try:
        server = LoopbackServer(("127.0.0.1", port), CallbackHandler)
    except OSError:
        raise SIWCError("Unable to bind the SIWC loopback listener; choose another --port.") from None
    with server:
        redirect = f"http://127.0.0.1:{server.server_port}/auth/callback"
        attempt, url = session.begin(account, redirect, consent=consent)
        print("Continue with ChatGPT: approve TESIS and ChatGPT plan usage in your browser.", file=sys.stderr)
        opened = False
        if not no_browser:
            try:
                opened = webbrowser.open(url)
            except webbrowser.Error:
                pass
        if not opened:
            print("Open this one-time URL in a browser on this host:", file=sys.stderr)
            print(_without_identity_hint(url), file=sys.stderr)
        server.timeout = 0.5
        while not callbacks and time.time() < attempt.expires_at:
            server.handle_request()
        if not callbacks:
            raise SIWCError("ChatGPT sign-in timed out after five minutes; run auth login again.")
        return session.complete(attempt, callbacks[0])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="tesis auth", description="Manage official Sign in with ChatGPT accounts.")
    commands = parser.add_subparsers(dest="command", required=True)
    login = commands.add_parser("login", help="Continue with ChatGPT in the system browser")
    login.add_argument("--account", default="default", help="Local label; reuse it to reauthorize the same registration")
    login.add_argument("--port", type=int, default=0, help="Loopback port (default: an available port)")
    login.add_argument("--no-browser", action="store_true", help="Print a one-time URL for manual browser opening")
    login.add_argument("--enable-plan-usage", action="store_true", help="Explicitly request consent again for plan usage")
    status = commands.add_parser("status", help="Show saved account labels, connection status, and grant state")
    status.add_argument("--account", default=None)
    models = commands.add_parser("models", help="Fetch the selected account's current OpenAI model catalog")
    models.add_argument("--account", default="default")
    logout = commands.add_parser("logout", help="Revoke the renewable session and clear its local tokens")
    logout.add_argument("--account", default="default")
    args = parser.parse_args(argv)
    try:
        session = SIWCSession()
        if args.command == "login":
            if not 0 <= args.port <= 65535:
                parser.error("--port must be between 0 and 65535")
            result = browser_login(session, args.account, port=args.port,
                                   no_browser=args.no_browser, consent=args.enable_plan_usage)
            print(json.dumps(result, indent=2))
            if not result[args.account]["plan_usage"]:
                print("Identity connected. ChatGPT plan usage is disabled; inference is unavailable.", file=sys.stderr)
        elif args.command == "status":
            print(json.dumps(session.status(args.account), indent=2))
        elif args.command == "models":
            print(json.dumps(session.list_models(args.account), indent=2))
        elif args.command == "logout":
            if session.logout(args.account):
                print("Signed out. The saved client registration can be reused for later sign-in.")
            else:
                print("Signed out locally. Remote revocation was not confirmed; disconnect TESIS in ChatGPT Settings.", file=sys.stderr)
                return 1
    except KeyboardInterrupt:
        print("ChatGPT authorization cancelled.", file=sys.stderr)
        return 130
    except SIWCError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0
