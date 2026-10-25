"""Atomic, owner-only SIWC records and process-safe refresh serialization."""

from __future__ import annotations

from contextlib import contextmanager
import json
import os
from pathlib import Path
import stat
import tempfile
from typing import Any, Iterator
import uuid

from filelock import FileLock, Timeout


class SIWCError(RuntimeError):
    """A safe-to-display error. Credentials and authorization URLs are excluded."""


class CredentialStore:
    """One host ID and separate named account registrations in private storage.

    Call read/write only inside locked(). Never expose the returned document to
    logs, artifacts, or the CLI. The directory must not be shared between hosts.
    """

    def __init__(self, directory: str | Path | None = None):
        configured = directory or os.getenv("TESIS_SIWC_HOME")
        self.directory = Path(configured).expanduser() if configured else (
            Path(os.getenv("XDG_CONFIG_HOME", str(Path.home() / ".config"))) / "tesis" / "siwc"
        )
        self.path = self.directory / "accounts.json"

    @contextmanager
    def locked(self) -> Iterator[CredentialStore]:
        try:
            self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            info = self.directory.lstat()
            if not stat.S_ISDIR(info.st_mode) or (
                hasattr(os, "getuid") and info.st_uid != os.getuid()
            ):
                raise SIWCError("SIWC storage must be a private directory owned by the current user.")
            if os.name == "posix":
                self.directory.chmod(0o700)
            lock_path = self.directory / "accounts.lock"
            if lock_path.is_symlink():
                raise SIWCError("Refusing a symbolic link in SIWC storage.")
            with FileLock(lock_path, timeout=30, mode=0o600):
                yield self
        except Timeout:
            raise SIWCError("SIWC credentials are busy in another process; retry shortly.") from None
        except OSError:
            raise SIWCError("Unable to access private SIWC storage; check its ownership and permissions.") from None

    def read(self) -> dict[str, Any]:
        if self.path.is_symlink():
            raise SIWCError("Refusing a symbolic link in SIWC storage.")
        try:
            descriptor = os.open(self.path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        except FileNotFoundError:
            return {"version": 1, "host_id": f"urn:uuid:{uuid.uuid4()}", "profiles": {}}
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or (
                os.name == "posix" and (info.st_mode & 0o077 or info.st_uid != os.getuid())
            ):
                raise SIWCError("SIWC credential files must be owner-only (0600) regular files.")
            with os.fdopen(descriptor, encoding="utf-8") as handle:
                descriptor = -1
                document = json.load(handle)
        except (ValueError, TypeError):
            raise SIWCError("SIWC credential storage is invalid; restore a protected backup.") from None
        finally:
            if descriptor != -1:
                os.close(descriptor)
        if (
            not isinstance(document, dict) or document.get("version") != 1
            or not isinstance(document.get("profiles"), dict)
        ):
            raise SIWCError("Unsupported SIWC credential storage format.")
        try:
            identifier = uuid.UUID(str(document["host_id"]).removeprefix("urn:uuid:"))
            if not document["host_id"].startswith("urn:uuid:") or identifier.version != 4:
                raise ValueError
        except (KeyError, ValueError, AttributeError):
            raise SIWCError("SIWC storage has no valid host ID.") from None
        if any(not isinstance(value, dict) for value in document["profiles"].values()):
            raise SIWCError("SIWC storage has invalid account records.")
        return document

    def write(self, document: dict[str, Any]) -> None:
        descriptor, temporary = tempfile.mkstemp(prefix=".accounts-", dir=self.directory)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(document, handle, ensure_ascii=True)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
            if os.name == "posix":
                directory_fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
        finally:
            Path(temporary).unlink(missing_ok=True)


TOKEN_FIELDS = frozenset({
    "access_token", "refresh_token", "id_token", "expires_at", "expires_in",
    "earliest_refresh_at", "saved_at", "scopes", "token_type",
})


def clear_tokens(profile: dict[str, Any]) -> None:
    """Retain registration and identity for later reauthorization."""
    for key in TOKEN_FIELDS:
        profile.pop(key, None)
