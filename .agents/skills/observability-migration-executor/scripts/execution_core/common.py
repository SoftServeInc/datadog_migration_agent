"""Shared validation and hashing primitives for migration execution."""

from __future__ import annotations

import hashlib
import json
import os
import re
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

import fcntl

from assessment_core.security import atomic_write_json, ensure_private_directory


SHA256 = re.compile(r"^[a-f0-9]{64}$")
SESSION_ID = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{7,63}$")
WAVE_ID = re.compile(r"^wave-[a-zA-Z0-9][a-zA-Z0-9_-]{2,31}$")
APPROVAL_ID = re.compile(r"^write-approval-[a-f0-9]{16}$")
MANIFEST_ID = re.compile(r"^manifest-[a-f0-9]{16}$")
REALM = re.compile(r"^[a-z]{2,4}[0-9]{1,2}$")
OBJECT_REF = re.compile(r"^obj_[a-f0-9]{16}$")


def canonical_hash(value: dict[str, Any], hash_field: str) -> str:
    unsigned = {key: item for key, item in value.items() if key != hash_field}
    payload = json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def value_hash(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def resolve_splunk_origin(realm: str) -> str:
    normalized = realm.strip().lower()
    if not REALM.fullmatch(normalized):
        raise ValueError("Splunk realm must be a short value such as us1 or eu0")
    return f"https://api.{normalized}.observability.splunkcloud.com"


def read_private_json(path: Path, max_bytes: int = 2_000_000) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"private JSON file not found or unsafe: {path.name}")
    if path.stat().st_size > max_bytes:
        raise ValueError(f"private JSON file exceeds {max_bytes} bytes: {path.name}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"private JSON root must be an object: {path.name}")
    return value


def execution_directory(work_root: Path, session_id: str, wave_id: str) -> Path:
    if not SESSION_ID.fullmatch(session_id) or not WAVE_ID.fullmatch(wave_id):
        raise ValueError("invalid session or wave ID")
    root = ensure_private_directory(work_root)
    session = ensure_private_directory(root / session_id)
    execution = ensure_private_directory(session / "execution")
    return ensure_private_directory(execution / wave_id)


@contextmanager
def wave_lock(directory: Path) -> Iterator[None]:
    """Serialize one local wave to close the common GET-before-POST race."""
    path = directory / ".execution.lock"
    if path.is_symlink():
        raise ValueError("refusing symlink execution lock")
    descriptor = os.open(
        path,
        os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        os.fchmod(descriptor, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ValueError("another process is executing this wave") from exc
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


@contextmanager
def session_execution_lock(wave_directory: Path) -> Iterator[None]:
    """Serialize all execution waves in one session across the final claim check and POSTs."""
    path = wave_directory.parent / ".session-execution.lock"
    if path.is_symlink():
        raise ValueError("refusing symlink session execution lock")
    descriptor = os.open(
        path,
        os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        os.fchmod(descriptor, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ValueError("another execution wave is active for this session") from exc
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


__all__ = [
    "APPROVAL_ID", "MANIFEST_ID", "OBJECT_REF", "SESSION_ID", "SHA256", "WAVE_ID",
    "atomic_write_json", "canonical_hash", "ensure_private_directory",
    "execution_directory", "read_private_json", "resolve_splunk_origin",
    "session_execution_lock", "value_hash", "wave_lock",
]
