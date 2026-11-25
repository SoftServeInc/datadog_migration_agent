"""Private storage, locking, and deterministic hashing primitives."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator


SHA256 = re.compile(r"^[a-f0-9]{64}$")
SESSION_ID = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{7,63}$")
IDENTIFIER = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}$")


def value_hash(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def canonical_hash(value: dict[str, Any], hash_field: str) -> str:
    return value_hash({key: item for key, item in value.items() if key != hash_field})


def ensure_private_directory(path: Path) -> Path:
    if path.is_symlink():
        raise ValueError(f"refusing symlink directory: {path.name}")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not path.is_dir():
        raise ValueError(f"private path is not a directory: {path.name}")
    path.chmod(0o700)
    return path


def atomic_write_json(path: Path, value: dict[str, Any]) -> None:
    parent = ensure_private_directory(path.parent)
    if path.is_symlink():
        raise ValueError(f"refusing symlink file: {path.name}")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(parent))
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        path.chmod(0o600)
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def read_private_json(path: Path, max_bytes: int = 25_000_000) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > max_bytes:
        raise ValueError(f"private JSON file is missing, unsafe, or too large: {path.name}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"private JSON root must be an object: {path.name}")
    return value


def runtime_directory(work_root: Path, session_id: str) -> Path:
    if not SESSION_ID.fullmatch(session_id):
        raise ValueError("invalid migration session ID")
    root = ensure_private_directory(work_root.resolve())
    session = ensure_private_directory(root / session_id)
    return ensure_private_directory(session / "unified-execution")


@contextmanager
def runtime_lock(directory: Path) -> Iterator[None]:
    path = directory / ".scheduler.lock"
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ValueError("another unified scheduler is running for this session") from exc
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)
