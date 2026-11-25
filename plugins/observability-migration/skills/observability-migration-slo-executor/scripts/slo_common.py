"""Shared primitives and private paths for create-only SLO execution."""

from __future__ import annotations

import fcntl
import os
import re
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from execution_core.common import (  # type: ignore[import-not-found]
    APPROVAL_ID,
    OBJECT_REF,
    SESSION_ID,
    SHA256,
    atomic_write_json,
    canonical_hash,
    ensure_private_directory,
    read_private_json,
    resolve_splunk_origin,
    value_hash,
)


SLO_WAVE_ID = re.compile(r"^slo-wave-[a-zA-Z0-9][a-zA-Z0-9_-]{2,27}$")
SLO_MANIFEST_ID = re.compile(r"^slo-manifest-[a-f0-9]{16}$")


def slo_execution_directory(work_root: Path, session_id: str, wave_id: str) -> Path:
    if not SESSION_ID.fullmatch(session_id) or not SLO_WAVE_ID.fullmatch(wave_id):
        raise ValueError("invalid session or SLO wave ID")
    root = ensure_private_directory(work_root)
    session = ensure_private_directory(root / session_id)
    execution = ensure_private_directory(session / "slo-execution")
    return ensure_private_directory(execution / wave_id)


@contextmanager
def _exclusive_lock(path: Path, message: str) -> Iterator[None]:
    if path.is_symlink():
        raise ValueError("refusing symlink SLO execution lock")
    descriptor = os.open(
        path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600,
    )
    try:
        os.fchmod(descriptor, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ValueError(message) from exc
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def slo_wave_lock(directory: Path) -> Iterator[None]:
    return _exclusive_lock(directory / ".execution.lock", "another process is executing this SLO wave")


def slo_session_lock(directory: Path) -> Iterator[None]:
    return _exclusive_lock(
        directory.parent / ".session-execution.lock",
        "another SLO execution wave is active for this session",
    )


__all__ = [
    "APPROVAL_ID", "OBJECT_REF", "SESSION_ID", "SHA256", "SLO_MANIFEST_ID",
    "SLO_WAVE_ID", "atomic_write_json", "canonical_hash", "read_private_json",
    "resolve_splunk_origin", "slo_execution_directory", "slo_session_lock",
    "slo_wave_lock", "value_hash",
]
