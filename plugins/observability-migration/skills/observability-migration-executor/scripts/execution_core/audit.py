"""Sanitized append-only execution audit events."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .common import APPROVAL_ID, SESSION_ID, WAVE_ID, ensure_private_directory


EVENTS = {"write_authorized", "wave_started", "object_created", "object_reused", "wave_completed", "validation_completed", "validation_failed", "pending_create_cleared", "wave_failed"}
OUTCOMES = {"approved", "success", "partial", "failed", "blocked"}


def append_execution_audit(
    path: Path,
    event_type: str,
    outcome: str,
    session_id: str,
    wave_id: str,
    approval_id: str,
    counts: dict[str, int] | None = None,
) -> None:
    if event_type not in EVENTS or outcome not in OUTCOMES:
        raise ValueError("unsupported execution audit event")
    if not SESSION_ID.fullmatch(session_id) or not WAVE_ID.fullmatch(wave_id) or not APPROVAL_ID.fullmatch(approval_id):
        raise ValueError("execution audit identity is invalid")
    if path.is_symlink():
        raise ValueError("refusing symlink audit log")
    parent = ensure_private_directory(path.parent)
    event: dict[str, Any] = {
        "schema_version": "1.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "outcome": outcome,
        "session_id": session_id,
        "wave_id": wave_id,
        "approval_id": approval_id,
        "counts": {
            key: value for key, value in sorted((counts or {}).items())
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0
        },
        "safety": {
            "secrets_included": False,
            "payloads_included": False,
            "direct_identifiers_included": False,
            "environment_classification_included": False,
        },
    }
    descriptor = os.open(
        parent / path.name,
        os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        os.fchmod(descriptor, 0o600)
        os.write(descriptor, (json.dumps(event, sort_keys=True) + "\n").encode("utf-8"))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


__all__ = ["append_execution_audit"]
