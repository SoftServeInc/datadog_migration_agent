"""Sanitized append-only audit for SLO execution."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from slo_common import APPROVAL_ID, SESSION_ID, SLO_WAVE_ID
from execution_core.common import ensure_private_directory  # type: ignore[import-not-found]


EVENTS = {
    "write_authorized", "wave_started", "wave_completed", "wave_failed",
    "validation_completed", "validation_failed", "pending_create_cleared",
}
OUTCOMES = {"approved", "success", "failed", "blocked"}


def append_slo_audit(
    path: Path, event_type: str, outcome: str, session_id: str,
    wave_id: str, approval_id: str, counts: dict[str, int] | None = None,
) -> None:
    if event_type not in EVENTS or outcome not in OUTCOMES:
        raise ValueError("unsupported SLO audit event")
    if (
        not SESSION_ID.fullmatch(session_id) or not SLO_WAVE_ID.fullmatch(wave_id)
        or not APPROVAL_ID.fullmatch(approval_id)
    ):
        raise ValueError("SLO audit identity is invalid")
    if path.is_symlink():
        raise ValueError("refusing symlink SLO audit log")
    parent = ensure_private_directory(path.parent)
    event = {
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
        os.write(descriptor, (json.dumps(event, sort_keys=True) + "\n").encode())
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


__all__ = ["append_slo_audit"]
