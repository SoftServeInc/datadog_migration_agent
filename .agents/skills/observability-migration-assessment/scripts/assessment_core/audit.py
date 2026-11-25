"""Append-only privacy-safe local audit events."""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .security import ensure_private_directory


EVENT_TYPES = {
    "authorization_granted", "live_preflight_completed", "discovery_started",
    "discovery_completed", "discovery_failed", "capability_catalog_generated",
    "plan_review_approved", "plan_compile_failed",
}
OUTCOMES = {"approved", "success", "partial", "failed", "blocked"}


def append_audit_event(
    path: Path,
    event_type: str,
    outcome: str,
    session_id: str,
    approval_id: str = "",
    counts: dict[str, int] | None = None,
) -> None:
    if event_type not in EVENT_TYPES or outcome not in OUTCOMES:
        raise ValueError("unsupported audit event")
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{7,63}", session_id):
        raise ValueError("invalid audit session ID")
    if approval_id and not re.fullmatch(r"approval-[a-f0-9]{16}", approval_id):
        raise ValueError("invalid audit approval ID")
    if path.is_symlink():
        raise ValueError("refusing symlink audit log")
    parent = ensure_private_directory(path.parent)
    path = parent / path.name
    event: dict[str, Any] = {
        "schema_version": "1.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "outcome": outcome,
        "session_id": session_id,
        "approval_id": approval_id or None,
        "counts": {
            str(key): value for key, value in sorted((counts or {}).items())
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0
        },
        "safety": {"secrets_included": False, "raw_customer_data_included": False},
    }
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        os.write(descriptor, (json.dumps(event, sort_keys=True) + "\n").encode("utf-8"))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
