"""Hash-bound review approval for a non-executable migration plan."""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .security import atomic_write_json


ACTOR_ROLES = {"customer", "authorized_operator"}
SESSION_ID = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{7,63}$")
APPROVAL_ID = re.compile(r"^approval-[a-f0-9]{16}$")
SHA256 = re.compile(r"^[a-f0-9]{64}$")
STRATEGIES = {"full", "safe_staged", "customer_selected"}


def _hash(record: dict[str, Any]) -> str:
    unsigned = {key: value for key, value in record.items() if key != "approval_hash"}
    payload = json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def create_plan_review_approval(
    session_id: str,
    actor_role: str,
    plan_hash: str,
    assessment_hash: str,
    strategy: str,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "schema_version": "1.0",
        "approval_id": f"approval-{uuid.uuid4().hex[:16]}",
        "session_id": session_id,
        "actor_role": actor_role,
        "approved_at": datetime.now(timezone.utc).isoformat(),
        "approval_scope": "dry_run_plan_review",
        "plan_hash": plan_hash,
        "assessment_hash": assessment_hash,
        "strategy": strategy,
        "plan_review_approved": True,
        "execution_authorized": False,
        "external_mutations_authorized": False,
    }
    record["approval_hash"] = _hash(record)
    validate_plan_review_approval(record)
    return record


def validate_plan_review_approval(record: dict[str, Any]) -> None:
    expected = {
        "schema_version", "approval_id", "session_id", "actor_role", "approved_at",
        "approval_scope", "plan_hash", "assessment_hash", "strategy",
        "plan_review_approved", "execution_authorized", "external_mutations_authorized",
        "approval_hash",
    }
    if set(record) != expected or record.get("schema_version") != "1.0":
        raise ValueError("plan review approval fields are invalid")
    if not SESSION_ID.fullmatch(str(record.get("session_id", ""))):
        raise ValueError("plan review session ID is invalid")
    if not APPROVAL_ID.fullmatch(str(record.get("approval_id", ""))):
        raise ValueError("plan review approval ID is invalid")
    if record.get("actor_role") not in ACTOR_ROLES or record.get("strategy") not in STRATEGIES:
        raise ValueError("plan review actor or strategy is invalid")
    if record.get("approval_scope") != "dry_run_plan_review":
        raise ValueError("plan review approval scope is invalid")
    if not SHA256.fullmatch(str(record.get("plan_hash", ""))) or not SHA256.fullmatch(
        str(record.get("assessment_hash", ""))
    ):
        raise ValueError("plan review bound hash is invalid")
    try:
        approved_at = datetime.fromisoformat(str(record["approved_at"]))
    except ValueError as exc:
        raise ValueError("plan review approval timestamp is invalid") from exc
    if approved_at.tzinfo is None:
        raise ValueError("plan review approval timestamp requires a timezone")
    if record.get("plan_review_approved") is not True:
        raise ValueError("plan review is not approved")
    if record.get("execution_authorized") is not False or record.get(
        "external_mutations_authorized"
    ) is not False:
        raise ValueError("plan review approval must not authorize execution")
    if not SHA256.fullmatch(str(record.get("approval_hash", ""))) or record["approval_hash"] != _hash(record):
        raise ValueError("plan review approval hash mismatch")


def write_plan_review_approval(path: Path, record: dict[str, Any]) -> None:
    validate_plan_review_approval(record)
    atomic_write_json(path, record)
