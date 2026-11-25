"""Apply-authorization binding for one immutable execution bundle."""

from __future__ import annotations

import uuid
import re
from datetime import datetime, timezone
from typing import Any

from .bundle import validate_bundle
from .common import SHA256, canonical_hash


APPROVAL_FIELDS = {
    "schema_version", "approval_id", "approval_number", "approval_scope", "actor_role",
    "approved_at", "session_id", "plan_hash", "bundle_hash", "target_binding",
    "authorized_actions", "external_mutations_authorized", "approval_hash",
}


def create_apply_approval(
    bundle: dict[str, Any], *, actor_role: str = "customer",
    approved_at: datetime | None = None,
) -> dict[str, Any]:
    validate_bundle(bundle)
    if actor_role not in {"customer", "authorized_operator"}:
        raise ValueError("apply approval actor role is invalid")
    record: dict[str, Any] = {
        "schema_version": "1.0",
        "approval_id": f"apply-approval-{uuid.uuid4().hex[:16]}",
        "approval_number": 2,
        "approval_scope": "immutable_observability_execution_bundle",
        "actor_role": actor_role,
        "approved_at": (approved_at or datetime.now(timezone.utc)).isoformat(),
        "session_id": bundle["session_id"],
        "plan_hash": bundle["plan_hash"],
        "bundle_hash": bundle["bundle_hash"],
        "target_binding": dict(bundle["target_binding"]),
        "authorized_actions": sorted({
            operation["action"] for operation in bundle["operations"]
            if operation["action"] not in {"DEFER", "NO_OP"}
        }),
        "external_mutations_authorized": True,
        "approval_hash": "",
    }
    record["approval_hash"] = canonical_hash(record, "approval_hash")
    return validate_apply_approval(record, bundle)


def validate_apply_approval(
    record: Any, bundle: dict[str, Any], runtime_target: dict[str, str] | None = None,
) -> dict[str, Any]:
    validate_bundle(bundle)
    if not isinstance(record, dict) or set(record) != APPROVAL_FIELDS or record.get("schema_version") != "1.0":
        raise ValueError("apply approval fields or version are invalid")
    if (
        record.get("approval_number") != 2
        or record.get("approval_scope") != "immutable_observability_execution_bundle"
        or record.get("actor_role") not in {"customer", "authorized_operator"}
        or record.get("external_mutations_authorized") is not True
    ):
        raise ValueError("apply approval policy is invalid")
    if not re.fullmatch(r"apply-approval-[a-f0-9]{16}", str(record.get("approval_id"))):
        raise ValueError("apply approval identity is invalid")
    try:
        timestamp = datetime.fromisoformat(str(record["approved_at"]))
    except ValueError as exc:
        raise ValueError("apply approval timestamp is invalid") from exc
    if timestamp.tzinfo is None:
        raise ValueError("apply approval timestamp must be timezone-aware")
    expected = {
        "session_id": bundle["session_id"], "plan_hash": bundle["plan_hash"],
        "bundle_hash": bundle["bundle_hash"], "target_binding": bundle["target_binding"],
    }
    if any(record[field] != value for field, value in expected.items()):
        raise ValueError("apply approval bundle binding mismatch")
    actions = sorted({
        operation["action"] for operation in bundle["operations"]
        if operation["action"] not in {"DEFER", "NO_OP"}
    })
    if record["authorized_actions"] != actions or (
        runtime_target is not None and runtime_target != bundle["target_binding"]
    ):
        raise ValueError("apply approval action or runtime target mismatch")
    if not SHA256.fullmatch(str(record["approval_hash"])) or record["approval_hash"] != canonical_hash(record, "approval_hash"):
        raise ValueError("apply approval hash mismatch")
    return record
