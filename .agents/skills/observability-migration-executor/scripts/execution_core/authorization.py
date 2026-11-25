"""Hash-bound, expiring authorization for one Splunk detector create wave."""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from .common import APPROVAL_ID, OBJECT_REF, SHA256, SESSION_ID, WAVE_ID, canonical_hash
from .manifest import validate_sealed_manifest


ACTOR_ROLES = {"customer", "authorized_operator"}
ALLOWED_OPERATIONS = ["CREATE_DETECTOR", "VALIDATE_DETECTOR"]


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def create_write_authorization(
    manifest: dict[str, Any],
    actor_role: str,
    target_origin: str,
    target_org_id_hash: str,
    ttl_minutes: int = 30,
    current_time: datetime | None = None,
) -> dict[str, Any]:
    validate_sealed_manifest(manifest)
    if actor_role not in ACTOR_ROLES:
        raise ValueError("write authorization actor role is invalid")
    if not 1 <= ttl_minutes <= 60:
        raise ValueError("write authorization TTL must be between 1 and 60 minutes")
    approved_at = current_time or now_utc()
    record: dict[str, Any] = {
        "schema_version": "1.0",
        "approval_id": f"write-approval-{uuid.uuid4().hex[:16]}",
        "approval_scope": "splunk_observability_create_wave",
        "actor_role": actor_role,
        "approved_at": approved_at.isoformat(),
        "expires_at": (approved_at + timedelta(minutes=ttl_minutes)).isoformat(),
        "source_session_id": manifest["source_session_id"],
        "plan_hash": manifest["plan_hash"],
        "plan_review_approval_hash": manifest["plan_review_approval_hash"],
        "manifest_hash": manifest["manifest_hash"],
        "target": "splunk_observability_cloud",
        "target_origin": target_origin,
        "target_org_id_hash": target_org_id_hash,
        "wave_id": manifest["wave_id"],
        "selected_refs": [entry["object_ref"] for entry in manifest["entries"]],
        "max_creates": manifest["max_creates"],
        "allowed_operations": ALLOWED_OPERATIONS,
        "conflict_policy": "fail_closed",
        "execution_contract": {
            "customer_approved_manifest": True,
            "detectors_created_disabled": True,
            "notifications_disabled": True,
        },
        "external_mutations_authorized": True,
        "updates_authorized": False,
        "deletes_authorized": False,
    }
    record["approval_hash"] = canonical_hash(record, "approval_hash")
    validate_write_authorization(record, manifest, current_time=approved_at)
    return record


def validate_write_authorization(
    record: dict[str, Any],
    manifest: dict[str, Any],
    operation: str = "CREATE_DETECTOR",
    current_time: datetime | None = None,
) -> None:
    validate_sealed_manifest(manifest)
    expected = {
        "schema_version", "approval_id", "approval_scope", "actor_role", "approved_at",
        "expires_at", "source_session_id", "plan_hash", "plan_review_approval_hash",
        "manifest_hash", "target", "target_origin", "target_org_id_hash", "wave_id",
        "selected_refs", "max_creates", "allowed_operations", "conflict_policy",
        "execution_contract",
        "external_mutations_authorized", "updates_authorized", "deletes_authorized",
        "approval_hash",
    }
    if set(record) != expected or record.get("schema_version") != "1.0":
        raise ValueError("write authorization fields are invalid")
    if not APPROVAL_ID.fullmatch(str(record["approval_id"])) or record["actor_role"] not in ACTOR_ROLES:
        raise ValueError("write authorization identity is invalid")
    if record["approval_scope"] != "splunk_observability_create_wave":
        raise ValueError("write authorization scope is invalid")
    if not SESSION_ID.fullmatch(str(record["source_session_id"])) or not WAVE_ID.fullmatch(str(record["wave_id"])):
        raise ValueError("write authorization session or wave is invalid")
    for field in ("plan_hash", "plan_review_approval_hash", "manifest_hash", "approval_hash"):
        if not SHA256.fullmatch(str(record[field])):
            raise ValueError(f"write authorization {field} is invalid")
    if not SHA256.fullmatch(str(record["target_org_id_hash"])):
        raise ValueError("write authorization target organization hash is invalid")
    try:
        approved_at = datetime.fromisoformat(str(record["approved_at"]))
        expires_at = datetime.fromisoformat(str(record["expires_at"]))
    except ValueError as exc:
        raise ValueError("write authorization timestamp is invalid") from exc
    if (
        approved_at.tzinfo is None or expires_at.tzinfo is None or expires_at <= approved_at
        or expires_at - approved_at > timedelta(minutes=60)
    ):
        raise ValueError("write authorization timestamps require a bounded timezone-aware window")
    moment = current_time or now_utc()
    if moment < approved_at:
        raise ValueError("write authorization is not active yet")
    if moment > expires_at:
        raise ValueError("write authorization has expired")
    if operation not in record["allowed_operations"] or record["allowed_operations"] != ALLOWED_OPERATIONS:
        raise ValueError("operation is not authorized for this execution wave")
    selected_refs = record["selected_refs"]
    expected_refs = [entry["object_ref"] for entry in manifest["entries"]]
    if selected_refs != expected_refs or any(not OBJECT_REF.fullmatch(str(item)) for item in selected_refs):
        raise ValueError("write authorization object scope mismatch")
    bindings = {
        "source_session_id": manifest["source_session_id"],
        "plan_hash": manifest["plan_hash"],
        "plan_review_approval_hash": manifest["plan_review_approval_hash"],
        "manifest_hash": manifest["manifest_hash"],
        "wave_id": manifest["wave_id"],
        "max_creates": manifest["max_creates"],
    }
    if any(record[key] != value for key, value in bindings.items()):
        raise ValueError("write authorization manifest binding mismatch")
    if record["target"] != "splunk_observability_cloud" or not re.fullmatch(
        r"https://api\.[a-z]{2,4}[0-9]{1,2}\.observability\.splunkcloud\.com",
        str(record["target_origin"]),
    ):
        raise ValueError("write authorization target is invalid")
    if record["conflict_policy"] != "fail_closed" or record["execution_contract"] != {
        "customer_approved_manifest": True,
        "detectors_created_disabled": True,
        "notifications_disabled": True,
    }:
        raise ValueError("write authorization execution contract is invalid")
    if record["external_mutations_authorized"] is not True or any([
        record["updates_authorized"], record["deletes_authorized"],
    ]):
        raise ValueError("write authorization safety invariants are invalid")
    if record["approval_hash"] != canonical_hash(record, "approval_hash"):
        raise ValueError("write authorization hash mismatch")


__all__ = ["create_write_authorization", "validate_write_authorization"]
