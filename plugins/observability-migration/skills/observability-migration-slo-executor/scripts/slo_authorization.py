"""Hash-bound expiring authorization for one create-only Splunk SLO wave."""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from slo_common import APPROVAL_ID, OBJECT_REF, SESSION_ID, SHA256, SLO_WAVE_ID, canonical_hash
from slo_manifest import validate_slo_manifest


ACTOR_ROLES = {"customer", "authorized_operator"}
ALLOWED_OPERATIONS = ["CREATE_SLO", "VALIDATE_SLO"]


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def create_slo_authorization(
    manifest: dict[str, Any], actor_role: str, target_origin: str,
    target_org_id_hash: str, ttl_minutes: int = 30,
    current_time: datetime | None = None,
) -> dict[str, Any]:
    validate_slo_manifest(manifest)
    if actor_role not in ACTOR_ROLES or not 1 <= ttl_minutes <= 60:
        raise ValueError("SLO authorization actor or TTL is invalid")
    approved_at = current_time or now_utc()
    record: dict[str, Any] = {
        "schema_version": "1.0",
        "approval_id": f"write-approval-{uuid.uuid4().hex[:16]}",
        "approval_scope": "splunk_observability_slo_create_wave",
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
        "selected_refs": manifest["entry"]["source_refs"],
        "max_creates": 1,
        "allowed_operations": ALLOWED_OPERATIONS,
        "conflict_policy": "fail_closed",
        "execution_contract": {
            "customer_approved_manifest": True,
            "slo_created_with_disabled_alerts": True,
            "notifications_disabled": True,
        },
        "external_mutations_authorized": True,
        "updates_authorized": False,
        "deletes_authorized": False,
    }
    record["approval_hash"] = canonical_hash(record, "approval_hash")
    validate_slo_authorization(record, manifest, current_time=approved_at)
    return record


def validate_slo_authorization(
    record: dict[str, Any], manifest: dict[str, Any], operation: str = "CREATE_SLO",
    current_time: datetime | None = None,
) -> None:
    validate_slo_manifest(manifest)
    expected = {
        "schema_version", "approval_id", "approval_scope", "actor_role", "approved_at",
        "expires_at", "source_session_id", "plan_hash", "plan_review_approval_hash",
        "manifest_hash", "target", "target_origin", "target_org_id_hash", "wave_id",
        "selected_refs", "max_creates", "allowed_operations", "conflict_policy",
        "execution_contract", "external_mutations_authorized", "updates_authorized",
        "deletes_authorized", "approval_hash",
    }
    if set(record) != expected or record.get("schema_version") != "1.0":
        raise ValueError("SLO authorization fields are invalid")
    if not APPROVAL_ID.fullmatch(str(record["approval_id"])) or record["actor_role"] not in ACTOR_ROLES:
        raise ValueError("SLO authorization identity is invalid")
    if record["approval_scope"] != "splunk_observability_slo_create_wave":
        raise ValueError("SLO authorization scope is invalid")
    if not SESSION_ID.fullmatch(str(record["source_session_id"])) or not SLO_WAVE_ID.fullmatch(str(record["wave_id"])):
        raise ValueError("SLO authorization session or wave is invalid")
    for field in ("plan_hash", "plan_review_approval_hash", "manifest_hash", "target_org_id_hash", "approval_hash"):
        if not SHA256.fullmatch(str(record[field])):
            raise ValueError(f"SLO authorization {field} is invalid")
    try:
        approved_at = datetime.fromisoformat(str(record["approved_at"]))
        expires_at = datetime.fromisoformat(str(record["expires_at"]))
    except ValueError as exc:
        raise ValueError("SLO authorization timestamp is invalid") from exc
    if (
        approved_at.tzinfo is None or expires_at.tzinfo is None or expires_at <= approved_at
        or expires_at - approved_at > timedelta(minutes=60)
    ):
        raise ValueError("SLO authorization timestamps are invalid")
    moment = current_time or now_utc()
    if moment < approved_at or moment > expires_at:
        raise ValueError("SLO authorization is not active")
    if record["allowed_operations"] != ALLOWED_OPERATIONS or operation not in ALLOWED_OPERATIONS:
        raise ValueError("operation is not authorized for this SLO wave")
    if record["selected_refs"] != manifest["entry"]["source_refs"] or any(
        not OBJECT_REF.fullmatch(str(item)) for item in record["selected_refs"]
    ):
        raise ValueError("SLO authorization source scope mismatch")
    for field in (
        "source_session_id", "plan_hash", "plan_review_approval_hash", "manifest_hash", "wave_id",
    ):
        if record[field] != manifest[field]:
            raise ValueError("SLO authorization manifest binding mismatch")
    if record["max_creates"] != 1 or record["target"] != "splunk_observability_cloud":
        raise ValueError("SLO authorization target or cap is invalid")
    if not re.fullmatch(
        r"https://api\.[a-z]{2,4}[0-9]{1,2}\.observability\.splunkcloud\.com",
        str(record["target_origin"]),
    ):
        raise ValueError("SLO authorization origin is invalid")
    if record["conflict_policy"] != "fail_closed" or record["execution_contract"] != {
        "customer_approved_manifest": True,
        "slo_created_with_disabled_alerts": True,
        "notifications_disabled": True,
    }:
        raise ValueError("SLO authorization execution contract is invalid")
    if record["external_mutations_authorized"] is not True or record["updates_authorized"] or record["deletes_authorized"]:
        raise ValueError("SLO authorization safety invariants are invalid")
    if record["approval_hash"] != canonical_hash(record, "approval_hash"):
        raise ValueError("SLO authorization hash mismatch")


__all__ = ["create_slo_authorization", "validate_slo_authorization"]
