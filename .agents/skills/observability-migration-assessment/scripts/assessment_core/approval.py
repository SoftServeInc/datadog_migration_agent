"""Hash-bound, time-limited approvals for customer-system read operations."""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .security import atomic_write_json


READ_OPERATIONS = {"LIVE_PREFLIGHT", "DATADOG_DISCOVERY"}
ACTOR_ROLES = {"customer", "authorized_operator"}
TARGETS = {"splunk_observability_cloud", "splunk_platform", "both"}
DATA_CATEGORIES = {
    "configuration_metadata", "object_queries", "ownership_tags",
    "notification_channel_types", "permission_status", "billing_and_usage",
}
SESSION_ID = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{7,63}$")
APPROVAL_ID = re.compile(r"^approval-[a-f0-9]{16}$")


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _canonical_hash(record: dict[str, Any]) -> str:
    unsigned = {key: value for key, value in record.items() if key != "approval_hash"}
    payload = json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def create_read_authorization(
    session_id: str,
    actor_role: str,
    target: str,
    ttl_minutes: int = 60,
    include_cost_read: bool = False,
    authorized_origins: dict[str, str] | None = None,
    current_time: datetime | None = None,
) -> dict[str, Any]:
    if actor_role not in ACTOR_ROLES:
        raise ValueError("actor role must be customer or authorized_operator")
    if not SESSION_ID.fullmatch(session_id):
        raise ValueError("invalid session ID")
    if target not in TARGETS:
        raise ValueError("unsupported target")
    if not 1 <= ttl_minutes <= 240:
        raise ValueError("authorization TTL must be between 1 and 240 minutes")
    approved_at = current_time or now_utc()
    record: dict[str, Any] = {
        "schema_version": "1.0",
        "approval_id": f"approval-{uuid.uuid4().hex[:16]}",
        "session_id": session_id,
        "actor_role": actor_role,
        "approved": True,
        "approved_at": approved_at.isoformat(),
        "expires_at": (approved_at + timedelta(minutes=ttl_minutes)).isoformat(),
        "source": "datadog",
        "target": target,
        "access_mode": "read_only",
        "operations": sorted(READ_OPERATIONS),
        "expected_api_impact": {
            "live_preflight_max_requests": 7,
            "discovery_max_requests": 5000,
            "discovery": "bounded GET requests with endpoint-level pagination",
        },
        "data_categories": [
            "configuration_metadata", "object_queries", "ownership_tags",
            "notification_channel_types", "permission_status",
        ] + (["billing_and_usage"] if include_cost_read else []),
        "external_mutations_authorized": False,
        "authorized_origins": dict(sorted((authorized_origins or {}).items())),
    }
    record["approval_hash"] = _canonical_hash(record)
    return record


def write_authorization(path: Path, record: dict[str, Any]) -> None:
    validate_authorization(record, "LIVE_PREFLIGHT")
    atomic_write_json(path, record)


def load_authorization(path: Path, operation: str, current_time: datetime | None = None) -> dict[str, Any]:
    if path.is_symlink():
        raise ValueError("refusing symlink authorization file")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("authorization must be a JSON object")
    validate_authorization(value, operation, current_time=current_time)
    return value


def validate_authorization(
    record: dict[str, Any],
    operation: str,
    current_time: datetime | None = None,
) -> None:
    if operation not in READ_OPERATIONS:
        raise ValueError("operation is not eligible for read-only authorization")
    if record.get("schema_version") != "1.0" or record.get("approved") is not True:
        raise ValueError("authorization is not approved")
    if not SESSION_ID.fullmatch(str(record.get("session_id", ""))):
        raise ValueError("authorization session ID is invalid")
    if not APPROVAL_ID.fullmatch(str(record.get("approval_id", ""))):
        raise ValueError("authorization approval ID is invalid")
    if record.get("actor_role") not in ACTOR_ROLES or record.get("source") != "datadog":
        raise ValueError("authorization actor or source is invalid")
    if record.get("target") not in TARGETS:
        raise ValueError("authorization target is invalid")
    if record.get("access_mode") != "read_only" or record.get("external_mutations_authorized") is not False:
        raise ValueError("authorization violates the read-only invariant")
    origins = record.get("authorized_origins")
    if not isinstance(origins, dict) or "datadog" not in origins:
        raise ValueError("authorization has no bound Datadog origin")
    if any(not isinstance(value, str) or not value.startswith("https://") for value in origins.values()):
        raise ValueError("authorization contains an invalid bound origin")
    if not set(origins).issubset({"datadog", "splunk_observability_cloud", "splunk_platform"}):
        raise ValueError("authorization contains an unknown origin")
    selected_origin_keys = (
        {"datadog", "splunk_observability_cloud", "splunk_platform"}
        if record.get("target") == "both" else {"datadog", str(record.get("target"))}
    )
    if not set(origins).issubset(selected_origin_keys):
        raise ValueError("authorization contains an unselected target origin")
    operations = record.get("operations")
    if not isinstance(operations, list) or not set(operations).issubset(READ_OPERATIONS):
        raise ValueError("authorization operations are invalid")
    categories = record.get("data_categories")
    if not isinstance(categories, list) or not set(categories).issubset(DATA_CATEGORIES):
        raise ValueError("authorization data categories are invalid")
    if operation not in record.get("operations", []):
        raise ValueError(f"authorization does not include {operation}")
    if not re.fullmatch(r"[a-f0-9]{64}", str(record.get("approval_hash", ""))):
        raise ValueError("authorization hash format is invalid")
    if record.get("approval_hash") != _canonical_hash(record):
        raise ValueError("authorization hash mismatch")
    try:
        approved_at = datetime.fromisoformat(str(record["approved_at"]))
        expires_at = datetime.fromisoformat(str(record["expires_at"]))
    except (KeyError, ValueError) as exc:
        raise ValueError("authorization expiry is invalid") from exc
    comparison_time = current_time or now_utc()
    if comparison_time.tzinfo is None:
        raise ValueError("authorization comparison time must include a timezone")
    if approved_at.tzinfo is None or expires_at.tzinfo is None or approved_at >= expires_at:
        raise ValueError("authorization timestamps are invalid")
    if comparison_time >= expires_at:
        raise ValueError("authorization has expired")


def public_approval_ref(record: dict[str, Any]) -> dict[str, str]:
    return {
        "approval_id": str(record["approval_id"]),
        "approval_hash": str(record["approval_hash"]),
        "access_mode": "read_only",
    }


def public_authorization_summary(record: dict[str, Any]) -> dict[str, Any]:
    """Return a reviewer-safe scope summary without credential-bearing endpoint values."""
    validate_authorization(record, "LIVE_PREFLIGHT")
    return {
        "schema_version": "1.0",
        "approval": public_approval_ref(record),
        "source": record["source"],
        "target": record["target"],
        "actor_role": record["actor_role"],
        "operations": list(record["operations"]),
        "data_categories": list(record["data_categories"]),
        "approved_at": record["approved_at"],
        "expires_at": record["expires_at"],
        "origin_bindings": {
            "providers": sorted(record["authorized_origins"]),
            "https_only": True,
            "values_included": False,
        },
        "expected_api_impact": dict(record["expected_api_impact"]),
        "safety": {
            "credential_values_included": False,
            "origin_values_included": False,
            "external_mutations_authorized": False,
        },
    }
