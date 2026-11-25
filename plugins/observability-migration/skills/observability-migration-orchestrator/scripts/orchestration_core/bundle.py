"""Immutable execution-bundle construction and dependency validation."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from .common import IDENTIFIER, SESSION_ID, SHA256, canonical_hash


ACTIONS = {"CREATE", "UPDATE", "UPSERT", "REUSE", "NO_OP", "DEFER"}
CAPABILITIES = {"SUPPORTED", "PARTIAL", "UNSUPPORTED", "BLOCKED"}
OPERATION_FIELDS = {
    "operation_id", "object_ref", "object_type", "adapter", "action", "status",
    "dependencies", "payload_hash", "adapter_input", "validation", "rollback",
}
BUNDLE_FIELDS = {
    "schema_version", "session_id", "plan_hash", "target_binding", "operations",
    "created_at", "bundle_hash",
}


def _valid_https_origin(value: Any) -> bool:
    parsed = urlparse(str(value))
    return parsed.scheme == "https" and bool(parsed.hostname) and not parsed.username and not parsed.password


def validate_operation(operation: Any) -> dict[str, Any]:
    if not isinstance(operation, dict) or set(operation) != OPERATION_FIELDS:
        raise ValueError("execution operation fields are invalid")
    for field in ("operation_id", "object_ref", "object_type", "adapter"):
        if not isinstance(operation[field], str) or not IDENTIFIER.fullmatch(operation[field]):
            raise ValueError(f"execution operation {field} is invalid")
    if operation["action"] not in ACTIONS or operation["status"] not in CAPABILITIES:
        raise ValueError("execution operation action or capability is invalid")
    dependencies = operation["dependencies"]
    if (
        not isinstance(dependencies, list) or len(dependencies) != len(set(dependencies))
        or any(not isinstance(item, str) or not IDENTIFIER.fullmatch(item) for item in dependencies)
        or operation["operation_id"] in dependencies
    ):
        raise ValueError("execution operation dependencies are invalid")
    payload_hash = operation["payload_hash"]
    if payload_hash is not None and not SHA256.fullmatch(str(payload_hash)):
        raise ValueError("execution operation payload hash is invalid")
    if operation["status"] == "SUPPORTED" and operation["action"] not in {"NO_OP", "DEFER"} and payload_hash is None:
        raise ValueError("supported executable operation requires a payload hash")
    if not isinstance(operation["adapter_input"], dict):
        raise ValueError("execution operation adapter input must be an object")
    if not isinstance(operation["validation"], list) or any(not isinstance(item, dict) for item in operation["validation"]):
        raise ValueError("execution operation validation assertions are invalid")
    if not isinstance(operation["rollback"], dict):
        raise ValueError("execution operation rollback intent is invalid")
    return operation


def topological_layers(bundle: dict[str, Any]) -> list[list[str]]:
    operations = {item["operation_id"]: item for item in bundle["operations"]}
    remaining = set(operations)
    complete: set[str] = set()
    layers: list[list[str]] = []
    while remaining:
        ready = sorted(
            operation_id for operation_id in remaining
            if set(operations[operation_id]["dependencies"]).issubset(complete)
        )
        if not ready:
            raise ValueError("execution bundle dependency graph contains a cycle")
        layers.append(ready)
        complete.update(ready)
        remaining.difference_update(ready)
    return layers


def validate_bundle(bundle: Any) -> dict[str, Any]:
    if not isinstance(bundle, dict) or set(bundle) != BUNDLE_FIELDS or bundle.get("schema_version") != "1.0":
        raise ValueError("execution bundle fields or version are invalid")
    if not SESSION_ID.fullmatch(str(bundle["session_id"])) or not SHA256.fullmatch(str(bundle["plan_hash"])):
        raise ValueError("execution bundle session or plan hash is invalid")
    target = bundle["target_binding"]
    if (
        not isinstance(target, dict) or set(target) != {"origin", "organization_id_hash"}
        or not _valid_https_origin(target["origin"])
        or not SHA256.fullmatch(str(target["organization_id_hash"]))
    ):
        raise ValueError("execution bundle target binding is invalid")
    try:
        created_at = datetime.fromisoformat(str(bundle["created_at"]))
    except ValueError as exc:
        raise ValueError("execution bundle timestamp is invalid") from exc
    if created_at.tzinfo is None:
        raise ValueError("execution bundle timestamp must be timezone-aware")
    operations = bundle["operations"]
    if not isinstance(operations, list) or not operations:
        raise ValueError("execution bundle requires at least one operation")
    for operation in operations:
        validate_operation(operation)
    ids = [item["operation_id"] for item in operations]
    refs = [item["object_ref"] for item in operations]
    if len(ids) != len(set(ids)) or len(refs) != len(set(refs)):
        raise ValueError("execution bundle operation IDs and object refs must be unique")
    known = set(ids)
    if any(not set(item["dependencies"]).issubset(known) for item in operations):
        raise ValueError("execution bundle dependency is missing")
    topological_layers(bundle)
    if not SHA256.fullmatch(str(bundle["bundle_hash"])) or bundle["bundle_hash"] != canonical_hash(bundle, "bundle_hash"):
        raise ValueError("execution bundle hash mismatch")
    return bundle


def seal_bundle(
    session_id: str, plan_hash: str, target_binding: dict[str, str],
    operations: list[dict[str, Any]], *, created_at: datetime | None = None,
) -> dict[str, Any]:
    bundle: dict[str, Any] = {
        "schema_version": "1.0",
        "session_id": session_id,
        "plan_hash": plan_hash,
        "target_binding": deepcopy(target_binding),
        "operations": deepcopy(operations),
        "created_at": (created_at or datetime.now(timezone.utc)).isoformat(),
        "bundle_hash": "",
    }
    bundle["bundle_hash"] = canonical_hash(bundle, "bundle_hash")
    return validate_bundle(bundle)
