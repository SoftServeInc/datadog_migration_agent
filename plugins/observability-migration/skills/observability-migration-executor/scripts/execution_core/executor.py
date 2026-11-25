"""Idempotent create-only wave execution and read-back validation."""

from __future__ import annotations

import copy
from typing import Any

from .adapter import AdapterError, DetectorAdapter
from .authorization import validate_write_authorization
from .common import value_hash
from .manifest import validate_sealed_manifest
from .state import ExecutionCheckpoint, ExecutionStore


def _project_expected(expected: Any, actual: Any) -> Any:
    if isinstance(expected, dict):
        if not isinstance(actual, dict):
            return None
        return {key: _project_expected(value, actual.get(key)) for key, value in expected.items()}
    if isinstance(expected, list):
        if not isinstance(actual, list) or len(actual) != len(expected):
            return None
        return [_project_expected(value, actual[index]) for index, value in enumerate(expected)]
    return actual


def _assert_equivalent(entry: dict[str, Any], actual: dict[str, Any]) -> None:
    expected = copy.deepcopy(entry["payload"])
    actual_for_projection = copy.deepcopy(actual)
    expected_rules = expected.get("rules")
    actual_rules_value = actual_for_projection.get("rules")
    if not isinstance(actual_rules_value, list) or len(actual_rules_value) != len(expected_rules):
        raise ValueError("detector rule set differs from the sealed payload")
    if any(
        not isinstance(rule, dict)
        or rule.get("disabled") is not True
        or rule.get("notifications") != []
        for rule in actual_rules_value
    ):
        raise ValueError("target detector contains an enabled or notifying rule")
    if actual_for_projection.get("customProperties") != expected.get("customProperties"):
        raise ValueError("detector custom properties differ from the sealed payload")
    if isinstance(expected.get("tags"), list) and isinstance(actual_for_projection.get("tags"), list):
        expected["tags"] = sorted(expected["tags"])
        actual_for_projection["tags"] = sorted(actual_for_projection["tags"])
    if isinstance(expected.get("rules"), list) and isinstance(actual_for_projection.get("rules"), list):
        actual_rules = {
            rule.get("detectLabel"): rule for rule in actual_for_projection["rules"]
            if isinstance(rule, dict) and isinstance(rule.get("detectLabel"), str)
        }
        actual_for_projection["rules"] = [
            actual_rules.get(rule.get("detectLabel"), {}) for rule in expected["rules"]
        ]
    projected = _project_expected(expected, actual_for_projection)
    if projected is None or value_hash(projected) != value_hash(expected):
        raise ValueError("existing or created detector differs from the sealed payload")
    if actual.get("id") is None or entry["marker_tag"] not in actual.get("tags", []):
        raise ValueError("detector identity or migration marker is missing")


def _find_existing(adapter: DetectorAdapter, entry: dict[str, Any]) -> dict[str, Any] | None:
    matches = adapter.find_detectors_by_tag(entry["marker_tag"])
    if len(matches) > 1:
        raise ValueError("multiple detectors share the migration marker")
    if not matches:
        return None
    candidate = matches[0]
    target_id = candidate.get("id")
    if not isinstance(target_id, str) or not target_id:
        raise ValueError("existing detector has no valid ID")
    actual = adapter.get_detector(target_id)
    _assert_equivalent(entry, actual)
    return actual


def _create_once_with_reconciliation(adapter: DetectorAdapter, entry: dict[str, Any]) -> dict[str, Any]:
    try:
        created = adapter.create_detector(entry["payload"])
    except AdapterError as exc:
        if exc.create_definitively_rejected:
            raise
        existing = _find_existing(adapter, entry)
        if existing is not None:
            return existing
        raise AdapterError("ambiguous_create_unresolved", retriable=True) from None
    target_id = created.get("id")
    if not isinstance(target_id, str) or not target_id:
        raise ValueError("created detector response has no valid ID")
    try:
        actual = adapter.get_detector(target_id)
        _assert_equivalent(entry, actual)
    except Exception:
        # POST already returned success. Preserve the pending intent so a resume can
        # reconcile by marker and can never issue a blind second POST.
        raise AdapterError("post_create_validation_unresolved", retriable=True) from None
    return actual


def _validate_bindings(
    checkpoint: ExecutionCheckpoint,
    manifest: dict[str, Any],
    authorization: dict[str, Any],
) -> None:
    if (
        checkpoint.source_session_id != manifest["source_session_id"]
        or checkpoint.wave_id != manifest["wave_id"]
        or checkpoint.plan_hash != manifest["plan_hash"]
        or checkpoint.manifest_hash != manifest["manifest_hash"]
    ):
        raise ValueError("execution checkpoint binding mismatch")


def _verify_target_identity(
    authorization: dict[str, Any], adapter: DetectorAdapter,
) -> None:
    organization_id = adapter.get_organization_id()
    if authorization["target_org_id_hash"] != value_hash(organization_id):
        raise ValueError("runtime Splunk organization differs from the authorized organization")


def execute_wave(
    manifest: dict[str, Any],
    authorization: dict[str, Any],
    adapter: DetectorAdapter,
    store: ExecutionStore,
) -> ExecutionCheckpoint:
    validate_sealed_manifest(manifest)
    validate_write_authorization(authorization, manifest, "CREATE_DETECTOR")
    _verify_target_identity(authorization, adapter)
    checkpoint = store.create(manifest, authorization)
    _validate_bindings(checkpoint, manifest, authorization)
    if checkpoint.authorization_hash != authorization["approval_hash"]:
        checkpoint.authorization_hash = authorization["approval_hash"]
        store.save(checkpoint)
    completed_refs = {result["object_ref"] for result in checkpoint.results}
    checkpoint.status = "EXECUTING"
    checkpoint.failure_category = None
    store.save(checkpoint)
    try:
        for entry in manifest["entries"]:
            validate_write_authorization(authorization, manifest, "CREATE_DETECTOR")
            if entry["object_ref"] in completed_refs:
                continue
            pending = entry["object_ref"] in checkpoint.pending_create_refs
            existing = _find_existing(adapter, entry)
            if pending:
                if existing is None:
                    raise ValueError("pending create is not yet visible; retry later without issuing another POST")
                actual = existing
                outcome = "created"
                checkpoint.pending_create_refs.remove(entry["object_ref"])
                checkpoint.created_count += 1
            elif existing is None:
                if checkpoint.created_count >= authorization["max_creates"]:
                    raise ValueError("execution create cap reached")
                checkpoint.pending_create_refs.append(entry["object_ref"])
                store.save(checkpoint)
                try:
                    validate_write_authorization(authorization, manifest, "CREATE_DETECTOR")
                except Exception:
                    checkpoint.pending_create_refs.remove(entry["object_ref"])
                    store.save(checkpoint)
                    raise
                try:
                    actual = _create_once_with_reconciliation(adapter, entry)
                except AdapterError as exc:
                    if exc.create_definitively_rejected:
                        checkpoint.pending_create_refs.remove(entry["object_ref"])
                        store.save(checkpoint)
                    raise
                outcome = "created"
                checkpoint.pending_create_refs.remove(entry["object_ref"])
                checkpoint.created_count += 1
            else:
                actual = existing
                outcome = "reused"
                checkpoint.reused_count += 1
            checkpoint.results.append({
                "object_ref": entry["object_ref"],
                "execution_key": entry["execution_key"],
                "target_kind": "detector",
                "outcome": outcome,
                "target_id": actual["id"],
                "validated": True,
            })
            checkpoint.validated_count += 1
            checkpoint.status = "PARTIAL"
            store.save(checkpoint)
        checkpoint.status = "COMPLETED"
        store.save(checkpoint)
        return checkpoint
    except Exception as exc:
        checkpoint.status = "FAILED"
        checkpoint.failure_category = getattr(exc, "category", type(exc).__name__.lower())
        store.save(checkpoint)
        raise


def validate_wave(
    manifest: dict[str, Any],
    authorization: dict[str, Any],
    adapter: DetectorAdapter,
    store: ExecutionStore,
) -> ExecutionCheckpoint:
    validate_sealed_manifest(manifest)
    validate_write_authorization(authorization, manifest, "VALIDATE_DETECTOR")
    _verify_target_identity(authorization, adapter)
    checkpoint = store.load()
    _validate_bindings(checkpoint, manifest, authorization)
    if checkpoint.authorization_hash != authorization["approval_hash"]:
        checkpoint.authorization_hash = authorization["approval_hash"]
    for result in checkpoint.results:
        result["validated"] = False
    checkpoint.validated_count = 0
    checkpoint.status = "PARTIAL"
    checkpoint.failure_category = None
    store.save(checkpoint)
    by_ref = {entry["object_ref"]: entry for entry in manifest["entries"]}
    try:
        for result in checkpoint.results:
            validate_write_authorization(authorization, manifest, "VALIDATE_DETECTOR")
            entry = by_ref[result["object_ref"]]
            actual = adapter.get_detector(result["target_id"])
            _assert_equivalent(entry, actual)
            result["validated"] = True
            checkpoint.validated_count += 1
            store.save(checkpoint)
        checkpoint.status = "VALIDATED" if checkpoint.validated_count == len(manifest["entries"]) else "PARTIAL"
        store.save(checkpoint)
        return checkpoint
    except Exception as exc:
        checkpoint.status = "FAILED"
        checkpoint.failure_category = getattr(exc, "category", type(exc).__name__.lower())
        store.save(checkpoint)
        raise


def clear_unresolved_pending(
    manifest: dict[str, Any],
    authorization: dict[str, Any],
    adapter: DetectorAdapter,
    store: ExecutionStore,
) -> tuple[ExecutionCheckpoint, list[str]]:
    """Clear only pending intents proven absent by a fresh exact-marker lookup."""
    validate_sealed_manifest(manifest)
    validate_write_authorization(authorization, manifest, "VALIDATE_DETECTOR")
    _verify_target_identity(authorization, adapter)
    checkpoint = store.load()
    _validate_bindings(checkpoint, manifest, authorization)
    entries = {entry["object_ref"]: entry for entry in manifest["entries"]}
    cleared: list[str] = []
    for object_ref in list(checkpoint.pending_create_refs):
        validate_write_authorization(authorization, manifest, "VALIDATE_DETECTOR")
        if _find_existing(adapter, entries[object_ref]) is None:
            checkpoint.pending_create_refs.remove(object_ref)
            cleared.append(object_ref)
    if cleared:
        checkpoint.status = "PARTIAL"
        checkpoint.failure_category = None
    store.save(checkpoint)
    return checkpoint, cleared


def rollback_proposal(checkpoint: ExecutionCheckpoint) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "source_session_id": checkpoint.source_session_id,
        "wave_id": checkpoint.wave_id,
        "created_target_ids": [
            result["target_id"] for result in checkpoint.results if result["outcome"] == "created"
        ],
        "automatic_rollback_authorized": False,
        "recommended_action": "customer_reviewed_manual_cleanup",
        "warning": "Deleting a detector can stop its SignalFlow job and emit stop notifications; review each target before cleanup.",
    }


__all__ = ["clear_unresolved_pending", "execute_wave", "rollback_proposal", "validate_wave"]
