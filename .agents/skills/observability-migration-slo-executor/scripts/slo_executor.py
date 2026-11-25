"""Idempotent create-only SLO execution and read-back validation."""

from __future__ import annotations

import copy
import re
from typing import Any

from slo_adapter import SloAdapter, SloAdapterError
from slo_authorization import validate_slo_authorization
from slo_common import value_hash
from slo_manifest import validate_slo_manifest
from slo_state import SloCheckpoint, SloStore


def _project_expected(expected: Any, actual: Any) -> Any:
    if isinstance(expected, dict):
        if not isinstance(actual, dict):
            return None
        return {key: _project_expected(value, actual.get(key)) for key, value in expected.items()}
    if isinstance(expected, list):
        if not isinstance(actual, list) or len(actual) != len(expected):
            return None
        return [_project_expected(item, actual[index]) for index, item in enumerate(expected)]
    return actual


def _normalize_server_alert_rules(expected: dict[str, Any], actual: dict[str, Any]) -> dict[str, Any]:
    """Normalize only Splunk server-managed SLO rule fields for comparison."""
    normalized = copy.deepcopy(actual)
    try:
        expected_groups = expected["targets"][0]["sloAlertRules"]
        actual_groups = normalized["targets"][0]["sloAlertRules"]
    except (KeyError, IndexError, TypeError) as exc:
        raise ValueError("target SLO alert rule structure differs") from exc
    if (
        not isinstance(actual_groups, list)
        or len(actual_groups) != len(expected_groups)
        or {group.get("type") for group in actual_groups if isinstance(group, dict)}
        != {group["type"] for group in expected_groups}
    ):
        raise ValueError("target SLO alert group set differs")
    by_type = {group["type"]: group for group in actual_groups}
    reordered: list[dict[str, Any]] = []
    for expected_group in expected_groups:
        group = by_type[expected_group["type"]]
        rules = group.get("rules")
        if not isinstance(rules, list) or len(rules) != 1 or not isinstance(rules[0], dict):
            raise ValueError("target SLO alert rule structure differs")
        rule = rules[0]
        label = rule.get("detectLabel")
        expected_rule = expected_group["rules"][0]
        if (
            not isinstance(label, str)
            or label != expected_rule["detectLabel"]
            and not re.fullmatch(r"[A-Za-z0-9_-]{7}", label)
        ):
            raise ValueError("target SLO server-managed detect label is invalid")
        rule["detectLabel"] = expected_rule["detectLabel"]
        calculated = rule.get("calculatedParameters")
        if expected_group["type"] == "BURN_RATE":
            required = {
                "burnRateThreshold1": 14.4,
                "burnRateThreshold2": 6,
                "longWindow1": "1h",
                "shortWindow1": "5m",
                "longWindow2": "6h",
                "shortWindow2": "30m",
            }
            if calculated is not None and calculated != required:
                raise ValueError("target SLO calculated burn-rate profile differs")
            if rule.get("parameters") == {}:
                if calculated is None:
                    raise ValueError("target SLO burn-rate parameters are missing")
                rule["parameters"] = copy.deepcopy(expected_rule["parameters"])
        elif calculated is not None and calculated != {
            "fireLasting": "3m", "percentOfLasting": 100.0,
        }:
            raise ValueError("target SLO calculated breach profile differs")
        reordered.append(group)
    normalized["targets"][0]["sloAlertRules"] = reordered
    return normalized


def _assert_equivalent(entry: dict[str, Any], actual: dict[str, Any]) -> None:
    expected = copy.deepcopy(entry["payload"])
    target_id = actual.get("id")
    if not isinstance(target_id, str) or not target_id:
        raise ValueError("target SLO has no valid ID")
    if actual.get("name") != entry["exact_name"]:
        raise ValueError("target SLO deterministic name differs")
    normalized = _normalize_server_alert_rules(expected, actual)
    if normalized.get("description") != expected.get("description"):
        description = normalized.get("description")
        if not isinstance(description, str) or not re.fullmatch(
            r"\[AI-Created\] Create-only Datadog metric SLO migration [a-f0-9]{16}; "
            r"source warning status is not represented\.",
            description,
        ):
            raise ValueError("target SLO provenance description differs")
        normalized["description"] = expected["description"]
    groups = normalized["targets"][0]["sloAlertRules"]
    rules = [rule for group in groups for rule in group["rules"]]
    if any(
        not isinstance(rule, dict) or rule.get("disabled") is not True
        or rule.get("notifications") != [] for rule in rules
    ):
        raise ValueError("target SLO contains an enabled or notifying alert rule")
    projected = _project_expected(expected, normalized)
    if projected is None or value_hash(projected) != value_hash(expected):
        raise ValueError("target SLO differs from the sealed payload")


def find_existing_slo(adapter: SloAdapter, entry: dict[str, Any]) -> dict[str, Any] | None:
    matches = adapter.search_slos(entry["exact_name"])
    if len(matches) > 1:
        raise ValueError("multiple SLOs share the deterministic migration name")
    if not matches:
        return None
    target_id = matches[0].get("id")
    if not isinstance(target_id, str) or not target_id:
        raise ValueError("existing SLO has no valid ID")
    actual = adapter.get_slo(target_id)
    _assert_equivalent(entry, actual)
    return actual


def _create_once(adapter: SloAdapter, entry: dict[str, Any]) -> dict[str, Any]:
    try:
        created = adapter.create_slo(entry["payload"])
    except SloAdapterError as exc:
        if exc.create_definitively_rejected:
            raise
        existing = find_existing_slo(adapter, entry)
        if existing is not None:
            return existing
        raise SloAdapterError("ambiguous_create_unresolved", retriable=True) from None
    target_id = created.get("id")
    if not isinstance(target_id, str) or not target_id:
        existing = find_existing_slo(adapter, entry)
        if existing is not None:
            return existing
        raise SloAdapterError("post_create_identity_unresolved", retriable=True)
    try:
        actual = adapter.get_slo(target_id)
        _assert_equivalent(entry, actual)
        return actual
    except Exception:
        raise SloAdapterError("post_create_validation_unresolved", retriable=True) from None


def _verify_target(authorization: dict[str, Any], adapter: SloAdapter) -> None:
    if authorization["target_org_id_hash"] != value_hash(adapter.get_organization_id()):
        raise ValueError("runtime Splunk organization differs from the SLO authorization")


def _validate_bindings(
    checkpoint: SloCheckpoint, manifest: dict[str, Any], authorization: dict[str, Any],
) -> None:
    if (
        checkpoint.source_session_id != manifest["source_session_id"]
        or checkpoint.wave_id != manifest["wave_id"]
        or checkpoint.plan_hash != manifest["plan_hash"]
        or checkpoint.manifest_hash != manifest["manifest_hash"]
    ):
        raise ValueError("SLO checkpoint binding mismatch")
    if checkpoint.authorization_hash != authorization["approval_hash"]:
        checkpoint.authorization_hash = authorization["approval_hash"]


def execute_slo_wave(
    manifest: dict[str, Any], authorization: dict[str, Any],
    adapter: SloAdapter, store: SloStore,
) -> SloCheckpoint:
    validate_slo_manifest(manifest)
    validate_slo_authorization(authorization, manifest, "CREATE_SLO")
    _verify_target(authorization, adapter)
    checkpoint = store.create(manifest, authorization)
    _validate_bindings(checkpoint, manifest, authorization)
    entry = manifest["entry"]
    if checkpoint.result is not None:
        actual = adapter.get_slo(checkpoint.result["target_id"])
        _assert_equivalent(entry, actual)
        checkpoint.result["validated"] = True
        checkpoint.status = "COMPLETED"
        checkpoint.failure_category = None
        store.save(checkpoint)
        return checkpoint
    checkpoint.status = "EXECUTING"
    checkpoint.failure_category = None
    store.save(checkpoint)
    try:
        validate_slo_authorization(authorization, manifest, "CREATE_SLO")
        existing = find_existing_slo(adapter, entry)
        if checkpoint.pending_create_ref is not None:
            if existing is None:
                raise ValueError("pending SLO create is not yet visible; retry later without another POST")
            actual = existing
            outcome = "created"
        elif existing is not None:
            actual = existing
            outcome = "reused"
        else:
            checkpoint.pending_create_ref = entry["object_ref"]
            store.save(checkpoint)
            try:
                validate_slo_authorization(authorization, manifest, "CREATE_SLO")
            except Exception:
                checkpoint.pending_create_ref = None
                store.save(checkpoint)
                raise
            try:
                actual = _create_once(adapter, entry)
            except SloAdapterError as exc:
                if exc.create_definitively_rejected:
                    checkpoint.pending_create_ref = None
                    store.save(checkpoint)
                raise
            outcome = "created"
        checkpoint.pending_create_ref = None
        checkpoint.result = {
            "object_ref": entry["object_ref"],
            "source_refs": entry["source_refs"],
            "execution_key": entry["execution_key"],
            "target_kind": "slo",
            "outcome": outcome,
            "target_id": actual["id"],
            "validated": True,
        }
        checkpoint.status = "COMPLETED"
        store.save(checkpoint)
        return checkpoint
    except Exception as exc:
        checkpoint.status = "FAILED"
        checkpoint.failure_category = getattr(exc, "category", type(exc).__name__.lower())
        store.save(checkpoint)
        raise


def validate_slo_wave(
    manifest: dict[str, Any], authorization: dict[str, Any],
    adapter: SloAdapter, store: SloStore,
) -> SloCheckpoint:
    validate_slo_manifest(manifest)
    validate_slo_authorization(authorization, manifest, "VALIDATE_SLO")
    _verify_target(authorization, adapter)
    checkpoint = store.load()
    _validate_bindings(checkpoint, manifest, authorization)
    if checkpoint.result is None:
        raise ValueError("SLO execution has no result to validate")
    checkpoint.status = "EXECUTING"
    checkpoint.result["validated"] = False
    store.save(checkpoint)
    try:
        validate_slo_authorization(authorization, manifest, "VALIDATE_SLO")
        actual = adapter.get_slo(checkpoint.result["target_id"])
        _assert_equivalent(manifest["entry"], actual)
        checkpoint.result["validated"] = True
        checkpoint.status = "VALIDATED"
        checkpoint.failure_category = None
        store.save(checkpoint)
        return checkpoint
    except Exception as exc:
        checkpoint.status = "FAILED"
        checkpoint.failure_category = getattr(exc, "category", type(exc).__name__.lower())
        store.save(checkpoint)
        raise


def clear_pending_slo(
    manifest: dict[str, Any], authorization: dict[str, Any],
    adapter: SloAdapter, store: SloStore,
) -> SloCheckpoint:
    validate_slo_authorization(authorization, manifest, "VALIDATE_SLO")
    _verify_target(authorization, adapter)
    checkpoint = store.load()
    _validate_bindings(checkpoint, manifest, authorization)
    if checkpoint.pending_create_ref is None:
        raise ValueError("SLO checkpoint has no unresolved pending create")
    if find_existing_slo(adapter, manifest["entry"]) is not None:
        raise ValueError("pending SLO is now visible and must be resumed, not cleared")
    checkpoint.pending_create_ref = None
    checkpoint.status = "AUTHORIZED"
    checkpoint.failure_category = None
    store.save(checkpoint)
    return checkpoint


def rollback_proposal(checkpoint: SloCheckpoint) -> dict[str, Any]:
    created = checkpoint.result is not None and checkpoint.result["outcome"] == "created"
    return {
        "schema_version": "1.0",
        "source_session_id": checkpoint.source_session_id,
        "wave_id": checkpoint.wave_id,
        "created_target_ids": [checkpoint.result["target_id"]] if created else [],
        "automatic_rollback_authorized": False,
        "recommended_action": "customer_reviewed_manual_cleanup",
        "warning": "Deleting an SLO is outside this executor and requires separate review.",
    }


__all__ = [
    "clear_pending_slo", "execute_slo_wave", "rollback_proposal", "validate_slo_wave",
]
