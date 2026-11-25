"""Deterministic, non-executable migration plan generation."""

from __future__ import annotations

import re
from typing import Any

from .ir import OBJECT_REF
from .model import Compatibility, Disposition
from .report import validate_assessment
from .security import assert_codex_safe, canonical_document_hash


TARGET_PROVIDER_KEY = {
    "splunk_observability_cloud": "splunk_observability_cloud",
    "splunk_platform": "splunk_platform",
}
SHA256 = re.compile(r"^[a-f0-9]{64}$")


def validate_migration_plan(plan: dict[str, Any]) -> None:
    expected = {
        "schema_version", "mode", "strategy", "assessment_hash", "target", "execution_enabled",
        "mutating_operations", "steps", "summary", "approval", "safety", "plan_hash",
    }
    if set(plan) != expected or plan.get("schema_version") != "1.1" or plan.get("mode") != "dry_run":
        raise ValueError("migration plan fields, version, or mode are invalid")
    if plan.get("strategy") not in {"full", "safe_staged", "customer_selected"}:
        raise ValueError("migration plan strategy is invalid")
    if plan.get("target") not in {"splunk_observability_cloud", "splunk_platform", "both"}:
        raise ValueError("migration plan target is invalid")
    if plan.get("execution_enabled") is not False or plan.get("mutating_operations") != []:
        raise ValueError("migration plan must remain non-executable")
    if plan.get("approval") != {
        "required_for_any_future_execution": True,
        "plan_review_approved": False,
        "external_mutations_authorized": False,
    }:
        raise ValueError("migration plan approval invariants are invalid")
    if plan.get("safety") != {
        "source_mutations_enabled": False,
        "target_mutations_enabled": False,
        "terraform_apply_enabled": False,
        "git_write_enabled": False,
    }:
        raise ValueError("migration plan safety invariants are invalid")
    steps = plan.get("steps")
    if not isinstance(steps, list):
        raise ValueError("migration plan steps are invalid")
    expected_sequence = list(range(1, len(steps) + 1))
    if [step.get("sequence") for step in steps if isinstance(step, dict)] != expected_sequence:
        raise ValueError("migration plan step sequence is invalid")
    for step in steps:
        if not isinstance(step, dict) or step.get("executable") is not False:
            raise ValueError("migration plan step must be non-executable")
        if not isinstance(step.get("object_ref"), str) or not OBJECT_REF.fullmatch(step["object_ref"]):
            raise ValueError("migration plan object reference is invalid")
        if step.get("proposed_operation") not in {
            "PROPOSE_CREATE", "PROPOSE_TRANSFORM", "PROPOSE_MANUAL_DESIGN", "PROPOSE_EXCLUDE",
            "PROPOSE_SKIP", "PROPOSE_HOLD",
        }:
            raise ValueError("migration plan proposed operation is invalid")
    for field in ("assessment_hash", "plan_hash"):
        value = plan.get(field)
        if not isinstance(value, str) or not SHA256.fullmatch(value):
            raise ValueError(f"migration plan {field} is invalid")
    if plan["plan_hash"] != canonical_document_hash(plan, "plan_hash"):
        raise ValueError("migration plan hash mismatch")
    assert_codex_safe(plan)


def _dependency_order(actions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_key = {(str(item["target"]), str(item["object_ref"])): item for item in actions}
    ordered: list[dict[str, Any]] = []
    active: set[tuple[str, str]] = set()
    visited: set[tuple[str, str]] = set()

    def visit(key: tuple[str, str]) -> None:
        if key in visited or key in active:
            return
        active.add(key)
        item = by_key[key]
        dependency_refs = sorted(
            str(value["object_ref"])
            for value in item.get("dependencies", [])
            if value.get("resolved") is True
        )
        for dependency_ref in dependency_refs:
            dependency_key = (key[0], dependency_ref)
            if dependency_key in by_key:
                visit(dependency_key)
        active.remove(key)
        visited.add(key)
        ordered.append(item)

    for value in sorted(by_key):
        visit(value)
    return ordered


def _classification(
    item: dict[str, Any], blocker: Compatibility | None
) -> tuple[Compatibility, Disposition, str]:
    if blocker == Compatibility.BLOCKED_BY_PERMISSIONS:
        return Compatibility.BLOCKED_BY_PERMISSIONS, Disposition.DEFER, "target read access is not configured or was denied"
    if blocker == Compatibility.BLOCKED_BY_DEPENDENCY:
        return Compatibility.BLOCKED_BY_DEPENDENCY, Disposition.DEFER, "target read probe is unavailable or incomplete"
    source_type = str(item.get("source_type", "unknown"))
    complexity = str(item.get("complexity", "unknown"))
    if source_type == "synthetic":
        return Compatibility.REQUIRES_REDESIGN, Disposition.REDESIGN, "synthetic behavior requires target-specific validation"
    if source_type in {"log_pipeline", "log_index"}:
        return Compatibility.PARTIAL, Disposition.ADAPT, "log routing and retention semantics require adaptation"
    if complexity == "high":
        return Compatibility.PARTIAL, Disposition.ADAPT, "high-complexity object requires semantic validation"
    if source_type in {"dashboard", "monitor", "slo"}:
        return Compatibility.TRANSFORMABLE, Disposition.ADAPT, "intent can be translated but target behavior must be verified"
    return Compatibility.UNKNOWN, Disposition.DEFER, "insufficient allowlisted evidence for deterministic classification"


def build_plan(
    projection: dict[str, Any],
    preflight: dict[str, Any],
    target: str,
    capability_catalog: dict[str, Any] | None = None,
) -> dict[str, Any]:
    assert_codex_safe(projection)
    targets = ["splunk_observability_cloud", "splunk_platform"] if target == "both" else [target]
    providers = preflight.get("providers", {})
    actions: list[dict[str, Any]] = []
    for target_name in targets:
        if target_name not in TARGET_PROVIDER_KEY:
            raise ValueError(f"unsupported target: {target_name}")
        provider = providers.get(TARGET_PROVIDER_KEY[target_name], {})
        configured = bool(provider.get("target_read_configured"))
        blocker: Compatibility | None = None
        if not configured:
            blocker = Compatibility.BLOCKED_BY_PERMISSIONS
        if capability_catalog:
            capability = capability_catalog.get("providers", {}).get(target_name, {})
            live_status = str(capability.get("live_probe_status", "not_run"))
            if live_status in {"denied", "invalid", "not_configured"}:
                blocker = Compatibility.BLOCKED_BY_PERMISSIONS
            elif live_status not in {"available", "not_run"}:
                blocker = Compatibility.BLOCKED_BY_DEPENDENCY
        for item in projection.get("objects", []):
            compatibility, disposition, reason = _classification(item, blocker)
            actions.append({
                "object_ref": item["object_ref"],
                "source_type": item["source_type"],
                "target": target_name,
                "compatibility": compatibility.value,
                "disposition": disposition.value,
                "confidence": "low",
                "reason": reason,
                "operation": "ASSESS_ONLY",
            })
    plan: dict[str, Any] = {
        "schema_version": "1.0",
        "mode": "dry_run",
        "target": target,
        "capability_catalog_used": capability_catalog is not None,
        "execution_enabled": False,
        "mutating_operations": [],
        "actions": actions,
        "approval": {"required_for_execution": True, "granted": False},
        "safety": {
            "source_mutations_enabled": False,
            "target_mutations_enabled": False,
            "terraform_apply_enabled": False,
        },
    }
    plan["plan_hash"] = canonical_document_hash(plan, "plan_hash")
    assert_codex_safe(plan)
    return plan


def build_plan_from_assessment(
    assessment: dict[str, Any],
    strategy: str,
    selected_refs: list[str] | None = None,
) -> dict[str, Any]:
    validate_assessment(assessment)
    actions = list(assessment.get("actions", []))
    if strategy == "safe_staged":
        selected = [
            item for item in actions
            if item.get("compatibility") in {"DIRECT", "TRANSFORMABLE"}
            and item.get("confidence_score", 0) >= 0.60
            and item.get("unresolved_dependency_count") == 0
            and item.get("dependency_cycle_member") is False
        ]
    elif strategy == "full":
        selected = actions
    elif strategy == "customer_selected":
        requested = set(selected_refs or [])
        if not requested:
            raise ValueError("customer_selected strategy requires at least one object ref")
        known = {str(item.get("object_ref")) for item in actions}
        if not requested.issubset(known):
            raise ValueError("customer-selected scope contains an unknown object ref")
        selected = [item for item in actions if item.get("object_ref") in requested]
    else:
        raise ValueError("unsupported migration strategy")

    operation_by_disposition = {
        "MIGRATE": "PROPOSE_CREATE",
        "ADAPT": "PROPOSE_TRANSFORM",
        "REDESIGN": "PROPOSE_MANUAL_DESIGN",
        "RETIRE": "PROPOSE_EXCLUDE",
        "SKIP": "PROPOSE_SKIP",
        "DEFER": "PROPOSE_HOLD",
    }
    ordered = _dependency_order(selected)
    steps = [
        {
            "sequence": index,
            "object_ref": item["object_ref"],
            "object_type": item["object_type"],
            "target": item["target"],
            "compatibility": item["compatibility"],
            "disposition": item["disposition"],
            "confidence_score": item["confidence_score"],
            "proposed_operation": operation_by_disposition[item["disposition"]],
            "proposed_target_representation": item["proposed_target_representation"],
            "dependency_count": item["dependency_count"],
            "dependency_cycle_member": item["dependency_cycle_member"],
            "validation_strategy": item["validation_strategy"],
            "rollback_strategy": item["rollback_strategy"],
            "executable": False,
        }
        for index, item in enumerate(ordered, 1)
    ]
    plan: dict[str, Any] = {
        "schema_version": "1.1",
        "mode": "dry_run",
        "strategy": strategy,
        "assessment_hash": assessment["assessment_hash"],
        "target": assessment["target"],
        "execution_enabled": False,
        "mutating_operations": [],
        "steps": steps,
        "summary": {
            "selected_action_count": len(steps),
            "manual_or_deferred_count": sum(
                item["disposition"] in {"REDESIGN", "DEFER"} for item in ordered
            ),
            "unresolved_dependency_count": sum(item["unresolved_dependency_count"] for item in ordered),
            "dependency_cycle_action_count": sum(item["dependency_cycle_member"] for item in ordered),
        },
        "approval": {
            "required_for_any_future_execution": True,
            "plan_review_approved": False,
            "external_mutations_authorized": False,
        },
        "safety": {
            "source_mutations_enabled": False,
            "target_mutations_enabled": False,
            "terraform_apply_enabled": False,
            "git_write_enabled": False,
        },
    }
    plan["plan_hash"] = canonical_document_hash(plan, "plan_hash")
    validate_migration_plan(plan)
    return plan
