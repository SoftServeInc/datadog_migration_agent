"""Strict loader and evaluator for declarative compatibility rules."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .model import Compatibility, Disposition
from .security import OBJECT_TYPES


RULE_PATH = Path(__file__).resolve().parents[2] / "references" / "compatibility-rules.v1.json"
RATIONALES = {
    "TARGET_ACCESS_DENIED": "Target assessment access is not configured or was denied.",
    "TARGET_DEPENDENCY_UNAVAILABLE": "Target assessment dependency is unavailable or incomplete.",
    "CONTROL_PLANE_TRANSLATION": "Control-plane intent requires target-specific translation and validation.",
    "HIGH_COMPLEXITY_ADAPTATION": "High-complexity behavior requires adaptation and semantic comparison.",
    "SYNTHETIC_REDESIGN": "Synthetic behavior requires target-specific redesign and replay validation.",
    "LOG_SEMANTICS_ADAPTATION": "Log routing, processing, indexing, or retention semantics require adaptation.",
    "INSUFFICIENT_EVIDENCE": "Available allowlisted evidence is insufficient for a stronger classification.",
}
TARGET_REPRESENTATIONS = {
    "splunk_observability_cloud": {
        "dashboard": "dashboard",
        "monitor": "detector",
        "slo": "service_level_objective",
        "synthetic": "synthetic_test_or_external_check",
        "log_index": "log_retention_policy",
        "log_pipeline": "log_processing_pipeline",
        "unknown": "manual_target_design",
    },
    "splunk_platform": {
        "dashboard": "dashboard",
        "monitor": "saved_search_alert",
        "slo": "service_level_definition",
        "synthetic": "external_test_and_ingestion",
        "log_index": "index_configuration",
        "log_pipeline": "ingest_or_search_time_processing",
        "unknown": "manual_target_design",
    },
}


def load_rules(path: Path | None = None) -> dict[str, Any]:
    value = json.loads((path or RULE_PATH).read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("schema_version") != "1.0":
        raise ValueError("compatibility rule schema is invalid")
    rules = value.get("rules")
    if not isinstance(rules, list) or not rules:
        raise ValueError("compatibility rules must be a non-empty list")
    seen: set[str] = set()
    for rule in rules:
        if not isinstance(rule, dict) or set(rule) != {
            "rule_id", "object_types", "complexities", "compatibility", "disposition", "rationale_code"
        }:
            raise ValueError("compatibility rule fields are invalid")
        rule_id = str(rule["rule_id"])
        if not rule_id.startswith("CR-") or rule_id in seen:
            raise ValueError("compatibility rule ID is invalid or duplicated")
        seen.add(rule_id)
        if not isinstance(rule["object_types"], list) or not isinstance(rule["complexities"], list):
            raise ValueError("compatibility rule selectors must be lists")
        if not rule["object_types"] or not set(rule["object_types"]).issubset(OBJECT_TYPES | {"*"}):
            raise ValueError("compatibility object type selector is invalid")
        if not rule["complexities"] or not set(rule["complexities"]).issubset({
            "low", "medium", "high", "unknown", "*"
        }):
            raise ValueError("compatibility complexity selector is invalid")
        Compatibility(str(rule["compatibility"]))
        Disposition(str(rule["disposition"]))
        if rule["rationale_code"] not in RATIONALES:
            raise ValueError("compatibility rationale code is invalid")
    return value


def _target_blocker(catalog: dict[str, Any], target: str) -> tuple[Compatibility, str] | None:
    provider = catalog.get("providers", {}).get(target, {})
    if not provider.get("configured"):
        return Compatibility.BLOCKED_BY_PERMISSIONS, "TARGET_ACCESS_DENIED"
    status = str(provider.get("live_probe_status", "not_run"))
    if status in {"denied", "invalid", "not_configured"}:
        return Compatibility.BLOCKED_BY_PERMISSIONS, "TARGET_ACCESS_DENIED"
    if status not in {"available", "not_run"}:
        return Compatibility.BLOCKED_BY_DEPENDENCY, "TARGET_DEPENDENCY_UNAVAILABLE"
    return None


def classify_object(
    item: dict[str, Any], target: str, catalog: dict[str, Any], ruleset: dict[str, Any]
) -> dict[str, Any]:
    blocker = _target_blocker(catalog, target)
    if blocker:
        compatibility, rationale_code = blocker
        disposition = Disposition.DEFER
        rule_id = "ACCESS-GATE"
    else:
        selected: dict[str, Any] | None = None
        for rule in ruleset["rules"]:
            types = rule["object_types"]
            levels = rule["complexities"]
            if ("*" in types or item["object_type"] in types) and (
                "*" in levels or item["complexity"] in levels
            ):
                selected = rule
                break
        if not selected:
            raise ValueError("no compatibility rule matched the IR object")
        compatibility = Compatibility(selected["compatibility"])
        disposition = Disposition(selected["disposition"])
        rationale_code = str(selected["rationale_code"])
        rule_id = str(selected["rule_id"])
    confidence_score = {
        Compatibility.DIRECT: 0.85,
        Compatibility.TRANSFORMABLE: 0.65,
        Compatibility.PARTIAL: 0.50,
        Compatibility.REQUIRES_REDESIGN: 0.40,
        Compatibility.MANUAL: 0.35,
        Compatibility.UNSUPPORTED: 0.70,
        Compatibility.UNKNOWN: 0.20,
        Compatibility.BLOCKED_BY_PERMISSIONS: 0.10,
        Compatibility.BLOCKED_BY_DEPENDENCY: 0.10,
    }[compatibility]
    confidence = "high" if confidence_score >= 0.75 else "medium" if confidence_score >= 0.5 else "low"
    return {
        "object_ref": item["object_ref"],
        "object_type": item["object_type"],
        "target": target,
        "compatibility": compatibility.value,
        "disposition": disposition.value,
        "confidence": confidence,
        "confidence_score": confidence_score,
        "risk_level": item["risk_level"],
        "effort_points": item["effort_points"],
        "dependency_count": len(item["dependencies"]),
        "unresolved_dependency_count": sum(not value["resolved"] for value in item["dependencies"]),
        "dependencies": item["dependencies"],
        "rule_id": rule_id,
        "rationale_code": rationale_code,
        "rationale": RATIONALES[rationale_code],
        "proposed_target_representation": TARGET_REPRESENTATIONS[target].get(
            item["object_type"], "manual_target_design"
        ),
        "recommended_migration_approach": disposition.value.lower(),
        "validation_strategy": "semantic_result_comparison",
        "rollback_strategy": "retain_source_and_remove_unapproved_target_draft",
    }
