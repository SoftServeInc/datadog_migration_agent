"""Sanitized discovery assessment and human-readable report generation."""

from __future__ import annotations

import re
from collections import Counter
from typing import Any

from .capabilities import validate_capability_catalog
from .ir import OBJECT_REF, validate_inventory_ir
from .model import Compatibility, Disposition
from .rules import RATIONALES, TARGET_REPRESENTATIONS, classify_object
from .security import assert_codex_safe, canonical_document_hash


SHA256 = re.compile(r"^[a-f0-9]{64}$")


def validate_assessment(assessment: dict[str, Any]) -> None:
    expected = {
        "schema_version", "source_platform", "target", "summary", "inventory_summary",
        "hygiene_summary", "dependency_graph", "actions", "strategies", "recommended_waves",
        "risk_observations", "limitations", "next_action", "safety", "assessment_hash",
    }
    if set(assessment) != expected or assessment.get("schema_version") != "1.0":
        raise ValueError("discovery assessment fields or version are invalid")
    if assessment.get("source_platform") != "datadog" or assessment.get("target") not in {
        "splunk_observability_cloud", "splunk_platform", "both"
    }:
        raise ValueError("discovery assessment source or target is invalid")
    if assessment.get("safety") != {
        "raw_customer_data_included": False,
        "pii_included": False,
        "external_mutations_enabled": False,
        "execution_available": False,
    }:
        raise ValueError("discovery assessment safety invariants are invalid")
    actions = assessment.get("actions")
    action_fields = {
        "object_ref", "object_type", "target", "compatibility", "disposition", "confidence",
        "confidence_score", "risk_level", "effort_points", "dependency_count",
        "unresolved_dependency_count", "dependencies", "rule_id", "rationale_code", "rationale",
        "proposed_target_representation", "recommended_migration_approach", "validation_strategy",
        "rollback_strategy", "dependency_cycle_member",
    }
    if not isinstance(actions, list):
        raise ValueError("discovery assessment actions are invalid")
    for item in actions:
        if not isinstance(item, dict) or set(item) != action_fields:
            raise ValueError("discovery assessment action fields are invalid")
        if not isinstance(item["object_ref"], str) or not OBJECT_REF.fullmatch(item["object_ref"]):
            raise ValueError("discovery assessment object reference is invalid")
        if item["compatibility"] not in {value.value for value in Compatibility}:
            raise ValueError("discovery assessment compatibility is invalid")
        if item["disposition"] not in {value.value for value in Disposition}:
            raise ValueError("discovery assessment disposition is invalid")
        if item["target"] not in {"splunk_observability_cloud", "splunk_platform"}:
            raise ValueError("discovery assessment action target is invalid")
        representations = TARGET_REPRESENTATIONS[item["target"]]
        if item["object_type"] not in representations or item["proposed_target_representation"] != representations[
            item["object_type"]
        ]:
            raise ValueError("discovery assessment target representation is invalid")
        if item["recommended_migration_approach"] != item["disposition"].lower():
            raise ValueError("discovery assessment migration approach is invalid")
        if item["confidence"] not in {"low", "medium", "high"} or not isinstance(
            item["confidence_score"], (int, float)
        ) or isinstance(item["confidence_score"], bool) or not 0 <= item["confidence_score"] <= 1:
            raise ValueError("discovery assessment confidence is invalid")
        if item["risk_level"] not in {"low", "medium", "high"}:
            raise ValueError("discovery assessment risk is invalid")
        if not all(
            isinstance(item[field], int) and not isinstance(item[field], bool) and item[field] >= 0
            for field in ("effort_points", "dependency_count", "unresolved_dependency_count")
        ):
            raise ValueError("discovery assessment action counts are invalid")
        dependencies = item["dependencies"]
        if not isinstance(dependencies, list) or len(dependencies) != item["dependency_count"]:
            raise ValueError("discovery assessment dependencies are invalid")
        for dependency in dependencies:
            if not isinstance(dependency, dict) or set(dependency) != {
                "object_ref", "relationship", "resolved"
            } or not isinstance(dependency["object_ref"], str) or not OBJECT_REF.fullmatch(
                dependency["object_ref"]
            ) or dependency["relationship"] != "depends_on" or not isinstance(dependency["resolved"], bool):
                raise ValueError("discovery assessment dependency is invalid")
        if item["unresolved_dependency_count"] != sum(not value["resolved"] for value in dependencies):
            raise ValueError("discovery assessment unresolved dependency count is invalid")
        if item["rationale_code"] not in RATIONALES or item["rationale"] != RATIONALES[item["rationale_code"]]:
            raise ValueError("discovery assessment rationale is invalid")
        if item["rule_id"] != "ACCESS-GATE" and not re.fullmatch(r"CR-[A-Z0-9_-]{1,48}", item["rule_id"]):
            raise ValueError("discovery assessment rule ID is invalid")
        if item["validation_strategy"] != "semantic_result_comparison" or item["rollback_strategy"] != (
            "retain_source_and_remove_unapproved_target_draft"
        ):
            raise ValueError("discovery assessment validation or rollback strategy is invalid")
        if not isinstance(item["dependency_cycle_member"], bool):
            raise ValueError("discovery assessment dependency cycle flag is invalid")
    embedded = assessment.get("assessment_hash")
    if not isinstance(embedded, str) or not SHA256.fullmatch(embedded):
        raise ValueError("discovery assessment hash is invalid")
    if embedded != canonical_document_hash(assessment, "assessment_hash"):
        raise ValueError("discovery assessment hash mismatch")
    assert_codex_safe(assessment)


def _targets(target: str) -> list[str]:
    if target == "both":
        return ["splunk_observability_cloud", "splunk_platform"]
    if target not in {"splunk_observability_cloud", "splunk_platform"}:
        raise ValueError("unsupported assessment target")
    return [target]


def build_assessment(
    ir: dict[str, Any],
    catalog: dict[str, Any],
    target: str,
    ruleset: dict[str, Any],
) -> dict[str, Any]:
    validate_inventory_ir(ir)
    validate_capability_catalog(catalog)
    cycle_refs = {
        value
        for cycle in ir.get("graph", {}).get("cycles", [])
        for value in cycle[:-1]
    }
    actions = [
        classify_object(item, target_name, catalog, ruleset)
        for target_name in _targets(target)
        for item in ir.get("objects", [])
    ]
    for action in actions:
        action["dependency_cycle_member"] = action["object_ref"] in cycle_refs
    compatibility = Counter(item["compatibility"] for item in actions)
    disposition = Counter(item["disposition"] for item in actions)
    by_target = {
        target_name: dict(sorted(Counter(
            item["compatibility"] for item in actions if item["target"] == target_name
        ).items()))
        for target_name in _targets(target)
    }
    safe_actions = [
        item for item in actions
        if item["compatibility"] in {"DIRECT", "TRANSFORMABLE"}
        and item["confidence_score"] >= 0.60
        and item["unresolved_dependency_count"] == 0
        and not item["dependency_cycle_member"]
    ]
    blocked = [item for item in actions if item["compatibility"].startswith("BLOCKED_")]
    assessment: dict[str, Any] = {
        "schema_version": "1.0",
        "source_platform": "datadog",
        "target": target,
        "summary": {
            "source_object_count": int(ir.get("graph", {}).get("node_count", 0)),
            "assessment_action_count": len(actions),
            "compatibility_counts": dict(sorted(compatibility.items())),
            "disposition_counts": dict(sorted(disposition.items())),
            "compatibility_by_target": by_target,
            "estimated_effort_points": sum(item["effort_points"] for item in actions),
            "blocked_action_count": len(blocked),
        },
        "inventory_summary": ir.get("summary", {}),
        "hygiene_summary": {
            "duplicate_candidate_group_count": len(
                ir.get("hygiene", {}).get("duplicate_candidate_groups", [])
            ),
            "ownerless_count": ir.get("hygiene", {}).get("ownerless_count", 0),
            "orphan_reference_count": ir.get("hygiene", {}).get("orphan_reference_count", 0),
            "invalid_status_count": ir.get("hygiene", {}).get("invalid_status_count", 0),
        },
        "dependency_graph": {
            "node_count": ir.get("graph", {}).get("node_count", 0),
            "edge_count": ir.get("graph", {}).get("edge_count", 0),
            "missing_dependency_count": len(ir.get("graph", {}).get("missing_dependencies", [])),
            "cycle_count": len(ir.get("graph", {}).get("cycles", [])),
        },
        "actions": actions,
        "strategies": [
            {
                "strategy_id": "full",
                "scope": "all_assessed_actions",
                "candidate_count": len(actions),
                "risk": "high",
                "requires_manual_intervention": True,
            },
            {
                "strategy_id": "safe_staged",
                "scope": "direct_or_transformable_without_unresolved_dependencies",
                "candidate_count": len(safe_actions),
                "risk": "medium",
                "requires_manual_intervention": False,
            },
            {
                "strategy_id": "customer_selected",
                "scope": "explicit_pseudonymous_object_refs",
                "candidate_count": len(actions),
                "risk": "scope_dependent",
                "requires_manual_intervention": True,
            },
        ],
        "recommended_waves": [
            {
                "wave": 0,
                "purpose": "resolve_access_and_dependency_blockers",
                "candidate_count": len(blocked),
            },
            {
                "wave": 1,
                "purpose": "translate_low_risk_objects",
                "candidate_count": len(safe_actions),
            },
            {
                "wave": 2,
                "purpose": "adapt_partial_or_high_risk_objects",
                "candidate_count": sum(item["compatibility"] == "PARTIAL" for item in actions),
            },
            {
                "wave": 3,
                "purpose": "redesign_manual_unknown_or_unsupported",
                "candidate_count": sum(item["compatibility"] in {
                    "REQUIRES_REDESIGN", "MANUAL", "UNKNOWN", "UNSUPPORTED"
                } for item in actions),
            },
        ],
        "risk_observations": [
            "No classification asserts semantic equivalence without target validation.",
            "Missing dependencies must be resolved before any future execution wave.",
            "Dual-target planning duplicates assessment effort and may produce different target semantics.",
            "Raw source expressions remain local and are excluded from this report.",
        ],
        "limitations": [
            "Configuration presence does not prove active telemetry usage.",
            "Runtime query parity and target object creation are not tested by this MVP.",
            "Cost impact is omitted unless separately authorized and evidenced.",
        ],
        "next_action": "review_report_and_select_strategy",
        "safety": {
            "raw_customer_data_included": False,
            "pii_included": False,
            "external_mutations_enabled": False,
            "execution_available": False,
        },
    }
    assessment["assessment_hash"] = canonical_document_hash(assessment, "assessment_hash")
    validate_assessment(assessment)
    return assessment


def markdown_report(assessment: dict[str, Any]) -> str:
    summary = assessment["summary"]
    graph = assessment["dependency_graph"]
    hygiene = assessment["hygiene_summary"]
    lines = [
        "# Observability migration discovery report",
        "",
        "This report is sanitized and assessment-only. No source or target resources were changed.",
        "",
        "## Executive summary",
        "",
        f"- Source objects assessed: **{summary['source_object_count']}**",
        f"- Target assessment actions: **{summary['assessment_action_count']}**",
        f"- Blocked actions: **{summary['blocked_action_count']}**",
        f"- Estimated relative effort points: **{summary['estimated_effort_points']}**",
        f"- Assessment hash: `{assessment['assessment_hash']}`",
        "",
        "## Compatibility matrix",
        "",
        "| Target | Classification | Count |",
        "|---|---|---:|",
    ]
    for target, counts in assessment["summary"]["compatibility_by_target"].items():
        for classification, count in counts.items():
            lines.append(f"| {target} | `{classification}` | {count} |")
    lines.extend([
        "",
        "## Hygiene summary",
        "",
        f"- Duplicate candidate groups: **{hygiene['duplicate_candidate_group_count']}**",
        f"- Ownerless configured objects: **{hygiene['ownerless_count']}**",
        f"- Orphan references: **{hygiene['orphan_reference_count']}**",
        f"- Invalid or unrecognized statuses: **{hygiene['invalid_status_count']}**",
        "",
        "Hygiene findings are review candidates, not automatic deletion decisions.",
        "",
        "## Dependency graph",
        "",
        f"- Nodes: **{graph['node_count']}**",
        f"- Edges: **{graph['edge_count']}**",
        f"- Missing dependencies: **{graph['missing_dependency_count']}**",
        f"- Cycles: **{graph['cycle_count']}**",
        "",
        "## Migration strategies",
        "",
        "| Strategy | Scope | Candidates | Risk |",
        "|---|---|---:|---|",
    ])
    for strategy in assessment["strategies"]:
        lines.append(
            f"| `{strategy['strategy_id']}` | {strategy['scope']} | "
            f"{strategy['candidate_count']} | {strategy['risk']} |"
        )
    lines.extend(["", "## Recommended waves", ""])
    for wave in assessment["recommended_waves"]:
        lines.append(f"{wave['wave']}. `{wave['purpose']}` — {wave['candidate_count']} candidates.")
    lines.extend(["", "## Risks and limitations", ""])
    for value in assessment["risk_observations"] + assessment["limitations"]:
        lines.append(f"- {value}")
    lines.extend([
        "",
        "## Security, validation, and rollback",
        "",
        "- Raw identifiers, expressions, PII, and credentials are excluded from this report.",
        "- Future validation must compare source intent with target results; object existence is insufficient.",
        "- Future rollback must retain source objects and remove only target drafts created by an approved wave.",
        "- Cost impact is omitted unless separately authorized and supported by customer billing evidence.",
        "",
        "## Suggested next action",
        "",
        "Review this report, select a migration strategy, and approve the resulting dry-run plan. "
        "The current implementation cannot execute target changes.",
        "",
    ])
    return "\n".join(lines)
