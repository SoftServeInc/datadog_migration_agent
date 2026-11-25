"""Immutable source-bound manifest for one create-only Splunk SLO."""

from __future__ import annotations

import copy
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from slo_common import (
    OBJECT_REF, SESSION_ID, SHA256, SLO_MANIFEST_ID, SLO_WAVE_ID, canonical_hash, value_hash,
)
from slo_translation import translate_slo_bundle


SEVERITIES = {"Critical", "Major", "Minor", "Warning", "Info"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _bounded_text(value: Any, field: str, maximum: int) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ValueError(f"SLO {field} is missing or too long")
    if any(ord(character) < 32 and character not in "\n\t" for character in value):
        raise ValueError(f"SLO {field} contains control characters")
    return value


def validate_slo_payload(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) != {"name", "description", "type", "inputs", "targets"}:
        raise ValueError("SLO payload fields are invalid")
    result = copy.deepcopy(payload)
    _bounded_text(result["name"], "name", 255)
    _bounded_text(result["description"], "description", 1024)
    if result["type"] != "RequestBased":
        raise ValueError("only request-based SLO payloads are supported")
    inputs = result["inputs"]
    if not isinstance(inputs, dict) or set(inputs) != {
        "programText", "goodEventsLabel", "totalEventsLabel",
    }:
        raise ValueError("SLO inputs are invalid")
    program = _bounded_text(inputs["programText"], "programText", 100_000)
    if inputs["goodEventsLabel"] != "GOOD" or inputs["totalEventsLabel"] != "TOTAL":
        raise ValueError("SLO input labels are invalid")
    if not re.search(r"(?m)^GOOD\s*=", program) or not re.search(r"(?m)^TOTAL\s*=", program):
        raise ValueError("SLO program does not define good and total event labels")
    targets = result["targets"]
    if not isinstance(targets, list) or len(targets) != 1 or not isinstance(targets[0], dict):
        raise ValueError("SLO payload requires exactly one target")
    target = targets[0]
    if set(target) != {"type", "compliancePeriod", "slo", "sloAlertRules"}:
        raise ValueError("SLO target fields are invalid")
    objective = target["slo"]
    if (
        target["type"] != "RollingWindow"
        or target["compliancePeriod"] != "30d"
        or not isinstance(objective, (int, float))
        or isinstance(objective, bool)
        or not 0 < objective < 100
    ):
        raise ValueError("SLO target is outside the allowlisted rolling-window profile")
    groups = target["sloAlertRules"]
    if (
        not isinstance(groups, list) or len(groups) != 2
        or any(not isinstance(group, dict) for group in groups)
        or [group.get("type") for group in groups] != ["BREACH", "BURN_RATE"]
    ):
        raise ValueError("SLO requires disabled breach and burn-rate alert groups")
    for group in groups:
        if set(group) != {"type", "rules"}:
            raise ValueError("SLO alert group is invalid")
        rules = group["rules"]
        if not isinstance(rules, list) or len(rules) != 1 or not isinstance(rules[0], dict):
            raise ValueError("SLO alert group requires exactly one rule")
        rule = rules[0]
        if set(rule) != {
            "description", "detectLabel", "disabled", "notifications", "parameters", "severity",
        }:
            raise ValueError("SLO alert rule fields are invalid")
        _bounded_text(rule["description"], "rule description", 1024)
        if rule["disabled"] is not True or rule["notifications"] != []:
            raise ValueError("SLO rules must be disabled and notification-free")
        if rule["severity"] not in SEVERITIES:
            raise ValueError("SLO rule severity is invalid")
    breach, burn = groups[0]["rules"][0], groups[1]["rules"][0]
    if (
        not re.fullmatch(r"migration_breach_[a-f0-9]{16}", str(breach["detectLabel"]))
        or breach["parameters"] != {"fireLasting": "3m"}
    ):
        raise ValueError("SLO breach rule is outside the required safe profile")
    if (
        not re.fullmatch(r"migration_[a-f0-9]{16}", str(burn["detectLabel"]))
        or burn["parameters"] != {
            "burnRateThreshold_1": 14.4, "burnRateThreshold_2": 6,
        }
    ):
        raise ValueError("SLO burn-rate rule is outside the allowlisted profile")
    return result


def build_slo_manifest(
    session_id: str,
    wave_id: str,
    plan: dict[str, Any],
    plan_review_approval: dict[str, Any],
    inventory: dict[str, Any],
    salt: str,
    source_binding: dict[str, str],
) -> dict[str, Any]:
    if not SESSION_ID.fullmatch(session_id) or not SLO_WAVE_ID.fullmatch(wave_id):
        raise ValueError("invalid session or SLO wave ID")
    translated = translate_slo_bundle(inventory, salt)
    if translated is None:
        raise ValueError("no allowlisted Datadog metric SLO bundle can be translated automatically")
    approved = {
        step["object_ref"]: step for step in plan["steps"]
        if step.get("target") == "splunk_observability_cloud"
    }
    for source_ref in translated["source_refs"]:
        step = approved.get(source_ref)
        if step is None or step.get("proposed_operation") not in {"PROPOSE_CREATE", "PROPOSE_TRANSFORM"}:
            raise ValueError("SLO bundle includes an object not approved by the Phase 1 plan")
    if approved[translated["primary_ref"]].get("object_type") != "slo":
        raise ValueError("SLO bundle primary object is not an approved SLO")
    if any(approved[item].get("object_type") != "monitor" for item in translated["source_refs"][1:]):
        raise ValueError("SLO burn-rate sources are not approved monitors")
    expected_binding = {
        "binding_method": "phase1_local_inventory_ir_rebuild_v1",
        "inventory_hash": source_binding.get("inventory_hash"),
        "inventory_ir_hash": source_binding.get("inventory_ir_hash"),
    }
    if source_binding != expected_binding or not all(
        SHA256.fullmatch(str(source_binding.get(field)))
        for field in ("inventory_hash", "inventory_ir_hash")
    ):
        raise ValueError("SLO source inventory binding is invalid")
    payload = validate_slo_payload(translated["payload"])
    execution_key = value_hash({
        "plan_hash": plan["plan_hash"], "wave_id": wave_id,
        "source_refs": translated["source_refs"],
    })
    result: dict[str, Any] = {
        "schema_version": "1.0",
        "manifest_id": f"slo-manifest-{uuid.uuid4().hex[:16]}",
        "source_session_id": session_id,
        "plan_hash": plan["plan_hash"],
        "plan_review_approval_hash": plan_review_approval["approval_hash"],
        "source_binding": source_binding,
        "target": "splunk_observability_cloud",
        "wave_id": wave_id,
        "max_creates": 1,
        "sealed_at": _now(),
        "entry": {
            "object_ref": translated["primary_ref"],
            "source_refs": translated["source_refs"],
            "target_kind": "slo",
            "operation": "CREATE_SLO",
            "execution_key": execution_key,
            "exact_name": payload["name"],
            "payload": payload,
            "payload_hash": value_hash(payload),
            "translation_method": translated["translation_method"],
            "differences": translated["differences"],
            "automatic_assurance": {
                "allowlisted_shape_validated": True,
                "source_intent_reviewed": False,
                "semantic_equivalence_proven": False,
                "disabled_effects_validated": True,
            },
        },
        "safety": {
            "create_only": True,
            "updates_authorized": False,
            "deletes_authorized": False,
            "alert_rules_disabled": True,
            "notifications_enabled": False,
        },
    }
    result["manifest_hash"] = canonical_hash(result, "manifest_hash")
    validate_slo_manifest(result)
    return result


def validate_slo_manifest(manifest: dict[str, Any]) -> None:
    expected = {
        "schema_version", "manifest_id", "source_session_id", "plan_hash",
        "plan_review_approval_hash", "source_binding", "target", "wave_id",
        "max_creates", "sealed_at", "entry", "safety", "manifest_hash",
    }
    if set(manifest) != expected or manifest.get("schema_version") != "1.0":
        raise ValueError("SLO manifest fields are invalid")
    if not SLO_MANIFEST_ID.fullmatch(str(manifest["manifest_id"])):
        raise ValueError("SLO manifest ID is invalid")
    if not SESSION_ID.fullmatch(str(manifest["source_session_id"])) or not SLO_WAVE_ID.fullmatch(str(manifest["wave_id"])):
        raise ValueError("SLO manifest session or wave is invalid")
    for field in ("plan_hash", "plan_review_approval_hash", "manifest_hash"):
        if not SHA256.fullmatch(str(manifest[field])):
            raise ValueError(f"SLO manifest {field} is invalid")
    if manifest["target"] != "splunk_observability_cloud" or manifest["max_creates"] != 1:
        raise ValueError("SLO manifest target or create cap is invalid")
    binding = manifest["source_binding"]
    if not isinstance(binding, dict) or set(binding) != {
        "binding_method", "inventory_hash", "inventory_ir_hash",
    } or binding.get("binding_method") != "phase1_local_inventory_ir_rebuild_v1":
        raise ValueError("SLO manifest source binding is invalid")
    if not all(SHA256.fullmatch(str(binding.get(field))) for field in ("inventory_hash", "inventory_ir_hash")):
        raise ValueError("SLO manifest source hashes are invalid")
    entry = manifest["entry"]
    if not isinstance(entry, dict) or set(entry) != {
        "object_ref", "source_refs", "target_kind", "operation", "execution_key",
        "exact_name", "payload", "payload_hash", "translation_method", "differences",
        "automatic_assurance",
    }:
        raise ValueError("SLO manifest entry fields are invalid")
    refs = entry["source_refs"]
    if (
        not OBJECT_REF.fullmatch(str(entry["object_ref"]))
        or not isinstance(refs, list) or len(refs) != 3 or len(set(refs)) != 3
        or refs[0] != entry["object_ref"]
        or any(not OBJECT_REF.fullmatch(str(item)) for item in refs)
    ):
        raise ValueError("SLO manifest source refs are invalid")
    if entry["target_kind"] != "slo" or entry["operation"] != "CREATE_SLO":
        raise ValueError("SLO manifest operation is invalid")
    if not SHA256.fullmatch(str(entry["execution_key"])) or not SHA256.fullmatch(str(entry["payload_hash"])):
        raise ValueError("SLO manifest entry hashes are invalid")
    payload = validate_slo_payload(entry["payload"])
    if entry["exact_name"] != payload["name"] or entry["payload_hash"] != value_hash(payload):
        raise ValueError("SLO manifest payload binding is invalid")
    marker = str(entry["object_ref"])[-16:]
    expected_execution_key = value_hash({
        "plan_hash": manifest["plan_hash"],
        "wave_id": manifest["wave_id"],
        "source_refs": refs,
    })
    breach = payload["targets"][0]["sloAlertRules"][0]["rules"][0]
    burn = payload["targets"][0]["sloAlertRules"][1]["rules"][0]
    if (
        entry["execution_key"] != expected_execution_key
        or breach["detectLabel"] != f"migration_breach_{marker}"
        or burn["detectLabel"] != f"migration_{marker}"
    ):
        raise ValueError("SLO deterministic identity binding is invalid")
    method = entry["translation_method"]
    if method not in {
        "automatic_metric_slo_burn_rate_v2", "automatic_metric_slo_burn_rate_v3",
    } or entry["differences"] != [
        "source_warning_status_not_represented",
        "splunk_required_breach_rule_added_disabled",
    ]:
        raise ValueError("SLO translation profile is invalid")
    if method == "automatic_metric_slo_burn_rate_v3" and not payload["description"].startswith(
        "[AI-Created] ",
    ):
        raise ValueError("SLO AI-Created provenance marker is missing")
    if entry["automatic_assurance"] != {
        "allowlisted_shape_validated": True,
        "source_intent_reviewed": False,
        "semantic_equivalence_proven": False,
        "disabled_effects_validated": True,
    }:
        raise ValueError("SLO automatic assurance is invalid")
    if manifest["safety"] != {
        "create_only": True,
        "updates_authorized": False,
        "deletes_authorized": False,
        "alert_rules_disabled": True,
        "notifications_enabled": False,
    }:
        raise ValueError("SLO manifest safety invariants are invalid")
    if manifest["manifest_hash"] != canonical_hash(manifest, "manifest_hash"):
        raise ValueError("SLO manifest hash mismatch")


__all__ = ["build_slo_manifest", "validate_slo_manifest", "validate_slo_payload"]
