"""Private translation-manifest preparation and sealing."""

from __future__ import annotations

import copy
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from .common import MANIFEST_ID, OBJECT_REF, SHA256, SESSION_ID, WAVE_ID, canonical_hash, value_hash


SEVERITIES = {"Critical", "Major", "Minor", "Warning", "Info"}
DETECTOR_KEYS = {"name", "programText", "rules", "description", "tags", "customProperties", "timezone"}
RULE_KEYS = {"detectLabel", "severity", "disabled", "notifications", "description", "runbookUrl", "tip"}
MARKER_TAG = re.compile(r"^codex-migration-[a-f0-9]{16}$")
AI_CREATED_TAG = "AI-Created"
MANUAL_SEMANTIC_REVIEW = {
    "source_intent_reviewed": True,
    "signalflow_reviewed": True,
    "differences_accepted": True,
}
AUTOMATIC_TRANSLATION_ASSURANCE = {
    "review_method": "automatic_allowlisted_v1",
    "source_intent_reviewed": False,
    "signalflow_reviewed": False,
    "differences_accepted": False,
    "allowlisted_shape_validated": True,
    "disabled_effects_validated": True,
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _execution_key(plan_hash: str, wave_id: str, object_ref: str) -> str:
    return value_hash({"plan_hash": plan_hash, "wave_id": wave_id, "object_ref": object_ref})


def _draft_payload() -> dict[str, Any]:
    return {
        "name": "REPLACE_LOCAL_ONLY",
        "programText": "REPLACE_LOCAL_ONLY",
        "rules": [{
            "detectLabel": "REPLACE_LOCAL_ONLY",
            "severity": "Warning",
            "disabled": True,
            "notifications": [],
        }],
        "tags": [],
        "customProperties": {},
    }


def prepare_manifest_draft(
    session_id: str,
    plan: dict[str, Any],
    plan_review_approval: dict[str, Any],
    wave_id: str,
    max_creates: int,
) -> dict[str, Any]:
    if not SESSION_ID.fullmatch(session_id) or not WAVE_ID.fullmatch(wave_id):
        raise ValueError("invalid session or wave ID")
    if isinstance(max_creates, bool) or not 1 <= max_creates <= 10:
        raise ValueError("execution wave cap must be between 1 and 10")
    entries: list[dict[str, Any]] = []
    for step in plan["steps"]:
        if step["target"] != "splunk_observability_cloud":
            continue
        supported = (
            step["object_type"] == "monitor"
            and step["proposed_operation"] in {"PROPOSE_CREATE", "PROPOSE_TRANSFORM"}
        )
        entries.append({
            "object_ref": step["object_ref"],
            "target_kind": "detector" if supported else "unsupported",
            "operation": "CREATE_ONLY" if supported else "NONE",
            "review_status": "pending" if supported else "not_applicable",
            "semantic_review": {
                "source_intent_reviewed": False,
                "signalflow_reviewed": False,
                "differences_accepted": False,
            },
            "payload": _draft_payload() if supported else None,
            "unsupported_reason": None if supported else "Phase 2 supports detectors only",
        })
    if not entries:
        raise ValueError("approved plan has no Splunk Observability Cloud steps")
    return {
        "schema_version": "1.0-draft",
        "manifest_id": f"manifest-{uuid.uuid4().hex[:16]}",
        "source_session_id": session_id,
        "plan_hash": plan["plan_hash"],
        "plan_review_approval_hash": plan_review_approval["approval_hash"],
        "target": "splunk_observability_cloud",
        "wave_id": wave_id,
        "max_creates": max_creates,
        "created_at": _now(),
        "entries": entries,
        "instructions": {
            "restricted_local_data": True,
            "set_review_status_to_approved_after_customer_review": True,
            "notifications_must_remain_empty": True,
            "rules_must_remain_disabled": True,
        },
    }


def _bounded_text(value: Any, field: str, minimum: int, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or not minimum <= len(value) <= maximum
    ):
        raise ValueError(f"detector {field} must be {minimum}-{maximum} characters")
    if value.startswith("REPLACE_LOCAL_ONLY") or any(ord(char) < 32 and char not in "\n\t" for char in value):
        raise ValueError(f"detector {field} is incomplete or contains control characters")
    return value


def validate_detector_payload(payload: Any, *, sealed: bool = False) -> dict[str, Any]:
    if not isinstance(payload, dict) or not {"name", "programText", "rules"}.issubset(payload):
        raise ValueError("detector payload requires name, programText, and rules")
    if not set(payload).issubset(DETECTOR_KEYS):
        raise ValueError("detector payload contains unsupported fields")
    result = copy.deepcopy(payload)
    result["name"] = _bounded_text(result["name"], "name", 1, 255)
    result["programText"] = _bounded_text(result["programText"], "programText", 1, 100_000)
    if "description" in result:
        result["description"] = _bounded_text(result["description"], "description", 1, 1024)
    if "timezone" in result:
        result["timezone"] = _bounded_text(result["timezone"], "timezone", 1, 64)
    rules = result["rules"]
    if not isinstance(rules, list) or not 1 <= len(rules) <= 25:
        raise ValueError("detector rules must contain 1-25 entries")
    labels: set[str] = set()
    for rule in rules:
        if not isinstance(rule, dict) or not {"detectLabel", "severity", "disabled", "notifications"}.issubset(rule):
            raise ValueError("each detector rule requires label, severity, disabled, and notifications")
        if not set(rule).issubset(RULE_KEYS):
            raise ValueError("detector rule contains unsupported fields")
        label = _bounded_text(rule["detectLabel"], "rule detectLabel", 1, 128)
        if label in labels:
            raise ValueError("detector rule labels must be unique")
        labels.add(label)
        publish_pattern = re.compile(
            r"publish\s*\(\s*(?:label\s*=\s*)?['\"]" + re.escape(label) + r"['\"]"
        )
        if not publish_pattern.search(result["programText"]):
            raise ValueError("detector rule label is not published by programText")
        if rule["severity"] not in SEVERITIES:
            raise ValueError("detector rule severity is invalid")
        if rule["disabled"] is not True or rule["notifications"] != []:
            raise ValueError("detector rules must be disabled and have no notifications")
        for field in ("description", "runbookUrl", "tip"):
            if field in rule:
                rule[field] = _bounded_text(rule[field], f"rule {field}", 1, 1024)
    tags = result.get("tags", [])
    tag_limit = 50 if sealed else 48
    if not isinstance(tags, list) or len(tags) > tag_limit or len(set(tags)) != len(tags):
        raise ValueError(f"detector tags must be a unique list with at most {tag_limit} entries")
    for tag in tags:
        _bounded_text(tag, "tag", 1, 256)
        if MARKER_TAG.fullmatch(tag) and not sealed:
            raise ValueError("reserved migration marker tag is not allowed in the draft")
    properties = result.get("customProperties", {})
    property_limit = 20 if sealed else 18
    if not isinstance(properties, dict) or len(properties) > property_limit:
        raise ValueError(f"detector customProperties must contain at most {property_limit} entries")
    for key, value in properties.items():
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,127}", str(key)):
            raise ValueError("detector custom property name is invalid")
        if key in {"migrationExecutionKey", "migrationPlanHash"} and not sealed:
            raise ValueError("reserved migration custom property is not allowed in the draft")
        if not isinstance(value, (str, int, float, bool)) or isinstance(value, str) and len(value) > 256:
            raise ValueError("detector custom property value is invalid")
    result["tags"] = tags
    result["customProperties"] = properties
    return result


def seal_manifest(
    draft: dict[str, Any],
    plan: dict[str, Any],
    plan_review_approval: dict[str, Any],
    source_binding: dict[str, str],
    *,
    automatic_payload_hashes: dict[str, str] | None = None,
) -> dict[str, Any]:
    required = {
        "schema_version", "manifest_id", "source_session_id", "plan_hash",
        "plan_review_approval_hash", "target", "wave_id", "max_creates",
        "created_at", "entries", "instructions",
    }
    if set(draft) != required or draft.get("schema_version") != "1.0-draft":
        raise ValueError("translation manifest draft fields are invalid")
    if draft["plan_hash"] != plan["plan_hash"] or draft["plan_review_approval_hash"] != plan_review_approval["approval_hash"]:
        raise ValueError("translation manifest draft provenance mismatch")
    approved_plan_steps = {
        step["object_ref"]: step for step in plan["steps"]
        if step["target"] == "splunk_observability_cloud"
    }
    sealed_entries: list[dict[str, Any]] = []
    seen: set[str] = set()
    for entry in draft["entries"]:
        if not isinstance(entry, dict) or entry.get("object_ref") not in approved_plan_steps:
            raise ValueError("translation manifest contains an unapproved object reference")
        object_ref = entry["object_ref"]
        if object_ref in seen:
            raise ValueError("translation manifest contains duplicate object references")
        seen.add(object_ref)
        if entry.get("target_kind") != "detector" or entry.get("review_status") != "approved":
            continue
        step = approved_plan_steps[object_ref]
        if step.get("object_type") != "monitor" or step.get("proposed_operation") not in {
            "PROPOSE_CREATE", "PROPOSE_TRANSFORM",
        }:
            raise ValueError("only approved monitor create/transform steps can become detectors")
        review = entry.get("semantic_review")
        if review not in (MANUAL_SEMANTIC_REVIEW, AUTOMATIC_TRANSLATION_ASSURANCE):
            raise ValueError("approved detector requires manual review or automatic translation assurance")
        if review == AUTOMATIC_TRANSLATION_ASSURANCE and (
            not isinstance(automatic_payload_hashes, dict)
            or automatic_payload_hashes.get(object_ref) != value_hash(entry.get("payload"))
        ):
            raise ValueError("automatic translation assurance requires a translator-produced payload")
        payload = validate_detector_payload(entry.get("payload"))
        execution_key = _execution_key(plan["plan_hash"], draft["wave_id"], object_ref)
        marker = f"codex-migration-{execution_key[:16]}"
        payload["tags"] = sorted({*payload["tags"], marker, AI_CREATED_TAG})
        payload["customProperties"] = {
            **payload["customProperties"],
            "migrationExecutionKey": execution_key,
            "migrationPlanHash": plan["plan_hash"],
        }
        sealed_entries.append({
            "object_ref": object_ref,
            "target_kind": "detector",
            "operation": "CREATE_DETECTOR",
            "execution_key": execution_key,
            "marker_tag": marker,
            "payload": payload,
            "payload_hash": value_hash(payload),
            "semantic_review": review,
        })
    if not sealed_entries:
        raise ValueError("no customer-approved detector entries are ready to seal")
    if len(sealed_entries) > draft["max_creates"] or not 1 <= draft["max_creates"] <= 10:
        raise ValueError("sealed entries exceed the execution wave cap")
    expected_source_binding = {
        "binding_method": "phase1_local_inventory_ir_rebuild_v1",
        "inventory_hash": source_binding.get("inventory_hash") if isinstance(source_binding, dict) else None,
        "inventory_ir_hash": source_binding.get("inventory_ir_hash") if isinstance(source_binding, dict) else None,
    }
    if source_binding != expected_source_binding or not all(
        SHA256.fullmatch(str(expected_source_binding[field]))
        for field in ("inventory_hash", "inventory_ir_hash")
    ):
        raise ValueError("source inventory binding is invalid")
    result: dict[str, Any] = {
        "schema_version": "1.1",
        "manifest_id": draft["manifest_id"],
        "source_session_id": draft["source_session_id"],
        "plan_hash": draft["plan_hash"],
        "plan_review_approval_hash": draft["plan_review_approval_hash"],
        "source_binding": source_binding,
        "target": "splunk_observability_cloud",
        "wave_id": draft["wave_id"],
        "max_creates": draft["max_creates"],
        "sealed_at": _now(),
        "entries": sealed_entries,
        "safety": {
            "create_only": True,
            "updates_authorized": False,
            "deletes_authorized": False,
            "notifications_enabled": False,
        },
    }
    result["manifest_hash"] = canonical_hash(result, "manifest_hash")
    validate_sealed_manifest(result)
    return result


def validate_sealed_manifest(manifest: dict[str, Any]) -> None:
    expected = {
        "schema_version", "manifest_id", "source_session_id", "plan_hash",
        "plan_review_approval_hash", "source_binding", "target", "wave_id", "max_creates",
        "sealed_at", "entries", "safety", "manifest_hash",
    }
    if set(manifest) != expected or manifest.get("schema_version") not in {"1.0", "1.1"}:
        raise ValueError("sealed manifest fields are invalid")
    if (
        not MANIFEST_ID.fullmatch(str(manifest["manifest_id"]))
        or not SESSION_ID.fullmatch(str(manifest["source_session_id"]))
        or not WAVE_ID.fullmatch(str(manifest["wave_id"]))
    ):
        raise ValueError("sealed manifest identity, session, or wave is invalid")
    if not SHA256.fullmatch(str(manifest["plan_hash"])) or not SHA256.fullmatch(str(manifest["plan_review_approval_hash"])):
        raise ValueError("sealed manifest provenance hash is invalid")
    source_binding = manifest["source_binding"]
    if not isinstance(source_binding, dict) or source_binding.get("binding_method") != "phase1_local_inventory_ir_rebuild_v1" or set(source_binding) != {
        "binding_method", "inventory_hash", "inventory_ir_hash",
    } or any(not SHA256.fullmatch(str(source_binding.get(field))) for field in (
        "inventory_hash", "inventory_ir_hash",
    )):
        raise ValueError("sealed manifest source inventory binding is invalid")
    if (
        manifest["target"] != "splunk_observability_cloud"
        or isinstance(manifest["max_creates"], bool)
        or not 1 <= manifest["max_creates"] <= 10
    ):
        raise ValueError("sealed manifest target or cap is invalid")
    if manifest["safety"] != {
        "create_only": True, "updates_authorized": False,
        "deletes_authorized": False, "notifications_enabled": False,
    }:
        raise ValueError("sealed manifest safety invariants are invalid")
    entries = manifest["entries"]
    if not isinstance(entries, list) or not 1 <= len(entries) <= manifest["max_creates"]:
        raise ValueError("sealed manifest entries are invalid")
    seen: set[str] = set()
    for entry in entries:
        required = {
            "object_ref", "target_kind", "operation", "execution_key", "marker_tag",
            "payload", "payload_hash", "semantic_review",
        }
        if not isinstance(entry, dict) or set(entry) != required:
            raise ValueError("sealed manifest entry fields are invalid")
        if not OBJECT_REF.fullmatch(str(entry["object_ref"])) or entry["object_ref"] in seen:
            raise ValueError("sealed manifest object reference is invalid or duplicated")
        seen.add(entry["object_ref"])
        if entry["target_kind"] != "detector" or entry["operation"] != "CREATE_DETECTOR":
            raise ValueError("sealed manifest contains an unsupported operation")
        if entry["semantic_review"] not in (MANUAL_SEMANTIC_REVIEW, AUTOMATIC_TRANSLATION_ASSURANCE):
            raise ValueError("sealed manifest translation assurance is incomplete")
        expected_key = _execution_key(manifest["plan_hash"], manifest["wave_id"], entry["object_ref"])
        if entry["execution_key"] != expected_key or entry["marker_tag"] != f"codex-migration-{expected_key[:16]}":
            raise ValueError("sealed manifest execution marker mismatch")
        payload = validate_detector_payload(entry["payload"], sealed=True)
        if entry["marker_tag"] not in payload["tags"]:
            raise ValueError("sealed manifest payload marker is missing")
        if manifest["schema_version"] == "1.1" and AI_CREATED_TAG not in payload["tags"]:
            raise ValueError("sealed manifest AI-Created provenance tag is missing")
        properties = payload["customProperties"]
        if properties.get("migrationExecutionKey") != expected_key or properties.get("migrationPlanHash") != manifest["plan_hash"]:
            raise ValueError("sealed manifest custom marker mismatch")
        if entry["payload_hash"] != value_hash(payload):
            raise ValueError("sealed manifest payload hash mismatch")
    if manifest["manifest_hash"] != canonical_hash(manifest, "manifest_hash"):
        raise ValueError("sealed manifest hash mismatch")


__all__ = [
    "AI_CREATED_TAG", "prepare_manifest_draft", "seal_manifest", "validate_detector_payload",
    "validate_sealed_manifest",
]
