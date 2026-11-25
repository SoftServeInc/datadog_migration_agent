"""Build and seal browser-validation evidence without exposing target IDs."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .common import canonical_hash, value_hash


CHECKS = {
    "title_match", "chart_count_match", "no_render_errors",
    "compact_layout", "source_geometry_preserved",
}


def build_browser_draft(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "1.0-draft",
        "session_id": result["session_id"],
        "result_hash": result["result_hash"],
        "dashboards": [{
            "object_ref": item["object_ref"],
            "target_id_hash": value_hash(item["target_id"]),
            "checks": {name: False for name in sorted(CHECKS)},
        } for item in result["results"]],
    }


def seal_browser_evidence(result: dict[str, Any], draft: dict[str, Any]) -> dict[str, Any]:
    expected = build_browser_draft(result)
    if (
        not isinstance(draft, dict)
        or set(draft) != {"schema_version", "session_id", "result_hash", "dashboards"}
        or draft.get("schema_version") != "1.0-draft"
        or draft.get("session_id") != expected["session_id"]
        or draft.get("result_hash") != expected["result_hash"]
        or not isinstance(draft.get("dashboards"), list)
    ):
        raise ValueError("browser validation draft binding is invalid")
    expected_ids = {
        item["object_ref"]: item["target_id_hash"] for item in expected["dashboards"]
    }
    observed_ids: dict[str, str] = {}
    dashboards: list[dict[str, Any]] = []
    for item in draft["dashboards"]:
        if not isinstance(item, dict) or set(item) != {"object_ref", "target_id_hash", "checks"}:
            raise ValueError("browser validation draft item is invalid")
        checks = item["checks"]
        if not isinstance(checks, dict) or set(checks) != CHECKS or any(value is not True for value in checks.values()):
            raise ValueError("browser validation checks are incomplete or failed")
        object_ref = str(item["object_ref"])
        target_id_hash = str(item["target_id_hash"])
        if object_ref in observed_ids:
            raise ValueError("browser validation contains duplicate dashboards")
        observed_ids[object_ref] = target_id_hash
        dashboards.append({
            "object_ref": object_ref, "target_id_hash": target_id_hash,
            "checks": checks, "passed": True,
        })
    if observed_ids != expected_ids:
        raise ValueError("browser validation scope differs from the dashboard result")
    evidence: dict[str, Any] = {
        "schema_version": "1.0", "session_id": result["session_id"],
        "result_hash": result["result_hash"],
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "dashboards": dashboards, "evidence_hash": "",
    }
    evidence["evidence_hash"] = canonical_hash(evidence, "evidence_hash")
    return evidence


__all__ = ["build_browser_draft", "seal_browser_evidence"]
