#!/usr/bin/env python3
"""Build one local, write-free preview across all migration executors."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
SKILLS = HERE.parents[1]
ASSESSMENT = SKILLS / "observability-migration-assessment" / "scripts"
DETECTOR = SKILLS / "observability-migration-executor" / "scripts"
SLO = SKILLS / "observability-migration-slo-executor" / "scripts"
sys.path[:0] = [str(ASSESSMENT), str(DETECTOR), str(SLO)]

from assessment_core.security import atomic_write_json, pseudonym  # noqa: E402
from execution_core.manifest import validate_detector_payload  # noqa: E402
from execution_core.translation import translate_allowlisted_monitor  # noqa: E402
from slo_manifest import validate_slo_payload  # noqa: E402
from slo_translation import translate_slo_bundle  # noqa: E402


def read(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"invalid JSON object: {path.name}")
    return value


def build(session: Path) -> dict:
    checkpoint = read(session / "checkpoint.local.json")
    plan = read(session / "dry-run-plan.json")
    recorded = checkpoint.get("artifacts", {}).get("local_inventory")
    inventory_path = Path(str(recorded)) if recorded else session / "discovery/datadog-estate.local.json"
    if not inventory_path.is_absolute():
        inventory_path = session / inventory_path
    if inventory_path.is_symlink():
        raise ValueError("private inventory path is unsafe")
    inventory_path = inventory_path.resolve(strict=True)
    if session.resolve() not in inventory_path.parents:
        raise ValueError("private inventory escapes the approved session")
    inventory = read(inventory_path)
    dashboard_path = session / "dashboard-execution/dashboard-preview.local.json"
    dashboards = read(dashboard_path) if dashboard_path.exists() else {
        "plan_hash": plan["plan_hash"], "preview_hash": None, "dashboards": [],
    }
    if plan["plan_hash"] != checkpoint["plan_hash"] or dashboards["plan_hash"] != plan["plan_hash"]:
        raise ValueError("cross-executor plan binding mismatch")
    salt = checkpoint["local_pseudonym_salt"]
    detector_refs: list[str] = []
    detector_names: list[str] = []
    unsupported_monitors: list[dict] = []
    for monitor in inventory["inventory"]["monitors"]:
        object_ref = pseudonym(f"monitor:{monitor['source_id']}", salt)
        payload = translate_allowlisted_monitor(monitor, object_ref)
        if payload is None:
            unsupported_monitors.append(monitor)
            continue
        validate_detector_payload(payload)
        detector_refs.append(object_ref)
        detector_names.append(payload["name"])
    slo = translate_slo_bundle(inventory, salt)
    if slo is not None:
        validate_slo_payload(slo["payload"])
    slo_alert_refs = set(slo["source_refs"][1:]) if slo is not None else set()
    deferred_monitors = [
        monitor for monitor in unsupported_monitors
        if pseudonym(f"monitor:{monitor['source_id']}", salt) not in slo_alert_refs
    ]
    result = {
        "schema_version": "1.0",
        "session_id": checkpoint["session_id"],
        "plan_hash": plan["plan_hash"],
        "dashboard_preview_hash": dashboards["preview_hash"],
        "source_scope": {
            "planned_objects": len(plan["steps"]),
            "object_types": dict(sorted(Counter(step["object_type"] for step in plan["steps"]).items())),
        },
        "target_create_scope": {
            "detectors": len(detector_refs),
            "slos": 1 if slo is not None else 0,
            "dashboards": len(dashboards["dashboards"]),
            "charts": sum(len(item["charts"]) for item in dashboards["dashboards"]),
            "dashboard_groups": 1,
        },
        "source_objects_consumed_by_slo": len(slo_alert_refs),
        "deferred": {
            "monitors": dict(sorted(Counter(str(item.get("monitor_type", "unknown")).lower() for item in deferred_monitors).items())),
            "slos": 0 if slo is not None else len(inventory["inventory"].get("slos", [])),
            "log_indexes": len(inventory["inventory"].get("log_indexes", [])),
            "log_pipelines": len(inventory["inventory"].get("log_pipelines", [])),
        },
        "naming": {
            "detectors": "human-readable target names; source-only placeholders removed",
            "slo": "validated Datadog source SLO name",
            "dashboards": "exact Datadog source name",
            "technical_hash_prefixes_in_visible_names": False,
        },
        "target_names": {
            "detectors": sorted(detector_names),
            "slo": [slo["payload"]["name"]] if slo is not None else [],
            "dashboards": sorted(item["target_name"] for item in dashboards["dashboards"]),
        },
        "provenance": {
            "detector_and_chart_tag": "AI-Created",
            "slo_description_prefix": "[AI-Created]",
            "dashboard_name_suffix": "none; provenance is in description/tags/group",
        },
        "adaptations": sorted({value for item in dashboards["dashboards"] for value in item["differences"]}),
        "validation": {
            "local_payload_validation": "passed",
            "live_payload_validation": "automatic non-mutating compile check",
            "post_create_read_back": "required for every target object",
            "browser_dashboard_validation": "required for every dashboard after apply",
        },
        "approval": {
            "customer_approval_number": 2,
            "required_once_for_this_bundle": True,
            "covers": "this immutable bundle, target organization, and listed operations",
        },
        "external_mutations_performed": 0,
    }
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--work-root", default=".migration-work")
    args = parser.parse_args()
    session = (Path(args.work_root) / args.session_id).resolve()
    result = build(session)
    output = session / "consolidated-preview.local.json"
    atomic_write_json(output, result)
    public = {key: value for key, value in result.items() if key != "target_names"}
    print(json.dumps({**public, "preview_file": str(output)}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
