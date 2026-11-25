"""Compile existing detector, SLO, and dashboard artifacts into one bundle."""

from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve()
SKILLS = HERE.parents[3]
DETECTOR = SKILLS / "observability-migration-executor" / "scripts"
SLO = SKILLS / "observability-migration-slo-executor" / "scripts"
DASHBOARD = SKILLS / "observability-migration-dashboard-executor" / "scripts"
sys.path[:0] = [str(DETECTOR), str(SLO), str(DASHBOARD)]

from dashboard_migration import canonical_hash as dashboard_hash  # noqa: E402
from execution_core.common import read_private_json  # noqa: E402
from execution_core.manifest import validate_sealed_manifest  # noqa: E402
from slo_manifest import validate_slo_manifest  # noqa: E402

from .bundle import seal_bundle
from .scheduler import AdapterPreflightDefer


def _operation(
    operation_id: str, object_ref: str, object_type: str, adapter: str,
    action: str, payload_hash: str, adapter_input: dict[str, Any],
) -> dict[str, Any]:
    return {
        "operation_id": operation_id, "object_ref": object_ref,
        "object_type": object_type, "adapter": adapter, "action": action,
        "status": "SUPPORTED", "dependencies": [], "payload_hash": payload_hash,
        "adapter_input": adapter_input,
        "validation": [{"kind": "api_read_back", "required": True}],
        "rollback": {"mode": "owned_create_or_restore_update"},
    }


def compile_legacy_bundle(
    work_root: Path, session_id: str, target_binding: dict[str, str],
) -> dict[str, Any]:
    session = work_root.resolve() / session_id
    checkpoint = read_private_json(session / "checkpoint.local.json")
    plan_hash = str(checkpoint.get("plan_hash", ""))
    plan = read_private_json(session / "dry-run-plan.json")
    if plan.get("plan_hash") != plan_hash:
        raise ValueError("approved plan no longer matches the session checkpoint")
    operations: list[dict[str, Any]] = []
    consumed_refs: set[str] = set()
    for path in sorted((session / "execution").glob("wave-*/translation-manifest.local.json")):
        manifest = read_private_json(path)
        validate_sealed_manifest(manifest)
        if manifest["source_session_id"] != session_id or manifest["plan_hash"] != plan_hash:
            raise ValueError("detector manifest is not bound to this session plan")
        wave_id = manifest["wave_id"]
        consumed_refs.update(str(entry["object_ref"]) for entry in manifest["entries"])
        operations.append(_operation(
            f"detector:{wave_id}", f"detector-batch:{wave_id}", "detector-batch",
            "detector-wave-v1", "CREATE", manifest["manifest_hash"], {"wave_id": wave_id},
        ))
    for path in sorted((session / "slo-execution").glob("slo-wave-*/slo-manifest.local.json")):
        manifest = read_private_json(path)
        validate_slo_manifest(manifest)
        if manifest["source_session_id"] != session_id or manifest["plan_hash"] != plan_hash:
            raise ValueError("SLO manifest is not bound to this session plan")
        wave_id = manifest["wave_id"]
        consumed_refs.update(str(item) for item in manifest["entry"]["source_refs"])
        operations.append(_operation(
            f"slo:{wave_id}", f"slo-batch:{wave_id}", "slo-batch",
            "slo-wave-v1", "CREATE", manifest["manifest_hash"], {"wave_id": wave_id},
        ))
    preview_path = session / "dashboard-execution" / "dashboard-preview.local.json"
    if preview_path.exists():
        preview = read_private_json(preview_path, max_bytes=25_000_000)
        unsigned = {key: value for key, value in preview.items() if key != "preview_hash"}
        if (
            preview.get("preview_hash") != dashboard_hash(unsigned)
            or preview.get("session_id") != session_id
            or preview.get("plan_hash") != plan_hash
        ):
            raise ValueError("dashboard preview is not bound to this session plan")
        operation = _operation(
            "dashboard:session", "dashboard-batch:session", "dashboard-batch",
            "dashboard-session-v1", "UPSERT", preview["preview_hash"], {},
        )
        operation["validation"].append({"kind": "browser_render", "required": True})
        operations.append(operation)
        consumed_refs.update(str(item["object_ref"]) for item in preview["dashboards"])
    for step in plan.get("steps", []):
        object_ref = str(step.get("object_ref", ""))
        if object_ref in consumed_refs:
            continue
        operations.append({
            "operation_id": f"defer:{object_ref}",
            "object_ref": object_ref,
            "object_type": str(step.get("object_type", "unknown")),
            "adapter": "deferred-v1",
            "action": "DEFER",
            "status": "PARTIAL",
            "dependencies": [],
            "payload_hash": None,
            "adapter_input": {"reason": "no_semantically_safe_registered_adapter"},
            "validation": [],
            "rollback": {"mode": "none"},
        })
    if not operations:
        raise ValueError("no compiled adapter artifacts are available for the unified bundle")
    try:
        session_created_at = datetime.fromisoformat(str(checkpoint["created_at"]))
    except (KeyError, ValueError) as exc:
        raise ValueError("session creation timestamp is missing or invalid") from exc
    return seal_bundle(
        session_id, plan_hash, target_binding, operations, created_at=session_created_at,
    )


def preflight_bundle(bundle: dict[str, Any], registry: Any) -> dict[str, Any]:
    context = {
        "session_id": bundle["session_id"], "plan_hash": bundle["plan_hash"],
        "bundle_hash": bundle["bundle_hash"], "target_binding": bundle["target_binding"],
        "operation_results": {},
    }
    operations = [dict(operation) for operation in bundle["operations"]]
    changed = False
    for index, operation in enumerate(operations):
        if operation["action"] == "DEFER" or operation["status"] != "SUPPORTED":
            continue
        adapter = registry.get(operation["adapter"])
        preflight = getattr(adapter, "preflight", None)
        if callable(preflight):
            try:
                preflight(operation, context)
            except AdapterPreflightDefer as exc:
                operations[index] = {
                    **operation,
                    "adapter": "deferred-v1",
                    "action": "DEFER",
                    "status": "BLOCKED",
                    "payload_hash": None,
                    "adapter_input": {"reason": exc.category},
                    "validation": [],
                    "rollback": {"mode": "none"},
                }
                changed = True
    if not changed:
        return bundle
    return seal_bundle(
        bundle["session_id"], bundle["plan_hash"], bundle["target_binding"], operations,
        created_at=datetime.fromisoformat(str(bundle["created_at"])),
    )


__all__ = ["compile_legacy_bundle", "preflight_bundle"]
