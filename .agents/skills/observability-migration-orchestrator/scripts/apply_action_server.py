#!/usr/bin/env python3
"""Local MCP action server for the governed observability migration workflow.

The assessment checkpoint is authoritative.  This module only translates native
customer actions into revision-checked checkpoint transitions and the unified
runtime commands; transport state can expire without changing the workflow.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import subprocess
import sys
import uuid
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
SKILLS = HERE.parents[1]
ASSESSMENT = SKILLS / "observability-migration-assessment" / "scripts"
sys.path[:0] = [str(ASSESSMENT), str(HERE)]

from assessment_core.model import SessionState, ValidationState  # noqa: E402
from assessment_core.plan_approval import (  # noqa: E402
    create_plan_review_approval,
    validate_plan_review_approval,
    write_plan_review_approval,
)
from assessment_core.state import CheckpointStore, Session  # noqa: E402
from assessment_core.security import atomic_write_json, pseudonym, redact  # noqa: E402
from terraform_export import export_terraform  # noqa: E402


STATE_FILE = "migration-action-state.local.json"
CHECKLIST_URI = "observability-migration://verification-checklist"
REPORT_URI = "observability-migration://report/current"
CONTROL_CENTER_URI = "ui://observability-migration/control-center-v1.html"
CONTROL_CENTER_MIME = "text/html;profile=mcp-app"
TOKEN_LIFETIME = timedelta(hours=1)
SHA256 = frozenset("0123456789abcdef")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _canonical_hash(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _read_json(path: Path, *, required: bool = True) -> dict[str, Any]:
    if path.is_symlink():
        raise ValueError("refusing symlink workflow artifact")
    if not path.is_file():
        if required:
            raise ValueError(f"workflow artifact not found: {path.name}")
        return {}
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"workflow artifact is not an object: {path.name}")
    return value


def _write_private(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    atomic_write_json(path, value)


def _workspace_relative_path(value: Any, workspace: Path, default: Path) -> Path:
    """Resolve tool-supplied relative paths from the customer workspace.

    MCP servers run from the installed plugin cache, so ``Path.resolve()`` on a
    value such as ``.env`` would otherwise look inside that cache.
    """

    path = Path(str(value)) if value not in (None, "") else default
    if not path.is_absolute():
        path = workspace / path
    return path.resolve()


def _paths(arguments: dict[str, Any]) -> dict[str, Path | str]:
    workspace = Path(str(arguments.get("workspace_root") or Path.cwd())).resolve()
    work_root = _workspace_relative_path(
        arguments.get("work_root"), workspace, workspace / ".migration-work",
    )
    env_file = _workspace_relative_path(
        arguments.get("env_file"), workspace, workspace / ".env",
    )
    emulator_root_value = arguments.get("emulator_root")
    emulator_root = (
        _workspace_relative_path(emulator_root_value, workspace, workspace)
        if emulator_root_value else None
    )
    session_id = str(arguments.get("session_id") or "")
    if not session_id:
        raise ValueError("session_id is required")
    # CheckpointStore performs the strict session identifier and symlink checks.
    session_root = CheckpointStore(work_root).session_directory(session_id)
    runtime = session_root / "unified-execution"
    return {
        "workspace_root": workspace,
        "work_root": work_root,
        "env_file": env_file,
        "session_id": session_id,
        "session_root": session_root,
        "runtime": runtime,
        "state": runtime / STATE_FILE,
        "emulator_root": emulator_root,
    }


def _workspace_paths(arguments: dict[str, Any]) -> tuple[Path, Path, Path]:
    workspace = Path(str(arguments.get("workspace_root") or Path.cwd())).resolve()
    work_root = _workspace_relative_path(
        arguments.get("work_root"), workspace, workspace / ".migration-work",
    )
    env_file = _workspace_relative_path(
        arguments.get("env_file"), workspace, workspace / ".env",
    )
    return workspace, work_root, env_file


def _latest_session(work_root: Path) -> Session | None:
    if not work_root.is_dir() or work_root.is_symlink():
        return None
    store = CheckpointStore(work_root)
    candidates: list[Session] = []
    for directory in work_root.iterdir():
        if not directory.is_dir() or directory.is_symlink():
            continue
        try:
            candidates.append(store.load(directory.name))
        except (ValueError, OSError, json.JSONDecodeError):
            continue
    if not candidates:
        return None
    return max(candidates, key=lambda item: (item.updated_at, item.created_at, item.session_id))


def _safe_display_name(value: Any, object_type: str) -> str:
    text = str(redact(str(value or ""))).strip()
    text = " ".join("".join(character if ord(character) >= 32 else " " for character in text).split())
    fallback = {
        "dashboard": "Untitled dashboard", "monitor": "Untitled monitor",
        "slo": "Untitled SLO", "synthetic": "Untitled synthetic test",
        "log_index": "Untitled log index", "log_pipeline": "Untitled log pipeline",
    }.get(object_type, "Untitled component")
    return (text or fallback)[:180]


def _curated_resource_rows(session: Session, session_root: Path) -> list[dict[str, Any]]:
    """Return widget-only named rows without source IDs, queries, or raw payloads."""

    inventory_path = session_root / session.artifacts.get(
        "local_inventory", "raw-inventory/datadog-estate.local.json"
    )
    inventory = _read_json(inventory_path, required=False)
    assessment = _read_json(
        session_root / session.artifacts.get("discovery_report_json", "discovery-report.json"),
        required=False,
    )
    actions = assessment.get("actions") if isinstance(assessment.get("actions"), list) else []
    action_by_ref = {
        str(action.get("object_ref")): action
        for action in actions if isinstance(action, dict) and action.get("object_ref")
    }
    collections = inventory.get("inventory") if isinstance(inventory.get("inventory"), dict) else {}
    rows: list[dict[str, Any]] = []
    for records in collections.values():
        if not isinstance(records, list):
            continue
        for index, record in enumerate(records):
            if not isinstance(record, dict) or record.get("source_type") == "host_total":
                continue
            object_type = str(record.get("source_type") or "unknown").lower()
            source_id = record.get("source_id")
            identity = str(source_id) if source_id is not None and str(source_id).strip() else f"index:{index}"
            object_ref = pseudonym(f"{object_type}:{identity}", session.local_pseudonym_salt)
            action = action_by_ref.get(object_ref, {})
            if not action:
                continue
            rows.append({
                "name": _safe_display_name(record.get("name"), object_type),
                "type": object_type,
                "compatibility": str(action.get("compatibility") or "UNKNOWN")[:48],
                "risk": str(action.get("risk_level") or "unknown")[:24],
                "effort": int(action.get("effort_points") or 0),
                "targetRepresentation": str(
                    action.get("proposed_target_representation") or "Review required"
                )[:140],
                "approach": str(action.get("recommended_migration_approach") or "Review required")[:180],
                "validation": str(action.get("validation_strategy") or "API read-back")[:140],
                "rollback": str(action.get("rollback_strategy") or "Session-owned rollback")[:140],
                "dependencyCount": int(action.get("dependency_count") or 0),
            })
    rows.sort(key=lambda item: (item["type"], item["name"].casefold()))
    return rows


def _resource_summary(session_root: Path) -> dict[str, Any]:
    assessment = _read_json(session_root / "discovery-report.json", required=False)
    actions = assessment.get("actions") if isinstance(assessment.get("actions"), list) else []
    by_type = Counter()
    by_compatibility = Counter()
    for action in actions:
        if not isinstance(action, dict):
            continue
        by_type[str(action.get("object_type") or "unknown")] += 1
        by_compatibility[str(action.get("compatibility") or "UNKNOWN")] += 1
    compatible = sum(
        count for name, count in by_compatibility.items()
        if name in {"DIRECT", "TRANSFORMABLE"}
    )
    return {
        "total": sum(by_type.values()),
        "compatible": compatible,
        "byType": dict(sorted(by_type.items())),
        "byCompatibility": dict(sorted(by_compatibility.items())),
    }


def _ensure_reviewable_assessment(assessment: dict[str, Any]) -> None:
    summary = assessment.get("summary")
    count = summary.get("source_object_count") if isinstance(summary, dict) else None
    if count is None:
        actions = assessment.get("actions")
        count = len(actions) if isinstance(actions, list) else 0
    if not isinstance(count, int) or count <= 0:
        raise ValueError("discovery found no source objects; migration review is unavailable")


def _challenge(state: dict[str, Any], kind: str, revision: int, bundle_hash: str = "") -> str:
    secret = str(state.get("transport_secret") or "")
    if not secret:
        raise ValueError("migration action transport state is incomplete")
    return _canonical_hash({
        "kind": kind,
        "session_id": state["session_id"],
        "action_id": state["action_id"],
        "revision": revision,
        "bundle_hash": bundle_hash,
        "secret": secret,
    })


def _verify_challenge(
    supplied: Any, state: dict[str, Any], kind: str, session: Session,
) -> None:
    expected = _challenge(state, kind, session.revision, str(state.get("bundle_hash") or ""))
    if not isinstance(supplied, str) or not secrets.compare_digest(supplied, expected):
        raise ValueError("stale or invalid migration action token")
    if state.get("assessment_revision") != session.revision:
        raise ValueError("stale or invalid migration action revision")


def _load_action_state(paths: dict[str, Path | str], action_id: Any = None) -> dict[str, Any]:
    state = _read_json(paths["state"])  # type: ignore[arg-type]
    if state.get("session_id") != paths["session_id"]:
        raise ValueError("migration action state belongs to another session")
    if action_id is not None and state.get("action_id") != action_id:
        raise ValueError("stale or invalid migration action instance")
    if paths.get("emulator_root") is None and state.get("emulator_root"):
        paths["emulator_root"] = Path(str(state["emulator_root"])).resolve()
    # Upgrade pre-v2 transport records in place.  This is transport metadata
    # only and never changes the authoritative assessment checkpoint.
    if not state.get("transport_secret"):
        state["transport_secret"] = secrets.token_hex(32)
        _write_private(paths["state"], state)  # type: ignore[arg-type]
    return state


def _new_action_state(session: Session, paths: dict[str, Path | str]) -> dict[str, Any]:
    state = {
        "schema_version": "2.0",
        "session_id": session.session_id,
        "action_id": f"action-{uuid.uuid4().hex[:24]}",
        "assessment_revision": session.revision,
        "transport_secret": secrets.token_hex(32),
        "created_at": _now().isoformat(),
        "expires_at": (_now() + TOKEN_LIFETIME).isoformat(),
        "external_mutations": session.mutations_performed,
    }
    if paths.get("emulator_root") is not None:
        state["emulator_root"] = str(paths["emulator_root"])
    _write_private(paths["state"], state)  # type: ignore[arg-type]
    return state


def _operation_counts(checkpoint: dict[str, Any]) -> dict[str, int]:
    operations = checkpoint.get("operations")
    if not isinstance(operations, dict):
        return {}
    return dict(sorted(Counter(
        str(value.get("status"))
        for value in operations.values() if isinstance(value, dict) and value.get("status")
    ).items()))


def _api_validation_passed(status: str, operation_states: dict[str, int]) -> bool:
    if status not in {"COMPLETED", "PARTIAL"} or not operation_states:
        return False
    return not any(
        count for name, count in operation_states.items()
        if name not in {"COMPLETED", "SKIPPED"}
    ) and operation_states.get("COMPLETED", 0) > 0


def _browser_validation_outcome(
    evidence_path: Path, session_id: str, dashboard_count: int, started_at: datetime,
) -> tuple[str, str | None]:
    if not evidence_path.is_file():
        warning = (
            "BROWSER_VALIDATION_TIMED_OUT"
            if _now() - started_at > timedelta(seconds=60)
            else "BROWSER_VALIDATION_SKIPPED"
        )
        return "BROWSER_VALIDATION_SKIPPED", warning
    try:
        value = _read_json(evidence_path)
        unsigned = {key: item for key, item in value.items() if key != "evidence_hash"}
        dashboards = value.get("dashboards")
        if (
            value.get("session_id") != session_id
            or value.get("evidence_hash") != _canonical_hash(unsigned)
            or not isinstance(dashboards, list)
            or len(dashboards) != dashboard_count
            or any(not isinstance(item, dict) or item.get("passed") is not True for item in dashboards)
        ):
            raise ValueError("browser evidence binding or checks failed")
        return "PASSED", None
    except (ValueError, OSError, json.JSONDecodeError):
        return "BROWSER_VALIDATION_SKIPPED", "BROWSER_VALIDATION_INVALID"


def _inventory_totals(session_root: Path) -> tuple[dict[str, int], dict[str, int]]:
    inventory = _read_json(session_root / "inventory-ir.json", required=False)
    objects = inventory.get("objects") if isinstance(inventory.get("objects"), list) else []
    totals = {"dashboards": 0, "monitors": 0, "queries": 0}
    query_by_ref: dict[str, int] = {}
    for item in objects:
        if not isinstance(item, dict):
            continue
        kind = item.get("object_type")
        if kind == "dashboard":
            totals["dashboards"] += 1
        elif kind == "monitor":
            totals["monitors"] += 1
        features = item.get("behavior_features")
        query_count = int(features.get("query_count", 0)) if isinstance(features, dict) else 0
        totals["queries"] += max(0, query_count)
        query_by_ref[str(item.get("object_ref") or "")] = max(0, query_count)
    return totals, query_by_ref


def _session_counters(session_root: Path) -> dict[str, dict[str, int]]:
    totals, query_by_ref = _inventory_totals(session_root)
    migrated: set[str] = set()
    validated: set[str] = set()
    failed: set[str] = set()
    checkpoint = _read_json(
        session_root / "unified-execution" / "execution-checkpoint.local.json", required=False,
    )
    operations = checkpoint.get("operations") if isinstance(checkpoint.get("operations"), dict) else {}
    for operation in operations.values():
        if not isinstance(operation, dict):
            continue
        status = str(operation.get("status") or "")
        for resource in operation.get("resources", []):
            if not isinstance(resource, dict):
                continue
            ref = str(resource.get("object_ref") or "")
            if ref:
                migrated.add(ref)
                if status == "COMPLETED":
                    validated.add(ref)
                elif status == "FAILED" and operation.get("failure_category") not in {
                    "browser_validation_pending", "browser_validation_skipped",
                }:
                    failed.add(ref)
    dashboard_progress = _read_json(
        session_root / "dashboard-execution" / "dashboard-apply-checkpoint.local.json",
        required=False,
    )
    for ref, value in (dashboard_progress.get("dashboards") or {}).items():
        if isinstance(value, dict):
            if value.get("outcome") in {"created", "updated", "reused"}:
                migrated.add(str(ref))
            if value.get("validated") is True:
                validated.add(str(ref))
            if value.get("outcome") == "failed":
                failed.add(str(ref))
    inventory = _read_json(session_root / "inventory-ir.json", required=False)
    objects = inventory.get("objects") if isinstance(inventory.get("objects"), list) else []
    refs = {
        "dashboards": {str(item.get("object_ref")) for item in objects if isinstance(item, dict) and item.get("object_type") == "dashboard"},
        "monitors": {str(item.get("object_ref")) for item in objects if isinstance(item, dict) and item.get("object_type") == "monitor"},
    }
    result: dict[str, dict[str, int]] = {}
    for name in ("dashboards", "monitors"):
        result[name] = {
            "total": totals[name],
            "migrated": len(refs[name] & migrated),
            "validated": len(refs[name] & validated),
            "failed": len(refs[name] & failed),
        }
    result["queries"] = {
        "total": totals["queries"],
        "migrated": sum(query_by_ref.get(ref, 0) for ref in migrated),
        "validated": sum(query_by_ref.get(ref, 0) for ref in validated),
        "failed": sum(query_by_ref.get(ref, 0) for ref in failed),
    }
    return result


def _runtime_snapshot(
    state_path: Path, state: dict[str, Any], work_root: Path,
) -> dict[str, Any]:
    session_root = work_root / str(state["session_id"])
    checkpoint = _read_json(session_root / "unified-execution" / "execution-checkpoint.local.json", required=False)
    operations = checkpoint.get("operations") if isinstance(checkpoint.get("operations"), dict) else {}
    resources = {
        (str(item.get("object_type") or ""), str(item.get("target_id") or item.get("id") or index))
        for operation in operations.values() if isinstance(operation, dict)
        for index, item in enumerate(operation.get("resources", [])) if isinstance(item, dict)
    }
    mutations = len(resources) if resources else int(state.get("external_mutations") or 0)
    current = next((
        operation_id for operation_id, value in operations.items()
        if isinstance(value, dict) and value.get("status") in {"APPLYING", "VALIDATING", "ROLLING_BACK"}
    ), "")
    return {
        "runtimeStatus": str(checkpoint.get("status") or state.get("status") or "NOT_STARTED"),
        "operationStates": _operation_counts(checkpoint),
        "currentOperation": current,
        "externalMutations": mutations,
        "progress": _session_counters(session_root),
    }


def _diagnostics(session: Session, runtime: dict[str, Any]) -> list[dict[str, Any]]:
    if session.workflow_state != SessionState.FAILED.value:
        return []
    return [{
        "code": session.error_code or "MIGRATION_FAILURE",
        "category": "workflow",
        "message": session.error_message or "Migration requires attention.",
        "retryable": "retry" in session.available_actions,
        "affectedResources": list(session.affected_resources),
    }]


def _response(
    session: Session, state: dict[str, Any], paths: dict[str, Path | str],
    *, warnings: list[str] | None = None, extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    runtime = _runtime_snapshot(paths["state"], state, paths["work_root"])  # type: ignore[arg-type]
    counters = runtime["progress"]
    for name, prefix in (("dashboards", "dashboards"), ("monitors", "monitors"), ("queries", "queries")):
        for field in ("total", "migrated", "validated", "failed"):
            counters[name][field] = max(
                int(counters[name][field]), int(getattr(session, f"{prefix}_{field}")),
            )
    # Rendering is read-only.  Runtime-to-assessment synchronization happens
    # in _sync_runtime so a response can never invalidate its own action token.
    content: dict[str, Any] = {
        "phase": session.workflow_state,
        "status": session.workflow_state,
        "environment": "Local emulator" if paths.get("emulator_root") is not None else "Connected target",
        "sessionId": session.session_id,
        "actionId": state["action_id"],
        "stateVersion": session.revision,
        "progress": counters,
        "currentOperation": runtime["currentOperation"] or session.current_operation,
        "nextAction": session.next_action,
        "warnings": list(warnings or []),
        "failureDiagnostics": _diagnostics(session, runtime),
        "workflow": {
            "currentStep": session.current_step,
            "currentOperation": runtime["currentOperation"] or session.current_operation,
            "nextAction": session.next_action,
            "dashboards": counters["dashboards"],
            "monitors": counters["monitors"],
            "queries": counters["queries"],
            "validation": {"api": session.validation_status, "browser": session.browser_validation_status},
            "approvalStatus": session.approval_status,
        },
    }
    if session.workflow_state == SessionState.FAILED.value:
        content.update({
            "rootCause": session.error_message or "Migration requires attention.",
            "affectedResources": list(session.affected_resources),
            "resolution": session.resolution or "Choose one of the available recovery actions.",
            "availableActions": list(session.available_actions),
        })
    if extra:
        content.update(extra)
    result = {
        "content": [{"type": "text", "text": json.dumps(content, sort_keys=True)}],
        "structuredContent": content,
    }
    result["_meta"] = {
        "resourceRows": _curated_resource_rows(session, paths["session_root"]),  # type: ignore[arg-type]
        "actionBindings": _control_center_bindings(session, state, paths),
    }
    return result


def _attach_transparency(
    result: dict[str, Any], arguments: dict[str, Any],
) -> dict[str, Any]:
    paths = _paths(arguments)
    session = CheckpointStore(paths["work_root"]).load(str(paths["session_id"]))  # type: ignore[arg-type]
    state = _load_action_state(paths, arguments.get("action_id"))
    transparent = _response(session, state, paths)["structuredContent"]
    result.setdefault("structuredContent", {})["workflow"] = transparent["workflow"]
    result["structuredContent"].setdefault("progress", transparent["progress"])
    result["structuredContent"].setdefault("currentOperation", transparent["currentOperation"])
    result["structuredContent"].setdefault("nextAction", transparent["nextAction"])
    result["structuredContent"].setdefault("warnings", transparent["warnings"])
    result["structuredContent"].setdefault("failureDiagnostics", transparent["failureDiagnostics"])
    return result


def _ready_control_center(
    workspace: Path, work_root: Path, env_file: Path,
) -> dict[str, Any]:
    progress = {
        name: {"total": 0, "migrated": 0, "validated": 0, "failed": 0}
        for name in ("dashboards", "monitors", "queries")
    }
    structured = {
        "phase": "READY", "status": "READY", "stateVersion": 0,
        "environment": "Not selected",
        "progress": progress,
        "currentOperation": "Migration control center opened",
        "nextAction": "Start a read-only assessment",
        "warnings": [], "failureDiagnostics": [],
        "resourceSummary": {"total": 0, "compatible": 0, "byType": {}, "byCompatibility": {}},
        "workflow": {
            "currentStep": "Start", "currentOperation": "Migration control center opened",
            "nextAction": "Start a read-only assessment", "dashboards": progress["dashboards"],
            "monitors": progress["monitors"], "queries": progress["queries"],
            "validation": {"api": "PENDING", "browser": "NOT_STARTED"},
            "approvalStatus": "NOT_REQUIRED",
        },
    }
    return {
        "content": [{"type": "text", "text": "Migration control center is ready."}],
        "structuredContent": structured,
        "_meta": {
            "resourceRows": [],
            "actionBindings": [{
                "kind": "tool", "label": "Start read-only assessment", "style": "primary",
                "tool": "start_read_only_assessment",
                "arguments": {
                    "workspace_root": str(workspace),
                    "work_root": str(work_root),
                    "env_file": str(env_file),
                    "new_run": True,
                },
            }],
        },
    }


def _control_center_bindings(
    session: Session, state: dict[str, Any], paths: dict[str, Path | str],
) -> list[dict[str, Any]]:
    common: dict[str, Any] = {
        "workspace_root": str(paths["workspace_root"]), "work_root": str(paths["work_root"]),
        "env_file": str(paths["env_file"]), "session_id": session.session_id,
        "action_id": state["action_id"],
    }
    if paths.get("emulator_root") is not None:
        common["emulator_root"] = str(paths["emulator_root"])
    phase = session.workflow_state
    if phase == SessionState.PLAN_REVIEW.value:
        return [{
            "kind": "tool", "label": "Continue to scope approval", "style": "primary",
            "tool": "continue_to_plan_review", "arguments": common,
        }]
    if phase == SessionState.WAITING_PLAN_APPROVAL.value:
        return [
            {
                "kind": "tool", "label": "Approve scope and start", "style": "primary",
                "tool": "approve_migration_scope",
                "arguments": {
                    **common, "scope": session.strategy,
                    "review_token": _challenge(state, "review", session.revision),
                },
                "confirmation": (
                    "Confirm the first customer approval and allow Splunk writes only for the "
                    "reviewed scope?"
                ),
            },
            {
                "kind": "tool", "label": "Reject plan", "style": "secondary",
                "tool": "reject_migration_scope", "arguments": common,
                "confirmation": "Reject this plan without performing any Splunk writes?",
            },
        ]
    if phase in {
        SessionState.MIGRATING.value, SessionState.VALIDATING.value,
        SessionState.REVIEW_READY.value, SessionState.ROLLING_BACK.value,
    }:
        return [{
            "kind": "tool", "label": "Refresh status", "style": "secondary",
            "tool": "get_migration_action_state", "arguments": common,
        }]
    if phase == SessionState.WAITING_FINAL_APPROVAL.value:
        bundle_hash = str(state.get("bundle_hash") or "")
        return [
            {
                "kind": "tool", "label": "Approve migration", "style": "primary",
                "tool": "approve_migration_result",
                "arguments": {
                    **common,
                    "final_token": _challenge(state, "final", session.revision, bundle_hash),
                },
                "confirmation": "Confirm the second and final customer approval?",
            },
            {
                "kind": "tool", "label": "Rollback", "style": "danger",
                "tool": "rollback_migration",
                "arguments": {
                    **common,
                    "rollback_token": _challenge(state, "rollback", session.revision, bundle_hash),
                },
                "confirmation": "Delete only resources created by this migration session?",
            },
        ]
    if phase == SessionState.FAILED.value:
        bindings: list[dict[str, Any]] = []
        if "retry" in session.available_actions:
            bindings.append({
                "kind": "tool", "label": "Retry from checkpoint", "style": "primary",
                "tool": "retry_migration_action", "arguments": common,
            })
        if session.mutations_performed:
            bindings.append({
                "kind": "tool", "label": "Rollback", "style": "danger",
                "tool": "rollback_migration",
                "arguments": {
                    **common,
                    "rollback_token": _challenge(
                        state, "rollback", session.revision, str(state.get("bundle_hash") or "")
                    ),
                },
                "confirmation": "Delete only resources created by this migration session?",
            })
        return bindings
    if phase in {SessionState.COMPLETED.value, SessionState.ROLLED_BACK.value}:
        fresh: dict[str, Any] = {
            "workspace_root": str(paths["workspace_root"]),
            "work_root": str(paths["work_root"]),
            "env_file": str(paths["env_file"]),
            "new_run": True,
        }
        if paths.get("emulator_root") is not None:
            fresh["emulator_root"] = str(paths["emulator_root"])
        bindings: list[dict[str, Any]] = []
        if phase == SessionState.COMPLETED.value:
            bindings.append({
                "kind": "tool",
                "label": "Generate Terraform code",
                "style": "secondary",
                "tool": "generate_terraform_code",
                "arguments": common,
            })
        bindings.append({
            "kind": "tool",
            "label": "Start new migration",
            "style": "primary",
            "tool": "start_read_only_assessment",
            "arguments": fresh,
        })
        return bindings
    return []


def open_migration_control_center(arguments: dict[str, Any]) -> dict[str, Any]:
    """Render a clean start unless an existing session is explicitly requested."""

    workspace, work_root, env_file = _workspace_paths(arguments)
    if arguments.get("new_run") is True:
        return _ready_control_center(workspace, work_root, env_file)
    requested_id = str(arguments.get("session_id") or "")
    if requested_id:
        session = CheckpointStore(work_root).load(requested_id)
    elif arguments.get("resume_latest") is True:
        session = _latest_session(work_root)
    else:
        session = None
    if session is None:
        return _ready_control_center(workspace, work_root, env_file)

    scoped = dict(arguments)
    scoped.update({
        "workspace_root": str(workspace), "work_root": str(work_root),
        "env_file": str(env_file), "session_id": session.session_id,
    })
    paths = _paths(scoped)
    existing = _read_json(paths["state"], required=False)  # type: ignore[arg-type]
    state = (
        _load_action_state(paths, existing.get("action_id"))
        if existing and existing.get("session_id") == session.session_id
        else _new_action_state(session, paths)
    )
    session = _sync_runtime(session, state, paths)
    state["assessment_revision"] = session.revision
    state["expires_at"] = (_now() + TOKEN_LIFETIME).isoformat()
    _write_private(paths["state"], state)  # type: ignore[arg-type]
    response = _response(session, state, paths)
    response["structuredContent"]["resourceSummary"] = _resource_summary(paths["session_root"])  # type: ignore[arg-type]
    response["content"] = [{
        "type": "text",
        "text": (
            "Migration control center opened with the authoritative checkpoint. "
            "Resource names are available only inside the widget."
        ),
    }]
    response["_meta"] = {
        "resourceRows": _curated_resource_rows(session, paths["session_root"]),  # type: ignore[arg-type]
        "actionBindings": _control_center_bindings(session, state, paths),
    }
    return response


def review_migration_plan(arguments: dict[str, Any]) -> dict[str, Any]:
    paths = _paths(arguments)
    store = CheckpointStore(paths["work_root"])  # type: ignore[arg-type]
    session = store.load(str(paths["session_id"]))
    if session.workflow_state == SessionState.FAILED.value:
        state = _read_json(paths["state"], required=False)  # type: ignore[arg-type]
        if not state:
            state = _new_action_state(session, paths)
        return _response(session, state, paths)
    if session.workflow_state not in {
        SessionState.PLAN_REVIEW.value, SessionState.WAITING_PLAN_APPROVAL.value,
        SessionState.MIGRATING.value, SessionState.VALIDATING.value,
        SessionState.REVIEW_READY.value, SessionState.WAITING_FINAL_APPROVAL.value,
    }:
        raise ValueError(f"INVALID_STATE_TRANSITION: cannot review from {session.workflow_state}")
    assessment = _read_json(paths["session_root"] / "discovery-report.json")  # type: ignore[operator]
    _ensure_reviewable_assessment(assessment)
    supplied_hash = arguments.get("plan_hash")
    if supplied_hash and supplied_hash != session.plan_hash:
        raise ValueError("reviewed plan differs from the checkpoint")
    existing = _read_json(paths["state"], required=False)  # type: ignore[arg-type]
    state = existing if existing and existing.get("session_id") == session.session_id else _new_action_state(session, paths)
    state["assessment_revision"] = session.revision
    state["expires_at"] = (_now() + TOKEN_LIFETIME).isoformat()
    _write_private(paths["state"], state)  # type: ignore[arg-type]
    return _response(session, state, paths, extra={
        "scopeOptions": ["full", "safe_staged"],
    })


def continue_to_plan_review(arguments: dict[str, Any]) -> dict[str, Any]:
    paths = _paths(arguments)
    store = CheckpointStore(paths["work_root"])  # type: ignore[arg-type]
    session = store.load(str(paths["session_id"]))
    state = _load_action_state(paths, arguments.get("action_id"))
    if session.workflow_state == SessionState.PLAN_REVIEW.value:
        session = store.transition(
            session.session_id, SessionState.PLAN_REVIEW, SessionState.WAITING_PLAN_APPROVAL,
            approval_status="WAITING_PLAN_APPROVAL", event="Plan review opened",
        )
    elif session.workflow_state != SessionState.WAITING_PLAN_APPROVAL.value:
        raise ValueError(f"INVALID_STATE_TRANSITION: cannot open plan approval from {session.workflow_state}")
    state["assessment_revision"] = session.revision
    state["expires_at"] = (_now() + TOKEN_LIFETIME).isoformat()
    _write_private(paths["state"], state)  # type: ignore[arg-type]
    return _response(session, state, paths)


def reject_migration_scope(arguments: dict[str, Any]) -> dict[str, Any]:
    """Reject the reviewed plan without authorizing or performing target writes."""

    paths = _paths(arguments)
    store = CheckpointStore(paths["work_root"])  # type: ignore[arg-type]
    session = store.load(str(paths["session_id"]))
    if session.workflow_state != SessionState.WAITING_PLAN_APPROVAL.value:
        raise ValueError(
            "INVALID_STATE_TRANSITION: cannot reject plan from "
            f"{session.workflow_state}"
        )
    state = _load_action_state(paths, arguments.get("action_id"))
    session = store.transition(
        session.session_id,
        SessionState.WAITING_PLAN_APPROVAL,
        SessionState.FAILED,
        approval_status="PLAN_REJECTED",
        event="Plan rejected by customer",
        updates={
            "error_code": "PLAN_REJECTED",
            "error_message": "The reviewed migration plan was rejected.",
            "expected_state": SessionState.WAITING_PLAN_APPROVAL.value,
            "actual_state": SessionState.WAITING_PLAN_APPROVAL.value,
            "current_operation": "Plan rejected",
            "next_action": "Retry plan review or start a new migration",
            "resolution": "Review the existing plan again or start a new read-only assessment.",
            "available_actions": ["retry"],
        },
    )
    state["assessment_revision"] = session.revision
    state["expires_at"] = (_now() + TOKEN_LIFETIME).isoformat()
    _write_private(paths["state"], state)  # type: ignore[arg-type]
    return _response(session, state, paths)


def _run_command(command: list[str], *, cwd: Path | None = None) -> dict[str, Any]:
    completed = subprocess.run(command, cwd=cwd, check=False, capture_output=True, text=True)
    if completed.returncode:
        message = (completed.stderr or completed.stdout or "migration command failed").strip()
        raise RuntimeError(message[:1000])
    output = completed.stdout.strip()
    if not output:
        return {}
    decoder = json.JSONDecoder()
    for index, char in enumerate(output):
        if char != "{":
            continue
        try:
            value, end = decoder.raw_decode(output[index:])
            if output[index + end:].strip() == "" and isinstance(value, dict):
                return value
        except json.JSONDecodeError:
            continue
    raise RuntimeError("migration command did not return a JSON object")


def _run_discovery(command: list[str], *, cwd: Path) -> None:
    """Run the bounded read-only collector, whose CLI output is human-readable."""

    completed = subprocess.run(command, cwd=cwd, check=False, capture_output=True, text=True)
    if completed.returncode:
        message = (completed.stderr or completed.stdout or "Datadog discovery failed").strip()
        raise RuntimeError(message[:1000])


def start_read_only_assessment(arguments: dict[str, Any]) -> dict[str, Any]:
    """Run a new read-only discovery and return the hydrated plan-review widget."""

    workspace, work_root, env_file = _workspace_paths(arguments)
    session_id = f"assessment-{uuid.uuid4().hex[:16]}"
    assessment_script = ASSESSMENT / "migration_assessment.py"
    collector_script = ASSESSMENT / "collect_datadog_configuration.py"
    common = ["--work-root", str(work_root), "--env-file", str(env_file)]

    authorized = _run_command([
        sys.executable, str(assessment_script), "authorize-read-only",
        "--session-id", session_id, *common,
        "--actor-role", "customer", "--target", "splunk_observability_cloud",
        "--ttl-minutes", "60", "--confirm-read-only",
    ], cwd=workspace)
    if authorized.get("session_id") != session_id:
        raise RuntimeError("read-only authorization returned an unexpected session")

    session_root = CheckpointStore(work_root).session_directory(session_id)
    authorization_file = session_root / "authorization.local.json"
    capability_catalog = session_root / "capability-catalog.json"
    inventory_dir = session_root / "raw-inventory"
    inventory_file = inventory_dir / "datadog-estate.local.json"

    _run_command([
        sys.executable, str(assessment_script), "live-preflight",
        "--authorization-file", str(authorization_file),
        "--env-file", str(env_file), "--output-dir", str(session_root),
    ], cwd=workspace)
    _run_discovery([
        sys.executable, str(collector_script),
        "--output-dir", str(inventory_dir),
        "--env-file", str(env_file),
        "--authorization-file", str(authorization_file),
    ], cwd=workspace)
    _run_command([
        sys.executable, str(assessment_script), "prepare",
        "--inventory", str(inventory_file),
        "--env-file", str(env_file),
        "--capability-catalog", str(capability_catalog),
        "--work-root", str(work_root), "--session-id", session_id,
        "--target", "splunk_observability_cloud", "--strategy", "full",
    ], cwd=workspace)
    return open_migration_control_center({
        "workspace_root": str(workspace), "work_root": str(work_root),
        "env_file": str(env_file), "session_id": session_id,
    })


def _approval_receipt(paths: dict[str, Path | str], bundle_hash: str) -> Path:
    runtime = paths["runtime"]  # type: ignore[assignment]
    now = _now()
    receipt = {
        "schema_version": "1.0", "approval_kind": "apply",
        "session_id": paths["session_id"], "bound_hash": bundle_hash,
        "approved_at": now.isoformat(), "expires_at": (now + timedelta(minutes=5)).isoformat(),
        "approval_channel": "native_codex_tool_confirmation", "user_confirmed": True,
        "receipt_hash": "",
    }
    receipt["receipt_hash"] = _canonical_hash({key: value for key, value in receipt.items() if key != "receipt_hash"})
    path = runtime / "interactive-apply-approval.used.local.json"
    _write_private(path, receipt)
    return path


def _start_migration_worker(
    compiled: dict[str, Any], paths: dict[str, Path | str], *, resume: bool = False,
) -> bool:
    bundle_hash = str(compiled.get("bundle_hash") or "")
    if len(bundle_hash) != 64 or any(char not in SHA256 for char in bundle_hash):
        raise ValueError("compiled execution bundle identity is invalid")
    emulator_root = paths.get("emulator_root")
    script = HERE / ("emulated_migration.py" if emulator_root else "unified_migration.py")
    command = [
        sys.executable, str(script), "execute" if resume else "apply",
        "--session-id", str(paths["session_id"]), "--work-root", str(paths["work_root"]),
        "--env-file", str(paths["env_file"]),
    ]
    if not resume:
        command.extend(["--approval-receipt", str(_approval_receipt(paths, bundle_hash))])
    if emulator_root:
        command.extend(["--target-root", str(emulator_root)])
    log_path = paths["runtime"] / "migration-worker.local.log"  # type: ignore[operator]
    log = log_path.open("ab")
    try:
        subprocess.Popen(command, cwd=paths["workspace_root"], stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
    finally:
        log.close()
    return True


def approve_migration_scope(arguments: dict[str, Any]) -> dict[str, Any]:
    paths = _paths(arguments)
    store = CheckpointStore(paths["work_root"])  # type: ignore[arg-type]
    session = store.load(str(paths["session_id"]))
    state = _load_action_state(paths, arguments.get("action_id"))
    supplied_token = arguments.get("review_token")
    token_hash = _canonical_hash({"review_token": supplied_token})
    requested_scope = str(arguments.get("scope") or session.strategy)
    aliases = {"supported": "safe_staged", "supported_subset": "safe_staged"}
    requested_scope = aliases.get(requested_scope, requested_scope)
    if session.workflow_state != SessionState.WAITING_PLAN_APPROVAL.value:
        recorded_hash = str(
            state.get("consumed_review_token_hash")
            or state.get("pending_review_token_hash")
            or ""
        )
        if (
            session.approval_status == "PLAN_APPROVED"
            and recorded_hash
            and secrets.compare_digest(recorded_hash, token_hash)
            and state.get("selected_scope") == requested_scope
        ):
            return _response(session, state, paths)
        raise ValueError(
            f"INVALID_STATE_TRANSITION: expected WAITING_PLAN_APPROVAL, actual {session.workflow_state}"
        )
    _verify_challenge(supplied_token, state, "review", session)
    if requested_scope != session.strategy:
        raise ValueError("selected scope differs from the reviewed plan; return to plan review")
    state.update({
        "pending_review_token_hash": token_hash,
        "selected_scope": requested_scope,
    })
    _write_private(paths["state"], state)  # type: ignore[arg-type]
    session_root = paths["session_root"]  # type: ignore[assignment]
    plan = _read_json(session_root / session.artifacts.get("dry_run_plan", "dry-run-plan.json"))
    assessment = _read_json(session_root / session.artifacts.get("discovery_report_json", "discovery-report.json"))
    if plan.get("plan_hash") != session.plan_hash or plan.get("assessment_hash") != assessment.get("assessment_hash"):
        raise ValueError("reviewed plan binding is invalid")
    record = create_plan_review_approval(
        session.session_id, "customer", str(plan["plan_hash"]),
        str(assessment["assessment_hash"]), session.strategy,
    )
    approval_path = session_root / "plan-review-approval.local.json"
    write_plan_review_approval(approval_path, record)
    validate_plan_review_approval(_read_json(approval_path))
    session.artifacts["plan_review_approval"] = approval_path.name
    session.approval_ids.append(str(record["approval_id"]))
    store.save(session)
    try:
        session = store.transition(
            session.session_id, SessionState.WAITING_PLAN_APPROVAL, SessionState.MIGRATING,
            approval_status="PLAN_APPROVED", event="PLAN_APPROVED",
        )
    except Exception as exc:
        store.block(
            session.session_id, error_code="APPROVAL_PERSISTENCE_FAILURE",
            error_message="Plan approval could not be persisted safely.",
            expected_state=SessionState.MIGRATING.value,
            recovery_state=SessionState.WAITING_PLAN_APPROVAL,
        )
        raise RuntimeError("APPROVAL_PERSISTENCE_FAILURE") from exc
    state["consumed_review_token_hash"] = state.pop("pending_review_token_hash")
    state["assessment_revision"] = session.revision
    _write_private(paths["state"], state)  # type: ignore[arg-type]
    try:
        emulator_root = paths.get("emulator_root")
        script = HERE / ("emulated_migration.py" if emulator_root else "unified_migration.py")
        compile_command = [
            sys.executable, str(script), "compile",
            "--session-id", session.session_id, "--work-root", str(paths["work_root"]),
            "--env-file", str(paths["env_file"]),
        ]
        if emulator_root:
            compile_command.extend(["--target-root", str(emulator_root)])
        compiled = _run_command(compile_command, cwd=paths["workspace_root"])  # type: ignore[arg-type]
        bundle_hash = str(compiled.get("bundle_hash") or "")
        state.update({
            "assessment_revision": session.revision,
            "bundle_hash": bundle_hash,
            "selected_scope": requested_scope,
            "external_mutations": 0,
            "expires_at": (_now() + TOKEN_LIFETIME).isoformat(),
        })
        _write_private(paths["state"], state)  # type: ignore[arg-type]
        _start_migration_worker(compiled, paths)
    except Exception as exc:
        blocked = store.block(
            session.session_id, error_code="BUNDLE_COMPILATION_FAILURE",
            error_message="The approved migration bundle could not be compiled.",
            expected_state=SessionState.MIGRATING.value,
            recovery_state=SessionState.MIGRATING,
            available_actions=["retry"],
        )
        state["assessment_revision"] = blocked.revision
        _write_private(paths["state"], state)  # type: ignore[arg-type]
        raise RuntimeError("scope compilation failed") from exc
    return _response(session, state, paths)


def _write_review(session: Session, paths: dict[str, Path | str], warnings: list[str]) -> Path:
    path = paths["session_root"] / "migration-review.json"  # type: ignore[operator]
    _write_private(path, {
        "schema_version": "1.0", "session_id": session.session_id,
        "successful": session.resources_migrated, "deferred": session.resources_deferred,
        "failed": session.resources_failed, "api_validation": session.validation_status,
        "browser_validation": session.browser_validation_status, "warnings": warnings,
    })
    return path


def _sync_runtime(session: Session, state: dict[str, Any], paths: dict[str, Path | str]) -> Session:
    store = CheckpointStore(paths["work_root"])  # type: ignore[arg-type]
    runtime = _runtime_snapshot(paths["state"], state, paths["work_root"])  # type: ignore[arg-type]
    runtime_status = runtime["runtimeStatus"]
    operation_states = runtime["operationStates"]
    if session.workflow_state == SessionState.MIGRATING.value and runtime_status == "VALIDATING":
        session = store.transition(
            session.session_id, SessionState.MIGRATING, SessionState.VALIDATING,
            updates={"validation_status": ValidationState.RUNNING.value},
            event="Execution finished; API validation started",
        )
    if session.workflow_state in {SessionState.MIGRATING.value, SessionState.VALIDATING.value} and runtime_status in {"COMPLETED", "PARTIAL", "FAILED"}:
        if not _api_validation_passed(runtime_status, operation_states):
            mutations = int(runtime["externalMutations"])
            return store.block(
                session.session_id, error_code="API_VALIDATION_FAILED",
                error_message="Required API validation did not pass for every selected operation.",
                expected_state=SessionState.REVIEW_READY.value,
                recovery_state=SessionState.MIGRATING,
                mutations_performed=mutations,
            )
        if session.workflow_state == SessionState.MIGRATING.value:
            session = store.transition(
                session.session_id, SessionState.MIGRATING, SessionState.VALIDATING,
                updates={"validation_status": ValidationState.RUNNING.value},
                event="Execution finished; API validation started",
            )
        counters = runtime["progress"]
        migrated = sum(counters[kind]["migrated"] for kind in ("dashboards", "monitors"))
        discovered = session.resources_discovered
        skipped = operation_states.get("SKIPPED", 0)
        session = store.transition(
            session.session_id, SessionState.VALIDATING, SessionState.REVIEW_READY,
            updates={
                "validation_status": ValidationState.PASSED.value,
                "resources_migrated": max(session.resources_migrated, min(discovered, migrated)),
                "resources_deferred": max(session.resources_deferred, min(discovered, skipped)),
                "mutations_performed": max(session.mutations_performed, int(runtime["externalMutations"])),
            },
            event="Required API validation passed",
        )
        dashboard_count = counters["dashboards"]["migrated"]
        started = datetime.fromisoformat(session.state_entered_at)
        browser_status, warning = _browser_validation_outcome(
            paths["session_root"] / "dashboard-execution" / "browser-validation.local.json",  # type: ignore[operator]
            session.session_id, dashboard_count, started,
        )
        warnings = [warning] if warning else []
        review_path = _write_review(session, paths, warnings)
        session.artifacts["migration_review"] = review_path.name
        session.browser_validation_status = browser_status
        store.save(session)
        session = store.transition(
            session.session_id, SessionState.REVIEW_READY, SessionState.WAITING_FINAL_APPROVAL,
            approval_status="WAITING_FINAL_APPROVAL", event="Migration results are ready for review",
        )
    return session


def get_migration_action_state(arguments: dict[str, Any]) -> dict[str, Any]:
    paths = _paths(arguments)
    store = CheckpointStore(paths["work_root"])  # type: ignore[arg-type]
    session = store.load(str(paths["session_id"]))
    state = _load_action_state(paths, arguments.get("action_id"))
    # Transport expiry is intentionally ignored here; refresh reads authoritative disk state.
    session = _sync_runtime(session, state, paths)
    state["assessment_revision"] = session.revision
    state["external_mutations"] = max(
        int(state.get("external_mutations") or 0), session.mutations_performed,
    )
    state["expires_at"] = (_now() + TOKEN_LIFETIME).isoformat()
    _write_private(paths["state"], state)  # type: ignore[arg-type]
    warnings: list[str] = []
    extra: dict[str, Any] = {}
    if session.workflow_state == SessionState.WAITING_FINAL_APPROVAL.value:
        review = _read_json(paths["session_root"] / session.artifacts.get("migration_review", "migration-review.json"))  # type: ignore[operator]
        dashboard_result = _read_json(paths["session_root"] / "dashboard-execution" / "dashboard-result.local.json", required=False)  # type: ignore[operator]
        dashboard_count = len(dashboard_result.get("results", [])) if isinstance(dashboard_result.get("results"), list) else session.dashboards_migrated
        browser_status, warning = _browser_validation_outcome(
            paths["session_root"] / "dashboard-execution" / "browser-validation.local.json",  # type: ignore[operator]
            session.session_id, dashboard_count, datetime.fromisoformat(session.state_entered_at),
        )
        if browser_status != session.browser_validation_status:
            session.browser_validation_status = browser_status
            store.save(session)
            session = store.load(session.session_id)
            state["assessment_revision"] = session.revision
            _write_private(paths["state"], state)  # type: ignore[arg-type]
        warnings = [] if browser_status == "PASSED" else list(review.get("warnings") or ([warning] if warning else []))
        extra = {"browserValidationStatus": browser_status}
    return _response(session, state, paths, warnings=warnings, extra=extra)


def retry_migration_action(arguments: dict[str, Any]) -> dict[str, Any]:
    paths = _paths(arguments)
    store = CheckpointStore(paths["work_root"])  # type: ignore[arg-type]
    session = store.load(str(paths["session_id"]))
    state = _load_action_state(paths, arguments.get("action_id"))
    if session.workflow_state != SessionState.FAILED.value or "retry" not in session.available_actions:
        raise ValueError("INVALID_STATE_TRANSITION: retry is unavailable")
    compilation_retry = session.error_code == "BUNDLE_COMPILATION_FAILURE"
    if compilation_retry and session.failure_recovery_state != SessionState.MIGRATING.value:
        # Upgrade checkpoints written by releases that incorrectly sent a
        # post-approval compile retry back through plan approval.
        session.failure_recovery_state = SessionState.MIGRATING.value
        store.save(session)
        session = store.load(session.session_id)
    target = (
        SessionState.MIGRATING
        if compilation_retry
        else SessionState(session.failure_recovery_state)
    )
    session = store.recover(session.session_id, target, event="Customer requested checkpointed retry")
    state["assessment_revision"] = session.revision
    _write_private(paths["state"], state)  # type: ignore[arg-type]
    if target is SessionState.MIGRATING:
        if compilation_retry:
            emulator_root = paths.get("emulator_root")
            script = HERE / ("emulated_migration.py" if emulator_root else "unified_migration.py")
            compile_command = [
                sys.executable, str(script), "compile",
                "--session-id", session.session_id,
                "--work-root", str(paths["work_root"]),
                "--env-file", str(paths["env_file"]),
            ]
            if emulator_root:
                compile_command.extend(["--target-root", str(emulator_root)])
            try:
                compiled = _run_command(compile_command, cwd=paths["workspace_root"])  # type: ignore[arg-type]
                state["bundle_hash"] = str(compiled.get("bundle_hash") or "")
                _write_private(paths["state"], state)  # type: ignore[arg-type]
                _start_migration_worker(compiled, paths)
            except Exception as exc:
                blocked = store.block(
                    session.session_id,
                    error_code="BUNDLE_COMPILATION_FAILURE",
                    error_message="The approved migration bundle could not be compiled.",
                    expected_state=SessionState.MIGRATING.value,
                    recovery_state=SessionState.MIGRATING,
                    available_actions=["retry"],
                )
                state["assessment_revision"] = blocked.revision
                _write_private(paths["state"], state)  # type: ignore[arg-type]
                raise RuntimeError("scope compilation retry failed") from exc
        else:
            bundle = _read_json(paths["runtime"] / "execution-bundle.local.json")  # type: ignore[operator]
            _start_migration_worker({"bundle_hash": bundle["bundle_hash"]}, paths, resume=True)
    return _response(session, state, paths)


def approve_migration_result(arguments: dict[str, Any]) -> dict[str, Any]:
    paths = _paths(arguments)
    store = CheckpointStore(paths["work_root"])  # type: ignore[arg-type]
    session = store.load(str(paths["session_id"]))
    if session.workflow_state != SessionState.WAITING_FINAL_APPROVAL.value:
        raise ValueError("INVALID_STATE_TRANSITION: final approval is unavailable")
    if session.validation_status != ValidationState.PASSED.value:
        raise ValueError("final approval requires successful API validation")
    state = _load_action_state(paths, arguments.get("action_id"))
    _verify_challenge(arguments.get("final_token"), state, "final", session)
    session = store.transition(
        session.session_id, SessionState.WAITING_FINAL_APPROVAL, SessionState.COMPLETED,
        approval_status="FINAL_APPROVED", event="FINAL_RESULT_APPROVED",
    )
    state.update({
        "assessment_revision": session.revision,
        "final_approved_at": _now().isoformat(),
    })
    _write_private(paths["state"], state)  # type: ignore[arg-type]
    return _response(session, state, paths)


def rollback_migration(arguments: dict[str, Any]) -> dict[str, Any]:
    paths = _paths(arguments)
    store = CheckpointStore(paths["work_root"])  # type: ignore[arg-type]
    session = store.load(str(paths["session_id"]))
    state = _load_action_state(paths, arguments.get("action_id"))
    _verify_challenge(arguments.get("rollback_token"), state, "rollback", session)
    if session.workflow_state == SessionState.WAITING_FINAL_APPROVAL.value:
        session = store.transition(
            session.session_id, SessionState.WAITING_FINAL_APPROVAL, SessionState.ROLLING_BACK,
            event="Customer authorized rollback",
        )
    elif session.workflow_state == SessionState.FAILED.value and session.mutations_performed:
        session = store.recover(session.session_id, SessionState.ROLLING_BACK, event="Customer authorized rollback")
    else:
        raise ValueError("INVALID_STATE_TRANSITION: rollback is unavailable")
    try:
        emulator_root = paths.get("emulator_root")
        script = HERE / ("emulated_migration.py" if emulator_root else "unified_migration.py")
        rollback_command = [
            sys.executable, str(script), "rollback",
            "--session-id", session.session_id, "--work-root", str(paths["work_root"]),
            "--env-file", str(paths["env_file"]), "--confirm-rollback",
        ]
        if emulator_root:
            rollback_command.extend(["--target-root", str(emulator_root)])
        result = _run_command(rollback_command, cwd=paths["workspace_root"])  # type: ignore[arg-type]
        if result.get("status") != "ROLLED_BACK":
            raise RuntimeError("rollback verification did not complete")
        session = store.transition(
            session.session_id, SessionState.ROLLING_BACK, SessionState.ROLLED_BACK,
            event="Session-owned resources rolled back and verified",
        )
    except Exception as exc:
        session = store.block(
            session.session_id, error_code="ROLLBACK_FAILURE",
            error_message="Rollback could not be verified for every session-owned resource.",
            recovery_state=SessionState.ROLLING_BACK,
            available_actions=["retry"], mutations_performed=session.mutations_performed,
        )
        raise RuntimeError("rollback failed") from exc
    state["assessment_revision"] = session.revision
    state["rolled_back_at"] = _now().isoformat()
    _write_private(paths["state"], state)  # type: ignore[arg-type]
    return _response(session, state, paths)


def generate_terraform_code(arguments: dict[str, Any]) -> dict[str, Any]:
    """Write import-only Terraform configuration for the completed migration."""

    paths = _paths(arguments)
    store = CheckpointStore(paths["work_root"])  # type: ignore[arg-type]
    session = store.load(str(paths["session_id"]))
    if session.workflow_state != SessionState.COMPLETED.value:
        raise ValueError("Terraform generation is available only after final migration approval")
    if session.validation_status != ValidationState.PASSED.value:
        raise ValueError("Terraform generation requires successful API validation")
    state = _load_action_state(paths, arguments.get("action_id"))
    export = export_terraform(
        Path(str(paths["workspace_root"])),
        Path(str(paths["work_root"])),
        session.session_id,
    )
    result = _response(session, state, paths, extra={"terraformExport": export})
    result["content"] = [{
        "type": "text",
        "text": (
            f"Terraform import configuration is ready for {export['resourceCount']} "
            "migration-managed resources. Terraform was not executed."
        ),
    }]
    return result


TOOLS = {
    "open_migration_control_center": open_migration_control_center,
    "start_read_only_assessment": start_read_only_assessment,
    "review_migration_plan": review_migration_plan,
    "continue_to_plan_review": continue_to_plan_review,
    "reject_migration_scope": reject_migration_scope,
    "approve_migration_scope": approve_migration_scope,
    "get_migration_action_state": get_migration_action_state,
    "retry_migration_action": retry_migration_action,
    "approve_migration_result": approve_migration_result,
    "rollback_migration": rollback_migration,
    "generate_terraform_code": generate_terraform_code,
}


def _tool_definitions() -> list[dict[str, Any]]:
    session_input = {
        "type": "object",
        "properties": {
            "workspace_root": {"type": "string"}, "work_root": {"type": "string"},
            "env_file": {"type": "string"}, "session_id": {"type": "string"},
            "action_id": {"type": "string"},
        },
        "required": ["session_id"], "additionalProperties": True,
    }
    open_input = {
        "type": "object",
        "properties": {
            "workspace_root": {"type": "string"}, "work_root": {"type": "string"},
            "env_file": {"type": "string"}, "session_id": {"type": "string"},
            "new_run": {
                "type": "boolean",
                "description": "Show a clean start screen instead of resuming an existing checkpoint.",
            },
            "resume_latest": {
                "type": "boolean",
                "description": "Resume the latest checkpoint only after an explicit customer request.",
            },
        },
        "additionalProperties": False,
    }
    output_schema = {
        "type": "object",
        "properties": {
            "phase": {"type": "string"}, "status": {"type": "string"},
            "stateVersion": {"type": "integer"}, "progress": {"type": "object"},
            "currentOperation": {"type": "string"}, "nextAction": {"type": "string"},
            "warnings": {"type": "array"}, "failureDiagnostics": {"type": "array"},
            "workflow": {"type": "object"}, "resourceSummary": {"type": "object"},
            "terraformExport": {"type": "object"},
        },
        "required": [
            "phase", "status", "progress", "currentOperation", "nextAction",
            "warnings", "failureDiagnostics", "workflow",
        ],
        "additionalProperties": True,
    }
    descriptions = {
        "open_migration_control_center": (
            "Use this when the observability migration plugin starts or the customer asks to see "
            "the migration UI. Render a clean start unless an existing session is explicitly requested."
        ),
        "start_read_only_assessment": (
            "Start a new bounded read-only Datadog discovery, assess Splunk Observability Cloud "
            "compatibility, build a non-executable plan, and return the plan-review UI."
        ),
        "review_migration_plan": "Open or resume the governed migration review.",
        "continue_to_plan_review": "Continue from discovery results to scope approval.",
        "reject_migration_scope": "Reject the reviewed plan without performing Splunk writes.",
        "approve_migration_scope": "Approval 1: approve the exact reviewed scope and start migration.",
        "get_migration_action_state": "Read authoritative migration progress and results.",
        "retry_migration_action": "Retry a recoverable failure from persisted checkpoints.",
        "approve_migration_result": "Approval 2: accept API-validated migration results.",
        "rollback_migration": "Roll back only resources owned by this migration session.",
        "generate_terraform_code": (
            "Generate local Terraform import configuration for created or updated resources "
            "after final approval. This never runs Terraform or writes to Splunk or Git."
        ),
    }
    annotations = {
        "open_migration_control_center": {
            "readOnlyHint": True, "destructiveHint": False, "openWorldHint": False,
            "idempotentHint": True,
        },
        "start_read_only_assessment": {
            "readOnlyHint": True, "destructiveHint": False, "openWorldHint": True,
            "idempotentHint": False,
        },
        "review_migration_plan": {
            "readOnlyHint": True, "destructiveHint": False, "openWorldHint": False,
            "idempotentHint": True,
        },
        "continue_to_plan_review": {
            "readOnlyHint": False, "destructiveHint": False, "openWorldHint": False,
            "idempotentHint": True,
        },
        "reject_migration_scope": {
            "readOnlyHint": False, "destructiveHint": False, "openWorldHint": False,
            "idempotentHint": True,
        },
        "approve_migration_scope": {
            "readOnlyHint": False, "destructiveHint": False, "openWorldHint": True,
            "idempotentHint": True,
        },
        "get_migration_action_state": {
            "readOnlyHint": True, "destructiveHint": False, "openWorldHint": False,
            "idempotentHint": True,
        },
        "retry_migration_action": {
            "readOnlyHint": False, "destructiveHint": False, "openWorldHint": True,
            "idempotentHint": False,
        },
        "approve_migration_result": {
            "readOnlyHint": False, "destructiveHint": False, "openWorldHint": False,
            "idempotentHint": True,
        },
        "rollback_migration": {
            "readOnlyHint": False, "destructiveHint": True, "openWorldHint": True,
            "idempotentHint": True,
        },
        "generate_terraform_code": {
            "readOnlyHint": False, "destructiveHint": False, "openWorldHint": False,
            "idempotentHint": True,
        },
    }
    titles = {
        "open_migration_control_center": "Open migration control center",
        "start_read_only_assessment": "Start read-only assessment",
        "review_migration_plan": "Review migration plan",
        "continue_to_plan_review": "Continue to scope approval",
        "reject_migration_scope": "Reject migration scope",
        "approve_migration_scope": "Approve migration scope",
        "get_migration_action_state": "Refresh migration status",
        "retry_migration_action": "Retry from checkpoint",
        "approve_migration_result": "Approve migration result",
        "rollback_migration": "Roll back session resources",
        "generate_terraform_code": "Generate Terraform code",
    }
    result: list[dict[str, Any]] = []
    for name in TOOLS:
        descriptor: dict[str, Any] = {
            "name": name, "title": titles[name], "description": descriptions[name],
            "inputSchema": (
                open_input if name in {
                    "open_migration_control_center", "start_read_only_assessment",
                } else session_input
            ),
            "outputSchema": output_schema, "annotations": annotations[name],
            "_meta": {
                "ui": {"visibility": ["model", "app"]},
                "openai/widgetAccessible": True,
                "openai/toolInvocation/invoking": "Updating migration…",
                "openai/toolInvocation/invoked": "Migration state ready",
            },
        }
        if name == "open_migration_control_center":
            descriptor["_meta"]["ui"]["resourceUri"] = CONTROL_CENTER_URI
            descriptor["_meta"].update({
                "openai/outputTemplate": CONTROL_CENTER_URI,
            })
        result.append(descriptor)
    return result


def _resources(workspace: Path) -> list[dict[str, Any]]:
    return [
        {
            "uri": CONTROL_CENTER_URI, "name": "Observability migration control center",
            "title": "Migration control center", "mimeType": CONTROL_CENTER_MIME,
            "description": "Interactive in-chat migration status, resource report, and approvals.",
        },
        {"uri": CHECKLIST_URI, "name": "Migration verification checklist", "mimeType": "text/markdown"},
        {"uri": REPORT_URI, "name": "Current migration report", "mimeType": "application/json"},
    ]


def _read_resource(uri: str, params: dict[str, Any]) -> dict[str, Any]:
    workspace = Path(str(params.get("workspace_root") or Path.cwd())).resolve()
    if uri == CONTROL_CENTER_URI:
        path = HERE / "control_center.html"
        if not path.is_file():
            raise ValueError("migration control center template is unavailable")
        return {"contents": [{
            "uri": uri, "mimeType": CONTROL_CENTER_MIME,
            "text": path.read_text(encoding="utf-8"),
            "_meta": {
                "ui": {
                    "prefersBorder": True,
                    "csp": {"connectDomains": [], "resourceDomains": []},
                },
                "openai/widgetDescription": (
                    "Interactive Datadog to Splunk migration control center with progress, "
                    "named component report, validation evidence, approvals, retry, and rollback."
                ),
            },
        }]}
    if uri == CHECKLIST_URI:
        path = workspace / "docs" / "OBSERVABILITY-MIGRATION-VERIFICATION-CHECKLIST.md"
        if not path.is_file():
            # In a packaged plugin the copied checklist lives in assets.
            path = HERE.parents[2] / "assets" / "OBSERVABILITY-MIGRATION-VERIFICATION-CHECKLIST.md"
        return {"contents": [{"uri": uri, "mimeType": "text/markdown", "text": path.read_text(encoding="utf-8")} ]}
    if uri == REPORT_URI:
        session_id = str(params.get("session_id") or "")
        work_root = Path(str(params.get("work_root") or workspace / ".migration-work"))
        session = CheckpointStore(work_root).load(session_id)
        report_path = work_root / session_id / session.artifacts.get("migration_review", "migration-review.json")
        report = _read_json(report_path)
        safe = {
            key: value for key, value in report.items()
            if "hash" not in key.lower() and "token" not in key.lower() and "credential" not in key.lower()
        }
        return {"contents": [{"uri": uri, "mimeType": "application/json", "text": json.dumps(safe, indent=2, sort_keys=True)}]}
    raise ValueError("unknown migration resource")


def _dispatch(request: dict[str, Any]) -> dict[str, Any] | None:
    request_id = request.get("id")
    method = request.get("method")
    params = request.get("params") if isinstance(request.get("params"), dict) else {}
    if method == "notifications/initialized":
        return None
    try:
        if method == "initialize":
            result = {
                "protocolVersion": params.get("protocolVersion", "2025-06-18"),
                "capabilities": {"tools": {}, "resources": {}},
                "serverInfo": {"name": "observability-migration-actions", "version": "1.0.0"},
            }
        elif method == "tools/list":
            result = {"tools": _tool_definitions()}
        elif method == "tools/call":
            name = params.get("name")
            arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
            if name not in TOOLS:
                raise ValueError("unknown migration action")
            result = TOOLS[name](arguments)
        elif method == "resources/list":
            result = {"resources": _resources(Path.cwd())}
        elif method == "resources/read":
            result = _read_resource(str(params.get("uri") or ""), params)
        else:
            raise ValueError("method not found")
        return {"jsonrpc": "2.0", "id": request_id, "result": result}
    except Exception as exc:
        return {
            "jsonrpc": "2.0", "id": request_id,
            "error": {"code": -32000, "message": str(exc)[:1000]},
        }


def main() -> int:
    for line in sys.stdin:
        try:
            request = json.loads(line)
            if not isinstance(request, dict):
                raise ValueError("request must be an object")
            response = _dispatch(request)
        except Exception as exc:
            response = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": str(exc)[:1000]}}
        if response is not None:
            print(json.dumps(response, separators=(",", ":")), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
