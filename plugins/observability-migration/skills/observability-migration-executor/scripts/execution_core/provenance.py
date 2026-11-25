"""Validate the immutable Phase 1 provenance required by the write-side workflow."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from assessment_core.plan_approval import validate_plan_review_approval
from assessment_core.ir import build_inventory_ir, validate_inventory_ir
from assessment_core.planner import validate_migration_plan
from assessment_core.state import CheckpointStore

from .common import read_private_json, value_hash


def load_approved_plan(work_root: Path, session_id: str) -> dict[str, Any]:
    store = CheckpointStore(work_root)
    session = store.load(session_id)
    # The customer-facing state machine persists MIGRATING immediately after the
    # approval transaction. PLAN_APPROVED is approval evidence, not a persisted
    # workflow value (the enum keeps it only as a compatibility alias).
    if (
        session.state != "MIGRATING"
        or session.approval_status != "PLAN_APPROVED"
        or session.mutations_performed != 0
    ):
        raise ValueError(
            "Phase 1 session must be MIGRATING with persisted PLAN_APPROVED evidence "
            "and zero mutations"
        )
    directory = store.session_directory(session_id)
    plan_name = session.artifacts.get("plan") or "dry-run-plan.json"
    approval_name = session.artifacts.get("plan_review_approval")
    if not approval_name:
        raise ValueError("Phase 1 plan-review approval artifact is missing")
    plan = read_private_json(directory / plan_name)
    approval = read_private_json(directory / approval_name)
    validate_migration_plan(plan)
    validate_plan_review_approval(approval)
    if plan["plan_hash"] != session.plan_hash or approval["plan_hash"] != plan["plan_hash"]:
        raise ValueError("Phase 1 plan hash does not match checkpoint and approval")
    if approval["assessment_hash"] != plan["assessment_hash"]:
        raise ValueError("Phase 1 assessment hash does not match approval")
    if approval["session_id"] != session_id or approval["approval_id"] not in session.approval_ids:
        raise ValueError("Phase 1 approval is not bound to this session")
    if approval["execution_authorized"] or approval["external_mutations_authorized"]:
        raise ValueError("Phase 1 review approval must not authorize execution")
    return {
        "session": session,
        "session_directory": directory,
        "plan": plan,
        "plan_review_approval": approval,
    }


def load_phase_one_inventory(provenance: dict[str, Any]) -> tuple[dict[str, Any], dict[str, str]]:
    """Load only the inventory recorded by Phase 1 and prove its IR is unchanged."""
    session = provenance["session"]
    directory = Path(provenance["session_directory"]).resolve(strict=True)
    inventory_name = session.artifacts.get("local_inventory")
    ir_name = session.artifacts.get("inventory_ir")
    if not inventory_name or not ir_name:
        raise ValueError("Phase 1 did not record a reusable local inventory and IR")
    inventory_path = Path(inventory_name)
    if not inventory_path.is_absolute():
        inventory_path = directory / inventory_path
    inventory_path = inventory_path.resolve(strict=True)
    ir_path = (directory / Path(ir_name).name).resolve(strict=True)
    if directory not in inventory_path.parents or ir_path.parent != directory:
        raise ValueError("Phase 1 inventory provenance escapes the approved session")
    inventory = read_private_json(inventory_path, max_bytes=20_000_000)
    stored_ir = read_private_json(ir_path, max_bytes=20_000_000)
    validate_inventory_ir(stored_ir)
    rebuilt_ir = build_inventory_ir(inventory, session.local_pseudonym_salt)
    if rebuilt_ir != stored_ir:
        raise ValueError("Phase 1 local inventory no longer matches its approved inventory IR")
    return inventory, {
        "binding_method": "phase1_local_inventory_ir_rebuild_v1",
        "inventory_hash": value_hash(inventory),
        "inventory_ir_hash": value_hash(stored_ir),
    }


__all__ = ["load_approved_plan", "load_phase_one_inventory"]
