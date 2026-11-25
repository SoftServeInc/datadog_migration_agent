#!/usr/bin/env python3
"""Prepare a secure, local, read-only observability migration assessment."""

from __future__ import annotations

import argparse
import json
import secrets
from pathlib import Path
from typing import Any

from assessment_core.approval import (
    create_read_authorization,
    load_authorization,
    public_authorization_summary,
    write_authorization,
)
from assessment_core.audit import append_audit_event
from assessment_core.capabilities import build_capability_catalog
from assessment_core.config import authorization_origins, merged_environment, provider_preflight
from assessment_core.ir import build_inventory_ir
from assessment_core.live_preflight import run_live_preflight
from assessment_core.model import SessionState
from assessment_core.plan_approval import create_plan_review_approval, write_plan_review_approval
from assessment_core.planner import build_plan_from_assessment, validate_migration_plan
from assessment_core.report import build_assessment, markdown_report, validate_assessment
from assessment_core.rules import load_rules
from assessment_core.security import atomic_write, atomic_write_json, codex_projection, ensure_private_directory
from assessment_core.state import CheckpointStore, Session


SOURCE_OBJECT_KEYS = (
    "dashboards", "monitors", "slos", "synthetics", "log_indexes", "log_pipelines"
)


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected a JSON object: {path}")
    return value


def load_preflight(env_file: str) -> dict[str, object]:
    path = Path(env_file).expanduser() if env_file else None
    if path and not path.is_file():
        raise ValueError(f"environment file not found: {path}")
    return provider_preflight(merged_environment(path))


def command_preflight(args: argparse.Namespace) -> int:
    print(json.dumps(load_preflight(args.env_file), indent=2, sort_keys=True))
    return 0


def command_authorize(args: argparse.Namespace) -> int:
    if not args.confirm_read_only:
        raise ValueError("explicit --confirm-read-only is required")
    env_path = Path(args.env_file).expanduser() if args.env_file else None
    if env_path and not env_path.is_file():
        raise ValueError(f"environment file not found: {env_path}")
    values = merged_environment(env_path)
    store = CheckpointStore(Path(args.work_root))
    requested_session_id = getattr(args, "session_id", "")
    if requested_session_id:
        directory = store.session_directory(requested_session_id)
        checkpoint_path = directory / "checkpoint.local.json"
    else:
        directory = None
        checkpoint_path = None
    if checkpoint_path is not None and checkpoint_path.is_file():
        session = store.load(requested_session_id)
        if session.target != args.target:
            raise ValueError(f"session target is already fixed to {session.target}")
        if session.workflow_state != SessionState.DISCOVERY.value or session.discovery_started_at:
            raise ValueError(
                "INVALID_WORKFLOW_TRANSITION: discovery authorization cannot reopen discovery"
            )
    else:
        session = Session.create(requested_session_id or None)
        directory = store.session_directory(session.session_id)
        session.target = args.target
        preflight_path = directory / "preflight.json"
        atomic_write_json(preflight_path, provider_preflight(values))
        session.artifacts["preflight"] = preflight_path.name
        store.save(session)
    origins = authorization_origins(values)
    if args.target != "both":
        origins = {key: value for key, value in origins.items() if key in {"datadog", args.target}}
    record = create_read_authorization(
        session_id=session.session_id,
        actor_role=args.actor_role,
        target=args.target,
        ttl_minutes=args.ttl_minutes,
        include_cost_read=args.include_cost_read,
        authorized_origins=origins,
    )
    path = directory / "authorization.local.json"
    write_authorization(path, record)
    summary_path = directory / "authorization-summary.json"
    atomic_write_json(summary_path, public_authorization_summary(record))
    session.artifacts["authorization"] = path.name
    session.artifacts["authorization_summary"] = summary_path.name
    session.approval_ids.append(str(record["approval_id"]))
    session.last_event = "Read-only discovery authorization recorded"
    store.save(session)
    append_audit_event(
        directory / "audit.local.jsonl",
        "authorization_granted",
        "approved",
        session.session_id,
        str(record["approval_id"]),
    )
    print(json.dumps({
        "session_id": session.session_id,
        "authorization_file": str(path.resolve()),
        "authorization_summary": str(summary_path.resolve()),
        "approval_id": record["approval_id"],
        "approval_hash": record["approval_hash"],
        "access_mode": "read_only",
        "expires_at": record["expires_at"],
        "external_mutations_authorized": False,
        "cost_read_authorized": "billing_and_usage" in record["data_categories"],
        "workflow_state": session.workflow_state,
    }, indent=2, sort_keys=True))
    return 0


def command_live_preflight(args: argparse.Namespace) -> int:
    authorization_path = Path(args.authorization_file).expanduser()
    authorization = load_authorization(authorization_path, "LIVE_PREFLIGHT")
    session_id = str(authorization["session_id"])
    if authorization_path.parent.name != session_id:
        raise ValueError("authorization file is not inside its bound session directory")
    store = CheckpointStore(authorization_path.parent.parent)
    session = store.load(session_id)
    if str(authorization["approval_id"]) not in session.approval_ids:
        raise ValueError("authorization is not registered in the session checkpoint")
    if session.workflow_state != SessionState.DISCOVERY.value:
        raise ValueError(
            f"INVALID_WORKFLOW_TRANSITION: {session.workflow_state} does not permit live preflight"
        )
    env_path = Path(args.env_file).expanduser() if args.env_file else None
    if env_path and not env_path.is_file():
        raise ValueError(f"environment file not found: {env_path}")
    values = merged_environment(env_path)
    live = run_live_preflight(values, authorization, timeout=args.timeout)
    offline = provider_preflight(values)
    catalog = build_capability_catalog(offline, live)
    output = ensure_private_directory(Path(args.output_dir) if args.output_dir else authorization_path.parent)
    live_path = output / "live-preflight.json"
    catalog_path = output / "capability-catalog.json"
    atomic_write_json(live_path, live)
    atomic_write_json(catalog_path, catalog)
    outcome = "success" if all(
        item.get("status") in {"available", "not_selected"}
        for item in live["providers"].values()
    ) else "partial"
    append_audit_event(
        authorization_path.parent / "audit.local.jsonl",
        "live_preflight_completed",
        outcome,
        str(authorization["session_id"]),
        str(authorization["approval_id"]),
        {"requests_attempted": int(live["requests_attempted"])},
    )
    append_audit_event(
        authorization_path.parent / "audit.local.jsonl",
        "capability_catalog_generated",
        "success",
        str(authorization["session_id"]),
        str(authorization["approval_id"]),
    )
    print(json.dumps({
        "live_preflight": str(live_path.resolve()),
        "capability_catalog": str(catalog_path.resolve()),
        "requests_attempted": live["requests_attempted"],
        "provider_status": {key: value["status"] for key, value in live["providers"].items()},
        "mutations_performed": 0,
    }, indent=2, sort_keys=True))
    return 0


def command_sanitize(args: argparse.Namespace) -> int:
    projection = codex_projection(read_json(Path(args.input)), secrets.token_hex(32))
    atomic_write_json(Path(args.output), projection)
    print(f"Wrote Codex-safe projection: {Path(args.output).resolve()}")
    return 0


def command_normalize(args: argparse.Namespace) -> int:
    inventory = read_json(Path(args.inventory))
    output = ensure_private_directory(Path(args.output_dir))
    state_path = output / "normalization-state.local.json"
    if state_path.is_symlink():
        raise ValueError("refusing symlink normalization state")
    if state_path.is_file():
        state = read_json(state_path)
        if set(state) != {"schema_version", "local_pseudonym_salt"}:
            raise ValueError("normalization state fields are invalid")
        salt = str(state.get("local_pseudonym_salt", ""))
        if state.get("schema_version") != "1.0" or len(salt) != 64 or any(
            value not in "0123456789abcdef" for value in salt
        ):
            raise ValueError("normalization state is invalid")
    else:
        salt = secrets.token_hex(32)
        atomic_write_json(state_path, {
            "schema_version": "1.0",
            "local_pseudonym_salt": salt,
        })
    projection = codex_projection(inventory, salt)
    inventory_ir = build_inventory_ir(inventory, salt)
    projection_path = output / "codex-context.json"
    ir_path = output / "inventory-ir.json"
    atomic_write_json(projection_path, projection)
    atomic_write_json(ir_path, inventory_ir)
    print(json.dumps({
        "codex_context": str(projection_path.resolve()),
        "inventory_ir": str(ir_path.resolve()),
        "normalization_state": str(state_path.resolve()),
        "raw_identifiers_in_outputs": False,
        "external_mutations_performed": 0,
    }, indent=2, sort_keys=True))
    return 0


def command_assess(args: argparse.Namespace) -> int:
    inventory_ir = read_json(Path(args.inventory_ir))
    preflight = load_preflight(args.env_file)
    catalog = (
        read_json(Path(args.capability_catalog))
        if args.capability_catalog else build_capability_catalog(preflight)
    )
    assessment = build_assessment(inventory_ir, catalog, args.target, load_rules())
    output = ensure_private_directory(Path(args.output_dir))
    json_path = output / "discovery-report.json"
    markdown_path = output / "discovery-report.md"
    atomic_write_json(json_path, assessment)
    atomic_write(markdown_path, markdown_report(assessment))
    print(json.dumps({
        "discovery_report_json": str(json_path.resolve()),
        "discovery_report_markdown": str(markdown_path.resolve()),
        "assessment_hash": assessment["assessment_hash"],
        "external_mutations_performed": 0,
    }, indent=2, sort_keys=True))
    return 0


def command_plan(args: argparse.Namespace) -> int:
    source = read_json(Path(args.input))
    if "assessment_hash" not in source or "actions" not in source:
        raise ValueError("plan requires a sanitized discovery assessment")
    plan = build_plan_from_assessment(source, args.strategy, args.select_ref)
    atomic_write_json(Path(args.output), plan)
    print(f"Wrote non-executable dry-run plan: {Path(args.output).resolve()}")
    print(f"Plan hash: {plan['plan_hash']}")
    return 0


def command_prepare(args: argparse.Namespace) -> int:
    preflight = load_preflight(args.env_file)
    inventory = read_json(Path(args.inventory))
    source_inventory = inventory.get("inventory")
    if not isinstance(source_inventory, dict):
        raise ValueError("inventory is missing source object collections")
    source_object_count = sum(
        len(source_inventory.get(key, []))
        for key in SOURCE_OBJECT_KEYS
        if isinstance(source_inventory.get(key, []), list)
    )
    if source_object_count == 0:
        if inventory.get("errors"):
            raise ValueError(
                "discovery returned zero source objects with endpoint errors; "
                "resolve source access and run a fresh assessment"
            )
        raise ValueError(
            "discovery found no source objects; no migration review can be created"
        )
    strategy = getattr(args, "strategy", "safe_staged")
    selected_refs = getattr(args, "select_ref", [])
    store = CheckpointStore(Path(args.work_root))
    existing_checkpoint = (
        store.session_directory(args.session_id) / "checkpoint.local.json"
        if args.session_id else None
    )
    if existing_checkpoint and existing_checkpoint.is_file():
        session = store.load(args.session_id)
        if session.target != args.target:
            raise ValueError(f"assessment target is already fixed to {session.target}")
        if session.workflow_state != SessionState.DISCOVERY.value:
            if session.workflow_state in {
                SessionState.PLAN_REVIEW.value,
                SessionState.WAITING_PLAN_APPROVAL.value,
            }:
                directory = store.session_directory(session.session_id)
                projection_path = directory / "codex-context.json"
                ir_path = directory / "inventory-ir.json"
                assessment_path = directory / "discovery-report.json"
                report_path = directory / "discovery-report.md"
                plan_path = directory / "dry-run-plan.json"
                plan = read_json(plan_path)
                validate_migration_plan(plan)
                print(json.dumps({
                    "session": session.public_summary(),
                    "session_directory": str(directory.resolve()),
                    "codex_context": str(projection_path.resolve()),
                    "inventory_ir": str(ir_path.resolve()),
                    "discovery_report_json": str(assessment_path.resolve()),
                    "discovery_report_markdown": str(report_path.resolve()),
                    "dry_run_plan": str(plan_path.resolve()),
                }, indent=2, sort_keys=True))
                return 0
            raise ValueError(
                f"INVALID_WORKFLOW_TRANSITION: discovery cannot run from {session.workflow_state}"
            )
        if session.discovery_started_at and session.inventory_origin != "datadog_live_discovery":
            raise ValueError(
                "INVALID_WORKFLOW_TRANSITION: discovery may run only once per assessment"
            )
        if session.strategy and session.strategy != strategy:
            raise ValueError(f"assessment strategy is already fixed to {session.strategy}")
        if not session.strategy:
            session.strategy = strategy
    else:
        session = Session.create(args.session_id or None)
        session.target = args.target
        session.strategy = strategy
        session.discovery_started_at = session.created_at
    directory = store.session_directory(session.session_id)

    local_inventory_path = directory / "raw-inventory" / "datadog-estate.local.json"
    atomic_write_json(local_inventory_path, inventory)
    session.artifacts["local_inventory"] = "raw-inventory/datadog-estate.local.json"

    preflight_path = directory / "preflight.json"
    atomic_write_json(preflight_path, preflight)
    session.artifacts["preflight"] = preflight_path.name

    projection = codex_projection(inventory, session.local_pseudonym_salt)
    inventory_ir = build_inventory_ir(inventory, session.local_pseudonym_salt)
    projection_path = directory / "codex-context.json"
    ir_path = directory / "inventory-ir.json"
    atomic_write_json(projection_path, projection)
    atomic_write_json(ir_path, inventory_ir)
    session.artifacts["codex_context"] = projection_path.name
    session.artifacts["inventory_ir"] = ir_path.name
    if not session.inventory_origin:
        session.inventory_origin = "provided_local_file"

    catalog = (
        read_json(Path(args.capability_catalog))
        if args.capability_catalog else build_capability_catalog(preflight)
    )
    assessment = build_assessment(inventory_ir, catalog, args.target, load_rules())
    assessment_path = directory / "discovery-report.json"
    report_path = directory / "discovery-report.md"
    atomic_write_json(assessment_path, assessment)
    atomic_write(report_path, markdown_report(assessment))
    session.artifacts["discovery_report_json"] = assessment_path.name
    session.artifacts["discovery_report_markdown"] = report_path.name

    plan = build_plan_from_assessment(assessment, strategy, selected_refs)
    plan_path = directory / "dry-run-plan.json"
    atomic_write_json(plan_path, plan)
    session.artifacts["dry_run_plan"] = plan_path.name
    session.plan_hash = str(plan["plan_hash"])

    objects = inventory_ir.get("objects", [])
    session.resources_discovered = len(objects)
    session.dashboards_total = sum(
        isinstance(item, dict) and item.get("object_type") == "dashboard" for item in objects
    )
    session.monitors_total = sum(
        isinstance(item, dict) and item.get("object_type") == "monitor" for item in objects
    )
    session.queries_total = sum(
        int(item.get("behavior_features", {}).get("query_count", 0))
        for item in objects if isinstance(item, dict)
        and isinstance(item.get("behavior_features", {}), dict)
    )
    session.discovery_completed_at = session.updated_at
    session.last_event = "Discovery, analysis, and plan generation completed"
    if existing_checkpoint and existing_checkpoint.is_file():
        store.save(session)
    else:
        store.save(session)
    store.transition(
        session.session_id,
        SessionState.DISCOVERY,
        SessionState.PLAN_REVIEW,
        approval_status="NOT_REQUIRED",
        event="Discovery completed; migration plan is ready to review",
    )
    session = store.load(session.session_id)

    print(json.dumps({
        "session": session.public_summary(),
        "session_directory": str(directory.resolve()),
        "codex_context": str(projection_path.resolve()),
        "inventory_ir": str(ir_path.resolve()),
        "discovery_report_json": str(assessment_path.resolve()),
        "discovery_report_markdown": str(report_path.resolve()),
        "dry_run_plan": str(plan_path.resolve()),
    }, indent=2, sort_keys=True))
    return 0


def command_select_strategy(args: argparse.Namespace) -> int:
    """Replace the reviewed dry-run plan with a user-selected safe or full scope."""

    store = CheckpointStore(Path(args.work_root))
    session = store.load(args.session_id)
    if session.workflow_state != SessionState.PLAN_REVIEW.value:
        raise ValueError("strategy can be selected only during plan review")
    # Read-only discovery authorization is recorded in approval_ids, but it
    # must not lock the customer out of choosing a migration strategy. Only a
    # non-NOT_REQUIRED approval status means plan approval has begun.
    if session.approval_status != "NOT_REQUIRED":
        raise ValueError("strategy cannot change after plan approval begins")

    directory = store.session_directory(session.session_id)
    assessment_path = directory / session.artifacts.get(
        "discovery_report_json", "discovery-report.json"
    )
    assessment = read_json(assessment_path)
    validate_assessment(assessment)
    plan = build_plan_from_assessment(assessment, args.strategy)
    validate_migration_plan(plan)

    plan_path = directory / session.artifacts.get("dry_run_plan", "dry-run-plan.json")
    atomic_write_json(plan_path, plan)
    session.strategy = args.strategy
    session.plan_hash = str(plan["plan_hash"])
    session.last_event = f"Migration plan strategy selected: {args.strategy}"
    store.save(session)

    summary = plan.get("summary") if isinstance(plan.get("summary"), dict) else {}
    print(json.dumps({
        "strategy": args.strategy,
        "selected_action_count": int(summary.get("selected_action_count") or 0),
        "manual_or_deferred_count": int(summary.get("manual_or_deferred_count") or 0),
        "unresolved_dependency_count": int(summary.get("unresolved_dependency_count") or 0),
        "external_mutations_performed": 0,
    }, indent=2, sort_keys=True))
    return 0


def command_approve_plan(args: argparse.Namespace) -> int:
    if not args.confirm_plan_review:
        raise ValueError("explicit --confirm-plan-review is required")
    store = CheckpointStore(Path(args.work_root))
    session = store.load(args.session_id)
    if session.workflow_state == SessionState.PLAN_REVIEW.value:
        session = store.transition(
            session.session_id,
            SessionState.PLAN_REVIEW,
            SessionState.WAITING_PLAN_APPROVAL,
            approval_status="WAITING_PLAN_APPROVAL",
            event="Plan review opened from CLI",
        )
    if session.workflow_state != SessionState.WAITING_PLAN_APPROVAL.value:
        raise ValueError(
            f"assessment state {session.workflow_state} cannot accept plan review approval"
        )
    directory = store.session_directory(session.session_id)
    plan_path = directory / session.artifacts.get("dry_run_plan", "dry-run-plan.json")
    assessment_path = directory / session.artifacts.get("discovery_report_json", "discovery-report.json")
    plan = read_json(plan_path)
    assessment = read_json(assessment_path)
    validate_assessment(assessment)
    validate_migration_plan(plan)
    if plan.get("plan_hash") != session.plan_hash:
        raise ValueError("reviewed plan hash does not match the checkpoint")
    if plan.get("assessment_hash") != assessment.get("assessment_hash"):
        raise ValueError("reviewed plan is not bound to the stored assessment")
    if plan.get("strategy") != session.strategy:
        raise ValueError("reviewed plan strategy does not match the checkpoint")
    record = create_plan_review_approval(
        session.session_id,
        args.actor_role,
        str(plan["plan_hash"]),
        str(assessment["assessment_hash"]),
        session.strategy,
    )
    approval_path = directory / "plan-review-approval.local.json"
    write_plan_review_approval(approval_path, record)
    session.artifacts["plan_review_approval"] = approval_path.name
    session.approval_ids.append(str(record["approval_id"]))
    store.save(session)
    session = store.transition(
        session.session_id,
        SessionState.WAITING_PLAN_APPROVAL,
        SessionState.MIGRATING,
        approval_status="PLAN_APPROVED",
        event="PLAN_APPROVED",
    )
    append_audit_event(
        directory / "audit.local.jsonl",
        "plan_review_approved",
        "approved",
        session.session_id,
        str(record["approval_id"]),
        {"reviewed_steps": len(plan.get("steps", []))},
    )
    print(json.dumps({
        "approval_file": str(approval_path.resolve()),
        "approval_id": record["approval_id"],
        "plan_hash": plan["plan_hash"],
        "workflow_state": session.workflow_state,
        "execution_authorized": False,
        "external_mutations_authorized": False,
    }, indent=2, sort_keys=True))
    return 0


def command_cleanup_session(args: argparse.Namespace) -> int:
    if not args.confirm_cleanup:
        raise ValueError("explicit --confirm-cleanup is required")
    store = CheckpointStore(Path(args.work_root))
    removed = store.delete(args.session_id)
    print(json.dumps({
        "session_id": args.session_id,
        "removed_directory": str(removed),
        "recoverable_from_application": False,
        "secure_media_erasure_guaranteed": False,
        "note": "Filesystem deletion cannot guarantee physical erasure on SSDs or backups.",
    }, indent=2, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    preflight = commands.add_parser("preflight", help="check configured provider access without network calls")
    preflight.add_argument("--env-file", default="")
    preflight.set_defaults(handler=command_preflight)

    authorize = commands.add_parser("authorize-read-only", help="create a time-limited read-only approval")
    authorize.add_argument(
        "--session-id",
        default="",
        help="existing session to resume; omit for a collision-safe new session",
    )
    authorize.add_argument("--work-root", default=".migration-work")
    authorize.add_argument("--env-file", default="")
    authorize.add_argument("--actor-role", choices=("customer", "authorized_operator"), required=True)
    authorize.add_argument("--target", choices=("splunk_observability_cloud", "splunk_platform", "both"), default="both")
    authorize.add_argument("--ttl-minutes", type=int, default=60)
    authorize.add_argument("--include-cost-read", action="store_true")
    authorize.add_argument("--confirm-read-only", action="store_true")
    authorize.set_defaults(handler=command_authorize)

    live = commands.add_parser("live-preflight", help="run approved bounded GET authentication probes")
    live.add_argument("--authorization-file", required=True)
    live.add_argument("--env-file", default="")
    live.add_argument("--output-dir", default="")
    live.add_argument("--timeout", type=int, default=10)
    live.set_defaults(handler=command_live_preflight)

    sanitize = commands.add_parser("sanitize", help="create a strict Codex-safe projection")
    sanitize.add_argument("--input", required=True)
    sanitize.add_argument("--output", required=True)
    sanitize.set_defaults(handler=command_sanitize)

    normalize = commands.add_parser(
        "normalize-inventory", help="create a stable pseudonymous projection and vendor-neutral IR"
    )
    normalize.add_argument("--inventory", required=True)
    normalize.add_argument("--output-dir", required=True)
    normalize.set_defaults(handler=command_normalize)

    assess = commands.add_parser(
        "assess-compatibility", help="classify a privacy-safe IR and generate discovery reports"
    )
    assess.add_argument("--inventory-ir", required=True)
    assess.add_argument("--output-dir", required=True)
    assess.add_argument("--env-file", default="")
    assess.add_argument("--capability-catalog", default="")
    assess.add_argument(
        "--target",
        choices=("splunk_observability_cloud", "splunk_platform", "both"),
        default="both",
    )
    assess.set_defaults(handler=command_assess)

    plan = commands.add_parser("plan", help="create a non-executable dry-run plan")
    plan.add_argument("--input", required=True, help="sanitized discovery assessment JSON")
    plan.add_argument("--output", required=True)
    plan.add_argument("--strategy", choices=("full", "safe_staged", "customer_selected"), default="safe_staged")
    plan.add_argument("--select-ref", action="append", default=[])
    plan.set_defaults(handler=command_plan)

    prepare = commands.add_parser("prepare", help="create a resumable local assessment session")
    prepare.add_argument("--inventory", required=True, help="local normalized inventory JSON")
    prepare.add_argument("--env-file", default="")
    prepare.add_argument("--capability-catalog", default="")
    prepare.add_argument("--work-root", default=".migration-work")
    prepare.add_argument("--session-id", default="")
    prepare.add_argument("--target", choices=("splunk_observability_cloud", "splunk_platform", "both"), default="both")
    prepare.add_argument("--strategy", choices=("full", "safe_staged", "customer_selected"), default="safe_staged")
    prepare.add_argument("--select-ref", action="append", default=[])
    prepare.set_defaults(handler=command_prepare)

    select_strategy = commands.add_parser(
        "select-strategy", help="select safe_staged or full scope after reviewing the assessment"
    )
    select_strategy.add_argument("--session-id", required=True)
    select_strategy.add_argument("--work-root", default=".migration-work")
    select_strategy.add_argument("--strategy", choices=("full", "safe_staged"), required=True)
    select_strategy.set_defaults(handler=command_select_strategy)

    approve_plan = commands.add_parser(
        "approve-plan", help="approve review of a hash-bound dry-run plan without authorizing execution"
    )
    approve_plan.add_argument("--session-id", required=True)
    approve_plan.add_argument("--work-root", default=".migration-work")
    approve_plan.add_argument("--actor-role", choices=("customer", "authorized_operator"), required=True)
    approve_plan.add_argument("--confirm-plan-review", action="store_true")
    approve_plan.set_defaults(handler=command_approve_plan)

    cleanup = commands.add_parser(
        "cleanup-session", help="delete one confirmed local session directory"
    )
    cleanup.add_argument("--session-id", required=True)
    cleanup.add_argument("--work-root", default=".migration-work")
    cleanup.add_argument("--confirm-cleanup", action="store_true")
    cleanup.set_defaults(handler=command_cleanup_session)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    return int(args.handler(args))


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
    except Exception as exc:
        print(f"ERROR: {exc}", file=__import__("sys").stderr)
        raise SystemExit(1)
