#!/usr/bin/env python3
"""Compile and run all migration adapters behind one bundle and one apply approval."""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import math
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
SKILLS = HERE.parents[1]
ASSESSMENT = SKILLS / "observability-migration-assessment" / "scripts"
DETECTOR = SKILLS / "observability-migration-executor" / "scripts"
SLO = SKILLS / "observability-migration-slo-executor" / "scripts"
DASHBOARD = SKILLS / "observability-migration-dashboard-executor" / "scripts"
sys.path[:0] = [str(ASSESSMENT), str(DETECTOR), str(SLO), str(DASHBOARD)]

from assessment_core.config import parse_dotenv, select_splunk_o11y_credentials  # noqa: E402
from assessment_core.security import pseudonym  # noqa: E402
from dashboard_migration import SplunkClient, prepare_preview, session_paths  # noqa: E402
from execution_core.adapter import SplunkDetectorClient  # noqa: E402
from execution_core.common import resolve_splunk_origin, value_hash  # noqa: E402
from execution_core.provenance import load_approved_plan, load_phase_one_inventory  # noqa: E402
from execution_core.translation import translate_allowlisted_monitor  # noqa: E402
from migration_execution import command_auto_seal as auto_seal_detector_wave  # noqa: E402
from slo_adapter import SplunkSloClient  # noqa: E402
from slo_execution import command_auto_seal as auto_seal_slo_wave  # noqa: E402
from slo_translation import translate_slo_bundle  # noqa: E402

from orchestration_core.approval import create_apply_approval, validate_apply_approval  # noqa: E402
from orchestration_core.browser_evidence import build_browser_draft, seal_browser_evidence  # noqa: E402
from orchestration_core.bridges import DashboardSessionBridge, DetectorWaveBridge, SloWaveBridge  # noqa: E402
from orchestration_core.bundle import validate_bundle  # noqa: E402
from orchestration_core.common import (  # noqa: E402
    atomic_write_json, canonical_hash, read_private_json, runtime_directory,
)
from orchestration_core.legacy_bundle import compile_legacy_bundle, preflight_bundle  # noqa: E402
from orchestration_core.scheduler import AdapterRegistry, MigrationScheduler, SchedulerPolicy  # noqa: E402
from orchestration_core.state import UnifiedStore  # noqa: E402


def target_clients(env_file: Path) -> tuple[dict[str, str], SplunkDetectorClient, SplunkSloClient, SplunkClient]:
    values = parse_dotenv(env_file)
    token, realm = select_splunk_o11y_credentials(values)
    if not token or not realm:
        raise ValueError("complete Splunk Observability credentials are required")
    origin = resolve_splunk_origin(realm)
    detector = SplunkDetectorClient(origin, token)
    organization = detector.get_organization_id()
    configured = values.get("SPLUNK_O11Y_ORG_ID")
    if configured and configured != organization:
        raise ValueError("configured organization differs from authenticated organization")
    target = {"origin": origin, "organization_id_hash": value_hash(organization)}
    return target, detector, SplunkSloClient(origin, token), SplunkClient(origin, token)


def registry(
    work_root: Path, session_id: str, detector: SplunkDetectorClient,
    slo: SplunkSloClient, dashboard: SplunkClient,
) -> AdapterRegistry:
    result = AdapterRegistry()
    result.register("detector-wave-v1", DetectorWaveBridge(work_root, session_id, detector))
    result.register("slo-wave-v1", SloWaveBridge(work_root, session_id, slo))
    result.register("dashboard-session-v1", DashboardSessionBridge(work_root, session_id, dashboard))
    return result


def paths(work_root: Path, session_id: str) -> tuple[Path, Path]:
    directory = runtime_directory(work_root, session_id)
    return directory / "execution-bundle.local.json", directory / "apply-approval.local.json"


def prepare_adapter_artifacts(work_root: Path, session_id: str) -> dict[str, int]:
    """Compile every registered source object without exposing legacy waves to the customer."""
    provenance = load_approved_plan(work_root, session_id)
    inventory, _binding = load_phase_one_inventory(provenance)
    salt = provenance["session"].local_pseudonym_salt
    monitors = inventory.get("inventory", {}).get("monitors", [])
    detector_refs = {
        pseudonym(f"monitor:{item['source_id']}", salt)
        for item in monitors
        if isinstance(item, dict)
        and item.get("source_id") is not None
        and translate_allowlisted_monitor(
            item, pseudonym(f"monitor:{item['source_id']}", salt),
        ) is not None
    }
    wave_count = math.ceil(len(detector_refs) / 10)
    with contextlib.redirect_stdout(io.StringIO()):
        for index in range(1, wave_count + 1):
            remaining = len(detector_refs) - 10 * (index - 1)
            auto_seal_detector_wave(argparse.Namespace(
                session_id=session_id,
                wave_id=f"wave-{index:03d}",
                work_root=str(work_root),
                max_creates=min(10, remaining),
            ))
        has_slo = translate_slo_bundle(inventory, salt) is not None
        if has_slo:
            auto_seal_slo_wave(argparse.Namespace(
                session_id=session_id,
                wave_id="slo-wave-001",
                work_root=str(work_root),
            ))
        dashboard_preview = prepare_preview(session_paths(work_root, session_id))
    sealed_refs: set[str] = set()
    execution_root = Path(provenance["session_directory"]) / "execution"
    for path in sorted(execution_root.glob("wave-*/translation-manifest.local.json")):
        manifest = read_private_json(path)
        sealed_refs.update(str(entry["object_ref"]) for entry in manifest["entries"])
    if sealed_refs != detector_refs:
        raise ValueError("compiled detector waves do not cover the complete translatable scope exactly once")
    return {
        "detectors": len(detector_refs),
        "detector_waves": wave_count,
        "slos": int(has_slo),
        "dashboards": len(dashboard_preview["dashboards"]),
        "charts": sum(len(item["charts"]) for item in dashboard_preview["dashboards"]),
    }


def bundle_summary(bundle: dict[str, Any]) -> dict[str, Any]:
    return {
        "session_id": bundle["session_id"], "plan_hash": bundle["plan_hash"],
        "bundle_hash": bundle["bundle_hash"], "target_origin": bundle["target_binding"]["origin"],
        "operation_count": len(bundle["operations"]),
        "actions": dict(sorted(Counter(item["action"] for item in bundle["operations"]).items())),
        "adapters": dict(sorted(Counter(item["adapter"] for item in bundle["operations"]).items())),
    }


def sanitized_status(checkpoint: dict[str, Any]) -> dict[str, Any]:
    states = Counter(item["status"] for item in checkpoint["operations"].values())
    return {
        "session_id": checkpoint["session_id"], "bundle_hash": checkpoint["bundle_hash"],
        "status": checkpoint["status"], "operation_states": dict(sorted(states.items())),
        "resource_count": sum(len(item["resources"]) for item in checkpoint["operations"].values()),
    }


def consume_interactive_apply_receipt(
    receipt_path: Path, work_root: Path, session_id: str, bundle_hash: str,
) -> Path:
    directory = runtime_directory(work_root, session_id)
    expected = directory / "interactive-apply-approval.used.local.json"
    if receipt_path.resolve() != expected.resolve() or receipt_path.is_symlink():
        raise ValueError("apply requires the exact interactive approval receipt")
    receipt = read_private_json(receipt_path, max_bytes=10_000)
    required = {
        "schema_version", "approval_kind", "session_id", "bound_hash", "approved_at",
        "expires_at", "approval_channel", "user_confirmed", "receipt_hash",
    }
    if set(receipt) != required or receipt.get("receipt_hash") != canonical_hash(receipt, "receipt_hash"):
        raise ValueError("interactive apply approval receipt is invalid")
    if (
        receipt.get("schema_version") != "1.0"
        or receipt.get("approval_kind") != "apply"
        or receipt.get("session_id") != session_id
        or receipt.get("bound_hash") != bundle_hash
        or receipt.get("approval_channel") != "native_codex_tool_confirmation"
        or receipt.get("user_confirmed") is not True
    ):
        raise ValueError("interactive apply approval receipt binding mismatch")
    try:
        approved_at = datetime.fromisoformat(str(receipt["approved_at"]))
        expires_at = datetime.fromisoformat(str(receipt["expires_at"]))
    except ValueError as exc:
        raise ValueError("interactive apply approval receipt timestamp is invalid") from exc
    now = datetime.now(timezone.utc)
    if (
        approved_at.tzinfo is None or expires_at.tzinfo is None
        or approved_at > now or expires_at <= now
        or expires_at - approved_at > timedelta(minutes=5, seconds=5)
    ):
        raise ValueError("interactive apply approval receipt is expired or invalid")
    consumed = directory / "interactive-apply-approval.consumed.local.json"
    receipt_path.replace(consumed)
    return consumed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in (
        "compile", "apply", "execute", "browser-template",
        "seal-browser-validation", "status", "rollback",
    ):
        command = commands.add_parser(name)
        command.add_argument("--session-id", required=True)
        command.add_argument("--work-root", default=".migration-work")
        if name in {"compile", "apply", "execute", "rollback"}:
            command.add_argument("--env-file", default=".env")
        if name == "apply":
            command.add_argument("--approval-receipt", required=True)
        if name == "rollback":
            command.add_argument("--confirm-rollback", action="store_true")
        if name in {"apply", "execute"}:
            command.add_argument("--max-workers", type=int, default=4)
            command.add_argument("--max-attempts", type=int, default=3)
            command.add_argument("--retry-delay-seconds", type=float, default=0.25)
            command.add_argument("--minimum-interval-seconds", type=float, default=0.05)
        if name == "seal-browser-validation":
            command.add_argument("--input")
    args = parser.parse_args()
    work_root = Path(args.work_root)
    bundle_path, approval_path = paths(work_root, args.session_id)
    clients: tuple[
        dict[str, str], SplunkDetectorClient, SplunkSloClient, SplunkClient,
    ] | None = None

    def get_clients() -> tuple[
        dict[str, str], SplunkDetectorClient, SplunkSloClient, SplunkClient,
    ]:
        nonlocal clients
        if clients is None:
            clients = target_clients(Path(args.env_file))
        return clients

    if args.command == "compile":
        prepared = prepare_adapter_artifacts(work_root, args.session_id)
        target, detector, slo, dashboard = get_clients()
        bundle = compile_legacy_bundle(work_root, args.session_id, target)
        adapters = registry(work_root, args.session_id, detector, slo, dashboard)
        bundle = preflight_bundle(bundle, adapters)
        atomic_write_json(bundle_path, bundle)
        print(json.dumps({
            **bundle_summary(bundle), "prepared_resources": prepared,
            "external_mutations_performed": 0,
        }, indent=2, sort_keys=True))
        return 0

    bundle = validate_bundle(read_private_json(bundle_path))
    if args.command == "apply":
        consume_interactive_apply_receipt(
            Path(args.approval_receipt), work_root, args.session_id, str(bundle["bundle_hash"]),
        )
        approval = create_apply_approval(bundle)
        atomic_write_json(approval_path, approval)
    if args.command in {"browser-template", "seal-browser-validation"}:
        dashboard_root = work_root.resolve() / args.session_id / "dashboard-execution"
        result = read_private_json(dashboard_root / "dashboard-result.local.json", max_bytes=25_000_000)
        draft_path = dashboard_root / "browser-validation.draft.local.json"
        evidence_path = dashboard_root / "browser-validation.local.json"
        if args.command == "browser-template":
            draft = build_browser_draft(result)
            atomic_write_json(draft_path, draft)
            print(json.dumps({
                "draft": str(draft_path), "dashboard_count": len(draft["dashboards"]),
                "external_mutations_performed": 0,
            }, indent=2, sort_keys=True))
            return 0
        draft = read_private_json(Path(args.input) if args.input else draft_path)
        evidence = seal_browser_evidence(result, draft)
        atomic_write_json(evidence_path, evidence)
        print(json.dumps({
            "evidence": str(evidence_path), "evidence_hash": evidence["evidence_hash"],
            "validated_dashboards": len(evidence["dashboards"]), "external_mutations_performed": 0,
        }, indent=2, sort_keys=True))
        return 0
    if args.command == "status":
        print(json.dumps(sanitized_status(UnifiedStore(work_root, args.session_id).load_checkpoint()), indent=2, sort_keys=True))
        return 0

    target, detector, slo, dashboard = get_clients()
    adapters = registry(work_root, args.session_id, detector, slo, dashboard)
    scheduler = MigrationScheduler(
        work_root, adapters,
        SchedulerPolicy(
            max_workers=getattr(args, "max_workers", 4),
            max_attempts=getattr(args, "max_attempts", 3),
            retry_delay_seconds=getattr(args, "retry_delay_seconds", 0.25),
            minimum_interval_seconds=getattr(args, "minimum_interval_seconds", 0.05),
        ),
    )
    if args.command in {"apply", "execute"}:
        approval = validate_apply_approval(read_private_json(approval_path), bundle, target)
        checkpoint = scheduler.run(bundle, approval, target)
    else:
        checkpoint = scheduler.rollback(bundle, target, confirmed=args.confirm_rollback)
    output = sanitized_status(checkpoint)
    if args.command == "apply":
        output["apply_authorization_hash"] = approval["approval_hash"]
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
