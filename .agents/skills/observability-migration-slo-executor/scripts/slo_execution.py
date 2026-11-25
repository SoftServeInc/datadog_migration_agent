#!/usr/bin/env python3
"""CLI for bounded create-only Splunk Observability Cloud SLO waves."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
SKILLS = HERE.parents[1]
ASSESSMENT_SCRIPTS = SKILLS / "observability-migration-assessment" / "scripts"
DETECTOR_SCRIPTS = SKILLS / "observability-migration-executor" / "scripts"
sys.path.insert(0, str(ASSESSMENT_SCRIPTS))
sys.path.insert(0, str(DETECTOR_SCRIPTS))
sys.path.insert(0, str(HERE))

from assessment_core.config import parse_dotenv, select_splunk_o11y_credentials  # noqa: E402
from execution_core.provenance import load_approved_plan, load_phase_one_inventory  # noqa: E402
from slo_adapter import SplunkSloClient  # noqa: E402
from slo_audit import append_slo_audit  # noqa: E402
from slo_authorization import create_slo_authorization, validate_slo_authorization  # noqa: E402
from slo_common import (  # noqa: E402
    SLO_WAVE_ID, atomic_write_json, read_private_json, resolve_splunk_origin,
    slo_execution_directory, slo_session_lock, slo_wave_lock, value_hash,
)
from slo_executor import (  # noqa: E402
    clear_pending_slo, execute_slo_wave, rollback_proposal, validate_slo_wave,
)
from slo_manifest import build_slo_manifest, validate_slo_manifest  # noqa: E402
from slo_state import SloStore  # noqa: E402


@dataclass(frozen=True)
class SplunkCredentials:
    token: str
    origin: str
    configured_org_id: str | None


def _paths(args: argparse.Namespace) -> dict[str, Path]:
    directory = slo_execution_directory(Path(args.work_root), args.session_id, args.wave_id)
    return {
        "directory": directory,
        "manifest": directory / "slo-manifest.local.json",
        "authorization": directory / "write-authorization.local.json",
        "checkpoint": directory / "execution-checkpoint.local.json",
        "audit": directory / "execution-audit.local.jsonl",
        "rollback": directory / "rollback-proposal.local.json",
    }


def _valid_org(value: str) -> str | None:
    if not value:
        return None
    if len(value) > 256 or any(character.isspace() or ord(character) < 32 for character in value):
        raise ValueError("Splunk organization ID is malformed")
    return value


def _credentials(env_file: str) -> SplunkCredentials:
    values = parse_dotenv(Path(env_file))
    token, realm = select_splunk_o11y_credentials(values)
    if not token or not realm:
        raise ValueError("a complete Splunk Observability Cloud token/realm profile is required")
    return SplunkCredentials(
        token=token,
        origin=resolve_splunk_origin(realm),
        configured_org_id=_valid_org(values.get("SPLUNK_O11Y_ORG_ID", "")),
    )


def _organization(client: SplunkSloClient, configured: str | None) -> str:
    actual = client.get_organization_id()
    if configured is not None and actual != configured:
        raise ValueError("authenticated organization differs from SPLUNK_O11Y_ORG_ID")
    return actual


def _validate_provenance(
    provenance: dict[str, Any], manifest: dict[str, Any], session_id: str, wave_id: str,
) -> None:
    if manifest["source_session_id"] != session_id or manifest["source_session_id"] != provenance["session"].session_id:
        raise ValueError("SLO manifest source session mismatch")
    if manifest["wave_id"] != wave_id:
        raise ValueError("SLO manifest wave mismatch")
    if manifest["plan_hash"] != provenance["plan"]["plan_hash"]:
        raise ValueError("SLO manifest plan hash mismatch")
    if manifest["plan_review_approval_hash"] != provenance["plan_review_approval"]["approval_hash"]:
        raise ValueError("SLO manifest plan-review approval mismatch")


def _claimed_source_refs(
    provenance: dict[str, Any], work_root: Path, session_id: str, current_wave: str,
) -> set[str]:
    root = Path(provenance["session_directory"]) / "slo-execution"
    if root.is_symlink():
        raise ValueError("refusing symlink SLO execution history")
    if not root.exists():
        return set()
    claimed: set[str] = set()
    for directory in root.iterdir():
        if (
            not directory.is_dir() or directory.is_symlink() or directory.name == current_wave
            or not SLO_WAVE_ID.fullmatch(directory.name)
            or not (directory / "execution-checkpoint.local.json").is_file()
        ):
            continue
        checkpoint = SloStore(work_root, session_id, directory.name).load()
        if checkpoint.source_session_id != session_id:
            raise ValueError("SLO execution history session mismatch")
        prior_manifest = None
        if checkpoint.result is not None or checkpoint.pending_create_ref is not None:
            prior_manifest = read_private_json(directory / "slo-manifest.local.json")
            validate_slo_manifest(prior_manifest)
            if (
                prior_manifest["source_session_id"] != session_id
                or prior_manifest["wave_id"] != directory.name
                or prior_manifest["manifest_hash"] != checkpoint.manifest_hash
            ):
                raise ValueError("SLO checkpoint manifest binding mismatch")
        if checkpoint.result is not None:
            entry = prior_manifest["entry"]
            if (
                checkpoint.result["object_ref"] != entry["object_ref"]
                or checkpoint.result["source_refs"] != entry["source_refs"]
                or checkpoint.result["execution_key"] != entry["execution_key"]
                or checkpoint.result["target_kind"] != entry["target_kind"]
            ):
                raise ValueError("completed SLO checkpoint result binding mismatch")
            claimed.update(str(item) for item in entry["source_refs"])
        if checkpoint.pending_create_ref is not None:
            if checkpoint.pending_create_ref != prior_manifest["entry"]["object_ref"]:
                raise ValueError("pending SLO checkpoint result binding mismatch")
            claimed.update(str(item) for item in prior_manifest["entry"]["source_refs"])
    return claimed


def _assert_unclaimed(
    provenance: dict[str, Any], args: argparse.Namespace, manifest: dict[str, Any],
) -> None:
    claimed = _claimed_source_refs(
        provenance, Path(args.work_root), args.session_id, args.wave_id,
    )
    if claimed & set(manifest["entry"]["source_refs"]):
        raise ValueError("SLO manifest contains source objects claimed by another SLO wave")


def command_inspect(args: argparse.Namespace) -> int:
    credentials = _credentials(args.env_file)
    client = SplunkSloClient(credentials.origin, credentials.token, timeout=args.timeout)
    organization_id = _organization(client, credentials.configured_org_id)
    print(json.dumps({
        "status": "connected", "target_origin": credentials.origin,
        "target_org_id_hash": value_hash(organization_id),
        "external_mutations_performed": 0,
    }, indent=2, sort_keys=True))
    return 0


def command_auto_seal(args: argparse.Namespace) -> int:
    provenance = load_approved_plan(Path(args.work_root), args.session_id)
    paths = _paths(args)
    with slo_wave_lock(paths["directory"]):
        inventory, source_binding = load_phase_one_inventory(provenance)
        if paths["manifest"].exists():
            manifest = read_private_json(paths["manifest"])
            validate_slo_manifest(manifest)
            _validate_provenance(provenance, manifest, args.session_id, args.wave_id)
            candidate = build_slo_manifest(
                args.session_id, args.wave_id, provenance["plan"],
                provenance["plan_review_approval"], inventory,
                provenance["session"].local_pseudonym_salt, source_binding,
            )
            stable_fields = ("source_binding", "entry", "safety", "max_creates")
            if any(candidate[field] != manifest[field] for field in stable_fields):
                raise ValueError("sealed SLO manifest differs from translator output")
            status = "already_sealed"
        else:
            manifest = build_slo_manifest(
                args.session_id, args.wave_id, provenance["plan"],
                provenance["plan_review_approval"], inventory,
                provenance["session"].local_pseudonym_salt, source_binding,
            )
            _assert_unclaimed(provenance, args, manifest)
            atomic_write_json(paths["manifest"], manifest)
            status = "sealed"
    print(json.dumps({
        "status": status,
        "wave_id": manifest["wave_id"],
        "manifest_hash": manifest["manifest_hash"],
        "primary_ref": manifest["entry"]["object_ref"],
        "bound_source_object_count": len(manifest["entry"]["source_refs"]),
        "approved_slo_count": 1,
        "alert_rule_count": 2,
        "source_warning_status_preserved": False,
        "manual_payload_edits_required": 0,
        "external_mutations_performed": 0,
    }, indent=2, sort_keys=True))
    return 0


def command_authorize(args: argparse.Namespace) -> int:
    provenance = load_approved_plan(Path(args.work_root), args.session_id)
    paths = _paths(args)
    manifest = read_private_json(paths["manifest"])
    validate_slo_manifest(manifest)
    _validate_provenance(provenance, manifest, args.session_id, args.wave_id)
    with slo_session_lock(paths["directory"]):
        _assert_unclaimed(provenance, args, manifest)
        credentials = _credentials(args.env_file)
        client = SplunkSloClient(credentials.origin, credentials.token, timeout=args.timeout)
        organization_id = _organization(client, credentials.configured_org_id)
        client.validate_slo_payload(manifest["entry"]["payload"])
        if paths["authorization"].exists():
            if not args.renew_expired:
                raise ValueError("SLO authorization exists; use --renew-expired after expiry")
            previous = read_private_json(paths["authorization"])
            validate_slo_authorization(
                previous, manifest, "CREATE_SLO",
                current_time=datetime.fromisoformat(str(previous["approved_at"])),
            )
            if datetime.now(timezone.utc) <= datetime.fromisoformat(str(previous["expires_at"])):
                raise ValueError("current SLO authorization has not expired")
            if (
                previous["target_origin"] != credentials.origin
                or previous["target_org_id_hash"] != value_hash(organization_id)
            ):
                raise ValueError("SLO authorization renewal cannot change the target")
            archive = paths["directory"] / f"{previous['approval_id']}.local.json"
            if archive.exists():
                if read_private_json(archive).get("approval_hash") != previous["approval_hash"]:
                    raise ValueError("archived SLO authorization conflicts")
            else:
                atomic_write_json(archive, previous)
        authorization = create_slo_authorization(
            manifest, args.actor_role, credentials.origin, value_hash(organization_id),
            ttl_minutes=args.ttl_minutes,
        )
        atomic_write_json(paths["authorization"], authorization)
        append_slo_audit(
            paths["audit"], "write_authorized", "approved", args.session_id,
            args.wave_id, authorization["approval_id"], {"authorized_slos": 1},
        )
    print(json.dumps({
        "approval_id": authorization["approval_id"],
        "approval_hash": authorization["approval_hash"],
        "wave_id": authorization["wave_id"],
        "selected_refs": authorization["selected_refs"],
        "max_creates": 1,
        "expires_at": authorization["expires_at"],
        "target_origin": authorization["target_origin"],
        "target_org_id_hash": authorization["target_org_id_hash"],
        "payloads_dry_run_validated": 1,
        "external_mutations_performed": 0,
    }, indent=2, sort_keys=True))
    return 0


def _live_inputs(args: argparse.Namespace, operation: str) -> tuple[Any, ...]:
    provenance = load_approved_plan(Path(args.work_root), args.session_id)
    paths = _paths(args)
    manifest = read_private_json(paths["manifest"])
    authorization = read_private_json(paths["authorization"])
    validate_slo_manifest(manifest)
    _validate_provenance(provenance, manifest, args.session_id, args.wave_id)
    credentials = _credentials(args.env_file)
    if authorization.get("target_origin") != credentials.origin:
        raise ValueError("runtime Splunk origin differs from SLO authorization")
    if (
        credentials.configured_org_id is not None
        and authorization["target_org_id_hash"] != value_hash(credentials.configured_org_id)
    ):
        raise ValueError("configured Splunk organization differs from SLO authorization")
    validate_slo_authorization(authorization, manifest, operation)
    client = SplunkSloClient(credentials.origin, credentials.token, timeout=args.timeout)
    store = SloStore(Path(args.work_root), args.session_id, args.wave_id)
    return provenance, manifest, authorization, client, store, paths


def command_execute(args: argparse.Namespace) -> int:
    if not args.confirm_execution:
        raise ValueError("--confirm-execution is required")
    provenance, manifest, authorization, client, store, paths = _live_inputs(args, "CREATE_SLO")
    with slo_session_lock(paths["directory"]):
        _assert_unclaimed(provenance, args, manifest)
        append_slo_audit(
            paths["audit"], "wave_started", "success", args.session_id,
            args.wave_id, authorization["approval_id"],
        )
        try:
            with slo_wave_lock(paths["directory"]):
                checkpoint = execute_slo_wave(manifest, authorization, client, store)
        except Exception:
            append_slo_audit(
                paths["audit"], "wave_failed", "failed", args.session_id,
                args.wave_id, authorization["approval_id"],
            )
            raise
    atomic_write_json(paths["rollback"], rollback_proposal(checkpoint))
    outcome = checkpoint.result["outcome"] if checkpoint.result else "none"
    append_slo_audit(
        paths["audit"], "wave_completed", "success", args.session_id,
        args.wave_id, authorization["approval_id"],
        {"created": int(outcome == "created"), "reused": int(outcome == "reused")},
    )
    print(json.dumps({
        "status": checkpoint.status,
        "created": int(outcome == "created"),
        "reused": int(outcome == "reused"),
        "validated": int(bool(checkpoint.result and checkpoint.result["validated"])),
        "bound_source_object_count": len(manifest["entry"]["source_refs"]),
        "rollback_proposal": str(paths["rollback"].resolve()),
    }, indent=2, sort_keys=True))
    return 0


def command_validate(args: argparse.Namespace) -> int:
    _provenance, manifest, authorization, client, store, paths = _live_inputs(args, "VALIDATE_SLO")
    try:
        with slo_wave_lock(paths["directory"]):
            checkpoint = validate_slo_wave(manifest, authorization, client, store)
    except Exception:
        append_slo_audit(
            paths["audit"], "validation_failed", "failed", args.session_id,
            args.wave_id, authorization["approval_id"],
        )
        raise
    append_slo_audit(
        paths["audit"], "validation_completed", "success", args.session_id,
        args.wave_id, authorization["approval_id"], {"validated": 1},
    )
    print(json.dumps({"status": checkpoint.status, "validated": 1, "expected": 1}, indent=2, sort_keys=True))
    return 0


def command_clear_pending(args: argparse.Namespace) -> int:
    if not args.confirm_retry_pending_create:
        raise ValueError("--confirm-retry-pending-create is required")
    _provenance, manifest, authorization, client, store, paths = _live_inputs(args, "VALIDATE_SLO")
    with slo_wave_lock(paths["directory"]):
        checkpoint = clear_pending_slo(manifest, authorization, client, store)
    append_slo_audit(
        paths["audit"], "pending_create_cleared", "success", args.session_id,
        args.wave_id, authorization["approval_id"], {"cleared": 1},
    )
    print(json.dumps({
        "status": checkpoint.status, "cleared": 1, "external_mutations_performed": 0,
    }, indent=2, sort_keys=True))
    return 0


def command_status(args: argparse.Namespace) -> int:
    paths = _paths(args)
    if not paths["checkpoint"].exists():
        print(json.dumps({"status": "NOT_STARTED", "wave_id": args.wave_id}, indent=2, sort_keys=True))
        return 0
    checkpoint = SloStore(Path(args.work_root), args.session_id, args.wave_id).load()
    print(json.dumps({
        "status": checkpoint.status,
        "wave_id": checkpoint.wave_id,
        "created": int(bool(checkpoint.result and checkpoint.result["outcome"] == "created")),
        "reused": int(bool(checkpoint.result and checkpoint.result["outcome"] == "reused")),
        "validated": int(bool(checkpoint.result and checkpoint.result["validated"])),
        "pending_create": int(checkpoint.pending_create_ref is not None),
        "failure_category": checkpoint.failure_category,
    }, indent=2, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    def common(command: argparse.ArgumentParser) -> None:
        command.add_argument("--session-id", required=True)
        command.add_argument("--wave-id", required=True)
        command.add_argument("--work-root", default=".migration-work")

    def live(command: argparse.ArgumentParser) -> None:
        command.add_argument("--env-file", default=".env")
        command.add_argument("--timeout", type=int, default=10)

    inspect = commands.add_parser("inspect-splunk-target")
    live(inspect)
    inspect.set_defaults(handler=command_inspect)

    seal = commands.add_parser("auto-seal-wave")
    common(seal)
    seal.set_defaults(handler=command_auto_seal)

    authorize = commands.add_parser("authorize-writes")
    common(authorize)
    live(authorize)
    authorize.add_argument("--actor-role", choices=["customer", "authorized_operator"], default="customer")
    authorize.add_argument("--ttl-minutes", type=int, default=30)
    authorize.add_argument("--renew-expired", action="store_true")
    authorize.set_defaults(handler=command_authorize)

    execute = commands.add_parser("execute-wave")
    common(execute)
    live(execute)
    execute.add_argument("--confirm-execution", action="store_true")
    execute.set_defaults(handler=command_execute)

    validate = commands.add_parser("validate-wave")
    common(validate)
    live(validate)
    validate.set_defaults(handler=command_validate)

    clear = commands.add_parser("clear-pending-create")
    common(clear)
    live(clear)
    clear.add_argument("--confirm-retry-pending-create", action="store_true")
    clear.set_defaults(handler=command_clear_pending)

    status = commands.add_parser("status")
    common(status)
    status.set_defaults(handler=command_status)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        return int(args.handler(args))
    except Exception as exc:
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
