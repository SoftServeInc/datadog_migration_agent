#!/usr/bin/env python3
"""CLI for bounded Splunk Observability Cloud detector migration waves."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
ASSESSMENT_SCRIPTS = HERE.parents[1] / "observability-migration-assessment" / "scripts"
sys.path.insert(0, str(ASSESSMENT_SCRIPTS))
sys.path.insert(0, str(HERE))

from assessment_core.config import parse_dotenv, select_splunk_o11y_credentials  # noqa: E402

from execution_core.adapter import SplunkDetectorClient  # noqa: E402
from execution_core.audit import append_execution_audit  # noqa: E402
from execution_core.authorization import create_write_authorization, validate_write_authorization  # noqa: E402
from execution_core.common import (  # noqa: E402
    atomic_write_json,
    execution_directory,
    read_private_json,
    resolve_splunk_origin,
    session_execution_lock,
    value_hash,
    WAVE_ID,
    wave_lock,
)
from execution_core.executor import clear_unresolved_pending, execute_wave, rollback_proposal, validate_wave  # noqa: E402
from execution_core.manifest import prepare_manifest_draft, seal_manifest, validate_sealed_manifest  # noqa: E402
from execution_core.provenance import load_approved_plan, load_phase_one_inventory  # noqa: E402
from execution_core.state import ExecutionStore  # noqa: E402
from execution_core.translation import auto_populate_draft  # noqa: E402


def _paths(args: argparse.Namespace) -> dict[str, Path]:
    directory = execution_directory(Path(args.work_root), args.session_id, args.wave_id)
    return {
        "directory": directory,
        "draft": directory / "translation-manifest.draft.local.json",
        "manifest": directory / "translation-manifest.local.json",
        "authorization": directory / "write-authorization.local.json",
        "audit": directory / "execution-audit.local.jsonl",
        "rollback": directory / "rollback-proposal.local.json",
    }


@dataclass(frozen=True)
class SplunkCredentials:
    token: str
    realm: str
    origin: str
    configured_org_id: str | None


def _valid_optional_org_id(org_id: str) -> str | None:
    if not org_id:
        return None
    if len(org_id) > 256 or any(character.isspace() or ord(character) < 32 for character in org_id):
        raise ValueError("Splunk organization ID is malformed")
    return org_id


def _load_splunk_credentials(env_file: str) -> SplunkCredentials:
    values = parse_dotenv(Path(env_file))
    token, realm = select_splunk_o11y_credentials(values)
    if not token or not realm:
        raise ValueError("a complete Splunk Observability Cloud token/realm profile is required")
    return SplunkCredentials(
        token,
        realm,
        resolve_splunk_origin(realm),
        _valid_optional_org_id(values.get("SPLUNK_O11Y_ORG_ID", "")),
    )


def _verified_organization_id(client: SplunkDetectorClient, configured_org_id: str | None) -> str:
    organization_id = client.get_organization_id()
    if configured_org_id is not None and organization_id != configured_org_id:
        raise ValueError("authenticated organization differs from SPLUNK_O11Y_ORG_ID")
    return organization_id


def command_inspect_target(args: argparse.Namespace) -> int:
    credentials = _load_splunk_credentials(args.env_file)
    client = SplunkDetectorClient(credentials.origin, credentials.token, timeout=args.timeout)
    organization_id = _verified_organization_id(client, credentials.configured_org_id)
    print(json.dumps({
        "status": "connected",
        "target_origin": credentials.origin,
        "target_org_id_hash": value_hash(organization_id),
        "external_mutations_performed": 0,
    }, indent=2, sort_keys=True))
    return 0


def _validate_provenance_binding(
    provenance: dict[str, Any], manifest: dict[str, Any], session_id: str, wave_id: str,
) -> None:
    if manifest["source_session_id"] != provenance["session"].session_id or manifest["source_session_id"] != session_id:
        raise ValueError("manifest source session mismatch")
    if manifest["wave_id"] != wave_id:
        raise ValueError("manifest wave does not match the selected execution directory")
    if manifest["plan_hash"] != provenance["plan"]["plan_hash"]:
        raise ValueError("manifest plan hash mismatch")
    if manifest["plan_review_approval_hash"] != provenance["plan_review_approval"]["approval_hash"]:
        raise ValueError("manifest plan-review approval mismatch")


def _claimed_refs_from_other_waves(
    provenance: dict[str, Any], work_root: Path, session_id: str, current_wave_id: str,
) -> tuple[set[str], set[str]]:
    execution_root = Path(provenance["session_directory"]) / "execution"
    if execution_root.is_symlink():
        raise ValueError("refusing symlink execution history")
    if not execution_root.exists():
        return set(), set()
    completed: set[str] = set()
    pending: set[str] = set()
    for directory in execution_root.iterdir():
        if (
            not directory.is_dir()
            or directory.is_symlink()
            or directory.name == current_wave_id
            or not WAVE_ID.fullmatch(directory.name)
            or not (directory / "execution-checkpoint.local.json").is_file()
        ):
            continue
        checkpoint = ExecutionStore(work_root, session_id, directory.name).load()
        if checkpoint.source_session_id != session_id:
            raise ValueError("execution history session mismatch")
        completed.update(str(result["object_ref"]) for result in checkpoint.results)
        pending.update(checkpoint.pending_create_refs)
    if completed & pending:
        raise ValueError("execution history contains conflicting completed and pending references")
    return completed, pending


def _sealed_refs_from_other_waves(
    provenance: dict[str, Any], session_id: str, current_wave_id: str,
) -> set[str]:
    """Reserve refs already compiled into another immutable detector wave."""
    execution_root = Path(provenance["session_directory"]) / "execution"
    if execution_root.is_symlink():
        raise ValueError("refusing symlink execution history")
    if not execution_root.exists():
        return set()
    reserved: set[str] = set()
    for directory in execution_root.iterdir():
        manifest_path = directory / "translation-manifest.local.json"
        if (
            not directory.is_dir()
            or directory.is_symlink()
            or directory.name == current_wave_id
            or not WAVE_ID.fullmatch(directory.name)
            or not manifest_path.is_file()
        ):
            continue
        manifest = read_private_json(manifest_path)
        validate_sealed_manifest(manifest)
        _validate_provenance_binding(provenance, manifest, session_id, directory.name)
        reserved.update(str(entry["object_ref"]) for entry in manifest["entries"])
    return reserved


def _exclude_prior_claims(
    draft: dict[str, Any], completed_refs: set[str], pending_refs: set[str],
) -> dict[str, int]:
    excluded_completed = 0
    excluded_pending = 0
    claimed = completed_refs | pending_refs
    for entry in draft.get("entries", []):
        if not isinstance(entry, dict) or entry.get("object_ref") not in claimed:
            continue
        if entry.get("review_status") == "approved":
            raise ValueError("draft approves a source object already claimed by another wave")
        if (
            entry.get("target_kind") == "detector"
            and entry.get("review_status") == "pending"
        ):
            entry["review_status"] = "not_applicable"
            entry["semantic_review"] = {
                "source_intent_reviewed": False,
                "signalflow_reviewed": False,
                "differences_accepted": False,
            }
            entry["payload"] = None
            if entry.get("object_ref") in pending_refs:
                entry["unsupported_reason"] = "unresolved pending create in another execution wave"
                excluded_pending += 1
            else:
                entry["unsupported_reason"] = "completed in another execution wave"
                excluded_completed += 1
    return {
        "already_completed_source_objects": excluded_completed,
        "prior_pending_create_objects": excluded_pending,
    }


def _assert_manifest_refs_unclaimed(
    provenance: dict[str, Any], work_root: Path, session_id: str, wave_id: str,
    manifest: dict[str, Any],
) -> None:
    completed_refs, pending_refs = _claimed_refs_from_other_waves(
        provenance, work_root, session_id, wave_id,
    )
    sealed_refs = _sealed_refs_from_other_waves(provenance, session_id, wave_id)
    manifest_refs = {str(entry["object_ref"]) for entry in manifest["entries"]}
    conflicts = manifest_refs & (completed_refs | pending_refs | sealed_refs)
    if conflicts:
        raise ValueError(
            "sealed manifest contains source objects claimed by another execution wave"
        )


def command_prepare_manifest(args: argparse.Namespace) -> int:
    provenance = load_approved_plan(Path(args.work_root), args.session_id)
    paths = _paths(args)
    if paths["manifest"].exists():
        raise ValueError("this wave already has a sealed manifest; start a new wave")
    if paths["draft"].exists() and not args.replace_draft:
        raise ValueError("manifest draft already exists; use --replace-draft to replace only the draft")
    draft = prepare_manifest_draft(
        args.session_id,
        provenance["plan"],
        provenance["plan_review_approval"],
        args.wave_id,
        args.max_creates,
    )
    atomic_write_json(paths["draft"], draft)
    supported = sum(entry["target_kind"] == "detector" for entry in draft["entries"])
    unsupported = len(draft["entries"]) - supported
    print(json.dumps({
        "draft": str(paths["draft"].resolve()),
        "wave_id": args.wave_id,
        "supported_detector_candidates": supported,
        "unsupported_objects": unsupported,
        "external_mutations_performed": 0,
    }, indent=2, sort_keys=True))
    return 0


def command_seal_manifest(args: argparse.Namespace) -> int:
    provenance = load_approved_plan(Path(args.work_root), args.session_id)
    paths = _paths(args)
    if paths["manifest"].exists():
        raise ValueError("sealed manifest already exists and is immutable")
    draft = read_private_json(paths["draft"])
    completed_refs, pending_refs = _claimed_refs_from_other_waves(
        provenance, Path(args.work_root), args.session_id, args.wave_id,
    )
    sealed_refs = _sealed_refs_from_other_waves(provenance, args.session_id, args.wave_id)
    _exclude_prior_claims(draft, completed_refs | sealed_refs, pending_refs)
    _inventory, source_binding = load_phase_one_inventory(provenance)
    manifest = seal_manifest(
        draft, provenance["plan"], provenance["plan_review_approval"], source_binding,
    )
    _validate_provenance_binding(provenance, manifest, args.session_id, args.wave_id)
    atomic_write_json(paths["manifest"], manifest)
    print(json.dumps({
        "manifest": str(paths["manifest"].resolve()),
        "manifest_hash": manifest["manifest_hash"],
        "wave_id": manifest["wave_id"],
        "approved_detector_count": len(manifest["entries"]),
        "external_mutations_performed": 0,
    }, indent=2, sort_keys=True))
    return 0


def command_auto_seal(args: argparse.Namespace) -> int:
    provenance = load_approved_plan(Path(args.work_root), args.session_id)
    paths = _paths(args)
    with wave_lock(paths["directory"]):
        if paths["manifest"].exists():
            manifest = read_private_json(paths["manifest"])
            validate_sealed_manifest(manifest)
            _validate_provenance_binding(provenance, manifest, args.session_id, args.wave_id)
            if manifest["max_creates"] != args.max_creates:
                raise ValueError("sealed manifest cap differs from --max-creates")
            draft = read_private_json(paths["draft"])
            if draft.get("max_creates") != args.max_creates:
                raise ValueError("existing draft cap differs from --max-creates; start a new wave")
            inventory, source_binding = load_phase_one_inventory(provenance)
            if manifest["source_binding"] != source_binding:
                raise ValueError("sealed manifest source inventory binding has drifted")
            verified_draft, summary = auto_populate_draft(
                draft, inventory, provenance["session"].local_pseudonym_salt,
            )
            candidate = seal_manifest(
                verified_draft,
                provenance["plan"],
                provenance["plan_review_approval"],
                source_binding,
                automatic_payload_hashes=summary.get("_automatic_payload_hashes"),
            )
            expected_entries = [
                (entry["object_ref"], entry["payload_hash"]) for entry in candidate["entries"]
            ]
            actual_entries = [
                (entry["object_ref"], entry["payload_hash"]) for entry in manifest["entries"]
            ]
            if actual_entries != expected_entries:
                raise ValueError("sealed payloads differ from the bound translator output")
            status = "already_sealed"
            summary["auto_translated"] = 0
        else:
            draft = (
                read_private_json(paths["draft"])
                if paths["draft"].exists()
                else prepare_manifest_draft(
                    args.session_id,
                    provenance["plan"],
                    provenance["plan_review_approval"],
                    args.wave_id,
                    args.max_creates,
                )
            )
            if draft.get("max_creates") != args.max_creates:
                raise ValueError("existing draft cap differs from --max-creates; start a new wave")
            completed_refs, pending_refs = _claimed_refs_from_other_waves(
                provenance, Path(args.work_root), args.session_id, args.wave_id,
            )
            sealed_refs = _sealed_refs_from_other_waves(
                provenance, args.session_id, args.wave_id,
            )
            prior_claims = _exclude_prior_claims(
                draft, completed_refs | sealed_refs, pending_refs,
            )
            inventory, source_binding = load_phase_one_inventory(provenance)
            draft, summary = auto_populate_draft(
                draft,
                inventory,
                provenance["session"].local_pseudonym_salt,
            )
            manifest = seal_manifest(
                draft,
                provenance["plan"],
                provenance["plan_review_approval"],
                source_binding,
                automatic_payload_hashes=summary.get("_automatic_payload_hashes"),
            )
            _validate_provenance_binding(provenance, manifest, args.session_id, args.wave_id)
            atomic_write_json(paths["draft"], draft)
            atomic_write_json(paths["manifest"], manifest)
            status = "sealed"
            summary.update(prior_claims)
    print(json.dumps({
        "status": status,
        "wave_id": manifest["wave_id"],
        "manifest_hash": manifest["manifest_hash"],
        "selected_refs": [entry["object_ref"] for entry in manifest["entries"]],
        "approved_detector_count": len(manifest["entries"]),
        "auto_translated": summary["auto_translated"],
        "unsupported_query_shapes": summary.get("unsupported_query_shapes", 0),
        "missing_source_records": summary.get("missing_source_records", 0),
        "already_completed_source_objects": summary.get("already_completed_source_objects", 0),
        "prior_pending_create_objects": summary.get("prior_pending_create_objects", 0),
        "manual_payload_edits_required": 0,
        "external_mutations_performed": 0,
    }, indent=2, sort_keys=True))
    return 0


def command_authorize(args: argparse.Namespace) -> int:
    provenance = load_approved_plan(Path(args.work_root), args.session_id)
    paths = _paths(args)
    manifest = read_private_json(paths["manifest"])
    validate_sealed_manifest(manifest)
    _validate_provenance_binding(provenance, manifest, args.session_id, args.wave_id)
    with session_execution_lock(paths["directory"]):
        _assert_manifest_refs_unclaimed(
            provenance, Path(args.work_root), args.session_id, args.wave_id, manifest,
        )
        credentials = _load_splunk_credentials(args.env_file)
        client = SplunkDetectorClient(credentials.origin, credentials.token, timeout=args.timeout)
        org_id = _verified_organization_id(client, credentials.configured_org_id)
        for entry in manifest["entries"]:
            client.validate_detector_payload(entry["payload"])
        origin = credentials.origin
        if paths["authorization"].exists():
            if not args.renew_expired:
                raise ValueError("write authorization already exists; use --renew-expired after it expires")
            previous = read_private_json(paths["authorization"])
            validate_write_authorization(
                previous,
                manifest,
                "CREATE_DETECTOR",
                current_time=datetime.fromisoformat(str(previous["approved_at"])),
            )
            if datetime.now(timezone.utc) <= datetime.fromisoformat(str(previous["expires_at"])):
                raise ValueError("current write authorization has not expired")
            if previous["target_origin"] != origin or previous["target_org_id_hash"] != value_hash(org_id):
                raise ValueError("renewal cannot change the authorized Splunk organization")
            archive = paths["directory"] / f"{previous['approval_id']}.local.json"
            if archive.exists():
                archived = read_private_json(archive)
                if archived.get("approval_hash") != previous["approval_hash"]:
                    raise ValueError("archived write authorization conflicts with the active record")
            else:
                atomic_write_json(archive, previous)
        authorization = create_write_authorization(
            manifest,
            args.actor_role,
            origin,
            value_hash(org_id),
            ttl_minutes=args.ttl_minutes,
        )
        atomic_write_json(paths["authorization"], authorization)
        append_execution_audit(
            paths["audit"], "write_authorized", "approved", args.session_id, args.wave_id,
            authorization["approval_id"], {"authorized_objects": len(manifest["entries"]), "max_creates": authorization["max_creates"]},
        )
    print(json.dumps({
        "approval_id": authorization["approval_id"],
        "approval_hash": authorization["approval_hash"],
        "target_origin": authorization["target_origin"],
        "target_org_id_hash": authorization["target_org_id_hash"],
        "wave_id": authorization["wave_id"],
        "selected_refs": authorization["selected_refs"],
        "max_creates": authorization["max_creates"],
        "expires_at": authorization["expires_at"],
        "payloads_dry_run_validated": len(manifest["entries"]),
        "external_mutations_performed": 0,
    }, indent=2, sort_keys=True))
    return 0


def _live_inputs(args: argparse.Namespace, operation: str) -> tuple[dict[str, Any], dict[str, Any], Any, ExecutionStore, dict[str, Path]]:
    provenance = load_approved_plan(Path(args.work_root), args.session_id)
    paths = _paths(args)
    manifest = read_private_json(paths["manifest"])
    authorization = read_private_json(paths["authorization"])
    validate_sealed_manifest(manifest)
    _validate_provenance_binding(provenance, manifest, args.session_id, args.wave_id)
    credentials = _load_splunk_credentials(args.env_file)
    if authorization.get("target_origin") != credentials.origin:
        raise ValueError("runtime Splunk origin differs from the authorized origin")
    if (
        credentials.configured_org_id is not None
        and authorization["target_org_id_hash"] != value_hash(credentials.configured_org_id)
    ):
        raise ValueError("configured Splunk organization differs from the authorized organization")
    validate_write_authorization(authorization, manifest, operation)
    client = SplunkDetectorClient(credentials.origin, credentials.token, timeout=args.timeout)
    store = ExecutionStore(Path(args.work_root), args.session_id, args.wave_id)
    return manifest, authorization, client, store, paths


def command_execute(args: argparse.Namespace) -> int:
    if not args.confirm_execution:
        raise ValueError("--confirm-execution is required")
    manifest, authorization, client, store, paths = _live_inputs(args, "CREATE_DETECTOR")
    provenance = load_approved_plan(Path(args.work_root), args.session_id)
    with session_execution_lock(paths["directory"]):
        _assert_manifest_refs_unclaimed(
            provenance, Path(args.work_root), args.session_id, args.wave_id, manifest,
        )
        append_execution_audit(paths["audit"], "wave_started", "success", args.session_id, args.wave_id, authorization["approval_id"])
        try:
            with wave_lock(paths["directory"]):
                checkpoint = execute_wave(manifest, authorization, client, store)
        except Exception:
            append_execution_audit(paths["audit"], "wave_failed", "failed", args.session_id, args.wave_id, authorization["approval_id"])
            raise
    atomic_write_json(paths["rollback"], rollback_proposal(checkpoint))
    append_execution_audit(
        paths["audit"], "wave_completed", "success", args.session_id, args.wave_id,
        authorization["approval_id"], {"created": checkpoint.created_count, "reused": checkpoint.reused_count},
    )
    print(json.dumps({
        "status": checkpoint.status,
        "created": checkpoint.created_count,
        "reused": checkpoint.reused_count,
        "validated": checkpoint.validated_count,
        "rollback_proposal": str(paths["rollback"].resolve()),
    }, indent=2, sort_keys=True))
    return 0


def command_validate(args: argparse.Namespace) -> int:
    manifest, authorization, client, store, paths = _live_inputs(args, "VALIDATE_DETECTOR")
    try:
        with wave_lock(paths["directory"]):
            checkpoint = validate_wave(manifest, authorization, client, store)
    except Exception:
        append_execution_audit(
            paths["audit"], "validation_failed", "failed", args.session_id, args.wave_id,
            authorization["approval_id"],
        )
        raise
    append_execution_audit(
        paths["audit"], "validation_completed", "success", args.session_id, args.wave_id,
        authorization["approval_id"], {"validated": checkpoint.validated_count},
    )
    print(json.dumps({
        "status": checkpoint.status,
        "validated": checkpoint.validated_count,
        "expected": len(manifest["entries"]),
    }, indent=2, sort_keys=True))
    return 0


def command_clear_pending(args: argparse.Namespace) -> int:
    if not args.confirm_retry_pending_create:
        raise ValueError("--confirm-retry-pending-create is required")
    manifest, authorization, client, store, paths = _live_inputs(args, "VALIDATE_DETECTOR")
    with wave_lock(paths["directory"]):
        checkpoint, cleared = clear_unresolved_pending(
            manifest, authorization, client, store,
        )
    append_execution_audit(
        paths["audit"], "pending_create_cleared", "success", args.session_id, args.wave_id,
        authorization["approval_id"], {"cleared": len(cleared), "remaining": len(checkpoint.pending_create_refs)},
    )
    print(json.dumps({
        "status": checkpoint.status,
        "cleared_refs": cleared,
        "remaining_pending_refs": checkpoint.pending_create_refs,
        "external_mutations_performed": 0,
    }, indent=2, sort_keys=True))
    return 0


def command_status(args: argparse.Namespace) -> int:
    paths = _paths(args)
    store = ExecutionStore(Path(args.work_root), args.session_id, args.wave_id)
    checkpoint = store.load()
    print(json.dumps({
        "session_id": checkpoint.source_session_id,
        "wave_id": checkpoint.wave_id,
        "status": checkpoint.status,
        "created": checkpoint.created_count,
        "reused": checkpoint.reused_count,
        "validated": checkpoint.validated_count,
        "pending_create_refs": checkpoint.pending_create_refs,
        "failure_category": checkpoint.failure_category,
        "rollback_proposal_present": paths["rollback"].is_file(),
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

    inspect = commands.add_parser("inspect-splunk-target", help="verify credentials and hash the authenticated Splunk organization")
    live(inspect)
    inspect.set_defaults(handler=command_inspect_target)

    prepare = commands.add_parser("prepare-manifest", help="create a private local translation-manifest draft")
    common(prepare)
    prepare.add_argument("--max-creates", type=int, default=5)
    prepare.add_argument("--replace-draft", action="store_true")
    prepare.set_defaults(handler=command_prepare_manifest)

    seal = commands.add_parser("seal-manifest", help="validate and hash-bind a customer-reviewed manifest")
    common(seal)
    seal.set_defaults(handler=command_seal_manifest)

    auto_seal = commands.add_parser(
        "auto-seal-wave",
        help="locally translate an allowlisted Datadog monitor subset and seal the wave",
    )
    common(auto_seal)
    auto_seal.add_argument("--max-creates", type=int, default=5)
    auto_seal.set_defaults(handler=command_auto_seal)

    authorize = commands.add_parser(
        "authorize-writes", help="authorize one bounded customer-approved detector create wave",
    )
    common(authorize)
    live(authorize)
    authorize.add_argument("--actor-role", choices=["customer", "authorized_operator"], default="customer")
    authorize.add_argument("--ttl-minutes", type=int, default=30)
    authorize.add_argument("--renew-expired", action="store_true")
    authorize.set_defaults(handler=command_authorize)

    execute = commands.add_parser(
        "execute-wave", help="execute or resume an authorized create-only detector wave",
    )
    common(execute)
    live(execute)
    execute.add_argument("--confirm-execution", action="store_true")
    execute.set_defaults(handler=command_execute)

    validate = commands.add_parser(
        "validate-wave", help="read back and validate an executed detector wave",
    )
    common(validate)
    live(validate)
    validate.set_defaults(handler=command_validate)

    clear_pending = commands.add_parser(
        "clear-pending-create",
        help="clear an unresolved create intent only after an exact-marker absence check",
    )
    common(clear_pending)
    live(clear_pending)
    clear_pending.add_argument("--confirm-retry-pending-create", action="store_true")
    clear_pending.set_defaults(handler=command_clear_pending)

    status = commands.add_parser("status", help="show a sanitized local execution checkpoint summary")
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
