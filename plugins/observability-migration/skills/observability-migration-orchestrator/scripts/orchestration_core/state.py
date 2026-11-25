"""Tamper-evident unified checkpoint and ownership ledger."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .bundle import validate_bundle
from .common import SHA256, atomic_write_json, canonical_hash, read_private_json, runtime_directory, value_hash


CHECKPOINT_STATUSES = {"READY", "APPLYING", "VALIDATING", "COMPLETED", "PARTIAL", "FAILED", "ROLLING_BACK", "ROLLED_BACK"}
OPERATION_STATUSES = {"PENDING", "APPLYING", "APPLIED", "VALIDATING", "COMPLETED", "FAILED", "BLOCKED", "SKIPPED", "ROLLING_BACK", "ROLLED_BACK"}
DISPOSITIONS = {"CREATED", "UPDATED", "REUSED", "NO_OP"}


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


class UnifiedStore:
    def __init__(self, work_root: Path, session_id: str):
        self.directory = runtime_directory(work_root, session_id)
        self.checkpoint_path = self.directory / "execution-checkpoint.local.json"
        self.ledger_path = self.directory / "ownership-ledger.local.json"
        self.before_state_directory = self.directory / "before-state"

    def create(self, bundle: dict[str, Any], approval: dict[str, Any]) -> dict[str, Any]:
        validate_bundle(bundle)
        if self.checkpoint_path.exists():
            checkpoint = self.load_checkpoint()
            if (
                checkpoint["bundle_hash"] != bundle["bundle_hash"]
                or checkpoint["approval_hash"] != approval["approval_hash"]
            ):
                raise ValueError("existing checkpoint belongs to a different bundle or approval")
            return checkpoint
        timestamp = now()
        checkpoint: dict[str, Any] = {
            "schema_version": "1.0", "session_id": bundle["session_id"],
            "plan_hash": bundle["plan_hash"], "bundle_hash": bundle["bundle_hash"],
            "approval_hash": approval["approval_hash"], "target_binding": deepcopy(bundle["target_binding"]),
            "status": "READY", "created_at": timestamp, "updated_at": timestamp,
            "operations": {
                operation["operation_id"]: {
                    "status": "SKIPPED" if operation["action"] == "DEFER" or operation["status"] != "SUPPORTED" else "PENDING",
                    "attempts": 0, "failure_category": None, "resources": [], "validation": [],
                }
                for operation in bundle["operations"]
            },
            "checkpoint_hash": "",
        }
        self.save_checkpoint(checkpoint)
        ledger = {
            "schema_version": "1.0", "session_id": bundle["session_id"],
            "bundle_hash": bundle["bundle_hash"], "entries": [], "ledger_hash": "",
        }
        self.save_ledger(ledger)
        return checkpoint

    def save_checkpoint(self, checkpoint: dict[str, Any]) -> None:
        checkpoint["updated_at"] = now()
        checkpoint["checkpoint_hash"] = canonical_hash(checkpoint, "checkpoint_hash")
        atomic_write_json(self.checkpoint_path, checkpoint)

    def load_checkpoint(self) -> dict[str, Any]:
        checkpoint = read_private_json(self.checkpoint_path)
        required = {
            "schema_version", "session_id", "plan_hash", "bundle_hash", "approval_hash",
            "target_binding", "status", "created_at", "updated_at", "operations", "checkpoint_hash",
        }
        if set(checkpoint) != required or checkpoint.get("schema_version") != "1.0":
            raise ValueError("unified checkpoint fields or version are invalid")
        if checkpoint["status"] not in CHECKPOINT_STATUSES:
            raise ValueError("unified checkpoint status is invalid")
        for field in ("plan_hash", "bundle_hash", "approval_hash", "checkpoint_hash"):
            if not SHA256.fullmatch(str(checkpoint[field])):
                raise ValueError(f"unified checkpoint {field} is invalid")
        if checkpoint["checkpoint_hash"] != canonical_hash(checkpoint, "checkpoint_hash"):
            raise ValueError("unified checkpoint hash mismatch")
        if not isinstance(checkpoint["operations"], dict):
            raise ValueError("unified checkpoint operations are invalid")
        for value in checkpoint["operations"].values():
            if (
                not isinstance(value, dict)
                or set(value) != {"status", "attempts", "failure_category", "resources", "validation"}
                or value["status"] not in OPERATION_STATUSES
                or not isinstance(value["attempts"], int) or isinstance(value["attempts"], bool) or value["attempts"] < 0
                or not isinstance(value["resources"], list) or not isinstance(value["validation"], list)
            ):
                raise ValueError("unified checkpoint operation state is invalid")
        return checkpoint

    def save_ledger(self, ledger: dict[str, Any]) -> None:
        ledger["ledger_hash"] = canonical_hash(ledger, "ledger_hash")
        atomic_write_json(self.ledger_path, ledger)

    def load_ledger(self) -> dict[str, Any]:
        ledger = read_private_json(self.ledger_path)
        if set(ledger) != {"schema_version", "session_id", "bundle_hash", "entries", "ledger_hash"}:
            raise ValueError("ownership ledger fields are invalid")
        if ledger.get("schema_version") != "1.0" or ledger["ledger_hash"] != canonical_hash(ledger, "ledger_hash"):
            raise ValueError("ownership ledger hash or version is invalid")
        identities: set[tuple[str, str]] = set()
        for entry in ledger["entries"]:
            required = {
                "operation_id", "adapter", "object_ref", "object_type", "target_id",
                "target_id_hash", "disposition", "payload_hash", "dependencies", "before_state_file",
            }
            if not isinstance(entry, dict) or set(entry) != required or entry["disposition"] not in DISPOSITIONS:
                raise ValueError("ownership ledger entry is invalid")
            if (
                not isinstance(entry["target_id"], str) or not entry["target_id"]
                or entry["target_id_hash"] != value_hash(entry["target_id"])
                or not SHA256.fullmatch(str(entry["payload_hash"]))
                or not isinstance(entry["dependencies"], list)
                or entry["before_state_file"] is not None and not isinstance(entry["before_state_file"], str)
            ):
                raise ValueError("ownership ledger target hash mismatch")
            identity = (entry["object_type"], entry["target_id"])
            if identity in identities:
                raise ValueError("ownership ledger target is duplicated")
            identities.add(identity)
        return ledger

    def record_resources(
        self, checkpoint: dict[str, Any], operation: dict[str, Any], resources: list[dict[str, Any]],
    ) -> None:
        ledger = self.load_ledger()
        existing = {(entry["object_type"], entry["target_id"]): entry for entry in ledger["entries"]}
        normalized: list[dict[str, Any]] = []
        for index, resource in enumerate(resources):
            if not isinstance(resource, dict):
                raise ValueError("adapter resource result must be an object")
            target_id = resource.get("target_id")
            disposition = str(resource.get("disposition", "")).upper()
            if not isinstance(target_id, str) or not target_id or disposition not in DISPOSITIONS:
                raise ValueError("adapter resource identity or disposition is invalid")
            before_state_file: str | None = None
            before_state = resource.get("before_state")
            if disposition == "UPDATED":
                if not isinstance(before_state, dict):
                    raise ValueError("updated resource requires a captured before-state")
                self.before_state_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
                before_name = f"{operation['operation_id'].replace(':', '_')}-{index}-{value_hash(target_id)[:12]}.local.json"
                before_path = self.before_state_directory / before_name
                atomic_write_json(before_path, before_state)
                before_state_file = str(before_path.relative_to(self.directory))
            entry = {
                "operation_id": operation["operation_id"], "adapter": operation["adapter"],
                "object_ref": str(resource.get("object_ref") or operation["object_ref"]),
                "object_type": str(resource.get("object_type") or operation["object_type"]),
                "target_id": target_id, "target_id_hash": value_hash(target_id),
                "disposition": disposition,
                "payload_hash": str(resource.get("payload_hash") or operation["payload_hash"]),
                "dependencies": list(resource.get("dependencies", operation["dependencies"])),
                "before_state_file": before_state_file,
            }
            identity = (entry["object_type"], target_id)
            if identity in existing and existing[identity] != entry:
                raise ValueError("adapter returned a target already owned by another operation")
            if identity not in existing:
                ledger["entries"].append(entry)
                existing[identity] = entry
            normalized.append(entry)
        checkpoint["operations"][operation["operation_id"]]["resources"] = normalized
        self.save_ledger(ledger)
        self.save_checkpoint(checkpoint)

    def read_before_state(self, entry: dict[str, Any]) -> dict[str, Any] | None:
        relative = entry.get("before_state_file")
        if relative is None:
            return None
        path = (self.directory / str(relative)).resolve()
        if self.directory.resolve() not in path.parents:
            raise ValueError("before-state path escapes the unified runtime directory")
        return read_private_json(path)
