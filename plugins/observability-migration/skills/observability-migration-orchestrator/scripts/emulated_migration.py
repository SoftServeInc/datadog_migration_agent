#!/usr/bin/env python3
"""Execute the unified migration against a persistent local target emulator."""

from __future__ import annotations

import argparse
import json
import sys
import threading
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from orchestration_core.approval import create_apply_approval  # noqa: E402
from orchestration_core.bundle import seal_bundle, validate_bundle  # noqa: E402
from orchestration_core.common import atomic_write_json, read_private_json, runtime_directory, value_hash  # noqa: E402
from orchestration_core.scheduler import AdapterExecutionError, AdapterRegistry, MigrationScheduler, SchedulerPolicy  # noqa: E402
from orchestration_core.state import UnifiedStore  # noqa: E402


TARGET = {
    "origin": "https://local-emulator.invalid",
    "organization_id_hash": value_hash("local-emulator-organization"),
}


class LocalTargetAdapter:
    """Small durable target that performs real create/read/delete operations on disk."""

    def __init__(self, target_root: Path, session_id: str):
        self.root = target_root.resolve()
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.root.chmod(0o700)
        self.path = self.root / "target-resources.local.json"
        self.failure_marker = self.root / f"{session_id}.partial-failure-consumed"
        self.session_id = session_id
        self.lock = threading.Lock()

    def _load(self) -> dict[str, Any]:
        return read_private_json(self.path) if self.path.is_file() else {"resources": {}}

    def _save(self, value: dict[str, Any]) -> None:
        atomic_write_json(self.path, value)

    def apply(self, operation: dict[str, Any], context: dict[str, Any]) -> list[dict[str, Any]]:
        # The first designated operation fails definitively once.  The marker is
        # durable, so a new process resumes it successfully from the checkpoint.
        if operation["adapter_input"].get("fail_first_process") and not self.failure_marker.exists():
            self.failure_marker.write_text("consumed\n", encoding="utf-8")
            self.failure_marker.chmod(0o600)
            raise AdapterExecutionError("emulated_partial_target_failure", safe_to_retry=False)
        target_id = f"local-{value_hash([self.session_id, operation['object_ref']])[:20]}"
        with self.lock:
            store = self._load()
            resources = store["resources"]
            existing = resources.get(target_id)
            candidate = {
                "target_id": target_id,
                "session_id": self.session_id,
                "object_ref": operation["object_ref"],
                "object_type": operation["object_type"],
                "payload_hash": operation["payload_hash"],
            }
            if existing is not None and existing != candidate:
                raise AdapterExecutionError("emulated_target_conflict")
            resources[target_id] = candidate
            self._save(store)
        return [{
            "target_id": target_id, "object_ref": operation["object_ref"],
            "object_type": operation["object_type"], "disposition": "CREATED",
            "payload_hash": operation["payload_hash"], "dependencies": operation["dependencies"],
        }]

    def validate(self, operation: dict[str, Any], resources: list[dict[str, Any]], context: dict[str, Any]) -> list[dict[str, Any]]:
        store = self._load()["resources"]
        for resource in resources:
            actual = store.get(resource["target_id"])
            if (
                not isinstance(actual, dict)
                or actual.get("session_id") != self.session_id
                or actual.get("object_ref") != operation["object_ref"]
                or actual.get("payload_hash") != operation["payload_hash"]
            ):
                raise AdapterExecutionError("emulated_api_validation_failed")
        return [{"kind": "api_read_back", "passed": True}]

    def rollback(self, entry: dict[str, Any], before_state: dict[str, Any] | None, context: dict[str, Any]) -> None:
        with self.lock:
            store = self._load()
            actual = store["resources"].get(entry["target_id"])
            if actual is None:
                return
            if actual.get("session_id") != self.session_id or actual.get("object_ref") != entry["object_ref"]:
                raise AdapterExecutionError("emulated_rollback_ownership_mismatch")
            del store["resources"][entry["target_id"]]
            self._save(store)
            if entry["target_id"] in self._load()["resources"]:
                raise AdapterExecutionError("emulated_rollback_verification_failed")


def compile_bundle(work_root: Path, session_id: str) -> dict[str, Any]:
    session_root = work_root / session_id
    checkpoint = read_private_json(session_root / "checkpoint.local.json")
    inventory = read_private_json(session_root / "inventory-ir.json")
    operations: list[dict[str, Any]] = []
    executable_index = 0
    for index, item in enumerate(inventory.get("objects", []), 1):
        if not isinstance(item, dict):
            continue
        object_type = str(item.get("object_type") or "unknown")
        supported = object_type in {"dashboard", "monitor", "slo"}
        operation_id = f"emulator:{index:03d}"
        adapter_input = {"source_kind": object_type}
        if supported:
            executable_index += 1
            adapter_input["fail_first_process"] = executable_index == 1
        operations.append({
            "operation_id": operation_id,
            "object_ref": str(item["object_ref"]),
            "object_type": object_type,
            "adapter": "local-target-v1",
            "action": "CREATE" if supported else "DEFER",
            "status": "SUPPORTED" if supported else "UNSUPPORTED",
            "dependencies": [],
            "payload_hash": value_hash(item) if supported else None,
            "adapter_input": adapter_input,
            "validation": [{"kind": "api_read_back", "required": True}],
            "rollback": {"mode": "owned_create_only"},
        })
    bundle = seal_bundle(session_id, str(checkpoint["plan_hash"]), TARGET, operations)
    runtime = runtime_directory(work_root, session_id)
    atomic_write_json(runtime / "execution-bundle.local.json", bundle)
    return bundle


def sanitized(checkpoint: dict[str, Any]) -> dict[str, Any]:
    states: dict[str, int] = {}
    for operation in checkpoint["operations"].values():
        states[operation["status"]] = states.get(operation["status"], 0) + 1
    return {
        "status": checkpoint["status"], "operation_states": states,
        "resource_count": sum(len(item["resources"]) for item in checkpoint["operations"].values()),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("compile", "apply", "execute", "status", "rollback"))
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--work-root", required=True)
    parser.add_argument("--target-root", required=True)
    parser.add_argument("--env-file")
    parser.add_argument("--approval-receipt")
    parser.add_argument("--confirm-rollback", action="store_true")
    args = parser.parse_args()
    work_root = Path(args.work_root)
    runtime = runtime_directory(work_root, args.session_id)
    bundle_path = runtime / "execution-bundle.local.json"
    approval_path = runtime / "apply-approval.local.json"
    if args.command == "compile":
        bundle = compile_bundle(work_root, args.session_id)
        print(json.dumps({
            "bundle_hash": bundle["bundle_hash"], "target_origin": TARGET["origin"],
            "operation_count": len(bundle["operations"]),
            "prepared_resources": {"objects": len(bundle["operations"])},
            "actions": dict(Counter(item["action"] for item in bundle["operations"])),
            "external_mutations_performed": 0,
        }, sort_keys=True))
        return 0
    bundle = validate_bundle(read_private_json(bundle_path))
    adapter = LocalTargetAdapter(Path(args.target_root), args.session_id)
    registry = AdapterRegistry()
    registry.register("local-target-v1", adapter)
    scheduler = MigrationScheduler(
        work_root, registry,
        SchedulerPolicy(max_workers=2, max_attempts=1, retry_delay_seconds=0, minimum_interval_seconds=0),
    )
    if args.command == "apply":
        if not args.approval_receipt:
            raise ValueError("approval receipt is required")
        receipt_path = Path(args.approval_receipt)
        receipt = read_private_json(receipt_path)
        unsigned = {key: value for key, value in receipt.items() if key != "receipt_hash"}
        if (
            receipt.get("session_id") != args.session_id
            or receipt.get("bound_hash") != bundle["bundle_hash"]
            or receipt.get("user_confirmed") is not True
            or receipt.get("receipt_hash") != value_hash(unsigned)
        ):
            raise ValueError("emulator approval receipt binding is invalid")
        receipt_path.replace(runtime / "interactive-apply-approval.consumed.local.json")
        approval = create_apply_approval(bundle, actor_role="authorized_operator")
        atomic_write_json(approval_path, approval)
        result = scheduler.run(bundle, approval, TARGET)
    elif args.command == "execute":
        approval = read_private_json(approval_path)
        result = scheduler.run(bundle, approval, TARGET)
    elif args.command == "status":
        result = UnifiedStore(work_root, args.session_id).load_checkpoint()
    else:
        result = scheduler.rollback(bundle, TARGET, confirmed=args.confirm_rollback)
    print(json.dumps(sanitized(result), sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
