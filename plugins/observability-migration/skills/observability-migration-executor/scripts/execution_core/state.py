"""Tamper-evident, resumable checkpoint for one migration execution wave."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .common import OBJECT_REF, SHA256, atomic_write_json, canonical_hash, execution_directory, read_private_json


STATUSES = {"AUTHORIZED", "EXECUTING", "PARTIAL", "COMPLETED", "VALIDATED", "FAILED"}
OUTCOMES = {"created", "reused"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class ExecutionCheckpoint:
    source_session_id: str
    wave_id: str
    plan_hash: str
    manifest_hash: str
    authorization_hash: str
    status: str = "AUTHORIZED"
    created_at: str = field(default_factory=_now)
    updated_at: str = field(default_factory=_now)
    results: list[dict[str, Any]] = field(default_factory=list)
    pending_create_refs: list[str] = field(default_factory=list)
    created_count: int = 0
    reused_count: int = 0
    validated_count: int = 0
    failure_category: str | None = None
    checkpoint_hash: str = ""

    def seal(self) -> None:
        self.updated_at = _now()
        value = asdict(self)
        self.checkpoint_hash = canonical_hash(value, "checkpoint_hash")


class ExecutionStore:
    def __init__(self, work_root: Path, session_id: str, wave_id: str):
        self.directory = execution_directory(work_root, session_id, wave_id)
        self.path = self.directory / "execution-checkpoint.local.json"

    def create(self, manifest: dict[str, Any], authorization: dict[str, Any]) -> ExecutionCheckpoint:
        if self.path.exists():
            return self.load()
        checkpoint = ExecutionCheckpoint(
            source_session_id=manifest["source_session_id"],
            wave_id=manifest["wave_id"],
            plan_hash=manifest["plan_hash"],
            manifest_hash=manifest["manifest_hash"],
            authorization_hash=authorization["approval_hash"],
        )
        self.save(checkpoint)
        return checkpoint

    def save(self, checkpoint: ExecutionCheckpoint) -> None:
        checkpoint.seal()
        atomic_write_json(self.path, asdict(checkpoint))

    def load(self) -> ExecutionCheckpoint:
        value = read_private_json(self.path)
        expected = set(ExecutionCheckpoint.__dataclass_fields__)
        if set(value) != expected:
            raise ValueError("execution checkpoint fields are invalid")
        checkpoint = ExecutionCheckpoint(**value)
        if checkpoint.status not in STATUSES:
            raise ValueError("execution checkpoint status is invalid")
        if not all(SHA256.fullmatch(str(item)) for item in (
            checkpoint.plan_hash, checkpoint.manifest_hash, checkpoint.authorization_hash,
            checkpoint.checkpoint_hash,
        )):
            raise ValueError("execution checkpoint hash field is invalid")
        if checkpoint.checkpoint_hash != canonical_hash(value, "checkpoint_hash"):
            raise ValueError("execution checkpoint hash mismatch")
        if any(not isinstance(count, int) or isinstance(count, bool) or count < 0 for count in (
            checkpoint.created_count, checkpoint.reused_count, checkpoint.validated_count,
        )):
            raise ValueError("execution checkpoint counts are invalid")
        seen: set[str] = set()
        for result in checkpoint.results:
            if not isinstance(result, dict) or set(result) != {
                "object_ref", "execution_key", "target_kind", "outcome", "target_id", "validated",
            }:
                raise ValueError("execution checkpoint result fields are invalid")
            if result["outcome"] not in OUTCOMES or result["object_ref"] in seen:
                raise ValueError("execution checkpoint result is invalid or duplicated")
            if not isinstance(result["target_id"], str) or not result["target_id"]:
                raise ValueError("execution checkpoint target ID is invalid")
            seen.add(result["object_ref"])
        if (
            not isinstance(checkpoint.pending_create_refs, list)
            or len(set(checkpoint.pending_create_refs)) != len(checkpoint.pending_create_refs)
            or any(not isinstance(item, str) or not OBJECT_REF.fullmatch(item) or item in seen for item in checkpoint.pending_create_refs)
        ):
            raise ValueError("execution checkpoint pending-create references are invalid")
        if checkpoint.created_count + checkpoint.reused_count != len(checkpoint.results):
            raise ValueError("execution checkpoint result counts do not reconcile")
        if checkpoint.validated_count > len(checkpoint.results):
            raise ValueError("execution checkpoint validation count is invalid")
        return checkpoint


__all__ = ["ExecutionCheckpoint", "ExecutionStore"]
