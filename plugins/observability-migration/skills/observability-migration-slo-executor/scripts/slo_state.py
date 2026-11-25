"""Tamper-evident checkpoint for one SLO execution wave."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from slo_common import (
    OBJECT_REF, SHA256, atomic_write_json, canonical_hash, read_private_json,
    slo_execution_directory,
)


STATUSES = {"AUTHORIZED", "EXECUTING", "COMPLETED", "VALIDATED", "FAILED"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class SloCheckpoint:
    source_session_id: str
    wave_id: str
    plan_hash: str
    manifest_hash: str
    authorization_hash: str
    status: str = "AUTHORIZED"
    created_at: str = field(default_factory=_now)
    updated_at: str = field(default_factory=_now)
    result: dict[str, Any] | None = None
    pending_create_ref: str | None = None
    failure_category: str | None = None
    checkpoint_hash: str = ""

    def seal(self) -> None:
        self.updated_at = _now()
        self.checkpoint_hash = canonical_hash(asdict(self), "checkpoint_hash")


class SloStore:
    def __init__(self, work_root: Path, session_id: str, wave_id: str):
        self.directory = slo_execution_directory(work_root, session_id, wave_id)
        self.path = self.directory / "execution-checkpoint.local.json"

    def create(self, manifest: dict[str, Any], authorization: dict[str, Any]) -> SloCheckpoint:
        if self.path.exists():
            return self.load()
        checkpoint = SloCheckpoint(
            source_session_id=manifest["source_session_id"], wave_id=manifest["wave_id"],
            plan_hash=manifest["plan_hash"], manifest_hash=manifest["manifest_hash"],
            authorization_hash=authorization["approval_hash"],
        )
        self.save(checkpoint)
        return checkpoint

    def save(self, checkpoint: SloCheckpoint) -> None:
        checkpoint.seal()
        atomic_write_json(self.path, asdict(checkpoint))

    def load(self) -> SloCheckpoint:
        value = read_private_json(self.path)
        if set(value) != set(SloCheckpoint.__dataclass_fields__):
            raise ValueError("SLO checkpoint fields are invalid")
        checkpoint = SloCheckpoint(**value)
        if checkpoint.status not in STATUSES:
            raise ValueError("SLO checkpoint status is invalid")
        if not all(SHA256.fullmatch(str(item)) for item in (
            checkpoint.plan_hash, checkpoint.manifest_hash,
            checkpoint.authorization_hash, checkpoint.checkpoint_hash,
        )):
            raise ValueError("SLO checkpoint hash field is invalid")
        if checkpoint.checkpoint_hash != canonical_hash(value, "checkpoint_hash"):
            raise ValueError("SLO checkpoint hash mismatch")
        if checkpoint.pending_create_ref is not None and not OBJECT_REF.fullmatch(checkpoint.pending_create_ref):
            raise ValueError("SLO pending-create reference is invalid")
        if checkpoint.status in {"COMPLETED", "VALIDATED"} and checkpoint.result is None:
            raise ValueError("completed SLO checkpoint requires a result")
        if checkpoint.pending_create_ref is not None and checkpoint.status not in {"EXECUTING", "FAILED"}:
            raise ValueError("SLO pending-create state is invalid")
        if checkpoint.result is not None:
            expected = {"object_ref", "source_refs", "execution_key", "target_kind", "outcome", "target_id", "validated"}
            if not isinstance(checkpoint.result, dict) or set(checkpoint.result) != expected:
                raise ValueError("SLO checkpoint result fields are invalid")
            if checkpoint.result["outcome"] not in {"created", "reused"} or checkpoint.result["target_kind"] != "slo":
                raise ValueError("SLO checkpoint result is invalid")
            if not isinstance(checkpoint.result["target_id"], str) or not checkpoint.result["target_id"]:
                raise ValueError("SLO checkpoint target ID is invalid")
            if not isinstance(checkpoint.result["validated"], bool):
                raise ValueError("SLO checkpoint validation flag is invalid")
            refs = checkpoint.result["source_refs"]
            if (
                not isinstance(refs, list) or len(refs) != 3 or len(set(refs)) != 3
                or refs[0] != checkpoint.result["object_ref"]
                or any(not OBJECT_REF.fullmatch(str(item)) for item in refs)
                or not OBJECT_REF.fullmatch(str(checkpoint.result["object_ref"]))
                or not SHA256.fullmatch(str(checkpoint.result["execution_key"]))
            ):
                raise ValueError("SLO checkpoint source refs are invalid")
            if checkpoint.pending_create_ref is not None:
                raise ValueError("completed SLO checkpoint cannot retain a pending create")
            if checkpoint.status in {"COMPLETED", "VALIDATED"} and not checkpoint.result["validated"]:
                raise ValueError("completed SLO checkpoint must be validated")
        return checkpoint


__all__ = ["SloCheckpoint", "SloStore"]
