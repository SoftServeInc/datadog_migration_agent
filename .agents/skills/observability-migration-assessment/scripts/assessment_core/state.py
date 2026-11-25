"""Atomic, resumable assessment checkpoints and strict workflow transitions."""

from __future__ import annotations

import fcntl
import json
import re
import secrets
import shutil
import uuid
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from .model import SessionState, ValidationState
from .security import atomic_write_json, ensure_private_directory


SESSION_ID = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{7,63}$")
TRANSITIONS = {
    SessionState.DISCOVERY: {SessionState.PLAN_REVIEW},
    SessionState.PLAN_REVIEW: {SessionState.WAITING_PLAN_APPROVAL},
    SessionState.WAITING_PLAN_APPROVAL: {SessionState.MIGRATING, SessionState.FAILED},
    SessionState.MIGRATING: {SessionState.VALIDATING, SessionState.FAILED},
    SessionState.VALIDATING: {SessionState.REVIEW_READY, SessionState.FAILED},
    SessionState.REVIEW_READY: {SessionState.WAITING_FINAL_APPROVAL},
    SessionState.WAITING_FINAL_APPROVAL: {
        SessionState.COMPLETED, SessionState.ROLLING_BACK,
    },
    SessionState.ROLLING_BACK: {SessionState.ROLLED_BACK, SessionState.FAILED},
    SessionState.COMPLETED: set(),
    SessionState.ROLLED_BACK: set(),
    SessionState.FAILED: {
        SessionState.WAITING_PLAN_APPROVAL,
        SessionState.MIGRATING,
        SessionState.ROLLING_BACK,
    },
}

RECOVERABLE_FAILURE_TARGETS = {
    SessionState.WAITING_PLAN_APPROVAL,
    SessionState.MIGRATING,
    SessionState.ROLLING_BACK,
}


STAGE_PRESENTATION = {
    SessionState.DISCOVERY: (
        "Discovery", "Collecting Datadog resources", "Complete discovery",
    ),
    SessionState.PLAN_REVIEW: (
        "Discovery", "Discovery complete", "Continue to plan review",
    ),
    SessionState.WAITING_PLAN_APPROVAL: (
        "Plan Review", "Reviewing selected and deferred resources", "Approve or reject plan",
    ),
    SessionState.MIGRATING: (
        "Migration", "Applying the approved migration", "Wait for migration progress",
    ),
    SessionState.VALIDATING: (
        "Migration", "Running required API validation", "Wait for API validation",
    ),
    SessionState.REVIEW_READY: (
        "Results", "Preparing migration results", "Open final review",
    ),
    SessionState.WAITING_FINAL_APPROVAL: (
        "Results", "Reviewing migration results", "Approve migration or rollback",
    ),
    SessionState.COMPLETED: (
        "Results", "Migration completed", "No action required",
    ),
    SessionState.ROLLING_BACK: (
        "Results", "Rolling back created resources", "Wait for rollback",
    ),
    SessionState.ROLLED_BACK: (
        "Results", "Rollback completed", "No action required",
    ),
    SessionState.FAILED: (
        "Results", "Migration needs attention", "Choose an available recovery action",
    ),
}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Session:
    assessment_id: str
    workflow_state: str = SessionState.DISCOVERY.value
    approval_status: str = "NOT_REQUIRED"
    resources_discovered: int = 0
    resources_migrated: int = 0
    resources_deferred: int = 0
    resources_failed: int = 0
    dashboards_total: int = 0
    dashboards_migrated: int = 0
    dashboards_validated: int = 0
    dashboards_failed: int = 0
    monitors_total: int = 0
    monitors_migrated: int = 0
    monitors_validated: int = 0
    monitors_failed: int = 0
    queries_total: int = 0
    queries_migrated: int = 0
    queries_validated: int = 0
    queries_failed: int = 0
    validation_status: str = ValidationState.PENDING.value
    browser_validation_status: str = "NOT_STARTED"
    current_step: str = "Discovery"
    current_operation: str = "Collecting Datadog resources"
    next_action: str = "Complete discovery"
    affected_resources: list[str] = field(default_factory=list)
    resolution: str = ""
    available_actions: list[str] = field(default_factory=list)
    schema_version: str = "2.0"
    revision: int = 0
    previous_state: str = "NONE"
    created_at: str = field(default_factory=now_iso)
    updated_at: str = field(default_factory=now_iso)
    state_entered_at: str = field(default_factory=now_iso)
    last_event: str = "Assessment created"
    last_validation_event: str = ""
    discovery_started_at: str = ""
    discovery_completed_at: str = ""
    local_pseudonym_salt: str = field(default_factory=lambda: secrets.token_hex(32), repr=False)
    target: str = ""
    strategy: str = ""
    artifacts: dict[str, str] = field(default_factory=dict)
    approval_ids: list[str] = field(default_factory=list)
    inventory_origin: str = ""
    plan_hash: str = ""
    mutations_performed: int = 0
    error_code: str = ""
    error_message: str = ""
    expected_state: str = ""
    actual_state: str = ""
    failure_recovery_state: str = ""
    recovery_attempts: int = 0

    @property
    def session_id(self) -> str:
        """Compatibility alias; assessment_id is the persisted identity."""

        return self.assessment_id

    @property
    def state(self) -> str:
        """Read-only compatibility alias for execution adapters."""

        return self.workflow_state

    @classmethod
    def create(cls, session_id: str | None = None) -> "Session":
        identifier = session_id or f"assessment-{uuid.uuid4().hex[:16]}"
        if not SESSION_ID.fullmatch(identifier):
            raise ValueError("session ID must be 8-64 characters using letters, digits, '_' or '-'")
        return cls(assessment_id=identifier)

    def transition(self, target: SessionState, *, event: str = "") -> None:
        current = SessionState(self.workflow_state)
        if target not in TRANSITIONS[current]:
            raise ValueError(f"INVALID_STATE_TRANSITION: {current.value} -> {target.value}")
        timestamp = now_iso()
        self.previous_state = current.value
        self.workflow_state = target.value
        self.current_step, self.current_operation, self.next_action = STAGE_PRESENTATION[target]
        self.updated_at = timestamp
        self.state_entered_at = timestamp
        self.last_event = event or f"{current.value} -> {target.value}"
        if target is SessionState.FAILED:
            recovery = (
                SessionState.MIGRATING
                if current is SessionState.VALIDATING
                else current
                if current in RECOVERABLE_FAILURE_TARGETS
                else None
            )
            self.failure_recovery_state = recovery.value if recovery else ""
            self.available_actions = ["retry"] if recovery else []

    def public_summary(self) -> dict[str, Any]:
        value = asdict(self)
        value.pop("local_pseudonym_salt", None)
        value["artifacts"] = {key: Path(item).name for key, item in self.artifacts.items()}
        return value


class CheckpointStore:
    def __init__(self, work_root: Path):
        self.work_root = ensure_private_directory(work_root)

    def session_directory(self, session_id: str) -> Path:
        if not SESSION_ID.fullmatch(session_id):
            raise ValueError("invalid assessment ID")
        directory = self.work_root / session_id
        if directory.is_symlink():
            raise ValueError("refusing symlink assessment directory")
        return ensure_private_directory(directory)

    @contextmanager
    def _lock(self, session_id: str) -> Iterator[None]:
        lock_path = self.session_directory(session_id) / ".checkpoint.lock"
        with lock_path.open("a+", encoding="utf-8") as stream:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)

    def _path(self, session_id: str) -> Path:
        return self.session_directory(session_id) / "checkpoint.local.json"

    def _load_unlocked(self, session_id: str) -> Session:
        path = self._path(session_id)
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"assessment checkpoint not found: {session_id}")
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError("invalid assessment checkpoint")
        expected = set(Session.__dataclass_fields__)
        unknown = set(value) - expected
        if unknown:
            raise ValueError("checkpoint fields do not match the assessment schema")
        defaults = Session.create(session_id)
        for name in expected - set(value):
            value[name] = getattr(defaults, name)
        session = Session(**value)
        if session.assessment_id != session_id or session.schema_version != "2.0":
            raise ValueError("checkpoint identity or schema mismatch")
        SessionState(session.workflow_state)
        ValidationState(session.validation_status)
        counters = (
            session.resources_discovered, session.resources_migrated,
            session.resources_deferred, session.resources_failed,
            session.dashboards_total, session.dashboards_migrated,
            session.dashboards_validated, session.dashboards_failed,
            session.monitors_total, session.monitors_migrated,
            session.monitors_validated, session.monitors_failed,
            session.queries_total, session.queries_migrated,
            session.queries_validated, session.queries_failed,
        )
        if any(not isinstance(value, int) or value < 0 for value in counters):
            raise ValueError("checkpoint counters are invalid")
        if session.resources_migrated > session.resources_discovered:
            raise ValueError("migrated resource count exceeds discovered resources")
        if (
            session.resources_migrated
            + session.resources_deferred
            + session.resources_failed
            > session.resources_discovered
        ):
            raise ValueError("accounted resources exceed discovered resources")
        if session.dashboards_validated > session.dashboards_total:
            raise ValueError("dashboard validation count exceeds total")
        if session.monitors_validated > session.monitors_total:
            raise ValueError("monitor validation count exceeds total")
        if session.queries_validated > session.queries_total:
            raise ValueError("query validation count exceeds total")
        if session.dashboards_migrated > session.dashboards_total:
            raise ValueError("migrated dashboard count exceeds total")
        if session.monitors_migrated > session.monitors_total:
            raise ValueError("migrated monitor count exceeds total")
        if session.queries_migrated > session.queries_total:
            raise ValueError("migrated query count exceeds total")
        if not re.fullmatch(r"[a-f0-9]{64}", session.local_pseudonym_salt):
            raise ValueError("checkpoint pseudonym salt is invalid")
        if session.target not in {"", "splunk_observability_cloud", "splunk_platform", "both"}:
            raise ValueError("checkpoint target is invalid")
        if session.strategy not in {"", "full", "safe_staged", "customer_selected"}:
            raise ValueError("checkpoint strategy is invalid")
        if session.failure_recovery_state not in {
            "", *[state.value for state in RECOVERABLE_FAILURE_TARGETS]
        }:
            raise ValueError("checkpoint failure recovery state is invalid")
        if (
            not isinstance(session.recovery_attempts, int)
            or isinstance(session.recovery_attempts, bool)
            or session.recovery_attempts < 0
        ):
            raise ValueError("checkpoint recovery attempts are invalid")
        if not isinstance(session.approval_ids, list) or any(
            not re.fullmatch(r"approval-[a-f0-9]{16}", str(value)) for value in session.approval_ids
        ):
            raise ValueError("checkpoint approvals are invalid")
        if not isinstance(session.artifacts, dict) or not all(
            isinstance(key, str) and isinstance(item, str) for key, item in session.artifacts.items()
        ):
            raise ValueError("checkpoint artifacts are invalid")
        if not all(
            isinstance(value, str) and value
            for value in (session.current_step, session.current_operation, session.next_action)
        ):
            raise ValueError("assessment visibility fields are missing")
        if not isinstance(session.affected_resources, list) or not isinstance(
            session.available_actions, list
        ):
            raise ValueError("assessment recovery fields are invalid")
        return session

    @staticmethod
    def _assert_persistence_invariants(prior: Session, candidate: Session) -> None:
        if prior.assessment_id != candidate.assessment_id:
            raise ValueError("CORRUPTED_SESSION: assessmentId changed")
        monotonic = (
            "resources_discovered", "resources_migrated",
            "dashboards_total", "dashboards_migrated", "dashboards_validated",
            "monitors_total", "monitors_migrated", "monitors_validated",
            "queries_total", "queries_migrated", "queries_validated",
            "mutations_performed", "recovery_attempts",
        )
        regressed = [
            name for name in monotonic
            if getattr(candidate, name) < getattr(prior, name)
        ]
        if regressed:
            raise ValueError(
                "CORRUPTED_SESSION: persisted counters decreased: " + ", ".join(regressed)
            )

    def _transition_log(self, session: Session) -> None:
        path = self.session_directory(session.assessment_id) / "workflow-transitions.local.jsonl"
        record = {
            "timestamp": session.updated_at,
            "assessment_id": session.assessment_id,
            "previous_state": session.previous_state,
            "new_state": session.workflow_state,
            "approval_status": session.approval_status,
            "revision": session.revision,
        }
        with path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")

    def save(self, session: Session) -> Path:
        path = self._path(session.assessment_id)
        with self._lock(session.assessment_id):
            prior = self._load_unlocked(session.assessment_id) if path.is_file() else None
            actual_revision = prior.revision if prior else 0
            if session.revision != actual_revision:
                raise ValueError(
                    f"STALE_ASSESSMENT_WRITE: expected revision {session.revision}, "
                    f"actual {actual_revision}"
                )
            if prior:
                self._assert_persistence_invariants(prior, session)
            if prior and prior.workflow_state != session.workflow_state:
                current = SessionState(prior.workflow_state)
                target = SessionState(session.workflow_state)
                if target not in TRANSITIONS[current]:
                    raise ValueError(
                        f"INVALID_STATE_TRANSITION: {current.value} -> {target.value}"
                    )
                if current is SessionState.FAILED:
                    recovery = SessionState(prior.failure_recovery_state) if prior.failure_recovery_state else None
                    rollback_allowed = (
                        target is SessionState.ROLLING_BACK
                        and prior.mutations_performed > 0
                    )
                    if target is not recovery and not rollback_allowed:
                        raise ValueError(
                            f"INVALID_STATE_TRANSITION: {current.value} -> {target.value}"
                        )
            session.revision += 1
            session.updated_at = now_iso()
            atomic_write_json(path, asdict(session))
            if prior is None or prior.workflow_state != session.workflow_state:
                self._transition_log(session)
        return path

    def load(self, session_id: str) -> Session:
        with self._lock(session_id):
            return self._load_unlocked(session_id)

    def transition(
        self,
        session_id: str,
        expected: SessionState,
        target: SessionState,
        *,
        approval_status: str | None = None,
        event: str = "",
        updates: dict[str, Any] | None = None,
    ) -> Session:
        with self._lock(session_id):
            session = self._load_unlocked(session_id)
            if session.workflow_state != expected.value:
                raise ValueError(
                    f"INVALID_STATE_TRANSITION: expected {expected.value}, "
                    f"actual {session.workflow_state}"
                )
            session.transition(target, event=event)
            if expected is SessionState.FAILED:
                recovery = SessionState(session.failure_recovery_state) if session.failure_recovery_state else None
                if target is not recovery and not (
                    target is SessionState.ROLLING_BACK and session.mutations_performed > 0
                ):
                    raise ValueError(
                        f"INVALID_STATE_TRANSITION: {expected.value} -> {target.value}"
                    )
            if approval_status is not None:
                session.approval_status = approval_status
            for key, value in (updates or {}).items():
                if key not in Session.__dataclass_fields__:
                    raise ValueError(f"unknown assessment field: {key}")
                setattr(session, key, value)
            session.revision += 1
            atomic_write_json(self._path(session_id), asdict(session))
            self._transition_log(session)
            return session

    def claim_discovery(self, session_id: str) -> Session:
        with self._lock(session_id):
            session = self._load_unlocked(session_id)
            if session.workflow_state != SessionState.DISCOVERY.value or session.discovery_started_at:
                raise ValueError(
                    "INVALID_STATE_TRANSITION: discovery may run only once per assessment"
                )
            timestamp = now_iso()
            session.discovery_started_at = timestamp
            session.last_event = "Discovery started"
            session.updated_at = timestamp
            session.revision += 1
            atomic_write_json(self._path(session_id), asdict(session))
            return session

    def block(
        self,
        session_id: str,
        *,
        error_code: str,
        error_message: str,
        expected_state: str = "",
        recovery_state: SessionState | None = None,
        available_actions: list[str] | None = None,
        mutations_performed: int | None = None,
    ) -> Session:
        with self._lock(session_id):
            session = self._load_unlocked(session_id)
            if session.workflow_state in {
                SessionState.COMPLETED.value, SessionState.ROLLED_BACK.value,
            }:
                raise ValueError("terminal assessment cannot become failed")
            if session.workflow_state == SessionState.FAILED.value:
                return session
            if mutations_performed is not None:
                if not isinstance(mutations_performed, int) or mutations_performed < 0:
                    raise ValueError("mutation count is invalid")
                session.mutations_performed = max(session.mutations_performed, mutations_performed)
            actual = session.workflow_state
            session.transition(SessionState.FAILED, event=error_message)
            session.error_code = error_code
            session.error_message = error_message
            session.expected_state = expected_state
            session.actual_state = actual
            session.current_operation = "Execution stopped"
            session.next_action = "Choose an available recovery action"
            session.resolution = error_message
            candidate = recovery_state
            if candidate is None and actual in {
                SessionState.WAITING_PLAN_APPROVAL.value,
                SessionState.MIGRATING.value,
                SessionState.VALIDATING.value,
            }:
                candidate = (
                    SessionState.MIGRATING
                    if actual == SessionState.VALIDATING.value
                    else SessionState(actual)
                )
            if not isinstance(candidate, SessionState) or candidate not in RECOVERABLE_FAILURE_TARGETS:
                candidate = None
            session.failure_recovery_state = candidate.value if candidate else ""
            actions = list(available_actions) if available_actions is not None else (
                ["retry"] if candidate is not None else []
            )
            if session.mutations_performed > 0 and "rollback" not in actions:
                actions.append("rollback")
            session.available_actions = actions
            session.revision += 1
            atomic_write_json(self._path(session_id), asdict(session))
            self._transition_log(session)
            return session

    def recover(
        self,
        session_id: str,
        target: SessionState,
        *,
        event: str = "",
    ) -> Session:
        with self._lock(session_id):
            session = self._load_unlocked(session_id)
            if session.workflow_state != SessionState.FAILED.value:
                raise ValueError(
                    f"INVALID_STATE_TRANSITION: expected FAILED, actual {session.workflow_state}"
                )
            recovery = SessionState(session.failure_recovery_state) if session.failure_recovery_state else None
            if target is not recovery and not (
                target is SessionState.ROLLING_BACK and session.mutations_performed > 0
            ):
                raise ValueError(
                    f"INVALID_STATE_TRANSITION: expected FAILED recovery to "
                    f"{session.failure_recovery_state or 'NONE'}, actual {target.value}"
                )
            required_action = "rollback" if target is SessionState.ROLLING_BACK else "retry"
            if required_action not in session.available_actions:
                raise ValueError(
                    f"INVALID_STATE_TRANSITION: FAILED action {required_action} is unavailable"
                )
            session.transition(target, event=event or f"Recovery started: {target.value}")
            session.failure_recovery_state = ""
            session.recovery_attempts += 1
            session.available_actions = []
            session.revision += 1
            atomic_write_json(self._path(session_id), asdict(session))
            self._transition_log(session)
            return session

    def delete(self, session_id: str) -> Path:
        if not SESSION_ID.fullmatch(session_id):
            raise ValueError("invalid session ID")
        directory = self.work_root / session_id
        if directory.is_symlink() or not directory.is_dir():
            raise ValueError(f"session directory not found or unsafe: {session_id}")
        resolved = directory.resolve(strict=True)
        if resolved.parent != self.work_root.resolve(strict=True):
            raise ValueError("session directory escapes the work root")
        for child in resolved.rglob("*"):
            if child.is_symlink():
                raise ValueError("refusing cleanup because the session contains a symlink")
            if not child.is_dir() and not child.is_file():
                raise ValueError("refusing cleanup because the session contains a special file")
        shutil.rmtree(resolved)
        return resolved
