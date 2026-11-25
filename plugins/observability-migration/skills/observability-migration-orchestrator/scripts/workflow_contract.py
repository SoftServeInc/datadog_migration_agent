"""Deterministic contract for the customer-facing migration lifecycle.

Only two transitions require customer approval. Compilation batches, retries,
object adapters, and validation waves are implementation details.
"""

from __future__ import annotations

from pathlib import Path
import sys


ASSESSMENT_SCRIPTS = Path(__file__).resolve().parents[2] / "observability-migration-assessment" / "scripts"
sys.path.insert(0, str(ASSESSMENT_SCRIPTS))

from assessment_core.model import SessionState as Stage  # noqa: E402
from assessment_core.state import TRANSITIONS  # noqa: E402


APPROVAL_TRANSITIONS = {
    (Stage.WAITING_PLAN_APPROVAL, Stage.MIGRATING): 1,
    (Stage.WAITING_FINAL_APPROVAL, Stage.COMPLETED): 2,
}


def advance(current: Stage, target: Stage) -> Stage:
    if target not in TRANSITIONS[current]:
        raise ValueError(f"INVALID_STATE_TRANSITION: {current.value} -> {target.value}")
    return target


def approval_count(stage: Stage) -> int:
    """Return the ordinal approval represented by a stage, or zero."""

    return {Stage.MIGRATING: 1, Stage.COMPLETED: 2}.get(stage, 0)


def approval_number(current: Stage, target: Stage) -> int | None:
    """Return the customer approval number for a transition, if any."""

    return APPROVAL_TRANSITIONS.get((current, target))


def bundle_change_requires_reapproval(approved_hash: str, candidate_hash: str) -> bool:
    """Apply authorization is reusable only while the immutable bundle is unchanged."""

    return approved_hash != candidate_hash
