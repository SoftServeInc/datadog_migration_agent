from __future__ import annotations

import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
ORCHESTRATOR = ROOT / ".agents/skills/observability-migration-orchestrator/scripts"
sys.path.insert(0, str(ORCHESTRATOR))

from orchestration_core.approval import create_apply_approval, validate_apply_approval  # noqa: E402
from orchestration_core.browser_evidence import build_browser_draft, seal_browser_evidence  # noqa: E402
from orchestration_core.bundle import seal_bundle, topological_layers, validate_bundle  # noqa: E402
from orchestration_core.bridges import DashboardSessionBridge  # noqa: E402
from orchestration_core.legacy_bundle import preflight_bundle  # noqa: E402
from orchestration_core.scheduler import (  # noqa: E402
    AdapterExecutionError,
    AdapterPreflightDefer,
    AdapterRegistry,
    MigrationScheduler,
    SchedulerPolicy,
)
from orchestration_core.state import UnifiedStore  # noqa: E402


PLAN_HASH = "a" * 64
TARGET = {"origin": "https://api.eu1.example.invalid", "organization_id_hash": "b" * 64}


def operation(
    operation_id: str, *, dependencies: list[str] | None = None,
    adapter: str = "fake-v1", action: str = "CREATE", status: str = "SUPPORTED",
) -> dict[str, object]:
    return {
        "operation_id": operation_id,
        "object_ref": f"object:{operation_id}",
        "object_type": "fixture",
        "adapter": adapter,
        "action": action,
        "status": status,
        "dependencies": dependencies or [],
        "payload_hash": "c" * 64 if action not in {"DEFER", "NO_OP"} else None,
        "adapter_input": {},
        "validation": [{"kind": "api_read_back", "required": True}],
        "rollback": {"mode": "owned_create_or_restore_update"},
    }


def bundle(operations: list[dict[str, object]]) -> dict[str, object]:
    return seal_bundle(
        "assessment-unified-test", PLAN_HASH, TARGET, operations,
        created_at=datetime(2026, 8, 27, tzinfo=timezone.utc),
    )


class FakeAdapter:
    def __init__(self) -> None:
        self.applied: list[str] = []
        self.validated: list[str] = []
        self.rolled_back: list[tuple[str, object]] = []
        self.fail_once: set[str] = set()
        self.fail_always: set[str] = set()
        self.updated: set[str] = set()

    def apply(self, item, context):
        operation_id = item["operation_id"]
        self.applied.append(operation_id)
        if operation_id in self.fail_once:
            self.fail_once.remove(operation_id)
            raise AdapterExecutionError("temporary", safe_to_retry=True)
        if operation_id in self.fail_always:
            raise AdapterExecutionError("definitive")
        updated = operation_id in self.updated
        return [{
            "object_ref": item["object_ref"], "object_type": "fixture",
            "target_id": f"target-{operation_id}",
            "disposition": "UPDATED" if updated else "CREATED",
            "payload_hash": item["payload_hash"], "dependencies": item["dependencies"],
            **({"before_state": {"name": "before"}} if updated else {}),
        }]

    def validate(self, item, resources, context):
        self.validated.append(item["operation_id"])
        return [{"kind": "api_read_back", "passed": True}]

    def rollback(self, entry, before_state, context):
        self.rolled_back.append((entry["target_id"], before_state))


class DeferredPreflightAdapter(FakeAdapter):
    def preflight(self, item, context):
        raise AdapterPreflightDefer("slo_target_name_conflict")


class UnifiedSchedulerTests(unittest.TestCase):
    def test_preflight_defers_one_conflict_and_reseals_bundle(self) -> None:
        value = bundle([
            operation("slo", adapter="slo-wave-v1"),
            operation("dashboard", adapter="fake-v1"),
        ])
        registry = AdapterRegistry()
        registry.register("slo-wave-v1", DeferredPreflightAdapter())
        registry.register("fake-v1", FakeAdapter())
        compiled = preflight_bundle(value, registry)
        validate_bundle(compiled)
        deferred, unaffected = compiled["operations"]
        self.assertEqual(deferred["action"], "DEFER")
        self.assertEqual(deferred["status"], "BLOCKED")
        self.assertEqual(deferred["adapter"], "deferred-v1")
        self.assertEqual(
            deferred["adapter_input"], {"reason": "slo_target_name_conflict"},
        )
        self.assertEqual(unaffected, value["operations"][1])
        self.assertNotEqual(compiled["bundle_hash"], value["bundle_hash"])

    def test_dashboard_api_validation_passes_without_browser_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bridge = DashboardSessionBridge.__new__(DashboardSessionBridge)
            bridge.paths = {"result": Path(directory) / "dashboard-result.local.json"}
            bridge.client = object()
            api_result = {
                "validated_dashboard_count": 1,
                "results": [{"object_ref": "dashboard:one", "target_id": "target-1"}],
                "result_hash": "e" * 64,
            }
            with patch(
                "orchestration_core.bridges.validate_dashboards",
                return_value=api_result,
            ):
                evidence = bridge.validate({}, [], {"session_id": "assessment-unified-test"})
            self.assertEqual(evidence[0]["kind"], "api_read_back")
            self.assertEqual(evidence[0]["status"], "passed")
            self.assertEqual(
                evidence[1]["status"],
                "BROWSER_VALIDATION_SKIPPED",
            )

    def test_bundle_rejects_cycles_and_approval_tampering(self) -> None:
        with self.assertRaisesRegex(ValueError, "cycle"):
            bundle([
                operation("one", dependencies=["two"]),
                operation("two", dependencies=["one"]),
            ])
        value = bundle([operation("one")])
        approval = create_apply_approval(value)
        validate_apply_approval(approval, value, TARGET)
        approval["bundle_hash"] = "d" * 64
        with self.assertRaisesRegex(ValueError, "binding"):
            validate_apply_approval(approval, value, TARGET)

    def test_dependency_order_retry_checkpoint_and_resume(self) -> None:
        value = bundle([
            operation("source"),
            operation("dependent", dependencies=["source"]),
        ])
        approval = create_apply_approval(value)
        adapter = FakeAdapter()
        adapter.fail_once.add("source")
        registry = AdapterRegistry()
        registry.register("fake-v1", adapter)
        with tempfile.TemporaryDirectory() as directory:
            scheduler = MigrationScheduler(
                Path(directory), registry,
                SchedulerPolicy(max_workers=2, max_attempts=2, retry_delay_seconds=0),
            )
            checkpoint = scheduler.run(value, approval, TARGET)
            self.assertEqual(checkpoint["status"], "COMPLETED")
            self.assertEqual(adapter.applied, ["source", "source", "dependent"])
            self.assertEqual(adapter.validated, ["source", "dependent"])
            ledger = UnifiedStore(Path(directory), value["session_id"]).load_ledger()
            self.assertEqual(len(ledger["entries"]), 2)
            scheduler.run(value, approval, TARGET)
            self.assertEqual(adapter.applied, ["source", "source", "dependent"])

    def test_failure_does_not_stop_independent_branch_and_blocks_dependent(self) -> None:
        value = bundle([
            operation("broken"), operation("independent"),
            operation("blocked", dependencies=["broken"]),
        ])
        approval = create_apply_approval(value)
        adapter = FakeAdapter()
        adapter.fail_always.add("broken")
        registry = AdapterRegistry()
        registry.register("fake-v1", adapter)
        with tempfile.TemporaryDirectory() as directory:
            checkpoint = MigrationScheduler(Path(directory), registry).run(value, approval, TARGET)
            self.assertEqual(checkpoint["status"], "PARTIAL")
            self.assertEqual(checkpoint["operations"]["broken"]["status"], "FAILED")
            self.assertEqual(checkpoint["operations"]["blocked"]["status"], "BLOCKED")
            self.assertEqual(checkpoint["operations"]["independent"]["status"], "COMPLETED")

    def test_deferred_scope_is_explicit_partial_not_failure(self) -> None:
        value = bundle([operation("deferred", action="DEFER", status="UNSUPPORTED")])
        approval = create_apply_approval(value)
        with tempfile.TemporaryDirectory() as directory:
            checkpoint = MigrationScheduler(Path(directory), AdapterRegistry()).run(value, approval, TARGET)
            self.assertEqual(checkpoint["status"], "PARTIAL")
            self.assertEqual(checkpoint["operations"]["deferred"]["status"], "SKIPPED")

    def test_rollback_reverses_dependencies_and_restores_updates(self) -> None:
        value = bundle([
            operation("parent"), operation("child", dependencies=["parent"]),
        ])
        approval = create_apply_approval(value)
        adapter = FakeAdapter()
        adapter.updated.add("parent")
        registry = AdapterRegistry()
        registry.register("fake-v1", adapter)
        with tempfile.TemporaryDirectory() as directory:
            scheduler = MigrationScheduler(Path(directory), registry)
            self.assertEqual(scheduler.run(value, approval, TARGET)["status"], "COMPLETED")
            result = scheduler.rollback(value, TARGET, confirmed=True)
            self.assertEqual(result["status"], "ROLLED_BACK")
            self.assertEqual(adapter.rolled_back[0][0], "target-child")
            self.assertEqual(adapter.rolled_back[1], ("target-parent", {"name": "before"}))

    def test_bundle_layers_are_deterministic(self) -> None:
        value = bundle([
            operation("c", dependencies=["a"]), operation("b"), operation("a"),
        ])
        validate_bundle(value)
        self.assertEqual(topological_layers(value), [["a", "b"], ["c"]])

    def test_browser_evidence_is_bound_and_requires_every_check(self) -> None:
        result = {
            "session_id": "assessment-unified-test", "result_hash": "e" * 64,
            "results": [{"object_ref": "dashboard:one", "target_id": "target-1"}],
        }
        draft = build_browser_draft(result)
        with self.assertRaisesRegex(ValueError, "incomplete"):
            seal_browser_evidence(result, draft)
        for value in draft["dashboards"][0]["checks"]:
            draft["dashboards"][0]["checks"][value] = True
        evidence = seal_browser_evidence(result, draft)
        self.assertTrue(evidence["dashboards"][0]["passed"])
        draft["dashboards"][0]["target_id_hash"] = "f" * 64
        with self.assertRaisesRegex(ValueError, "scope"):
            seal_browser_evidence(result, draft)


if __name__ == "__main__":
    unittest.main()
