import sys
import subprocess
import json
import tempfile
import unittest
from argparse import Namespace
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from io import StringIO
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".agents/skills/observability-migration-orchestrator/scripts"))
sys.path.insert(0, str(ROOT / ".agents/skills/observability-migration-executor/scripts"))
from workflow_contract import (  # noqa: E402
    Stage,
    advance,
    approval_count,
    approval_number,
    bundle_change_requires_reapproval,
)
from cleanup_created import (  # noqa: E402
    CLEANUP_PRIORITY, inspect_targets, revoke_session_apply_authorizations, value_hash,
)
import apply_action_server as action_server  # noqa: E402
from execution_core.provenance import load_approved_plan  # noqa: E402
from migration_assessment import command_prepare  # noqa: E402
from assessment_core.model import SessionState, ValidationState  # noqa: E402
from assessment_core.state import CheckpointStore, Session  # noqa: E402


FLOW = [
    SessionState.PLAN_REVIEW,
    SessionState.WAITING_PLAN_APPROVAL,
    SessionState.MIGRATING,
    SessionState.VALIDATING,
    SessionState.REVIEW_READY,
    SessionState.WAITING_FINAL_APPROVAL,
    SessionState.COMPLETED,
]


def persist_assessment(work_root: Path, session_id: str, target: SessionState, **updates):
    work_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    work_root.chmod(0o700)
    session_root = work_root / session_id
    session_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    session_root.chmod(0o700)
    store = CheckpointStore(work_root)
    session = Session.create(session_id)
    for key, value in updates.items():
        setattr(session, key, value)
    store.save(session)
    for state in FLOW:
        if target is SessionState.DISCOVERY:
            break
        session = store.transition(session_id, SessionState(session.workflow_state), state)
        if state is target:
            break
    return store.load(session_id)


class OrchestratorFlowTests(unittest.TestCase):
    def test_control_center_is_a_versioned_mcp_app_resource(self):
        descriptors = {item["name"]: item for item in action_server._tool_definitions()}
        control = descriptors["open_migration_control_center"]
        self.assertEqual(
            control["_meta"]["ui"]["resourceUri"], action_server.CONTROL_CENTER_URI,
        )
        self.assertEqual(
            control["_meta"]["openai/outputTemplate"], action_server.CONTROL_CENTER_URI,
        )
        self.assertEqual(control["inputSchema"].get("required"), None)
        self.assertTrue(control["annotations"]["readOnlyHint"])
        self.assertFalse(control["annotations"]["destructiveHint"])
        rollback = descriptors["rollback_migration"]
        self.assertTrue(rollback["annotations"]["destructiveHint"])
        terraform = descriptors["generate_terraform_code"]
        self.assertFalse(terraform["annotations"]["readOnlyHint"])
        self.assertFalse(terraform["annotations"]["destructiveHint"])
        self.assertFalse(terraform["annotations"]["openWorldHint"])
        self.assertTrue(terraform["annotations"]["idempotentHint"])
        for descriptor in descriptors.values():
            self.assertEqual(descriptor["_meta"]["ui"]["visibility"], ["model", "app"])
            self.assertTrue(descriptor["_meta"]["openai/widgetAccessible"])
        resource = action_server._read_resource(action_server.CONTROL_CENTER_URI, {})
        content = resource["contents"][0]
        self.assertEqual(content["mimeType"], "text/html;profile=mcp-app")
        self.assertEqual(content["_meta"]["ui"]["csp"], {
            "connectDomains": [], "resourceDomains": [],
        })
        self.assertIn("ui/notifications/tool-result", content["text"])
        self.assertIn('rpc("tools/call"', content["text"])
        self.assertIn("window.openai.callTool", content["text"])
        self.assertNotIn("ui/message", content["text"])
        self.assertNotIn("sendFollowUpMessage", content["text"])
        self.assertIn("resourceRows", content["text"])
        self.assertNotIn("window.confirm", content["text"])
        self.assertIn("confirmationKey", content["text"])

    def test_control_center_opens_before_a_session_exists(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            result = action_server.open_migration_control_center({
                "workspace_root": str(workspace),
                "work_root": str(workspace / ".migration-work"),
            })
            self.assertEqual(result["structuredContent"]["phase"], "READY")
            self.assertEqual(result["structuredContent"]["resourceSummary"]["total"], 0)
            self.assertEqual(result["_meta"]["resourceRows"], [])
            binding = result["_meta"]["actionBindings"][0]
            self.assertEqual(binding["kind"], "tool")
            self.assertEqual(binding["tool"], "start_read_only_assessment")
            self.assertNotIn("prompt", binding)

    def test_control_center_resolves_relative_paths_from_customer_workspace(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            result = action_server.open_migration_control_center({
                "workspace_root": str(workspace),
                "work_root": ".observability-migration",
                "env_file": ".env",
            })
            arguments = result["_meta"]["actionBindings"][0]["arguments"]
            self.assertEqual(
                arguments["work_root"],
                str((workspace / ".observability-migration").resolve()),
            )
            self.assertEqual(arguments["env_file"], str((workspace / ".env").resolve()))

    def test_control_center_defaults_to_clean_start_with_existing_checkpoint(self):
        fixture = ROOT / "tests/fixtures/datadog_inventory.synthetic.json"
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            env_file = workspace / ".env"
            env_file.write_text("", encoding="utf-8")
            work_root = workspace / ".migration-work"
            args = Namespace(
                env_file=str(env_file), capability_catalog="", inventory=str(fixture),
                work_root=str(work_root), session_id="existing-default-clean",
                target="splunk_observability_cloud", strategy="full", select_ref=[],
            )
            with redirect_stdout(StringIO()):
                command_prepare(args)
            clean = action_server.open_migration_control_center({
                "workspace_root": str(workspace), "work_root": str(work_root),
                "env_file": str(env_file),
            })
            self.assertEqual(clean["structuredContent"]["phase"], "READY")
            self.assertEqual(clean["structuredContent"]["resourceSummary"]["total"], 0)
            self.assertEqual(clean["_meta"]["resourceRows"], [])
            self.assertTrue(clean["_meta"]["actionBindings"][0]["arguments"]["new_run"])
            resumed = action_server.open_migration_control_center({
                "workspace_root": str(workspace), "work_root": str(work_root),
                "env_file": str(env_file), "resume_latest": True,
            })
            self.assertEqual(resumed["structuredContent"]["sessionId"], args.session_id)

    def test_read_only_assessment_tool_never_uses_follow_up_message(self):
        descriptor = {
            item["name"]: item for item in action_server._tool_definitions()
        }["start_read_only_assessment"]
        self.assertTrue(descriptor["annotations"]["readOnlyHint"])
        self.assertFalse(descriptor["annotations"]["destructiveHint"])
        self.assertTrue(descriptor["annotations"]["openWorldHint"])
        self.assertTrue(descriptor["_meta"]["openai/widgetAccessible"])

    def test_control_center_can_start_fresh_without_mutating_existing_checkpoint(self):
        fixture = ROOT / "tests/fixtures/datadog_inventory.synthetic.json"
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            env_file = workspace / ".env"
            env_file.write_text("", encoding="utf-8")
            work_root = workspace / ".migration-work"
            args = Namespace(
                env_file=str(env_file), capability_catalog="", inventory=str(fixture),
                work_root=str(work_root), session_id="existing-control-center",
                target="splunk_observability_cloud", strategy="full", select_ref=[],
            )
            with redirect_stdout(StringIO()):
                command_prepare(args)
            before = CheckpointStore(work_root).load(args.session_id)
            result = action_server.open_migration_control_center({
                "workspace_root": str(workspace), "work_root": str(work_root),
                "env_file": str(env_file), "new_run": True,
            })
            after = CheckpointStore(work_root).load(args.session_id)
            self.assertEqual(result["structuredContent"]["phase"], "READY")
            self.assertEqual(after.revision, before.revision)
            self.assertEqual(after.workflow_state, before.workflow_state)

    def test_terminal_control_center_offers_a_fresh_migration(self):
        paths = {
            "workspace_root": Path("/workspace"),
            "work_root": Path("/workspace/.migration-work"),
            "env_file": Path("/workspace/.env"),
            "session_id": "terminal-session",
            "action_id": "action-unused",
        }
        for terminal in (SessionState.COMPLETED, SessionState.ROLLED_BACK):
            session = Session.create("terminal-session")
            session.workflow_state = terminal.value
            bindings = action_server._control_center_bindings(
                session, {"action_id": "action-terminal"}, paths,
            )
            expected_count = 2 if terminal is SessionState.COMPLETED else 1
            self.assertEqual(len(bindings), expected_count)
            if terminal is SessionState.COMPLETED:
                self.assertEqual(bindings[0]["tool"], "generate_terraform_code")
            fresh = bindings[-1]
            self.assertEqual(fresh["label"], "Start new migration")
            self.assertEqual(fresh["tool"], "start_read_only_assessment")
            self.assertEqual(fresh["arguments"]["new_run"], True)
            self.assertNotIn("session_id", fresh["arguments"])
            self.assertNotIn("action_id", fresh["arguments"])

    def test_control_center_hydrates_named_resources_only_in_widget_metadata(self):
        fixture = ROOT / "tests/fixtures/datadog_inventory.synthetic.json"
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            env_file = workspace / ".env"
            env_file.write_text("", encoding="utf-8")
            work_root = workspace / ".migration-work"
            session_id = "migration-control-center"
            args = Namespace(
                env_file=str(env_file), capability_catalog="", inventory=str(fixture),
                work_root=str(work_root), session_id=session_id,
                target="splunk_observability_cloud", strategy="full", select_ref=[],
            )
            with redirect_stdout(StringIO()):
                command_prepare(args)
            result = action_server.open_migration_control_center({
                "workspace_root": str(workspace), "work_root": str(work_root),
                "env_file": str(env_file), "session_id": session_id,
            })
            structured = result["structuredContent"]
            rows = result["_meta"]["resourceRows"]
            self.assertEqual(structured["phase"], "PLAN_REVIEW")
            self.assertEqual(structured["resourceSummary"]["total"], len(rows))
            self.assertGreater(len(rows), 0)
            self.assertTrue(all(row["name"] and row["type"] for row in rows))
            self.assertTrue(all("source_id" not in row and "object_ref" not in row for row in rows))
            serialized = json.dumps(structured, sort_keys=True)
            for row in rows:
                self.assertNotIn(row["name"], serialized)
            self.assertEqual(
                result["_meta"]["actionBindings"][0]["tool"],
                "continue_to_plan_review",
            )
            continued = action_server.continue_to_plan_review({
                "workspace_root": str(workspace), "work_root": str(work_root),
                "env_file": str(env_file), "session_id": session_id,
                "action_id": result["structuredContent"]["actionId"],
            })
            self.assertEqual(continued["structuredContent"]["phase"], "WAITING_PLAN_APPROVAL")
            self.assertEqual(
                continued["_meta"]["actionBindings"][0]["tool"],
                "approve_migration_scope",
            )
            self.assertIn("review_token", continued["_meta"]["actionBindings"][0]["arguments"])
            reject = continued["_meta"]["actionBindings"][1]
            self.assertEqual(reject["kind"], "tool")
            self.assertEqual(reject["tool"], "reject_migration_scope")
            rejected = action_server.reject_migration_scope(reject["arguments"])
            self.assertEqual(rejected["structuredContent"]["phase"], "FAILED")
            self.assertEqual(rejected["structuredContent"]["progress"]["dashboards"]["migrated"], 0)
            self.assertEqual(
                CheckpointStore(work_root).load(session_id).approval_status,
                "PLAN_REJECTED",
            )

    def test_empty_assessment_cannot_open_migration_review(self):
        with self.assertRaisesRegex(ValueError, "no source objects"):
            action_server._ensure_reviewable_assessment({
                "summary": {"source_object_count": 0},
                "actions": [],
            })

    def test_transparency_snapshot_reports_exact_session_counts_and_state(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            (workspace / ".env").write_text("", encoding="utf-8")
            work_root = workspace / ".migration-work"
            session_id = "migration-transparency-test"
            session_root = work_root / session_id
            runtime = session_root / "unified-execution"
            dashboard = session_root / "dashboard-execution"
            runtime.mkdir(parents=True)
            dashboard.mkdir(parents=True)
            action_id = "action-1234567890abcdef12345678"
            action_server._write_private(runtime / action_server.STATE_FILE, {
                "schema_version": "1.0", "session_id": session_id,
                "action_id": action_id, "state_version": 3, "status": "VALIDATING",
                "created_at": datetime.now(timezone.utc).isoformat(),
                "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
            })
            persist_assessment(
                work_root, session_id, SessionState.VALIDATING,
                resources_discovered=2, resources_migrated=2,
                dashboards_total=1, dashboards_migrated=1, dashboards_validated=1,
                monitors_total=1, monitors_migrated=1, monitors_validated=1,
                queries_total=4, queries_migrated=4, queries_validated=4,
                validation_status=ValidationState.RUNNING.value,
                approval_status="PLAN_APPROVED",
            )
            action_server._write_private(session_root / "inventory-ir.json", {
                "objects": [
                    {"object_ref": "dashboard-1", "object_type": "dashboard",
                     "behavior_features": {"query_count": 3}},
                    {"object_ref": "monitor-1", "object_type": "monitor",
                     "behavior_features": {"query_count": 1}},
                ],
            })
            action_server._write_private(runtime / "execution-checkpoint.local.json", {
                "operations": {
                    "dashboard:session": {"status": "FAILED",
                        "failure_category": "browser_validation_pending",
                        "resources": [{"object_ref": "dashboard-1"}]},
                    "detector:wave": {"status": "COMPLETED", "failure_category": None,
                        "resources": [{"object_ref": "monitor-1"}]},
                },
            })
            result = action_server._attach_transparency(
                {"structuredContent": {"phase": "VALIDATING", "sessionId": session_id,
                    "actionId": action_id, "stateVersion": 3}},
                {"workspace_root": str(workspace), "work_root": str(work_root),
                 "env_file": str(workspace / ".env"), "session_id": session_id},
            )
            transparency = result["structuredContent"]["workflow"]
            self.assertEqual(transparency["currentStep"], "Migration")
            self.assertTrue(transparency["currentOperation"])
            self.assertTrue(transparency["nextAction"])
            self.assertEqual(transparency["dashboards"], {
                "total": 1, "migrated": 1, "validated": 1, "failed": 0,
            })
            self.assertEqual(transparency["monitors"], {
                "total": 1, "migrated": 1, "validated": 1, "failed": 0,
            })
            self.assertEqual(transparency["queries"], {
                "total": 4, "migrated": 4, "validated": 4, "failed": 0,
            })
            self.assertEqual(transparency["validation"]["api"], "RUNNING")
            self.assertEqual(
                transparency["approvalStatus"],
                "PLAN_APPROVED",
            )

    def test_atomic_apply_command_exposes_required_runtime_controls(self):
        script = ROOT / ".agents/skills/observability-migration-orchestrator/scripts/unified_migration.py"
        result = subprocess.run(
            [sys.executable, str(script), "apply", "--help"],
            check=True, capture_output=True, text=True,
        )
        self.assertIn("--approval-receipt", result.stdout)
        self.assertNotIn("--confirm-apply", result.stdout)
        self.assertIn("--env-file", result.stdout)
        self.assertIn("--max-workers", result.stdout)

    def test_failed_scope_compile_blocks_without_reopening_prior_stage(self):
        fixture = ROOT / "tests/fixtures/datadog_inventory.synthetic.json"
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            env_file = workspace / ".env"
            env_file.write_text("", encoding="utf-8")
            work_root = workspace / ".migration-work"
            session_id = "migration-rollback-test"
            args = Namespace(
                env_file=str(env_file), capability_catalog="", inventory=str(fixture),
                work_root=str(work_root), session_id=session_id,
                target="splunk_observability_cloud", strategy="full", select_ref=[],
            )
            with redirect_stdout(StringIO()):
                command_prepare(args)
            checkpoint = json.loads(
                (work_root / session_id / "checkpoint.local.json").read_text(encoding="utf-8")
            )
            review = action_server.review_migration_plan({
                "workspace_root": str(workspace), "work_root": str(work_root),
                "env_file": str(env_file), "session_id": session_id,
                "plan_hash": checkpoint["plan_hash"],
            })
            review = action_server.continue_to_plan_review({
                "workspace_root": str(workspace), "work_root": str(work_root),
                "env_file": str(env_file), "session_id": session_id,
                "action_id": review["structuredContent"]["actionId"],
            })
            with patch.object(action_server, "_run_command", side_effect=RuntimeError("compile broke")):
                with self.assertRaisesRegex(RuntimeError, "scope compilation failed"):
                    action_server.approve_migration_scope({
                        "workspace_root": str(workspace), "work_root": str(work_root),
                        "env_file": str(env_file), "session_id": session_id,
                        "action_id": review["structuredContent"]["actionId"],
                        "scope": "full", "review_token": review["_meta"]["actionBindings"][0]["arguments"]["review_token"],
                    })
            restored = json.loads(
                (work_root / session_id / "checkpoint.local.json").read_text(encoding="utf-8")
            )
            action_state = json.loads(
                (work_root / session_id / "unified-execution/migration-action-state.local.json")
                .read_text(encoding="utf-8")
            )
            self.assertEqual(restored["workflow_state"], "FAILED")
            self.assertEqual(restored["error_code"], "BUNDLE_COMPILATION_FAILURE")
            self.assertEqual(restored["failure_recovery_state"], "MIGRATING")
            self.assertEqual(restored["available_actions"], ["retry"])
            self.assertNotIn("status", action_state)
            self.assertTrue((work_root / session_id / "plan-review-approval.local.json").is_file())
            self.assertEqual(len(restored["approval_ids"]), 1)
            compiled = {"bundle_hash": "a" * 64}
            with (
                patch.object(action_server, "_run_command", return_value=compiled),
                patch.object(action_server, "_start_migration_worker", return_value=True),
            ):
                recovered = action_server.retry_migration_action({
                    "workspace_root": str(workspace), "work_root": str(work_root),
                    "env_file": str(env_file), "session_id": session_id,
                    "action_id": review["structuredContent"]["actionId"],
                })
            self.assertEqual(
                recovered["structuredContent"]["phase"],
                SessionState.MIGRATING.value,
            )

    def test_plan_approval_transaction_persists_verifies_and_continues_execution(self):
        fixture = ROOT / "tests/fixtures/datadog_inventory.synthetic.json"
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            env_file = workspace / ".env"
            env_file.write_text("", encoding="utf-8")
            work_root = workspace / ".migration-work"
            session_id = "migration-approval-transaction"
            args = Namespace(
                env_file=str(env_file), capability_catalog="", inventory=str(fixture),
                work_root=str(work_root), session_id=session_id,
                target="splunk_observability_cloud", strategy="full", select_ref=[],
            )
            with redirect_stdout(StringIO()):
                command_prepare(args)
            checkpoint = json.loads(
                (work_root / session_id / "checkpoint.local.json").read_text(encoding="utf-8")
            )
            review = action_server.review_migration_plan({
                "workspace_root": str(workspace), "work_root": str(work_root),
                "env_file": str(env_file), "session_id": session_id,
                "plan_hash": checkpoint["plan_hash"],
            })
            review = action_server.continue_to_plan_review({
                "workspace_root": str(workspace), "work_root": str(work_root),
                "env_file": str(env_file), "session_id": session_id,
                "action_id": review["structuredContent"]["actionId"],
            })
            compiled = {
                "bundle_hash": "b" * 64,
                "target_origin": "https://api.example.invalid",
                "operation_count": 1,
                "prepared_resources": {"detectors": 1},
                "actions": {"CREATE": 1},
            }
            def compile_after_provenance_check(*_args, **_kwargs):
                loaded = load_approved_plan(work_root, session_id)
                self.assertEqual(loaded["session"].workflow_state, "MIGRATING")
                self.assertEqual(loaded["session"].approval_status, "PLAN_APPROVED")
                return compiled

            with patch.object(
                action_server, "_run_command", side_effect=compile_after_provenance_check
            ), patch.object(
                action_server, "_start_migration_worker", return_value=True
            ) as execute:
                result = action_server.approve_migration_scope({
                    "workspace_root": str(workspace), "work_root": str(work_root),
                    "env_file": str(env_file), "session_id": session_id,
                    "action_id": review["structuredContent"]["actionId"],
                    "scope": "full", "review_token": review["_meta"]["actionBindings"][0]["arguments"]["review_token"],
                })
            self.assertEqual(result["structuredContent"]["phase"], "MIGRATING")
            persisted = json.loads(
                (work_root / session_id / "checkpoint.local.json").read_text(encoding="utf-8")
            )
            approval = json.loads(
                (work_root / session_id / "plan-review-approval.local.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(persisted["workflow_state"], "MIGRATING")
            self.assertEqual(persisted["approval_status"], "PLAN_APPROVED")
            self.assertEqual(persisted["last_event"], "PLAN_APPROVED")
            self.assertIn(approval["approval_id"], persisted["approval_ids"])
            self.assertEqual(execute.call_args.args[0]["bundle_hash"], "b" * 64)

    def test_scope_approval_rejects_another_widget_action_instance(self):
        fixture = ROOT / "tests/fixtures/datadog_inventory.synthetic.json"
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            env_file = workspace / ".env"
            env_file.write_text("", encoding="utf-8")
            work_root = workspace / ".migration-work"
            session_id = "migration-action-binding"
            args = Namespace(
                env_file=str(env_file), capability_catalog="", inventory=str(fixture),
                work_root=str(work_root), session_id=session_id,
                target="splunk_observability_cloud", strategy="full", select_ref=[],
            )
            with redirect_stdout(StringIO()):
                command_prepare(args)
            checkpoint = json.loads(
                (work_root / session_id / "checkpoint.local.json").read_text(encoding="utf-8")
            )
            review = action_server.review_migration_plan({
                "workspace_root": str(workspace), "work_root": str(work_root),
                "env_file": str(env_file), "session_id": session_id,
                "plan_hash": checkpoint["plan_hash"],
            })
            review = action_server.continue_to_plan_review({
                "workspace_root": str(workspace), "work_root": str(work_root),
                "env_file": str(env_file), "session_id": session_id,
                "action_id": review["structuredContent"]["actionId"],
            })
            with self.assertRaisesRegex(ValueError, "stale or invalid"):
                action_server.approve_migration_scope({
                    "workspace_root": str(workspace), "work_root": str(work_root),
                    "env_file": str(env_file), "session_id": session_id,
                    "action_id": "action-000000000000000000000000",
                    "scope": "full", "review_token": review["_meta"]["actionBindings"][0]["arguments"]["review_token"],
                })
            state = json.loads(
                (work_root / session_id / "unified-execution/migration-action-state.local.json")
                .read_text(encoding="utf-8")
            )
            self.assertNotIn("status", state)
            self.assertIn("assessment_revision", state)

    def test_plan_approval_persistence_failure_blocks_without_restart(self):
        fixture = ROOT / "tests/fixtures/datadog_inventory.synthetic.json"
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            env_file = workspace / ".env"
            env_file.write_text("", encoding="utf-8")
            work_root = workspace / ".migration-work"
            session_id = "migration-approval-cas"
            args = Namespace(
                env_file=str(env_file), capability_catalog="", inventory=str(fixture),
                work_root=str(work_root), session_id=session_id,
                target="splunk_observability_cloud", strategy="full", select_ref=[],
            )
            with redirect_stdout(StringIO()):
                command_prepare(args)
            checkpoint = json.loads(
                (work_root / session_id / "checkpoint.local.json").read_text(encoding="utf-8")
            )
            review = action_server.review_migration_plan({
                "workspace_root": str(workspace), "work_root": str(work_root),
                "env_file": str(env_file), "session_id": session_id,
                "plan_hash": checkpoint["plan_hash"],
            })
            review = action_server.continue_to_plan_review({
                "workspace_root": str(workspace), "work_root": str(work_root),
                "env_file": str(env_file), "session_id": session_id,
                "action_id": review["structuredContent"]["actionId"],
            })
            with patch.object(
                CheckpointStore, "transition",
                side_effect=ValueError("simulated persistence failure"),
            ):
                with self.assertRaisesRegex(RuntimeError, "APPROVAL_PERSISTENCE_FAILURE"):
                    action_server.approve_migration_scope({
                        "workspace_root": str(workspace), "work_root": str(work_root),
                        "env_file": str(env_file), "session_id": session_id,
                        "action_id": review["structuredContent"]["actionId"],
                        "scope": "full", "review_token": review["_meta"]["actionBindings"][0]["arguments"]["review_token"],
                    })
            blocked = json.loads(
                (work_root / session_id / "checkpoint.local.json").read_text(encoding="utf-8")
            )
            self.assertEqual(blocked["workflow_state"], "FAILED")
            self.assertEqual(blocked["error_code"], "APPROVAL_PERSISTENCE_FAILURE")
            self.assertEqual(blocked["actual_state"], "WAITING_PLAN_APPROVAL")

    def test_browser_validation_is_optional_after_api_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            (workspace / ".env").write_text("", encoding="utf-8")
            work_root = workspace / ".migration-work"
            session_id = "migration-refresh-test"
            runtime = work_root / session_id / "unified-execution"
            dashboard = work_root / session_id / "dashboard-execution"
            runtime.mkdir(parents=True)
            dashboard.mkdir(parents=True)
            action_id = "action-1234567890abcdef12345678"
            action_server._write_private(runtime / action_server.STATE_FILE, {
                "schema_version": "2.0", "session_id": session_id,
                "action_id": action_id, "external_mutations": 2,
                "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
            })
            persist_assessment(
                work_root, session_id, SessionState.WAITING_FINAL_APPROVAL,
                resources_discovered=2, resources_migrated=2,
                dashboards_total=1, dashboards_migrated=1, dashboards_validated=1,
                validation_status=ValidationState.PASSED.value,
                artifacts={"migration_review": "migration-review.json"},
                approval_status="WAITING_FINAL_APPROVAL",
            )
            action_server._write_private(work_root / session_id / "migration-review.json", {
                "warnings": ["BROWSER_VALIDATION_SKIPPED"],
                "browser_validation": "BROWSER_VALIDATION_SKIPPED",
            })
            action_server._write_private(runtime / "execution-checkpoint.local.json", {
                "session_id": session_id, "bundle_hash": "a" * 64, "status": "COMPLETED",
                "operations": {
                    "dashboard:session": {
                        "status": "COMPLETED", "failure_category": None,
                        "resources": [{"object_type": "dashboard"}, {"object_type": "chart"}],
                    },
                },
            })
            (runtime / "ownership-ledger.local.json").write_text("{}\n", encoding="utf-8")
            action_server._write_private(dashboard / "dashboard-result.local.json", {
                "session_id": session_id, "result_hash": "b" * 64,
                "results": [{"object_ref": "dashboard-1", "target_id": "target-1"}],
            })
            arguments = {
                "workspace_root": str(workspace), "work_root": str(work_root),
                "env_file": str(workspace / ".env"), "session_id": session_id,
                "action_id": action_id,
            }
            review = action_server.get_migration_action_state(arguments)
            self.assertEqual(review["structuredContent"]["phase"], "WAITING_FINAL_APPROVAL")
            self.assertEqual(
                review["structuredContent"]["warnings"],
                ["BROWSER_VALIDATION_SKIPPED"],
            )
            self.assertEqual(
                review["structuredContent"]["browserValidationStatus"],
                "BROWSER_VALIDATION_SKIPPED",
            )
            self.assertNotIn("finalChallenge", review["structuredContent"])
            self.assertNotIn("rollbackChallenge", review["structuredContent"])
            self.assertIn("final_token", review["_meta"]["actionBindings"][0]["arguments"])
            self.assertIn("rollback_token", review["_meta"]["actionBindings"][1]["arguments"])

            browser_evidence = {
                "schema_version": "1.0", "session_id": session_id,
                "result_hash": "b" * 64, "dashboards": [{
                    "object_ref": "dashboard-1", "target_id_hash": "c" * 64,
                    "passed": True, "checks": {
                        "title_match": True, "chart_count_match": True,
                        "no_render_errors": True, "compact_layout": True,
                        "source_geometry_preserved": True,
                    },
                }],
                "checked_at": datetime.now(timezone.utc).isoformat(),
                "evidence_hash": "",
            }
            browser_evidence["evidence_hash"] = action_server._canonical_hash({
                key: value for key, value in browser_evidence.items()
                if key != "evidence_hash"
            })
            action_server._write_private(
                dashboard / "browser-validation.local.json", browser_evidence
            )
            refreshed = action_server.get_migration_action_state(arguments)
            self.assertEqual(refreshed["structuredContent"]["phase"], "WAITING_FINAL_APPROVAL")
            self.assertEqual(
                refreshed["structuredContent"]["warnings"],
                [],
            )
            self.assertEqual(
                refreshed["structuredContent"]["browserValidationStatus"],
                "PASSED",
            )
            persisted = CheckpointStore(work_root).load(session_id)
            self.assertEqual(persisted.browser_validation_status, "PASSED")
            approved = action_server.approve_migration_result({
                **arguments, "final_token": refreshed["_meta"]["actionBindings"][0]["arguments"]["final_token"],
            })
            self.assertEqual(approved["structuredContent"]["phase"], "COMPLETED")

    def test_expired_transport_token_does_not_close_authoritative_assessment(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            (workspace / ".env").write_text("", encoding="utf-8")
            work_root = workspace / ".migration-work"
            session_id = "migration-expired-test"
            runtime = work_root / session_id / "unified-execution"
            runtime.mkdir(parents=True)
            action_id = "action-abcdefabcdefabcdefabcdef"
            action_server._write_private(runtime / action_server.STATE_FILE, {
                "schema_version": "2.0", "session_id": session_id,
                "action_id": action_id, "bundle_hash": "a" * 64,
                "selected_scope": "full",
                "expires_at": (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(),
            })
            persist_assessment(
                work_root, session_id, SessionState.MIGRATING,
                resources_discovered=5, approval_status="PLAN_APPROVED",
            )
            result = action_server.get_migration_action_state({
                "workspace_root": str(workspace), "work_root": str(work_root),
                "env_file": str(workspace / ".env"), "session_id": session_id,
                "action_id": action_id,
            })
            self.assertEqual(result["structuredContent"]["phase"], "MIGRATING")

    def test_completed_runtime_waits_for_final_button_approval(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            env_file = workspace / ".env"
            env_file.write_text("", encoding="utf-8")
            work_root = workspace / ".migration-work"
            session_id = "migration-final-approval"
            runtime = work_root / session_id / "unified-execution"
            runtime.mkdir(parents=True)
            action_id = "action-1234567890abcdef12345678"
            action_server._write_private(runtime / action_server.STATE_FILE, {
                "schema_version": "2.0", "session_id": session_id,
                "action_id": action_id, "external_mutations": 1,
                "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
            })
            persist_assessment(
                work_root, session_id, SessionState.WAITING_FINAL_APPROVAL,
                resources_discovered=1, resources_migrated=1,
                validation_status=ValidationState.PASSED.value,
                artifacts={"migration_review": "migration-review.json"},
                approval_status="WAITING_FINAL_APPROVAL",
            )
            action_server._write_private(work_root / session_id / "migration-review.json", {
                "warnings": [], "browser_validation": "BROWSER_VALIDATION_SKIPPED",
            })
            action_server._write_private(runtime / "execution-checkpoint.local.json", {
                "session_id": session_id, "bundle_hash": "a" * 64,
                "status": "COMPLETED", "operations": {
                    "detector:1": {
                        "status": "COMPLETED", "failure_category": None,
                        "resources": [{"object_type": "detector"}],
                    },
                },
            })
            common = {
                "workspace_root": str(workspace), "work_root": str(work_root),
                "env_file": str(env_file), "session_id": session_id,
                "action_id": action_id,
            }
            review = action_server.get_migration_action_state(common)
            self.assertEqual(review["structuredContent"]["phase"], "WAITING_FINAL_APPROVAL")
            self.assertEqual(
                review["structuredContent"]["status"], "WAITING_FINAL_APPROVAL",
            )
            self.assertNotIn("finalChallenge", review["structuredContent"])
            self.assertIn("final_token", review["_meta"]["actionBindings"][0]["arguments"])
            checkpoint = json.loads(
                (work_root / session_id / "checkpoint.local.json").read_text()
            )
            self.assertEqual(checkpoint["workflow_state"], "WAITING_FINAL_APPROVAL")

            approved = action_server.approve_migration_result({
                **common, "final_token": review["_meta"]["actionBindings"][0]["arguments"]["final_token"],
            })
            self.assertEqual(approved["structuredContent"]["phase"], "COMPLETED")
            self.assertEqual(
                approved["_meta"]["actionBindings"][0]["tool"],
                "generate_terraform_code",
            )
            with patch.object(action_server, "export_terraform", return_value={
                "status": "generated", "directory": str(workspace / "terraform"),
                "resourceCount": 1, "files": ["imports.tf"],
            }):
                generated = action_server.generate_terraform_code(common)
            self.assertEqual(generated["structuredContent"]["terraformExport"]["resourceCount"], 1)
            self.assertIn("Terraform import configuration is ready", generated["content"][0]["text"])
            checkpoint = json.loads(
                (work_root / session_id / "checkpoint.local.json").read_text()
            )
            self.assertEqual(checkpoint["workflow_state"], "COMPLETED")
            persisted = json.loads((runtime / action_server.STATE_FILE).read_text())
            self.assertIn("final_approved_at", persisted)

    def test_existing_blocked_session_reopens_with_rollback_button_token(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            env_file = workspace / ".env"
            env_file.write_text("", encoding="utf-8")
            work_root = workspace / ".migration-work"
            session_id = "migration-resume-blocked"
            runtime = work_root / session_id / "unified-execution"
            runtime.mkdir(parents=True)
            action_id = "action-abcdefabcdefabcdefabcdef"
            action_server._write_private(runtime / action_server.STATE_FILE, {
                "schema_version": "2.0", "session_id": session_id,
                "action_id": action_id, "external_mutations": 1,
                "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
            })
            persist_assessment(work_root, session_id, SessionState.WAITING_PLAN_APPROVAL)
            CheckpointStore(work_root).block(
                session_id, error_code="API_VALIDATION_FAILED",
                error_message="Validation failed.", expected_state="REVIEW_READY",
            )
            (runtime / "ownership-ledger.local.json").write_text("{}\n", encoding="utf-8")
            result = action_server.review_migration_plan({
                "workspace_root": str(workspace), "work_root": str(work_root),
                "env_file": str(env_file), "session_id": session_id,
                "plan_hash": "a" * 64,
            })
            self.assertEqual(result["structuredContent"]["phase"], "FAILED")
            self.assertIn("rootCause", result["structuredContent"])

    def test_customer_state_machine_requires_final_approval(self):
        self.assertEqual(
            advance(Stage.DISCOVERY, Stage.PLAN_REVIEW), Stage.PLAN_REVIEW,
        )
        self.assertEqual(
            advance(Stage.PLAN_REVIEW, Stage.WAITING_PLAN_APPROVAL),
            Stage.WAITING_PLAN_APPROVAL,
        )
        self.assertEqual(
            advance(Stage.WAITING_PLAN_APPROVAL, Stage.MIGRATING),
            Stage.MIGRATING,
        )
        self.assertEqual(advance(Stage.MIGRATING, Stage.VALIDATING), Stage.VALIDATING)
        self.assertEqual(advance(Stage.VALIDATING, Stage.REVIEW_READY), Stage.REVIEW_READY)
        self.assertEqual(
            advance(Stage.REVIEW_READY, Stage.WAITING_FINAL_APPROVAL),
            Stage.WAITING_FINAL_APPROVAL,
        )
        self.assertEqual(
            advance(Stage.WAITING_FINAL_APPROVAL, Stage.COMPLETED),
            Stage.COMPLETED,
        )
        with self.assertRaises(ValueError):
            advance(Stage.VALIDATING, Stage.COMPLETED)

    def test_customer_decisions_are_consolidated(self):
        self.assertEqual(approval_count(Stage.MIGRATING), 1)
        self.assertEqual(approval_count(Stage.COMPLETED), 2)
        self.assertEqual(approval_count(Stage.VALIDATING), 0)
        self.assertEqual(
            approval_number(Stage.WAITING_PLAN_APPROVAL, Stage.MIGRATING), 1,
        )
        self.assertEqual(approval_number(Stage.WAITING_FINAL_APPROVAL, Stage.COMPLETED), 2)
        self.assertIsNone(approval_number(Stage.MIGRATING, Stage.VALIDATING))

    def test_validation_follows_apply(self):
        self.assertEqual(advance(Stage.MIGRATING, Stage.VALIDATING), Stage.VALIDATING)
        with self.assertRaises(ValueError):
            advance(Stage.WAITING_PLAN_APPROVAL, Stage.VALIDATING)

    def test_stages_cannot_be_skipped(self):
        with self.assertRaises(ValueError):
            advance(Stage.PLAN_REVIEW, Stage.MIGRATING)
        with self.assertRaises(ValueError):
            advance(Stage.VALIDATING, Stage.COMPLETED)

    def test_same_bundle_can_resume_without_reapproval(self):
        self.assertFalse(bundle_change_requires_reapproval("abc", "abc"))
        self.assertTrue(bundle_change_requires_reapproval("abc", "def"))

    def test_failed_runs_do_not_skip_back_into_normal_flow(self):
        with self.assertRaises(ValueError):
            advance(Stage.FAILED, Stage.VALIDATING)

    def test_failed_execution_recovers_only_through_persisted_retry_target(self):
        with tempfile.TemporaryDirectory() as directory:
            store = CheckpointStore(Path(directory) / ".migration-work")
            session = Session.create("assessment-failed-recovery")
            store.save(session)
            store.transition(session.assessment_id, SessionState.DISCOVERY, SessionState.PLAN_REVIEW)
            store.transition(session.assessment_id, SessionState.PLAN_REVIEW, SessionState.WAITING_PLAN_APPROVAL)
            store.transition(session.assessment_id, SessionState.WAITING_PLAN_APPROVAL, SessionState.MIGRATING)
            failed = store.block(
                session.assessment_id,
                error_code="APPLY_FAILURE",
                error_message="synthetic failure",
                expected_state=SessionState.MIGRATING.value,
            )
            self.assertEqual(failed.failure_recovery_state, SessionState.MIGRATING.value)
            self.assertEqual(failed.available_actions, ["retry"])
            recovered = store.recover(session.assessment_id, SessionState.MIGRATING)
            self.assertEqual(recovered.workflow_state, SessionState.MIGRATING.value)
            self.assertEqual(recovered.recovery_attempts, 1)

    def test_failed_execution_can_roll_back_only_when_mutations_exist(self):
        with tempfile.TemporaryDirectory() as directory:
            store = CheckpointStore(Path(directory) / ".migration-work")
            session = Session.create("assessment-failed-rollback")
            store.save(session)
            store.transition(session.assessment_id, SessionState.DISCOVERY, SessionState.PLAN_REVIEW)
            store.transition(session.assessment_id, SessionState.PLAN_REVIEW, SessionState.WAITING_PLAN_APPROVAL)
            store.transition(session.assessment_id, SessionState.WAITING_PLAN_APPROVAL, SessionState.MIGRATING)
            failed = store.block(
                session.assessment_id,
                error_code="PARTIAL_APPLY_FAILURE",
                error_message="synthetic partial failure",
                expected_state=SessionState.MIGRATING.value,
                mutations_performed=1,
            )
            self.assertEqual(failed.available_actions, ["retry", "rollback"])
            rolling = store.recover(session.assessment_id, SessionState.ROLLING_BACK)
            self.assertEqual(rolling.workflow_state, SessionState.ROLLING_BACK.value)

    def test_required_transition_matrix_is_exact(self):
        allowed = {
            Stage.DISCOVERY: {Stage.PLAN_REVIEW},
            Stage.PLAN_REVIEW: {Stage.WAITING_PLAN_APPROVAL},
            Stage.WAITING_PLAN_APPROVAL: {Stage.MIGRATING, Stage.FAILED},
            Stage.MIGRATING: {Stage.VALIDATING, Stage.FAILED},
            Stage.VALIDATING: {Stage.REVIEW_READY, Stage.FAILED},
            Stage.REVIEW_READY: {Stage.WAITING_FINAL_APPROVAL},
            Stage.WAITING_FINAL_APPROVAL: {Stage.COMPLETED, Stage.ROLLING_BACK},
            Stage.ROLLING_BACK: {Stage.ROLLED_BACK, Stage.FAILED},
            Stage.COMPLETED: set(),
            Stage.ROLLED_BACK: set(),
            Stage.FAILED: {
                Stage.WAITING_PLAN_APPROVAL,
                Stage.MIGRATING,
                Stage.ROLLING_BACK,
            },
        }
        for current in Stage:
            for target in Stage:
                if target in allowed[current]:
                    self.assertEqual(advance(current, target), target)
                else:
                    with self.assertRaisesRegex(ValueError, "INVALID_STATE_TRANSITION"):
                        advance(current, target)

    def test_retried_identical_plan_approval_is_idempotent(self):
        fixture = ROOT / "tests/fixtures/datadog_inventory.synthetic.json"
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            env_file = workspace / ".env"
            env_file.write_text("", encoding="utf-8")
            work_root = workspace / ".migration-work"
            session_id = "migration-double-approval"
            args = Namespace(
                env_file=str(env_file), capability_catalog="", inventory=str(fixture),
                work_root=str(work_root), session_id=session_id,
                target="splunk_observability_cloud", strategy="full", select_ref=[],
            )
            with redirect_stdout(StringIO()):
                command_prepare(args)
            checkpoint = json.loads(
                (work_root / session_id / "checkpoint.local.json").read_text()
            )
            review = action_server.review_migration_plan({
                "workspace_root": str(workspace), "work_root": str(work_root),
                "env_file": str(env_file), "session_id": session_id,
                "plan_hash": checkpoint["plan_hash"],
            })
            review = action_server.continue_to_plan_review({
                "workspace_root": str(workspace), "work_root": str(work_root),
                "env_file": str(env_file), "session_id": session_id,
                "action_id": review["structuredContent"]["actionId"],
            })
            approval = {
                "workspace_root": str(workspace), "work_root": str(work_root),
                "env_file": str(env_file), "session_id": session_id,
                "action_id": review["structuredContent"]["actionId"],
                "scope": "full", "review_token": review["_meta"]["actionBindings"][0]["arguments"]["review_token"],
            }
            compiled = {
                "bundle_hash": "b" * 64, "target_origin": "https://api.invalid",
                "operation_count": 1, "prepared_resources": {"detectors": 1},
                "actions": {"CREATE": 1},
            }
            with patch.object(action_server, "_run_command", return_value=compiled), patch.object(
                action_server, "_start_migration_worker", return_value=True
            ):
                first = action_server.approve_migration_scope(approval)
                second = action_server.approve_migration_scope(approval)
                self.assertEqual(first["structuredContent"]["phase"], "MIGRATING")
                self.assertEqual(second["structuredContent"]["phase"], "MIGRATING")
                self.assertEqual(
                    CheckpointStore(work_root).load(session_id).approval_ids,
                    [json.loads((work_root / session_id / "plan-review-approval.local.json").read_text())["approval_id"]],
                )
                tampered = dict(approval, review_token="0" * 64)
                with self.assertRaisesRegex(ValueError, "INVALID_STATE_TRANSITION"):
                    action_server.approve_migration_scope(tampered)

    def test_assessment_identity_and_resource_counters_never_reset(self):
        with tempfile.TemporaryDirectory() as directory:
            work_root = Path(directory) / "work"
            store = CheckpointStore(work_root)
            session = Session.create("assessment-A123")
            session.resources_discovered = 92
            session.dashboards_total = 6
            session.monitors_total = 16
            session.queries_total = 74
            store.save(session)
            assessment_id = session.assessment_id
            for target in (
                SessionState.PLAN_REVIEW,
                SessionState.WAITING_PLAN_APPROVAL,
                SessionState.MIGRATING,
                SessionState.VALIDATING,
                SessionState.REVIEW_READY,
                SessionState.WAITING_FINAL_APPROVAL,
            ):
                current = store.load(assessment_id)
                store.transition(assessment_id, SessionState(current.workflow_state), target)
                persisted = store.load(assessment_id)
                self.assertEqual(persisted.assessment_id, assessment_id)
                self.assertEqual(persisted.resources_discovered, 92)
                self.assertEqual(persisted.dashboards_total, 6)
                self.assertEqual(persisted.monitors_total, 16)
                self.assertEqual(persisted.queries_total, 74)

    def test_counter_regression_stops_as_corrupted_session(self):
        with tempfile.TemporaryDirectory() as directory:
            store = CheckpointStore(Path(directory) / "work")
            session = Session.create("assessment-counter-integrity")
            session.resources_discovered = 92
            store.save(session)
            candidate = store.load(session.assessment_id)
            candidate.resources_discovered = 0
            with self.assertRaisesRegex(ValueError, "CORRUPTED_SESSION"):
                store.save(candidate)
            self.assertEqual(store.load(session.assessment_id).resources_discovered, 92)

    def test_browser_timeout_and_missing_results_never_block_review(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "browser-validation.local.json"
            status, warning = action_server._browser_validation_outcome(
                missing,
                "assessment-browser-timeout",
                6,
                datetime.now(timezone.utc) - timedelta(seconds=61),
            )
            self.assertEqual(status, "BROWSER_VALIDATION_SKIPPED")
            self.assertEqual(warning, "BROWSER_VALIDATION_TIMED_OUT")
            status, warning = action_server._browser_validation_outcome(
                missing,
                "assessment-browser-missing",
                6,
                datetime.now(timezone.utc),
            )
            self.assertEqual(status, "BROWSER_VALIDATION_SKIPPED")
            self.assertEqual(warning, "BROWSER_VALIDATION_SKIPPED")

    def test_api_validation_accepts_planned_deferred_operations(self):
        self.assertTrue(action_server._api_validation_passed(
            "PARTIAL", {"COMPLETED": 4, "SKIPPED": 4},
        ))
        self.assertTrue(action_server._api_validation_passed(
            "COMPLETED", {"COMPLETED": 8},
        ))

    def test_api_validation_rejects_failed_or_incomplete_operations(self):
        self.assertFalse(action_server._api_validation_passed(
            "PARTIAL", {"COMPLETED": 3, "SKIPPED": 4, "FAILED": 1},
        ))
        self.assertFalse(action_server._api_validation_passed(
            "VALIDATING", {"COMPLETED": 3, "VALIDATING": 1},
        ))

    def test_dashboard_subcheckpoint_exposes_live_progress(self):
        fixture = ROOT / "tests/fixtures/datadog_inventory.synthetic.json"
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            env_file = workspace / ".env"
            env_file.write_text("", encoding="utf-8")
            work_root = workspace / ".migration-work"
            session_id = "assessment-dashboard-live-progress"
            with redirect_stdout(StringIO()):
                command_prepare(Namespace(
                    env_file=str(env_file), capability_catalog="", inventory=str(fixture),
                    work_root=str(work_root), session_id=session_id,
                    target="splunk_observability_cloud", strategy="full", select_ref=[],
                ))
            session_root = work_root / session_id
            inventory = json.loads((session_root / "inventory-ir.json").read_text())
            dashboard_ref = next(
                item["object_ref"] for item in inventory["objects"]
                if item["object_type"] == "dashboard"
            )
            progress_root = session_root / "dashboard-execution"
            progress_root.mkdir()
            (progress_root / "dashboard-apply-checkpoint.local.json").write_text(
                json.dumps({
                    "dashboards": {
                        dashboard_ref: {"outcome": "created", "validated": True},
                    },
                }),
                encoding="utf-8",
            )
            counters = action_server._session_counters(session_root)
            self.assertEqual(counters["dashboards"]["migrated"], 1)
            self.assertEqual(counters["dashboards"]["validated"], 1)

    def test_runtime_snapshot_does_not_double_count_committed_dashboard_resources(self):
        with tempfile.TemporaryDirectory() as directory:
            work_root = Path(directory) / ".migration-work"
            session_id = "assessment-dashboard-no-double-count"
            session_root = work_root / session_id
            runtime = session_root / "unified-execution"
            dashboard = session_root / "dashboard-execution"
            runtime.mkdir(parents=True)
            dashboard.mkdir(parents=True)
            action_server._write_private(session_root / "inventory-ir.json", {
                "objects": [],
            })
            resources = [{"id": f"resource-{index}"} for index in range(4)]
            action_server._write_private(runtime / "execution-checkpoint.local.json", {
                "status": "VALIDATING",
                "operations": {
                    "dashboard:session": {
                        "status": "VALIDATING",
                        "resources": resources,
                    },
                },
            })
            action_server._write_private(
                dashboard / "dashboard-apply-checkpoint.local.json",
                {
                    "charts": {"chart-1": {}, "chart-2": {}},
                    "dashboards": {"dashboard-1": {}},
                    "group": {"id": "group-1"},
                },
            )
            state_path = runtime / action_server.STATE_FILE
            state = {
                "session_id": session_id,
                "action_id": "action-1234567890abcdef12345678",
                "state_version": 3,
                "status": "MIGRATING",
            }
            action_server._write_private(state_path, state)
            snapshot = action_server._runtime_snapshot(state_path, state, work_root)
            self.assertEqual(snapshot["externalMutations"], 4)

    def test_every_state_has_current_operation_progress_and_next_action(self):
        normal = Session.create("assessment-visibility-normal")
        paths = [normal]
        for target in (
            SessionState.PLAN_REVIEW,
            SessionState.WAITING_PLAN_APPROVAL,
            SessionState.MIGRATING,
            SessionState.VALIDATING,
            SessionState.REVIEW_READY,
            SessionState.WAITING_FINAL_APPROVAL,
            SessionState.COMPLETED,
        ):
            normal.transition(target)
            paths.append(Session(**normal.__dict__))
        rollback = Session.create("assessment-visibility-rollback")
        for target in (
            SessionState.PLAN_REVIEW,
            SessionState.WAITING_PLAN_APPROVAL,
            SessionState.MIGRATING,
            SessionState.VALIDATING,
            SessionState.REVIEW_READY,
            SessionState.WAITING_FINAL_APPROVAL,
            SessionState.ROLLING_BACK,
            SessionState.ROLLED_BACK,
        ):
            rollback.transition(target)
            paths.append(Session(**rollback.__dict__))
        failed = Session.create("assessment-visibility-failed")
        failed.transition(SessionState.PLAN_REVIEW)
        failed.transition(SessionState.WAITING_PLAN_APPROVAL)
        failed.transition(SessionState.FAILED)
        failed.error_message = "A detector query needs redesign."
        failed.affected_resources = ["monitor-a"]
        failed.resolution = "Provide a detector mapping or exclude the monitor."
        failed.available_actions = ["Exclude", "Retry"]
        paths.append(failed)
        for session in paths:
            self.assertTrue(session.current_step)
            self.assertTrue(session.current_operation)
            self.assertTrue(session.next_action)
        self.assertTrue(failed.error_message)
        self.assertTrue(failed.affected_resources)
        self.assertTrue(failed.resolution)
        self.assertTrue(failed.available_actions)

    def test_e2e_state_flow_requires_api_pass_and_final_approval(self):
        session = Session.create("assessment-e2e-success")
        session.resources_discovered = 92
        session.transition(SessionState.PLAN_REVIEW)
        session.transition(SessionState.WAITING_PLAN_APPROVAL)
        session.transition(SessionState.MIGRATING, event="PLAN_APPROVED")
        session.resources_migrated = 88
        session.resources_deferred = 4
        session.transition(SessionState.VALIDATING)
        session.validation_status = ValidationState.PASSED.value
        session.browser_validation_status = "SKIPPED"
        session.transition(SessionState.REVIEW_READY)
        session.transition(SessionState.WAITING_FINAL_APPROVAL)
        self.assertNotEqual(session.workflow_state, SessionState.COMPLETED.value)
        session.transition(SessionState.COMPLETED)
        session.approval_status = "FINAL_APPROVED"
        self.assertEqual(session.workflow_state, "COMPLETED")
        self.assertEqual(session.validation_status, "PASSED")
        self.assertEqual(session.browser_validation_status, "SKIPPED")

    def test_cleanup_uses_reverse_dependency_order(self):
        order = sorted(CLEANUP_PRIORITY, key=CLEANUP_PRIORITY.get)
        self.assertEqual(order, ["dashboard", "chart", "dashboardgroup", "detector", "slo"])

    def test_cleanup_revokes_apply_authorization(self):
        with tempfile.TemporaryDirectory() as directory:
            work_root = Path(directory)
            runtime = work_root / "migration-test" / "unified-execution"
            runtime.mkdir(parents=True)
            active = runtime / "apply-approval.local.json"
            active.write_text("{}\n", encoding="utf-8")
            revoked = revoke_session_apply_authorizations(work_root, "migration-test")
            self.assertEqual(revoked, ["apply-approval.local.json"])
            self.assertFalse(active.exists())
            self.assertTrue((runtime / "apply-approval.revoked.local.json").exists())

    def test_cleanup_proves_orphan_chart_from_ownership_ledger(self):
        marker = "codex-migration-0123456789abcdef"
        payload = {
            "name": "Migrated chart",
            "tags": ["AI-Created", marker],
            "options": {"type": "Text"},
        }
        target_id = "chart-123"

        class ResourceClient:
            def get(self, kind, actual_target_id):
                if kind == "chart" and actual_target_id == target_id:
                    return {"id": target_id, "name": payload["name"], "tags": payload["tags"]}
                return None

        scope = {
            "group": {
                "kind": "dashboardgroup", "target_id": "group-absent",
                "object_ref": "dashboard-group", "name": "Migration",
            },
            "dashboards": [],
            "chart_payloads": [payload],
            "chart_entries": {
                marker: {
                    "object_ref": marker, "object_type": "chart", "target_id": target_id,
                    "target_id_hash": value_hash(target_id), "payload_hash": value_hash(payload),
                    "disposition": "CREATED",
                },
            },
        }
        resolved, counts = inspect_targets([], scope, None, None, ResourceClient())
        self.assertEqual([(item["kind"], item["target_id"]) for item in resolved], [("chart", target_id)])
        self.assertEqual(counts["chart"], 1)
