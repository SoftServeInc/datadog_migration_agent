import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / ".agents/skills/observability-migration-orchestrator/scripts"
sys.path.insert(0, str(SCRIPTS))

from orchestration_core.bundle import seal_bundle  # noqa: E402
from orchestration_core.common import atomic_write_json, value_hash  # noqa: E402
from orchestration_core.state import UnifiedStore  # noqa: E402
from terraform_export import export_terraform  # noqa: E402


class TerraformExportTests(unittest.TestCase):
    def _migration(self, root: Path) -> tuple[Path, Path, str]:
        workspace = root / "workspace"
        workspace.mkdir()
        work_root = root / "work"
        work_root.mkdir(mode=0o700)
        session_id = "terraform-export-session"
        chart = {
            "name": "Latency",
            "tags": ["AI-Created", "codex-migration-test"],
            "programText": "A = data('latency').publish()",
            "options": {"type": "TimeSeriesChart", "defaultPlotType": "LineChart"},
        }
        operation = {
            "operation_id": "dashboard:session", "object_ref": "dashboard:session",
            "object_type": "dashboard", "adapter": "dashboard-session", "action": "CREATE",
            "status": "SUPPORTED", "dependencies": [], "payload_hash": "a" * 64,
            "adapter_input": {}, "validation": [], "rollback": {"mode": "owned"},
        }
        bundle = seal_bundle(
            session_id, "b" * 64,
            {"origin": "https://api.eu1.observability.splunkcloud.com", "organization_id_hash": "c" * 64},
            [operation],
        )
        runtime = work_root / session_id / "unified-execution"
        runtime.mkdir(mode=0o700, parents=True)
        atomic_write_json(runtime / "execution-bundle.local.json", bundle)
        store = UnifiedStore(work_root, session_id)
        checkpoint = store.create(bundle, {"approval_hash": "d" * 64})
        store.record_resources(checkpoint, operation, [
            {
                "object_ref": "chart:test", "object_type": "chart", "target_id": "chart-id",
                "disposition": "CREATED", "payload_hash": value_hash(chart), "dependencies": [],
            },
            {
                "object_ref": "dashboard:test", "object_type": "dashboard", "target_id": "dashboard-id",
                "disposition": "UPDATED", "payload_hash": "e" * 64, "dependencies": [],
                "before_state": {"name": "Before"},
            },
            {
                "object_ref": "detector:reused", "object_type": "detector", "target_id": "reused-id",
                "disposition": "REUSED", "payload_hash": "f" * 64, "dependencies": [],
            },
        ])
        checkpoint = store.load_checkpoint()
        checkpoint["status"] = "COMPLETED"
        store.save_checkpoint(checkpoint)
        preview = {"dashboards": [{"charts": [chart]}]}
        dashboard_dir = work_root / session_id / "dashboard-execution"
        dashboard_dir.mkdir(mode=0o700)
        atomic_write_json(dashboard_dir / "dashboard-preview.local.json", preview)
        return workspace, work_root, session_id

    def test_generates_import_only_configuration_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace, work_root, session_id = self._migration(Path(directory))
            result = export_terraform(workspace, work_root, session_id)
            self.assertEqual(result["status"], "generated")
            self.assertEqual(result["resourceCount"], 2)
            output = Path(result["directory"])
            imports = (output / "imports.tf").read_text(encoding="utf-8")
            provider = (output / "provider.tf").read_text(encoding="utf-8")
            self.assertIn("signalfx_time_chart.migrated_time_chart_001", imports)
            self.assertIn("signalfx_dashboard.migrated_dashboard_001", imports)
            self.assertNotIn("reused-id", imports)
            self.assertNotIn("token", imports.lower())
            self.assertIn("sensitive   = true", provider)
            self.assertNotIn("SFX_AUTH_TOKEN", provider)
            self.assertFalse((output / "terraform.tfstate").exists())

            repeated = export_terraform(workspace, work_root, session_id)
            self.assertEqual(repeated["status"], "already_generated")
            self.assertEqual(repeated["resourceCount"], 2)

    def test_refuses_modified_export_and_cleaned_session(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace, work_root, session_id = self._migration(Path(directory))
            result = export_terraform(workspace, work_root, session_id)
            output = Path(result["directory"])
            (output / "imports.tf").write_text("changed\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "differs from its manifest"):
                export_terraform(workspace, work_root, session_id)

        with tempfile.TemporaryDirectory() as directory:
            workspace, work_root, session_id = self._migration(Path(directory))
            result = export_terraform(workspace, work_root, session_id)
            output = Path(result["directory"])
            (output / "unexpected.txt").write_text("unexpected\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "unexpected files"):
                export_terraform(workspace, work_root, session_id)

        with tempfile.TemporaryDirectory() as directory:
            workspace, work_root, session_id = self._migration(Path(directory))
            atomic_write_json(work_root / session_id / "cleanup-result.local.json", {"status": "cleanup_complete"})
            with self.assertRaisesRegex(ValueError, "cleaned up"):
                export_terraform(workspace, work_root, session_id)

    def test_generated_manifest_contains_hashes_not_target_ids(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace, work_root, session_id = self._migration(Path(directory))
            result = export_terraform(workspace, work_root, session_id)
            manifest = json.loads((Path(result["directory"]) / ".terraform-export-manifest.json").read_text())
            self.assertEqual(manifest["resource_count"], 2)
            self.assertNotIn("chart-id", json.dumps(manifest))
            self.assertNotIn("dashboard-id", json.dumps(manifest))


if __name__ == "__main__":
    unittest.main()
