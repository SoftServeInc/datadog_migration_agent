from __future__ import annotations

import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SKILLS_ROOT = ROOT / ".agents" / "skills"

SKILLS = {
    "observability-migration-assessment",
    "observability-provider-preflight",
    "datadog-configuration-discovery",
    "observability-inventory-normalizer",
    "observability-compatibility-assessment",
    "observability-migration-planner",
    "observability-migration-executor",
    "observability-migration-slo-executor",
    "observability-migration-dashboard-executor",
    "observability-migration-orchestrator",
    "observability-migration-security-review",
}

AGENTS = {
    "migration-discovery-reviewer.toml",
    "migration-compatibility-analyst.toml",
    "migration-plan-reviewer.toml",
    "migration-execution-reviewer.toml",
    "migration-security-reviewer.toml",
}


def frontmatter_value(text: str, key: str) -> str:
    match = re.search(rf"^{re.escape(key)}:\s*(.+)$", text, re.MULTILINE)
    if not match:
        raise AssertionError(f"missing frontmatter key: {key}")
    return match.group(1).strip().strip('"')


class CodexObservabilityLayoutTests(unittest.TestCase):
    def test_all_skills_are_repo_scoped_and_have_ui_metadata(self) -> None:
        for skill_name in SKILLS:
            with self.subTest(skill=skill_name):
                skill_dir = SKILLS_ROOT / skill_name
                skill_text = (skill_dir / "SKILL.md").read_text(encoding="utf-8")
                metadata = (skill_dir / "agents" / "openai.yaml").read_text(encoding="utf-8")
                self.assertEqual(frontmatter_value(skill_text, "name"), skill_name)
                self.assertGreater(len(frontmatter_value(skill_text, "description")), 30)
                self.assertIn(f"${skill_name}", metadata)

    def test_custom_agents_are_read_only_and_instruction_complete(self) -> None:
        agents_root = ROOT / ".codex" / "agents"
        self.assertEqual({path.name for path in agents_root.glob("*.toml")}, AGENTS)
        for filename in AGENTS:
            with self.subTest(agent=filename):
                text = (agents_root / filename).read_text(encoding="utf-8")
                self.assertRegex(text, re.compile(r'^name = "[a-z][a-z0-9_]+"$', re.MULTILINE))
                self.assertRegex(text, re.compile(r'^description = ".+"$', re.MULTILINE))
                self.assertIn('sandbox_mode = "read-only"', text)
                self.assertIn('developer_instructions = """', text)
                self.assertNotRegex(text, r"(?m)^model\s*=")

    def test_project_limits_parallel_review_lanes(self) -> None:
        config = (ROOT / ".codex" / "config.toml").read_text(encoding="utf-8")
        self.assertIn("[agents]", config)
        self.assertIn("max_concurrent_threads_per_session = 4", config)

    def test_orchestrator_contract_has_consolidated_decisions_and_internal_adapters(self) -> None:
        orchestrator = (
            SKILLS_ROOT / "observability-migration-orchestrator" / "SKILL.md"
        ).read_text(encoding="utf-8")
        self.assertIn("### 1. Assessment only", orchestrator)
        self.assertIn("### 2. Governed migration", orchestrator)
        self.assertIn("### 3. Resume or recover", orchestrator)
        self.assertIn("```mermaid", orchestrator)
        self.assertIn("scope", orchestrator)
        self.assertIn("`.env`", orchestrator)
        self.assertIn("Never ask the customer to type internal values", orchestrator)
        self.assertNotIn("MCP", orchestrator)
        self.assertNotIn("apply_migration_bundle", orchestrator)
        self.assertNotIn("embedded checklist", orchestrator)
        for name in (
            "observability-migration-executor",
            "observability-migration-slo-executor",
            "observability-migration-dashboard-executor",
        ):
            metadata = (SKILLS_ROOT / name / "agents" / "openai.yaml").read_text(encoding="utf-8")
            self.assertIn("allow_implicit_invocation: false", metadata)

    def test_shared_execution_and_ownership_schemas_exist(self) -> None:
        schemas = SKILLS_ROOT / "observability-migration-orchestrator" / "schemas"
        execution = json.loads((schemas / "execution-bundle.schema.json").read_text(encoding="utf-8"))
        ownership = json.loads((schemas / "ownership-ledger.schema.json").read_text(encoding="utf-8"))
        approval = json.loads((schemas / "apply-approval.schema.json").read_text(encoding="utf-8"))
        browser = json.loads((schemas / "dashboard-browser-validation.schema.json").read_text(encoding="utf-8"))
        self.assertIn("operations", execution["required"])
        self.assertIn("bundle_hash", execution["required"])
        self.assertIn("entries", ownership["required"])
        self.assertEqual(approval["properties"]["approval_number"]["const"], 2)
        self.assertIn("dashboards", browser["required"])
        dispositions = ownership["properties"]["entries"]["items"]["properties"]["disposition"]["enum"]
        self.assertEqual(dispositions, ["CREATED", "UPDATED", "REUSED", "NO_OP"])
        runtime = SKILLS_ROOT / "observability-migration-orchestrator" / "scripts" / "unified_migration.py"
        self.assertTrue(runtime.is_file())


if __name__ == "__main__":
    unittest.main()
