#!/usr/bin/env python3
"""Run and verify the complete governed migration against the local emulator."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
ACTION_SERVER = ROOT / "skills/observability-migration-orchestrator/scripts/apply_action_server.py"
ASSESSMENT = ROOT / "skills/observability-migration-assessment/scripts/migration_assessment.py"
FIXTURE = ROOT / "assets/datadog_inventory.synthetic.json"


def run_json(command: list[str]) -> dict[str, Any]:
    completed = subprocess.run(command, check=True, capture_output=True, text=True, cwd=ROOT)
    output = completed.stdout.strip()
    start = output.find("{")
    if start < 0:
        raise RuntimeError("command returned no JSON")
    value = json.loads(output[start:])
    if not isinstance(value, dict):
        raise RuntimeError("command JSON is not an object")
    return value


def mcp_tool_result(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
        {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": name, "arguments": arguments}},
    ]
    completed = subprocess.run(
        [sys.executable, str(ACTION_SERVER)],
        input="".join(json.dumps(item) + "\n" for item in requests),
        check=True, capture_output=True, text=True, cwd=ROOT,
    )
    responses = [json.loads(line) for line in completed.stdout.splitlines() if line.strip()]
    response = next(item for item in responses if item.get("id") == 2)
    if "error" in response:
        raise RuntimeError(response["error"]["message"])
    return response["result"]


def mcp_call(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    return mcp_tool_result(name, arguments)["structuredContent"]


def mcp_request(method: str, params: dict[str, Any]) -> dict[str, Any]:
    request = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    completed = subprocess.run(
        [sys.executable, str(ACTION_SERVER)], input=json.dumps(request) + "\n",
        check=True, capture_output=True, text=True, cwd=ROOT,
    )
    response = json.loads(completed.stdout.strip())
    if "error" in response:
        raise RuntimeError(response["error"]["message"])
    return response["result"]


def wait_for_phase(common: dict[str, Any], phases: set[str], timeout: float = 15) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    latest: dict[str, Any] = {}
    while time.monotonic() < deadline:
        latest = mcp_call("get_migration_action_state", common)
        if latest["phase"] in phases:
            return latest
        time.sleep(0.05)
    raise RuntimeError(f"emulated migration timed out in phase {latest.get('phase')}")


def prepare(work_root: Path, env_file: Path, session_id: str) -> dict[str, Any]:
    return run_json([
        sys.executable, str(ASSESSMENT), "prepare",
        "--env-file", str(env_file), "--inventory", str(FIXTURE),
        "--work-root", str(work_root), "--session-id", session_id,
        "--target", "splunk_observability_cloud", "--strategy", "full",
    ])


def run_session(
    workspace: Path, work_root: Path, target_root: Path, env_file: Path,
    session_id: str, *, finish: str,
) -> dict[str, Any]:
    launch = mcp_tool_result("open_migration_control_center", {
        "workspace_root": str(workspace), "work_root": str(work_root),
        "env_file": str(env_file),
    })
    if launch["structuredContent"]["phase"] not in {"READY", "COMPLETED", "ROLLED_BACK"}:
        raise RuntimeError("control center did not open at plugin start")

    prepared = prepare(work_root, env_file, session_id)
    session = prepared["session"]
    if session["workflow_state"] != "PLAN_REVIEW" or session["resources_discovered"] <= 0:
        raise RuntimeError("discovery, normalization, compatibility, or planning did not complete")
    common: dict[str, Any] = {
        "workspace_root": str(workspace), "work_root": str(work_root),
        "env_file": str(env_file), "emulator_root": str(target_root),
        "session_id": session_id,
    }
    hydrated = mcp_tool_result("open_migration_control_center", common)
    if hydrated["structuredContent"]["phase"] != "PLAN_REVIEW":
        raise RuntimeError("control center did not render the plan checkpoint")
    rows = hydrated.get("_meta", {}).get("resourceRows", [])
    if len(rows) != session["resources_discovered"] or any(
        not row.get("name") or "source_id" in row or "object_ref" in row for row in rows
    ):
        raise RuntimeError("control center named-resource report is incomplete or unsafe")
    if any(row["name"] in json.dumps(hydrated["structuredContent"]) for row in rows):
        raise RuntimeError("resource names escaped widget-only metadata")
    binding = hydrated["_meta"]["actionBindings"][0]
    if binding["tool"] != "continue_to_plan_review":
        raise RuntimeError("control center did not expose the plan-review action")
    continued = mcp_tool_result(binding["tool"], binding["arguments"])
    if continued["structuredContent"]["phase"] != "WAITING_PLAN_APPROVAL":
        raise RuntimeError("plan review did not reach scope approval")
    approve_binding = continued["_meta"]["actionBindings"][0]
    if approve_binding["tool"] != "approve_migration_scope":
        raise RuntimeError("control center did not refresh the scope-approval action")
    common["action_id"] = approve_binding["arguments"]["action_id"]
    migrating = mcp_call(approve_binding["tool"], approve_binding["arguments"])
    if migrating["phase"] != "MIGRATING":
        raise RuntimeError("scope approval did not start execution")

    partial = wait_for_phase(common, {"FAILED"})
    if not partial["failureDiagnostics"] or "retry" not in partial.get("availableActions", []):
        raise RuntimeError("partial failure did not expose typed retry diagnostics")
    session_root = work_root / session_id
    before_retry = json.loads((session_root / "checkpoint.local.json").read_text(encoding="utf-8"))
    discovery_completed = before_retry["discovery_completed_at"]
    approval_ids = list(before_retry["approval_ids"])

    # mcp_call launches a fresh action-server process for every action.  Retry
    # therefore proves restart/resume using the existing assessment and bundle.
    resumed = mcp_call("retry_migration_action", common)
    if resumed["phase"] != "MIGRATING":
        raise RuntimeError("retry did not resume migration")
    results = wait_for_phase(common, {"WAITING_FINAL_APPROVAL"})
    after_resume = json.loads((session_root / "checkpoint.local.json").read_text(encoding="utf-8"))
    if after_resume["discovery_completed_at"] != discovery_completed or after_resume["approval_ids"] != approval_ids:
        raise RuntimeError("resume repeated discovery or customer scope approval")
    if after_resume["validation_status"] != "PASSED":
        raise RuntimeError("required API validation did not pass")

    if finish == "approve":
        result_envelope = mcp_tool_result("get_migration_action_state", common)
        final_binding = result_envelope["_meta"]["actionBindings"][0]
        final = mcp_call(final_binding["tool"], final_binding["arguments"])
        if final["phase"] != "COMPLETED":
            raise RuntimeError("final result approval did not complete")
        return final
    result_envelope = mcp_tool_result("get_migration_action_state", common)
    rollback_binding = result_envelope["_meta"]["actionBindings"][1]
    rolled = mcp_call(rollback_binding["tool"], rollback_binding["arguments"])
    if rolled["phase"] != "ROLLED_BACK":
        raise RuntimeError("rollback did not complete")
    return rolled


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--keep-work", action="store_true")
    args = parser.parse_args()
    temporary = tempfile.TemporaryDirectory(prefix="observability-migration-e2e-")
    workspace = Path(temporary.name)
    work_root = workspace / ".migration-work"
    target_root = workspace / "local-target"
    env_file = workspace / ".env"
    # Presence-only dummy values make compatibility assessment exercise the
    # configured-target path.  The emulator never sends or logs these values.
    env_file.write_text(
        'DD_API_KEY="emulator"\nDD_APP_KEY="emulator"\nDD_SITE="datadoghq.com"\n'
        'SPLUNK_O11Y_ACCESS_TOKEN="emulator"\nSPLUNK_O11Y_REALM="eu1"\n',
        encoding="utf-8",
    )
    env_file.chmod(0o600)

    run_session(
        workspace, work_root, target_root, env_file,
        "emulated-final-approval", finish="approve",
    )
    target_after_approval = json.loads(
        (target_root / "target-resources.local.json").read_text(encoding="utf-8")
    )["resources"]
    approved_owned = {
        key for key, value in target_after_approval.items()
        if value.get("session_id") == "emulated-final-approval"
    }
    if not approved_owned:
        raise RuntimeError("approved session created no emulator resources")

    run_session(
        workspace, work_root, target_root, env_file,
        "emulated-rollback-check", finish="rollback",
    )
    target_after_rollback = json.loads(
        (target_root / "target-resources.local.json").read_text(encoding="utf-8")
    )["resources"]
    if any(value.get("session_id") == "emulated-rollback-check" for value in target_after_rollback.values()):
        raise RuntimeError("rollback left session-owned resources behind")
    if not approved_owned.issubset(target_after_rollback):
        raise RuntimeError("rollback removed resources belonging to another session")

    resources = mcp_request("resources/list", {})
    uris = {item["uri"] for item in resources["resources"]}
    if "observability-migration://verification-checklist" not in uris:
        raise RuntimeError("checklist resource is not listed")
    if "ui://observability-migration/control-center-v1.html" not in uris:
        raise RuntimeError("control center resource is not listed")
    widget = mcp_request("resources/read", {
        "uri": "ui://observability-migration/control-center-v1.html",
        "workspace_root": str(ROOT),
    })
    widget_content = widget["contents"][0]
    if widget_content["mimeType"] != "text/html;profile=mcp-app" or (
        "ui/notifications/tool-result" not in widget_content["text"]
    ):
        raise RuntimeError("control center resource is not a valid MCP App template")
    checklist = mcp_request("resources/read", {
        "uri": "observability-migration://verification-checklist",
        "workspace_root": str(ROOT),
    })
    if not checklist["contents"][0]["text"].startswith("# Observability migration"):
        raise RuntimeError("checklist resource could not be read")
    report = mcp_request("resources/read", {
        "uri": "observability-migration://report/current", "workspace_root": str(workspace),
        "work_root": str(work_root), "session_id": "emulated-final-approval",
    })
    if '"api_validation": "PASSED"' not in report["contents"][0]["text"]:
        raise RuntimeError("validated report resource could not be read")

    print("FULL EMULATED MIGRATION COMPLETED SUCCESSFULLY")
    if args.keep_work:
        print(str(workspace))
        temporary.cleanup = lambda: None  # type: ignore[method-assign]
    else:
        temporary.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
