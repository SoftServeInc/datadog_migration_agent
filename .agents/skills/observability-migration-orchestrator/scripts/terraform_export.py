#!/usr/bin/env python3
"""Generate local Terraform import configuration for a completed migration."""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from orchestration_core.bundle import validate_bundle
from orchestration_core.common import SESSION_ID, read_private_json, value_hash
from orchestration_core.state import UnifiedStore


SUPPORTED_TYPES = {
    "dashboardgroup": "signalfx_dashboard_group",
    "dashboard": "signalfx_dashboard",
    "detector": "signalfx_detector",
    "slo": "signalfx_slo",
}
CHART_TYPES = {
    "TimeSeriesChart": "signalfx_time_chart",
    "SingleValue": "signalfx_single_value_chart",
    "List": "signalfx_list_chart",
    "Heatmap": "signalfx_heatmap_chart",
    "Text": "signalfx_text_chart",
}
MANIFEST = ".terraform-export-manifest.json"


def _file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _secure_write(path: Path, content: str) -> None:
    if path.exists() or path.is_symlink():
        raise ValueError(f"refusing to overwrite Terraform export file: {path.name}")
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(temporary, flags, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        path.chmod(0o600)
    finally:
        if temporary.exists():
            temporary.unlink()


def _chart_resource_types(session_root: Path) -> dict[str, str]:
    preview_path = session_root / "dashboard-execution" / "dashboard-preview.local.json"
    if not preview_path.is_file() or preview_path.is_symlink():
        return {}
    preview = read_private_json(preview_path, max_bytes=20_000_000)
    result: dict[str, str] = {}
    for dashboard in preview.get("dashboards", []):
        if not isinstance(dashboard, dict):
            raise ValueError("Terraform export dashboard preview is invalid")
        for chart in dashboard.get("charts", []):
            if not isinstance(chart, dict):
                raise ValueError("Terraform export chart preview is invalid")
            options = chart.get("options")
            chart_type = options.get("type") if isinstance(options, dict) else None
            resource_type = CHART_TYPES.get(str(chart_type))
            if resource_type is None:
                raise ValueError(f"Terraform provider does not support migrated chart type: {chart_type}")
            payload_hash = value_hash(chart)
            previous = result.setdefault(payload_hash, resource_type)
            if previous != resource_type:
                raise ValueError("Terraform chart payload maps to conflicting resource types")
    return result


def _resource_imports(session_root: Path, ledger: dict[str, Any]) -> list[dict[str, str]]:
    chart_types = _chart_resource_types(session_root)
    selected = [
        entry for entry in ledger["entries"]
        if entry["disposition"] in {"CREATED", "UPDATED"}
    ]
    imports: list[dict[str, str]] = []
    counters: Counter[str] = Counter()
    for entry in sorted(selected, key=lambda item: (item["object_type"], item["target_id_hash"])):
        object_type = entry["object_type"]
        if object_type == "chart":
            resource_type = chart_types.get(entry["payload_hash"])
            if resource_type is None:
                raise ValueError("Terraform chart type is not bound to the approved dashboard payload")
        else:
            resource_type = SUPPORTED_TYPES.get(object_type)
        if resource_type is None:
            raise ValueError(f"Terraform provider mapping is unavailable for: {object_type}")
        counters[resource_type] += 1
        label = f"migrated_{resource_type.removeprefix('signalfx_')}_{counters[resource_type]:03d}"
        imports.append({
            "resource_type": resource_type,
            "label": label,
            "target_id": entry["target_id"],
            "disposition": entry["disposition"],
        })
    if not imports:
        raise ValueError("completed migration has no created or updated resources to export")
    return imports


def _render_versions() -> str:
    return """terraform {
  required_version = \">= 1.5.0\"

  required_providers {
    signalfx = {
      source  = \"splunk-terraform/signalfx\"
      version = \">= 9.1.0, < 10.0.0\"
    }
  }
}
"""


def _render_provider(origin: str) -> str:
    return f"""variable \"signalfx_auth_token\" {{
  description = \"Splunk Observability Cloud access token. Supply with TF_VAR_signalfx_auth_token.\"
  type        = string
  sensitive   = true
}}

variable \"signalfx_api_url\" {{
  description = \"Splunk Observability Cloud API origin bound to the migration.\"
  type        = string
  default     = {json.dumps(origin)}
}}

provider \"signalfx\" {{
  auth_token = var.signalfx_auth_token
  api_url    = var.signalfx_api_url
}}
"""


def _render_imports(imports: list[dict[str, str]]) -> str:
    blocks = [
        "# Generated from the migration ownership ledger.\n"
        "# These import blocks do not create, update, or delete Splunk resources.\n"
    ]
    for item in imports:
        blocks.append(
            "import {\n"
            f"  to = {item['resource_type']}.{item['label']}\n"
            f"  id = {json.dumps(item['target_id'])}\n"
            "}\n"
        )
    return "\n".join(blocks)


def _render_readme(session_id: str, count: int) -> str:
    return f"""# Splunk Observability Terraform export

This directory was generated from migration session `{session_id}` and contains {count}
configuration-driven import blocks. It contains no credentials and the generator did not run
Terraform, change Splunk, or write to Git.

## Generate provider-native resource blocks

1. Export the token only in your shell: `export TF_VAR_signalfx_auth_token=...`
2. Run `terraform init`.
3. Run `terraform plan -generate-config-out=resources.generated.tf`.
4. Review `resources.generated.tf` and the plan before deciding whether to apply anything.

Terraform state and local variable files are ignored by the generated `.gitignore`. Reused target
resources are intentionally excluded so this export does not silently adopt unrelated ownership.
"""


def _existing_export(output: Path, expected: dict[str, Any]) -> dict[str, Any] | None:
    if not output.exists():
        return None
    if output.is_symlink() or not output.is_dir():
        raise ValueError("Terraform export path is not a safe directory")
    manifest_path = output / MANIFEST
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise ValueError("Terraform export directory already exists and is not managed by this session")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict):
        raise ValueError("Terraform export manifest is invalid")
    for key in ("session_id", "bundle_hash", "scope_hash", "resource_count"):
        if manifest.get(key) != expected[key]:
            raise ValueError("Terraform export already exists for different migration content")
    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        raise ValueError("Terraform export manifest has no file evidence")
    expected_names = {"versions.tf", "provider.tf", "imports.tf", "README.md", ".gitignore"}
    if set(files) != expected_names:
        raise ValueError("Terraform export manifest contains unexpected files")
    if {path.name for path in output.iterdir()} != {*expected_names, MANIFEST}:
        raise ValueError("Terraform export directory contains unexpected files")
    for name, digest in files.items():
        path = output / str(name)
        if path.is_symlink() or not path.is_file() or _file_hash(path) != digest:
            raise ValueError("Terraform export file differs from its manifest")
    return manifest


def export_terraform(workspace_root: Path, work_root: Path, session_id: str) -> dict[str, Any]:
    if not SESSION_ID.fullmatch(session_id):
        raise ValueError("invalid Terraform export session ID")
    if workspace_root.is_symlink():
        raise ValueError("Terraform export workspace cannot be a symlink")
    workspace = workspace_root.resolve(strict=True)
    if not workspace.is_dir():
        raise ValueError("Terraform export workspace is not a directory")
    resolved_work_root = work_root.resolve()
    session_path = resolved_work_root / session_id
    if session_path.is_symlink() or not session_path.is_dir():
        raise ValueError("Terraform export session directory is missing or unsafe")
    session_root = session_path.resolve()
    if resolved_work_root not in session_root.parents:
        raise ValueError("Terraform export session escapes the work root")
    if (session_root / "cleanup-result.local.json").exists():
        raise ValueError("Terraform export is unavailable after session-owned resources were cleaned up")

    runtime = session_root / "unified-execution"
    bundle = validate_bundle(read_private_json(runtime / "execution-bundle.local.json"))
    store = UnifiedStore(resolved_work_root, session_id)
    checkpoint = store.load_checkpoint()
    ledger = store.load_ledger()
    if bundle["session_id"] != session_id or ledger["bundle_hash"] != bundle["bundle_hash"]:
        raise ValueError("Terraform export provenance does not match the completed migration")
    if (
        checkpoint["session_id"] != session_id
        or checkpoint["bundle_hash"] != bundle["bundle_hash"]
        or checkpoint["status"] not in {"COMPLETED", "PARTIAL"}
    ):
        raise ValueError("Terraform export requires a completed validated runtime checkpoint")
    imports = _resource_imports(session_root, ledger)
    scope_hash = value_hash([
        (item["resource_type"], item["target_id"], item["disposition"]) for item in imports
    ])
    expected = {
        "session_id": session_id,
        "bundle_hash": bundle["bundle_hash"],
        "scope_hash": scope_hash,
        "resource_count": len(imports),
    }

    terraform_root = workspace / "terraform"
    if terraform_root.is_symlink():
        raise ValueError("Terraform root cannot be a symlink")
    terraform_root.mkdir(mode=0o700, exist_ok=True)
    output = terraform_root / f"observability-migration-{session_id}"
    existing = _existing_export(output, expected)
    if existing is not None:
        return {
            "status": "already_generated", "directory": str(output),
            "resourceCount": len(imports), "files": sorted(existing["files"]),
        }

    output.mkdir(mode=0o700)
    output.chmod(0o700)
    rendered = {
        "versions.tf": _render_versions(),
        "provider.tf": _render_provider(bundle["target_binding"]["origin"]),
        "imports.tf": _render_imports(imports),
        "README.md": _render_readme(session_id, len(imports)),
        ".gitignore": ".terraform/\n*.tfstate\n*.tfstate.*\n*.tfvars\n*.tfvars.json\ncrash.log\n",
    }
    for name, content in rendered.items():
        _secure_write(output / name, content)
    manifest = {
        "schema_version": "1.0", **expected,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "provider": "splunk-terraform/signalfx",
        "files": {name: _file_hash(output / name) for name in sorted(rendered)},
    }
    _secure_write(output / MANIFEST, json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return {
        "status": "generated", "directory": str(output),
        "resourceCount": len(imports), "files": sorted(rendered),
        "resourceTypes": dict(sorted(Counter(item["resource_type"] for item in imports).items())),
    }


__all__ = ["CHART_TYPES", "SUPPORTED_TYPES", "export_terraform"]
