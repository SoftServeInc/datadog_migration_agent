"""Bridges from the unified scheduler to the proven legacy object executors."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any
from urllib import parse

HERE = Path(__file__).resolve()
SKILLS = HERE.parents[3]
ASSESSMENT = SKILLS / "observability-migration-assessment" / "scripts"
DETECTOR = SKILLS / "observability-migration-executor" / "scripts"
SLO = SKILLS / "observability-migration-slo-executor" / "scripts"
DASHBOARD = SKILLS / "observability-migration-dashboard-executor" / "scripts"
sys.path[:0] = [str(ASSESSMENT), str(DETECTOR), str(SLO), str(DASHBOARD)]

from assessment_core.security import atomic_write_json  # noqa: E402
from dashboard_migration import (  # noqa: E402
    SplunkClient, canonical_hash as dashboard_hash, execute as execute_dashboards,
    read_object as read_dashboard_object, session_paths, validate as validate_dashboards,
)
from execution_core.adapter import AdapterError, SplunkDetectorClient  # noqa: E402
from execution_core.authorization import create_write_authorization  # noqa: E402
from execution_core.common import read_private_json, value_hash  # noqa: E402
from execution_core.executor import execute_wave, validate_wave  # noqa: E402
from execution_core.manifest import validate_sealed_manifest  # noqa: E402
from execution_core.state import ExecutionStore  # noqa: E402
from slo_adapter import SloAdapterError, SplunkSloClient  # noqa: E402
from slo_authorization import create_slo_authorization  # noqa: E402
from slo_executor import execute_slo_wave, find_existing_slo, validate_slo_wave  # noqa: E402
from slo_manifest import validate_slo_manifest  # noqa: E402
from slo_state import SloStore  # noqa: E402

from .scheduler import AdapterExecutionError, AdapterPreflightDefer


def _wrap_error(exc: Exception) -> AdapterExecutionError:
    return AdapterExecutionError(
        str(getattr(exc, "category", type(exc).__name__.lower())),
        safe_to_retry=bool(getattr(exc, "retriable", False)),
    )


class DetectorWaveBridge:
    def __init__(self, work_root: Path, session_id: str, client: SplunkDetectorClient):
        self.work_root, self.session_id, self.client = work_root, session_id, client

    def _manifest(self, operation: dict[str, Any]) -> tuple[dict[str, Any], ExecutionStore]:
        wave_id = str(operation["adapter_input"].get("wave_id", ""))
        store = ExecutionStore(self.work_root, self.session_id, wave_id)
        manifest = read_private_json(store.directory / "translation-manifest.local.json")
        validate_sealed_manifest(manifest)
        if manifest["manifest_hash"] != operation["payload_hash"]:
            raise ValueError("detector operation no longer matches its manifest")
        return manifest, store

    def _inputs(self, operation: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], ExecutionStore]:
        manifest, store = self._manifest(operation)
        for entry in manifest["entries"]:
            self.client.validate_detector_payload(entry["payload"])
        authorization = create_write_authorization(
            manifest, "authorized_operator", self.client.origin,
            value_hash(self.client.get_organization_id()), ttl_minutes=60,
        )
        atomic_write_json(store.directory / "write-authorization.local.json", authorization)
        return manifest, authorization, store

    def preflight(self, operation: dict[str, Any], context: dict[str, Any]) -> None:
        manifest, _store = self._manifest(operation)
        for entry in manifest["entries"]:
            self.client.validate_detector_payload(entry["payload"])
        if value_hash(self.client.get_organization_id()) != context["target_binding"]["organization_id_hash"]:
            raise ValueError("detector runtime organization mismatch")
        if manifest["source_session_id"] != context["session_id"]:
            raise ValueError("detector manifest session mismatch")

    def apply(self, operation: dict[str, Any], context: dict[str, Any]) -> list[dict[str, Any]]:
        try:
            manifest, authorization, store = self._inputs(operation)
            checkpoint = execute_wave(manifest, authorization, self.client, store)
            entries = {entry["object_ref"]: entry for entry in manifest["entries"]}
            return [{
                "object_ref": result["object_ref"], "object_type": "detector",
                "target_id": result["target_id"], "disposition": result["outcome"].upper(),
                "payload_hash": entries[result["object_ref"]]["payload_hash"], "dependencies": [],
            } for result in checkpoint.results]
        except Exception as exc:
            raise _wrap_error(exc) from exc

    def validate(self, operation: dict[str, Any], resources: list[dict[str, Any]], context: dict[str, Any]) -> list[dict[str, Any]]:
        try:
            manifest, authorization, store = self._inputs(operation)
            checkpoint = validate_wave(manifest, authorization, self.client, store)
            return [{"kind": "api_read_back", "validated": checkpoint.validated_count, "expected": len(manifest["entries"])}]
        except Exception as exc:
            raise _wrap_error(exc) from exc

    def rollback(self, entry: dict[str, Any], before_state: dict[str, Any] | None, context: dict[str, Any]) -> None:
        if entry["disposition"] != "CREATED":
            return
        actual = self.client.get_detector(entry["target_id"])
        if any(rule.get("notifications") for rule in actual.get("rules", [])):
            raise ValueError("refusing detector rollback while notifications are configured")
        from cleanup_created import delete_detector_or_slo  # noqa: PLC0415
        delete_detector_or_slo(self.client.origin, self.client.token, "detector", entry["target_id"])


class SloWaveBridge:
    def __init__(self, work_root: Path, session_id: str, client: SplunkSloClient):
        self.work_root, self.session_id, self.client = work_root, session_id, client

    def _manifest(self, operation: dict[str, Any]) -> tuple[dict[str, Any], SloStore]:
        wave_id = str(operation["adapter_input"].get("wave_id", ""))
        store = SloStore(self.work_root, self.session_id, wave_id)
        manifest = read_private_json(store.directory / "slo-manifest.local.json")
        validate_slo_manifest(manifest)
        if manifest["manifest_hash"] != operation["payload_hash"]:
            raise ValueError("SLO operation no longer matches its manifest")
        return manifest, store

    def _inputs(
        self, operation: dict[str, Any], *, validate_payload: bool = True,
    ) -> tuple[dict[str, Any], dict[str, Any], SloStore]:
        manifest, store = self._manifest(operation)
        if validate_payload:
            self.client.validate_slo_payload(manifest["entry"]["payload"])
        authorization = create_slo_authorization(
            manifest, "authorized_operator", self.client.origin,
            value_hash(self.client.get_organization_id()), ttl_minutes=60,
        )
        atomic_write_json(store.directory / "write-authorization.local.json", authorization)
        return manifest, authorization, store

    def preflight(self, operation: dict[str, Any], context: dict[str, Any]) -> None:
        manifest, _store = self._manifest(operation)
        if value_hash(self.client.get_organization_id()) != context["target_binding"]["organization_id_hash"]:
            raise ValueError("SLO runtime organization mismatch")
        if manifest["source_session_id"] != context["session_id"]:
            raise ValueError("SLO manifest session mismatch")
        try:
            existing = find_existing_slo(self.client, manifest["entry"])
        except ValueError as exc:
            raise AdapterPreflightDefer("slo_target_name_conflict") from exc
        if existing is None:
            self.client.validate_slo_payload(manifest["entry"]["payload"])

    def apply(self, operation: dict[str, Any], context: dict[str, Any]) -> list[dict[str, Any]]:
        try:
            manifest, authorization, store = self._inputs(operation)
            checkpoint = execute_slo_wave(manifest, authorization, self.client, store)
            if checkpoint.result is None:
                raise ValueError("SLO executor returned no resource")
            return [{
                "object_ref": checkpoint.result["object_ref"], "object_type": "slo",
                "target_id": checkpoint.result["target_id"],
                "disposition": checkpoint.result["outcome"].upper(),
                "payload_hash": manifest["entry"]["payload_hash"], "dependencies": [],
            }]
        except Exception as exc:
            raise _wrap_error(exc) from exc

    def validate(self, operation: dict[str, Any], resources: list[dict[str, Any]], context: dict[str, Any]) -> list[dict[str, Any]]:
        try:
            # The dry-run payload endpoint belongs to pre-create validation.
            # Post-create validation must use only organization/read-back APIs.
            manifest, authorization, store = self._inputs(operation, validate_payload=False)
            checkpoint = validate_slo_wave(manifest, authorization, self.client, store)
            return [{"kind": "api_read_back", "validated": bool(checkpoint.result and checkpoint.result["validated"])}]
        except Exception as exc:
            raise _wrap_error(exc) from exc

    def rollback(self, entry: dict[str, Any], before_state: dict[str, Any] | None, context: dict[str, Any]) -> None:
        if entry["disposition"] != "CREATED":
            return
        from cleanup_created import delete_detector_or_slo  # noqa: PLC0415
        delete_detector_or_slo(self.client.origin, self.client.token, "slo", entry["target_id"])


class DashboardSessionBridge:
    def __init__(self, work_root: Path, session_id: str, client: SplunkClient):
        self.paths = session_paths(work_root, session_id)
        self.client = client

    def _preview(self, operation: dict[str, Any]) -> dict[str, Any]:
        preview = read_dashboard_object(self.paths["preview"])
        unsigned = {key: value for key, value in preview.items() if key != "preview_hash"}
        if preview.get("preview_hash") != dashboard_hash(unsigned) or preview["preview_hash"] != operation["payload_hash"]:
            raise ValueError("dashboard operation no longer matches its preview")
        if any(item.get("unsupported_chart_count") for item in preview.get("dashboards", [])):
            raise ValueError("dashboard preview contains unsupported widgets")
        return preview

    def preflight(self, operation: dict[str, Any], context: dict[str, Any]) -> None:
        self._preview(operation)
        organization = self.client.call("GET", "/v2/organization").get("id")
        if dashboard_hash(organization) != context["target_binding"]["organization_id_hash"]:
            raise ValueError("dashboard runtime organization mismatch")

    def apply(self, operation: dict[str, Any], context: dict[str, Any]) -> list[dict[str, Any]]:
        preview = self._preview(operation)
        result = execute_dashboards(self.paths, self.client)
        resources: list[dict[str, Any]] = [{
            "object_ref": "dashboard-group", "object_type": "dashboardgroup",
            "target_id": result["group_id"], "disposition": result["group_outcome"].upper(),
            "payload_hash": dashboard_hash(preview["group"]), "dependencies": [],
        }]
        resources.extend({
            "object_ref": item["object_ref"], "object_type": "chart",
            "target_id": item["target_id"], "disposition": item["outcome"].upper(),
            "payload_hash": item["payload_hash"], "dependencies": [],
        } for item in result.get("charts", []))
        resources.extend({
            "object_ref": item["object_ref"], "object_type": "dashboard",
            "target_id": item["target_id"], "disposition": item["outcome"].upper(),
            "payload_hash": item["payload_hash"], "dependencies": [],
            "before_state": item.get("before_state"),
        } for item in result["results"])
        return resources

    def validate(self, operation: dict[str, Any], resources: list[dict[str, Any]], context: dict[str, Any]) -> list[dict[str, Any]]:
        result = validate_dashboards(self.paths, self.client)
        evidence: list[dict[str, Any]] = [{
            "kind": "api_read_back", "validated": result["validated_dashboard_count"],
            "expected": len(result["results"]), "status": "passed",
        }]
        evidence_path = self.paths["result"].parent / "browser-validation.local.json"
        if not evidence_path.exists():
            evidence.append({
                "kind": "browser_render", "validated": 0,
                "expected": len(result["results"]),
                "status": "BROWSER_VALIDATION_SKIPPED",
            })
            return evidence
        try:
            browser = read_dashboard_object(evidence_path)
            unsigned = {key: value for key, value in browser.items() if key != "evidence_hash"}
            expected = {item["object_ref"]: value_hash(item["target_id"]) for item in result["results"]}
            observed = browser.get("dashboards")
            if (
                set(browser) != {"schema_version", "session_id", "result_hash", "checked_at", "dashboards", "evidence_hash"}
                or browser.get("schema_version") != "1.0"
                or browser.get("session_id") != context["session_id"]
                or browser.get("result_hash") != result["result_hash"]
                or browser.get("evidence_hash") != dashboard_hash(unsigned)
                or not isinstance(observed, list)
            ):
                raise ValueError("dashboard browser evidence binding is invalid")
            observed_refs: dict[str, str] = {}
            required_checks = {
                "title_match", "chart_count_match", "no_render_errors",
                "compact_layout", "source_geometry_preserved",
            }
            for item in observed:
                if not isinstance(item, dict) or set(item) != {"object_ref", "target_id_hash", "checks", "passed"}:
                    raise ValueError("dashboard browser evidence item is invalid")
                checks = item["checks"]
                if (
                    not isinstance(checks, dict) or set(checks) != required_checks
                    or any(value is not True for value in checks.values()) or item["passed"] is not True
                ):
                    raise ValueError("dashboard browser validation did not pass")
                observed_refs[str(item["object_ref"])] = str(item["target_id_hash"])
            if observed_refs != expected:
                raise ValueError("dashboard browser evidence scope differs from execution result")
            evidence.append({
                "kind": "browser_render", "validated": len(observed),
                "expected": len(result["results"]), "status": "passed",
            })
        except Exception as exc:
            evidence.append({
                "kind": "browser_render", "validated": 0,
                "expected": len(result["results"]),
                "status": "BROWSER_VALIDATION_SKIPPED",
                "warning": str(exc),
            })
        return evidence

    def rollback(self, entry: dict[str, Any], before_state: dict[str, Any] | None, context: dict[str, Any]) -> None:
        if entry["disposition"] == "UPDATED":
            if entry["object_type"] != "dashboard" or before_state is None:
                raise ValueError("dashboard update rollback requires before-state")
            self.client.call(
                "PUT", f"/v2/dashboard/{parse.quote(entry['target_id'], safe='')}", before_state,
            )
            return
        if entry["disposition"] != "CREATED":
            return
        from cleanup_created import ResourceClient  # noqa: PLC0415
        cleanup = ResourceClient(self.client.origin, self.client.token)
        cleanup.delete(entry["object_type"], entry["target_id"])
        if cleanup.get(entry["object_type"], entry["target_id"]) is not None:
            raise ValueError("dashboard resource still exists after rollback")


__all__ = ["DashboardSessionBridge", "DetectorWaveBridge", "SloWaveBridge"]
