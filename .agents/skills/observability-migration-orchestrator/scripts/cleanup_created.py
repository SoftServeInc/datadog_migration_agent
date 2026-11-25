#!/usr/bin/env python3
"""Inspect and delete only target objects proven owned by a migration session."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib import error, parse, request


HERE = Path(__file__).resolve().parent
SKILLS = HERE.parents[1]
ASSESSMENT = SKILLS / "observability-migration-assessment" / "scripts"
DETECTOR = SKILLS / "observability-migration-executor" / "scripts"
SLO = SKILLS / "observability-migration-slo-executor" / "scripts"
sys.path[:0] = [str(ASSESSMENT), str(DETECTOR), str(SLO)]

from assessment_core.config import parse_dotenv, select_splunk_o11y_credentials  # noqa: E402
from execution_core.adapter import AdapterError, SplunkDetectorClient  # noqa: E402
from execution_core.authorization import validate_write_authorization  # noqa: E402
from execution_core.common import (  # noqa: E402
    SESSION_ID, atomic_write_json, read_private_json, resolve_splunk_origin, value_hash,
)
from execution_core.executor import _assert_equivalent as assert_detector_equivalent  # noqa: E402
from execution_core.manifest import validate_sealed_manifest  # noqa: E402
from execution_core.state import ExecutionStore  # noqa: E402
from slo_adapter import SloAdapterError, SplunkSloClient  # noqa: E402
from slo_authorization import validate_slo_authorization  # noqa: E402
from slo_executor import _assert_equivalent as assert_slo_equivalent  # noqa: E402
from slo_manifest import validate_slo_manifest  # noqa: E402
from slo_state import SloStore  # noqa: E402
from orchestration_core.state import UnifiedStore  # noqa: E402


CLEANUP_PRIORITY = {
    "dashboard": 0,
    "chart": 1,
    "dashboardgroup": 2,
    "detector": 3,
    "slo": 4,
}


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(
        self, req: object, fp: object, code: int, msg: str,
        headers: object, newurl: str,
    ) -> None:
        return None


class ResourceClient:
    """Narrow GET/DELETE client for dashboard resources."""

    def __init__(self, origin: str, token: str, *, timeout: int = 15):
        if not origin.startswith("https://api.") or not token or any(c.isspace() for c in token):
            raise ValueError("invalid cleanup target credentials")
        self.origin = origin
        self.token = token
        self.timeout = timeout
        self.opener = request.build_opener(NoRedirect())

    def _call(
        self, method: str, path: str, *, query: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        allowed_collection = method == "GET" and path in {"/v2/chart", "/v2/dashboard"}
        allowed_item = method in {"GET", "DELETE"} and any(
            path.startswith(f"/v2/{kind}/")
            for kind in ("chart", "dashboard", "dashboardgroup")
        )
        if not (allowed_collection or allowed_item):
            raise ValueError("unsupported cleanup resource operation")
        url = self.origin + path
        if query:
            url += "?" + parse.urlencode(query, doseq=True)
        req = request.Request(
            url, method=method,
            headers={
                "Accept": "application/json", "Content-Type": "application/json",
                "X-SF-TOKEN": self.token,
                "User-Agent": "cisco-innovation-cleanup/1.0",
            },
        )
        try:
            with self.opener.open(req, timeout=self.timeout) as response:
                if str(getattr(response, "url", url)) != url:
                    raise RuntimeError("cleanup redirect rejected")
                raw = response.read(10_000_001)
                if len(raw) > 10_000_000:
                    raise RuntimeError("cleanup response too large")
                value = json.loads(raw.decode()) if raw else {}
                if not isinstance(value, dict):
                    raise RuntimeError("cleanup response is not an object")
                return value
        except error.HTTPError as exc:
            if exc.code == 404:
                return None
            raise RuntimeError(f"cleanup_http_{exc.code}") from None
        except (error.URLError, TimeoutError, OSError):
            raise RuntimeError("cleanup_network_error") from None

    def get(self, kind: str, target_id: str) -> dict[str, Any] | None:
        if kind not in {"chart", "dashboard", "dashboardgroup"} or not target_id:
            raise ValueError("invalid cleanup resource identity")
        return self._call("GET", f"/v2/{kind}/{parse.quote(target_id, safe='')}")

    def find_charts(self, marker: str) -> list[dict[str, Any]]:
        value = self._call("GET", "/v2/chart", query={"tags": marker, "limit": 2})
        results = (value or {}).get("results")
        if not isinstance(results, list) or any(not isinstance(item, dict) for item in results):
            raise RuntimeError("invalid chart search response")
        return results

    def delete(self, kind: str, target_id: str) -> str:
        return "already_absent" if self._call(
            "DELETE", f"/v2/{kind}/{parse.quote(target_id, safe='')}",
        ) is None else "delete_accepted"


def credentials(env_file: Path) -> tuple[str, str, str | None]:
    values = parse_dotenv(env_file)
    token, realm = select_splunk_o11y_credentials(values)
    if not token or not realm:
        raise ValueError("complete Splunk Observability credentials are required")
    return resolve_splunk_origin(realm), token, values.get("SPLUNK_O11Y_ORG_ID") or None


def is_not_found(exc: Exception) -> bool:
    return getattr(exc, "category", "") == "http_404"


def load_detector_slo_targets(
    work_root: Path, session_id: str, origin: str, actual_org_id: str,
) -> list[dict[str, Any]]:
    targets: list[dict[str, Any]] = []
    execution_root = work_root / session_id / "execution"
    for checkpoint_path in sorted(execution_root.glob("wave-*/execution-checkpoint.local.json")):
        wave_id = checkpoint_path.parent.name
        checkpoint = ExecutionStore(work_root, session_id, wave_id).load()
        manifest = read_private_json(checkpoint_path.parent / "translation-manifest.local.json")
        authorization = read_private_json(checkpoint_path.parent / "write-authorization.local.json")
        validate_sealed_manifest(manifest)
        validate_write_authorization(
            authorization, manifest,
            current_time=datetime.fromisoformat(str(authorization["approved_at"])),
        )
        if (
            checkpoint.manifest_hash != manifest["manifest_hash"]
            or checkpoint.authorization_hash != authorization["approval_hash"]
            or authorization["target_origin"] != origin
            or authorization["target_org_id_hash"] != value_hash(actual_org_id)
        ):
            raise ValueError(f"detector wave binding mismatch: {wave_id}")
        entries = {entry["object_ref"]: entry for entry in manifest["entries"]}
        for result in checkpoint.results:
            if result["outcome"] != "created":
                continue
            entry = entries.get(result["object_ref"])
            if (
                entry is None or result["execution_key"] != entry["execution_key"]
                or result["target_kind"] != "detector" or result["validated"] is not True
            ):
                raise ValueError(f"detector result binding mismatch: {wave_id}")
            targets.append({
                "kind": "detector", "target_id": result["target_id"],
                "object_ref": result["object_ref"], "entry": entry,
            })

    slo_root = work_root / session_id / "slo-execution"
    for checkpoint_path in sorted(slo_root.glob("slo-wave-*/execution-checkpoint.local.json")):
        wave_id = checkpoint_path.parent.name
        checkpoint = SloStore(work_root, session_id, wave_id).load()
        if checkpoint.result is None or checkpoint.result["outcome"] != "created":
            continue
        manifest = read_private_json(checkpoint_path.parent / "slo-manifest.local.json")
        authorization = read_private_json(checkpoint_path.parent / "write-authorization.local.json")
        validate_slo_manifest(manifest)
        validate_slo_authorization(
            authorization, manifest,
            current_time=datetime.fromisoformat(str(authorization["approved_at"])),
        )
        result = checkpoint.result
        if (
            checkpoint.manifest_hash != manifest["manifest_hash"]
            or checkpoint.authorization_hash != authorization["approval_hash"]
            or authorization["target_origin"] != origin
            or authorization["target_org_id_hash"] != value_hash(actual_org_id)
            or result["object_ref"] != manifest["entry"]["object_ref"]
            or result["execution_key"] != manifest["entry"]["execution_key"]
            or result["validated"] is not True
        ):
            raise ValueError(f"SLO wave binding mismatch: {wave_id}")
        targets.append({
            "kind": "slo", "target_id": result["target_id"],
            "object_ref": result["object_ref"], "entry": manifest["entry"],
        })
    return targets


def load_dashboard_scope(work_root: Path, session_id: str) -> dict[str, Any] | None:
    root = work_root / session_id / "dashboard-execution"
    result_path = root / "dashboard-result.local.json"
    preview_path = root / "dashboard-preview.local.json"
    if not result_path.exists() and not preview_path.exists():
        return None
    result = read_private_json(result_path, max_bytes=20_000_000)
    preview = read_private_json(preview_path, max_bytes=20_000_000)
    expected_preview_hash = value_hash({
        key: value for key, value in preview.items() if key != "preview_hash"
    })
    if (
        preview.get("preview_hash") != expected_preview_hash
        or result.get("preview_hash") != preview.get("preview_hash")
        or result.get("session_id") != session_id
    ):
        raise ValueError("dashboard result binding mismatch")
    previews = {item["object_ref"]: item for item in preview.get("dashboards", [])}
    ledger = UnifiedStore(work_root, session_id).load_ledger()
    chart_entries = {
        entry["object_ref"]: entry
        for entry in ledger["entries"]
        if entry["object_type"] == "chart" and entry["disposition"] == "CREATED"
    }
    dashboards: list[dict[str, Any]] = []
    for item in result.get("results", []):
        expected = previews.get(item.get("object_ref"))
        if expected is None or item.get("validated") is not True:
            raise ValueError("dashboard target is not bound to its preview")
        dashboards.append({
            "kind": "dashboard", "target_id": item["target_id"],
            "object_ref": item["object_ref"], "name": expected["target_name"],
        })
    return {
        "group": {
            "kind": "dashboardgroup", "target_id": result["group_id"],
            "object_ref": "dashboard-group", "name": preview["group"]["name"],
        },
        "dashboards": dashboards,
        "chart_payloads": [
            chart for dashboard in preview["dashboards"] for chart in dashboard["charts"]
        ],
        "chart_entries": chart_entries,
    }


def inspect_targets(
    targets: list[dict[str, Any]], dashboard_scope: dict[str, Any] | None,
    detector_client: SplunkDetectorClient, slo_client: SplunkSloClient,
    resource_client: ResourceClient,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    resolved: list[dict[str, Any]] = []
    counts = {kind: 0 for kind in ("detector", "slo", "dashboard", "chart", "dashboardgroup")}
    for item in targets:
        try:
            if item["kind"] == "detector":
                actual = detector_client.get_detector(item["target_id"])
                assert_detector_equivalent(item["entry"], actual)
                if any(rule.get("notifications") for rule in actual.get("rules", [])):
                    raise ValueError("refusing to delete a detector with notifications")
            else:
                actual = slo_client.get_slo(item["target_id"])
                assert_slo_equivalent(item["entry"], actual)
            resolved.append(item)
            counts[item["kind"]] += 1
        except (AdapterError, SloAdapterError) as exc:
            if not is_not_found(exc):
                raise

    if dashboard_scope is None:
        return resolved, counts
    group = dashboard_scope["group"]
    actual_group = resource_client.get("dashboardgroup", group["target_id"])
    if actual_group is not None:
        if actual_group.get("name") != group["name"] or "AI-Created" not in str(actual_group.get("description", "")):
            raise ValueError("dashboard group ownership proof failed")
        resolved.append(group)
        counts["dashboardgroup"] += 1
    for item in dashboard_scope["dashboards"]:
        actual = resource_client.get("dashboard", item["target_id"])
        if actual is None:
            continue
        if actual.get("name") != item["name"] or "AI-Created" not in str(actual.get("description", "")):
            raise ValueError("dashboard ownership proof failed")
        resolved.append(item)
        counts["dashboard"] += 1
    chart_ids: set[str] = set()
    observed_markers: set[str] = set()
    for payload in dashboard_scope["chart_payloads"]:
        marker = next((tag for tag in payload.get("tags", []) if tag.startswith("codex-migration-")), None)
        if marker is None:
            raise ValueError("chart payload marker is missing")
        entry = dashboard_scope["chart_entries"].get(marker)
        if (
            entry is None
            or entry.get("payload_hash") != value_hash(payload)
            or entry.get("target_id_hash") != value_hash(entry.get("target_id"))
        ):
            raise ValueError("chart ownership ledger binding failed")
        observed_markers.add(marker)
        chart_id = entry["target_id"]
        actual = resource_client.get("chart", chart_id)
        if actual is None:
            continue
        if (
            actual.get("name") != payload.get("name")
            or not set(payload.get("tags", [])).issubset(set(actual.get("tags", [])))
        ):
            raise ValueError("chart ownership proof failed")
        if chart_id in chart_ids:
            raise ValueError("duplicate chart identity in cleanup scope")
        chart_ids.add(chart_id)
        resolved.append({
            "kind": "chart", "target_id": chart_id,
            "object_ref": marker, "name": payload.get("name"),
        })
        counts["chart"] += 1
    if observed_markers != set(dashboard_scope["chart_entries"]):
        raise ValueError("chart ownership ledger contains unexpected scope")
    identities = {(item["kind"], item["target_id"]) for item in resolved}
    if len(identities) != len(resolved):
        raise ValueError("duplicate target identity in cleanup scope")
    return resolved, counts


def delete_detector_or_slo(origin: str, token: str, kind: str, target_id: str) -> str:
    url = f"{origin}/v2/{kind}/{parse.quote(target_id, safe='')}"
    req = request.Request(url, method="DELETE", headers={"Accept": "application/json", "X-SF-TOKEN": token})
    try:
        with request.build_opener(NoRedirect()).open(req, timeout=15) as response:
            if str(getattr(response, "url", url)) != url or response.status not in {200, 202, 204}:
                raise RuntimeError("unexpected cleanup response")
            response.read(4097)
            return "delete_accepted"
    except error.HTTPError as exc:
        if exc.code == 404:
            return "already_absent"
        raise RuntimeError(f"cleanup_http_{exc.code}") from None
    except (error.URLError, TimeoutError, OSError):
        raise RuntimeError("cleanup_outcome_ambiguous") from None


def verified_absent(
    item: dict[str, Any], detector_client: SplunkDetectorClient,
    slo_client: SplunkSloClient, resource_client: ResourceClient,
) -> bool:
    try:
        if item["kind"] == "detector":
            detector_client.get_detector(item["target_id"])
            return False
        if item["kind"] == "slo":
            slo_client.get_slo(item["target_id"])
            return False
        return resource_client.get(item["kind"], item["target_id"]) is None
    except (AdapterError, SloAdapterError) as exc:
        if is_not_found(exc):
            return True
        raise


def revoke_session_apply_authorizations(work_root: Path, session_id: str) -> list[str]:
    """Prevent a cleaned session from being resumed into target writes."""
    directory = work_root / session_id / "unified-execution"
    revoked: list[str] = []
    for name in (
        "apply-approval.local.json",
        "interactive-apply-approval.local.json",
        "interactive-apply-approval.used.local.json",
    ):
        source = directory / name
        if not source.exists():
            continue
        if source.is_symlink() or not source.is_file():
            raise ValueError("unsafe apply authorization artifact during cleanup")
        destination = directory / name.replace(".local.json", ".revoked.local.json")
        source.replace(destination)
        revoked.append(name)
    return revoked


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--work-root", default=".migration-work")
    parser.add_argument("--env-file", default=".env")
    parser.add_argument("--confirm-delete-created", action="store_true")
    args = parser.parse_args()
    if not SESSION_ID.fullmatch(args.session_id):
        raise ValueError("invalid session ID")
    work_root = Path(args.work_root).resolve()
    origin, token, configured_org = credentials(Path(args.env_file))
    detector_client = SplunkDetectorClient(origin, token)
    slo_client = SplunkSloClient(origin, token)
    resource_client = ResourceClient(origin, token)
    actual_org_id = detector_client.get_organization_id()
    if configured_org is not None and configured_org != actual_org_id:
        raise ValueError("configured organization does not match authenticated organization")
    targets = load_detector_slo_targets(work_root, args.session_id, origin, actual_org_id)
    dashboard_scope = load_dashboard_scope(work_root, args.session_id)
    resolved, counts = inspect_targets(
        targets, dashboard_scope, detector_client, slo_client, resource_client,
    )
    summary = {
        "session_id": args.session_id, "target_origin": origin,
        "target_org_id_hash": value_hash(actual_org_id), "created_only_scope": True,
        "scope": counts, "cleanup_hash": value_hash([
            (item["kind"], item["target_id"]) for item in resolved
        ]),
        "external_mutations_performed": 0,
    }
    if not args.confirm_delete_created:
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0

    results: list[dict[str, Any]] = []
    output = work_root / args.session_id / "cleanup-result.local.json"
    for item in sorted(resolved, key=lambda value: CLEANUP_PRIORITY[value["kind"]]):
        if item["kind"] in {"detector", "slo"}:
            transport = delete_detector_or_slo(origin, token, item["kind"], item["target_id"])
        else:
            transport = resource_client.delete(item["kind"], item["target_id"])
        if not verified_absent(item, detector_client, slo_client, resource_client):
            raise RuntimeError("target still exists after cleanup request")
        results.append({
            "kind": item["kind"], "object_ref": item["object_ref"],
            "target_id_hash": value_hash(item["target_id"]), "outcome": "deleted",
            "delete_transport": transport, "verified_absent": True,
        })
        atomic_write_json(output, {
            "schema_version": "2.0", "session_id": args.session_id,
            "target_origin": origin, "target_org_id_hash": value_hash(actual_org_id),
            "cleanup_hash": summary["cleanup_hash"],
            "updated_at": datetime.now(timezone.utc).isoformat(), "results": results,
        })
    revoked = revoke_session_apply_authorizations(work_root, args.session_id)
    print(json.dumps({
        **summary, "deleted": len(results), "verified_absent": len(results),
        "external_mutations_performed": len(results), "status": "cleanup_complete",
        "revoked_apply_authorizations": revoked,
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
