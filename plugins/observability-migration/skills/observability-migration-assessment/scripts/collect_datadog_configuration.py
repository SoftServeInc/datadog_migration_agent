#!/usr/bin/env python3
"""Collect a read-only, migration-oriented Datadog configuration inventory.

The collector intentionally uses only Python's standard library. It normalizes
source objects, redacts notification addresses and secret-shaped fields, and
records endpoint permission failures without aborting the whole assessment.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import HTTPRedirectHandler, Request, build_opener

from assessment_core.approval import load_authorization, public_approval_ref
from assessment_core.audit import append_audit_event
from assessment_core.config import merged_environment
from assessment_core.model import SessionState
from assessment_core.security import (
    atomic_write,
    atomic_write_json,
    ensure_private_directory,
    redact,
    resolve_datadog_api_base,
    safe_error,
)
from assessment_core.state import CheckpointStore


EMAIL = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.I)
NOTIFY = re.compile(r"@([a-zA-Z0-9_-]+)(?:-[^\s,]+)?")
QUERY_KEYS = {"q", "query", "formula", "search", "metric", "data_source"}
MAX_RESPONSE_BYTES = 16 * 1024 * 1024
MAX_DISCOVERY_REQUESTS = 5000
SOURCE_OBJECT_KEYS = (
    "dashboards", "monitors", "slos", "synthetics", "log_indexes", "log_pipelines"
)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def config_value(values: dict[str, str], *names: str) -> str:
    for name in names:
        value = values.get(name)
        if value:
            return value
    return ""


redacted = redact


def validate_discovery_result(result: dict[str, Any]) -> int:
    """Reject transport-wide discovery failures instead of reporting an empty estate."""
    access = result.get("access")
    errors = result.get("errors")
    counts = result.get("counts")
    if not isinstance(access, dict) or not isinstance(errors, list) or not isinstance(counts, dict):
        raise RuntimeError("Datadog discovery returned an invalid result")
    successful_endpoints = [
        key for key in SOURCE_OBJECT_KEYS if access.get(key) == "available"
    ]
    if not successful_endpoints:
        categories = {
            str(item.get("error", "unknown"))
            for item in errors
            if isinstance(item, dict)
        }
        reason = "network/runtime access failed" if categories & {
            "runtimeerror", "network_error"
        } else "credentials or permissions were rejected"
        raise RuntimeError(
            f"Datadog discovery unavailable: no source endpoint succeeded ({reason})"
        )
    return sum(int(counts.get(key, 0) or 0) for key in SOURCE_OBJECT_KEYS)


class NoRedirectHandler(HTTPRedirectHandler):
    """Fail closed instead of forwarding Datadog credentials to a redirect."""

    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


class DatadogAPI:
    def __init__(self, api_key: str, app_key: str, site: str, timeout: int = 30):
        if not 1 <= timeout <= 60:
            raise ValueError("Datadog timeout must be between 1 and 60 seconds")
        self.base = resolve_datadog_api_base(site)
        self.timeout = timeout
        self.requests_attempted = 0
        self.opener = build_opener(NoRedirectHandler())
        self.headers = {
            "Accept": "application/json",
            "DD-API-KEY": api_key,
            "DD-APPLICATION-KEY": app_key,
            "User-Agent": "observability-migration-assessment/1.0",
        }

    def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        if not path.startswith("/api/") or "://" in path:
            raise ValueError("refusing non-Datadog API path")
        url = self.base + path
        if params:
            url += "?" + urlencode(params, doseq=True)
        request = Request(url, headers=self.headers, method="GET")
        for attempt in range(4):
            if self.requests_attempted >= MAX_DISCOVERY_REQUESTS:
                raise RuntimeError("request_budget_exceeded")
            self.requests_attempted += 1
            try:
                with self.opener.open(request, timeout=self.timeout) as response:
                    content_length = response.headers.get("Content-Length")
                    if content_length:
                        try:
                            if int(content_length) > MAX_RESPONSE_BYTES:
                                raise RuntimeError("response_too_large")
                        except ValueError as exc:
                            raise RuntimeError("invalid_content_length") from exc
                    payload = response.read(MAX_RESPONSE_BYTES + 1)
                    if len(payload) > MAX_RESPONSE_BYTES:
                        raise RuntimeError("response_too_large")
                    return json.loads(payload)
            except HTTPError as exc:
                if exc.code == 429 and attempt < 3:
                    time.sleep(2**attempt)
                    continue
                raise RuntimeError(f"http_{exc.code}") from exc
            except URLError as exc:
                if attempt < 3:
                    time.sleep(2**attempt)
                    continue
                raise RuntimeError("network_error") from exc


def list_items(payload: Any, *keys: str) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if not isinstance(payload, dict):
        return []
    for key in keys:
        value = payload.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    data = payload.get("data")
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    return []


def extract_fragments(value: Any, path: str = "") -> list[dict[str, str]]:
    fragments: list[dict[str, str]] = []
    if isinstance(value, dict):
        for key, item in value.items():
            child = f"{path}.{key}" if path else key
            if key in QUERY_KEYS and isinstance(item, str) and item.strip():
                fragments.append({"path": child, "value": item.strip()})
            fragments.extend(extract_fragments(item, child))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            fragments.extend(extract_fragments(item, f"{path}[{index}]"))
    return fragments


def notification_types(message: str) -> list[str]:
    types = set()
    message_without_emails = EMAIL.sub("", message or "")
    for match in NOTIFY.finditer(message_without_emails):
        prefix = match.group(1).lower()
        matched = next((kind for kind in ("slack", "pagerduty", "opsgenie", "webhook", "teams", "jira", "case") if prefix == kind or prefix.startswith(kind + "-")), None)
        if matched:
            types.add(matched)
        elif prefix.startswith("http"):
            types.add("webhook")
        else:
            types.add("other")
    if EMAIL.search(message or ""):
        types.add("email")
    return sorted(types)


def team_tags(tags: list[str]) -> list[str]:
    return sorted({tag for tag in tags if str(tag).lower().startswith(("team:", "owner:", "squad:"))})


def complexity_score(queries: list[dict[str, str]], payload: dict[str, Any], source_type: str) -> tuple[int, str]:
    score = 1 + max(0, len(queries) - 1)
    text = json.dumps(payload, sort_keys=True).lower()
    if any(term in text for term in ("anomal", "forecast", "outlier", "formula")):
        score += 1
    if any(term in text for term in ("group_by", "groupby", "multi alert", "notify_by")):
        score += 1
    if source_type == "monitor" and (payload.get("type") == "composite" or "monitor(" in text):
        score += 1
    if any(term in text for term in ("logs", "spans", "rum", "security", "database-monitoring", "network")):
        score += 1
    options = payload.get("options") if isinstance(payload.get("options"), dict) else {}
    if any(options.get(key) for key in ("renotify_interval", "scheduling_options", "evaluation_delay", "new_group_delay")):
        score += 1
    return score, "low" if score <= 2 else "medium" if score <= 4 else "high"


def normalize_dashboard(item: dict[str, Any], detail: dict[str, Any] | None = None) -> dict[str, Any]:
    source = detail or item
    queries = extract_fragments(source.get("widgets", []))
    tags = [str(tag) for tag in source.get("tags", []) if isinstance(tag, str)]
    score, level = complexity_score(queries, source, "dashboard")
    widgets = source.get("widgets", []) if isinstance(source.get("widgets"), list) else []
    widget_types = Counter()
    for widget in widgets:
        if isinstance(widget, dict):
            definition = widget.get("definition", {})
            if isinstance(definition, dict):
                widget_types[str(definition.get("type", "unknown"))] += 1
    return {
        "source_type": "dashboard",
        "source_id": source.get("id") or item.get("id"),
        "name": source.get("title") or item.get("title"),
        "status": "active",
        "modified_at": source.get("modified_at"),
        "created_at": source.get("created_at"),
        "tags": tags,
        "owner_tags": team_tags(tags),
        "author_present": bool(source.get("author_handle") or source.get("author_name")),
        "layout_type": source.get("layout_type"),
        "widget_count": len(widgets),
        "widget_types": dict(sorted(widget_types.items())),
        # Restricted local execution input. This field remains in the private
        # inventory and is never copied into Codex-safe projection or IR files.
        "dashboard_spec": {
            "description": source.get("description"),
            "layout_type": source.get("layout_type"),
            "template_variables": source.get("template_variables", []),
            "widgets": widgets,
        },
        "queries": queries,
        "complexity_score": score,
        "complexity": level,
        "evidence": "GET /api/v1/dashboard and GET /api/v1/dashboard/{id}",
    }


def normalize_monitor(item: dict[str, Any]) -> dict[str, Any]:
    queries = [{"path": "query", "value": item["query"]}] if item.get("query") else []
    tags = [str(tag) for tag in item.get("tags", []) if isinstance(tag, str)]
    score, level = complexity_score(queries, item, "monitor")
    options = item.get("options") if isinstance(item.get("options"), dict) else {}
    return {
        "source_type": "monitor",
        "source_id": item.get("id"),
        "name": item.get("name"),
        "monitor_type": item.get("type"),
        "status": item.get("overall_state") or "unknown",
        "created_at": item.get("created"),
        "modified_at": item.get("modified"),
        "priority": item.get("priority"),
        "tags": tags,
        "owner_tags": team_tags(tags),
        "queries": queries,
        "thresholds": redacted(options.get("thresholds", {})),
        "notify_by": options.get("notify_by", []),
        "notification_types": notification_types(str(item.get("message", ""))),
        "restricted_role_count": len(item.get("restricted_roles", []) or []),
        "complexity_score": score,
        "complexity": level,
        "evidence": "GET /api/v1/monitor",
    }


def normalize_slo(item: dict[str, Any]) -> dict[str, Any]:
    tags = [str(tag) for tag in item.get("tags", []) if isinstance(tag, str)]
    thresholds = item.get("thresholds", []) if isinstance(item.get("thresholds"), list) else []
    monitor_ids = item.get("monitor_ids", []) if isinstance(item.get("monitor_ids"), list) else []
    query = item.get("query") if isinstance(item.get("query"), dict) else {}
    score = 1 + (1 if monitor_ids else 0) + (1 if query else 0) + max(0, len(thresholds) - 1)
    return {
        "source_type": "slo",
        "source_id": item.get("id"),
        "name": item.get("name"),
        "slo_type": item.get("type"),
        "created_at": item.get("created_at"),
        "modified_at": item.get("modified_at"),
        "tags": tags,
        "owner_tags": team_tags(tags),
        "thresholds": redacted(thresholds),
        "monitor_ids": monitor_ids,
        "query": redacted(query),
        "complexity_score": score,
        "complexity": "low" if score <= 2 else "medium" if score <= 4 else "high",
        "evidence": "GET /api/v1/slo",
    }


def normalize_synthetic(item: dict[str, Any]) -> dict[str, Any]:
    config = item.get("config") if isinstance(item.get("config"), dict) else {}
    options = item.get("options") if isinstance(item.get("options"), dict) else {}
    tags = [str(tag) for tag in item.get("tags", []) if isinstance(tag, str)]
    return {
        "source_type": "synthetic",
        "source_id": item.get("public_id"),
        "name": item.get("name"),
        "test_type": item.get("type"),
        "subtype": item.get("subtype"),
        "status": item.get("status"),
        "created_at": item.get("created_at"),
        "modified_at": item.get("modified_at"),
        "tags": tags,
        "owner_tags": team_tags(tags),
        "location_count": len(item.get("locations", []) or []),
        "tick_every_seconds": options.get("tick_every"),
        "request_method": (config.get("request") or {}).get("method") if isinstance(config.get("request"), dict) else None,
        "notification_types": notification_types(str(item.get("message", ""))),
        "complexity": "medium" if item.get("type") == "browser" else "low",
        "evidence": "GET /api/v1/synthetics/tests",
    }


def normalize_log_index(item: dict[str, Any]) -> dict[str, Any]:
    exclusions = item.get("exclusion_filters", []) if isinstance(item.get("exclusion_filters"), list) else []
    return {
        "source_type": "log_index",
        "source_id": item.get("name"),
        "name": item.get("name"),
        "retention_days": item.get("num_retention_days"),
        "daily_limit": item.get("daily_limit"),
        "filter": redacted(item.get("filter", {})),
        "exclusion_filter_count": len(exclusions),
        "exclusion_filters": redacted(exclusions),
        "complexity": "high" if len(exclusions) > 3 else "medium" if exclusions else "low",
        "evidence": "GET /api/v1/logs/config/indexes",
    }


def normalize_log_pipeline(item: dict[str, Any]) -> dict[str, Any]:
    processors = item.get("processors", []) if isinstance(item.get("processors"), list) else []
    types = Counter(str(p.get("type", "unknown")) for p in processors if isinstance(p, dict))
    return {
        "source_type": "log_pipeline",
        "source_id": item.get("id"),
        "name": item.get("name"),
        "status": "enabled" if item.get("is_enabled", True) else "disabled",
        "filter": redacted(item.get("filter", {})),
        "processor_count": len(processors),
        "processor_types": dict(sorted(types.items())),
        "complexity": "high" if len(processors) > 8 else "medium" if len(processors) > 3 else "low",
        "evidence": "GET /api/v1/logs/config/pipelines",
    }


def stable_signature(record: dict[str, Any]) -> str:
    relevant = {
        "type": record.get("source_type"),
        "queries": record.get("queries"),
        "thresholds": record.get("thresholds"),
        "widget_types": record.get("widget_types"),
        "filter": record.get("filter"),
        "processor_types": record.get("processor_types"),
    }
    return hashlib.sha256(json.dumps(relevant, sort_keys=True).encode("utf-8")).hexdigest()[:16]


def month_shift(year: int, month: int, delta: int) -> str:
    value = year * 12 + (month - 1) + delta
    return f"{value // 12:04d}-{value % 12 + 1:02d}"


class Collector:
    def __init__(self, api: DatadogAPI, verbose: bool = False):
        self.api = api
        self.verbose = verbose
        self.errors: list[dict[str, str]] = []
        self.permissions: dict[str, str] = {}

    def log(self, text: str) -> None:
        if self.verbose:
            print(f"[assessment] {text}", file=sys.stderr)

    def safe(self, name: str, path: str, params: dict[str, Any] | None = None) -> Any:
        try:
            self.log(f"reading {name}: {path}")
            payload = self.api.get(path, params)
            self.permissions[name] = "available"
            return payload
        except Exception as exc:  # Each endpoint is independently optional.
            category = safe_error(exc)
            if str(exc).startswith("http_"):
                category = str(exc)
            self.permissions[name] = "denied" if category in {"http_401", "http_403"} else "unavailable"
            self.errors.append({"source": name, "error": category})
            self.log(f"skipped {name}: {category}")
            return None

    def collect_dashboards(self) -> list[dict[str, Any]]:
        payload = self.safe("dashboards", "/api/v1/dashboard")
        items = list_items(payload, "dashboards")
        records = []
        for item in items:
            dashboard_id = item.get("id")
            detail = None
            if dashboard_id:
                try:
                    detail = self.api.get(f"/api/v1/dashboard/{quote(str(dashboard_id), safe='')}")
                except Exception as exc:
                    category = str(exc) if str(exc).startswith("http_") else safe_error(exc)
                    self.errors.append({"source": "dashboard_detail", "error": category})
            records.append(normalize_dashboard(item, detail if isinstance(detail, dict) else None))
        return records

    def collect_monitors(self) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        page = 0
        while True:
            payload = self.safe("monitors", "/api/v1/monitor", {"page": page, "page_size": 1000, "with_downtimes": "true"})
            if payload is None:
                break
            items = list_items(payload)
            records.extend(normalize_monitor(item) for item in items)
            if len(items) < 1000:
                break
            page += 1
        return records

    def collect(self, months: int, include_cost: bool = False) -> dict[str, Any]:
        dashboards = self.collect_dashboards()
        monitors = self.collect_monitors()

        slo_payload = self.safe("slos", "/api/v1/slo", {"limit": 1000})
        slos = [normalize_slo(item) for item in list_items(slo_payload)]

        synthetic_payload = self.safe("synthetics", "/api/v1/synthetics/tests")
        synthetics = [normalize_synthetic(item) for item in list_items(synthetic_payload, "tests")]

        index_payload = self.safe("log_indexes", "/api/v1/logs/config/indexes")
        log_indexes = [normalize_log_index(item) for item in list_items(index_payload, "indexes")]

        pipeline_payload = self.safe("log_pipelines", "/api/v1/logs/config/pipelines")
        log_pipelines = [normalize_log_pipeline(item) for item in list_items(pipeline_payload, "pipelines")]

        hosts_payload = self.safe("hosts", "/api/v1/hosts", {"count": 1, "include_hosts_metadata": "false"})
        host_totals = {}
        if isinstance(hosts_payload, dict):
            host_totals = redacted(hosts_payload.get("total_matching", hosts_payload.get("total_returned", {})))

        integrations = {}
        for name, endpoint in {
            "aws": "/api/v2/integration/aws/accounts",
            "azure": "/api/v2/integration/azure/accounts",
            "gcp": "/api/v2/integration/gcp/accounts",
        }.items():
            payload = self.safe(f"integration_{name}", endpoint)
            integrations[name] = {"account_count": len(list_items(payload))} if payload is not None else {"account_count": None}

        current = datetime.now(timezone.utc)
        current_month = f"{current.year:04d}-{current.month:02d}"
        start_month = month_shift(current.year, current.month, -(max(1, months) - 1))
        previous_month = month_shift(current.year, current.month, -1)
        billing: dict[str, Any] = {"collection": "not_requested"}
        if include_cost:
            billing = {
                "collection": "requested",
                "estimated_cost": redacted(self.safe("estimated_cost", "/api/v2/usage/estimated_cost", {"start_month": current_month, "view": "summary"})),
                "projected_cost": redacted(self.safe("projected_cost", "/api/v2/usage/projected_cost", {"view": "summary"})),
                "historical_cost": redacted(self.safe("historical_cost", "/api/v2/usage/historical_cost", {"start_month": start_month, "end_month": previous_month, "view": "summary"})),
                "usage_summary": redacted(self.safe("usage_summary", "/api/v1/usage/summary", {"start_month": start_month, "end_month": current_month})),
            }

        records = dashboards + monitors + slos + synthetics + log_indexes + log_pipelines
        signatures: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for record in records:
            signatures[stable_signature(record)].append(record)
        duplicate_candidates = [
            {
                "signature": signature,
                "source_type": group[0].get("source_type"),
                "objects": [{"id": item.get("source_id"), "name": item.get("name")} for item in group],
            }
            for signature, group in signatures.items()
            if len(group) > 1
        ]

        ownerless = [
            {"source_type": item.get("source_type"), "id": item.get("source_id"), "name": item.get("name")}
            for item in records
            if item.get("source_type") in {"dashboard", "monitor", "slo", "synthetic"}
            and not item.get("owner_tags")
        ]
        complexity = Counter(item.get("complexity", "unknown") for item in records)
        return {
            "schema_version": "1.1",
            "generated_at": now_iso(),
            "source": {"platform": "Datadog", "api_base": self.api.base},
            "scope": {"cost_months_requested": months},
            "inventory": {
                "dashboards": dashboards,
                "monitors": monitors,
                "slos": slos,
                "synthetics": synthetics,
                "log_indexes": log_indexes,
                "log_pipelines": log_pipelines,
                "host_totals": host_totals,
                "integrations": integrations,
            },
            "counts": {
                "dashboards": len(dashboards),
                "monitors": len(monitors),
                "slos": len(slos),
                "synthetics": len(synthetics),
                "log_indexes": len(log_indexes),
                "log_pipelines": len(log_pipelines),
                "ownerless_objects": len(ownerless),
                "duplicate_candidate_groups": len(duplicate_candidates),
                "complexity": dict(sorted(complexity.items())),
            },
            "hygiene": {
                "ownerless": ownerless,
                "duplicate_candidates": duplicate_candidates,
            },
            "billing": billing,
            "access": self.permissions,
            "errors": self.errors,
            "safety": {
                "read_only": True,
                "mutations_performed": 0,
                "request_budget": MAX_DISCOVERY_REQUESTS,
                "requests_attempted": self.api.requests_attempted,
                "notification_addresses_redacted": True,
                "redirects_followed": False,
                "api_host_allowlisted": True,
                "raw_inventory_local_only": True,
            },
        }


def markdown_summary(result: dict[str, Any]) -> str:
    counts = result["counts"]
    access = result["access"]
    lines = [
        "# Datadog migration assessment inventory",
        "",
        f"Generated: `{result['generated_at']}`",
        "",
        "This is a read-only normalized inventory. No Datadog resources were changed.",
        "",
        "## Configuration inventory",
        "",
        "| Object | Count |",
        "|---|---:|",
    ]
    for key in ("dashboards", "monitors", "slos", "synthetics", "log_indexes", "log_pipelines"):
        lines.append(f"| {key.replace('_', ' ').title()} | {counts.get(key, 0)} |")
    lines.extend([
        "",
        "## Migration hygiene indicators",
        "",
        f"- Ownerless configured objects: **{counts.get('ownerless_objects', 0)}**",
        f"- Exact normalized duplicate candidate groups: **{counts.get('duplicate_candidate_groups', 0)}**",
        f"- Complexity distribution: `{json.dumps(counts.get('complexity', {}), sort_keys=True)}`",
        "",
        "These are candidates for review, not automatic deletion decisions.",
        "",
        "## API coverage",
        "",
        "| Area | Status |",
        "|---|---|",
    ])
    for name, status in sorted(access.items()):
        lines.append(f"| {name} | {status} |")
    lines.extend([
        "",
        "## Next analysis steps",
        "",
        "1. Join this configuration inventory with active metric/tag discovery.",
        "2. Reconcile billing API data with invoices and contracted rates.",
        "3. Confirm ownership and identify approved retirements.",
        "4. Define the vendor-neutral observability specification.",
        "5. Score one or more target platforms and model as-is, optimized, growth, and dual-run scenarios.",
        "",
    ])
    if result.get("errors"):
        lines.extend(["## Collection limitations", ""])
        for error in result["errors"]:
            lines.append(f"- `{error['source']}`: `{error['error']}`")
        lines.append("")
    return "\n".join(lines)


def self_test() -> int:
    dashboard = normalize_dashboard({
        "id": "abc",
        "title": "Demo",
        "tags": ["team:platform"],
        "widgets": [{"definition": {"type": "timeseries", "requests": [{"q": "avg:system.cpu.user{*}"}]}}],
    })
    monitor = normalize_monitor({
        "id": 1,
        "name": "CPU",
        "type": "query alert",
        "query": "avg(last_5m):avg:system.cpu.user{*} > 80",
        "message": "Notify person@example.com and @slack-platform-alerts",
        "tags": [],
        "options": {"thresholds": {"critical": 80}},
    })
    assert dashboard["widget_count"] == 1
    assert dashboard["queries"][0]["value"] == "avg:system.cpu.user{*}"
    assert dashboard["owner_tags"] == ["team:platform"]
    assert monitor["notification_types"] == ["email", "slack"]
    assert "person@example.com" not in json.dumps(monitor)
    assert redacted({"api_token": "secret", "owner": "a@example.com"}) == {
        "api_token": "[redacted]", "owner": "[redacted-email]"
    }
    assert resolve_datadog_api_base("us3") == "https://api.us3.datadoghq.com"
    try:
        resolve_datadog_api_base("api.attacker.example")
    except ValueError:
        pass
    else:
        raise AssertionError("custom Datadog hosts must be rejected")
    print("self-test passed")
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", default="", help="Output directory; required unless --self-test is used")
    parser.add_argument("--env-file", default="", help="Static dotenv file parsed without shell execution")
    parser.add_argument("--authorization-file", default="", help="Approved read-only authorization JSON")
    parser.add_argument("--cost-months", type=int, default=3, help="Historical cost/usage window in months (default: 3)")
    parser.add_argument("--include-cost", action="store_true", help="Opt in to billing and usage endpoints")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.self_test:
        return self_test()
    if not args.output_dir:
        raise RuntimeError("--output-dir is required")
    if not args.authorization_file:
        raise RuntimeError("--authorization-file is required for customer-system discovery")

    authorization_path = Path(args.authorization_file).expanduser()
    authorization = load_authorization(authorization_path, "DATADOG_DISCOVERY")
    if args.include_cost and "billing_and_usage" not in authorization.get("data_categories", []):
        raise RuntimeError("cost collection requires a separate --include-cost-read authorization")

    env_file = Path(args.env_file).expanduser() if args.env_file else None
    if env_file and not env_file.is_file():
        raise RuntimeError(f"environment file not found: {env_file}")
    values = merged_environment(env_file)
    api_key = config_value(values, "DATADOG_API_KEY", "DD_API_KEY")
    app_key = config_value(values, "DATADOG_APP_KEY", "DD_APP_KEY")
    site = config_value(values, "DATADOG_SITE", "DD_SITE") or "datadoghq.com"
    if not api_key or not app_key:
        raise RuntimeError("Set DATADOG_API_KEY and DATADOG_APP_KEY (or DD_API_KEY and DD_APP_KEY).")
    if resolve_datadog_api_base(site) != authorization.get("authorized_origins", {}).get("datadog"):
        raise RuntimeError("configured Datadog origin differs from the approved origin")

    session_id = str(authorization["session_id"])
    if authorization_path.parent.name != session_id:
        raise RuntimeError("authorization file is not inside its bound session directory")
    store = CheckpointStore(authorization_path.parent.parent)
    session = store.load(session_id)
    if str(authorization["approval_id"]) not in session.approval_ids:
        raise RuntimeError("authorization is not registered in the session checkpoint")
    try:
        session = store.claim_discovery(session_id)
    except ValueError as exc:
        raise RuntimeError(str(exc)) from exc

    audit_path = authorization_path.parent / "audit.local.jsonl"
    try:
        output = ensure_private_directory(Path(args.output_dir))
        append_audit_event(
            audit_path,
            "discovery_started",
            "success",
            str(authorization["session_id"]),
            str(authorization["approval_id"]),
        )
        collector = Collector(DatadogAPI(api_key, app_key, site), verbose=args.verbose)
        result = collector.collect(max(1, args.cost_months), include_cost=args.include_cost)
        configured_objects = validate_discovery_result(result)
        result["authorization"] = public_approval_ref(authorization)
        json_path = output / "datadog-estate.local.json"
        summary_path = output / "datadog-estate-summary.md"
        atomic_write_json(json_path, result)
        atomic_write(summary_path, markdown_summary(result))
        append_audit_event(
            audit_path,
            "discovery_completed",
            "partial" if result.get("errors") else "success",
            str(authorization["session_id"]),
            str(authorization["approval_id"]),
            {
                "configured_objects": configured_objects,
                "endpoint_limitations": len(result.get("errors", [])),
            },
        )
        current = store.load(session_id)
        current.inventory_origin = "datadog_live_discovery"
        current.artifacts["local_inventory"] = str(json_path.resolve())
        current.resources_discovered = configured_objects
        current.discovery_completed_at = datetime.now(timezone.utc).isoformat()
        current.last_event = "Discovery completed"
        store.save(current)
    except Exception as exc:
        try:
            append_audit_event(
                audit_path,
                "discovery_failed",
                "failed",
                str(authorization["session_id"]),
                str(authorization["approval_id"]),
            )
        finally:
            try:
                current = store.load(session_id)
                if current.workflow_state == SessionState.DISCOVERY.value:
                    store.block(
                        session_id,
                        error_code="DISCOVERY_FAILURE",
                        error_message=str(exc),
                        expected_state=SessionState.DISCOVERY.value,
                    )
            except ValueError:
                # A newer, successful worker already advanced the assessment.
                # Never let this stale failure overwrite authoritative state.
                pass
        raise
    print(f"Collected {sum(result['counts'].get(k, 0) for k in ('dashboards', 'monitors', 'slos', 'synthetics', 'log_indexes', 'log_pipelines'))} configured objects into {output}")
    print(f"Summary: {summary_path}")
    print("Next: run normalize-inventory to create stable Codex-safe artifacts")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
