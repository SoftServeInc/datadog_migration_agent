#!/usr/bin/env python3
"""Prepare, create, and validate source-bound Splunk dashboard bundles."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any
from urllib import error, parse, request

HERE = Path(__file__).resolve().parent
SKILLS = HERE.parents[1]
sys.path.insert(0, str(SKILLS / "observability-migration-assessment" / "scripts"))

from assessment_core.config import parse_dotenv, select_splunk_o11y_credentials  # noqa: E402
from assessment_core.security import atomic_write_json, pseudonym  # noqa: E402

SESSION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$")
ORIGIN = re.compile(r"^https://api\.[a-z]{2,4}[0-9]{1,2}\.observability\.splunkcloud\.com$")
QUERY = re.compile(
    r"^(?:(?P<outer>avg|sum|max|min)\(last_(?P<window>[0-9]+[smhdw])\):)?"
    r"(?P<agg>avg|sum|max|min|count):(?P<metric>[A-Za-z_][A-Za-z0-9_.-]*)"
    r"\{(?P<scope>[^{}]{1,4096})\}(?:\s+by\s+\{(?P<groups>[A-Za-z0-9_., -]{1,1024})\})?"
    r"(?P<suffix>(?:\.(?:(?:as_count|as_rate)\(\)|rollup\([A-Za-z]+(?:,\s*[0-9]+)?\)))*)"
    r"(?P<scale>\s*/\s*(?:[1-9][0-9]{0,8})(?:\.[0-9]+)?)?$",
    re.IGNORECASE,
)
SAFE_FORMULA = re.compile(r"^[A-Za-z0-9_ +*/().-]{1,2048}$")


def canonical_hash(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def read_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 20_000_000:
        raise ValueError(f"private JSON is missing or unsafe: {path.name}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"private JSON root is invalid: {path.name}")
    return value


def clean_name(value: Any, fallback: str, maximum: int = 255) -> str:
    text = " ".join(str(value or "").split())
    if not text or any(ord(character) < 32 for character in text):
        text = fallback
    return text[:maximum]


def quoted(value: str) -> str:
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def scope_filter(scope: str) -> tuple[str, list[str]]:
    if scope.strip() == "*":
        return "", []
    filters: list[str] = []
    differences: list[str] = []
    for raw in scope.split(","):
        item = raw.strip()
        if not item:
            continue
        if "$" in item:
            differences.append("template_variable_filter_requires_target_binding")
            continue
        negative = item.startswith("!")
        item = item[1:] if negative else item
        if ":" not in item:
            return "", ["unsupported_scope_filter"]
        key, value = (part.strip() for part in item.split(":", 1))
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*", key) or not value:
            return "", ["unsupported_scope_filter"]
        expression = f"filter({quoted(key)}, {quoted(value)})"
        filters.append(f"not ({expression})" if negative else expression)
    return " and ".join(filters), differences


def metric_expression(query: str) -> tuple[str, list[str]] | None:
    normalized = " ".join(query.strip().split())
    if normalized.lower().startswith("count_nonzero(") and normalized.endswith(")"):
        nested = metric_expression(normalized[len("count_nonzero("):-1])
        if nested is None:
            return None
        expression, differences = nested
        return f"({expression}).count()", sorted({*differences, "count_nonzero_adapted_to_stream_count"})
    match = QUERY.fullmatch(normalized)
    if not match:
        return None
    aggregate = match.group("agg").lower()
    rollup = {"avg": "average", "sum": "sum", "max": "max", "min": "min", "count": "count"}[aggregate]
    method = {"avg": "mean", "sum": "sum", "max": "max", "min": "min", "count": "count"}[aggregate]
    suffix = match.group("suffix").lower()
    if ".as_rate()" in suffix:
        rollup = "rate"
    elif ".as_count()" in suffix:
        rollup = "sum"
    filter_text, differences = scope_filter(match.group("scope"))
    args = [quoted(match.group("metric"))]
    if filter_text:
        args.append(f"filter={filter_text}")
    args.append(f"rollup={quoted(rollup)}")
    groups = [item.strip() for item in (match.group("groups") or "").split(",") if item.strip()]
    if groups:
        rendered = ", ".join(quoted(item) for item in groups)
        by = f"[{rendered}]" if len(groups) > 1 else rendered
        expression = f"data({', '.join(args)}).{method}(by={by})"
    else:
        expression = f"data({', '.join(args)}).{method}()"
    if match.group("outer") and match.group("window"):
        outer = {"avg": "mean", "sum": "sum", "max": "max", "min": "min"}[match.group("outer").lower()]
        expression += f".{outer}(over={quoted(match.group('window').lower())})"
    if match.group("scale"):
        expression += " " + match.group("scale").strip()
    return expression, differences


def request_program(definition: dict[str, Any]) -> tuple[str | None, list[str]]:
    requests = definition.get("requests")
    if not isinstance(requests, list) or not requests:
        return None, ["missing_query"]
    lines: list[str] = []
    differences: list[str] = []
    label_index = 0
    for request_item in requests:
        if not isinstance(request_item, dict):
            return None, ["invalid_query_request"]
        direct = request_item.get("q")
        if isinstance(direct, str):
            parsed_query = metric_expression(direct)
            if parsed_query is None:
                return None, ["unsupported_datadog_query"]
            expression, query_differences = parsed_query
            label = chr(ord("A") + label_index)
            lines.extend([f"{label} = {expression}", f"{label}.publish(label={quoted(label)})"])
            label_index += 1
            differences.extend(query_differences)
            continue
        queries = request_item.get("queries")
        if not isinstance(queries, list) or not queries:
            return None, ["missing_metric_queries"]
        names: dict[str, str] = {}
        for item in queries:
            if not isinstance(item, dict) or item.get("data_source") != "metrics":
                return None, ["unsupported_query_data_source"]
            parsed_query = metric_expression(str(item.get("query", "")))
            if parsed_query is None:
                return None, ["unsupported_datadog_query"]
            expression, query_differences = parsed_query
            variable = chr(ord("A") + len(names))
            source_name = str(item.get("name") or variable)
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", source_name):
                return None, ["unsupported_query_name"]
            names[source_name] = variable
            lines.append(f"{variable} = {expression}")
            differences.extend(query_differences)
        formulas = request_item.get("formulas")
        if formulas:
            if not isinstance(formulas, list):
                return None, ["invalid_formula"]
            for formula in formulas:
                value = formula.get("formula") if isinstance(formula, dict) else None
                if not isinstance(value, str) or not SAFE_FORMULA.fullmatch(value):
                    return None, ["unsupported_formula"]
                translated = value
                for source_name, variable in sorted(names.items(), key=lambda pair: -len(pair[0])):
                    translated = re.sub(rf"\b{re.escape(source_name)}\b", variable, translated)
                remaining = re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", translated)
                if any(token not in set(names.values()) for token in remaining):
                    return None, ["unresolved_formula_reference"]
                label = chr(ord("A") + len(names))
                lines.extend([f"{label} = {translated}", f"{label}.publish(label={quoted(label)})"])
                label_index += 1
        else:
            for variable in names.values():
                lines.append(f"{variable}.publish(label={quoted(variable)})")
                label_index += 1
    return "\n".join(lines), sorted(set(differences))


def translate_widget(widget: dict[str, Any], index: int, dashboard_ref: str) -> dict[str, Any]:
    definition = widget.get("definition") if isinstance(widget.get("definition"), dict) else {}
    widget_type = str(definition.get("type", "unknown"))
    title = clean_name(definition.get("title"), f"{widget_type.replace('_', ' ').title()} {index + 1}")
    marker = canonical_hash({"dashboard_ref": dashboard_ref, "widget_index": index})[:16]
    common = {
        "name": title,
        "tags": ["AI-Created", "migration-source-datadog", f"codex-migration-{marker}"],
        "customProperties": {"sourcePlatform": "datadog", "migrationMarker": marker},
    }
    if widget_type == "note":
        content = str(definition.get("content", ""))[:50_000]
        return {"chart": {**common, "options": {"type": "Text", "markdown": content}}, "supported": True, "differences": []}
    type_map = {
        "timeseries": {"type": "TimeSeriesChart", "defaultPlotType": "LineChart"},
        # Splunk rejects showSparkLine when SingleValue has a secondary
        # visualization option; retain the value widget without that option.
        "query_value": {"type": "SingleValue"},
        "toplist": {"type": "List"},
        "heatmap": {"type": "Heatmap"},
    }
    if widget_type not in type_map:
        return {"chart": common, "supported": False, "differences": ["unsupported_widget_type"]}
    program, differences = request_program(definition)
    if program is None:
        return {"chart": common, "supported": False, "differences": differences}
    return {"chart": {**common, "programText": program, "options": type_map[widget_type]}, "supported": True, "differences": differences}


def translate_variables(spec: dict[str, Any]) -> list[dict[str, Any]]:
    source = spec.get("template_variables")
    if not isinstance(source, list):
        return []
    result: list[dict[str, Any]] = []
    for item in source:
        if not isinstance(item, dict):
            continue
        name = clean_name(item.get("name"), "variable", 128)
        property_name = clean_name(item.get("prefix") or item.get("name"), name, 128)
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*", property_name):
            raise ValueError("Datadog template variable property cannot be mapped safely")
        default = item.get("default")
        values = [str(value) for value in default] if isinstance(default, list) else [str(default)] if default not in (None, "", "*") else []
        result.append({
            "alias": name, "property": property_name, "value": values,
            "required": False, "restricted": False,
        })
    return result


def translate_layouts(widgets: list[dict[str, Any]]) -> list[dict[str, int]]:
    """Scale Datadog geometry into Splunk's 12-column grid.

    Datadog screenboards use a wider coordinate system.  Keeping shared source
    boundaries preserves intentional four-column KPI rows, half-width charts,
    and full-width notes.  Compress vertical source intervals because one
    Splunk grid row is substantially taller than one Datadog layout unit.
    """
    source_layouts: list[dict[str, int]] = []
    for widget in widgets:
        layout = widget.get("layout")
        if not isinstance(layout, dict):
            break
        values = {key: layout.get(key) for key in ("x", "y", "width", "height")}
        if (
            any(not isinstance(value, int) for value in values.values())
            or values["x"] < 0 or values["y"] < 0
            or values["width"] <= 0 or values["height"] <= 0
        ):
            break
        source_layouts.append(values)
    if len(source_layouts) == len(widgets) and source_layouts:
        grid_width = max(layout["x"] + layout["width"] for layout in source_layouts)
        vertical_edges = sorted({
            edge
            for layout in source_layouts
            for edge in (layout["y"], layout["y"] + layout["height"])
        })
        row_by_edge: dict[int, int] = {vertical_edges[0]: 0}
        row = 0
        for start, end in zip(vertical_edges, vertical_edges[1:]):
            row += max(1, (end - start + 14) // 15)
            row_by_edge[end] = row

        def scale_x(value: int) -> int:
            return min(12, (value * 12 + grid_width // 2) // grid_width)

        result: list[dict[str, int]] = []
        for layout in source_layouts:
            column = scale_x(layout["x"])
            right = scale_x(layout["x"] + layout["width"])
            result.append({
                "column": column,
                "row": row_by_edge[layout["y"]],
                "width": max(1, right - column),
                "height": max(
                    1,
                    row_by_edge[layout["y"] + layout["height"]] - row_by_edge[layout["y"]],
                ),
            })
        return result

    # Some API fixtures and older inventories do not include source geometry.
    # Retain a deterministic, overlap-free fallback for those inputs.
    result: list[dict[str, int]] = []
    row = 0
    slot = 0
    row_height = 0
    for widget in widgets:
        widget_type = str((widget.get("definition") or {}).get("type", "")).lower()
        if widget_type == "note":
            if slot:
                row += row_height
                slot = 0
                row_height = 0
            result.append({"column": 0, "row": row, "width": 12, "height": 1})
            row += 1
            continue
        height = 1 if widget_type == "query_value" else 2
        result.append({"column": slot * 4, "row": row, "width": 4, "height": height})
        slot += 1
        row_height = max(row_height, height)
        if slot == 3:
            row += row_height
            slot = 0
            row_height = 0
    return result


def session_paths(work_root: Path, session_id: str) -> dict[str, Path]:
    if not SESSION_ID.fullmatch(session_id):
        raise ValueError("invalid session ID")
    directory = (work_root / session_id).resolve()
    private = directory / "dashboard-execution"
    private.mkdir(mode=0o700, parents=True, exist_ok=True)
    return {
        "directory": directory,
        "checkpoint": directory / "checkpoint.local.json",
        "plan": directory / "dry-run-plan.json",
        "inventory": directory / "discovery" / "datadog-estate.local.json",
        "preview": private / "dashboard-preview.local.json",
        "result": private / "dashboard-result.local.json",
        "progress": private / "dashboard-apply-checkpoint.local.json",
    }


def prepare_preview(paths: dict[str, Path]) -> dict[str, Any]:
    checkpoint = read_object(paths["checkpoint"])
    plan = read_object(paths["plan"])
    inventory_path = paths["inventory"]
    recorded = checkpoint.get("artifacts", {}).get("local_inventory")
    if recorded:
        candidate = Path(str(recorded))
        if not candidate.is_absolute():
            candidate = paths["directory"] / candidate
        if candidate.is_symlink():
            raise ValueError("private inventory path is unsafe")
        candidate = candidate.resolve(strict=True)
        if paths["directory"].resolve() not in candidate.parents:
            raise ValueError("private inventory escapes the approved session")
        inventory_path = candidate
    inventory = read_object(inventory_path)
    salt = str(checkpoint.get("local_pseudonym_salt", ""))
    if len(salt) != 64 or plan.get("plan_hash") != checkpoint.get("plan_hash"):
        raise ValueError("session plan or pseudonym binding is invalid")
    plan_dashboards = {
        step["object_ref"] for step in plan.get("steps", [])
        if step.get("object_type") == "dashboard" and step.get("target") == "splunk_observability_cloud"
        and step.get("proposed_operation") in {"PROPOSE_CREATE", "PROPOSE_TRANSFORM"}
    }
    source = inventory.get("inventory", {}).get("dashboards")
    if not isinstance(source, list) or not source:
        raise ValueError("private dashboard inventory is missing")
    dashboards: list[dict[str, Any]] = []
    for item in source:
        source_id = item.get("source_id") if isinstance(item, dict) else None
        object_ref = pseudonym(f"dashboard:{source_id}", salt)
        if object_ref not in plan_dashboards:
            raise ValueError("source dashboard is absent from the full plan")
        spec = item.get("dashboard_spec")
        widgets = spec.get("widgets") if isinstance(spec, dict) else None
        if not isinstance(widgets, list):
            raise ValueError("dashboard widget details are missing; rerun discovery")
        translated = [translate_widget(widget, index, object_ref) for index, widget in enumerate(widgets)]
        variables = translate_variables(spec)
        differences = {difference for value in translated for difference in value["differences"]}
        differences.add("dashboard_layout_compacted_for_splunk_density")
        if variables and "template_variable_filter_requires_target_binding" in differences:
            differences.remove("template_variable_filter_requires_target_binding")
            differences.add("template_variables_mapped_to_splunk_dashboard_variables")
        source_name = clean_name(item.get("name"), f"Datadog dashboard {object_ref[-8:]}", 235)
        # Keep the customer-facing dashboard name identical to Datadog.
        # Provenance is carried by descriptions, chart tags, and the group.
        target_name = source_name
        dashboards.append({
            "object_ref": object_ref, "source_name": source_name, "target_name": target_name,
            "charts": [value["chart"] for value in translated],
            "layouts": translate_layouts(widgets),
            "variables": variables,
            "supported_chart_count": sum(value["supported"] for value in translated),
            "unsupported_chart_count": sum(not value["supported"] for value in translated),
            "differences": sorted(differences),
        })
    preview = {
        "schema_version": "1.0",
        "session_id": checkpoint.get("assessment_id") or checkpoint.get("session_id"),
        "plan_hash": plan["plan_hash"], "inventory_hash": canonical_hash(inventory),
        "group": {
            "name": "Datadog Migration [AI-Created]",
            "description": "[AI-Created] Dashboards migrated from Datadog by the approved Codex flow.",
        },
        "dashboards": dashboards,
    }
    preview["preview_hash"] = canonical_hash(preview)
    atomic_write_json(paths["preview"], preview)
    return preview


class _NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req: object, fp: object, code: int, msg: str, headers: object, newurl: str) -> None:
        return None


class SplunkClient:
    def __init__(self, origin: str, token: str, timeout: int = 15):
        if not ORIGIN.fullmatch(origin) or not token or any(character.isspace() for character in token):
            raise ValueError("Splunk credentials or origin are invalid")
        self.origin, self.token, self.timeout = origin, token, timeout
        self.opener = request.build_opener(_NoRedirect())

    def call(self, method: str, path: str, payload: Any = None, query: dict[str, Any] | None = None) -> dict[str, Any]:
        allowed = (
            method == "GET" and (
                path == "/v2/organization" or path in {"/v2/chart", "/v2/dashboard", "/v2/dashboardgroup"}
                or path.startswith("/v2/chart/") or path.startswith("/v2/dashboard/")
                or path.startswith("/v2/dashboardgroup/")
            )
            or method == "POST" and path in {"/v2/chart", "/v2/dashboard", "/v2/dashboardgroup"}
            or method == "PUT" and path.startswith("/v2/dashboard/")
        )
        if not allowed:
            raise ValueError("unsupported dashboard API operation")
        url = self.origin + path + (("?" + parse.urlencode(query)) if query else "")
        body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
        req = request.Request(url, data=body, method=method, headers={
            "Accept": "application/json", "Content-Type": "application/json",
            "X-SF-TOKEN": self.token, "User-Agent": "cisco-innovation-dashboard-executor/1.0",
        })
        try:
            with self.opener.open(req, timeout=self.timeout) as response:
                if not str(getattr(response, "url", url)).startswith(self.origin + "/"):
                    raise ValueError("redirect or origin change rejected")
                raw = response.read(10_000_001)
                if len(raw) > 10_000_000:
                    raise ValueError("Splunk response exceeds limit")
                value = json.loads(raw.decode()) if raw else {}
                if not isinstance(value, dict):
                    raise ValueError("Splunk response is not an object")
                return value
        except error.HTTPError as exc:
            detail = ""
            try:
                body = json.loads(exc.read(4096).decode(errors="replace"))
                if isinstance(body, dict) and isinstance(body.get("message"), str):
                    detail = ": " + " ".join(body["message"].split())[:300]
            except (ValueError, OSError):
                pass
            raise RuntimeError(f"splunk_http_{exc.code}{detail}") from None
        except (error.URLError, TimeoutError, OSError):
            raise RuntimeError("splunk_network_error") from None


def credentials(env_file: Path) -> tuple[str, str]:
    values = parse_dotenv(env_file)
    token, realm = select_splunk_o11y_credentials(values)
    if not token or not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,15}", realm.lower()):
        raise ValueError("complete Splunk token/realm profile is required")
    return token, f"https://api.{realm.lower()}.observability.splunkcloud.com"


def exact_results(value: dict[str, Any], name: str) -> list[dict[str, Any]]:
    results = value.get("results", [])
    if not isinstance(results, list):
        raise ValueError("Splunk search response is invalid")
    return [item for item in results if isinstance(item, dict) and item.get("name") == name]


def contains_expected(actual: Any, expected: Any) -> bool:
    if isinstance(expected, dict):
        return isinstance(actual, dict) and all(
            key in actual and contains_expected(actual[key], value) for key, value in expected.items()
        )
    if isinstance(expected, list):
        return actual == expected
    return actual == expected


def equivalent_program_text(actual: Any, expected: Any) -> bool:
    """Accept the API's equivalent positional form of publish(label=...)."""
    if not isinstance(actual, str) or not isinstance(expected, str):
        return actual == expected
    normalize = lambda value: re.sub(r"\\s+", " ", value).strip().replace(
        "publish(label=", "publish(",
    )
    return normalize(actual) == normalize(expected)


def chart_by_marker(
    client: SplunkClient, payload: dict[str, Any], *, allow_create: bool = True,
    on_create_intent: Any = None,
) -> tuple[dict[str, Any] | None, bool]:
    marker = next((tag for tag in payload["tags"] if tag.startswith("codex-migration-")), None)
    if marker is None:
        raise ValueError("chart payload migration marker is missing")
    results = client.call("GET", "/v2/chart", query={"tags": marker, "limit": 2}).get("results", [])
    if not isinstance(results, list) or len(results) > 1:
        raise ValueError("chart marker search is invalid or ambiguous")
    created = False
    if results:
        chart_id = results[0].get("id") if isinstance(results[0], dict) else None
    else:
        if not allow_create:
            raise ValueError("pending chart create is not yet visible; refusing a blind second POST")
        if callable(on_create_intent):
            on_create_intent(marker)
        response = client.call("POST", "/v2/chart", payload)
        chart_id = response.get("id")
        created = True
    if not isinstance(chart_id, str) or not chart_id:
        raise ValueError("chart ID is missing")
    actual = client.call("GET", f"/v2/chart/{parse.quote(chart_id, safe='')}")
    for field in ("name", "description", "programText", "options", "customProperties"):
        # The universal chart API materializes a programText field for text
        # charts even when the create payload intentionally omits it.
        if field in payload and payload[field] is not None and not (
            equivalent_program_text(actual.get(field), payload[field])
            if field == "programText"
            else contains_expected(actual.get(field), payload[field])
        ):
            raise ValueError(f"chart read-back {field} differs")
    if not set(payload["tags"]).issubset(set(actual.get("tags", []))):
        raise ValueError("chart read-back tags differ")
    return actual, created


def _execute_unlocked(paths: dict[str, Path], client: SplunkClient) -> dict[str, Any]:
    preview = read_object(paths["preview"])
    unsigned = {key: value for key, value in preview.items() if key != "preview_hash"}
    if preview.get("preview_hash") != canonical_hash(unsigned):
        raise ValueError("dashboard preview hash mismatch")
    if any(item.get("unsupported_chart_count") for item in preview.get("dashboards", [])):
        raise ValueError("dashboard preview contains unsupported data widgets")
    if paths["progress"].exists():
        progress = read_object(paths["progress"])
        if progress.get("preview_hash") != preview["preview_hash"]:
            progress = {"preview_hash": preview["preview_hash"], "group": None, "charts": {}, "dashboards": {}}
    else:
        progress = {"preview_hash": preview["preview_hash"], "group": None, "charts": {}, "dashboards": {}}

    def save_progress() -> None:
        atomic_write_json(paths["progress"], progress)

    organization = client.call("GET", "/v2/organization").get("id")
    if not isinstance(organization, str) or not organization:
        raise ValueError("Splunk organization identity is invalid")
    group_id: str | None = None
    group_created = False
    group_name = preview["group"]["name"]
    group_matches = exact_results(client.call("GET", "/v2/dashboardgroup", query={"name": group_name, "limit": 20}), group_name)
    if len(group_matches) > 1:
        raise ValueError("multiple dashboard groups share the approved target name")
    previous_group = progress.get("group")
    if group_matches:
        group_id = group_matches[0].get("id")
        if "AI-Created" not in str(group_matches[0].get("description", "")):
            raise ValueError("dashboard group name conflict is not migration-owned")
    else:
        if isinstance(previous_group, dict) and previous_group.get("outcome") == "pending_create":
            raise ValueError("pending dashboard-group create is not visible; refusing a blind second POST")
        progress["group"] = {"target_id": None, "outcome": "pending_create"}
        save_progress()
        group = client.call("POST", "/v2/dashboardgroup", preview["group"])
        group_id = group.get("id")
        group_created = True
    if not isinstance(group_id, str) or not group_id:
        raise ValueError("dashboard group ID is missing")
    group_outcome = "created" if group_created else "reused"
    if (
        isinstance(previous_group, dict)
        and previous_group.get("target_id") in {None, group_id}
        and previous_group.get("outcome") in {"created", "pending_create"}
    ):
        group_outcome = "created"
    progress["group"] = {"target_id": group_id, "outcome": group_outcome}
    save_progress()
    created_chart_count = 0
    chart_results: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for item in preview["dashboards"]:
        chart_layouts: list[dict[str, Any]] = []
        if len(item["charts"]) != len(item["layouts"]):
            raise ValueError("dashboard chart and layout counts differ")
        for payload, layout in zip(item["charts"], item["layouts"]):
            marker = next(tag for tag in payload["tags"] if tag.startswith("codex-migration-"))
            prior_chart = progress["charts"].get(marker)

            def record_chart_intent(_marker: str) -> None:
                progress["charts"][_marker] = {
                    "object_ref": _marker, "target_id": None, "outcome": "pending_create",
                    "payload_hash": canonical_hash(payload), "validated": False,
                }
                save_progress()

            chart, created = chart_by_marker(
                client, payload,
                allow_create=not (isinstance(prior_chart, dict) and prior_chart.get("outcome") == "pending_create"),
                on_create_intent=record_chart_intent,
            )
            created_chart_count += int(created)
            chart_layouts.append({"chartId": chart["id"], **layout})
            previous = chart_results.get(marker)
            current = {
                "object_ref": marker,
                "target_id": chart["id"],
                "outcome": "created" if created else "reused",
                "payload_hash": canonical_hash(payload),
                "validated": True,
            }
            if (
                isinstance(prior_chart, dict)
                and prior_chart.get("outcome") in {"created", "pending_create"}
                and prior_chart.get("target_id") in {None, chart["id"]}
            ):
                current["outcome"] = "created"
            if previous is not None and previous != current:
                raise ValueError("chart marker resolved inconsistently across dashboards")
            chart_results[marker] = current
            progress["charts"][marker] = current
            save_progress()
        body: dict[str, Any] = {
            "name": item["target_name"],
            "description": f"[AI-Created] Migrated from Datadog. SourceRef: {item['object_ref']}",
            "chartDensity": "DEFAULT", "charts": chart_layouts,
            "filters": {"sources": [], "variables": item["variables"]},
            "groupId": group_id,
        }
        matches = exact_results(client.call("GET", "/v2/dashboard", query={"name": item["target_name"], "limit": 20}), item["target_name"])
        if len(matches) > 1:
            raise ValueError("multiple dashboards share an approved target name")
        before_state: dict[str, Any] | None = None
        prior_dashboard = progress["dashboards"].get(item["object_ref"])
        if matches:
            dashboard_id = matches[0].get("id")
            if not isinstance(dashboard_id, str) or not dashboard_id:
                raise ValueError("existing dashboard ID is missing")
            dashboard = client.call("GET", f"/v2/dashboard/{parse.quote(dashboard_id, safe='')}")
            if f"SourceRef: {item['object_ref']}" not in str(dashboard.get("description", "")):
                raise ValueError("dashboard name conflict is not owned by this migration source")
            if contains_expected(dashboard, body):
                outcome = "reused"
                if (
                    isinstance(prior_dashboard, dict)
                    and prior_dashboard.get("target_id") == dashboard_id
                    and prior_dashboard.get("outcome") in {"created", "updated"}
                ):
                    outcome = prior_dashboard["outcome"]
                    before_state = prior_dashboard.get("before_state")
            else:
                before_state = dashboard
                dashboard = client.call(
                    "PUT", f"/v2/dashboard/{parse.quote(dashboard_id, safe='')}", body,
                )
                outcome = "updated"
        else:
            if isinstance(prior_dashboard, dict) and prior_dashboard.get("outcome") == "pending_create":
                raise ValueError("pending dashboard create is not yet visible; refusing a blind second POST")
            progress["dashboards"][item["object_ref"]] = {
                "object_ref": item["object_ref"], "target_id": None,
                "outcome": "pending_create", "chart_count": len(chart_layouts),
                "validated": False, "payload_hash": canonical_hash(body), "before_state": None,
            }
            save_progress()
            dashboard = client.call("POST", "/v2/dashboard", body)
            outcome = "created"
        dashboard_id = dashboard.get("id")
        if not isinstance(dashboard_id, str) or not dashboard_id:
            raise ValueError("created dashboard ID is missing")
        actual = client.call("GET", f"/v2/dashboard/{parse.quote(dashboard_id, safe='')}")
        actual_group_id = actual.get("groupId")
        if not isinstance(actual_group_id, str) or not actual_group_id:
            raise ValueError("dashboard read-back group ID is missing")
        if actual_group_id != group_id:
            raise ValueError("dashboards were created in different groups")
        if actual.get("name") != item["target_name"]:
            raise ValueError("dashboard read-back name differs")
        charts = actual.get("charts")
        if not isinstance(charts, list) or len(charts) != len(item["charts"]):
            raise ValueError("dashboard read-back chart count differs")
        if any(
            not contains_expected(actual_chart, expected_chart)
            for actual_chart, expected_chart in zip(charts, chart_layouts)
        ):
            raise ValueError("dashboard read-back chart layout differs")
        variables = (actual.get("filters") or {}).get("variables", [])
        if len(variables) != len(item["variables"]):
            raise ValueError("dashboard read-back variable count differs")
        dashboard_result = {
            "object_ref": item["object_ref"], "target_id": dashboard_id,
            "outcome": outcome, "chart_count": len(charts), "validated": True,
            "payload_hash": canonical_hash(body), "before_state": before_state,
        }
        results.append(dashboard_result)
        progress["dashboards"][item["object_ref"]] = dashboard_result
        save_progress()
    group = client.call("GET", f"/v2/dashboardgroup/{parse.quote(group_id, safe='')}")
    configs = group.get("dashboardConfigs", [])
    config_by_dashboard = {
        value.get("dashboardId"): value.get("configId") for value in configs if isinstance(value, dict)
    }
    realm_host = client.origin.removeprefix("https://api.")
    for item in results:
        config_id = config_by_dashboard.get(item["target_id"])
        if not isinstance(config_id, str) or not config_id:
            raise ValueError("dashboard group config ID is missing")
        item["config_id"] = config_id
        item["url"] = (
            f"https://app.{realm_host}/#/dashboard/{item['target_id']}"
            f"?groupId={parse.quote(group_id, safe='')}"
            f"&configId={parse.quote(config_id, safe='')}"
        )
    result = {
        "schema_version": "1.0", "session_id": preview["session_id"],
        "preview_hash": preview["preview_hash"], "organization_hash": canonical_hash(organization),
        "group_id": group_id, "group_outcome": group_outcome, "results": results,
        "charts": sorted(chart_results.values(), key=lambda item: item["object_ref"]),
        "created_dashboard_count": sum(item["outcome"] == "created" for item in results),
        "updated_dashboard_count": sum(item["outcome"] == "updated" for item in results),
        "reused_dashboard_count": sum(item["outcome"] == "reused" for item in results),
        "validated_dashboard_count": len(results),
        "created_chart_count": created_chart_count,
    }
    result["result_hash"] = canonical_hash(result)
    atomic_write_json(paths["result"], result)
    return result


def execute(paths: dict[str, Path], client: SplunkClient) -> dict[str, Any]:
    """Serialize the complete dashboard apply to prevent duplicate creates."""
    lock_path = paths["directory"] / "dashboard-execution" / "apply.lock"
    lock_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with lock_path.open("a+", encoding="utf-8") as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError("dashboard apply is already running") from None
        return _execute_unlocked(paths, client)


def validate(paths: dict[str, Path], client: SplunkClient) -> dict[str, Any]:
    result = read_object(paths["result"])
    for item in result.get("results", []):
        actual = client.call("GET", f"/v2/dashboard/{parse.quote(str(item['target_id']), safe='')}")
        if actual.get("id") != item["target_id"] or len(actual.get("charts", [])) != item["chart_count"]:
            raise ValueError("dashboard validation failed")
    return result


def preview_summary(preview: dict[str, Any], path: Path) -> dict[str, Any]:
    dashboards = preview["dashboards"]
    return {
        "preview": str(path.resolve()), "preview_hash": preview["preview_hash"],
        "dashboard_count": len(dashboards), "chart_count": sum(len(item["charts"]) for item in dashboards),
        "supported_chart_count": sum(item["supported_chart_count"] for item in dashboards),
        "unsupported_chart_count": sum(item["unsupported_chart_count"] for item in dashboards),
        "adaptations": sorted({value for item in dashboards for value in item["differences"]}),
        "external_mutations_performed": 0,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("prepare-preview", "execute", "validate"):
        command = commands.add_parser(name)
        command.add_argument("--session-id", required=True)
        command.add_argument("--work-root", default=".migration-work")
        if name != "prepare-preview":
            command.add_argument("--env-file", default=".env")
        if name == "execute":
            command.add_argument("--confirm-execution", action="store_true")
    args = parser.parse_args()
    paths = session_paths(Path(args.work_root), args.session_id)
    if args.command == "prepare-preview":
        print(json.dumps(preview_summary(prepare_preview(paths), paths["preview"]), indent=2, sort_keys=True))
        return 0
    if args.command == "execute" and not args.confirm_execution:
        raise ValueError("explicit --confirm-execution is required")
    token, origin = credentials(Path(args.env_file))
    client = SplunkClient(origin, token)
    value = execute(paths, client) if args.command == "execute" else validate(paths, client)
    print(json.dumps({
        "result": str(paths["result"].resolve()), "created_dashboards": value["created_dashboard_count"],
        "updated_dashboards": value["updated_dashboard_count"],
        "reused_dashboards": value["reused_dashboard_count"], "validated_dashboards": value["validated_dashboard_count"],
        "created_charts": value["created_chart_count"],
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
