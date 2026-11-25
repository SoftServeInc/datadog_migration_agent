from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ASSESSMENT = ROOT / ".agents" / "skills" / "observability-migration-assessment" / "scripts"
DASHBOARD = ROOT / ".agents" / "skills" / "observability-migration-dashboard-executor" / "scripts"
sys.path[:0] = [str(ASSESSMENT), str(DASHBOARD)]

from assessment_core.security import pseudonym  # noqa: E402
from dashboard_migration import (  # noqa: E402
    canonical_hash, execute, metric_expression, prepare_preview, request_program,
    session_paths, translate_widget,
)


SALT = "a" * 64


def widget(widget_type: str = "timeseries") -> dict[str, object]:
    return {
        "definition": {
            "type": widget_type,
            "title": "Request latency",
            "requests": [{"q": "avg:service.request.latency{env:prod} by {service}"}],
        }
    }


class FakeClient:
    def __init__(self) -> None:
        self.origin = "https://api.eu1.observability.splunkcloud.com"
        self.groups: list[dict[str, object]] = []
        self.charts: list[dict[str, object]] = []
        self.dashboards: list[dict[str, object]] = []

    def call(self, method: str, path: str, payload=None, query=None):
        if path == "/v2/organization":
            return {"id": "org-1"}
        if method == "GET" and path == "/v2/dashboardgroup":
            return {"results": self.groups}
        if method == "POST" and path == "/v2/dashboardgroup":
            value = {"id": "group-1", "dashboardConfigs": [], **payload}
            self.groups.append(value)
            return value
        if method == "GET" and path.startswith("/v2/dashboardgroup/"):
            group = self.groups[0]
            return {**group, "dashboardConfigs": [
                {"dashboardId": item["id"], "configId": f"config-{index + 1}"}
                for index, item in enumerate(self.dashboards)
            ]}
        if method == "GET" and path == "/v2/chart":
            marker = query["tags"]
            return {"results": [item for item in self.charts if marker in item["tags"]]}
        if method == "POST" and path == "/v2/chart":
            value = {**payload, "id": f"chart-{len(self.charts) + 1}"}
            self.charts.append(value)
            return value
        if method == "GET" and path.startswith("/v2/chart/"):
            return next(item for item in self.charts if item["id"] == path.rsplit("/", 1)[-1])
        if method == "GET" and path == "/v2/dashboard":
            return {"results": self.dashboards}
        if method == "POST" and path == "/v2/dashboard":
            value = {
                "id": f"dashboard-{len(self.dashboards) + 1}",
                **payload,
                "groupId": payload.get("groupId", "group-1"),
            }
            self.dashboards.append(value)
            return value
        if method == "PUT" and path.startswith("/v2/dashboard/"):
            dashboard_id = path.rsplit("/", 1)[-1]
            index = next(index for index, item in enumerate(self.dashboards) if item["id"] == dashboard_id)
            value = {**self.dashboards[index], **payload, "id": dashboard_id}
            self.dashboards[index] = value
            return value
        if method == "GET" and path.startswith("/v2/dashboard/"):
            return next(item for item in self.dashboards if item["id"] == path.rsplit("/", 1)[-1])
        raise AssertionError((method, path))


class DashboardTranslationTests(unittest.TestCase):
    def test_metric_and_count_nonzero_translation(self) -> None:
        parsed = metric_expression("count_nonzero(avg:host.cpu{*} by {host})")
        self.assertIsNotNone(parsed)
        expression, differences = parsed
        self.assertIn("data('host.cpu'", expression)
        self.assertIn(".count()", expression)
        self.assertIn("count_nonzero_adapted_to_stream_count", differences)

    def test_formula_request_translation(self) -> None:
        program, differences = request_program({"requests": [{
            "queries": [
                {"data_source": "metrics", "name": "good", "query": "sum:req.good{*}"},
                {"data_source": "metrics", "name": "total", "query": "sum:req.total{*}"},
            ],
            "formulas": [{"formula": "100 * good / total"}],
        }]})
        self.assertEqual(differences, [])
        self.assertIn("C = 100 * A / B", program)

    def test_note_and_data_widgets_keep_names_and_ai_tag(self) -> None:
        note = translate_widget({"definition": {"type": "note", "content": "# SLO"}}, 0, "obj_0123456789abcdef")
        chart = translate_widget(widget(), 1, "obj_0123456789abcdef")
        self.assertTrue(note["supported"] and chart["supported"])
        self.assertEqual(chart["chart"]["name"], "Request latency")
        self.assertIn("AI-Created", chart["chart"]["tags"])

    def test_layout_is_compacted_for_splunk(self) -> None:
        from dashboard_migration import translate_layouts
        layouts = translate_layouts([
            widget(), widget("query_value"), {"definition": {"type": "note"}}, widget(),
        ])
        self.assertEqual(layouts, [
            {"column": 0, "row": 0, "width": 4, "height": 2},
            {"column": 4, "row": 0, "width": 4, "height": 1},
            {"column": 0, "row": 2, "width": 12, "height": 1},
            {"column": 0, "row": 3, "width": 4, "height": 2},
        ])

    def test_layout_preserves_datadog_rows_and_column_boundaries(self) -> None:
        from dashboard_migration import translate_layouts
        layouts = translate_layouts([
            {"definition": {"type": "note"}, "layout": {"x": 0, "y": 0, "width": 90, "height": 5}},
            {"definition": {"type": "query_value"}, "layout": {"x": 0, "y": 5, "width": 22, "height": 15}},
            {"definition": {"type": "query_value"}, "layout": {"x": 22, "y": 5, "width": 22, "height": 15}},
            {"definition": {"type": "query_value"}, "layout": {"x": 45, "y": 5, "width": 22, "height": 15}},
            {"definition": {"type": "query_value"}, "layout": {"x": 68, "y": 5, "width": 22, "height": 15}},
            {"definition": {"type": "timeseries"}, "layout": {"x": 0, "y": 20, "width": 45, "height": 20}},
            {"definition": {"type": "timeseries"}, "layout": {"x": 45, "y": 20, "width": 45, "height": 20}},
        ])
        self.assertEqual(layouts, [
            {"column": 0, "row": 0, "width": 12, "height": 1},
            {"column": 0, "row": 1, "width": 3, "height": 1},
            {"column": 3, "row": 1, "width": 3, "height": 1},
            {"column": 6, "row": 1, "width": 3, "height": 1},
            {"column": 9, "row": 1, "width": 3, "height": 1},
            {"column": 0, "row": 2, "width": 6, "height": 2},
            {"column": 6, "row": 2, "width": 6, "height": 2},
        ])

    def test_prepare_preview_keeps_all_dashboards_and_widgets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            session_id = "assessment-dashboard-test"
            paths = session_paths(root, session_id)
            source_id = "dashboard-1"
            object_ref = pseudonym(f"dashboard:{source_id}", SALT)
            paths["checkpoint"].write_text(json.dumps({
                "assessment_id": session_id, "local_pseudonym_salt": SALT,
                "plan_hash": "b" * 64,
            }))
            paths["plan"].write_text(json.dumps({"plan_hash": "b" * 64, "steps": [{
                "object_ref": object_ref, "object_type": "dashboard",
                "target": "splunk_observability_cloud", "proposed_operation": "PROPOSE_TRANSFORM",
            }]}))
            paths["inventory"].parent.mkdir(parents=True)
            paths["inventory"].write_text(json.dumps({"inventory": {"dashboards": [{
                "source_id": source_id, "name": "Production overview",
                "dashboard_spec": {
                    "widgets": [widget(), {"definition": {"type": "note", "content": "hello"}}],
                    "template_variables": [{"name": "environment", "prefix": "env", "default": "prod"}],
                },
            }]}}))
            preview = prepare_preview(paths)
            self.assertEqual(preview["session_id"], session_id)
            self.assertEqual(preview["dashboards"][0]["target_name"], "Production overview")
            self.assertEqual(len(preview["dashboards"][0]["charts"]), 2)
            self.assertEqual(preview["dashboards"][0]["variables"][0]["property"], "env")

    def test_execute_creates_and_validates_one_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            paths = session_paths(Path(directory), "assessment-dashboard-test")
            translated = translate_widget(widget(), 0, "obj_0123456789abcdef")
            preview = {
                "schema_version": "1.0", "session_id": "assessment-dashboard-test",
                "plan_hash": "b" * 64, "inventory_hash": "c" * 64,
                "group": {"name": "Datadog Migration [AI-Created]", "description": "[AI-Created]"},
                "dashboards": [{
                    "object_ref": "obj_0123456789abcdef", "source_name": "Overview",
                    "target_name": "Overview [AI-Created]", "charts": [translated["chart"]],
                    "layouts": [{"column": 0, "row": 0, "width": 12, "height": 1}],
                    "variables": [],
                    "supported_chart_count": 1, "unsupported_chart_count": 0, "differences": [],
                }],
            }
            preview["preview_hash"] = canonical_hash(preview)
            paths["preview"].write_text(json.dumps(preview))
            client = FakeClient()
            result = execute(paths, client)
            self.assertEqual(result["created_dashboard_count"], 1)
            self.assertEqual(result["created_chart_count"], 1)
            self.assertEqual(result["validated_dashboard_count"], 1)
            resumed = execute(paths, client)
            self.assertEqual(resumed["results"][0]["outcome"], "created")
            self.assertEqual(resumed["charts"][0]["outcome"], "created")
            self.assertEqual(resumed["group_outcome"], "created")

            preview["dashboards"][0]["layouts"][0] = {
                "column": 3, "row": 1, "width": 6, "height": 2,
            }
            preview["preview_hash"] = canonical_hash({
                key: value for key, value in preview.items() if key != "preview_hash"
            })
            paths["preview"].write_text(json.dumps(preview))
            updated = execute(paths, client)
            self.assertEqual(updated["updated_dashboard_count"], 1)
            self.assertEqual(client.dashboards[0]["charts"][0], {
                "chartId": "chart-1", "column": 3, "row": 1, "width": 6, "height": 2,
            })
            self.assertEqual(
                updated["results"][0]["url"],
                "https://app.eu1.observability.splunkcloud.com/#/dashboard/dashboard-1"
                "?groupId=group-1&configId=config-1",
            )


if __name__ == "__main__":
    unittest.main()
