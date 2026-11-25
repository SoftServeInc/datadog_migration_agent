"""Vendor-neutral, privacy-safe inventory IR and dependency graph."""

from __future__ import annotations

import re
from collections import Counter
from typing import Any, Optional

from .security import OBJECT_TYPES, assert_codex_safe, pseudonym


COMPOSITE_MONITOR = re.compile(r"\bmonitor\((\d+)\)", re.I)
SIGNAL_TERMS = {
    "metrics": ("avg:", "sum:", "min:", "max:", "p95:", "p99:", "metric"),
    "logs": ("logs(", "log", "@"),
    "traces": ("trace", "span", "apm"),
    "rum": ("rum",),
    "synthetics": ("synthetic",),
}
BEHAVIOR_TERMS = {
    "anomaly": ("anomal",),
    "forecast": ("forecast",),
    "outlier": ("outlier",),
    "uses_formula": ("formula",),
    "grouped": (" by {", "group_by", "groupby"),
}
OBJECT_REF = re.compile(r"^obj_[a-f0-9]{16}$")
BEHAVIOR_REF = re.compile(r"^behavior_[a-f0-9]{16}$")


def _source_id(record: dict[str, Any], index: int) -> str:
    value = record.get("source_id")
    if value is None or not str(value).strip():
        return f"index:{index}"
    return str(value)


def _plain_int(value: Any, minimum: int = 0, maximum: Optional[int] = None) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and value >= minimum
        and (maximum is None or value <= maximum)
    )


def validate_inventory_ir(ir: dict[str, Any]) -> None:
    if set(ir) != {"schema_version", "source_platform", "objects", "graph", "summary", "hygiene", "safety"}:
        raise ValueError("inventory IR fields are invalid")
    if ir.get("schema_version") != "1.0" or ir.get("source_platform") != "datadog":
        raise ValueError("inventory IR version or source is invalid")
    objects = ir.get("objects")
    if not isinstance(objects, list):
        raise ValueError("inventory IR objects must be a list")
    seen: set[str] = set()
    object_fields = {
        "object_ref", "object_type", "behavior_ref", "status", "complexity", "complexity_score",
        "risk_level", "effort_points", "owner_present", "signal_types", "behavior_features",
        "dependencies", "evidence_class",
    }
    for item in objects:
        if not isinstance(item, dict) or set(item) != object_fields:
            raise ValueError("inventory IR object fields are invalid")
        object_ref = item.get("object_ref")
        if not isinstance(object_ref, str) or not OBJECT_REF.fullmatch(object_ref) or object_ref in seen:
            raise ValueError("inventory IR object reference is invalid or duplicated")
        seen.add(object_ref)
        if item.get("object_type") not in OBJECT_TYPES | {"unknown"}:
            raise ValueError("inventory IR object type is invalid")
        if not isinstance(item.get("behavior_ref"), str) or not BEHAVIOR_REF.fullmatch(item["behavior_ref"]):
            raise ValueError("inventory IR behavior reference is invalid")
        if item.get("status") not in {"active", "enabled", "disabled", "muted", "archived", "unknown", "other"}:
            raise ValueError("inventory IR status is invalid")
        if item.get("complexity") not in {"low", "medium", "high", "unknown"}:
            raise ValueError("inventory IR complexity is invalid")
        if not _plain_int(item.get("complexity_score"), 0, 100) or not _plain_int(item.get("effort_points"), 1, 13):
            raise ValueError("inventory IR score is invalid")
        if item.get("risk_level") not in {"low", "medium", "high"} or not isinstance(item.get("owner_present"), bool):
            raise ValueError("inventory IR risk or ownership flag is invalid")
        if item.get("evidence_class") != "api_observed":
            raise ValueError("inventory IR evidence class is invalid")
        if not isinstance(item.get("signal_types"), list) or not all(
            value in {"metrics", "logs", "traces", "rum", "synthetics", "unknown"}
            for value in item["signal_types"]
        ):
            raise ValueError("inventory IR signal types are invalid")
        features = item.get("behavior_features")
        if not isinstance(features, dict) or set(features) != {
            "query_count", "widget_count", "processor_count", "anomaly", "forecast", "outlier",
            "uses_formula", "grouped",
        }:
            raise ValueError("inventory IR behavior features are invalid")
        if not all(_plain_int(features[key]) for key in ("query_count", "widget_count", "processor_count")):
            raise ValueError("inventory IR behavior feature counts are invalid")
        if not all(isinstance(features[key], bool) for key in (
            "anomaly", "forecast", "outlier", "uses_formula", "grouped"
        )):
            raise ValueError("inventory IR behavior feature flags are invalid")
        dependencies = item.get("dependencies")
        if not isinstance(dependencies, list):
            raise ValueError("inventory IR dependencies are invalid")
        for dependency in dependencies:
            if not isinstance(dependency, dict) or set(dependency) != {"object_ref", "relationship", "resolved"}:
                raise ValueError("inventory IR dependency fields are invalid")
            if not isinstance(dependency["object_ref"], str) or not OBJECT_REF.fullmatch(dependency["object_ref"]):
                raise ValueError("inventory IR dependency reference is invalid")
            if dependency["relationship"] != "depends_on" or not isinstance(dependency["resolved"], bool):
                raise ValueError("inventory IR dependency is invalid")
    graph = ir.get("graph")
    if not isinstance(graph, dict) or set(graph) != {
        "node_count", "edge_count", "edges", "missing_dependencies", "cycles"
    }:
        raise ValueError("inventory IR graph fields are invalid")
    if graph["node_count"] != len(objects) or not _plain_int(graph.get("edge_count")):
        raise ValueError("inventory IR graph counts are invalid")
    if not all(isinstance(graph.get(key), list) for key in ("edges", "missing_dependencies", "cycles")):
        raise ValueError("inventory IR graph collections are invalid")
    for edge in graph["edges"]:
        if not isinstance(edge, dict) or set(edge) != {"from_ref", "to_ref", "relationship"}:
            raise ValueError("inventory IR graph edge fields are invalid")
        if edge["relationship"] != "depends_on" or not all(
            isinstance(edge[key], str) and OBJECT_REF.fullmatch(edge[key]) for key in ("from_ref", "to_ref")
        ):
            raise ValueError("inventory IR graph edge is invalid")
    if graph["edge_count"] != len(graph["edges"]):
        raise ValueError("inventory IR graph edge count does not match")
    for missing in graph["missing_dependencies"]:
        if not isinstance(missing, dict) or set(missing) != {"from_ref", "missing_ref"} or not all(
            isinstance(missing[key], str) and OBJECT_REF.fullmatch(missing[key])
            for key in ("from_ref", "missing_ref")
        ):
            raise ValueError("inventory IR missing dependency is invalid")
    for cycle in graph["cycles"]:
        if not isinstance(cycle, list) or not cycle or not all(
            isinstance(value, str) and OBJECT_REF.fullmatch(value) for value in cycle
        ):
            raise ValueError("inventory IR cycle is invalid")
    expected_edges = sorted(
        {
            (item["object_ref"], dependency["object_ref"], "depends_on")
            for item in objects
            for dependency in item["dependencies"]
        }
    )
    actual_edges = sorted(
        (edge["from_ref"], edge["to_ref"], edge["relationship"])
        for edge in graph["edges"]
    )
    if actual_edges != expected_edges:
        raise ValueError("inventory IR graph edges do not match object dependencies")
    expected_missing = sorted(
        (item["object_ref"], dependency["object_ref"])
        for item in objects
        for dependency in item["dependencies"]
        if dependency["resolved"] is False
    )
    actual_missing = sorted(
        (item["from_ref"], item["missing_ref"]) for item in graph["missing_dependencies"]
    )
    if actual_missing != expected_missing:
        raise ValueError("inventory IR missing dependencies are inconsistent")
    adjacency = {item["object_ref"]: [] for item in objects}
    for from_ref, to_ref, _relationship in expected_edges:
        if to_ref in adjacency:
            adjacency[from_ref].append(to_ref)
    if graph["cycles"] != _cycles(adjacency):
        raise ValueError("inventory IR cycles are inconsistent")
    summary = ir.get("summary")
    hygiene = ir.get("hygiene")
    if not isinstance(summary, dict) or set(summary) != {"object_counts", "ownerless_count", "high_risk_count"}:
        raise ValueError("inventory IR summary is invalid")
    object_counts = summary["object_counts"]
    if not isinstance(object_counts, dict) or not set(object_counts).issubset(OBJECT_TYPES | {"unknown"}) or not all(
        _plain_int(value) for value in object_counts.values()
    ):
        raise ValueError("inventory IR object counts are invalid")
    if not _plain_int(summary["ownerless_count"]) or not _plain_int(summary["high_risk_count"]):
        raise ValueError("inventory IR summary counts are invalid")
    expected_counts = dict(sorted(Counter(item["object_type"] for item in objects).items()))
    if object_counts != expected_counts or summary["ownerless_count"] != sum(
        not item["owner_present"] for item in objects
    ) or summary["high_risk_count"] != sum(item["risk_level"] == "high" for item in objects):
        raise ValueError("inventory IR summary does not match objects")
    if not isinstance(hygiene, dict) or set(hygiene) != {
        "duplicate_candidate_groups", "ownerless_count", "orphan_reference_count", "invalid_status_count"
    }:
        raise ValueError("inventory IR hygiene is invalid")
    groups = hygiene["duplicate_candidate_groups"]
    if not isinstance(groups, list) or not all(
        isinstance(group, dict)
        and set(group) == {"behavior_ref", "object_refs"}
        and isinstance(group["behavior_ref"], str)
        and BEHAVIOR_REF.fullmatch(group["behavior_ref"])
        and isinstance(group["object_refs"], list)
        and all(isinstance(value, str) and OBJECT_REF.fullmatch(value) for value in group["object_refs"])
        for group in groups
    ):
        raise ValueError("inventory IR duplicate groups are invalid")
    if not all(_plain_int(hygiene[key]) for key in (
        "ownerless_count", "orphan_reference_count", "invalid_status_count"
    )):
        raise ValueError("inventory IR hygiene counts are invalid")
    behavior_counts = Counter(item["behavior_ref"] for item in objects)
    expected_groups = [
        {
            "behavior_ref": value,
            "object_refs": sorted(item["object_ref"] for item in objects if item["behavior_ref"] == value),
        }
        for value, count in sorted(behavior_counts.items()) if count > 1
    ]
    if groups != expected_groups or hygiene["ownerless_count"] != summary["ownerless_count"] or (
        hygiene["orphan_reference_count"] != len(graph["missing_dependencies"])
    ) or hygiene["invalid_status_count"] != sum(item["status"] == "other" for item in objects):
        raise ValueError("inventory IR hygiene does not match objects and graph")
    safety = ir.get("safety")
    if safety != {
        "raw_identifiers_included": False,
        "raw_expressions_included": False,
        "pii_included": False,
        "external_mutations_enabled": False,
    }:
        raise ValueError("inventory IR safety invariants are invalid")
    assert_codex_safe(ir)


def _records(inventory: dict[str, Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    collections = inventory.get("inventory", {})
    if not isinstance(collections, dict):
        return result
    for records in collections.values():
        if isinstance(records, list):
            result.extend(item for item in records if isinstance(item, dict))
    return result


def _object_type(record: dict[str, Any]) -> str:
    value = str(record.get("source_type", "unknown")).lower()
    return value if value in OBJECT_TYPES else "unknown"


def _complexity(record: dict[str, Any]) -> tuple[str, int]:
    level = str(record.get("complexity", "unknown"))
    if level not in {"low", "medium", "high"}:
        level = "unknown"
    score = record.get("complexity_score")
    if not isinstance(score, int) or isinstance(score, bool) or score < 0:
        score = {"low": 1, "medium": 3, "high": 5}.get(level, 0)
    return level, min(score, 100)


def _query_text(record: dict[str, Any]) -> str:
    fragments: list[str] = []
    queries = record.get("queries")
    if isinstance(queries, list):
        for query in queries:
            if isinstance(query, dict) and isinstance(query.get("value"), str):
                fragments.append(query["value"])
    query = record.get("query")
    if isinstance(query, dict):
        fragments.append(str(query))
    return " ".join(fragments).lower()


def _signal_types(text: str, object_type: str) -> list[str]:
    values = {
        signal for signal, terms in SIGNAL_TERMS.items()
        if any(term in text for term in terms)
    }
    if object_type == "synthetic":
        values.add("synthetics")
    return sorted(values or {"unknown"})


def _behavior_features(text: str, record: dict[str, Any]) -> dict[str, Any]:
    queries = record.get("queries", [])
    return {
        "query_count": len(queries) if isinstance(queries, list) else 0,
        "widget_count": record.get("widget_count") if isinstance(record.get("widget_count"), int) else 0,
        "processor_count": record.get("processor_count") if isinstance(record.get("processor_count"), int) else 0,
        **{
            key: any(term in text for term in terms)
            for key, terms in BEHAVIOR_TERMS.items()
        },
    }


def _dependency_ids(record: dict[str, Any], object_type: str, text: str) -> list[tuple[str, str]]:
    values: set[tuple[str, str]] = set()
    if object_type == "slo":
        monitor_ids = record.get("monitor_ids", [])
        if isinstance(monitor_ids, list):
            values.update(("monitor", str(value)) for value in monitor_ids if value is not None)
    if object_type == "monitor":
        values.update(("monitor", match) for match in COMPOSITE_MONITOR.findall(text))
    return sorted(values)


def _cycles(adjacency: dict[str, list[str]]) -> list[list[str]]:
    found: set[tuple[str, ...]] = set()
    visiting: list[str] = []
    active: set[str] = set()
    visited: set[str] = set()

    def walk(node: str) -> None:
        if node in active:
            start = visiting.index(node)
            cycle = visiting[start:] + [node]
            rotations = [tuple(cycle[index:-1] + cycle[:index] + [cycle[index]]) for index in range(len(cycle) - 1)]
            found.add(min(rotations))
            return
        if node in visited:
            return
        active.add(node)
        visiting.append(node)
        for target in adjacency.get(node, []):
            walk(target)
        visiting.pop()
        active.remove(node)
        visited.add(node)

    for value in sorted(adjacency):
        walk(value)
    return [list(value) for value in sorted(found)]


def build_inventory_ir(inventory: dict[str, Any], salt: str) -> dict[str, Any]:
    records = _records(inventory)
    refs: dict[tuple[str, str], str] = {}
    for index, record in enumerate(records):
        object_type = _object_type(record)
        source_id = _source_id(record, index)
        if (object_type, source_id) in refs:
            raise ValueError("duplicate source object identifier")
        refs[(object_type, source_id)] = pseudonym(f"{object_type}:{source_id}", salt)

    objects: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    missing: list[dict[str, str]] = []
    for index, record in enumerate(records):
        object_type = _object_type(record)
        source_id = _source_id(record, index)
        object_ref = refs[(object_type, source_id)]
        text = _query_text(record)
        behavior_ref = pseudonym(f"{object_type}:{text or 'no-expression'}", salt, prefix="behavior")
        level, score = _complexity(record)
        dependencies: list[dict[str, Any]] = []
        for dependency_type, dependency_id in _dependency_ids(record, object_type, text):
            target_ref = refs.get((dependency_type, dependency_id)) or pseudonym(
                f"{dependency_type}:{dependency_id}", salt
            )
            resolved = (dependency_type, dependency_id) in refs
            dependency = {
                "object_ref": target_ref,
                "relationship": "depends_on",
                "resolved": resolved,
            }
            dependencies.append(dependency)
            edges.append({"from_ref": object_ref, "to_ref": target_ref, "relationship": "depends_on"})
            if not resolved:
                missing.append({"from_ref": object_ref, "missing_ref": target_ref})
        risk = "high" if level == "high" or any(not item["resolved"] for item in dependencies) else (
            "medium" if level in {"medium", "unknown"} else "low"
        )
        objects.append({
            "object_ref": object_ref,
            "object_type": object_type,
            "behavior_ref": behavior_ref,
            "status": str(record.get("status", "unknown")).lower()
            if str(record.get("status", "unknown")).lower() in {
                "active", "enabled", "disabled", "muted", "archived", "unknown"
            } else "other",
            "complexity": level,
            "complexity_score": score,
            "risk_level": risk,
            "effort_points": max(1, min(13, score + len(dependencies))),
            "owner_present": bool(record.get("owner_tags")),
            "signal_types": _signal_types(text, object_type),
            "behavior_features": _behavior_features(text, record),
            "dependencies": dependencies,
            "evidence_class": "api_observed",
        })
    objects.sort(key=lambda item: (item["object_type"], item["object_ref"]))
    edges.sort(key=lambda item: (item["from_ref"], item["to_ref"]))
    adjacency: dict[str, list[str]] = {item["object_ref"]: [] for item in objects}
    for edge in edges:
        if edge["to_ref"] in adjacency:
            adjacency[edge["from_ref"]].append(edge["to_ref"])
    counts = Counter(item["object_type"] for item in objects)
    behavior_counts = Counter(item["behavior_ref"] for item in objects)
    duplicate_groups = [
        {
            "behavior_ref": value,
            "object_refs": sorted(item["object_ref"] for item in objects if item["behavior_ref"] == value),
        }
        for value, count in sorted(behavior_counts.items()) if count > 1
    ]
    ir = {
        "schema_version": "1.0",
        "source_platform": "datadog",
        "objects": objects,
        "graph": {
            "node_count": len(objects),
            "edge_count": len(edges),
            "edges": edges,
            "missing_dependencies": sorted(missing, key=lambda item: (item["from_ref"], item["missing_ref"])),
            "cycles": _cycles(adjacency),
        },
        "summary": {
            "object_counts": dict(sorted(counts.items())),
            "ownerless_count": sum(not item["owner_present"] for item in objects),
            "high_risk_count": sum(item["risk_level"] == "high" for item in objects),
        },
        "hygiene": {
            "duplicate_candidate_groups": duplicate_groups,
            "ownerless_count": sum(not item["owner_present"] for item in objects),
            "orphan_reference_count": len(missing),
            "invalid_status_count": sum(item["status"] == "other" for item in objects),
        },
        "safety": {
            "raw_identifiers_included": False,
            "raw_expressions_included": False,
            "pii_included": False,
            "external_mutations_enabled": False,
        },
    }
    validate_inventory_ir(ir)
    return ir
