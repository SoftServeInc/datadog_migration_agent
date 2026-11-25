"""Deterministic local translation for a narrow Datadog metric-monitor subset."""

from __future__ import annotations

import copy
import re
from decimal import Decimal, InvalidOperation, localcontext
from typing import Any

from assessment_core.security import pseudonym

from .common import OBJECT_REF, value_hash


NUMBER = r"-?(?:0|[1-9][0-9]{0,17})(?:\.[0-9]{1,12})?"
IDENTIFIER = r"[A-Za-z_][A-Za-z0-9_.-]*"
WINDOW = r"[1-9][0-9]{0,5}[smhd]"
SIMPLE_METRIC_QUERY = re.compile(
    rf"""
    (?P<outer>avg|sum|min|max)\(last_(?P<window>{WINDOW})\):
    (?P<inner>avg|sum|min|max):(?P<metric>[A-Za-z_][A-Za-z0-9_.-]*)\{{\*\}}
    (?:\s*by\s*\{{(?P<groups>{IDENTIFIER}(?:\s*,\s*{IDENTIFIER})*)\}})?
    (?P<scale>\s*/\s*\(\s*{NUMBER}(?:\s*\*\s*{NUMBER}){{1,3}}\s*\))?
    \s*(?P<operator>>=|<=|>|<)\s*(?P<threshold>{NUMBER})\s*
    """,
    re.IGNORECASE | re.VERBOSE,
)
COMPLEMENT_METRIC_QUERY = re.compile(
    rf"""
    avg\(last_(?P<window>{WINDOW})\):
    (?P<constant>1(?:\.0+)?|100(?:\.0+)?)\s*-\s*
    avg:(?P<metric>[A-Za-z_][A-Za-z0-9_.-]*)\{{\*\}}
    \s*by\s*\{{(?P<groups>{IDENTIFIER}(?:\s*,\s*{IDENTIFIER}){{0,7}})\}}
    \s*(?P<operator>>=|<=|>|<)\s*(?P<threshold>{NUMBER})\s*
    """,
    re.IGNORECASE | re.VERBOSE,
)
AGGREGATION = {"avg": "mean", "sum": "sum", "min": "min", "max": "max"}
ROLLUP = {"avg": "average", "sum": "sum", "min": "min", "max": "max"}
RATE_RATIO_PREFIX = re.compile(
    rf"^(?P<outer>avg|sum|min|max)\(last_(?P<window>{WINDOW})\):",
    re.IGNORECASE,
)
RATE_TERM = re.compile(
    rf"^(?P<aggregation>sum):(?P<metric>{IDENTIFIER})"
    rf"\{{(?P<scope>[^{{}}]{{1,2048}})\}}\s*by\s*"
    rf"\{{(?P<groups>{IDENTIFIER}(?:\s*,\s*{IDENTIFIER}){{0,7}})\}}"
    rf"\s*\.as_rate\(\)\s*$",
    re.IGNORECASE,
)
FILTER_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,127}$")
FILTER_VALUE = re.compile(r"^[^\x00-\x20'\"\\,{}]{1,256}$")
IN_SCOPE = re.compile(
    rf"^(?P<key>{IDENTIFIER})\s+IN\s+\((?P<values>[^(){{}}]{{1,2048}})\)$",
    re.IGNORECASE,
)
OPERATION_PREFIX = re.compile(r"^\[operation:([^\]]{1,128})\]\s*", re.IGNORECASE)
SOURCE_PLACEHOLDER = re.compile(r"\{\{\s*([A-Za-z_][A-Za-z0-9_.-]{0,127})\s*\}\}")


def _scale_divisor(scale: str | None) -> Decimal | None:
    if not scale:
        return None
    try:
        factors = [Decimal(value) for value in re.findall(NUMBER, scale)]
        with localcontext() as context:
            context.prec = 160
            divisor = Decimal(1)
            for factor in factors:
                divisor *= factor
    except (InvalidOperation, OverflowError):
        return None
    if not factors or not divisor.is_finite() or divisor <= 0:
        return None
    return divisor


def _split_top_level_once(value: str, tokens: tuple[str, ...]) -> tuple[str, str, str] | None:
    """Split once on a token outside braces, parentheses, and quoted strings."""
    braces = 0
    parentheses = 0
    quote: str | None = None
    escaped = False
    found: tuple[int, str] | None = None
    index = 0
    while index < len(value):
        character = value[index]
        if quote is not None:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            index += 1
            continue
        if character in {"'", '"'}:
            quote = character
        elif character == "{":
            braces += 1
        elif character == "}":
            braces -= 1
        elif character == "(":
            parentheses += 1
        elif character == ")":
            parentheses -= 1
        elif braces == 0 and parentheses == 0:
            token = next((item for item in tokens if value.startswith(item, index)), None)
            if token is not None:
                if found is not None:
                    return None
                found = (index, token)
                index += len(token)
                continue
        if braces < 0 or parentheses < 0:
            return None
        index += 1
    if quote is not None or braces != 0 or parentheses != 0 or found is None:
        return None
    position, token = found
    return value[:position].strip(), token, value[position + len(token):].strip()


def _parse_scope(scope: str) -> list[tuple[str, tuple[str, ...], bool]] | None:
    in_match = IN_SCOPE.fullmatch(scope.strip())
    if in_match:
        choices = tuple(item.strip() for item in in_match.group("values").split(","))
        if (
            not 1 <= len(choices) <= 8
            or len(set(choices)) != len(choices)
            or any(not FILTER_VALUE.fullmatch(value) or value.startswith("*") for value in choices)
        ):
            return None
        return [(in_match.group("key"), choices, False)]
    values: list[tuple[str, tuple[str, ...], bool]] = []
    for raw in scope.split(","):
        clause = raw.strip()
        negated = clause.startswith("!")
        if negated:
            clause = clause[1:]
        key, separator, value = clause.partition(":")
        if not separator or not FILTER_KEY.fullmatch(key) or not FILTER_VALUE.fullmatch(value):
            return None
        if value.startswith("*"):
            return None
        values.append((key, (value,), negated))
    if not 1 <= len(values) <= 8 or len({(key, choices, negated) for key, choices, negated in values}) != len(values):
        return None
    return values


def _quoted(value: str) -> str:
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def _source_name(record: dict[str, Any], fallback: str) -> str:
    value = record.get("name")
    if not isinstance(value, str):
        return fallback
    value = " ".join(value.split())
    if not value or any(ord(character) < 32 for character in value):
        return fallback
    return value[:255]


def _dimension_name(value: str) -> str:
    leaf = value.rsplit(".", 1)[-1].replace("_", " ").replace("-", " ")
    return " ".join(leaf.split()).lower() or "dimension"


def _target_name(record: dict[str, Any], fallback: str) -> str:
    """Convert source-only template syntax to a stable human-readable target name."""

    source = _source_name(record, fallback)
    operation: str | None = None
    match = OPERATION_PREFIX.match(source)
    if match:
        operation = " ".join(match.group(1).split())
        source = source[match.end():].strip()

    # Normalize common Datadog message-template grammar before the generic fallback.
    source = re.sub(
        r"\bfor\s+host\s+\{\{\s*host\.name\s*\}\}\s+on\s+device\s+\{\{\s*device\.name\s*\}\}",
        "by host and device",
        source,
        flags=re.IGNORECASE,
    )
    source = re.sub(
        r"\b(?:for|on)\s+(?:host\s+)?\{\{\s*host\.name\s*\}\}",
        "by host",
        source,
        flags=re.IGNORECASE,
    )
    source = re.sub(
        r"\b(?:for|on)\s+(?:service\s+)?\{\{\s*service\.name\s*\}\}",
        "by service",
        source,
        flags=re.IGNORECASE,
    )
    source = re.sub(
        r"\b(?:for|on)\s+(?:device\s+)?\{\{\s*device\.name\s*\}\}",
        "by device",
        source,
        flags=re.IGNORECASE,
    )
    dimensions: list[str] = []

    def replace_placeholder(match: re.Match[str]) -> str:
        dimension = _dimension_name(match.group(1))
        if dimension not in dimensions:
            dimensions.append(dimension)
        return dimension

    source = SOURCE_PLACEHOLDER.sub(replace_placeholder, source)
    source = re.sub(r"\s+", " ", source).strip(" -—:;,.")
    if dimensions and " by " not in f" {source.lower()} ":
        source = f"{source} by {' and '.join(dimensions)}"
    if operation:
        source = f"{source} — {operation}"
    return (source or fallback)[:255]


def _filter_expression(filters: list[tuple[str, tuple[str, ...], bool]]) -> str:
    return " and ".join(
        ("not " if negated else "")
        + f"filter({_quoted(key)}, {', '.join(_quoted(value) for value in choices)})"
        for key, choices, negated in filters
    )


def _parse_rate_term(value: str) -> dict[str, Any] | None:
    match = RATE_TERM.fullmatch(value)
    if not match:
        return None
    filters = _parse_scope(match.group("scope"))
    groups = [item.strip() for item in match.group("groups").split(",")]
    if filters is None or len(set(groups)) != len(groups):
        return None
    return {
        "metric": match.group("metric"),
        "filters": filters,
        "groups": groups,
    }


def translate_rate_ratio_monitor(
    monitor: dict[str, Any], object_ref: str,
) -> dict[str, Any] | None:
    """Translate two filtered grouped rate streams divided as one timed ratio."""
    if not OBJECT_REF.fullmatch(object_ref) or monitor.get("source_type") != "monitor":
        return None
    queries = monitor.get("queries")
    if not isinstance(queries, list) or len(queries) != 1 or not isinstance(queries[0], dict):
        return None
    query = queries[0].get("value")
    if not isinstance(query, str) or len(query) > 20_000:
        return None
    prefix = RATE_RATIO_PREFIX.match(query)
    if not prefix:
        return None
    comparison = _split_top_level_once(query[prefix.end():], (">=", "<=", ">", "<"))
    if comparison is None:
        return None
    expression, operator, threshold = comparison
    if not re.fullmatch(NUMBER, threshold):
        return None
    ratio = _split_top_level_once(expression, ("/",))
    if ratio is None:
        return None
    numerator_text, _slash, denominator_text = ratio
    numerator = _parse_rate_term(numerator_text)
    denominator = _parse_rate_term(denominator_text)
    if numerator is None or denominator is None or numerator["groups"] != denominator["groups"]:
        return None
    groups = ", ".join(_quoted(value) for value in numerator["groups"])
    by_argument = f"[{groups}]" if len(numerator["groups"]) > 1 else _quoted(numerator["groups"][0])
    numerator_filter = _filter_expression(numerator["filters"])
    denominator_filter = _filter_expression(denominator["filters"])
    outer = AGGREGATION[prefix.group("outer").lower()]
    window = prefix.group("window").lower()
    label = f"migration_{object_ref[-16:]}"
    lines = [
        f"N = data({_quoted(numerator['metric'])}, filter={numerator_filter}, rollup='rate').sum(by={by_argument})",
        f"D = data({_quoted(denominator['metric'])}, filter={denominator_filter}, rollup='rate').sum(by={by_argument})",
        f"R = (N / D).{outer}(over='{window}')",
        f"detect(R {operator} {threshold}).publish('{label}')",
    ]
    return {
        "name": _target_name(monitor, f"Datadog rate ratio {object_ref[-8:]}"),
        "description": "Automatically translated from an allowlisted filtered grouped rate-ratio query shape.",
        "programText": "\n".join(lines),
        "rules": [{
            "detectLabel": label,
            "severity": "Warning",
            "disabled": True,
            "notifications": [],
        }],
        "tags": ["migration-source-datadog", "migration-auto-translated", "migration-rate-ratio"],
        "customProperties": {
            "translationMethod": "automatic_rate_ratio_v1",
            "sourcePlatform": "datadog",
        },
    }


def translate_allowlisted_monitor(
    monitor: dict[str, Any], object_ref: str,
) -> dict[str, Any] | None:
    """Run every deterministic translator profile in a fixed order."""
    return (
        translate_simple_metric_monitor(monitor, object_ref)
        or translate_complement_metric_monitor(monitor, object_ref)
        or translate_rate_ratio_monitor(monitor, object_ref)
    )


def translate_simple_metric_monitor(monitor: dict[str, Any], object_ref: str) -> dict[str, Any] | None:
    """Translate one allowlisted query shape; return None for every other shape."""
    if not OBJECT_REF.fullmatch(object_ref) or monitor.get("source_type") != "monitor":
        return None
    queries = monitor.get("queries")
    if not isinstance(queries, list) or len(queries) != 1 or not isinstance(queries[0], dict):
        return None
    query = queries[0].get("value")
    if not isinstance(query, str) or len(query) > 20_000:
        return None
    match = SIMPLE_METRIC_QUERY.fullmatch(query)
    if not match:
        return None
    groups = [value.strip() for value in (match.group("groups") or "").split(",") if value.strip()]
    if len(groups) > 8 or len(set(groups)) != len(groups):
        return None
    inner_name = match.group("inner").lower()
    inner = AGGREGATION[inner_name]
    rollup = ROLLUP[inner_name]
    outer = AGGREGATION[match.group("outer").lower()]
    metric = match.group("metric")
    group_argument = ""
    if groups:
        values = ", ".join(f"'{value}'" for value in groups)
        group_argument = f"by=[{values}]"
    stream = f"data('{metric}', rollup='{rollup}').{inner}({group_argument})"
    stream += f".{outer}(over='{match.group('window').lower()}')"
    divisor = _scale_divisor(match.group("scale"))
    lines = [f"A = {stream}"]
    signal = "A"
    if match.group("scale"):
        if divisor is None:
            return None
        rendered = format(divisor.normalize(), "f")
        lines.append(f"B = A / {rendered}")
        signal = "B"
    label = f"migration_{object_ref[-16:]}"
    lines.append(
        f"detect({signal} {match.group('operator')} {match.group('threshold')}).publish('{label}')"
    )
    return {
        "name": _target_name(monitor, f"Datadog monitor {object_ref[-8:]}"),
        "description": "Automatically translated from an allowlisted Datadog metric-threshold query shape.",
        "programText": "\n".join(lines),
        "rules": [{
            "detectLabel": label,
            "severity": "Warning",
            "disabled": True,
            "notifications": [],
        }],
        "tags": ["migration-source-datadog", "migration-auto-translated"],
        "customProperties": {
            "translationMethod": "automatic_simple_metric_v1",
            "sourcePlatform": "datadog",
        },
    }


def translate_complement_metric_monitor(
    monitor: dict[str, Any], object_ref: str,
) -> dict[str, Any] | None:
    """Translate an allowlisted scalar minus a grouped mean over a bounded mean window."""
    if not OBJECT_REF.fullmatch(object_ref) or monitor.get("source_type") != "monitor":
        return None
    queries = monitor.get("queries")
    if not isinstance(queries, list) or len(queries) != 1 or not isinstance(queries[0], dict):
        return None
    query = queries[0].get("value")
    if not isinstance(query, str) or len(query) > 20_000:
        return None
    match = COMPLEMENT_METRIC_QUERY.fullmatch(query)
    if not match:
        return None
    groups = [value.strip() for value in match.group("groups").split(",")]
    if len(set(groups)) != len(groups):
        return None
    values = ", ".join(_quoted(value) for value in groups)
    by_argument = f"[{values}]" if len(groups) > 1 else _quoted(groups[0])
    label = f"migration_{object_ref[-16:]}"
    constant = format(Decimal(match.group("constant")).normalize(), "f")
    lines = [
        f"A = data({_quoted(match.group('metric'))}, rollup='average').mean(by={by_argument}).mean(over='{match.group('window').lower()}')",
        f"B = {constant} - A",
        f"detect(B {match.group('operator')} {match.group('threshold')}).publish('{label}')",
    ]
    return {
        "name": _target_name(monitor, f"Datadog complement metric {object_ref[-8:]}"),
        "description": "Automatically translated from an allowlisted grouped scalar-minus-mean metric query shape.",
        "programText": "\n".join(lines),
        "rules": [{
            "detectLabel": label,
            "severity": "Warning",
            "disabled": True,
            "notifications": [],
        }],
        "tags": [
            "migration-source-datadog", "migration-auto-translated",
            "migration-complement-metric",
        ],
        "customProperties": {
            "translationMethod": "automatic_complement_metric_v1",
            "sourcePlatform": "datadog",
        },
    }


def auto_populate_draft(
    draft: dict[str, Any],
    inventory: dict[str, Any],
    salt: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Populate up to the wave cap without returning raw source or target values."""
    collections = inventory.get("inventory")
    monitors = collections.get("monitors") if isinstance(collections, dict) else None
    if not isinstance(monitors, list):
        raise ValueError("Datadog inventory monitors are missing")
    by_ref: dict[str, dict[str, Any]] = {}
    for monitor in monitors:
        if not isinstance(monitor, dict) or monitor.get("source_type") != "monitor":
            continue
        source_id = monitor.get("source_id")
        if source_id is None or not str(source_id).strip():
            continue
        object_ref = pseudonym(f"monitor:{source_id}", salt)
        if object_ref in by_ref:
            raise ValueError("Datadog inventory contains duplicate monitor references")
        by_ref[object_ref] = monitor
    result = copy.deepcopy(draft)
    approved = sum(
        isinstance(entry, dict)
        and entry.get("target_kind") == "detector"
        and entry.get("review_status") == "approved"
        for entry in result.get("entries", [])
    )
    capacity = int(result.get("max_creates", 0)) - approved
    if capacity < 0:
        raise ValueError("approved entries exceed the execution wave cap")
    translated = 0
    eligible_unsupported = 0
    missing_source = 0
    automatic_payload_hashes: dict[str, str] = {}
    for entry in result.get("entries", []):
        if (
            not isinstance(entry, dict)
            or entry.get("target_kind") != "detector"
        ):
            continue
        object_ref = entry.get("object_ref")
        if entry.get("review_status") == "approved":
            review = entry.get("semantic_review")
            if isinstance(review, dict) and review.get("review_method") == "automatic_allowlisted_v1":
                monitor = by_ref.get(str(object_ref))
                expected = translate_allowlisted_monitor(monitor, str(object_ref)) if monitor is not None else None
                if expected is None or expected != entry.get("payload"):
                    raise ValueError("automatic draft payload no longer matches the bound source inventory")
                automatic_payload_hashes[str(object_ref)] = value_hash(expected)
            continue
        if entry.get("review_status") != "pending":
            continue
        monitor = by_ref.get(str(object_ref))
        if monitor is None:
            missing_source += 1
            continue
        payload = translate_allowlisted_monitor(monitor, str(object_ref))
        if payload is None:
            eligible_unsupported += 1
            continue
        if translated >= capacity:
            continue
        entry["payload"] = payload
        entry["review_status"] = "approved"
        entry["semantic_review"] = {
            "review_method": "automatic_allowlisted_v1",
            "source_intent_reviewed": False,
            "signalflow_reviewed": False,
            "differences_accepted": False,
            "allowlisted_shape_validated": True,
            "disabled_effects_validated": True,
        }
        automatic_payload_hashes[str(object_ref)] = value_hash(payload)
        translated += 1
    if translated == 0 and approved == 0:
        raise ValueError("no allowlisted Datadog metric monitors can be translated automatically")
    instructions = result.get("instructions")
    if isinstance(instructions, dict):
        instructions.pop("automatic_translation_method", None)
        instructions["automatic_translation_methods"] = sorted({
            str(entry.get("payload", {}).get("customProperties", {}).get("translationMethod"))
            for entry in result.get("entries", [])
            if isinstance(entry, dict)
            and entry.get("review_status") == "approved"
            and isinstance(entry.get("semantic_review"), dict)
            and entry.get("semantic_review", {}).get("review_method") == "automatic_allowlisted_v1"
            and isinstance(entry.get("payload"), dict)
            and entry.get("payload", {}).get("customProperties", {}).get("translationMethod")
        })
    return result, {
        "previously_approved": approved,
        "auto_translated": translated,
        "unsupported_query_shapes": eligible_unsupported,
        "missing_source_records": missing_source,
        "_automatic_payload_hashes": automatic_payload_hashes,
    }


__all__ = [
    "auto_populate_draft", "translate_allowlisted_monitor",
    "translate_complement_metric_monitor", "translate_rate_ratio_monitor",
    "translate_simple_metric_monitor",
]
