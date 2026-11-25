"""Fail-closed Datadog metric-SLO and burn-rate translation."""

from __future__ import annotations

import re
from decimal import Decimal, InvalidOperation
from typing import Any

from assessment_core.security import pseudonym

from slo_common import OBJECT_REF


IDENTIFIER = r"[A-Za-z_][A-Za-z0-9_.-]*"
TERM = re.compile(
    rf"^sum:(?P<metric>{IDENTIFIER})\{{(?P<scope>[^{{}}]{{1,2048}})\}}\s*by\s*"
    rf"\{{(?P<groups>{IDENTIFIER}(?:\s*,\s*{IDENTIFIER}){{0,7}})\}}\s*\.as_count\(\)$",
    re.IGNORECASE,
)
TERM_TEXT = rf"sum:{IDENTIFIER}\{{[^{{}}]{{1,2048}}\}}\s*by\s*\{{{IDENTIFIER}(?:\s*,\s*{IDENTIFIER}){{0,7}}\}}\s*\.as_count\(\)"
NUMERATOR = re.compile(rf"^\s*(?P<a>{TERM_TEXT})\s*-\s*(?P<b>{TERM_TEXT})\s*$", re.IGNORECASE)
DENOMINATOR = re.compile(
    rf"^\s*\(\s*(?P<a>{TERM_TEXT})\s*-\s*(?P<b>{TERM_TEXT})\s*\)\s*"
    rf"\+\s*\(\s*(?P<c>{TERM_TEXT})\s*\)\s*$",
    re.IGNORECASE,
)
BURN_RATE = re.compile(
    r"^\s*burn_rate\(['\"](?P<slo>[^'\"]{1,256})['\"]\)"
    r"\.over\(['\"](?P<period>[^'\"]{1,16})['\"]\)"
    r"\.long_window\(['\"](?P<long>[^'\"]{1,16})['\"]\)"
    r"\.short_window\(['\"](?P<short>[^'\"]{1,16})['\"]\)"
    r"\s*>\s*(?P<threshold>-?(?:0|[1-9][0-9]{0,8})(?:\.[0-9]{1,6})?)\s*$",
    re.IGNORECASE,
)


def _quoted(value: str) -> str:
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def _term(value: str) -> dict[str, Any] | None:
    match = TERM.fullmatch(value.strip())
    if not match or match.group("scope").strip() != "*":
        return None
    groups = [item.strip() for item in match.group("groups").split(",")]
    if len(set(groups)) != len(groups):
        return None
    return {"metric": match.group("metric"), "groups": groups}


def _decimal(value: Any) -> Decimal | None:
    try:
        result = Decimal(str(value))
    except (InvalidOperation, ValueError):
        return None
    return result if result.is_finite() else None


def _json_number(value: Decimal) -> int | float:
    return int(value) if value == value.to_integral_value() else float(value)


def _source_name(record: dict[str, Any], fallback: str) -> str:
    value = record.get("name")
    if not isinstance(value, str):
        return fallback
    value = " ".join(value.split())
    if not value or any(ord(character) < 32 for character in value):
        return fallback
    return value[:255]


def _program_line(label: str, term: dict[str, Any]) -> str:
    rendered = ", ".join(_quoted(item) for item in term["groups"])
    by = f"[{rendered}]" if len(term["groups"]) > 1 else _quoted(term["groups"][0])
    return f"{label} = data({_quoted(term['metric'])}, rollup='sum').sum(by={by})"


def translate_slo_bundle(inventory: dict[str, Any], salt: str) -> dict[str, Any] | None:
    """Translate exactly one allowlisted metric SLO plus its standard burn-rate pair."""
    collections = inventory.get("inventory")
    if not isinstance(collections, dict):
        return None
    slos = collections.get("slos")
    monitors = collections.get("monitors")
    if not isinstance(slos, list) or len(slos) != 1 or not isinstance(monitors, list):
        return None
    source = slos[0]
    if not isinstance(source, dict) or source.get("source_type") != "slo" or source.get("slo_type") != "metric":
        return None
    source_id = source.get("source_id")
    if source_id is None or not str(source_id).strip():
        return None
    query = source.get("query")
    if not isinstance(query, dict) or set(query) != {"numerator", "denominator"}:
        return None
    numerator = NUMERATOR.fullmatch(str(query["numerator"]))
    denominator = DENOMINATOR.fullmatch(str(query["denominator"]))
    if not numerator or not denominator:
        return None
    if numerator.group("a") != denominator.group("a") or numerator.group("b") != denominator.group("b"):
        return None
    a = _term(numerator.group("a"))
    b = _term(numerator.group("b"))
    c = _term(denominator.group("c"))
    if a is None or b is None or c is None or not (a["groups"] == b["groups"] == c["groups"]):
        return None
    thresholds = source.get("thresholds")
    if not isinstance(thresholds, list) or len(thresholds) != 1 or not isinstance(thresholds[0], dict):
        return None
    threshold = thresholds[0]
    period = threshold.get("timeframe")
    objective = _decimal(threshold.get("target"))
    warning = _decimal(threshold.get("warning"))
    if period != "30d" or objective is None or warning is None:
        return None
    if not (Decimal(0) < objective < warning <= Decimal(100)) or -objective.as_tuple().exponent > 3:
        return None
    alert_profiles: dict[str, str] = {}
    alert_refs: dict[str, str] = {}
    for monitor in monitors:
        if not isinstance(monitor, dict) or str(monitor.get("monitor_type", "")).lower() != "slo alert":
            continue
        queries = monitor.get("queries")
        if not isinstance(queries, list) or len(queries) != 1 or not isinstance(queries[0], dict):
            return None
        match = BURN_RATE.fullmatch(str(queries[0].get("value", "")))
        monitor_id = monitor.get("source_id")
        if not match or monitor_id is None or match.group("slo") != str(source_id) or match.group("period") != period:
            return None
        value = _decimal(match.group("threshold"))
        windows = (match.group("long"), match.group("short"))
        profile = None
        if windows == ("1h", "5m") and value == Decimal("14.4"):
            profile = "fast"
        elif windows == ("6h", "30m") and value == Decimal("6"):
            profile = "slow"
        if profile is None or profile in alert_profiles:
            return None
        alert_profiles[profile] = str(value)
        alert_refs[profile] = pseudonym(f"monitor:{monitor_id}", salt)
    if set(alert_profiles) != {"fast", "slow"}:
        return None
    slo_ref = pseudonym(f"slo:{source_id}", salt)
    if not all(OBJECT_REF.fullmatch(item) for item in (slo_ref, *alert_refs.values())):
        return None
    marker = slo_ref[-16:]
    program = "\n".join([
        _program_line("A", a),
        _program_line("B", b),
        _program_line("C", c),
        "GOOD = A - B",
        "TOTAL = GOOD + C",
    ])
    payload = {
        "name": _source_name(source, f"Datadog SLO {marker}"),
        "description": (
            f"[AI-Created] Create-only Datadog metric SLO migration {marker}; "
            "source warning status is not represented."
        ),
        "type": "RequestBased",
        "inputs": {
            "programText": program,
            "goodEventsLabel": "GOOD",
            "totalEventsLabel": "TOTAL",
        },
        "targets": [{
            "type": "RollingWindow",
            "compliancePeriod": period,
            "slo": _json_number(objective),
            "sloAlertRules": [
                {
                    "type": "BREACH",
                    "rules": [{
                        "description": "Required Splunk breach rule; disabled for migration safety.",
                        "detectLabel": f"migration_breach_{marker}",
                        "disabled": True,
                        "notifications": [],
                        "parameters": {"fireLasting": "3m"},
                        "severity": "Warning",
                    }],
                },
                {
                    "type": "BURN_RATE",
                    "rules": [{
                        "description": "Migrated burn-rate pair; review before enabling.",
                        "detectLabel": f"migration_{marker}",
                        "disabled": True,
                        "notifications": [],
                        "parameters": {
                            "burnRateThreshold_1": 14.4,
                            "burnRateThreshold_2": 6,
                        },
                        "severity": "Warning",
                    }],
                },
            ],
        }],
    }
    return {
        "primary_ref": slo_ref,
        "source_refs": [slo_ref, alert_refs["fast"], alert_refs["slow"]],
        "payload": payload,
        "translation_method": "automatic_metric_slo_burn_rate_v3",
        "differences": [
            "source_warning_status_not_represented",
            "splunk_required_breach_rule_added_disabled",
        ],
    }


__all__ = ["translate_slo_bundle"]
