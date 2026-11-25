"""Conservative target capability catalog derived from configuration and probes."""

from __future__ import annotations

from typing import Any

from .security import assert_codex_safe


OBJECT_TYPES = ("dashboard", "monitor", "slo", "synthetic", "log_index", "log_pipeline")
PROVIDERS = ("splunk_observability_cloud", "splunk_platform")


def validate_capability_catalog(catalog: dict[str, Any]) -> None:
    if set(catalog) != {"schema_version", "mode", "providers", "safety"}:
        raise ValueError("capability catalog fields are invalid")
    if catalog.get("schema_version") != "1.0" or catalog.get("mode") != "assessment_only":
        raise ValueError("capability catalog version or mode is invalid")
    safety = catalog.get("safety")
    if safety != {"target_mutations_enabled": False, "capabilities_inferred_as_equivalent": False}:
        raise ValueError("capability catalog safety invariants are invalid")
    providers = catalog.get("providers")
    if not isinstance(providers, dict) or set(providers) != set(PROVIDERS):
        raise ValueError("capability catalog providers are invalid")
    for provider_name in PROVIDERS:
        provider = providers[provider_name]
        if not isinstance(provider, dict) or set(provider) != {
            "configured", "live_probe_status", "read_probe", "write_operations_available",
            "object_assessment",
        }:
            raise ValueError("capability provider fields are invalid")
        if not isinstance(provider["configured"], bool) or provider["write_operations_available"] is not False:
            raise ValueError("capability provider flags are invalid")
        status = provider["live_probe_status"]
        if not isinstance(status, str) or not status or len(status) > 64 or not all(
            value.islower() or value.isdigit() or value == "_" for value in status
        ):
            raise ValueError("capability provider live status is invalid")
        expected_probe = "detector_list" if provider_name == "splunk_observability_cloud" else "server_info"
        if provider["read_probe"] != expected_probe:
            raise ValueError("capability provider read probe is invalid")
        assessments = provider["object_assessment"]
        if not isinstance(assessments, list) or len(assessments) != len(OBJECT_TYPES):
            raise ValueError("capability object assessment is invalid")
        if {item.get("source_type") for item in assessments if isinstance(item, dict)} != set(OBJECT_TYPES):
            raise ValueError("capability object types are invalid")
        for item in assessments:
            if not isinstance(item, dict) or set(item) != {
                "source_type", "status", "semantic_equivalence_claimed"
            }:
                raise ValueError("capability object assessment fields are invalid")
            if item["status"] not in {"ASSESSMENT_REQUIRED", "BLOCKED_BY_PERMISSIONS"}:
                raise ValueError("capability object assessment status is invalid")
            if item["semantic_equivalence_claimed"] is not False:
                raise ValueError("capability catalog must not claim semantic equivalence")
    assert_codex_safe(catalog)


def build_capability_catalog(preflight: dict[str, Any], live: dict[str, Any] | None = None) -> dict[str, Any]:
    providers = preflight.get("providers", {})
    live_providers = (live or {}).get("providers", {})
    catalog: dict[str, Any] = {
        "schema_version": "1.0",
        "mode": "assessment_only",
        "providers": {},
        "safety": {"target_mutations_enabled": False, "capabilities_inferred_as_equivalent": False},
    }
    for provider_name in PROVIDERS:
        configured = bool(providers.get(provider_name, {}).get("target_read_configured"))
        live_status = str(live_providers.get(provider_name, {}).get("status", "not_run"))
        catalog["providers"][provider_name] = {
            "configured": configured,
            "live_probe_status": live_status,
            "read_probe": "detector_list" if provider_name == "splunk_observability_cloud" else "server_info",
            "write_operations_available": False,
            "object_assessment": [
                {
                    "source_type": source_type,
                    "status": "ASSESSMENT_REQUIRED" if configured else "BLOCKED_BY_PERMISSIONS",
                    "semantic_equivalence_claimed": False,
                }
                for source_type in OBJECT_TYPES
            ],
        }
    validate_capability_catalog(catalog)
    return catalog
