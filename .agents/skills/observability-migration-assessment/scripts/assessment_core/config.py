"""Safe, non-executing environment parsing and provider preflight."""

from __future__ import annotations

import os
import re
import shlex
from pathlib import Path
from typing import Mapping
from urllib.parse import urlsplit, urlunsplit

from .security import resolve_datadog_api_base, validate_https_endpoint


KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def parse_dotenv(path: Path) -> dict[str, str]:
    """Parse KEY=VALUE syntax without shell evaluation or interpolation."""
    values: dict[str, str] = {}
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        if "=" not in line:
            raise ValueError(f"{path}:{number}: expected KEY=VALUE")
        key, source_value = line.split("=", 1)
        key = key.strip()
        if not KEY.fullmatch(key):
            raise ValueError(f"{path}:{number}: invalid environment key")
        if "$(" in source_value or "`" in source_value or "${" in source_value:
            raise ValueError(f"{path}:{number}: shell expansion is not supported")
        try:
            tokens = shlex.split(source_value, comments=True, posix=True)
        except ValueError as exc:
            raise ValueError(f"{path}:{number}: invalid quoted value") from exc
        if len(tokens) > 1:
            raise ValueError(f"{path}:{number}: quote values containing whitespace")
        values[key] = tokens[0] if tokens else ""
    return values


def merged_environment(env_file: Path | None, environ: Mapping[str, str] | None = None) -> dict[str, str]:
    values = parse_dotenv(env_file) if env_file else {}
    values.update(dict(os.environ if environ is None else environ))
    return values


def _present(values: Mapping[str, str], *keys: str) -> bool:
    return any(bool(values.get(key, "").strip()) for key in keys)


def select_splunk_o11y_credentials(values: Mapping[str, str]) -> tuple[str, str]:
    """Select one complete Splunk profile consistently across assessment and execution."""
    profiles = (
        ("SPLUNK_O11Y_INNOVATIONLAB_TOKEN", "SPLUNK_O11Y_INNOVATIONLAB_REALM"),
        ("SPLUNK_O11Y_ACCESS_TOKEN", "SPLUNK_O11Y_REALM"),
    )
    for token_key, realm_key in profiles:
        token = values.get(token_key, "").strip()
        realm = values.get(realm_key, "").strip()
        if token and realm:
            return token, realm
    return "", ""


def provider_preflight(values: Mapping[str, str]) -> dict[str, object]:
    """Report credential presence and safe endpoints, never credential values."""
    datadog_site = values.get("DATADOG_SITE") or values.get("DD_SITE") or "datadoghq.com"
    datadog_base = resolve_datadog_api_base(datadog_site)

    o11y_token, o11y_realm = select_splunk_o11y_credentials(values)
    gateway = values.get("SPLUNK_MCP_GATEWAY_URL", "").strip()
    if gateway:
        gateway = validate_https_endpoint(gateway, "SPLUNK_MCP_GATEWAY_URL")

    platform_url = values.get("SPLUNK_MCP_PLATFORM_URL", "").strip()
    if platform_url:
        platform_url = validate_https_endpoint(platform_url, "SPLUNK_MCP_PLATFORM_URL")
    hec_endpoint = values.get("SPLUNK_HEC_ENDPOINT", "").strip()
    if hec_endpoint:
        hec_endpoint = validate_https_endpoint(hec_endpoint, "SPLUNK_HEC_ENDPOINT")

    return {
        "schema_version": "1.0",
        "mode": "read_only",
        "providers": {
            "datadog": {
                "source_read_configured": _present(values, "DATADOG_API_KEY", "DD_API_KEY")
                and _present(values, "DATADOG_APP_KEY", "DD_APP_KEY"),
                "api_base": datadog_base,
            },
            "splunk_observability_cloud": {
                "target_read_configured": bool(o11y_token and o11y_realm),
                "realm_configured": bool(o11y_realm),
                "gateway_configured": bool(gateway),
                "target_mutations_enabled": False,
            },
            "splunk_platform": {
                "target_read_configured": bool(platform_url and _present(values, "SPLUNK_MCP_PLATFORM_TOKEN")),
                "delivery_credentials_configured": bool(hec_endpoint and _present(values, "SPLUNK_HEC_TOKEN")),
                "target_mutations_enabled": False,
            },
        },
        "safety": {
            "credential_values_included": False,
            "dotenv_executed_as_shell": False,
            "network_calls_performed": False,
        },
    }


def authorization_origins(values: Mapping[str, str]) -> dict[str, str]:
    """Resolve the exact credential-bearing origins that an approval will bind."""
    origins = {
        "datadog": resolve_datadog_api_base(
            values.get("DATADOG_SITE") or values.get("DD_SITE") or "datadoghq.com"
        )
    }
    _, realm = select_splunk_o11y_credentials(values)
    realm = realm.lower()
    if realm:
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,15}", realm):
            raise ValueError("Splunk Observability Cloud realm has an invalid format")
        origins["splunk_observability_cloud"] = f"https://api.{realm}.observability.splunkcloud.com"
    platform_url = values.get("SPLUNK_MCP_PLATFORM_URL", "").strip()
    if platform_url:
        validated = validate_https_endpoint(platform_url, "SPLUNK_MCP_PLATFORM_URL")
        parts = urlsplit(validated)
        origins["splunk_platform"] = urlunsplit((parts.scheme, parts.netloc, "", "", ""))
    return origins
