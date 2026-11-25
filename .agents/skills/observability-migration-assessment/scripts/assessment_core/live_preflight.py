"""Bounded live authentication and permission probes with sanitized results."""

from __future__ import annotations

import json
import re
from typing import Any, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, OpenerDirector, Request, build_opener

from .approval import validate_authorization
from .config import authorization_origins, select_splunk_o11y_credentials
from .security import resolve_datadog_api_base, validate_https_endpoint


MAX_PROBE_RESPONSE_BYTES = 512 * 1024
REALM = re.compile(r"^[a-z0-9][a-z0-9-]{1,15}$")


class NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


class LiveProbeClient:
    def __init__(self, timeout: int = 10, opener: OpenerDirector | Any | None = None):
        if not 1 <= timeout <= 60:
            raise ValueError("probe timeout must be between 1 and 60 seconds")
        self.timeout = timeout
        self.opener = opener or build_opener(NoRedirectHandler())
        self.requests_attempted = 0

    def get(self, url: str, headers: Mapping[str, str]) -> tuple[str, Any | None]:
        if self.requests_attempted >= 7:
            raise RuntimeError("live preflight request budget exceeded")
        self.requests_attempted += 1
        request = Request(url, headers=dict(headers), method="GET")
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                length = response.headers.get("Content-Length")
                if length:
                    try:
                        if int(length) > MAX_PROBE_RESPONSE_BYTES:
                            return "response_too_large", None
                    except ValueError:
                        return "invalid_response", None
                payload = response.read(MAX_PROBE_RESPONSE_BYTES + 1)
                if len(payload) > MAX_PROBE_RESPONSE_BYTES:
                    return "response_too_large", None
                if not payload:
                    return "available", None
                try:
                    return "available", json.loads(payload)
                except json.JSONDecodeError:
                    return "available", None
        except HTTPError as exc:
            if exc.code in (401, 403):
                return "denied", None
            if exc.code == 429:
                return "rate_limited", None
            return f"http_{exc.code}", None
        except (URLError, TimeoutError, OSError):
            return "unavailable", None


def _env(values: Mapping[str, str], *names: str) -> str:
    for name in names:
        value = values.get(name, "").strip()
        if value:
            return value
    return ""


def _provider_status(checks: dict[str, str], primary: str) -> str:
    status = checks.get(primary, "not_configured")
    if status != "available":
        return status
    if any(value == "denied" for value in checks.values()):
        return "partial"
    if any(value not in {"available", "not_applicable"} for value in checks.values()):
        return "partial"
    return "available"


def run_live_preflight(
    values: Mapping[str, str],
    authorization: dict[str, Any],
    timeout: int = 10,
    client: LiveProbeClient | None = None,
) -> dict[str, Any]:
    """Run at most seven GET probes and return statuses only."""
    validate_authorization(authorization, "LIVE_PREFLIGHT")
    current_origins = authorization_origins(values)
    target = str(authorization["target"])
    selected_targets = (
        {"splunk_observability_cloud", "splunk_platform"}
        if target == "both" else {target}
    )
    expected_origins = {"datadog": current_origins["datadog"]}
    expected_origins.update({key: value for key, value in current_origins.items() if key in selected_targets})
    if expected_origins != authorization.get("authorized_origins"):
        raise ValueError("configured API origins differ from the approved origins")
    probe = client or LiveProbeClient(timeout=timeout)
    providers: dict[str, Any] = {}

    api_key = _env(values, "DATADOG_API_KEY", "DD_API_KEY")
    app_key = _env(values, "DATADOG_APP_KEY", "DD_APP_KEY")
    if api_key and app_key:
        base = resolve_datadog_api_base(_env(values, "DATADOG_SITE", "DD_SITE") or "datadoghq.com")
        api_headers = {"Accept": "application/json", "DD-API-KEY": api_key}
        full_headers = {**api_headers, "DD-APPLICATION-KEY": app_key}
        api_status, api_payload = probe.get(base + "/api/v1/validate", api_headers)
        if api_status == "available" and isinstance(api_payload, dict) and api_payload.get("valid") is not True:
            api_status = "invalid"
        app_status, _ = probe.get(base + "/api/v2/validate_keys", full_headers)
        dashboard_status, _ = probe.get(base + "/api/v1/dashboard", full_headers)
        monitor_status, _ = probe.get(base + "/api/v1/monitor?" + urlencode({"page_size": 1}), full_headers)
        slo_status, _ = probe.get(base + "/api/v1/slo?" + urlencode({"limit": 1}), full_headers)
        datadog_checks = {
            "api_key": api_status,
            "application_key": app_status,
            "dashboards_read": dashboard_status,
            "monitors_read": monitor_status,
            "slos_read": slo_status,
        }
    else:
        datadog_checks = {"credentials": "not_configured"}
    providers["datadog"] = {
        "status": _provider_status(datadog_checks, "api_key" if api_key and app_key else "credentials"),
        "checks": datadog_checks,
    }

    o11y_token, realm = select_splunk_o11y_credentials(values)
    realm = realm.lower()
    if "splunk_observability_cloud" not in selected_targets:
        o11y_checks = {"selection": "not_selected"}
    elif o11y_token and realm:
        if not REALM.fullmatch(realm):
            raise ValueError("Splunk Observability Cloud realm has an invalid format")
        detector_url = f"https://api.{realm}.observability.splunkcloud.com/v2/detector?limit=1"
        detector_status, _ = probe.get(detector_url, {"Accept": "application/json", "X-SF-TOKEN": o11y_token})
        o11y_checks = {"detectors_read": detector_status}
    else:
        o11y_checks = {"credentials": "not_configured"}
    providers["splunk_observability_cloud"] = {
        "status": "not_selected" if "splunk_observability_cloud" not in selected_targets else _provider_status(
            o11y_checks, "detectors_read" if o11y_token and realm else "credentials"
        ),
        "checks": o11y_checks,
    }

    platform_url = _env(values, "SPLUNK_MCP_PLATFORM_URL")
    platform_token = _env(values, "SPLUNK_MCP_PLATFORM_TOKEN")
    if "splunk_platform" not in selected_targets:
        platform_checks = {"selection": "not_selected"}
    elif platform_url and platform_token:
        validated = validate_https_endpoint(platform_url, "SPLUNK_MCP_PLATFORM_URL")
        parts = urlsplit(validated)
        server_info = urlunsplit((parts.scheme, parts.netloc, "/services/server/info", "output_mode=json&count=0", ""))
        server_status, _ = probe.get(
            server_info,
            {"Accept": "application/json", "Authorization": f"Bearer {platform_token}"},
        )
        platform_checks = {"server_info_read": server_status}
    else:
        platform_checks = {"credentials": "not_configured"}
    providers["splunk_platform"] = {
        "status": "not_selected" if "splunk_platform" not in selected_targets else _provider_status(
            platform_checks, "server_info_read" if platform_url and platform_token else "credentials"
        ),
        "checks": platform_checks,
    }

    return {
        "schema_version": "1.0",
        "mode": "live_read_only",
        "approval": {
            "approval_id": authorization["approval_id"],
            "approval_hash": authorization["approval_hash"],
        },
        "providers": providers,
        "requests_attempted": probe.requests_attempted,
        "safety": {
            "request_method": "GET",
            "response_payloads_persisted": False,
            "credential_values_included": False,
            "redirects_followed": False,
            "mutations_performed": 0,
        },
    }
