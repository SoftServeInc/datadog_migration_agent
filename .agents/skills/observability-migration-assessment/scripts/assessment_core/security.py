"""Security primitives for local-only collection and Codex-safe projections."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit


DATADOG_API_HOSTS = {
    "datadoghq.com": "api.datadoghq.com",
    "us1": "api.datadoghq.com",
    "datadoghq.eu": "api.datadoghq.eu",
    "eu": "api.datadoghq.eu",
    "us3.datadoghq.com": "api.us3.datadoghq.com",
    "us3": "api.us3.datadoghq.com",
    "us5.datadoghq.com": "api.us5.datadoghq.com",
    "us5": "api.us5.datadoghq.com",
    "ap1.datadoghq.com": "api.ap1.datadoghq.com",
    "ap1": "api.ap1.datadoghq.com",
    "ap2.datadoghq.com": "api.ap2.datadoghq.com",
    "ap2": "api.ap2.datadoghq.com",
    "uk1.datadoghq.com": "api.uk1.datadoghq.com",
    "uk1": "api.uk1.datadoghq.com",
    "ddog-gov.com": "api.ddog-gov.com",
    "us1-fed": "api.ddog-gov.com",
    "us2.ddog-gov.com": "api.us2.ddog-gov.com",
    "us2-fed": "api.us2.ddog-gov.com",
}
SECRET_KEY = re.compile(
    r"(?:api.?key|app.?key|token|password|passwd|secret|credential|authorization|cookie)", re.I
)
EMAIL = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.I)
BEARER = re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]+", re.I)
TOKENISH = re.compile(r"\b(?:sk|dd|xox[baprs]|gh[opsu])[-_][A-Za-z0-9_-]{12,}\b", re.I)
FORBIDDEN_PROJECTION_KEYS = {
    "name", "title", "query", "queries", "formula", "filter", "tags",
    "source_id", "message", "url", "endpoint", "author_handle",
}
OBJECT_TYPES = {"dashboard", "monitor", "slo", "synthetic", "log_index", "log_pipeline"}
ACCESS_AREAS = {
    "dashboards", "monitors", "slos", "synthetics", "log_indexes", "log_pipelines",
    "hosts", "integration_aws", "integration_azure", "integration_gcp",
    "estimated_cost", "projected_cost", "historical_cost", "usage_summary", "dashboard_detail",
}
COUNT_KEYS = {
    "dashboards", "monitors", "slos", "synthetics", "log_indexes", "log_pipelines",
    "ownerless_objects", "duplicate_candidate_groups",
}


def resolve_datadog_api_base(site: str) -> str:
    """Return an allowlisted Datadog API base; never derive a host from input."""
    normalized = (site or "datadoghq.com").strip().lower()
    if normalized.startswith("https://"):
        parts = urlsplit(normalized)
        if parts.path not in ("", "/") or parts.query or parts.fragment or parts.username:
            raise ValueError("DATADOG_SITE must contain only an approved Datadog hostname")
        normalized = parts.hostname or ""
        if normalized.startswith("api."):
            normalized = normalized[4:]
    host = DATADOG_API_HOSTS.get(normalized)
    if not host:
        allowed = ", ".join(sorted(k for k in DATADOG_API_HOSTS if "." in k))
        raise ValueError(f"unsupported DATADOG_SITE; allowed sites: {allowed}")
    return f"https://{host}"


def validate_https_endpoint(value: str, label: str) -> str:
    """Validate a configured customer endpoint without contacting it."""
    candidate = value.strip()
    if any(character.isspace() or ord(character) < 32 for character in candidate):
        raise ValueError(f"{label} contains invalid whitespace or control characters")
    parts = urlsplit(candidate)
    if parts.scheme != "https" or not parts.hostname:
        raise ValueError(f"{label} must be an absolute https URL")
    if parts.username or parts.password or parts.fragment:
        raise ValueError(f"{label} must not contain credentials or a fragment")
    try:
        parts.port
    except ValueError as exc:
        raise ValueError(f"{label} contains an invalid port") from exc
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", parts.query, ""))


def redact(value: Any) -> Any:
    """Recursively redact common credentials and direct contact identifiers."""
    if isinstance(value, dict):
        return {
            str(key): "[redacted]" if SECRET_KEY.search(str(key)) else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, tuple):
        return [redact(item) for item in value]
    if isinstance(value, str):
        text = EMAIL.sub("[redacted-email]", value)
        text = BEARER.sub("Bearer [redacted]", text)
        return TOKENISH.sub("[redacted-token]", text)
    return value


def safe_error(exc: BaseException) -> str:
    """Return a bounded error class, never a response body or credential."""
    code = getattr(exc, "code", None)
    if isinstance(code, int):
        return f"http_{code}"
    reason = getattr(exc, "reason", None)
    if reason is not None:
        return "network_error"
    if isinstance(exc, (TimeoutError, OSError)):
        return "io_error"
    return type(exc).__name__.lower()


def pseudonym(value: Any, salt: str, prefix: str = "obj") -> str:
    digest = hmac.new(salt.encode("utf-8"), str(value).encode("utf-8"), hashlib.sha256).hexdigest()[:16]
    return f"{prefix}_{digest}"


def _safe_status(value: Any) -> str:
    normalized = str(value or "unknown").strip().lower()
    return normalized if normalized in {
        "active", "enabled", "disabled", "muted", "archived", "unknown", "ok", "alert", "warn"
    } else "other"


def _nonnegative_int(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


def _safe_counts(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    result = {key: _nonnegative_int(value.get(key)) for key in sorted(COUNT_KEYS) if key in value}
    complexity = value.get("complexity")
    if isinstance(complexity, dict):
        result["complexity"] = {
            key: _nonnegative_int(complexity.get(key))
            for key in ("low", "medium", "high", "unknown") if key in complexity
        }
    return result


def _safe_error_category(value: Any) -> str:
    category = str(value or "unavailable").lower()
    if re.fullmatch(r"http_[1-5][0-9]{2}", category):
        return category
    return category if category in {
        "unavailable", "network_error", "io_error", "timeout", "runtimeerror",
        "jsondecodeerror", "response_too_large",
    } else "unavailable"


def codex_projection(inventory: dict[str, Any], salt: str) -> dict[str, Any]:
    """Create a strict allowlisted projection; raw names, IDs and queries stay local."""
    objects: list[dict[str, Any]] = []
    raw_inventory = inventory.get("inventory", {})
    if isinstance(raw_inventory, dict):
        for collection, records in sorted(raw_inventory.items()):
            if not isinstance(records, list):
                continue
            for index, record in enumerate(records):
                if not isinstance(record, dict):
                    continue
                candidate_type = str(record.get("source_type") or collection.rstrip("s")).lower()
                source_type = candidate_type if candidate_type in OBJECT_TYPES else "unknown"
                source_id = record.get("source_id", f"{collection}:{index}")
                item = {
                    "object_ref": pseudonym(f"{source_type}:{source_id}", salt),
                    "source_type": source_type,
                    "status": _safe_status(record.get("status")),
                    "complexity": str(record.get("complexity"))
                    if str(record.get("complexity")) in {"low", "medium", "high"} else "unknown",
                    "owner_present": bool(record.get("owner_tags")),
                    "query_count": len(record.get("queries", [])) if isinstance(record.get("queries"), list) else 0,
                    "widget_count": _nonnegative_int(record.get("widget_count")),
                    "processor_count": _nonnegative_int(record.get("processor_count")),
                    "notification_types": sorted(
                        str(item) for item in record.get("notification_types", [])
                        if str(item) in {"email", "slack", "pagerduty", "opsgenie", "webhook", "teams", "jira", "case", "other"}
                    ),
                }
                objects.append(item)
    projection = {
        "schema_version": "1.0",
        "projection": "codex_allowlisted",
        "generated_at": str(inventory.get("generated_at"))[:40]
        if re.fullmatch(r"[0-9T:+.Z-]{10,40}", str(inventory.get("generated_at", ""))) else None,
        "source": {
            "platform": "Datadog"
            if str((inventory.get("source") or {}).get("platform", "")).lower() == "datadog" else "unknown"
        },
        "counts": _safe_counts(inventory.get("counts", {})),
        "access": {
            str(key): str(value) if str(value) in {"available", "denied", "unavailable"} else "unknown"
            for key, value in (inventory.get("access", {}) or {}).items()
            if str(key) in ACCESS_AREAS
        },
        "objects": objects,
        "limitations": [
            {
                "source": str(item.get("source")) if str(item.get("source")) in ACCESS_AREAS else "unknown",
                "category": _safe_error_category(item.get("error")),
            }
            for item in inventory.get("errors", []) if isinstance(item, dict)
        ],
        "safety": {
            "raw_payloads_included": False,
            "direct_identifiers_included": False,
            "queries_included": False,
            "target_mutations_enabled": False,
        },
    }
    assert_codex_safe(projection)
    return projection


def assert_codex_safe(value: Any, path: str = "$") -> None:
    """Fail closed if a projection contains forbidden fields or secret patterns."""
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).lower() in FORBIDDEN_PROJECTION_KEYS:
                raise ValueError(f"forbidden Codex projection field at {path}.{key}")
            assert_codex_safe(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            assert_codex_safe(item, f"{path}[{index}]")
    elif isinstance(value, str):
        if EMAIL.search(value) or BEARER.search(value) or TOKENISH.search(value):
            raise ValueError(f"sensitive value detected at {path}")


def canonical_document_hash(value: dict[str, Any], hash_field: str) -> str:
    """Hash a JSON document without trusting its embedded hash field."""
    unsigned = {key: item for key, item in value.items() if key != hash_field}
    payload = json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def ensure_private_directory(path: Path) -> Path:
    """Create a local artifact directory and reject symlink destinations."""
    path = path.expanduser()
    if path.is_symlink():
        raise ValueError(f"refusing symlink output directory: {path}")
    path = path.resolve(strict=False)
    existed = path.exists()
    if existed and not path.is_dir():
        raise ValueError(f"output directory path is not a directory: {path}")
    if existed and path.stat().st_mode & 0o077:
        raise ValueError(f"output directory must not be group/world-accessible: {path}")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not existed:
        os.chmod(path, 0o700)
    return path


def atomic_write(path: Path, content: str) -> None:
    if path.is_symlink():
        raise ValueError(f"refusing symlink output file: {path}")
    parent = ensure_private_directory(path.parent)
    path = parent / path.name
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=parent, text=True)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def atomic_write_json(path: Path, value: Any) -> None:
    atomic_write(path, json.dumps(value, indent=2, sort_keys=True) + "\n")
