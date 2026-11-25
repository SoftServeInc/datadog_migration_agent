"""Narrow create-only Splunk Observability Cloud detector adapter."""

from __future__ import annotations

import json
import re
import time
from typing import Any, Callable, Protocol
from urllib import error, parse, request


class DetectorAdapter(Protocol):
    def get_organization_id(self) -> str: ...

    def find_detectors_by_tag(self, marker_tag: str) -> list[dict[str, Any]]: ...

    def create_detector(self, payload: dict[str, Any]) -> dict[str, Any]: ...

    def validate_detector_payload(self, payload: dict[str, Any]) -> None: ...

    def get_detector(self, target_id: str) -> dict[str, Any]: ...


class AdapterError(RuntimeError):
    def __init__(
        self,
        category: str,
        *,
        retriable: bool = False,
        create_definitively_rejected: bool = False,
    ):
        super().__init__(category)
        self.category = category
        self.retriable = retriable
        self.create_definitively_rejected = create_definitively_rejected


class _NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req: object, fp: object, code: int, msg: str, headers: object, newurl: str) -> None:
        return None


class SplunkDetectorClient:
    """Only GET detector and POST detector are exposed by this class."""

    def __init__(
        self,
        origin: str,
        token: str,
        *,
        timeout: int = 10,
        max_response_bytes: int = 1_000_000,
        get_retries: int = 2,
        opener: Any | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ):
        if not re.fullmatch(
            r"https://api\.[a-z]{2,4}[0-9]{1,2}\.observability\.splunkcloud\.com",
            origin,
        ):
            raise ValueError("Splunk detector origin is invalid")
        if not token or any(character.isspace() for character in token):
            raise ValueError("Splunk token is missing or malformed")
        if not 1 <= timeout <= 30 or not 1_024 <= max_response_bytes <= 2_000_000:
            raise ValueError("HTTP timeout or response limit is outside the safe range")
        if not 0 <= get_retries <= 3:
            raise ValueError("GET retry count is outside the safe range")
        self.origin = origin
        self.token = token
        self.timeout = timeout
        self.max_response_bytes = max_response_bytes
        self.get_retries = get_retries
        self.opener = opener or request.build_opener(_NoRedirect())
        self.sleep = sleep

    def _request(
        self,
        method: str,
        path: str,
        *,
        query: dict[str, Any] | None = None,
        payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        allowed = (
            method == "POST" and path in {"/v2/detector", "/v2/detector/validate"}
            or method == "GET" and (
                path == "/v2/organization" or path == "/v2/detector" or path.startswith("/v2/detector/")
            )
        )
        if not allowed:
            raise ValueError("unsupported Splunk detector operation")
        url = f"{self.origin}{path}"
        if query:
            url = f"{url}?{parse.urlencode(query, doseq=True)}"
        body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode("utf-8")
        attempts = self.get_retries + 1 if method == "GET" else 1
        for attempt in range(attempts):
            req = request.Request(
                url,
                data=body,
                method=method,
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                    "X-SF-TOKEN": self.token,
                    "User-Agent": "cisco-innovation-migration-executor/1.0",
                },
            )
            try:
                with self.opener.open(req, timeout=self.timeout) as response:
                    final_url = str(getattr(response, "url", url))
                    if not final_url.startswith(f"{self.origin}/"):
                        raise AdapterError("redirect_or_origin_change")
                    length = response.headers.get("Content-Length")
                    if length and int(length) > self.max_response_bytes:
                        raise AdapterError("response_too_large")
                    raw = response.read(self.max_response_bytes + 1)
                    if len(raw) > self.max_response_bytes:
                        raise AdapterError("response_too_large")
                    value = json.loads(raw.decode("utf-8")) if raw else {}
                    if not isinstance(value, dict):
                        raise AdapterError("invalid_json_shape")
                    return value
            except error.HTTPError as exc:
                retriable = exc.code == 429 or 500 <= exc.code <= 599
                if method == "GET" and retriable and attempt + 1 < attempts:
                    retry_after = exc.headers.get("Retry-After") if exc.headers else None
                    delay = min(2.0, float(retry_after)) if retry_after and retry_after.isdigit() else min(2.0, 0.25 * (2 ** attempt))
                    self.sleep(delay)
                    continue
                definitive_rejection = (
                    method == "POST"
                    and 400 <= exc.code <= 499
                    and exc.code not in {408, 409, 429}
                )
                raise AdapterError(
                    f"http_{exc.code}",
                    retriable=retriable,
                    create_definitively_rejected=definitive_rejection,
                ) from None
            except AdapterError:
                raise
            except (error.URLError, TimeoutError, OSError):
                if method == "GET" and attempt + 1 < attempts:
                    self.sleep(min(2.0, 0.25 * (2 ** attempt)))
                    continue
                raise AdapterError("network_error", retriable=True) from None
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
                raise AdapterError("invalid_response") from None
        raise AdapterError("retry_budget_exhausted")

    def find_detectors_by_tag(self, marker_tag: str) -> list[dict[str, Any]]:
        value = self._request("GET", "/v2/detector", query={"tags": marker_tag, "limit": 2})
        results = value.get("results")
        if not isinstance(results, list) or any(not isinstance(item, dict) for item in results):
            raise AdapterError("invalid_search_response")
        return results

    def get_organization_id(self) -> str:
        value = self._request("GET", "/v2/organization")
        organization_id = value.get("id")
        if (
            not isinstance(organization_id, str)
            or not organization_id
            or len(organization_id) > 256
            or any(character.isspace() or ord(character) < 32 for character in organization_id)
        ):
            raise AdapterError("invalid_organization_response")
        return organization_id

    def create_detector(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._request("POST", "/v2/detector", payload=payload)

    def validate_detector_payload(self, payload: dict[str, Any]) -> None:
        self._request("POST", "/v2/detector/validate", payload=payload)

    def get_detector(self, target_id: str) -> dict[str, Any]:
        if not target_id or len(target_id) > 256:
            raise ValueError("detector ID is invalid")
        return self._request("GET", f"/v2/detector/{parse.quote(target_id, safe='')}")


__all__ = ["AdapterError", "DetectorAdapter", "SplunkDetectorClient"]
