"""Narrow Splunk Observability Cloud SLO adapter."""

from __future__ import annotations

import json
import re
import time
from typing import Any, Callable, Protocol
from urllib import error, parse, request


class SloAdapter(Protocol):
    def get_organization_id(self) -> str: ...
    def search_slos(self, exact_name: str) -> list[dict[str, Any]]: ...
    def validate_slo_payload(self, payload: dict[str, Any]) -> None: ...
    def create_slo(self, payload: dict[str, Any]) -> dict[str, Any]: ...
    def get_slo(self, target_id: str) -> dict[str, Any]: ...


class SloAdapterError(RuntimeError):
    def __init__(
        self, category: str, *, retriable: bool = False,
        create_definitively_rejected: bool = False,
    ):
        super().__init__(category)
        self.category = category
        self.retriable = retriable
        self.create_definitively_rejected = create_definitively_rejected


class _NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req: object, fp: object, code: int, msg: str, headers: object, newurl: str) -> None:
        return None


class SplunkSloClient:
    def __init__(
        self, origin: str, token: str, *, timeout: int = 10,
        max_response_bytes: int = 1_000_000, read_retries: int = 2,
        opener: Any | None = None, sleep: Callable[[float], None] = time.sleep,
    ):
        if not re.fullmatch(
            r"https://api\.[a-z]{2,4}[0-9]{1,2}\.observability\.splunkcloud\.com", origin,
        ):
            raise ValueError("Splunk SLO origin is invalid")
        if not token or any(character.isspace() for character in token):
            raise ValueError("Splunk token is missing or malformed")
        if not 1 <= timeout <= 30 or not 1_024 <= max_response_bytes <= 2_000_000:
            raise ValueError("SLO HTTP bounds are invalid")
        if not 0 <= read_retries <= 3:
            raise ValueError("SLO read retry count is invalid")
        self.origin = origin
        self.token = token
        self.timeout = timeout
        self.max_response_bytes = max_response_bytes
        self.read_retries = read_retries
        self.opener = opener or request.build_opener(_NoRedirect())
        self.sleep = sleep

    def _request(
        self, method: str, path: str, *, payload: dict[str, Any] | None = None,
        query: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        read_operation = method == "GET" or method == "POST" and path == "/v2/slo/search"
        allowed = (
            method == "POST" and path in {"/v2/slo", "/v2/slo/validate", "/v2/slo/search"}
            or method == "GET" and (path == "/v2/organization" or path.startswith("/v2/slo/"))
        )
        if not allowed:
            raise ValueError("unsupported Splunk SLO operation")
        url = f"{self.origin}{path}"
        if query:
            url += "?" + parse.urlencode(query, doseq=True)
        body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
        attempts = self.read_retries + 1 if read_operation else 1
        for attempt in range(attempts):
            req = request.Request(
                url, data=body, method=method,
                headers={
                    "Accept": "application/json", "Content-Type": "application/json",
                    "X-SF-TOKEN": self.token,
                    "User-Agent": "cisco-innovation-slo-executor/1.0",
                },
            )
            try:
                with self.opener.open(req, timeout=self.timeout) as response:
                    final_url = str(getattr(response, "url", url))
                    if not final_url.startswith(f"{self.origin}/"):
                        raise SloAdapterError("redirect_or_origin_change")
                    length = response.headers.get("Content-Length")
                    if length and int(length) > self.max_response_bytes:
                        raise SloAdapterError("response_too_large")
                    raw = response.read(self.max_response_bytes + 1)
                    if len(raw) > self.max_response_bytes:
                        raise SloAdapterError("response_too_large")
                    value = json.loads(raw.decode()) if raw else {}
                    if not isinstance(value, dict):
                        raise SloAdapterError("invalid_json_shape")
                    return value
            except error.HTTPError as exc:
                retriable = exc.code == 429 or 500 <= exc.code <= 599
                if read_operation and retriable and attempt + 1 < attempts:
                    self.sleep(min(2.0, 0.25 * (2 ** attempt)))
                    continue
                definitive = path == "/v2/slo" and 400 <= exc.code <= 499 and exc.code not in {408, 409, 429}
                raise SloAdapterError(
                    f"http_{exc.code}", retriable=retriable,
                    create_definitively_rejected=definitive,
                ) from None
            except SloAdapterError:
                raise
            except (error.URLError, TimeoutError, OSError):
                if read_operation and attempt + 1 < attempts:
                    self.sleep(min(2.0, 0.25 * (2 ** attempt)))
                    continue
                raise SloAdapterError("network_error", retriable=True) from None
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
                raise SloAdapterError("invalid_response") from None
        raise SloAdapterError("retry_budget_exhausted")

    def get_organization_id(self) -> str:
        value = self._request("GET", "/v2/organization")
        organization_id = value.get("id")
        if (
            not isinstance(organization_id, str) or not organization_id or len(organization_id) > 256
            or any(character.isspace() or ord(character) < 32 for character in organization_id)
        ):
            raise SloAdapterError("invalid_organization_response")
        return organization_id

    def search_slos(self, exact_name: str) -> list[dict[str, Any]]:
        if not exact_name or len(exact_name) > 255:
            raise ValueError("SLO search name is invalid")
        value = self._request(
            "POST", "/v2/slo/search", payload={"name": exact_name}, query={"limit": 100},
        )
        results = value.get("results")
        count = value.get("count")
        if (
            not isinstance(results, list) or any(not isinstance(item, dict) for item in results)
            or not isinstance(count, int) or isinstance(count, bool) or count < len(results)
            or count > len(results)
        ):
            raise SloAdapterError("incomplete_or_invalid_search_response")
        return [item for item in results if item.get("name") == exact_name]

    def validate_slo_payload(self, payload: dict[str, Any]) -> None:
        self._request("POST", "/v2/slo/validate", payload=payload)

    def create_slo(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._request("POST", "/v2/slo", payload=payload)

    def get_slo(self, target_id: str) -> dict[str, Any]:
        if not target_id or len(target_id) > 256:
            raise ValueError("SLO ID is invalid")
        return self._request("GET", f"/v2/slo/{parse.quote(target_id, safe='')}")


__all__ = ["SloAdapter", "SloAdapterError", "SplunkSloClient"]
