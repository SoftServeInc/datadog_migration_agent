"""Dependency-aware, resumable scheduler for registered migration adapters."""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Protocol

from .approval import validate_apply_approval
from .bundle import topological_layers, validate_bundle
from .common import runtime_lock
from .state import UnifiedStore


class AdapterExecutionError(RuntimeError):
    def __init__(self, category: str, *, safe_to_retry: bool = False):
        super().__init__(category)
        self.category = category
        self.safe_to_retry = safe_to_retry


class AdapterPreflightDefer(RuntimeError):
    """Signal that one operation must be deferred without blocking unrelated work."""

    def __init__(self, category: str):
        super().__init__(category)
        self.category = category


class OperationAdapter(Protocol):
    def apply(self, operation: dict[str, Any], context: dict[str, Any]) -> list[dict[str, Any]]: ...
    def validate(self, operation: dict[str, Any], resources: list[dict[str, Any]], context: dict[str, Any]) -> list[dict[str, Any]]: ...
    def rollback(self, entry: dict[str, Any], before_state: dict[str, Any] | None, context: dict[str, Any]) -> None: ...


class AdapterRegistry:
    def __init__(self) -> None:
        self._adapters: dict[str, OperationAdapter] = {}

    def register(self, name: str, adapter: OperationAdapter) -> None:
        if name in self._adapters:
            raise ValueError(f"migration adapter is already registered: {name}")
        self._adapters[name] = adapter

    def get(self, name: str) -> OperationAdapter:
        try:
            return self._adapters[name]
        except KeyError:
            raise ValueError(f"migration adapter is not registered: {name}") from None


class RateLimiter:
    def __init__(self, minimum_interval_seconds: float):
        self.interval = max(0.0, minimum_interval_seconds)
        self._lock = threading.Lock()
        self._last = 0.0

    def wait(self) -> None:
        with self._lock:
            remaining = self.interval - (time.monotonic() - self._last)
            if remaining > 0:
                time.sleep(remaining)
            self._last = time.monotonic()


@dataclass(frozen=True)
class SchedulerPolicy:
    max_workers: int = 4
    max_attempts: int = 3
    retry_delay_seconds: float = 0.25
    minimum_interval_seconds: float = 0.05

    def validate(self) -> None:
        if not 1 <= self.max_workers <= 16 or not 1 <= self.max_attempts <= 5:
            raise ValueError("scheduler worker or retry limit is invalid")
        if not 0 <= self.retry_delay_seconds <= 30 or not 0 <= self.minimum_interval_seconds <= 10:
            raise ValueError("scheduler timing policy is invalid")


class MigrationScheduler:
    def __init__(
        self, work_root: Path, registry: AdapterRegistry,
        policy: SchedulerPolicy | None = None,
        cancel_requested: Callable[[], bool] | None = None,
    ) -> None:
        self.work_root = work_root
        self.registry = registry
        self.policy = policy or SchedulerPolicy()
        self.policy.validate()
        self.cancel_requested = cancel_requested or (lambda: False)
        self.rate_limiter = RateLimiter(self.policy.minimum_interval_seconds)
        self._adapter_locks: dict[str, threading.Lock] = {}

    def _context(self, bundle: dict[str, Any], checkpoint: dict[str, Any]) -> dict[str, Any]:
        return {
            "session_id": bundle["session_id"], "plan_hash": bundle["plan_hash"],
            "bundle_hash": bundle["bundle_hash"], "target_binding": bundle["target_binding"],
            "operation_results": {
                key: value["resources"] for key, value in checkpoint["operations"].items()
            },
        }

    def _invoke(self, adapter_name: str, function: Callable[[], Any]) -> Any:
        lock = self._adapter_locks.setdefault(adapter_name, threading.Lock())
        last_error: Exception | None = None
        for attempt in range(1, self.policy.max_attempts + 1):
            if self.cancel_requested():
                raise AdapterExecutionError("cancelled")
            self.rate_limiter.wait()
            try:
                with lock:
                    return function()
            except Exception as exc:
                last_error = exc
                safe = bool(getattr(exc, "safe_to_retry", False))
                if not safe or attempt == self.policy.max_attempts:
                    raise
                time.sleep(self.policy.retry_delay_seconds * attempt)
        raise last_error or RuntimeError("adapter invocation failed")

    @staticmethod
    def _failure_category(exc: Exception) -> str:
        return str(getattr(exc, "category", type(exc).__name__.lower()))[:128]

    def run(
        self, bundle: dict[str, Any], approval: dict[str, Any], runtime_target: dict[str, str],
    ) -> dict[str, Any]:
        validate_bundle(bundle)
        validate_apply_approval(approval, bundle, runtime_target)
        store = UnifiedStore(self.work_root, bundle["session_id"])
        operations = {item["operation_id"]: item for item in bundle["operations"]}
        with runtime_lock(store.directory):
            checkpoint = store.create(bundle, approval)
            if checkpoint["status"] == "ROLLED_BACK":
                raise ValueError("rolled-back bundle cannot be executed again; compile a new bundle")
            for state in checkpoint["operations"].values():
                if state["status"] in {"FAILED", "BLOCKED", "APPLYING", "VALIDATING"}:
                    state["status"] = "APPLIED" if state["resources"] else "PENDING"
                    state["failure_category"] = None
            checkpoint["status"] = "APPLYING"
            store.save_checkpoint(checkpoint)

            for layer in topological_layers(bundle):
                if self.cancel_requested():
                    break
                ready: list[str] = []
                for operation_id in layer:
                    state = checkpoint["operations"][operation_id]
                    if state["status"] in {"APPLIED", "COMPLETED", "SKIPPED"}:
                        continue
                    dependency_states = [checkpoint["operations"][item]["status"] for item in operations[operation_id]["dependencies"]]
                    if any(item in {"FAILED", "BLOCKED", "SKIPPED"} for item in dependency_states):
                        state["status"] = "BLOCKED"
                        state["failure_category"] = "dependency_not_completed"
                    elif all(item in {"APPLIED", "COMPLETED"} for item in dependency_states):
                        ready.append(operation_id)
                store.save_checkpoint(checkpoint)
                with ThreadPoolExecutor(max_workers=min(self.policy.max_workers, max(1, len(ready)))) as pool:
                    futures = {}
                    for operation_id in ready:
                        operation = operations[operation_id]
                        state = checkpoint["operations"][operation_id]
                        state["status"] = "APPLYING"
                        state["attempts"] += 1
                        try:
                            adapter = self.registry.get(operation["adapter"])
                            context = self._context(bundle, checkpoint)
                            futures[pool.submit(
                                self._invoke, operation["adapter"],
                                lambda adapter=adapter, operation=operation, context=context: adapter.apply(operation, context),
                            )] = operation_id
                        except Exception as exc:
                            state["status"] = "FAILED"
                            state["failure_category"] = self._failure_category(exc)
                    store.save_checkpoint(checkpoint)
                    for future in as_completed(futures):
                        operation_id = futures[future]
                        state = checkpoint["operations"][operation_id]
                        try:
                            resources = future.result()
                            if not isinstance(resources, list):
                                raise ValueError("adapter apply result must be a resource list")
                            store.record_resources(checkpoint, operations[operation_id], resources)
                            state["status"] = "APPLIED"
                            state["failure_category"] = None
                        except Exception as exc:
                            state["status"] = "FAILED"
                            state["failure_category"] = self._failure_category(exc)
                        store.save_checkpoint(checkpoint)

            checkpoint["status"] = "VALIDATING"
            store.save_checkpoint(checkpoint)
            for layer in topological_layers(bundle):
                for operation_id in layer:
                    state = checkpoint["operations"][operation_id]
                    if state["status"] != "APPLIED":
                        continue
                    operation = operations[operation_id]
                    state["status"] = "VALIDATING"
                    store.save_checkpoint(checkpoint)
                    try:
                        adapter = self.registry.get(operation["adapter"])
                        context = self._context(bundle, checkpoint)
                        evidence = self._invoke(
                            operation["adapter"],
                            lambda: adapter.validate(operation, state["resources"], context),
                        )
                        if not isinstance(evidence, list) or any(not isinstance(item, dict) for item in evidence):
                            raise ValueError("adapter validation evidence must be a list of objects")
                        state["validation"] = evidence
                        state["status"] = "COMPLETED"
                        state["failure_category"] = None
                    except Exception as exc:
                        state["status"] = "FAILED"
                        state["failure_category"] = self._failure_category(exc)
                    store.save_checkpoint(checkpoint)

            states = [value["status"] for value in checkpoint["operations"].values()]
            completed = sum(value == "COMPLETED" for value in states)
            incomplete = sum(value in {"FAILED", "BLOCKED", "SKIPPED", "PENDING", "APPLIED", "VALIDATING"} for value in states)
            failed = sum(value == "FAILED" for value in states)
            if incomplete == 0:
                checkpoint["status"] = "COMPLETED"
            elif completed or failed == 0:
                checkpoint["status"] = "PARTIAL"
            else:
                checkpoint["status"] = "FAILED"
            store.save_checkpoint(checkpoint)
            return checkpoint

    def rollback(
        self, bundle: dict[str, Any], runtime_target: dict[str, str], *, confirmed: bool,
    ) -> dict[str, Any]:
        validate_bundle(bundle)
        if not confirmed or runtime_target != bundle["target_binding"]:
            raise ValueError("explicit rollback confirmation and exact target binding are required")
        store = UnifiedStore(self.work_root, bundle["session_id"])
        operations = {item["operation_id"]: item for item in bundle["operations"]}
        with runtime_lock(store.directory):
            checkpoint = store.load_checkpoint()
            ledger = store.load_ledger()
            checkpoint["status"] = "ROLLING_BACK"
            store.save_checkpoint(checkpoint)
            entries_by_operation: dict[str, list[dict[str, Any]]] = {}
            for entry in ledger["entries"]:
                entries_by_operation.setdefault(entry["operation_id"], []).append(entry)
            failures = 0
            for layer in reversed(topological_layers(bundle)):
                for operation_id in reversed(layer):
                    state = checkpoint["operations"][operation_id]
                    if state["status"] == "ROLLED_BACK":
                        continue
                    entries = entries_by_operation.get(operation_id, [])
                    if not entries:
                        continue
                    state["status"] = "ROLLING_BACK"
                    store.save_checkpoint(checkpoint)
                    adapter = self.registry.get(operations[operation_id]["adapter"])
                    context = self._context(bundle, checkpoint)
                    try:
                        for entry in reversed(entries):
                            if entry["disposition"] in {"CREATED", "UPDATED"}:
                                adapter.rollback(entry, store.read_before_state(entry), context)
                        state["status"] = "ROLLED_BACK"
                        state["failure_category"] = None
                    except Exception as exc:
                        failures += 1
                        state["status"] = "FAILED"
                        state["failure_category"] = self._failure_category(exc)
                    store.save_checkpoint(checkpoint)
            checkpoint["status"] = "ROLLED_BACK" if failures == 0 else "PARTIAL"
            store.save_checkpoint(checkpoint)
            return checkpoint


__all__ = [
    "AdapterExecutionError", "AdapterRegistry", "MigrationScheduler", "OperationAdapter",
    "SchedulerPolicy",
]
