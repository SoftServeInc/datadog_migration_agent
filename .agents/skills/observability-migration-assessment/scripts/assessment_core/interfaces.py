"""Typed extension contracts for future source and target adapters."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Protocol, Sequence


@dataclass(frozen=True)
class ProviderCapability:
    capability_id: str
    access_mode: str
    status: str
    evidence_class: str


class SourceProvider(Protocol):
    provider_id: str

    def preflight(self) -> Mapping[str, Any]: ...

    def discover_read_only(self) -> Mapping[str, Any]: ...


class TargetProvider(Protocol):
    provider_id: str

    def preflight(self) -> Mapping[str, Any]: ...

    def capabilities(self) -> Sequence[ProviderCapability]: ...


class InventoryNormalizer(Protocol):
    def normalize(self, inventory: Mapping[str, Any], salt: str) -> Mapping[str, Any]: ...


class CompatibilityRule(Protocol):
    rule_id: str

    def matches(self, item: Mapping[str, Any], target: str) -> bool: ...


class ApprovalGate(Protocol):
    def validate(self, record: Mapping[str, Any], operation: str) -> None: ...


class AuditLogger(Protocol):
    def append(self, event_type: str, outcome: str, references: Mapping[str, str]) -> None: ...
