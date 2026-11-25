from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from argparse import Namespace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from urllib.error import HTTPError
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]
ASSESSMENT = ROOT / ".agents" / "skills" / "observability-migration-assessment" / "scripts"
DETECTOR = ROOT / ".agents" / "skills" / "observability-migration-executor" / "scripts"
SLO = ROOT / ".agents" / "skills" / "observability-migration-slo-executor" / "scripts"
sys.path[:0] = [str(ASSESSMENT), str(DETECTOR), str(SLO)]

from assessment_core.security import pseudonym  # noqa: E402
from slo_adapter import SloAdapterError, SplunkSloClient  # noqa: E402
from slo_authorization import create_slo_authorization, validate_slo_authorization  # noqa: E402
from slo_common import (  # noqa: E402
    canonical_hash, slo_execution_directory, slo_session_lock, slo_wave_lock, value_hash,
)
from slo_execution import command_authorize, command_execute  # noqa: E402
from slo_executor import execute_slo_wave, rollback_proposal, validate_slo_wave  # noqa: E402
from slo_manifest import build_slo_manifest, validate_slo_manifest, validate_slo_payload  # noqa: E402
from slo_state import SloCheckpoint, SloStore  # noqa: E402
from slo_translation import translate_slo_bundle  # noqa: E402


PLAN_HASH = "a" * 64
REVIEW_HASH = "b" * 64
SOURCE_BINDING = {
    "binding_method": "phase1_local_inventory_ir_rebuild_v1",
    "inventory_hash": "c" * 64,
    "inventory_ir_hash": "d" * 64,
}
SALT = "e" * 64
ORIGIN = "https://api.eu1.observability.splunkcloud.com"
ORG_HASH = value_hash("splunk-org")


def source_inventory() -> dict[str, object]:
    return {"inventory": {
        "slos": [{
            "source_type": "slo",
            "source_id": "slo-100",
            "name": "Checkout availability",
            "slo_type": "metric",
            "query": {
                "numerator": (
                    "sum:requests.total{*} by {service}.as_count() - "
                    "sum:requests.errors{*} by {service}.as_count()"
                ),
                "denominator": (
                    "(sum:requests.total{*} by {service}.as_count() - "
                    "sum:requests.errors{*} by {service}.as_count()) + "
                    "(sum:requests.timeouts{*} by {service}.as_count())"
                ),
            },
            "thresholds": [{"target": 99.9, "warning": 99.95, "timeframe": "30d"}],
        }],
        "monitors": [
            {
                "source_type": "monitor", "source_id": "monitor-fast",
                "monitor_type": "slo alert", "queries": [{
                    "value": (
                        'burn_rate("slo-100").over("30d").long_window("1h")'
                        '.short_window("5m") > 14.4'
                    ),
                }],
            },
            {
                "source_type": "monitor", "source_id": "monitor-slow",
                "monitor_type": "slo alert", "queries": [{
                    "value": (
                        'burn_rate("slo-100").over("30d").long_window("6h")'
                        '.short_window("30m") > 6'
                    ),
                }],
            },
        ],
    }}


def approved_plan() -> dict[str, object]:
    refs = [
        (pseudonym("slo:slo-100", SALT), "slo"),
        (pseudonym("monitor:monitor-fast", SALT), "monitor"),
        (pseudonym("monitor:monitor-slow", SALT), "monitor"),
    ]
    return {"plan_hash": PLAN_HASH, "steps": [{
        "object_ref": ref,
        "object_type": object_type,
        "target": "splunk_observability_cloud",
        "proposed_operation": "PROPOSE_TRANSFORM",
    } for ref, object_type in refs]}


def sealed_manifest(wave_id: str = "slo-wave-001") -> dict[str, object]:
    return build_slo_manifest(
        "assessment-slo-test", wave_id, approved_plan(),
        {"approval_hash": REVIEW_HASH}, source_inventory(), SALT, SOURCE_BINDING,
    )


class FakeSloAdapter:
    def __init__(self) -> None:
        self.organization_id = "splunk-org"
        self.by_id: dict[str, dict[str, object]] = {}
        self.create_calls = 0
        self.validate_calls = 0

    def get_organization_id(self) -> str:
        return self.organization_id

    def search_slos(self, exact_name: str) -> list[dict[str, object]]:
        return [copy.deepcopy(item) for item in self.by_id.values() if item.get("name") == exact_name]

    def validate_slo_payload(self, payload: dict[str, object]) -> None:
        self.validate_calls += 1

    def create_slo(self, payload: dict[str, object]) -> dict[str, object]:
        self.create_calls += 1
        value = {**copy.deepcopy(payload), "id": f"slo-{self.create_calls}"}
        self.by_id[str(value["id"])] = value
        return copy.deepcopy(value)

    def get_slo(self, target_id: str) -> dict[str, object]:
        return copy.deepcopy(self.by_id[target_id])


class AmbiguousCreateAdapter(FakeSloAdapter):
    def create_slo(self, payload: dict[str, object]) -> dict[str, object]:
        super().create_slo(payload)
        raise SloAdapterError("network_error", retriable=True)


class DefinitiveCreateAdapter(FakeSloAdapter):
    def create_slo(self, payload: dict[str, object]) -> dict[str, object]:
        self.create_calls += 1
        raise SloAdapterError("http_400", create_definitively_rejected=True)


class UnresolvedCreateAdapter(FakeSloAdapter):
    def create_slo(self, payload: dict[str, object]) -> dict[str, object]:
        self.create_calls += 1
        raise SloAdapterError("network_error", retriable=True)


class DelayedReadbackAdapter(FakeSloAdapter):
    def __init__(self) -> None:
        super().__init__()
        self.failed_reads_remaining = 1

    def get_slo(self, target_id: str) -> dict[str, object]:
        if self.failed_reads_remaining:
            self.failed_reads_remaining -= 1
            raise SloAdapterError("network_error", retriable=True)
        return super().get_slo(target_id)


class MissingIdentityCreateAdapter(FakeSloAdapter):
    def create_slo(self, payload: dict[str, object]) -> dict[str, object]:
        self.create_calls += 1
        return {"name": payload["name"]}


class ServerNormalizedAdapter(FakeSloAdapter):
    def create_slo(self, payload: dict[str, object]) -> dict[str, object]:
        created = super().create_slo(payload)
        groups = created["targets"][0]["sloAlertRules"]
        burn = groups[1]
        breach = groups[0]
        burn["rules"][0]["detectLabel"] = "server1"
        burn["rules"][0]["parameters"] = {}
        burn["rules"][0]["calculatedParameters"] = {
            "burnRateThreshold1": 14.4,
            "burnRateThreshold2": 6.0,
            "longWindow1": "1h",
            "shortWindow1": "5m",
            "longWindow2": "6h",
            "shortWindow2": "30m",
        }
        breach["rules"][0]["detectLabel"] = "server2"
        created["targets"][0]["sloAlertRules"] = [burn, breach]
        self.by_id[created["id"]] = copy.deepcopy(created)
        return copy.deepcopy(created)


class InterruptingValidationStore(SloStore):
    interrupt_validation = False

    def save(self, checkpoint: SloCheckpoint) -> None:
        super().save(checkpoint)
        if (
            self.interrupt_validation
            and checkpoint.status == "EXECUTING"
            and checkpoint.result is not None
            and checkpoint.result["validated"] is False
        ):
            raise RuntimeError("simulated validation interruption")


class FakeHttpResponse:
    def __init__(self, payload: bytes, url: str):
        self.payload = payload
        self.url = url
        self.headers = {"Content-Length": str(len(payload))}

    def __enter__(self) -> "FakeHttpResponse":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self, limit: int) -> bytes:
        return self.payload[:limit]


class SequenceOpener:
    def __init__(self, outcomes: list[object]):
        self.outcomes = outcomes
        self.calls = 0
        self.requests: list[object] = []

    def open(self, req: object, timeout: int) -> FakeHttpResponse:
        self.requests.append(req)
        outcome = self.outcomes[self.calls]
        self.calls += 1
        if isinstance(outcome, BaseException):
            raise outcome
        return FakeHttpResponse(outcome, str(getattr(req, "full_url")))


class SloTranslationTests(unittest.TestCase):
    def test_allowlisted_bundle_is_deterministic_disabled_and_notification_free(self) -> None:
        first = translate_slo_bundle(source_inventory(), SALT)
        second = translate_slo_bundle(source_inventory(), SALT)
        self.assertEqual(first, second)
        self.assertIsNotNone(first)
        payload = first["payload"]
        self.assertTrue(payload["description"].startswith("[AI-Created] "))
        self.assertEqual(first["translation_method"], "automatic_metric_slo_burn_rate_v3")
        self.assertEqual(payload["type"], "RequestBased")
        self.assertIn("GOOD = A - B", payload["inputs"]["programText"])
        self.assertIn("TOTAL = GOOD + C", payload["inputs"]["programText"])
        groups = payload["targets"][0]["sloAlertRules"]
        self.assertEqual([group["type"] for group in groups], ["BREACH", "BURN_RATE"])
        self.assertTrue(all(group["rules"][0]["disabled"] for group in groups))
        self.assertTrue(all(group["rules"][0]["notifications"] == [] for group in groups))
        self.assertEqual(groups[0]["rules"][0]["parameters"], {"fireLasting": "3m"})
        rule = groups[1]["rules"][0]
        self.assertEqual(
            rule["parameters"], {"burnRateThreshold_1": 14.4, "burnRateThreshold_2": 6},
        )
        self.assertEqual(first["differences"], [
            "source_warning_status_not_represented",
            "splunk_required_breach_rule_added_disabled",
        ])

    def test_translation_rejects_profile_drift_and_injection(self) -> None:
        cases = []
        wrong_period = source_inventory()
        wrong_period["inventory"]["slos"][0]["thresholds"][0]["timeframe"] = "7d"
        cases.append(wrong_period)
        wrong_group = source_inventory()
        wrong_group["inventory"]["slos"][0]["query"]["denominator"] = str(
            wrong_group["inventory"]["slos"][0]["query"]["denominator"]
        ).replace("{service}.as_count())", "{host}.as_count())", 1)
        cases.append(wrong_group)
        wrong_burn = source_inventory()
        wrong_burn["inventory"]["monitors"][0]["queries"][0]["value"] = str(
            wrong_burn["inventory"]["monitors"][0]["queries"][0]["value"]
        ).replace("14.4", "15")
        cases.append(wrong_burn)
        injection = source_inventory()
        injection["inventory"]["slos"][0]["query"]["numerator"] = (
            "sum:requests.total');publish('x{*} by {service}.as_count() - "
            "sum:requests.errors{*} by {service}.as_count()"
        )
        cases.append(injection)
        for index, value in enumerate(cases):
            with self.subTest(case=index):
                self.assertIsNone(translate_slo_bundle(value, SALT))

    def test_manifest_is_plan_and_source_bound(self) -> None:
        manifest = sealed_manifest()
        validate_slo_manifest(manifest)
        self.assertEqual(manifest["max_creates"], 1)
        self.assertEqual(len(manifest["entry"]["source_refs"]), 3)
        self.assertEqual(manifest["entry"]["payload"]["name"], "Checkout availability")
        tampered = copy.deepcopy(manifest)
        tampered["entry"]["payload"]["targets"][0]["slo"] = 50
        with self.assertRaisesRegex(ValueError, "payload binding|hash mismatch"):
            validate_slo_manifest(tampered)

    def test_rehashed_manifest_cannot_replace_deterministic_identity(self) -> None:
        manifest = sealed_manifest()
        manifest["entry"]["execution_key"] = "f" * 64
        manifest["entry"]["exact_name"] = "MIGRATION-CODEX-SLO fedcba9876543210"
        manifest["entry"]["payload"]["name"] = manifest["entry"]["exact_name"]
        groups = manifest["entry"]["payload"]["targets"][0]["sloAlertRules"]
        groups[0]["rules"][0]["detectLabel"] = "migration_breach_fedcba9876543210"
        groups[1]["rules"][0]["detectLabel"] = "migration_fedcba9876543210"
        manifest["entry"]["payload_hash"] = value_hash(manifest["entry"]["payload"])
        manifest["manifest_hash"] = canonical_hash(manifest, "manifest_hash")
        with self.assertRaisesRegex(ValueError, "deterministic identity"):
            validate_slo_manifest(manifest)

    def test_legacy_v2_manifest_without_ai_marker_remains_readable(self) -> None:
        manifest = sealed_manifest()
        entry = manifest["entry"]
        entry["translation_method"] = "automatic_metric_slo_burn_rate_v2"
        entry["payload"]["description"] = entry["payload"]["description"].removeprefix(
            "[AI-Created] ",
        )
        entry["payload_hash"] = value_hash(entry["payload"])
        manifest["manifest_hash"] = canonical_hash(manifest, "manifest_hash")
        validate_slo_manifest(manifest)

    def test_payload_rejects_enabled_or_notifying_rule(self) -> None:
        payload = sealed_manifest()["entry"]["payload"]
        enabled = copy.deepcopy(payload)
        enabled["targets"][0]["sloAlertRules"][0]["rules"][0]["disabled"] = False
        with self.assertRaisesRegex(ValueError, "disabled"):
            validate_slo_payload(enabled)
        notifying = copy.deepcopy(payload)
        notifying["targets"][0]["sloAlertRules"][0]["rules"][0]["notifications"] = [{"type": "Email"}]
        with self.assertRaisesRegex(ValueError, "notification"):
            validate_slo_payload(notifying)


class SloAuthorizationAndExecutionTests(unittest.TestCase):
    def test_authorization_binds_manifest_target_and_expiry(self) -> None:
        manifest = sealed_manifest()
        now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        authorization = create_slo_authorization(
            manifest, "customer", ORIGIN, ORG_HASH, current_time=now,
        )
        validate_slo_authorization(authorization, manifest, current_time=now)
        with self.assertRaisesRegex(ValueError, "not active"):
            validate_slo_authorization(
                authorization, manifest, current_time=now + timedelta(minutes=31),
            )
        tampered = copy.deepcopy(authorization)
        tampered["target_org_id_hash"] = "f" * 64
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            validate_slo_authorization(tampered, manifest, current_time=now)

    def test_execute_is_idempotent_and_read_back_validated(self) -> None:
        manifest = sealed_manifest()
        authorization = create_slo_authorization(manifest, "customer", ORIGIN, ORG_HASH)
        adapter = FakeSloAdapter()
        with tempfile.TemporaryDirectory() as directory:
            store = SloStore(Path(directory), manifest["source_session_id"], manifest["wave_id"])
            first = execute_slo_wave(manifest, authorization, adapter, store)
            second = execute_slo_wave(manifest, authorization, adapter, store)
            validated = validate_slo_wave(manifest, authorization, adapter, store)
            self.assertEqual(adapter.create_calls, 1)
            self.assertEqual(first.result["outcome"], "created")
            self.assertEqual(second.status, "COMPLETED")
            self.assertEqual(validated.status, "VALIDATED")

    def test_server_normalized_rule_order_labels_and_calculated_profile_validate(self) -> None:
        manifest = sealed_manifest()
        authorization = create_slo_authorization(manifest, "customer", ORIGIN, ORG_HASH)
        adapter = ServerNormalizedAdapter()
        with tempfile.TemporaryDirectory() as directory:
            store = SloStore(Path(directory), manifest["source_session_id"], manifest["wave_id"])
            checkpoint = execute_slo_wave(manifest, authorization, adapter, store)
            self.assertEqual(checkpoint.status, "COMPLETED")
            self.assertTrue(checkpoint.result["validated"])
            self.assertEqual(adapter.create_calls, 1)

    def test_server_calculated_burn_profile_drift_fails_closed(self) -> None:
        manifest = sealed_manifest()
        authorization = create_slo_authorization(manifest, "customer", ORIGIN, ORG_HASH)
        adapter = ServerNormalizedAdapter()
        adapter.create_slo(manifest["entry"]["payload"])
        burn = next(
            group for group in adapter.by_id["slo-1"]["targets"][0]["sloAlertRules"]
            if group["type"] == "BURN_RATE"
        )
        burn["rules"][0]["calculatedParameters"]["longWindow1"] = "2h"
        with tempfile.TemporaryDirectory() as directory:
            store = SloStore(Path(directory), manifest["source_session_id"], manifest["wave_id"])
            with self.assertRaisesRegex(ValueError, "calculated burn-rate profile differs"):
                execute_slo_wave(manifest, authorization, adapter, store)
            self.assertEqual(adapter.create_calls, 1)

    def test_server_calculated_profile_is_checked_even_when_request_parameters_remain(self) -> None:
        manifest = sealed_manifest()
        authorization = create_slo_authorization(manifest, "customer", ORIGIN, ORG_HASH)
        adapter = ServerNormalizedAdapter()
        adapter.create_slo(manifest["entry"]["payload"])
        burn = next(
            group for group in adapter.by_id["slo-1"]["targets"][0]["sloAlertRules"]
            if group["type"] == "BURN_RATE"
        )
        burn["rules"][0]["parameters"] = {
            "burnRateThreshold_1": 14.4, "burnRateThreshold_2": 6,
        }
        burn["rules"][0]["calculatedParameters"]["unexpected"] = True
        with tempfile.TemporaryDirectory() as directory:
            store = SloStore(Path(directory), manifest["source_session_id"], manifest["wave_id"])
            with self.assertRaisesRegex(ValueError, "calculated burn-rate profile differs"):
                execute_slo_wave(manifest, authorization, adapter, store)

    def test_malformed_server_detect_label_fails_closed(self) -> None:
        manifest = sealed_manifest()
        authorization = create_slo_authorization(manifest, "customer", ORIGIN, ORG_HASH)
        adapter = ServerNormalizedAdapter()
        adapter.create_slo(manifest["entry"]["payload"])
        adapter.by_id["slo-1"]["targets"][0]["sloAlertRules"][0]["rules"][0][
            "detectLabel"
        ] = "bad\nlabel"
        with tempfile.TemporaryDirectory() as directory:
            store = SloStore(Path(directory), manifest["source_session_id"], manifest["wave_id"])
            with self.assertRaisesRegex(ValueError, "server-managed detect label is invalid"):
                execute_slo_wave(manifest, authorization, adapter, store)

    def test_validation_interruption_leaves_a_loadable_intermediate_state(self) -> None:
        manifest = sealed_manifest()
        authorization = create_slo_authorization(manifest, "customer", ORIGIN, ORG_HASH)
        adapter = FakeSloAdapter()
        with tempfile.TemporaryDirectory() as directory:
            store = InterruptingValidationStore(
                Path(directory), manifest["source_session_id"], manifest["wave_id"],
            )
            execute_slo_wave(manifest, authorization, adapter, store)
            store.interrupt_validation = True
            with self.assertRaisesRegex(RuntimeError, "simulated validation interruption"):
                validate_slo_wave(manifest, authorization, adapter, store)
            checkpoint = store.load()
            self.assertEqual(checkpoint.status, "EXECUTING")
            self.assertFalse(checkpoint.result["validated"])

    def test_ambiguous_create_reconciles_without_second_post(self) -> None:
        manifest = sealed_manifest()
        authorization = create_slo_authorization(manifest, "customer", ORIGIN, ORG_HASH)
        adapter = AmbiguousCreateAdapter()
        with tempfile.TemporaryDirectory() as directory:
            store = SloStore(Path(directory), manifest["source_session_id"], manifest["wave_id"])
            checkpoint = execute_slo_wave(manifest, authorization, adapter, store)
            self.assertEqual(adapter.create_calls, 1)
            self.assertIsNone(checkpoint.pending_create_ref)
            self.assertEqual(checkpoint.result["outcome"], "created")

    def test_unresolved_create_is_not_posted_twice_on_rerun(self) -> None:
        manifest = sealed_manifest()
        authorization = create_slo_authorization(manifest, "customer", ORIGIN, ORG_HASH)
        adapter = UnresolvedCreateAdapter()
        with tempfile.TemporaryDirectory() as directory:
            store = SloStore(Path(directory), manifest["source_session_id"], manifest["wave_id"])
            with self.assertRaisesRegex(SloAdapterError, "ambiguous_create_unresolved"):
                execute_slo_wave(manifest, authorization, adapter, store)
            self.assertIsNotNone(store.load().pending_create_ref)
            with self.assertRaisesRegex(ValueError, "pending SLO create"):
                execute_slo_wave(manifest, authorization, adapter, store)
            self.assertEqual(adapter.create_calls, 1)

    def test_post_success_readback_failure_reconciles_on_rerun(self) -> None:
        manifest = sealed_manifest()
        authorization = create_slo_authorization(manifest, "customer", ORIGIN, ORG_HASH)
        adapter = DelayedReadbackAdapter()
        with tempfile.TemporaryDirectory() as directory:
            store = SloStore(Path(directory), manifest["source_session_id"], manifest["wave_id"])
            with self.assertRaisesRegex(SloAdapterError, "post_create_validation_unresolved"):
                execute_slo_wave(manifest, authorization, adapter, store)
            checkpoint = execute_slo_wave(manifest, authorization, adapter, store)
            self.assertEqual(adapter.create_calls, 1)
            self.assertEqual(checkpoint.result["outcome"], "created")

    def test_missing_create_identity_keeps_intent_and_prevents_second_post(self) -> None:
        manifest = sealed_manifest()
        authorization = create_slo_authorization(manifest, "customer", ORIGIN, ORG_HASH)
        adapter = MissingIdentityCreateAdapter()
        with tempfile.TemporaryDirectory() as directory:
            store = SloStore(Path(directory), manifest["source_session_id"], manifest["wave_id"])
            with self.assertRaisesRegex(SloAdapterError, "post_create_identity_unresolved"):
                execute_slo_wave(manifest, authorization, adapter, store)
            self.assertIsNotNone(store.load().pending_create_ref)
            with self.assertRaisesRegex(ValueError, "pending SLO create"):
                execute_slo_wave(manifest, authorization, adapter, store)
            self.assertEqual(adapter.create_calls, 1)

    def test_duplicate_exact_name_fails_closed_without_create(self) -> None:
        manifest = sealed_manifest()
        authorization = create_slo_authorization(manifest, "customer", ORIGIN, ORG_HASH)
        adapter = FakeSloAdapter()
        payload = copy.deepcopy(manifest["entry"]["payload"])
        adapter.by_id["slo-one"] = {**copy.deepcopy(payload), "id": "slo-one"}
        adapter.by_id["slo-two"] = {**copy.deepcopy(payload), "id": "slo-two"}
        with tempfile.TemporaryDirectory() as directory:
            store = SloStore(Path(directory), manifest["source_session_id"], manifest["wave_id"])
            with self.assertRaisesRegex(ValueError, "multiple SLOs"):
                execute_slo_wave(manifest, authorization, adapter, store)
            self.assertEqual(adapter.create_calls, 0)

    def test_definitive_rejection_clears_pending_intent(self) -> None:
        manifest = sealed_manifest()
        authorization = create_slo_authorization(manifest, "customer", ORIGIN, ORG_HASH)
        adapter = DefinitiveCreateAdapter()
        with tempfile.TemporaryDirectory() as directory:
            store = SloStore(Path(directory), manifest["source_session_id"], manifest["wave_id"])
            with self.assertRaises(SloAdapterError):
                execute_slo_wave(manifest, authorization, adapter, store)
            failed = store.load()
            self.assertIsNone(failed.pending_create_ref)
            self.assertEqual(failed.status, "FAILED")

    def test_existing_payload_drift_fails_closed(self) -> None:
        manifest = sealed_manifest()
        authorization = create_slo_authorization(manifest, "customer", ORIGIN, ORG_HASH)
        adapter = FakeSloAdapter()
        existing = adapter.create_slo(manifest["entry"]["payload"])
        adapter.by_id[existing["id"]]["targets"][0]["slo"] = 50
        with tempfile.TemporaryDirectory() as directory:
            store = SloStore(Path(directory), manifest["source_session_id"], manifest["wave_id"])
            with self.assertRaisesRegex(ValueError, "differs"):
                execute_slo_wave(manifest, authorization, adapter, store)
            self.assertEqual(adapter.create_calls, 1)

    def test_prior_migration_description_marker_is_safely_reused(self) -> None:
        manifest = sealed_manifest()
        authorization = create_slo_authorization(manifest, "customer", ORIGIN, ORG_HASH)
        adapter = FakeSloAdapter()
        existing = adapter.create_slo(manifest["entry"]["payload"])
        adapter.by_id[existing["id"]]["description"] = (
            "[AI-Created] Create-only Datadog metric SLO migration "
            "0123456789abcdef; source warning status is not represented."
        )
        with tempfile.TemporaryDirectory() as directory:
            store = SloStore(Path(directory), manifest["source_session_id"], manifest["wave_id"])
            checkpoint = execute_slo_wave(manifest, authorization, adapter, store)
            self.assertEqual(checkpoint.result["outcome"], "reused")
            self.assertEqual(adapter.create_calls, 1)

    def test_untrusted_description_drift_is_not_reused(self) -> None:
        manifest = sealed_manifest()
        authorization = create_slo_authorization(manifest, "customer", ORIGIN, ORG_HASH)
        adapter = FakeSloAdapter()
        existing = adapter.create_slo(manifest["entry"]["payload"])
        adapter.by_id[existing["id"]]["description"] = "unrelated pre-existing SLO"
        with tempfile.TemporaryDirectory() as directory:
            store = SloStore(Path(directory), manifest["source_session_id"], manifest["wave_id"])
            with self.assertRaisesRegex(ValueError, "provenance description differs"):
                execute_slo_wave(manifest, authorization, adapter, store)
            self.assertEqual(adapter.create_calls, 1)

    def test_rollback_contains_created_not_reused_target(self) -> None:
        manifest = sealed_manifest()
        authorization = create_slo_authorization(manifest, "customer", ORIGIN, ORG_HASH)
        adapter = FakeSloAdapter()
        with tempfile.TemporaryDirectory() as directory:
            store = SloStore(Path(directory), manifest["source_session_id"], manifest["wave_id"])
            created = execute_slo_wave(manifest, authorization, adapter, store)
            self.assertEqual(len(rollback_proposal(created)["created_target_ids"]), 1)

    def test_checkpoint_tampering_is_detected(self) -> None:
        manifest = sealed_manifest()
        authorization = create_slo_authorization(manifest, "customer", ORIGIN, ORG_HASH)
        with tempfile.TemporaryDirectory() as directory:
            store = SloStore(Path(directory), manifest["source_session_id"], manifest["wave_id"])
            store.create(manifest, authorization)
            value = json.loads(store.path.read_text(encoding="utf-8"))
            value["status"] = "COMPLETED"
            store.path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "hash mismatch"):
                store.load()

    def test_checkpoint_status_and_boolean_invariants_are_enforced(self) -> None:
        manifest = sealed_manifest()
        authorization = create_slo_authorization(manifest, "customer", ORIGIN, ORG_HASH)
        with tempfile.TemporaryDirectory() as directory:
            store = SloStore(Path(directory), manifest["source_session_id"], manifest["wave_id"])
            checkpoint = store.create(manifest, authorization)
            checkpoint.status = "COMPLETED"
            store.save(checkpoint)
            with self.assertRaisesRegex(ValueError, "requires a result"):
                store.load()

        adapter = FakeSloAdapter()
        with tempfile.TemporaryDirectory() as directory:
            store = SloStore(Path(directory), manifest["source_session_id"], manifest["wave_id"])
            checkpoint = execute_slo_wave(manifest, authorization, adapter, store)
            checkpoint.result["validated"] = "false"
            store.save(checkpoint)
            with self.assertRaisesRegex(ValueError, "validation flag"):
                store.load()

    def test_stale_manifest_is_blocked_before_authorization_network_calls(self) -> None:
        manifest = sealed_manifest()
        session_id = str(manifest["source_session_id"])
        wave_id = str(manifest["wave_id"])
        provenance = {
            "session": SimpleNamespace(session_id=session_id),
            "session_directory": None,
            "plan": approved_plan(),
            "plan_review_approval": {"approval_hash": REVIEW_HASH},
        }
        with tempfile.TemporaryDirectory() as directory:
            provenance["session_directory"] = Path(directory) / session_id
            current = slo_execution_directory(Path(directory), session_id, wave_id)
            (current / "slo-manifest.local.json").write_text(
                json.dumps(manifest), encoding="utf-8",
            )
            prior_manifest = sealed_manifest("slo-wave-000")
            prior = SloStore(Path(directory), session_id, "slo-wave-000")
            (prior.directory / "slo-manifest.local.json").write_text(
                json.dumps(prior_manifest), encoding="utf-8",
            )
            prior.save(SloCheckpoint(
                source_session_id=session_id,
                wave_id="slo-wave-000",
                plan_hash=PLAN_HASH,
                manifest_hash=prior_manifest["manifest_hash"],
                authorization_hash="1" * 64,
                status="COMPLETED",
                result={
                    "object_ref": prior_manifest["entry"]["object_ref"],
                    "source_refs": prior_manifest["entry"]["source_refs"],
                    "execution_key": prior_manifest["entry"]["execution_key"],
                    "target_kind": "slo",
                    "outcome": "created",
                    "target_id": "slo-prior",
                    "validated": True,
                },
            ))
            args = Namespace(
                session_id=session_id, wave_id=wave_id, work_root=directory,
                env_file="unused", timeout=10, renew_expired=False,
                actor_role="customer", ttl_minutes=30,
            )
            with patch("slo_execution.load_approved_plan", return_value=provenance), \
                 patch("slo_execution._credentials") as credentials, \
                 self.assertRaisesRegex(ValueError, "claimed by another"):
                command_authorize(args)
            credentials.assert_not_called()

    def test_stale_manifest_is_blocked_before_execute_adapter_mutation(self) -> None:
        manifest = sealed_manifest()
        authorization = create_slo_authorization(manifest, "customer", ORIGIN, ORG_HASH)
        session_id = str(manifest["source_session_id"])
        wave_id = str(manifest["wave_id"])
        adapter = FakeSloAdapter()
        with tempfile.TemporaryDirectory() as directory:
            current = slo_execution_directory(Path(directory), session_id, wave_id)
            store = SloStore(Path(directory), session_id, wave_id)
            prior_manifest = sealed_manifest("slo-wave-000")
            prior = SloStore(Path(directory), session_id, "slo-wave-000")
            (prior.directory / "slo-manifest.local.json").write_text(
                json.dumps(prior_manifest), encoding="utf-8",
            )
            prior.save(SloCheckpoint(
                source_session_id=session_id,
                wave_id="slo-wave-000",
                plan_hash=PLAN_HASH,
                manifest_hash=prior_manifest["manifest_hash"],
                authorization_hash="1" * 64,
                status="COMPLETED",
                result={
                    "object_ref": prior_manifest["entry"]["object_ref"],
                    "source_refs": prior_manifest["entry"]["source_refs"],
                    "execution_key": prior_manifest["entry"]["execution_key"],
                    "target_kind": "slo",
                    "outcome": "created",
                    "target_id": "slo-prior",
                    "validated": True,
                },
            ))
            provenance = {"session_directory": Path(directory) / session_id}
            paths = {
                "directory": current,
                "audit": current / "execution-audit.local.jsonl",
                "rollback": current / "rollback-proposal.local.json",
            }
            args = Namespace(
                session_id=session_id, wave_id=wave_id, work_root=directory,
                confirm_execution=True,
            )
            with patch(
                "slo_execution._live_inputs",
                return_value=(provenance, manifest, authorization, adapter, store, paths),
            ), self.assertRaisesRegex(ValueError, "claimed by another"):
                command_execute(args)
            self.assertEqual(adapter.create_calls, 0)
            self.assertFalse(store.path.exists())
            self.assertFalse(paths["audit"].exists())

    def test_validation_rejection_prevents_authorization_and_audit(self) -> None:
        manifest = sealed_manifest()
        session_id = str(manifest["source_session_id"])
        wave_id = str(manifest["wave_id"])
        provenance = {
            "session": SimpleNamespace(session_id=session_id),
            "session_directory": None,
            "plan": approved_plan(),
            "plan_review_approval": {"approval_hash": REVIEW_HASH},
        }
        client = Mock()
        client.get_organization_id.return_value = "splunk-org"
        client.validate_slo_payload.side_effect = SloAdapterError(
            "http_400", create_definitively_rejected=True,
        )
        with tempfile.TemporaryDirectory() as directory:
            provenance["session_directory"] = Path(directory) / session_id
            target = slo_execution_directory(Path(directory), session_id, wave_id)
            (target / "slo-manifest.local.json").write_text(
                json.dumps(manifest), encoding="utf-8",
            )
            args = Namespace(
                session_id=session_id, wave_id=wave_id, work_root=directory,
                env_file="unused", timeout=10, renew_expired=False,
                actor_role="customer", ttl_minutes=30,
            )
            credentials = SimpleNamespace(
                origin=ORIGIN, token="test-token", configured_org_id=None,
            )
            with patch("slo_execution.load_approved_plan", return_value=provenance), \
                 patch("slo_execution._credentials", return_value=credentials), \
                 patch("slo_execution.SplunkSloClient", return_value=client), \
                 self.assertRaisesRegex(SloAdapterError, "http_400"):
                command_authorize(args)
            self.assertFalse((target / "write-authorization.local.json").exists())
            self.assertFalse((target / "execution-audit.local.jsonl").exists())

    def test_wave_and_session_locks_reject_concurrent_execution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            first = slo_execution_directory(
                Path(directory), "assessment-slo-test", "slo-wave-001",
            )
            second = slo_execution_directory(
                Path(directory), "assessment-slo-test", "slo-wave-002",
            )
            with slo_wave_lock(first):
                with self.assertRaisesRegex(ValueError, "another process"):
                    with slo_wave_lock(first):
                        self.fail("second wave lock must not be acquired")
            with slo_session_lock(first):
                with self.assertRaisesRegex(ValueError, "another SLO execution wave"):
                    with slo_session_lock(second):
                        self.fail("second session lock must not be acquired")


class SloAdapterTests(unittest.TestCase):
    def test_adapter_exposes_no_update_or_delete(self) -> None:
        client = SplunkSloClient(ORIGIN, "token", opener=object())
        self.assertFalse(hasattr(client, "update_slo"))
        self.assertFalse(hasattr(client, "delete_slo"))

    def test_adapter_rejects_put_delete_and_arbitrary_paths(self) -> None:
        client = SplunkSloClient(ORIGIN, "token", opener=object())
        for method, path in (
            ("PUT", "/v2/slo/id"),
            ("DELETE", "/v2/slo/id"),
            ("POST", "/v2/slo/id/enable"),
            ("GET", "/v2/detector"),
        ):
            with self.subTest(method=method, path=path), self.assertRaisesRegex(
                ValueError, "unsupported",
            ):
                client._request(method, path)

    def test_validate_and_search_use_only_allowlisted_posts(self) -> None:
        opener = SequenceOpener([b"", b'{"count":0,"results":[]}'])
        client = SplunkSloClient(ORIGIN, "token", opener=opener)
        client.validate_slo_payload({"name": "x"})
        self.assertEqual(client.search_slos("MIGRATION-CODEX-SLO 0123456789abcdef"), [])
        self.assertEqual(opener.requests[0].full_url, f"{ORIGIN}/v2/slo/validate")
        self.assertIn("/v2/slo/search?limit=100", opener.requests[1].full_url)

    def test_create_400_is_definitive_and_not_retried(self) -> None:
        failure = HTTPError(f"{ORIGIN}/v2/slo", 400, "bad", {}, None)
        opener = SequenceOpener([failure])
        client = SplunkSloClient(ORIGIN, "token", opener=opener)
        with self.assertRaises(SloAdapterError) as context:
            client.create_slo({"name": "x"})
        self.assertTrue(context.exception.create_definitively_rejected)
        self.assertEqual(opener.calls, 1)


if __name__ == "__main__":
    unittest.main()
