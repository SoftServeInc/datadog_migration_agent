from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from argparse import Namespace
from contextlib import redirect_stdout
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from urllib.error import HTTPError
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]
ASSESSMENT_SCRIPTS = ROOT / ".agents" / "skills" / "observability-migration-assessment" / "scripts"
EXECUTOR_SCRIPTS = ROOT / ".agents" / "skills" / "observability-migration-executor" / "scripts"
sys.path.insert(0, str(ASSESSMENT_SCRIPTS))
sys.path.insert(0, str(EXECUTOR_SCRIPTS))

from execution_core.adapter import AdapterError, SplunkDetectorClient  # noqa: E402
from execution_core.authorization import create_write_authorization, validate_write_authorization  # noqa: E402
from execution_core.common import (  # noqa: E402
    canonical_hash, execution_directory, session_execution_lock, value_hash, wave_lock,
)
from execution_core.executor import clear_unresolved_pending, execute_wave, rollback_proposal, validate_wave  # noqa: E402
from execution_core.manifest import (  # noqa: E402
    prepare_manifest_draft,
    seal_manifest,
    validate_detector_payload,
    validate_sealed_manifest,
)
from execution_core.provenance import load_phase_one_inventory  # noqa: E402
from execution_core.state import ExecutionCheckpoint, ExecutionStore  # noqa: E402
from execution_core.translation import (  # noqa: E402
    auto_populate_draft,
    translate_allowlisted_monitor,
    translate_complement_metric_monitor,
    translate_rate_ratio_monitor,
    translate_simple_metric_monitor,
)
from migration_execution import (  # noqa: E402
    _assert_manifest_refs_unclaimed,
    _claimed_refs_from_other_waves,
    _exclude_prior_claims,
    _load_splunk_credentials,
    command_authorize,
    command_auto_seal,
    command_execute,
    command_seal_manifest,
)
from assessment_core.ir import build_inventory_ir  # noqa: E402
from assessment_core.security import pseudonym  # noqa: E402


PLAN_HASH = "a" * 64
REVIEW_HASH = "b" * 64
ORG_HASH = value_hash("splunk-org")
OBJECT_REF = "obj_0123456789abcdef"
SOURCE_BINDING = {
    "binding_method": "phase1_local_inventory_ir_rebuild_v1",
    "inventory_hash": "c" * 64,
    "inventory_ir_hash": "d" * 64,
}


def sealed_manifest() -> dict[str, object]:
    plan = {
        "plan_hash": PLAN_HASH,
        "steps": [{
            "object_ref": OBJECT_REF,
            "object_type": "monitor",
            "target": "splunk_observability_cloud",
            "proposed_operation": "PROPOSE_TRANSFORM",
        }],
    }
    review = {"approval_hash": REVIEW_HASH}
    draft = prepare_manifest_draft("assessment-phase2-test", plan, review, "wave-001", 2)
    entry = draft["entries"][0]
    entry["review_status"] = "approved"
    entry["semantic_review"] = {
        "source_intent_reviewed": True,
        "signalflow_reviewed": True,
        "differences_accepted": True,
    }
    entry["payload"] = {
        "name": "CPU migration detector",
        "programText": "A = data('cpu.utilization').mean(); detect(A > 90).publish('highCpu')",
        "rules": [{
            "detectLabel": "highCpu",
            "severity": "Warning",
            "disabled": True,
            "notifications": [],
        }],
        "tags": ["migration"],
        "customProperties": {"reviewed": True},
    }
    return seal_manifest(draft, plan, review, SOURCE_BINDING)


class FakeAdapter:
    def __init__(self) -> None:
        self.by_id: dict[str, dict[str, object]] = {}
        self.create_calls = 0
        self.organization_id = "splunk-org"

    def get_organization_id(self) -> str:
        return self.organization_id

    def find_detectors_by_tag(self, marker_tag: str) -> list[dict[str, object]]:
        return [value for value in self.by_id.values() if marker_tag in value.get("tags", [])]

    def create_detector(self, payload: dict[str, object]) -> dict[str, object]:
        self.create_calls += 1
        value = copy.deepcopy(payload)
        value["id"] = f"detector-{self.create_calls}"
        self.by_id[str(value["id"])] = value
        return copy.deepcopy(value)

    def validate_detector_payload(self, payload: dict[str, object]) -> None:
        return None

    def get_detector(self, target_id: str) -> dict[str, object]:
        return copy.deepcopy(self.by_id[target_id])


class AmbiguousFirstCreateAdapter(FakeAdapter):
    def create_detector(self, payload: dict[str, object]) -> dict[str, object]:
        value = super().create_detector(payload)
        if self.create_calls == 1:
            raise AdapterError("network_error", retriable=True)
        return value


class EventuallyConsistentCreateAdapter(FakeAdapter):
    def __init__(self) -> None:
        super().__init__()
        self.hidden = True

    def find_detectors_by_tag(self, marker_tag: str) -> list[dict[str, object]]:
        return [] if self.hidden else super().find_detectors_by_tag(marker_tag)

    def create_detector(self, payload: dict[str, object]) -> dict[str, object]:
        super().create_detector(payload)
        raise AdapterError("network_error", retriable=True)


class DefinitiveFailureAdapter(FakeAdapter):
    def create_detector(self, payload: dict[str, object]) -> dict[str, object]:
        self.create_calls += 1
        raise AdapterError("http_400", retriable=False, create_definitively_rejected=True)


class CreateThenReadBackFailsAdapter(FakeAdapter):
    def __init__(self) -> None:
        super().__init__()
        self.fail_next_read_back = True

    def get_detector(self, target_id: str) -> dict[str, object]:
        if self.fail_next_read_back:
            self.fail_next_read_back = False
            raise AdapterError("http_404", retriable=False)
        return super().get_detector(target_id)


class MalformedPostResponseAdapter(EventuallyConsistentCreateAdapter):
    def create_detector(self, payload: dict[str, object]) -> dict[str, object]:
        FakeAdapter.create_detector(self, payload)
        raise AdapterError("invalid_response", retriable=False)


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


class ManifestAndAuthorizationTests(unittest.TestCase):
    def test_simple_metric_monitor_translation_is_deterministic_and_disabled(self) -> None:
        monitor = {
            "source_type": "monitor",
            "source_id": "100",
            "name": "CPU high",
            "priority": 2,
            "queries": [{
                "value": "avg(last_5m):avg:system.cpu.user{*} by {host} / (60 * 60) > 80",
            }],
        }
        first = translate_simple_metric_monitor(monitor, OBJECT_REF)
        second = translate_simple_metric_monitor(monitor, OBJECT_REF)
        self.assertEqual(first, second)
        self.assertIsNotNone(first)
        self.assertIn("B = A / 3600", first["programText"])
        self.assertIn("rollup='average'", first["programText"])
        self.assertTrue(first["rules"][0]["disabled"])
        self.assertEqual(first["rules"][0]["notifications"], [])

    def test_detector_name_removes_source_template_syntax(self) -> None:
        monitor = {
            "source_type": "monitor",
            "source_id": "100",
            "name": "Memory space is low for host {{host.name}} on device {{device.name}}",
            "queries": [{"value": "avg(last_5m):avg:system.mem.pct_usable{*} > 80"}],
        }
        translated = translate_simple_metric_monitor(monitor, OBJECT_REF)
        self.assertIsNotNone(translated)
        self.assertEqual(translated["name"], "Memory space is low by host and device")
        self.assertNotIn("{{", translated["name"])

    def test_detector_name_preserves_operation_as_human_context(self) -> None:
        monitor = {
            "source_type": "monitor",
            "source_id": "100",
            "name": "[operation:server.request] High Error Rate on {{service.name}}",
            "queries": [{"value": "avg(last_5m):avg:trace.errors{*} > 5"}],
        }
        translated = translate_simple_metric_monitor(monitor, OBJECT_REF)
        self.assertIsNotNone(translated)
        self.assertEqual(translated["name"], "High Error Rate by service — server.request")

    def test_decimal_scale_translation_is_exact(self) -> None:
        monitor = {
            "source_type": "monitor",
            "source_id": "100",
            "queries": [{"value": "avg(last_5m):avg:sample.metric{*} / (0.1 * 0.2) > 80"}],
        }
        translated = translate_simple_metric_monitor(monitor, OBJECT_REF)
        self.assertIsNotNone(translated)
        self.assertIn("B = A / 0.02", translated["programText"])
        self.assertNotIn("0.020000000000000004", translated["programText"])

    def test_grouped_complement_metric_translation_is_narrow_and_disabled(self) -> None:
        monitor = {
            "source_type": "monitor",
            "source_id": "100",
            "queries": [{
                "value": "avg(last_15m):100 - avg:sample.success.percent{*} by {service,zone} > 20",
            }],
        }
        translated = translate_complement_metric_monitor(monitor, OBJECT_REF)
        self.assertIsNotNone(translated)
        self.assertIn("rollup='average'", translated["programText"])
        self.assertIn("mean(by=['service', 'zone'])", translated["programText"])
        self.assertIn("mean(over='15m')", translated["programText"])
        self.assertIn("B = 100 - A", translated["programText"])
        self.assertTrue(translated["rules"][0]["disabled"])
        self.assertEqual(translated["rules"][0]["notifications"], [])
        self.assertEqual(
            translated["customProperties"]["translationMethod"],
            "automatic_complement_metric_v1",
        )

        wrong_constant = copy.deepcopy(monitor)
        wrong_constant["queries"][0]["value"] = wrong_constant["queries"][0]["value"].replace(
            "100 - avg", "2 - avg",
        )
        self.assertIsNone(translate_complement_metric_monitor(wrong_constant, OBJECT_REF))

        wrong_outer = copy.deepcopy(monitor)
        wrong_outer["queries"][0]["value"] = wrong_outer["queries"][0]["value"].replace(
            "avg(last_15m)", "max(last_15m)",
        )
        self.assertIsNone(translate_complement_metric_monitor(wrong_outer, OBJECT_REF))

        missing_group = copy.deepcopy(monitor)
        missing_group["queries"][0]["value"] = missing_group["queries"][0]["value"].replace(
            " by {service,zone}", "",
        )
        self.assertIsNone(translate_complement_metric_monitor(missing_group, OBJECT_REF))

    def test_complement_profile_dispatch_revalidation_and_sealing_are_source_bound(self) -> None:
        salt = "5" * 64
        source_id = "100"
        object_ref = pseudonym(f"monitor:{source_id}", salt)
        monitor = {
            "source_type": "monitor",
            "source_id": source_id,
            "queries": [{
                "value": "avg(last_10m):100 - avg:sample.success.percent{*} by {service} > 20",
            }],
        }
        plan = {"plan_hash": PLAN_HASH, "steps": [{
            "object_ref": object_ref,
            "object_type": "monitor",
            "target": "splunk_observability_cloud",
            "proposed_operation": "PROPOSE_TRANSFORM",
        }]}
        review = {"approval_hash": REVIEW_HASH}
        draft = prepare_manifest_draft(
            "assessment-phase2-test", plan, review, "wave-006", 1,
        )
        populated, first_summary = auto_populate_draft(
            draft, {"inventory": {"monitors": [monitor]}}, salt,
        )
        self.assertEqual(first_summary["auto_translated"], 1)
        self.assertEqual(
            populated["instructions"]["automatic_translation_methods"],
            ["automatic_complement_metric_v1"],
        )
        self.assertEqual(
            translate_allowlisted_monitor(monitor, object_ref),
            populated["entries"][0]["payload"],
        )
        revalidated, second_summary = auto_populate_draft(
            populated, {"inventory": {"monitors": [monitor]}}, salt,
        )
        self.assertEqual(second_summary["auto_translated"], 0)
        manifest = seal_manifest(
            revalidated, plan, review, SOURCE_BINDING,
            automatic_payload_hashes=second_summary["_automatic_payload_hashes"],
        )
        validate_sealed_manifest(manifest)
        self.assertEqual(manifest["entries"][0]["object_ref"], object_ref)

    def test_allowlisted_dispatch_rejects_forecast_event_slo_and_injection_shapes(self) -> None:
        unsupported_queries = [
            "max(last_1h):forecast(avg:sample.metric{*}, 'linear', 1) > 10",
            "events('sources:test').rollup('count').last('5m') > 1",
            "slo('synthetic-id').burn_rate('1h').window('30d') > 2",
            "avg(last_5m):100 - avg:sample.metric'); detect(True).publish('x{*} by {host} > 20",
        ]
        for query in unsupported_queries:
            monitor = {
                "source_type": "monitor",
                "source_id": "100",
                "queries": [{"value": query}],
            }
            with self.subTest(query_class=unsupported_queries.index(query)):
                self.assertIsNone(translate_allowlisted_monitor(monitor, OBJECT_REF))

    def test_filtered_grouped_rate_ratio_translation_is_fail_closed(self) -> None:
        monitor = {
            "source_type": "monitor",
            "source_id": "100",
            "queries": [{
                "value": (
                    "min(last_5m):sum:requests.errors{env:prod,!path:/health} "
                    "by {service}.as_rate() / sum:requests.total{env:prod,!path:/health} "
                    "by {service}.as_rate() > 0.05"
                ),
            }],
        }
        translated = translate_rate_ratio_monitor(monitor, OBJECT_REF)
        self.assertIsNotNone(translated)
        self.assertIn("rollup='rate'", translated["programText"])
        self.assertIn("not filter('path', '/health')", translated["programText"])
        self.assertIn("R = (N / D).min(over='5m')", translated["programText"])
        self.assertTrue(translated["rules"][0]["disabled"])
        self.assertEqual(translated["rules"][0]["notifications"], [])
        self.assertEqual(
            translated["customProperties"]["translationMethod"],
            "automatic_rate_ratio_v1",
        )

        mismatched = copy.deepcopy(monitor)
        mismatched["queries"][0]["value"] = mismatched["queries"][0]["value"].replace(
            "by {service}.as_rate() >", "by {host}.as_rate() >",
        )
        self.assertIsNone(translate_rate_ratio_monitor(mismatched, OBJECT_REF))

        leading_wildcard = copy.deepcopy(monitor)
        leading_wildcard["queries"][0]["value"] = leading_wildcard["queries"][0]["value"].replace(
            "env:prod", "env:*prod",
        )
        self.assertIsNone(translate_rate_ratio_monitor(leading_wildcard, OBJECT_REF))

        in_scope = copy.deepcopy(monitor)
        in_scope["queries"][0]["value"] = (
            "min(last_10m):sum:requests.errors{env IN (prod,staging)}"
            "by{service,zone}.as_rate() / sum:requests.total{env IN (prod,staging)}"
            "by{service,zone}.as_rate() > 0.1"
        )
        translated_in = translate_rate_ratio_monitor(in_scope, OBJECT_REF)
        self.assertIsNotNone(translated_in)
        self.assertIn("filter('env', 'prod', 'staging')", translated_in["programText"])
        self.assertIn("sum(by=['service', 'zone'])", translated_in["programText"])

        ratio_salt = "7" * 64
        ratio_ref = pseudonym("monitor:100", ratio_salt)
        plan = {"plan_hash": PLAN_HASH, "steps": [{
            "object_ref": ratio_ref, "object_type": "monitor",
            "target": "splunk_observability_cloud", "proposed_operation": "PROPOSE_TRANSFORM",
        }]}
        review = {"approval_hash": REVIEW_HASH}
        draft = prepare_manifest_draft(
            "assessment-phase2-test", plan, review, "wave-005", 1,
        )
        populated, first_summary = auto_populate_draft(
            draft, {"inventory": {"monitors": [in_scope]}}, ratio_salt,
        )
        # Revalidation must use all translator profiles, including rate ratios.
        second, second_summary = auto_populate_draft(
            populated, {"inventory": {"monitors": [in_scope]}}, ratio_salt,
        )
        self.assertEqual(first_summary["auto_translated"], 1)
        self.assertEqual(second_summary["auto_translated"], 0)
        self.assertEqual(
            second["instructions"]["automatic_translation_methods"],
            ["automatic_rate_ratio_v1"],
        )
        self.assertIn(ratio_ref, second_summary["_automatic_payload_hashes"])

    def test_completed_source_objects_are_excluded_from_later_waves(self) -> None:
        plan = {"plan_hash": PLAN_HASH, "steps": [
            {
                "object_ref": OBJECT_REF, "object_type": "monitor",
                "target": "splunk_observability_cloud", "proposed_operation": "PROPOSE_TRANSFORM",
            },
            {
                "object_ref": "obj_fedcba9876543210", "object_type": "monitor",
                "target": "splunk_observability_cloud", "proposed_operation": "PROPOSE_TRANSFORM",
            },
        ]}
        draft = prepare_manifest_draft(
            "assessment-phase2-test", plan, {"approval_hash": REVIEW_HASH}, "wave-005", 2,
        )
        summary = _exclude_prior_claims(draft, {OBJECT_REF}, set())
        self.assertEqual(summary["already_completed_source_objects"], 1)
        self.assertEqual(summary["prior_pending_create_objects"], 0)
        first, second = draft["entries"]
        self.assertEqual(first["review_status"], "not_applicable")
        self.assertIsNone(first["payload"])
        self.assertEqual(second["review_status"], "pending")

        pending_draft = prepare_manifest_draft(
            "assessment-phase2-test", plan, {"approval_hash": REVIEW_HASH}, "wave-006", 2,
        )
        pending_summary = _exclude_prior_claims(pending_draft, set(), {OBJECT_REF})
        self.assertEqual(pending_summary["prior_pending_create_objects"], 1)
        self.assertIn("unresolved pending create", pending_draft["entries"][0]["unsupported_reason"])

        approved_draft = prepare_manifest_draft(
            "assessment-phase2-test", plan, {"approval_hash": REVIEW_HASH}, "wave-007", 2,
        )
        approved_draft["entries"][0]["review_status"] = "approved"
        with self.assertRaisesRegex(ValueError, "already claimed"):
            _exclude_prior_claims(approved_draft, {OBJECT_REF}, set())

    def test_manual_payload_cannot_spoof_automatic_translation_metadata(self) -> None:
        salt = "6" * 64
        automatic_ref = pseudonym("monitor:100", salt)
        manual_ref = pseudonym("monitor:101", salt)
        plan = {"plan_hash": PLAN_HASH, "steps": [
            {
                "object_ref": automatic_ref, "object_type": "monitor",
                "target": "splunk_observability_cloud", "proposed_operation": "PROPOSE_TRANSFORM",
            },
            {
                "object_ref": manual_ref, "object_type": "monitor",
                "target": "splunk_observability_cloud", "proposed_operation": "PROPOSE_TRANSFORM",
            },
        ]}
        draft = prepare_manifest_draft(
            "assessment-phase2-test", plan, {"approval_hash": REVIEW_HASH}, "wave-005", 2,
        )
        inventory = {"inventory": {"monitors": [{
            "source_type": "monitor", "source_id": "100",
            "queries": [{"value": "avg(last_5m):avg:sample.metric{*} > 80"}],
        }]}}
        populated, _summary = auto_populate_draft(draft, inventory, salt)
        manual_entry = next(entry for entry in populated["entries"] if entry["object_ref"] == manual_ref)
        manual_entry["review_status"] = "approved"
        manual_entry["semantic_review"] = {
            "review_method": "customer_manual_v1",
            "source_intent_reviewed": True,
            "signalflow_reviewed": True,
            "differences_accepted": True,
        }
        manual_entry["payload"] = copy.deepcopy(sealed_manifest()["entries"][0]["payload"])
        manual_entry["payload"]["customProperties"] = {
            "translationMethod": "automatic_rate_ratio_v1",
        }
        refreshed, _second_summary = auto_populate_draft(populated, inventory, salt)
        self.assertEqual(
            refreshed["instructions"]["automatic_translation_methods"],
            ["automatic_simple_metric_v1"],
        )

    def test_unresolved_pending_intent_is_claimed_by_prior_wave_history(self) -> None:
        session_id = "assessment-phase2-test"
        with tempfile.TemporaryDirectory() as directory:
            store = ExecutionStore(Path(directory), session_id, "wave-004")
            checkpoint = ExecutionCheckpoint(
                source_session_id=session_id,
                wave_id="wave-004",
                plan_hash=PLAN_HASH,
                manifest_hash="e" * 64,
                authorization_hash="f" * 64,
                status="FAILED",
                pending_create_refs=[OBJECT_REF],
                failure_category="ambiguous_create_unresolved",
            )
            store.save(checkpoint)
            provenance = {"session_directory": Path(directory) / session_id}
            completed, pending = _claimed_refs_from_other_waves(
                provenance, Path(directory), session_id, "wave-005",
            )
            self.assertEqual(completed, set())
            self.assertEqual(pending, {OBJECT_REF})

    def test_manual_seal_rejects_an_approved_ref_claimed_by_prior_wave(self) -> None:
        session_id = "assessment-phase2-test"
        manifest = sealed_manifest()
        plan = {
            "plan_hash": manifest["plan_hash"],
            "steps": [{
                "object_ref": OBJECT_REF,
                "object_type": "monitor",
                "target": "splunk_observability_cloud",
                "proposed_operation": "PROPOSE_TRANSFORM",
            }],
        }
        review = {"approval_hash": manifest["plan_review_approval_hash"]}
        draft = prepare_manifest_draft(session_id, plan, review, "wave-005", 1)
        draft["entries"][0]["review_status"] = "approved"
        draft["entries"][0]["payload"] = manifest["entries"][0]["payload"]
        draft["entries"][0]["semantic_review"] = manifest["entries"][0]["semantic_review"]
        with tempfile.TemporaryDirectory() as directory:
            current = execution_directory(Path(directory), session_id, "wave-005")
            (current / "translation-manifest.draft.local.json").write_text(
                json.dumps(draft), encoding="utf-8",
            )
            prior = ExecutionStore(Path(directory), session_id, "wave-004")
            checkpoint = ExecutionCheckpoint(
                source_session_id=session_id,
                wave_id="wave-004",
                plan_hash=PLAN_HASH,
                manifest_hash="e" * 64,
                authorization_hash="f" * 64,
                status="FAILED",
                pending_create_refs=[OBJECT_REF],
                failure_category="ambiguous_create_unresolved",
            )
            prior.save(checkpoint)
            provenance = {
                "session": SimpleNamespace(session_id=session_id),
                "session_directory": Path(directory) / session_id,
                "plan": plan,
                "plan_review_approval": review,
            }
            args = Namespace(
                session_id=session_id, wave_id="wave-005", work_root=directory,
            )
            with patch("migration_execution.load_approved_plan", return_value=provenance), \
                 self.assertRaisesRegex(ValueError, "already claimed"):
                command_seal_manifest(args)

    def test_stale_sealed_manifest_is_blocked_before_authorization_network_calls(self) -> None:
        manifest = sealed_manifest()
        session_id = str(manifest["source_session_id"])
        wave_id = str(manifest["wave_id"])
        plan = {"plan_hash": manifest["plan_hash"]}
        review = {"approval_hash": manifest["plan_review_approval_hash"]}
        with tempfile.TemporaryDirectory() as directory:
            current = execution_directory(Path(directory), session_id, wave_id)
            (current / "translation-manifest.local.json").write_text(
                json.dumps(manifest), encoding="utf-8",
            )
            prior = ExecutionStore(Path(directory), session_id, "wave-004")
            checkpoint = ExecutionCheckpoint(
                source_session_id=session_id,
                wave_id="wave-004",
                plan_hash=PLAN_HASH,
                manifest_hash="e" * 64,
                authorization_hash="f" * 64,
                status="FAILED",
                pending_create_refs=[OBJECT_REF],
                failure_category="ambiguous_create_unresolved",
            )
            prior.save(checkpoint)
            provenance = {
                "session": SimpleNamespace(session_id=session_id),
                "session_directory": Path(directory) / session_id,
                "plan": plan,
                "plan_review_approval": review,
            }
            args = Namespace(
                session_id=session_id, wave_id=wave_id, work_root=directory,
                env_file="unused", timeout=10, renew_expired=False,
                actor_role="customer", ttl_minutes=30,
            )
            with patch("migration_execution.load_approved_plan", return_value=provenance), \
                 patch("migration_execution._load_splunk_credentials") as credentials, \
                 self.assertRaisesRegex(ValueError, "claimed by another"):
                command_authorize(args)
            credentials.assert_not_called()

    def test_stale_sealed_manifest_is_blocked_before_execute_adapter_mutation(self) -> None:
        manifest = sealed_manifest()
        session_id = str(manifest["source_session_id"])
        wave_id = str(manifest["wave_id"])
        authorization = create_write_authorization(
            manifest, "customer", "https://api.eu0.observability.splunkcloud.com", ORG_HASH,
        )
        adapter = FakeAdapter()
        with tempfile.TemporaryDirectory() as directory:
            current = execution_directory(Path(directory), session_id, wave_id)
            store = ExecutionStore(Path(directory), session_id, wave_id)
            prior = ExecutionStore(Path(directory), session_id, "wave-004")
            checkpoint = ExecutionCheckpoint(
                source_session_id=session_id,
                wave_id="wave-004",
                plan_hash=PLAN_HASH,
                manifest_hash="e" * 64,
                authorization_hash="f" * 64,
                status="FAILED",
                pending_create_refs=[OBJECT_REF],
                failure_category="ambiguous_create_unresolved",
            )
            prior.save(checkpoint)
            provenance = {
                "session_directory": Path(directory) / session_id,
            }
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
                "migration_execution._live_inputs",
                return_value=(manifest, authorization, adapter, store, paths),
            ), patch(
                "migration_execution.load_approved_plan", return_value=provenance,
            ), self.assertRaisesRegex(ValueError, "claimed by another"):
                command_execute(args)
            self.assertEqual(adapter.create_calls, 0)
            self.assertFalse(store.path.exists())
            self.assertFalse(paths["audit"].exists())

    def test_manifest_claim_check_detects_completed_and_pending_refs(self) -> None:
        manifest = sealed_manifest()
        provenance = {"session_directory": "/unused"}
        with patch(
            "migration_execution._claimed_refs_from_other_waves",
            return_value=({OBJECT_REF}, set()),
        ), self.assertRaisesRegex(ValueError, "claimed by another"):
            _assert_manifest_refs_unclaimed(
                provenance, Path("/unused"), "assessment-phase2-test", "wave-001", manifest,
            )

    def test_auto_populate_selects_only_wave_cap_from_allowlisted_queries(self) -> None:
        salt = "c" * 64
        monitors = []
        steps = []
        for index in range(6):
            source_id = str(100 + index)
            object_ref = pseudonym(f"monitor:{source_id}", salt)
            monitors.append({
                "source_type": "monitor",
                "source_id": source_id,
                "name": f"Synthetic monitor {index}",
                "priority": None,
                "queries": [{"value": f"avg(last_5m):avg:sample.metric{index}{{*}} by {{host}} > 80"}],
            })
            steps.append({
                "object_ref": object_ref,
                "object_type": "monitor",
                "target": "splunk_observability_cloud",
                "proposed_operation": "PROPOSE_TRANSFORM",
            })
        plan = {"plan_hash": PLAN_HASH, "steps": steps}
        review = {"approval_hash": REVIEW_HASH}
        draft = prepare_manifest_draft("assessment-phase2-test", plan, review, "wave-001", 5)
        populated, summary = auto_populate_draft(draft, {"inventory": {"monitors": monitors}}, salt)
        self.assertEqual(summary["auto_translated"], 5)
        self.assertEqual(sum(entry["review_status"] == "approved" for entry in populated["entries"]), 5)
        self.assertEqual(sum(entry["review_status"] == "pending" for entry in populated["entries"]), 1)
        automatic_review = next(
            entry["semantic_review"] for entry in populated["entries"]
            if entry["review_status"] == "approved"
        )
        self.assertEqual(automatic_review["review_method"], "automatic_allowlisted_v1")
        self.assertFalse(automatic_review["source_intent_reviewed"])
        self.assertFalse(automatic_review["signalflow_reviewed"])
        self.assertFalse(automatic_review["differences_accepted"])
        manifest = seal_manifest(
            populated, plan, review, SOURCE_BINDING,
            automatic_payload_hashes=summary["_automatic_payload_hashes"],
        )
        validate_sealed_manifest(manifest)
        self.assertEqual(len(manifest["entries"]), 5)

    def test_automatic_assurance_cannot_be_claimed_by_an_edited_draft(self) -> None:
        salt = "8" * 64
        source_id = "100"
        object_ref = pseudonym(f"monitor:{source_id}", salt)
        plan = {"plan_hash": PLAN_HASH, "steps": [{
            "object_ref": object_ref, "object_type": "monitor",
            "target": "splunk_observability_cloud", "proposed_operation": "PROPOSE_TRANSFORM",
        }]}
        review = {"approval_hash": REVIEW_HASH}
        draft = prepare_manifest_draft(
            "assessment-phase2-test", plan, review, "wave-001", 1,
        )
        inventory = {"inventory": {"monitors": [{
            "source_type": "monitor", "source_id": source_id,
            "queries": [{"value": "avg(last_5m):avg:sample.metric{*} > 80"}],
        }]}}
        populated, _summary = auto_populate_draft(draft, inventory, salt)
        populated["entries"][0]["payload"]["description"] = "manually changed"
        with self.assertRaisesRegex(ValueError, "translator-produced"):
            seal_manifest(populated, plan, review, SOURCE_BINDING)

    def test_auto_translation_leaves_unsupported_query_pending(self) -> None:
        salt = "d" * 64
        object_ref = pseudonym("monitor:100", salt)
        plan = {
            "plan_hash": PLAN_HASH,
            "steps": [{
                "object_ref": object_ref,
                "object_type": "monitor",
                "target": "splunk_observability_cloud",
                "proposed_operation": "PROPOSE_TRANSFORM",
            }],
        }
        draft = prepare_manifest_draft(
            "assessment-phase2-test", plan, {"approval_hash": REVIEW_HASH}, "wave-001", 1,
        )
        inventory = {"inventory": {"monitors": [{
            "source_type": "monitor",
            "source_id": "100",
            "name": "Composite",
            "queries": [{"value": "monitor(1) && monitor(2)"}],
        }]}}
        with self.assertRaisesRegex(ValueError, "no allowlisted"):
            auto_populate_draft(draft, inventory, salt)

    def test_auto_populate_counts_unsupported_after_capacity_is_reached(self) -> None:
        salt = "e" * 64
        monitors = []
        steps = []
        for index, query in enumerate((
            "avg(last_5m):avg:sample.one{*} > 1",
            "avg(last_5m):avg:sample.two{*} > 2",
            "monitor(1) && monitor(2)",
        )):
            source_id = str(index + 1)
            monitors.append({
                "source_type": "monitor", "source_id": source_id,
                "queries": [{"value": query}],
            })
            steps.append({
                "object_ref": pseudonym(f"monitor:{source_id}", salt),
                "object_type": "monitor", "target": "splunk_observability_cloud",
                "proposed_operation": "PROPOSE_TRANSFORM",
            })
        draft = prepare_manifest_draft(
            "assessment-phase2-test", {"plan_hash": PLAN_HASH, "steps": steps},
            {"approval_hash": REVIEW_HASH}, "wave-001", 1,
        )
        _populated, summary = auto_populate_draft(
            draft, {"inventory": {"monitors": monitors}}, salt,
        )
        self.assertEqual(summary["auto_translated"], 1)
        self.assertEqual(summary["unsupported_query_shapes"], 1)

    def test_phase_one_inventory_rejects_query_drift(self) -> None:
        salt = "f" * 64
        inventory = {"inventory": {"monitors": [{
            "source_type": "monitor", "source_id": "100",
            "queries": [{"value": "avg(last_5m):avg:sample.metric{*} > 80"}],
        }]}}
        with tempfile.TemporaryDirectory() as directory:
            session_dir = Path(directory)
            discovery_dir = session_dir / "discovery"
            discovery_dir.mkdir()
            inventory_path = discovery_dir / "datadog-estate.local.json"
            ir_path = session_dir / "inventory-ir.json"
            inventory_path.write_text(json.dumps(inventory), encoding="utf-8")
            ir_path.write_text(json.dumps(build_inventory_ir(inventory, salt)), encoding="utf-8")
            provenance = {
                "session": SimpleNamespace(
                    artifacts={"local_inventory": str(inventory_path), "inventory_ir": ir_path.name},
                    local_pseudonym_salt=salt,
                ),
                "session_directory": session_dir,
            }
            loaded, binding = load_phase_one_inventory(provenance)
            self.assertEqual(loaded, inventory)
            self.assertEqual(binding["binding_method"], "phase1_local_inventory_ir_rebuild_v1")
            inventory["inventory"]["monitors"][0]["queries"][0]["value"] = (
                "avg(last_5m):avg:sample.metric{*} > 90"
            )
            inventory_path.write_text(json.dumps(inventory), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "no longer matches"):
                load_phase_one_inventory(provenance)

    def test_auto_seal_rejects_existing_draft_cap_mismatch(self) -> None:
        session_id = "assessment-phase2-test"
        wave_id = "wave-001"
        plan = {
            "plan_hash": PLAN_HASH,
            "steps": [{
                "object_ref": OBJECT_REF, "object_type": "monitor",
                "target": "splunk_observability_cloud", "proposed_operation": "PROPOSE_TRANSFORM",
            }],
        }
        review = {"approval_hash": REVIEW_HASH}
        provenance = {
            "session": SimpleNamespace(session_id=session_id, local_pseudonym_salt="a" * 64),
            "plan": plan, "plan_review_approval": review,
        }
        with tempfile.TemporaryDirectory() as directory:
            provenance["session_directory"] = Path(directory) / session_id
            args = Namespace(
                session_id=session_id, wave_id=wave_id, work_root=directory, max_creates=1,
            )
            target = execution_directory(Path(directory), session_id, wave_id)
            draft = prepare_manifest_draft(session_id, plan, review, wave_id, 2)
            (target / "translation-manifest.draft.local.json").write_text(
                json.dumps(draft), encoding="utf-8",
            )
            with patch("migration_execution.load_approved_plan", return_value=provenance), \
                 self.assertRaisesRegex(ValueError, "draft cap differs"):
                command_auto_seal(args)

    def test_auto_seal_output_is_sanitized_and_idempotent(self) -> None:
        session_id = "assessment-phase2-test"
        wave_id = "wave-001"
        salt = "9" * 64
        object_ref = pseudonym("monitor:100", salt)
        unsupported_ref = pseudonym("monitor:101", salt)
        plan = {
            "plan_hash": PLAN_HASH,
            "steps": [
                {
                    "object_ref": object_ref, "object_type": "monitor",
                    "target": "splunk_observability_cloud", "proposed_operation": "PROPOSE_TRANSFORM",
                },
                {
                    "object_ref": unsupported_ref, "object_type": "monitor",
                    "target": "splunk_observability_cloud", "proposed_operation": "PROPOSE_TRANSFORM",
                },
            ],
        }
        review = {"approval_hash": REVIEW_HASH}
        provenance = {
            "session": SimpleNamespace(session_id=session_id, local_pseudonym_salt=salt),
            "plan": plan, "plan_review_approval": review,
        }
        inventory = {"inventory": {"monitors": [
            {
                "source_type": "monitor", "source_id": "100", "name": "PRIVATE NAME",
                "queries": [{"value": "avg(last_5m):avg:private.metric{*} > 80"}],
            },
            {
                "source_type": "monitor", "source_id": "101",
                "queries": [{"value": "monitor(1) && monitor(2)"}],
            },
        ]}}
        with tempfile.TemporaryDirectory() as directory:
            provenance["session_directory"] = Path(directory) / session_id
            args = Namespace(
                session_id=session_id, wave_id=wave_id, work_root=directory, max_creates=1,
            )
            with patch("migration_execution.load_approved_plan", return_value=provenance), \
                 patch(
                     "migration_execution.load_phase_one_inventory",
                     return_value=(inventory, SOURCE_BINDING),
                 ):
                first = StringIO()
                with redirect_stdout(first):
                    self.assertEqual(command_auto_seal(args), 0)
                second = StringIO()
                with redirect_stdout(second):
                    self.assertEqual(command_auto_seal(args), 0)
            self.assertIn('"status": "sealed"', first.getvalue())
            self.assertIn('"status": "already_sealed"', second.getvalue())
            self.assertIn('"unsupported_query_shapes": 1', first.getvalue())
            self.assertIn('"unsupported_query_shapes": 1', second.getvalue())
            self.assertNotIn("PRIVATE NAME", first.getvalue())
            self.assertNotIn("private.metric", first.getvalue())

    def test_sealed_manifest_adds_deterministic_markers_and_disables_effects(self) -> None:
        manifest = sealed_manifest()
        validate_sealed_manifest(manifest)
        entry = manifest["entries"][0]
        payload = entry["payload"]
        self.assertEqual(payload["name"], "CPU migration detector")
        self.assertIn(entry["marker_tag"], payload["tags"])
        self.assertIn("AI-Created", payload["tags"])
        self.assertEqual(manifest["schema_version"], "1.1")
        self.assertTrue(all(rule["disabled"] for rule in payload["rules"]))
        self.assertTrue(all(rule["notifications"] == [] for rule in payload["rules"]))
        self.assertTrue(manifest["safety"]["create_only"])

    def test_manifest_rejects_notifications_and_enabled_rules(self) -> None:
        plan = {
            "plan_hash": PLAN_HASH,
            "steps": [{"object_ref": OBJECT_REF, "object_type": "monitor", "target": "splunk_observability_cloud", "proposed_operation": "PROPOSE_TRANSFORM"}],
        }
        review = {"approval_hash": REVIEW_HASH}
        draft = prepare_manifest_draft("assessment-phase2-test", plan, review, "wave-001", 2)
        entry = draft["entries"][0]
        entry["review_status"] = "approved"
        entry["semantic_review"] = {"source_intent_reviewed": True, "signalflow_reviewed": True, "differences_accepted": True}
        entry["payload"] = {
            "name": "unsafe", "programText": "detect(data('x') > 1).publish('x')",
            "rules": [{"detectLabel": "x", "severity": "Major", "disabled": False, "notifications": [{"type": "Email"}]}],
        }
        with self.assertRaisesRegex(ValueError, "disabled and have no notifications"):
            seal_manifest(draft, plan, review, SOURCE_BINDING)

    def test_runtime_rejects_overlong_whitespace_padded_tag(self) -> None:
        payload = {
            "name": "valid",
            "programText": "detect(data('x') > 1).publish('x')",
            "rules": [{"detectLabel": "x", "severity": "Info", "disabled": True, "notifications": []}],
            "tags": ["x" + " " * 300],
        }
        with self.assertRaisesRegex(ValueError, "tag must be 1-256"):
            validate_detector_payload(payload)

    def test_unsupported_plan_object_cannot_be_retyped_as_detector(self) -> None:
        plan = {
            "plan_hash": PLAN_HASH,
            "steps": [{"object_ref": OBJECT_REF, "object_type": "dashboard", "target": "splunk_observability_cloud", "proposed_operation": "PROPOSE_TRANSFORM"}],
        }
        review = {"approval_hash": REVIEW_HASH}
        draft = prepare_manifest_draft("assessment-phase2-test", plan, review, "wave-001", 2)
        entry = draft["entries"][0]
        entry.update({
            "target_kind": "detector", "operation": "CREATE_ONLY", "review_status": "approved",
            "semantic_review": {"source_intent_reviewed": True, "signalflow_reviewed": True, "differences_accepted": True},
            "payload": {"name": "wrong type", "programText": "detect(data('x') > 1).publish('x')", "rules": [{"detectLabel": "x", "severity": "Info", "disabled": True, "notifications": []}]},
        })
        with self.assertRaisesRegex(ValueError, "only approved monitor"):
            seal_manifest(draft, plan, review, SOURCE_BINDING)

    def test_authorization_is_manifest_bound_temporary_and_create_only(self) -> None:
        manifest = sealed_manifest()
        now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        authorization = create_write_authorization(
            manifest, "customer", "https://api.eu0.observability.splunkcloud.com", ORG_HASH, 15, now,
        )
        validate_write_authorization(authorization, manifest, current_time=now + timedelta(minutes=14))
        self.assertFalse(authorization["updates_authorized"])
        self.assertFalse(authorization["deletes_authorized"])
        self.assertEqual(authorization["approval_scope"], "splunk_observability_create_wave")
        with self.assertRaisesRegex(ValueError, "expired"):
            validate_write_authorization(authorization, manifest, current_time=now + timedelta(minutes=16))
        tampered = dict(authorization)
        tampered["max_creates"] = 10
        with self.assertRaisesRegex(ValueError, "binding mismatch|hash mismatch"):
            validate_write_authorization(tampered, manifest, current_time=now)

    def test_executor_uses_existing_splunk_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            env_file = Path(directory) / ".env"
            env_file.write_text(
                'SPLUNK_O11Y_REALM="eu0"\n'
                'SPLUNK_O11Y_ORG_ID="splunk-org"\n'
                'SPLUNK_O11Y_ACCESS_TOKEN="existing-token"\n',
                encoding="utf-8",
            )
            credentials = _load_splunk_credentials(str(env_file))
            self.assertEqual(credentials.origin, "https://api.eu0.observability.splunkcloud.com")
            self.assertEqual(credentials.configured_org_id, "splunk-org")

    def test_executor_uses_same_complete_profile_priority_as_phase_one(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            env_file = Path(directory) / ".env"
            env_file.write_text(
                'SPLUNK_O11Y_INNOVATIONLAB_REALM="eu1"\n'
                'SPLUNK_O11Y_INNOVATIONLAB_TOKEN="innovation-token"\n'
                'SPLUNK_O11Y_REALM="eu0"\n'
                'SPLUNK_O11Y_ACCESS_TOKEN="default-token"\n',
                encoding="utf-8",
            )
            credentials = _load_splunk_credentials(str(env_file))
            self.assertEqual(credentials.realm, "eu1")
            self.assertEqual(credentials.token, "innovation-token")

    def test_sealed_manifest_accepts_reserved_name_and_tag_capacity(self) -> None:
        plan = {
            "plan_hash": PLAN_HASH,
            "steps": [{
                "object_ref": OBJECT_REF,
                "object_type": "monitor",
                "target": "splunk_observability_cloud",
                "proposed_operation": "PROPOSE_TRANSFORM",
            }],
        }
        review = {"approval_hash": REVIEW_HASH}
        draft = prepare_manifest_draft("assessment-phase2-test", plan, review, "wave-001", 2)
        entry = draft["entries"][0]
        entry["review_status"] = "approved"
        entry["semantic_review"] = {
            "source_intent_reviewed": True,
            "signalflow_reviewed": True,
            "differences_accepted": True,
        }
        entry["payload"] = {
            "name": "n" * 200,
            "programText": "detect(data('x') > 1).publish('x')",
            "rules": [{"detectLabel": "x", "severity": "Info", "disabled": True, "notifications": []}],
            "tags": [f"tag-{index}" for index in range(48)],
        }
        manifest = seal_manifest(draft, plan, review, SOURCE_BINDING)
        validate_sealed_manifest(manifest)
        self.assertLessEqual(len(manifest["entries"][0]["payload"]["name"]), 255)
        self.assertEqual(len(manifest["entries"][0]["payload"]["tags"]), 50)

    def test_legacy_detector_manifest_without_ai_tag_remains_readable(self) -> None:
        manifest = sealed_manifest()
        manifest["schema_version"] = "1.0"
        entry = manifest["entries"][0]
        entry["payload"]["tags"].remove("AI-Created")
        entry["payload_hash"] = value_hash(entry["payload"])
        manifest["manifest_hash"] = canonical_hash(manifest, "manifest_hash")
        validate_sealed_manifest(manifest)

    def test_draft_reserves_two_target_tag_slots(self) -> None:
        payload = {
            "name": "valid",
            "programText": "detect(data('x') > 1).publish('x')",
            "rules": [{
                "detectLabel": "x", "severity": "Info",
                "disabled": True, "notifications": [],
            }],
            "tags": [f"tag-{index}" for index in range(49)],
        }
        with self.assertRaisesRegex(ValueError, "at most 48"):
            validate_detector_payload(payload)

    def test_machine_readable_schemas_track_runtime_contracts(self) -> None:
        schema_root = ROOT / ".agents" / "skills" / "observability-migration-executor" / "schemas"
        manifest = sealed_manifest()
        authorization = create_write_authorization(
            manifest, "customer", "https://api.eu0.observability.splunkcloud.com", ORG_HASH,
        )
        with tempfile.TemporaryDirectory() as directory:
            store = ExecutionStore(Path(directory), manifest["source_session_id"], manifest["wave_id"])
            checkpoint = asdict(store.create(manifest, authorization))
        pairs = [
            ("translation-manifest.schema.json", manifest),
            ("write-authorization.schema.json", authorization),
            ("execution-checkpoint.schema.json", checkpoint),
        ]
        for filename, artifact in pairs:
            with self.subTest(schema=filename):
                schema = json.loads((schema_root / filename).read_text(encoding="utf-8"))
                self.assertEqual(set(schema["required"]), set(artifact))
                self.assertFalse(schema["additionalProperties"])
        manifest_schema = json.loads((schema_root / "translation-manifest.schema.json").read_text(encoding="utf-8"))
        payload_schema = manifest_schema["properties"]["entries"]["items"]["properties"]["payload"]
        self.assertFalse(payload_schema["additionalProperties"])
        self.assertEqual(payload_schema["properties"]["rules"]["items"]["properties"]["disabled"]["const"], True)
        self.assertEqual(payload_schema["properties"]["rules"]["items"]["properties"]["notifications"]["maxItems"], 0)


class ExecutionTests(unittest.TestCase):
    def test_execution_is_idempotent_and_resumable(self) -> None:
        manifest = sealed_manifest()
        authorization = create_write_authorization(
            manifest, "customer", "https://api.eu0.observability.splunkcloud.com", ORG_HASH,
        )
        adapter = FakeAdapter()
        with tempfile.TemporaryDirectory() as directory:
            store = ExecutionStore(Path(directory), manifest["source_session_id"], manifest["wave_id"])
            first = execute_wave(manifest, authorization, adapter, store)
            second = execute_wave(manifest, authorization, adapter, store)
            self.assertEqual(adapter.create_calls, 1)
            self.assertEqual(first.created_count, 1)
            self.assertEqual(second.created_count, 1)
            self.assertEqual(len(second.results), 1)
            validated = validate_wave(manifest, authorization, adapter, store)
            self.assertEqual(validated.status, "VALIDATED")
            proposal = rollback_proposal(validated)
            self.assertFalse(proposal["automatic_rollback_authorized"])
            self.assertEqual(proposal["created_target_ids"], ["detector-1"])

            renewed = create_write_authorization(
                manifest, "customer", "https://api.eu0.observability.splunkcloud.com", ORG_HASH,
            )
            resumed = execute_wave(manifest, renewed, adapter, store)
            self.assertEqual(resumed.authorization_hash, renewed["approval_hash"])
            self.assertEqual(adapter.create_calls, 1)

    def test_ambiguous_post_reconciles_without_second_post(self) -> None:
        manifest = sealed_manifest()
        authorization = create_write_authorization(
            manifest, "customer", "https://api.eu0.observability.splunkcloud.com", ORG_HASH,
        )
        adapter = AmbiguousFirstCreateAdapter()
        with tempfile.TemporaryDirectory() as directory:
            store = ExecutionStore(Path(directory), manifest["source_session_id"], manifest["wave_id"])
            checkpoint = execute_wave(manifest, authorization, adapter, store)
            self.assertEqual(adapter.create_calls, 1)
            self.assertEqual(checkpoint.created_count, 1)

    def test_eventually_consistent_ambiguous_post_never_blindly_retries(self) -> None:
        manifest = sealed_manifest()
        authorization = create_write_authorization(
            manifest, "customer", "https://api.eu0.observability.splunkcloud.com", ORG_HASH,
        )
        adapter = EventuallyConsistentCreateAdapter()
        with tempfile.TemporaryDirectory() as directory:
            store = ExecutionStore(Path(directory), manifest["source_session_id"], manifest["wave_id"])
            with self.assertRaisesRegex(AdapterError, "ambiguous_create_unresolved"):
                execute_wave(manifest, authorization, adapter, store)
            failed = store.load()
            self.assertEqual(adapter.create_calls, 1)
            self.assertEqual(failed.pending_create_refs, [OBJECT_REF])
            adapter.hidden = False
            resumed = execute_wave(manifest, authorization, adapter, store)
            self.assertEqual(adapter.create_calls, 1)
            self.assertEqual(resumed.created_count, 1)
            self.assertEqual(rollback_proposal(resumed)["created_target_ids"], ["detector-1"])

    def test_explicit_pending_clear_is_read_only_and_allows_later_retry(self) -> None:
        manifest = sealed_manifest()
        authorization = create_write_authorization(
            manifest, "customer", "https://api.eu0.observability.splunkcloud.com", ORG_HASH,
        )
        adapter = EventuallyConsistentCreateAdapter()
        with tempfile.TemporaryDirectory() as directory:
            store = ExecutionStore(Path(directory), manifest["source_session_id"], manifest["wave_id"])
            with self.assertRaises(AdapterError):
                execute_wave(manifest, authorization, adapter, store)
            checkpoint, cleared = clear_unresolved_pending(
                manifest, authorization, adapter, store,
            )
            self.assertEqual(adapter.create_calls, 1)
            self.assertEqual(cleared, [OBJECT_REF])
            self.assertEqual(checkpoint.pending_create_refs, [])

    def test_definitive_post_failure_does_not_strand_pending_intent(self) -> None:
        manifest = sealed_manifest()
        authorization = create_write_authorization(
            manifest, "customer", "https://api.eu0.observability.splunkcloud.com", ORG_HASH,
        )
        adapter = DefinitiveFailureAdapter()
        with tempfile.TemporaryDirectory() as directory:
            store = ExecutionStore(Path(directory), manifest["source_session_id"], manifest["wave_id"])
            with self.assertRaisesRegex(AdapterError, "http_400"):
                execute_wave(manifest, authorization, adapter, store)
            self.assertEqual(store.load().pending_create_refs, [])
            self.assertEqual(adapter.create_calls, 1)

    def test_post_success_read_back_failure_never_retries_create(self) -> None:
        manifest = sealed_manifest()
        authorization = create_write_authorization(
            manifest, "customer", "https://api.eu0.observability.splunkcloud.com", ORG_HASH,
        )
        adapter = CreateThenReadBackFailsAdapter()
        with tempfile.TemporaryDirectory() as directory:
            store = ExecutionStore(Path(directory), manifest["source_session_id"], manifest["wave_id"])
            with self.assertRaisesRegex(AdapterError, "post_create_validation_unresolved"):
                execute_wave(manifest, authorization, adapter, store)
            self.assertEqual(store.load().pending_create_refs, [OBJECT_REF])
            resumed = execute_wave(manifest, authorization, adapter, store)
            self.assertEqual(adapter.create_calls, 1)
            self.assertEqual(resumed.created_count, 1)

    def test_malformed_post_response_never_causes_blind_retry(self) -> None:
        manifest = sealed_manifest()
        authorization = create_write_authorization(
            manifest, "customer", "https://api.eu0.observability.splunkcloud.com", ORG_HASH,
        )
        adapter = MalformedPostResponseAdapter()
        with tempfile.TemporaryDirectory() as directory:
            store = ExecutionStore(Path(directory), manifest["source_session_id"], manifest["wave_id"])
            with self.assertRaisesRegex(AdapterError, "ambiguous_create_unresolved"):
                execute_wave(manifest, authorization, adapter, store)
            self.assertEqual(adapter.create_calls, 1)
            self.assertEqual(store.load().pending_create_refs, [OBJECT_REF])
            adapter.hidden = False
            resumed = execute_wave(manifest, authorization, adapter, store)
            self.assertEqual(adapter.create_calls, 1)
            self.assertEqual(resumed.created_count, 1)

    def test_core_rejects_wrong_organization_before_detector_calls(self) -> None:
        manifest = sealed_manifest()
        authorization = create_write_authorization(
            manifest, "customer", "https://api.eu0.observability.splunkcloud.com", ORG_HASH,
        )
        adapter = FakeAdapter()
        with tempfile.TemporaryDirectory() as directory:
            store = ExecutionStore(Path(directory), manifest["source_session_id"], manifest["wave_id"])
            adapter.organization_id = "different-org"
            with self.assertRaisesRegex(ValueError, "runtime Splunk organization"):
                execute_wave(manifest, authorization, adapter, store)
            self.assertEqual(adapter.create_calls, 0)
            self.assertFalse(store.path.exists())

    def test_conflicting_marker_fails_closed_without_create(self) -> None:
        manifest = sealed_manifest()
        authorization = create_write_authorization(
            manifest, "customer", "https://api.eu0.observability.splunkcloud.com", ORG_HASH,
        )
        adapter = FakeAdapter()
        entry = manifest["entries"][0]
        conflicting = copy.deepcopy(entry["payload"])
        conflicting["id"] = "conflict"
        conflicting["programText"] = "detect(data('different') > 1).publish('different')"
        adapter.by_id["conflict"] = conflicting
        with tempfile.TemporaryDirectory() as directory:
            store = ExecutionStore(Path(directory), manifest["source_session_id"], manifest["wave_id"])
            with self.assertRaisesRegex(ValueError, "differs"):
                execute_wave(manifest, authorization, adapter, store)
            self.assertEqual(adapter.create_calls, 0)
            self.assertEqual(store.load().status, "FAILED")

    def test_extra_target_rule_and_failed_validation_are_recorded(self) -> None:
        manifest = sealed_manifest()
        authorization = create_write_authorization(
            manifest, "customer", "https://api.eu0.observability.splunkcloud.com", ORG_HASH,
        )
        adapter = FakeAdapter()
        with tempfile.TemporaryDirectory() as directory:
            store = ExecutionStore(Path(directory), manifest["source_session_id"], manifest["wave_id"])
            execute_wave(manifest, authorization, adapter, store)
            adapter.by_id["detector-1"]["rules"].append({
                "detectLabel": "unexpected", "severity": "Critical", "disabled": False,
                "notifications": [{"type": "Email"}],
            })
            with self.assertRaisesRegex(ValueError, "rule set differs"):
                validate_wave(manifest, authorization, adapter, store)
            failed = store.load()
            self.assertEqual(failed.status, "FAILED")
            self.assertEqual(failed.validated_count, 0)
            self.assertFalse(failed.results[0]["validated"])

    def test_checkpoint_tampering_is_detected(self) -> None:
        manifest = sealed_manifest()
        authorization = create_write_authorization(
            manifest, "customer", "https://api.eu0.observability.splunkcloud.com", ORG_HASH,
        )
        with tempfile.TemporaryDirectory() as directory:
            store = ExecutionStore(Path(directory), manifest["source_session_id"], manifest["wave_id"])
            store.create(manifest, authorization)
            value = json.loads(store.path.read_text(encoding="utf-8"))
            value["created_count"] = 9
            store.path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "hash mismatch"):
                store.load()

    def test_rehashed_manifest_still_requires_semantic_and_payload_invariants(self) -> None:
        manifest = sealed_manifest()
        manifest["entries"][0]["semantic_review"]["differences_accepted"] = False
        manifest["manifest_hash"] = canonical_hash(manifest, "manifest_hash")
        with self.assertRaisesRegex(ValueError, "translation assurance"):
            validate_sealed_manifest(manifest)

        manifest = sealed_manifest()
        entry = manifest["entries"][0]
        entry["payload"]["name"] = ""
        entry["payload_hash"] = value_hash(entry["payload"])
        manifest["manifest_hash"] = canonical_hash(manifest, "manifest_hash")
        with self.assertRaisesRegex(ValueError, "name"):
            validate_sealed_manifest(manifest)

    def test_live_adapter_exposes_no_update_or_delete_methods(self) -> None:
        client = SplunkDetectorClient(
            "https://api.eu0.observability.splunkcloud.com", "test-token", opener=object(),
        )
        self.assertFalse(hasattr(client, "update_detector"))
        self.assertFalse(hasattr(client, "delete_detector"))

    def test_live_adapter_returns_valid_organization_id(self) -> None:
        origin = "https://api.eu0.observability.splunkcloud.com"
        opener = SequenceOpener([b'{"id": "splunk-org"}'])
        client = SplunkDetectorClient(origin, "test-token", opener=opener)
        self.assertEqual(client.get_organization_id(), "splunk-org")
        invalid = SplunkDetectorClient(
            origin, "test-token", opener=SequenceOpener([b'{"name": "missing id"}']),
        )
        with self.assertRaisesRegex(AdapterError, "invalid_organization_response"):
            invalid.get_organization_id()

    def test_live_adapter_supports_non_mutating_detector_validation(self) -> None:
        origin = "https://api.eu0.observability.splunkcloud.com"
        opener = SequenceOpener([b""])
        client = SplunkDetectorClient(origin, "test-token", opener=opener)
        self.assertIsNone(client.validate_detector_payload({"name": "dry run"}))
        self.assertEqual(opener.calls, 1)
        self.assertEqual(opener.requests[0].get_method(), "POST")
        self.assertEqual(opener.requests[0].full_url, f"{origin}/v2/detector/validate")

        rejected = SequenceOpener([
            HTTPError(f"{origin}/v2/detector/validate", 503, "unavailable", {}, None),
        ])
        with self.assertRaisesRegex(AdapterError, "http_503"):
            SplunkDetectorClient(origin, "test-token", opener=rejected).validate_detector_payload(
                {"name": "dry run"},
            )
        self.assertEqual(rejected.calls, 1)

    def test_validation_rejection_prevents_write_authorization_and_audit(self) -> None:
        manifest = sealed_manifest()
        session_id = str(manifest["source_session_id"])
        wave_id = str(manifest["wave_id"])
        provenance = {
            "session": SimpleNamespace(session_id=session_id),
            "session_directory": None,
            "plan": {"plan_hash": manifest["plan_hash"]},
            "plan_review_approval": {"approval_hash": manifest["plan_review_approval_hash"]},
        }
        client = Mock()
        client.get_organization_id.return_value = "splunk-org"
        client.validate_detector_payload.side_effect = AdapterError(
            "http_400", create_definitively_rejected=True,
        )
        with tempfile.TemporaryDirectory() as directory:
            provenance["session_directory"] = Path(directory) / session_id
            target = execution_directory(Path(directory), session_id, wave_id)
            (target / "translation-manifest.local.json").write_text(
                json.dumps(manifest), encoding="utf-8",
            )
            args = Namespace(
                session_id=session_id, wave_id=wave_id, work_root=directory,
                env_file="unused", timeout=10, renew_expired=False,
                actor_role="customer", ttl_minutes=30,
            )
            credentials = SimpleNamespace(
                origin="https://api.eu0.observability.splunkcloud.com",
                token="test-token", configured_org_id=None,
            )
            with patch("migration_execution.load_approved_plan", return_value=provenance), \
                 patch("migration_execution._load_splunk_credentials", return_value=credentials), \
                 patch("migration_execution.SplunkDetectorClient", return_value=client), \
                 self.assertRaisesRegex(AdapterError, "http_400"):
                command_authorize(args)
            self.assertFalse((target / "write-authorization.local.json").exists())
            self.assertFalse((target / "execution-audit.local.jsonl").exists())

    def test_authorization_is_rechecked_before_each_object(self) -> None:
        manifest = sealed_manifest()
        authorization = create_write_authorization(
            manifest, "customer", "https://api.eu0.observability.splunkcloud.com", ORG_HASH,
        )
        adapter = FakeAdapter()
        with tempfile.TemporaryDirectory() as directory:
            store = ExecutionStore(Path(directory), manifest["source_session_id"], manifest["wave_id"])
            with patch(
                "execution_core.executor.validate_write_authorization",
                side_effect=[None, None, ValueError("write authorization has expired")],
            ):
                with self.assertRaisesRegex(ValueError, "expired"):
                    execute_wave(manifest, authorization, adapter, store)
            self.assertEqual(adapter.create_calls, 0)
            self.assertEqual(store.load().status, "FAILED")
            self.assertEqual(store.load().pending_create_refs, [])

    def test_wave_lock_rejects_concurrent_local_executor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            wave = execution_directory(Path(directory), "assessment-phase2-test", "wave-001")
            with wave_lock(wave):
                with self.assertRaisesRegex(ValueError, "another process"):
                    with wave_lock(wave):
                        self.fail("second lock must not be acquired")

    def test_session_execution_lock_serializes_different_waves(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            first = execution_directory(Path(directory), "assessment-phase2-test", "wave-001")
            second = execution_directory(Path(directory), "assessment-phase2-test", "wave-002")
            with session_execution_lock(first):
                with self.assertRaisesRegex(ValueError, "another execution wave"):
                    with session_execution_lock(second):
                        self.fail("second session execution lock must not be acquired")

    def test_get_retries_are_bounded_and_post_is_not_blindly_retried(self) -> None:
        origin = "https://api.eu0.observability.splunkcloud.com"
        failures = [
            HTTPError(f"{origin}/v2/detector", 503, "unavailable", {}, None),
            HTTPError(f"{origin}/v2/detector", 503, "unavailable", {}, None),
            b'{"results": []}',
        ]
        opener = SequenceOpener(failures)
        sleeps: list[float] = []
        client = SplunkDetectorClient(origin, "test-token", opener=opener, sleep=sleeps.append)
        self.assertEqual(client.find_detectors_by_tag("codex-migration-0123456789abcdef"), [])
        self.assertEqual(opener.calls, 3)
        self.assertEqual(len(sleeps), 2)

        post_opener = SequenceOpener([
            HTTPError(f"{origin}/v2/detector", 503, "unavailable", {}, None),
        ])
        post_client = SplunkDetectorClient(origin, "test-token", opener=post_opener, sleep=sleeps.append)
        with self.assertRaises(AdapterError):
            post_client.create_detector({"name": "x"})
        self.assertEqual(post_opener.calls, 1)


if __name__ == "__main__":
    unittest.main()
