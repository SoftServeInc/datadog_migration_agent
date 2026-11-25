---
name: observability-migration-assessment
description: Internal read-only assessment adapter for the observability migration orchestrator. Perform preflight, complete discovery, normalization, compatibility analysis, and planning; the orchestrator presents the report for scope confirmation.
---

# Observability Migration Assessment

Produce an evidence-backed current-state inventory, portability assessment, redesign recommendations, and migration decision package. Datadog is the first implemented source adapter; target platforms are selected by the user or compared vendor-neutrally. Cost analysis is an optional mode, not a default deliverable.

The current implementation is local and single-customer. This skill remains read-only and hands its
complete report to the orchestrator; target execution belongs to the shared execution bundle.

## Skill routing

Use this umbrella skill for the complete workflow, resuming a session, or explaining cross-phase state. For a narrow request, use only the matching specialized skill:

- `$observability-provider-preflight` — local configuration and bounded live authentication checks.
- `$datadog-configuration-discovery` — bounded source inventory collection.
- `$observability-inventory-normalizer` — local pseudonymous IR and dependency graph.
- `$observability-compatibility-assessment` — declarative Datadog-to-Splunk classification and discovery reports.
- `$observability-migration-planner` — strategy comparison, dry-run plan, and hash-bound review approval.
- `$observability-migration-executor` — internal detector adapter invoked by the orchestrator.
- `$observability-migration-slo-executor` — internal SLO adapter invoked by the orchestrator.
- `$observability-migration-dashboard-executor` — internal dashboard/chart adapter invoked by the orchestrator.
- `$observability-migration-orchestrator` — default customer-facing flow with report approval and shared apply approval; use it instead of asking the customer to drive phases or waves.
- `$observability-migration-security-review` — explicit read-only security and privacy review.

Do not load every specialized skill for a single-phase task. The skills share the deterministic core under this skill's `scripts/assessment_core/`; no specialized skill may bypass its validation or approval gates.

For a broad review, the parent may delegate independent read-only work to `migration_discovery_reviewer`, `migration_compatibility_analyst`, `migration_plan_reviewer`, `migration_execution_reviewer`, and `migration_security_reviewer`, then consolidate their evidence. Do not delegate live customer access or concurrent artifact writes.

## Safety boundary

- Treat source and target platforms as read-only until orchestrator apply authorization permits the immutable execution bundle.
- Never print, persist, or embed API keys, tokens, contract documents, account IDs marked sensitive, or notification secrets.
- Do not create, update, delete, disable, mute, publish, or import dashboards, monitors, detectors, SLOs, tests, integrations, pipelines, or telemetry.
- Do not run Terraform apply, Helm upgrade, vendor importers, or collector rollout commands.
- Store collection output in a temporary directory by default. Put a report in the repository only when the user asks for an artifact.
- Keep `*.local.json` and `checkpoint.local.json` on the user's machine. Send only `codex-context.json`, the pseudonymous IR, sanitized discovery report, and dry-run plan into Codex context.
- Parse `.env` with `scripts/migration_assessment.py`; never `source` it or execute it as shell.
- An explicit migration/assessment request plus configured environment access authorizes bounded
  read-only source and target discovery for that run. Create the internal expiring
  `authorization.local.json` automatically; it is an audit artifact, not a customer approval.
- A read-only authorization never permits target writes, Terraform apply, or Git operations. Billing/usage reads require the separate `--include-cost-read` approval flag.
- Distinguish API-observed facts, contract/billing facts, estimates, and assumptions. Never present public list prices as the customer's contracted cost.

## Workflow

1. Infer source, target, and single-customer scope from the request and environment. Ask at most one
   concise question only when several configured targets make the intended destination genuinely ambiguous.
2. Run the offline preflight in [references/operation-guide.md](references/operation-guide.md). Report credential presence and provider readiness only; never reveal values.
3. Record source, target, read-only operation, data categories, request budget, expiration, and expected
   artifacts in an automatically generated time-limited audit authorization. Do not create a user step.
4. Run the approved live preflight. It makes at most seven bounded GET requests, persists statuses only, and emits a conservative Splunk capability catalog. Missing or denied target access produces `BLOCKED_BY_PERMISSIONS`; unreachable dependencies produce `BLOCKED_BY_DEPENDENCY`.
5. For Datadog, run `scripts/collect_datadog_configuration.py` with the same authorization artifact. Inventory configuration, ownership, dependencies, integrations, retention, and explicitly authorized billing evidence. Record endpoint permission gaps instead of failing the entire assessment.
6. Normalize the estate into the evidence model in [references/evidence-model.md](references/evidence-model.md), following [references/provider-interface-spec.md](references/provider-interface-spec.md), then build the pseudonymous vendor-neutral IR and dependency graph.
7. Create or resume a local session with `scripts/migration_assessment.py prepare`, passing the
   capability catalog and selecting `full` by default. `full` must represent every discovered object;
   unsupported and deferred objects remain explicit. Inspect only sanitized artifacts; raw identifiers
   and queries remain in the local inventory. Contract details are in [references/schema-contracts.md](references/schema-contracts.md).
8. When cost is explicitly requested and separately authorized, quantify spend and cost drivers using [references/cost-model.md](references/cost-model.md). Otherwise skip billing endpoints and omit cost sections.
9. Define a vendor-neutral observability specification before mapping to a target. Preserve intent, not vendor JSON syntax.
10. If a target is named, read [references/target-mapping.md](references/target-mapping.md) and produce a capability/parity matrix. Add product-specific evidence from current official documentation when features, APIs, or pricing can have changed.
11. Hand the complete report and hashed dry-run plan to the orchestrator for scope confirmation. This
   approval accepts scope and policy but never permits target mutation.
12. Return to the orchestrator, which compiles all registered adapters automatically. Never ask the
   customer to start Phase 2 or choose detector/SLO/dashboard waves.
13. Deliver the report structure defined below with traceable evidence and confidence labels.

## Required source inventory

Collect what is accessible and state what is not:

- Dashboards, dashboard lists, widget/query types, template variables, owners, and usage metadata when available.
- Monitors/alerts, query type, thresholds, windows, grouping, notifications, dependencies, mute state, and last-modified metadata.
- SLOs, SLIs, targets, windows, burn-rate alerts, and monitor dependencies.
- Synthetic tests, locations, frequency, subtype, status, and notification bindings.
- Metrics, distributions, tag cardinality, hosts, containers, services, APM, RUM, profiles, events, and estimated usage.
- Log indexes, retention, daily limits, exclusion filters, archives, pipelines, processors, and routing.
- Cloud/integration accounts, OTel/agent collectors, exporters, receivers, processors, sampling, and enrichment.
- Users/teams/roles only when needed to assess ownership and migration access; minimize personal data in outputs.
- Estimated, projected, historical, and billable cost/usage only when explicitly requested.

## Migration decision rules

Prefer a direct target migration when configuration is small, source-specific features have clear target equivalents, telemetry already uses open protocols, and cutover can be validated service by service.

Prefer an OpenTelemetry intermediary when several targets must be evaluated, dual shipping is required, applications use proprietary agents, routing/redaction/sampling must be centralized, or future vendor portability is a stated requirement.

Do not claim that OpenTelemetry makes dashboards, alerts, SLOs, synthetics, RUM, log pipelines, or billing portable. It primarily standardizes telemetry generation, transport, processing, and resource semantics; control-plane objects still require translation.

Classify compatibility as one of:

- `DIRECT`, `TRANSFORMABLE`, `PARTIAL`, `REQUIRES_REDESIGN`, `MANUAL`, `UNSUPPORTED`, or `UNKNOWN`.
- Use `BLOCKED_BY_PERMISSIONS` or `BLOCKED_BY_DEPENDENCY` for explicit blockers.

Record the decision separately as `MIGRATE`, `ADAPT`, `REDESIGN`, `RETIRE`, `SKIP`, or `DEFER`. Compatibility is an evidence finding; disposition is a migration decision. Never infer `RETIRE` from age, ownerlessness, or missing activity data alone.

## Deliverable

Produce:

1. Executive decision summary.
2. Scope, collection timestamp, permissions, and evidence limitations.
3. Current-state inventory with counts, owners, dependencies, and complexity.
4. Telemetry and data-flow architecture.
5. Hygiene findings: stale, duplicate, ownerless, noisy, high-cardinality, or unused assets.
6. Vendor-neutral observability specification covering signals, dimensions, SLO intent, alerts, retention, access, and compliance.
7. Target capability and object-level migration matrix when a target is selected.
8. Direct-versus-intermediary architecture decision with tradeoffs.
9. Internal batching strategy, automatic validation, rollback plan, risks, effort ranges, and prerequisite decisions.
10. Appendices with machine-readable inventories and evidence references.

Add a cost baseline only when the user explicitly requests cost analysis.

For every material conclusion include the evidence source, period, observed value/count, confidence, and limitation. Clearly state that no source or target resources were changed.
