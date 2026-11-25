# Target mapping guide

Read this reference only when comparing or planning a target platform.

## Vendor-neutral specification first

Express each source object as intent before translating syntax:

- signal and semantic unit;
- aggregation, rollup, alignment, percentile, and missing-data behavior;
- filters and grouping dimensions;
- evaluation and recovery windows;
- thresholds, severities, notification routing, and maintenance behavior;
- SLI numerator/denominator, target, window, and burn policy;
- retention, indexing/search expectations, access policy, and compliance constraints.

This intermediate specification is the migration contract. Source JSON is evidence, not the target design.

## Target families

Potential targets include Splunk Observability Cloud, Grafana Cloud, Dynatrace, New Relic, Elastic Observability, Prometheus/Mimir + Grafana, Loki, Tempo, Jaeger, and other managed or self-hosted systems. Do not assume one target fits metrics, logs, traces, RUM, synthetics, profiling, incidents, and security equally well.

For the selected target, verify current official documentation for APIs, limits, query language, alert behavior, SLOs, retention, RBAC, regional availability, data residency, and billing units.

## Configured target selection

The local preflight supports these independent targets:

- Splunk Observability Cloud: configured when an API access token and realm are present. An MCP gateway URL is optional configuration metadata; the read-only MVP does not execute gateway tools.
- Splunk Platform: read access is configured when the MCP platform URL and token are present. HEC endpoint/token presence is reported separately as delivery configuration, but write execution remains disabled.
- `both`: generate one assessment action per object per target. A missing target credential becomes `BLOCKED_BY_PERMISSIONS` for that target only.

Never interpret configured HEC or ingest credentials as authorization to send telemetry or create target resources.

The generated `capability-catalog.json` is a runtime access/catalog artifact, not a product-parity claim. Pass it to the planner so denied authentication maps to `BLOCKED_BY_PERMISSIONS` and unavailable/rate-limited probes map to `BLOCKED_BY_DEPENDENCY`. Product compatibility still requires object-level semantic analysis and current official target documentation.

## Capability matrix

Rate each requirement:

- native equivalent;
- equivalent with adaptation;
- third-party or custom implementation;
- unavailable;
- not assessed.

Cover ingestion/protocols, semantic conventions, metrics, logs, traces, profiles, RUM, synthetics, dashboards, alerting, SLOs, incidents/on-call, topology, anomaly/forecasting, access control, audit, data residency, retention, APIs/IaC, and cost governance.

## OpenTelemetry intermediary

An intermediary architecture can provide OTLP ingestion, resource normalization, routing, redaction, filtering, tail/head sampling, batching, retries, queueing, and dual export. It does not make query languages or control-plane objects portable.

Assess:

- agent versus gateway deployment;
- high availability and backpressure;
- persistent queues and retry limits;
- processor ordering and semantic-convention normalization;
- secrets and tenant routing;
- PII redaction and compliance;
- sampling impact on SLOs and troubleshooting;
- collector self-observability;
- dual-run egress and duplicate-ingest cost;
- configuration ownership, testing, and rollout.

## Validation gates

Require service-by-service signal parity, query-result comparison, alert replay or shadow evaluation, SLO reconciliation, log/trace correlation, ownership routing, retention validation, RBAC validation, cost guardrails, and rollback readiness before source shutdown.
