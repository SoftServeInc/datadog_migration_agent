# Evidence model

Normalize source-platform data before comparing vendors. Keep raw API responses separate from the normalized inventory.

## Object record

Each configured object should contain, when available:

| Field | Meaning |
|---|---|
| `source_type` | dashboard, monitor, slo, synthetic, log_index, pipeline, integration, collector |
| `source_id` | stable source identifier |
| `name` | source display name |
| `owner` | team or service owner; `unknown` is explicit evidence |
| `status` | enabled, disabled, muted, archived, unknown |
| `created_at`, `modified_at` | source timestamps |
| `scope` | services, environments, clusters, namespaces, hosts, accounts |
| `signals` | metrics, logs, traces, profiles, RUM, synthetics, events |
| `queries` | source query expressions and data sources |
| `dependencies` | IDs of monitors, SLOs, dashboards, tests, integrations, or notification channels |
| `notifications` | channel types only; redact addresses, tokens, and secrets |
| `complexity` | low, medium, high with reason |
| `activity_evidence` | last viewed/triggered/modified where exposed; otherwise unavailable |
| `compatibility` | `DIRECT`, `TRANSFORMABLE`, `PARTIAL`, `REQUIRES_REDESIGN`, `MANUAL`, `UNSUPPORTED`, `UNKNOWN`, `BLOCKED_BY_PERMISSIONS`, or `BLOCKED_BY_DEPENDENCY` |
| `disposition` | separate decision: `MIGRATE`, `ADAPT`, `REDESIGN`, `RETIRE`, `SKIP`, or `DEFER` |
| `evidence` | endpoint/file and collection timestamp |

## Data boundaries

- `datadog-estate.local.json` is a local normalized inventory. It may contain source names, IDs, queries, filters, and ownership tags; never place it in Codex context or commit it.
- `checkpoint.local.json` contains local session material used for stable pseudonyms and resume; never place it in Codex context or commit it.
- `codex-context.json` is an allowlisted projection. It contains pseudonymous object references, aggregate counts, coarse complexity, provider access status, and safe limitations only.
- `inventory-ir.json` is the pseudonymous vendor-neutral object model and dependency graph. It contains no raw IDs, names, expressions, tags, or PII.
- `discovery-report.json` and `discovery-report.md` contain sanitized compatibility findings, hygiene counts, migration strategies, risks, and limitations.
- `dry-run-plan.json` contains no executable operations. Its hash binds the reviewed plan content.
- `plan-review-approval.local.json` binds customer review to the assessment and plan hashes while explicitly leaving execution and external mutations unauthorized.
- `authorization.local.json` is a time-limited, hash-bound approval for named read-only operations. It stores an actor role, not a person's name, and never authorizes external mutations.
- `authorization-summary.json` is the Codex-safe review view of authorization scope. It includes selected provider bindings, operations, categories, expiry, and request budgets but excludes endpoint and credential values.
- `audit.local.jsonl` is an append-only local event stream containing event types, outcomes, approval/session references, and aggregate counts only.
- `live-preflight.json` stores status categories only; response payloads, endpoint URLs, headers, and credentials are excluded.
- `capability-catalog.json` records configured/probed target families and marks each object type `ASSESSMENT_REQUIRED` or `BLOCKED_BY_PERMISSIONS`. It never claims semantic equivalence.

The assessment checkpoint schema is `2.0`; projections, IR, reports, approvals, and audit events remain `1.0`. The dry-run plan schema is `1.1`, and the Datadog local inventory schema is `1.1`.

The persisted workflow is `DISCOVERY -> PLAN_GENERATED -> WAITING_PLAN_APPROVAL -> PLAN_APPROVED -> APPLYING -> VALIDATING -> REVIEW_READY -> WAITING_FINAL_APPROVAL -> COMPLETED`. Internal discovery substages are artifacts and audit events, not workflow states. `PLAN_APPROVED` means the plan approval persisted and survived reload; target writes still require the explicit **Apply Approved Plan** action. Errors transition the same assessment to `BLOCKED`; skipped transitions and repeated discovery are rejected. Importing an already local inventory records `inventory_origin: provided_local_file` without inventing additional states.

## Authorization record

Required fields are `approval_id`, `session_id`, `actor_role`, `approved_at`, `expires_at`, `access_mode`, `operations`, `data_categories`, `authorized_origins`, `external_mutations_authorized`, and `approval_hash`. The hash covers every field except itself. Reject expired, modified, non-read-only, operation-mismatched, or endpoint-mismatched records.

`LIVE_PREFLIGHT` and `DATADOG_DISCOVERY` are the only supported operations. Billing endpoints additionally require the `billing_and_usage` data category.

## Complexity scoring

Use the score to estimate translation effort, not runtime criticality.

- Start at 1.
- Add 1 for each additional query beyond one.
- Add 1 for formulas, anomaly/forecast/outlier functions, or nested expressions.
- Add 1 for multi-alert grouping or more than two template dimensions.
- Add 1 for cross-object dependencies such as composite monitors or monitor-based SLOs.
- Add 1 for logs, traces, RUM, security, DBM, network, or other event-platform data sources.
- Add 1 for custom notification routing, scheduling, renotify, or maintenance behavior.
- Map 1-2 to low, 3-4 to medium, and 5+ to high.

## Telemetry record

For each signal family record volume, resolution, retention, indexed versus ingested scope, dimensions, top cardinality drivers, sampling, ownership, and freshness. Preserve original units.

## Evidence classes

- `api_observed`: directly returned by a read-only platform API.
- `billing_observed`: invoice, contract, or billing API.
- `config_observed`: collector/agent/IaC configuration.
- `ui_observed`: manually verified in the platform UI.
- `estimated`: calculated from observed quantities and an explicit rate/model.
- `assumed`: required input not yet evidenced.

Confidence is high only when the evidence directly measures the claim and covers the stated period and scope.

## Hygiene classification

Do not call an object unused merely because usage metadata is unavailable. Use:

- `stale_candidate`: old modification date plus no activity evidence where activity is available.
- `duplicate_candidate`: same normalized query/threshold or highly similar dashboard composition.
- `ownerless`: no owner/team tag or mapping.
- `noisy_candidate`: alert event volume or frequent state changes support the claim.
- `high_cardinality_candidate`: observed cardinality/volume supports the claim.
- `unknown`: insufficient evidence.
