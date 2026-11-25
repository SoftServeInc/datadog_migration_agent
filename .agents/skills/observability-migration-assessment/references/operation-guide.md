# Datadog collection operation guide

## Offline credential and provider preflight

Do not `source .env`. Parse it without shell execution and print presence/status only:

```bash
python3 .agents/skills/observability-migration-assessment/scripts/migration_assessment.py \
  preflight --env-file .env
```

The parser accepts static `KEY=VALUE` syntax and rejects shell substitutions. Process environment values override the file. Required Datadog variables are `DATADOG_API_KEY`, `DATADOG_APP_KEY`, and `DATADOG_SITE`; `DD_*` aliases are accepted. The Datadog site must be in the built-in allowlist.

Each target is independent. Splunk Observability Cloud and Splunk Platform may both be configured, only one may be configured, or neither. Missing target access is represented in the plan as `BLOCKED_BY_PERMISSIONS`; it never enables a write path.

## Explicit read-only authorization

Before any live preflight or discovery, show the customer:

- source: Datadog;
- selected target: Splunk Observability Cloud, Splunk Platform, or both;
- operations: live authentication/permission probes and Datadog discovery;
- access mode: read-only;
- live preflight impact: at most seven GET requests;
- discovery impact: bounded GET requests with endpoint-level pagination and a 5,000-request hard ceiling;
- data categories: configuration metadata, queries, ownership tags, notification channel types, and permission status;
- authorization lifetime and local artifacts.

After explicit confirmation, create the approval:

```bash
python3 .agents/skills/observability-migration-assessment/scripts/migration_assessment.py \
  authorize-read-only \
  --session-id assessment-example01 \
  --env-file .env \
  --actor-role customer \
  --target both \
  --ttl-minutes 60 \
  --confirm-read-only
```

This writes `.migration-work/<session-id>/authorization.local.json`, a reviewer-safe
`authorization-summary.json`, and an append-only `audit.local.jsonl`. The private record
is hash-bound, expires, and binds the exact credential-bearing Datadog/Splunk API origins
resolved from the approved environment. The summary exposes selected provider bindings,
operations, categories, expiry, and request budgets without endpoint or credential values.
Changing a realm, site, host, operation, target, or data category invalidates the private
approval. It authorizes no external mutations. Add `--include-cost-read` only after a
separate explicit cost/billing-data confirmation.

## Approved live preflight

```bash
python3 .agents/skills/observability-migration-assessment/scripts/migration_assessment.py \
  live-preflight \
  --authorization-file .migration-work/assessment-example01/authorization.local.json \
  --env-file .env \
  --timeout 10
```

The live preflight uses GET only and persists status categories, never response payloads. It checks:

- Datadog API key via `/api/v1/validate`, API/application key pair via `/api/v2/validate_keys`, and minimal dashboard/monitor/SLO read access;
- Splunk Observability Cloud token/realm through `GET /v2/detector?limit=1`;
- Splunk Platform bearer token through `GET /services/server/info?output_mode=json&count=0` on the explicitly configured host.

It writes `live-preflight.json` and `capability-catalog.json`. Redirects are disabled, responses are capped at 512 KiB, timeouts are bounded, and response bodies are discarded after status evaluation. See the official [Datadog key validation](https://docs.datadoghq.com/account_management/api-app-keys/), [Splunk Observability Cloud detector API](https://dev.splunk.com/observability/reference/api/detectors/latest), and [Splunk Platform server info endpoint](https://help.splunk.com/en/splunk-enterprise/rest-api-reference/9.4/introspection-endpoints/introspection-endpoint-descriptions).

## Configuration collection

Use a temporary directory unless the user requests durable artifacts:

```bash
assessment_dir="$(mktemp -d)"
python3 .agents/skills/observability-migration-assessment/scripts/collect_datadog_configuration.py \
  --env-file .env \
  --authorization-file .migration-work/assessment-example01/authorization.local.json \
  --output-dir "$assessment_dir/configuration" \
  --verbose
```

The collector writes:

- `datadog-estate.local.json`: local normalized configuration, hygiene indicators, endpoint coverage, and redacted billing/usage payloads. It can still contain source names and queries; do not add it to Codex context or commit it.
- `datadog-estate-summary.md`: quick inventory and collection limitations.

Run `normalize-inventory` next to create the stable `codex-context.json` and
`inventory-ir.json`. The collector does not create a second independently salted
projection.

The collector uses GET requests only, rejects non-allowlisted Datadog hosts, does not follow redirects with credentials, caps response size, and records error categories without response bodies. Treat duplicate and ownerless findings as review candidates, never deletion instructions.

Cost collection is disabled by default. Add `--include-cost-read` when creating the authorization and `--include-cost --cost-months 3` during collection only when the user explicitly requests cost analysis.

## Composable local phases

For a narrow normalization or compatibility task, run the phase command directly instead
of creating an umbrella session:

```bash
python3 .agents/skills/observability-migration-assessment/scripts/migration_assessment.py \
  normalize-inventory \
  --inventory "$assessment_dir/configuration/datadog-estate.local.json" \
  --output-dir "$assessment_dir/normalized"

python3 .agents/skills/observability-migration-assessment/scripts/migration_assessment.py \
  assess-compatibility \
  --inventory-ir "$assessment_dir/normalized/inventory-ir.json" \
  --capability-catalog .migration-work/assessment-example01/capability-catalog.json \
  --target both \
  --output-dir "$assessment_dir/assessment"
```

`normalize-inventory` stores its local pseudonym salt in
`normalization-state.local.json`; reuse the same private output directory to preserve
stable object references. `assess-compatibility` consumes only the pseudonymous IR and
writes sanitized JSON and Markdown reports. Both commands are local and perform zero
external mutations.

## Resumable assessment and dry-run plan

Create an ignored local session after collection:

```bash
python3 .agents/skills/observability-migration-assessment/scripts/migration_assessment.py prepare \
  --inventory "$assessment_dir/configuration/datadog-estate.local.json" \
  --env-file .env \
  --capability-catalog .migration-work/assessment-example01/capability-catalog.json \
  --target both \
  --work-root .migration-work \
  --session-id assessment-example01 \
  --strategy safe_staged
```

Use `--target splunk_observability_cloud` or `--target splunk_platform` for one target. Internal preflight, authorization, collection, normalization, analysis, and planning remain within the persisted `DISCOVERY` workflow state. The assessment then advances atomically through `PLAN_GENERATED` to `WAITING_PLAN_APPROVAL`. A customer-provided local inventory follows the same persisted workflow without contacting an external system. It writes:

- `checkpoint.local.json`: private resume state and pseudonym salt;
- `preflight.json`: provider status without credential values;
- `codex-context.json`: allowlisted assessment input;
- `inventory-ir.json`: pseudonymous vendor-neutral inventory and dependency graph;
- `discovery-report.json` and `discovery-report.md`: sanitized compatibility report and strategy comparison;
- `dry-run-plan.json`: deterministic proposed steps and plan hash.

The default `safe_staged` strategy selects only direct/transformable objects without unresolved dependencies. `full` includes all assessed actions, including manual/deferred work. `customer_selected` requires one or more pseudonymous `--select-ref` values. The dry-run plan has `execution_enabled: false`, an empty `mutating_operations` list, and no Terraform apply, Git write, or target API operation.

After reviewing both reports and the plan, record explicit plan-review approval:

```bash
python3 .agents/skills/observability-migration-assessment/scripts/migration_assessment.py approve-plan \
  --session-id assessment-example01 \
  --work-root .migration-work \
  --actor-role customer \
  --confirm-plan-review
```

This advances the session to `PLAN_APPROVED` and writes a hash-bound `plan-review-approval.local.json`. It explicitly records `execution_authorized: false` and `external_mutations_authorized: false`; it is not migration write approval.

To resume an interrupted session, rerun `prepare` with the same `--session-id`, inventory, work root, target, and strategy. Completed stages are loaded from the private checkpoint; a stored plan is accepted only when its hash matches the checkpoint.

## Session cleanup

After the customer-approved retention period, delete one exact local session with an explicit confirmation:

```bash
python3 .agents/skills/observability-migration-assessment/scripts/migration_assessment.py cleanup-session \
  --session-id assessment-example01 \
  --work-root .migration-work \
  --confirm-cleanup
```

Cleanup validates the session ID and work-root containment, rejects symlinks and special files, and removes only that session directory. Filesystem deletion cannot guarantee physical erasure from SSD wear-leveling, snapshots, or backups; use an approved encrypted volume and customer retention controls when that guarantee matters.

## Telemetry discovery limitation

This repository does not currently include an active-metric/telemetry discovery adapter. Do not claim active usage, freshness, cardinality, or OpenTelemetry pipeline quality from configuration inventory alone. Add such evidence only from a separately installed, reviewed, read-only collector and keep its raw output behind the same local/sanitized boundary.

## Reconciliation

Join any separately collected telemetry evidence locally by normalized service, environment, cluster, namespace, host, team/owner, metric name, and source object query. Do not expose those join keys in `codex-context.json`. Do not assume a query's metric is active merely because it appears in configuration.

Important distinctions:

- Configured is not active.
- Active is not used by a dashboard or alert.
- Ingested is not necessarily indexed or billable.
- Estimated usage is not finalized billable usage.
- A source object with no owner tag is not necessarily abandoned.
- An empty API payload can mean no data, insufficient permission, unsupported account level, or an endpoint error; use the collector's access and errors sections.

## Report evidence table

For each headline count or cost include:

| Claim | Evidence | Period | Scope | Confidence | Limitation |
|---|---|---|---|---|---|

Cost totals should reconcile to invoices or contracted billing data before an executive savings commitment is made.
