# Detector execution operation guide

This guide documents the legacy detector-adapter CLI used internally by the orchestrator.
Its waves, authorization commands, confirmations, and checkpoints are not customer workflow
steps. Apply authorization for the shared immutable bundle is the permission for these target writes.

## Credentials

Use the Splunk Observability Cloud access already supplied in the local ignored
environment file. The token needs an API-compatible scope and sufficient permission for
the requested operation:

```dotenv
SPLUNK_O11Y_REALM="us1"
SPLUNK_O11Y_ACCESS_TOKEN="..."
# Optional exact organization pin:
SPLUNK_O11Y_ORG_ID="..."
```

If a complete `SPLUNK_O11Y_INNOVATIONLAB_TOKEN` and
`SPLUNK_O11Y_INNOVATIONLAB_REALM` pair is present, both Phase 1 and Phase 2 select it;
otherwise they use the standard pair above. A partial pair is not selected.

The executor reads `GET /v2/organization`, stores only its hash in the authorization,
and requires the same authenticated organization before detector operations. It does not
classify the environment as sandbox, non-production, or production. Do not paste the
token into chat or add it to a manifest.

Verify the configured connection without writing:

```bash
python3 .agents/skills/observability-migration-executor/scripts/migration_execution.py \
  inspect-splunk-target --env-file .env
```

## Automatic default flow

```bash
python3 .agents/skills/observability-migration-executor/scripts/migration_execution.py \
  auto-seal-wave \
  --session-id assessment-example01 \
  --wave-id wave-001 \
  --work-root .migration-work \
  --max-creates 5
```

This command reads only the private Datadog inventory recorded by Phase 1, rebuilds and
compares its private IR to reject source-query drift, joins it to pseudonymous plan
references with the session salt, translates only the supported metric-threshold,
grouped scalar-minus-mean, and grouped rate-ratio profiles, hash-binds the inventory and
IR into the manifest, writes the private draft, and
seals the selected subset. The final write authorization therefore binds the exact source
snapshot through the manifest hash. Output contains only
counts, hashes, and pseudonymous refs. It performs no network request or external mutation.

The automatic profiles support one metric signal with wildcard scope and optional
constant scaling, a grouped mean subtracted from an exact scalar of 1 or 100, or two
filtered grouped `as_rate()` streams divided into a timed ratio. The ratio profile accepts
only bounded `IN` or simple tag filters and identical grouping on both streams. Other
formulas, ratios, forecast/anomaly functions, events, logs, composites, and SLO alerts
remain pending instead of being approximated.

Before selecting a later wave, the executor reads tamper-evident execution checkpoints
and excludes every source object already created, reused, or left with an unresolved
create intent by another wave. Failed or sealed-only waves with neither a successful
result nor an unresolved create intent do not suppress the source object.

Automatic entries explicitly record mechanical allowlist validation; they do not claim
human semantic review or semantic equivalence. The orchestrator includes them in the complete
bundle and runs semantic validation automatically after apply.

## Manual fallback

Use `prepare-manifest` only when the customer explicitly wants to author or correct
SignalFlow for an unsupported query. Edit only `translation-manifest.draft.local.json`:

- replace the placeholder name, SignalFlow, and rule label;
- keep every rule `disabled: true` and `notifications: []`;
- compare the SignalFlow and alert semantics with the source intent;
- set all three semantic-review values to `true`;
- set `review_status` to `approved`.

Leave unsupported objects and deferred detectors unchanged. Names, queries, tags, and
custom properties in this file are restricted customer data and must not enter Codex
context, Git, logs, tickets, or the sanitized audit.

Then seal the reviewed subset:

```bash
python3 .agents/skills/observability-migration-executor/scripts/migration_execution.py \
  seal-manifest \
  --session-id assessment-example01 \
  --wave-id wave-001 \
  --work-root .migration-work
```

Sealing adds the `AI-Created` provenance tag, deterministic marker, and custom properties.
Detector names normalize source-only placeholders and operation prefixes. The resulting manifest
is immutable. Regenerate the operation through the orchestrator; do not hand-edit the sealed file.

## Authorize, execute, and validate

After apply authorization, the orchestrator creates this internal bounded authorization:

```bash
python3 .agents/skills/observability-migration-executor/scripts/migration_execution.py \
  authorize-writes \
  --session-id assessment-example01 \
  --wave-id wave-001 \
  --work-root .migration-work \
  --env-file .env \
  --ttl-minutes 30 \
  --actor-role customer
```

Before writing the local authorization, this command submits every payload to Splunk's
`POST /v2/detector/validate` dry-run endpoint. The endpoint validates the detector but
does not create it. Any rejected payload stops before authorization and before target mutation.

If a partial wave outlives its authorization, rerun this command with
`--renew-expired`. The CLI validates and archives the expired record, creates a new
authorization bound to the same sealed manifest, and does not change object scope or the
create cap, realm, or organization ID.

The orchestrator supplies the CLI confirmation from the already approved bundle; it must not ask
the customer again:

```bash
python3 .agents/skills/observability-migration-executor/scripts/migration_execution.py \
  execute-wave \
  --session-id assessment-example01 \
  --wave-id wave-001 \
  --work-root .migration-work \
  --env-file .env \
  --confirm-execution
```

Rerun the same command to resume. Before each create, the executor searches by exact
migration tag. A matching payload is reused; duplicates or drift stop the wave. A POST
is attempted once; after a retriable ambiguous failure, the executor reconciles by tag.
If the object is not yet visible, the wave fails with a pending-create checkpoint and
does not issue another POST. Rerun later to reconcile. A local non-blocking per-wave lock
serializes resume operations. A session-wide execution lock spans the final cross-wave
claim check and detector POSTs, preventing different local waves from creating the same
source object on one workstation. Authorization also repeats the cross-wave claim check
before dry-run validation.

If a pending create remains absent after bounded target-consistency retries, the orchestrator may
clear only that local intent after a fresh exact-marker GET when the approved bundle is unchanged:

```bash
python3 .agents/skills/observability-migration-executor/scripts/migration_execution.py \
  clear-pending-create \
  --session-id assessment-example01 \
  --wave-id wave-001 \
  --work-root .migration-work \
  --env-file .env \
  --confirm-retry-pending-create
```

This command performs organization/detector reads and a local checkpoint update only;
it never issues POST. The next `execute-wave` invocation may retry the cleared object.
Do not clear an intent merely because the first lookup is empty: target search can be
eventually consistent.

Read back the final state while the authorization is still valid:

```bash
python3 .agents/skills/observability-migration-executor/scripts/migration_execution.py \
  validate-wave \
  --session-id assessment-example01 \
  --wave-id wave-001 \
  --work-root .migration-work \
  --env-file .env
```

## Rollback boundary

The legacy executor writes `rollback-proposal.local.json`. The orchestrator's
`cleanup_created.py` verifies immutable provenance, refuses detectors with notifications, deletes
only session-created resources after an explicit destructive request, and verifies absence. Reused
objects are never included.

## Current limits

- Splunk Observability Cloud detectors only.
- Create-only, disabled, and notification-free.
- Maximum ten objects per legacy internal wave; the scheduler creates as many internal waves as
  needed without customer interaction.
- This adapter does not implement detector updates or enablement. Owned deletion belongs to the
  orchestrator cleanup path. Other object types use their own adapters.
- Validation compares sealed payload fields and markers; the orchestrator must additionally report
  semantic confidence and any unavailable telemetry evidence as partial, not equivalent.
