# SLO execution operation guide

This guide documents the legacy SLO-adapter CLI used internally by the orchestrator. Its wave,
authorization, confirmation, and validation commands are not customer steps. Apply authorization
for the shared immutable bundle permits target writes.

## Commands

Prepare and seal one automatic SLO bundle locally:

```bash
python3 .agents/skills/observability-migration-slo-executor/scripts/slo_execution.py \
  auto-seal-wave \
  --session-id assessment-example01 \
  --wave-id slo-wave-001 \
  --work-root .migration-work
```

The manifest binds one SLO and its two burn-rate monitor refs to the raw inventory and
rebuilt pseudonymous IR. Output is limited to hashes, counts, and pseudonymous refs.

Validate the payload and create a short-lived local authorization:

```bash
python3 .agents/skills/observability-migration-slo-executor/scripts/slo_execution.py \
  authorize-writes \
  --session-id assessment-example01 \
  --wave-id slo-wave-001 \
  --work-root .migration-work \
  --env-file .env \
  --ttl-minutes 30 \
  --actor-role customer
```

This verifies `GET /v2/organization`, then calls `POST /v2/slo/validate`. Splunk documents
the validation endpoint as non-creating. Any rejection stops before authorization and
before target mutation. Renew an expired unchanged authorization with `--renew-expired`.

After migration-wide apply authorization, the orchestrator creates or reconciles the SLO automatically:

```bash
python3 .agents/skills/observability-migration-slo-executor/scripts/slo_execution.py \
  execute-wave \
  --session-id assessment-example01 \
  --wave-id slo-wave-001 \
  --work-root .migration-work \
  --env-file .env \
  --confirm-execution
```

The executor searches through `POST /v2/slo/search` using a deterministic name and accepts
only an exact-name, payload-equivalent match. A create POST is attempted once. An ambiguous
outcome is reconciled by exact name; if still absent, the checkpoint keeps a pending intent
and a rerun does not issue another POST.

The orchestrator runs final read-back automatically:

```bash
python3 .agents/skills/observability-migration-slo-executor/scripts/slo_execution.py \
  validate-wave \
  --session-id assessment-example01 \
  --wave-id slo-wave-001 \
  --work-root .migration-work \
  --env-file .env
```

If a pending create remains absent after an appropriate consistency wait and independent
operator review, clear only the local intent with `clear-pending-create` and
`--confirm-retry-pending-create`. This performs reads and local checkpoint mutation only.

## Boundaries

- The wave creates at most one SLO.
- The migrated burn-rate rule and Splunk-required breach rule are disabled and have no
  notifications. The added breach rule is recorded as an explicit target requirement.
- The source warning display state is recorded as unrepresented.
- New SLOs carry `[AI-Created]` in their description; Splunk SLO metadata is read-only.
- This adapter has no update or enable method. Owned deletion belongs to the orchestrator cleanup
  path and requires an explicit destructive request.
- Rollback includes only session-created targets; reused SLOs are never deleted.
