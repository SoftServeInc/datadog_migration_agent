# Unified runtime contract

The commands below are internal. The model must not use them to bypass the native approval workflow.

## Compile and apply

After **Approve Plan** is transactionally persisted and verified, the app compiles the exact
approved plan:

```bash
python3 scripts/unified_migration.py compile --session-id SESSION \
  --work-root .migration-work --env-file .env
```

The backend appends `PLAN_APPROVED`, transitions directly to `MIGRATING`, creates a short-lived
internal receipt, and asynchronously starts:

```bash
python3 scripts/unified_migration.py apply --session-id SESSION \
  --work-root .migration-work --env-file .env \
  --approval-receipt .migration-work/SESSION/unified-execution/interactive-apply-approval.used.local.json
```

There is no customer Apply button or second apply approval. The receipt is valid only for the
persisted plan, bundle hash, target binding, and assessment. Checkpoints make the same execution
resumable after an MCP restart without discovery or reapproval.

## Live progress

While `MIGRATING`, write operation state and owned resources to the unified checkpoint after every
operation. The orchestrator polls the persisted assessment/checkpoint and returns:

- dashboards migrated / total;
- monitors migrated / total;
- queries migrated / total;
- current operation;
- up to five recent completed operations.

Never replace a known total with zero and never infer completion from a missing file.

## Validation

Required API validation follows apply and controls transition to Results. Browser validation is
optional. If requested, browser evidence may be prepared and sealed with:

```bash
python3 scripts/unified_migration.py browser-template --session-id SESSION --work-root .migration-work
python3 scripts/unified_migration.py seal-browser-validation --session-id SESSION --work-root .migration-work
```

Browser validation has a 60-second limit. Missing, invalid, failed, crashed, or timed-out evidence
becomes `BROWSER_VALIDATION_SKIPPED`. API success proceeds to review immediately.

## Rollback

The Results-stage **Rollback** button is the only rollback authorization. It runs the ownership
ledger in reverse dependency order, removes created resources, restores captured before-state, and
leaves reused resources untouched. The assessment persists `ROLLING_BACK` before mutation and
`ROLLED_BACK` only after verification.

Internal detector/SLO authorizations, retries, batching, and reconciliation never create additional
customer approvals.
