# Deterministic migration flow

## Persisted state machine

The assessment is the only source of workflow state and counters.

```text
DISCOVERY -> PLAN_REVIEW -> WAITING_PLAN_APPROVAL -> MIGRATING -> VALIDATING
          -> REVIEW_READY -> WAITING_FINAL_APPROVAL -> COMPLETED

WAITING_PLAN_APPROVAL -> FAILED
MIGRATING -> FAILED
VALIDATING -> FAILED
WAITING_FINAL_APPROVAL -> ROLLING_BACK -> ROLLED_BACK
```

All other transitions raise `INVALID_STATE_TRANSITION`. `assessment_id` never changes. Discovery
may be claimed once. Every transition is file-locked, revision-checked, atomically persisted, read
back where approval is involved, and appended to `workflow-transitions.local.jsonl`.

## Four customer stages

Tool results translate persisted state into four plain-language stages; they never
displays raw enum values.

| Stage | Displays | Action |
|---|---|---|
| Discovery | found, supported, deferred | Continue |
| Plan Review | selected/deferred by type, object details, risks | Approve Plan / Reject Plan |
| Migration | live per-type progress, current operation, recent activity | automatic |
| Results | successful/deferred/failed, validation and warnings | Approve Migration / Rollback |

Every stage shows what is happening, what completed, what remains, and the next action. Only one
approval button can be active.

## Approval transactions

There are exactly two approvals.

**Approve Plan**:

1. persist the approval bound to assessment, plan, scope, target, and policy;
2. read and validate the record;
3. reload the assessment and verify the approval ID and artifact binding;
4. append `PLAN_APPROVED`;
5. transition directly to `MIGRATING` and start the unchanged bundle.

Failure transitions to `FAILED`; execution stops. A second click is
`INVALID_STATE_TRANSITION`. There is no separate Apply approval or button.

**Approve Migration** is available only after API validation passes and the review artifact exists.
It transitions `WAITING_FINAL_APPROVAL -> COMPLETED`.

## Persistence invariants

The assessment preserves identity, revision, totals, counters, approval evidence, current
operation, and next action. Identity changes or counter regression produce
`CORRUPTED_SESSION`; the candidate write is rejected and execution stops. Accounted resources may
never exceed discovered resources and final results must account for migrated, deferred, and failed
objects.

## Validation

API validation is required. Browser validation is optional and limited to 60 seconds. Missing,
failed, invalid, or timed-out browser evidence is recorded as `BROWSER_VALIDATION_SKIPPED`; it never
holds the assessment in validation and never blocks final approval.

## Failure and rollback

Failure UI shows Root Cause, Affected Resources, Resolution, and Available Actions. It does not show
a generic blocked label. UI transport failures never mutate assessment state.

Rollback is available only in Results. It transitions through `ROLLING_BACK`, uses the ownership
ledger in reverse dependency order, verifies deletion/restoration, and ends at `ROLLED_BACK`.
