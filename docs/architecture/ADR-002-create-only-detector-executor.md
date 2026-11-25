# ADR-002: Separate create-only detector migration executor

- Status: Superseded as a customer workflow by ADR-004; retained as the legacy detector-adapter record
- Date: 2026-08-27

## Context

> ADR-004 makes this executor an internal adapter. Its wave and authorization details no longer
> define customer interactions; orchestrator apply authorization and owned cleanup govern execution.

ADR-001 deliberately ended at a reviewed non-executable plan. Phase 2 needs to prove
write-side architecture without turning a read-only approval into mutation authority.

The Phase 1 plan is pseudonymous by design and excludes source names and expressions. It
therefore cannot be converted safely into a target payload by itself. Detector creation
also has side effects beyond persistence: enabled rules and recipients can create alerts
and notifications.

## Decision

Add `observability-migration-executor` as a separate project skill and deterministic
`execution_core`. Do not add write methods to `assessment_core.TargetProvider` or extend
the Phase 1 state machine past `PLAN_APPROVED`.

The first adapter supports only Splunk Observability Cloud `CREATE_DETECTOR` in the
organization authenticated by the configured environment access. Inputs are a valid Phase 1 session, its
review approval, a customer-completed private translation manifest, and a separate
expiring write authorization. The authorization also binds the expected organization ID
hash, and runtime reads `/v2/organization` before detector operations. Every rule must be
disabled and notification-free.

Sealing the manifest adds deterministic markers and hashes each payload. Execution
searches for the exact marker before each POST, reuses only an equivalent object, and
fails closed on duplicates or drift. A retriable ambiguous POST is reconciled by tag; if
the object is not visible, execution records a pending create and stops without another
POST. Clearing an unresolved intent requires a separate confirmation and fresh exact-tag
absence check; that command performs no POST. Checkpoints are saved after each object. Validation reads each
target back and compares the sealed fields. A per-wave lock serializes resume operations,
while a session-wide lock and final cross-wave claim check prevent two local waves from
creating the same source object.

The original detector adapter intentionally had no update, delete, enable, arbitrary URL,
browser, Terraform apply, or Git interface. ADR-004 now supplies owned deletion through the
orchestrator cleanup path while leaving detector updates and enablement unsupported.

## Consequences

- The assessment boundary remains stable and independently testable.
- Restricted payloads remain local and excluded from Codex context and sanitized audit.
- Exact organization-ID binding detects a token/realm accidentally changed after
  authorization. The executor intentionally makes no environment classification;
  it uses the same complete Splunk token/realm profile selected from the provided
  environment by Phase 1.
- Unkeyed local hashes detect accidental tampering but do not authenticate a same-user
  attacker. A keychain-backed signature or external approval service may be added if the
  deployment later requires stronger multi-user authorization.
- Dashboard, log, event, forecast, Splunk Platform, and Terraform capabilities require
  later ADRs and contract tests. SLO creation is isolated in ADR-003 and its own executor.
  Automatic detector translation remains restricted
  to the allowlisted profiles documented by the executor skill and its contract tests.
