# Provider interface specification

Provider code is a trusted extension boundary. The executable MVP protocols are in `scripts/assessment_core/interfaces.py`; schemas are in `schemas/`.

## Read-side contracts

### SourceProvider

- `provider_id`: stable lowercase identifier.
- `preflight()`: returns credential presence, validated origins, and permission status without secret values.
- `discover_read_only()`: performs only explicitly authorized read operations and returns a provider-local inventory.

### TargetProvider

- `provider_id`: stable lowercase identifier.
- `preflight()`: checks assessment access without creating probe objects.
- `capabilities()`: returns evidence-backed capability statuses; it must never infer semantic equivalence from credential presence.

### InventoryNormalizer

- `normalize(inventory, salt)`: treats inventory as untrusted, emits the versioned pseudonymous IR, and fails closed on forbidden fields.

## Decision contracts

### CompatibilityRule

Rules use JSON enum selectors and rationale codes only. No Python, shell, template, URL, or free-form expression is permitted. First matching rule wins after the target-access gate.

### ApprovalGate and AuditLogger

Approval validation must bind actor role, operation, target, data categories, exact origins or plan hashes, expiry where relevant, and the invariant that external mutation is false. Audit accepts only allowlisted event types, outcomes, references, and integer counts.

## Future write-side contracts

Write interfaces must live in a separate package and cannot be added to `SourceProvider` or the read-only `TargetProvider`. A future `MigrationExecutor` must accept an immutable plan, a separate expiring write authorization, a bounded wave, idempotency keys, conflict policy, and rollback scope. A `Validator` returns typed semantic comparisons; `RemediationProposal` is data only; `IaCGenerator` writes only inside an approved empty/staged directory; and `PolicyEngine` verifies every transition.

New adapters require source and license review, pinned dependencies, synthetic contract tests, a security diff, and explicit activation. Customer-specific rules remain local to the session until reviewed for promotion.
