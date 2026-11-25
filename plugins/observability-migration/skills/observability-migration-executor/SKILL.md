---
name: observability-migration-executor
description: Internal detector adapter for the observability migration orchestrator. Classify and translate supported Datadog monitors, contribute operations to the shared execution bundle, then apply, resume, validate, and roll back through the orchestrator without detector-specific customer prompts.
---

# Observability Migration Executor

This is an internal adapter, not a customer-facing workflow. The orchestrator owns customer decisions,
the immutable execution bundle, scheduling, target binding, ownership ledger, and final report.
Never ask for a detector, SignalFlow, preflight, authorization, phase, or wave approval.

## Default low-friction sequence

1. Classify every planned monitor. Emit `SUPPORTED`, `PARTIAL`, `UNSUPPORTED`, or `BLOCKED` with
   a reason; never silently reduce scope to a wave cap.
2. Deterministically translate supported monitor intent and contribute dependency, payload,
   validation assertions, and rollback intent to the shared execution bundle.
3. Run local and target non-mutating validation during compilation. Keep unsupported query shapes
   as explicit bundle results; do not ask the customer to edit generated JSON.
4. After migration-wide apply authorization, let the orchestrator schedule internal batches, call the
   existing execution engine, checkpoint each operation, and reconcile ambiguous creates.
5. API-read back every detector and run semantic assertions. Return results to the orchestrator;
   do not produce a separate customer report.

Use `prepare-manifest` plus `seal-manifest` only as a manual fallback for unsupported
query shapes or customer-authored SignalFlow.

## Safety invariants

- The current live adapter implements detector validation, create, read-back, and owned cleanup;
  unsupported update semantics must be represented as `DEFER`, never simulated by duplicate create.
- Every detector uses a deterministic human-readable target name. Remove source-only placeholders
  such as `{{host.name}}` and preserve operation context without `[operation:...]` syntax. Keep the
  exact source name only in the private mapping artifact. Include `AI-Created` and a deterministic
  marker tag. Existing
  resources are reused only when the marker and approved payload fingerprint match;
  any ambiguity or drift fails closed.
- Before detector operations, read the authenticated organization and require its ID to
  match the organization hash captured by the write authorization.
- Internal write authorization binds the source session, confirmed plan, bundle, target organization,
  operations, and expiry. It is not a customer interaction.
- The local draft and sealed manifest contain restricted customer configuration. Keep
  them in the ignored private session directory and out of Codex context, logs, Git,
  issue trackers, and audit events.
- Tests use fake adapters only; live writes occur solely in orchestrator execution after apply authorization.
- Automatic translation accepts a simple Datadog metric threshold profile, a grouped
  scalar-minus-mean profile restricted to constants 1 or 100, and a filtered grouped
  two-stream `as_rate()` ratio profile. The ratio profile requires bounded `IN` or simple
  tag filters, identical grouping on both terms, one top-level division, a bounded time
  window, and a numeric threshold. Other composites, ratios, forecast, anomaly, SLO,
  log, or event queries remain pending.
- Automatic entries record mechanical translation assurance, not human semantic review
  or semantic equivalence. Their target names and severity are deterministic and do not
  consume unbound source metadata.

## Commands

Use the operation guide in `references/operation-guide.md`. The entry point is:

```bash
python3 .agents/skills/observability-migration-executor/scripts/migration_execution.py --help
```

Return structured adapter results to the orchestrator. Never print tokens, raw payloads,
SignalFlow, response bodies, or direct identifiers.
