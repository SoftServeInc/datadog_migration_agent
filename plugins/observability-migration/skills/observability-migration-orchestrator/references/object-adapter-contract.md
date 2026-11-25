# Object adapter contract

The orchestrator owns workflow state, approvals, target binding, scheduling, checkpoints, and the
ownership ledger. Object adapters must not create customer-facing phases or approvals.

Each source adapter provides paginated discovery, stable source identity, normalized intent,
dependencies, geometry where relevant, and evidence limitations. Each target object adapter
provides these deterministic operations:

1. `classify(ir)`: return `SUPPORTED`, `PARTIAL`, `UNSUPPORTED`, or `BLOCKED` with reasons.
2. `plan(ir, target_inventory, policy)`: return create/update/reuse/no-op/defer intent.
3. `compile(operation)`: produce payload, dependencies, validation assertions, and rollback intent.
4. `validate_payload(payload)`: local and non-mutating target validation.
5. `apply(operation)`: idempotent mutation with bounded retries and ambiguous-create reconciliation.
6. `validate_result(operation, target)`: API, semantic, dependency, and visual checks as applicable.
7. `rollback(ledger_entry)`: delete owned creates or restore captured before-state for updates.

An adapter returns data for unsupported capabilities; it does not abort unrelated object types.
Adapter registration requires schema fixtures, unit tests, conflict tests, resume tests, and rollback
tests. Batch sizing, concurrency, and API throttling belong to the scheduler and never alter the
customer approval model.
