# Schema contracts

The skill's machine-readable contracts live in `schemas/`:

- `inventory-ir.schema.json` — pseudonymous vendor-neutral objects and dependency graph.
- `discovery-report.schema.json` — compatibility findings, migration strategies, risks, and limitations.
- `migration-plan.schema.json` — hashed, non-executable proposed operations.
- `approval-record.schema.json` — read authorization or plan-review approval; neither permits mutations.
- `audit-event.schema.json` — allowlisted append-only local event shape.

Producers must emit the exact `schema_version` declared by each contract. Consumers must reject unsupported major versions and fail closed when a safety invariant changes. JSON Schema validation is an integration boundary; Python constructors and strict loaders remain the runtime enforcement boundary in the dependency-free MVP.
