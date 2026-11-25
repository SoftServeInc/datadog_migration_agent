---
name: observability-migration-planner
description: Build the complete deterministic, dependency-aware plan used for migration Approval #1. Include every discovered object and explicit unsupported/deferred outcomes; never execute target changes or silently reduce scope.
---

# Observability Migration Planner

Turn a sanitized discovery assessment into the complete report and dry-run plan for Approval #1.

## Strategy selection

- `safe_staged`: direct or transformable objects with confidence at least 0.60, no missing dependency, and no dependency cycle.
- `full`: every discovered object, including redesign, manual, blocked, unsupported, partial, and deferred work. This is the orchestrator default.
- `customer_selected`: only explicitly supplied pseudonymous object references.

Generate a standalone plan:

```bash
python3 .agents/skills/observability-migration-assessment/scripts/migration_assessment.py \
  plan \
  --input <discovery-report.json> \
  --output /tmp/cisco-migration-plan/dry-run-plan.json \
  --strategy safe_staged
```

Use a dedicated private output directory. The command creates a missing directory with
mode `0700` and refuses a group/world-accessible parent.

For resumable end-to-end sessions, use the orchestrator. After the customer reviews the complete
report and policy, Approval #1 binds assessment, plan, scope, naming, conflicts, validation, and rollback hashes.

## Invariants

- Order resolved dependencies before dependents and surface cycles/missing dependencies.
- Every step must have `executable: false`; mutation lists must remain empty.
- Plan-review approval must retain `execution_authorized: false` and `external_mutations_authorized: false`.
- Do not create or update Splunk resources, generate/apply Terraform, run browser remediation, or perform Git writes.
- Execution requires orchestrator Approval #2 bound to the compiled immutable bundle and target.
- Internal waves, profiles, and adapter caps must never remove objects from a `full` plan.

Return strategy scope, selected/deferred counts, risks, validation and rollback expectations, plan hash, and the precise next approval boundary.
