---
name: observability-compatibility-assessment
description: Classify pseudonymous observability IR objects against configured Splunk targets using declarative compatibility rules, confidence, risk, effort, target representation, validation, and rollback guidance. Use after normalization; do not read raw customer inventory or generate executable plans.
---

# Observability Compatibility Assessment

Evaluate a privacy-safe IR against Splunk Observability Cloud, Splunk Platform, or both. Configuration presence proves access readiness only, never semantic equivalence.

## Workflow

```bash
python3 .agents/skills/observability-migration-assessment/scripts/migration_assessment.py \
  assess-compatibility \
  --inventory-ir <inventory-ir.json> \
  --capability-catalog <capability-catalog.json> \
  --target both \
  --output-dir <private-session-directory>
```

If a live capability catalog is unavailable, omit it and use sanitized offline preflight status. The command writes `discovery-report.json` and `discovery-report.md`.

## Decision model

- Compatibility: `DIRECT`, `TRANSFORMABLE`, `PARTIAL`, `REQUIRES_REDESIGN`, `MANUAL`, `UNSUPPORTED`, `UNKNOWN`, `BLOCKED_BY_PERMISSIONS`, or `BLOCKED_BY_DEPENDENCY`.
- Disposition: `MIGRATE`, `ADAPT`, `REDESIGN`, `RETIRE`, `SKIP`, or `DEFER`.
- Apply target access gates before ordered rules in `compatibility-rules.v1.json`.
- Rules contain selectors, enum outcomes, and rationale codes only; reject free-form executable expressions.
- Never infer `RETIRE` from age, missing owner, or absent activity evidence.

Report evidence class, confidence score, complexity, risk, effort, dependencies, proposed target representation, validation strategy, rollback strategy, assumptions, and limitations. Clearly state that no semantic equivalence was proven and no resources were changed.
