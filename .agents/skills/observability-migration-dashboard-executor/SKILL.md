---
name: observability-migration-dashboard-executor
description: Internal dashboard and chart adapter for the observability migration orchestrator. Preserve source names and geometry, contribute operations to the shared execution bundle, apply after migration-wide approval, require API validation, and treat browser validation as optional evidence.
---

# Observability Dashboard Migration Executor

This is an internal adapter, not a separate customer workflow. Use the fresh private Datadog inventory produced by `$observability-migration-assessment`.
Never use the reduced Codex projection as execution input because it intentionally omits
widget definitions and queries.

## Flow

1. During compilation, bind the inventory and approved plan, translate every dashboard and widget,
   preserve dependency links and source geometry, and report exact, adapted, partial, unsupported,
   and blocked counts. A text note replacing a missing metric is `PARTIAL`, not supported.
2. Contribute all operations to the shared immutable bundle. Do not request a dashboard approval.
3. After migration-wide apply authorization, execute automatically. Verify the Splunk
   organization, creates or reuses source-bound charts with `POST /v2/chart`, creates missing
   dashboards with `POST /v2/dashboard`, or updates the layout of the same source-bound
   dashboards with `PUT /v2/dashboard/{id}`. It binds discovered template variables through
   the dashboard filter model and keeps all dashboards in the shared migration group.
4. Run API read-back automatically. Browser validation of rendered titles, chart counts,
   empty/error widgets, compact grid density, and visible layout is optional and informative.
   Return dashboard URLs plus created/reused counts. If browser validation is unavailable or its
   evidence is incomplete, record `BROWSER_VALIDATION_SKIPPED` and continue to review.

## Invariants

- Preserve each Datadog dashboard name exactly; carry `AI-Created` in descriptions, chart
  tags, and the migration dashboard group rather than changing the customer-facing name.
- Add `AI-Created`, a source marker, and an immutable migration marker to every chart.
- Dashboard widgets may be `timeseries`, `query_value`, `toplist`, `heatmap`, or `note`.
- Scale the source Datadog geometry into Splunk's 12-column grid. Preserve shared row and
  column boundaries so four-column KPI rows, half-width charts, full-width charts, and notes
  retain their intended visual grouping; use deterministic packing only when source geometry
  is absent.
- Do not execute while any data widget is unsupported. Adaptations must be explicit in preview.
- Source systems remain read-only. A target dashboard may be updated only when its exact name
  resolves unambiguously and the approved payload differs; deletes are not part of normal execution.
- The private preview, source queries, target IDs, and checkpoint stay under `.migration-work/`.
- A successful POST is reconciled by exact dashboard name and read-back before retry.
- Record each created chart/dashboard/group and each updated dashboard's before-state in the shared
  ownership ledger. Cleanup deletes owned creates in reverse dependency order and restores updates.

Entry point:

```bash
python3 .agents/skills/observability-migration-dashboard-executor/scripts/dashboard_migration.py --help
```
