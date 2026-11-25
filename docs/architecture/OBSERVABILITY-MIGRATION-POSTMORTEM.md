# Datadog-to-Splunk migration POC postmortem

Date: 2026-08-27

## Outcome

The POC created valid Splunk resources but failed the requested operating model and visual/semantic
quality bar. An earlier v2 cleanup removed 12 detectors and 1 SLO. After the corrected objects were
recreated, the final v3 cleanup removed 72 charts, 6 dashboards, 12 detectors, 1 SLO, and 1 dashboard
group. Subsequent read-only inventories for both sessions resolved zero remaining session-owned
resources in every category.

No source Datadog objects were changed. Reused target resources were not part of the deletion scope.

## What went wrong

### Workflow and approvals

1. Internal phases and waves became customer commands (`start phase`, `execute wave`, SLO and
   dashboard approvals). Safety controls were designed per executor instead of once per migration.
2. Read-only authorization, payload preflight, SignalFlow validation, dashboard apply, and browser
   checks became unnecessary confirmation points and made the customer flow too interactive.
3. Detector, SLO, and dashboard executors had separate manifests, caps, checkpoints, and write
   authorizations. The orchestrator composed outputs but did not own one execution transaction.
4. Technical hashes, wave IDs, and commands were exposed to the customer instead of remaining audit
   evidence. The customer had to operate the implementation rather than approve business decisions.
5. Payloads and names changed after approval, forcing new hashes and repeated approvals.

### Scope and scalability

6. `safe_staged` and allowlisted translator profiles silently narrowed work. “Full” did not always
   mean every discovered object was represented.
7. Caps such as ten detectors per wave and one strict SLO profile were treated as process structure.
   They should have been internal scheduler limits and explicit unsupported outcomes.
8. The architecture lacked one generic adapter registry, execution bundle, rate limiter, cancellation
   path, progress model, and dependency-aware operation scheduler.
9. Missing target metrics could become text notes yet still appear in successful dashboard counts.
   This overstated migration fidelity; such widgets are partial.

### Names and semantics

10. Detector names mechanically copied Datadog templates such as `{{host.name}}`,
    `{{service.name}}`, and `[operation:...]`, which are not readable Splunk detector names.
11. Dashboard names were initially modified with migration/AI suffixes instead of matching Datadog.
12. Mechanical query translation was applied even when semantic-review flags were false. API
    acceptance and read-back proved payload persistence, not behavioral equivalence.
13. Conflict behavior and source-to-target naming policy were not finalized before compilation.

### Dashboard implementation and validation

14. Initial layout generation ignored Datadog coordinates and packed charts into a fixed three-column
    grid. Four-KPI rows became 3+1, half-width charts became thirds, and note widgets occupied excessive
    space.
15. API validation counted objects but did not validate rendering, compactness, or visual grouping.
16. Browser review happened after the incorrect dashboards were already applied. Browser access and
    dashboard-group navigation also caused the user to perceive dashboards as missing.
17. Dashboard create/update bookkeeping could overwrite original ownership disposition, weakening
    deterministic cleanup evidence.

### Rollback, documentation, and implementation consistency

18. Rollback was initially a proposal rather than an executable owned-resource operation. Cleanup
    depended on a temporary one-off script.
19. There was no shared ownership ledger for created, updated, reused, and no-op resources, and no
    before-state snapshots for updates.
20. Documentation contradicted implemented behavior: it described create-only/no-browser support
    while dashboard updates and browser checks had appeared elsewhere.
21. Retries, throttling, and ambiguous-create handling were inconsistent across executors.
22. IaC/Git capabilities from the long-term design were discussed but not implemented; the boundary
    was not always clear in status reporting.

## Root causes

- Safety was implemented locally in each object executor before the customer journey was fixed.
- Object-specific prototypes became orchestration primitives instead of adapters.
- Acceptance criteria emphasized API correctness and mutation safety more than semantic and visual
  fidelity.
- The full source inventory was not the invariant input to a single compilation transaction.
- Rollback and ownership were added after writes rather than designed as part of every operation.

## Corrective actions completed

- Defined a consolidated approval lifecycle and resumable state machine.
- Made the orchestrator the only customer-facing migration skill.
- Reclassified executor skills as internal object adapters and disabled their implicit invocation.
- Added shared execution-bundle and ownership-ledger schemas plus an adapter contract.
- Implemented the shared scheduler, immutable apply-authorization binding, bounded concurrency/rate limiting, safe
  retries, partial-failure continuation, resume, adapter bridges, and reverse-order rollback.
- Defined complete-scope semantics: all discovered resources remain represented.
- Added deterministic detector-name normalization for Datadog placeholders and operation prefixes.
- Required source-geometry dashboard mapping and browser validation of every dashboard.
- Classified missing-metric placeholders as partial.
- Added repository-owned cleanup supporting charts, dashboards, groups, detectors, and SLOs with
  provenance checks, reverse dependency order, and absence verification.
- Updated architecture, agent instructions, and tests to match the new contract.

## Required before the next large migration

1. Replace compatibility batch bridges with native per-resource operations where finer parallelism
   or cross-type dependencies are required; this does not change the customer flow.
2. Add update before-state capture/restore to any future adapter that introduces updates.
3. Expand adapter conformance tests for pagination, vendor rate-limit headers, conflicts,
   partial failure, resume, semantic validation, and rollback.
4. Add remaining object adapters (synthetics, log pipelines/indexes, integrations, roles/teams, and
   other requested types) as explicit supported/partial/unsupported capabilities.
5. Run a non-production rehearsal using the same volume and object-type mix expected in production,
   then review one report and one immutable bundle before live apply.
