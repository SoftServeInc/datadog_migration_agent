# ADR-004: Unified execution bundle and consolidated orchestration

- Status: accepted and implemented
- Date: 2026-08-27

## Context

Detector, SLO, and dashboard executors evolved as separate safe workflows. Their individual
manifests, authorizations, wave caps, commands, and validation steps leaked into the customer
experience. The result required repeated approvals and did not scale to many resource types.

## Decision

Use one customer-facing orchestrator, a consolidated approval flow, one immutable execution
bundle, one dependency-aware scheduler, and one ownership/rollback ledger. Object-specific skills
are internal adapters. Internal batches and retries are never customer workflow steps.

Scope confirmation binds the complete report, plan, mappings, and policies. Apply authorization
binds the compiled bundle and authenticated target organization. API, semantic, and browser
validation run automatically after apply.

Every discovered object appears in a `full` plan. Unsupported and partial objects remain explicit.
Cleanup deletes only session-created objects; updates restore captured before-state; reused objects
are never deleted.

## Consequences

- Adding object types no longer adds approval gates.
- Large migrations can be internally paginated and batched while preserving one bundle hash.
- Resume and rollback become operation-level and dependency-aware.
- Adapter-specific CLIs may remain during transition but cannot be presented as customer phases.
- Compatibility bridges keep proven executor behavior while the generic scheduler owns dependency
  layers, retries, checkpoints, validation, ownership, and rollback.
