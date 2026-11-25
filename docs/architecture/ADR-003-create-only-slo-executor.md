# ADR-003: Separate create-only SLO migration executor

- Status: Superseded as a customer workflow by ADR-004; retained as the legacy SLO-adapter record
- Date: 2026-08-27

## Context

> ADR-004 makes this executor an internal adapter. Its separate manifest remains an implementation
> detail during runtime consolidation and cannot add a customer approval.

Splunk SLOs use a distinct API, schema, permission set, validation endpoint, and
idempotency mechanism from detectors. Datadog metric SLOs can also reference separate
burn-rate monitors. Extending the detector adapter would blur authorization scope and
make rollback and resume state ambiguous.

## Decision

Add `observability-migration-slo-executor` with a separate manifest, authorization,
checkpoint, audit, adapter, and private `slo-execution/` namespace. The live adapter
allows only organization GET, SLO search POST, non-creating SLO validation POST, one SLO
create POST, and SLO GET. PUT and DELETE are absent.

The first automatic profile accepts one 30-day Datadog metric SLO whose good and total
events use a strict grouped count algebra, plus the standard fast and slow burn-rate
monitor pair. It creates one request-based rolling-window SLO with a migrated burn-rate
rule and the Splunk-required breach rule, both disabled and notification-free. The added
breach rule and the unrepresented source warning display state are explicit differences;
automatic assurance does not claim semantic equivalence.

New manifests add `[AI-Created]` to the writable SLO description as a provenance marker.
The API exposes SLO metadata as server-generated read-only state, so the executor does
not submit an unsupported tag field. Legacy v2 manifests remain readable for validation.

The deterministic exact name is used for idempotency. Existing resources are reused only
after exact payload comparison. Ambiguous create outcomes retain a pending intent and
never cause a blind second POST. A separate expiring authorization binds all three source
refs, the immutable source snapshot, exact target organization, cap 1, and operation.

## Consequences

- Detector and SLO permissions and state remain independently reviewable.
- Only the allowlisted SLO bundle is automatic; other periods, formulas, SLO types, and
  alert profiles remain unsupported.
- Created alert rules cannot notify until separately reviewed and enabled outside this
  executor.
- The original adapter exposed only a local cleanup proposal. ADR-004 now supplies owned deletion
  through the orchestrator cleanup path; reused SLOs remain outside rollback scope.
