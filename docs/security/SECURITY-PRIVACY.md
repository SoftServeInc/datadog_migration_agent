# Security and privacy guide

## Security posture

The migration workflow is local-first and single-customer. Phase 1 is assessment-only. Phase 2 has no network listener and exposes bounded creation of disabled, notification-free detectors and one strict SLO profile in the Splunk Observability Cloud organization selected by the provided environment access. Detector and SLO authorizations remain separate. Reviewing a plan does not authorize execution.

These controls support privacy-by-design, least privilege, auditability, and evidence collection relevant to GDPR and SOC 2 programs. They do not by themselves make the product or an organization GDPR-compliant or SOC 2-compliant.

## Data classification and handling

| Class | Examples | Handling |
|---|---|---|
| Secrets | API/app keys, tokens, cookies, authorization headers | Environment only; never chat, reports, state, audit, tests, or Git |
| Restricted customer configuration | Raw names, IDs, expressions, tags, notification bindings | Private local raw inventory; excluded from LLM context |
| Restricted translation manifest | Target names, SignalFlow, rules, tags, direct target IDs | Private local execution directory; excluded from chat and sanitized audit |
| PII | User names, email addresses, team ownership metadata | Minimize, redact, and replace with presence flags or pseudonyms |
| Sanitized assessment | Object references, enum classifications, counts, risks | May enter Codex context after fail-closed allowlist validation |
| Public project data | Documentation and synthetic fixtures | Repository-safe after review |

Raw inventory remains on the customer workstation. Direct identifiers are HMAC-pseudonymized with a per-session local salt before use by the rule engine or conversational layer. Object names, descriptions, expressions, and API content are always untrusted data, never instructions.

## Credentials and authorization

- Never ask a customer to paste a secret into chat.
- Use the same complete Splunk token/realm profile selected from the provided environment by both phases; optionally pin `SPLUNK_O11Y_ORG_ID`.
- The migration core parses dotenv syntax without shell execution or interpolation.
- Bind read authorization to exact origins and reject redirects or runtime origin changes.
- Billing and usage reads require separate approval.
- Plan-review approval is hash-bound and explicitly records `execution_authorized: false`.
- Each Phase 2 write authorization is a separate record bound to source session, plan review, sealed manifest, exact realm-derived origin and organization ID hash, selected refs, operation, wave cap, expiry, and fail-closed conflict policy. Runtime verifies `/v2/organization` before detector or SLO operations; it does not infer an environment classification.
- Local SHA-256 records detect accidental edits but do not authenticate against a same-user attacker. Keychain-backed signing or an external approval service can be added if stronger multi-user authorization becomes necessary.

## Network and filesystem controls

- Datadog hosts are selected from an allowlist; configured Splunk URLs must be absolute HTTPS URLs without embedded credentials.
- Phase 1 HTTP calls are GET-only. Phase 2 allows bounded detector or SLO reads, non-mutating validation POSTs, exact-name SLO search POST, and separately authorized create POSTs. Both clients bound timeouts/responses/retries, reject redirects, and derive the origin from a short validated Splunk realm.
- New detector and SLO manifest versions add a non-secret `AI-Created` provenance marker. Legacy immutable manifests remain readable; no existing target is updated to backfill the marker.
- Live preflight is capped at seven requests; collectors paginate at known endpoints and record permission gaps.
- Session directories are mode `0700`; files are mode `0600`.
- Atomic writes reject symlink destinations. Append-only audit opens use `O_NOFOLLOW` where supported.
- Repository output is not used for raw inventory, checkpoints, credentials, or private approvals; `.gitignore` excludes the local work area.

## Prompt-injection and output controls

Only strict allowlisted fields may enter Codex context. Forbidden keys include names, raw IDs, queries, formulas, filters, tags, messages, URLs, and authorization-like fields. PII and token patterns cause generation to fail closed. Compatibility rules contain only IDs, enum selectors, enum outcomes, and rationale codes; executable expressions and free-form rule fields are rejected.

Generated plans are proposals. Every step has `executable: false`, the mutation list is empty, and source/target mutation, Terraform apply, and Git write flags are false.

Phase 2 never sends a generated plan directly. Automatic translators consume only the Phase 1-bound private snapshot and seal exact payload hashes. Detector and SLO manifests accept only allowlisted disabled, notification-free effects and bind every source ref to the approved plan and wave. Mechanical assurance does not claim semantic equivalence.

## Audit, retention, and deletion

The local JSONL audits record allowlisted event types, outcomes, timestamps, session/approval references, non-sensitive counts, and explicit safety flags. They intentionally exclude raw payloads, SignalFlow, target names/IDs, error bodies, tokens, and actor PII.

The MVP provides a confirmation-gated `cleanup-session` command that validates exact work-root containment and rejects symlinks or special files. Filesystem deletion cannot guarantee physical erasure from SSD wear-leveling, snapshots, or backups. The MVP still lacks application-level encryption and externally immutable audit retention, so customers should use an approved encrypted volume, define a retention period, and control workstation backups.

## Legacy repository cautions

The repository's lab shell tooling predates the migration core and sources `.env` as shell in `scripts/lib.sh` and `scripts/verify-mcp.sh`. Treat those scripts as a separate trusted-operator boundary; do not reuse them for customer-supplied migration configuration. `.mcp.json` also allows an `npx -y` bridge with a pinned package version and a bearer-token argument. Preinstall and integrity-verify that dependency, and prefer native authenticated MCP transport before using it in a hardened customer workflow.

## Operational checklist

- Confirm single-customer session and approved work root.
- Review requested providers, origins, data categories, request impact, and expiry.
- Keep only minimum read scopes during discovery.
- Inspect sanitized report and limitations before selecting a strategy.
- Verify plan and assessment hashes before review approval.
- Do not interpret plan review as write approval.
- Before an execution wave, verify the authenticated organization hash, exact origin, manifest hash, refs, cap, expiry, disabled rules, and empty notifications.
- Treat marker conflicts or payload drift as blockers. Never overwrite an existing object.
- Treat an ambiguous POST as pending and never retry blindly. Clear a pending intent only after waiting for target consistency, a fresh exact-marker absence check, and explicit customer confirmation.
- Rollback is a proposal only; the executor has no delete method.
- Run tests and inspect diffs before changing trusted skill/core code.
- Never commit `.env`, local approvals, checkpoints, raw inventories, browser profiles, or Terraform state.
- Rotate credentials and review repository history if a real secret is ever found in tracked content.
