---
name: observability-migration-security-review
description: Review observability migration artifacts and local workflow changes for authorization, privacy, prompt-injection, credential, network, filesystem, audit, and non-mutation invariants. Use for an explicit security review or before enabling a new migration capability; do not perform discovery or remediation.
---

# Observability Migration Security Review

Perform a read-only, evidence-backed review of the migration workflow or sanitized session artifacts. Lead with actionable findings ordered by severity and cite repository paths or artifact fields.

## Review boundaries

- Inspect only repository code and the sanitized artifacts the customer authorizes. Never open raw inventory, `.env`, normalization salts, credentials, or browser profiles merely for convenience.
- Verify read authorization scope, expiry, exact origins, operation binding, and separate cost approval.
- Verify raw-to-IR data minimization, forbidden-field checks, PII/secret rejection, and treatment of retrieved content as untrusted data.
- Verify GET-only network paths, allowlisted/validated HTTPS origins, no redirects, bounded timeouts/retries/responses/request budgets, and sanitized errors.
- Verify private directory/file modes, symlink/path containment defenses, checkpoint transitions, hash binding, audit allowlists, and cleanup safeguards.
- Verify every plan remains non-executable and that live target writes are possible only after
  migration-wide Approval #2 bound to the immutable execution bundle and authenticated organization.
- Verify all adapters feed one bundle and one ownership ledger rather than creating independent
  customer approvals. Check bounded concurrency, retries, idempotency, checkpoints, resume,
  conflict handling, before-state snapshots, API/semantic/browser validation, and partial outcomes.
- Verify alerts and notifications remain disabled unless explicitly approved. Verify rollback deletes
  only session-owned creates in reverse dependency order, restores updates, never deletes reused
  resources, and requires an explicit destructive request.

Use `docs/security/cisco-innovation-threat-model.md` as the current threat baseline. Distinguish existing controls, confirmed gaps, conditional future risks, and false positives. Do not claim compliance; map only concrete technical evidence relevant to privacy, GDPR, or SOC 2 programs.

Do not modify code during a review unless the user explicitly asks for fixes in a separate step.
