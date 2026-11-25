# Roadmap

Planned work is tracked as GitHub Issues (label `roadmap`). This page summarises the
main themes; it is not a commitment to dates.

## Near term

- **Bind migration review to execution evidence.** Review generation must require a
  non-empty ownership ledger and `execution_enabled: true` before writing an
  `api_validation` verdict (see `docs/migration-triage-2026-09-02.md`, finding 1).
- **CI hardening.** Add Python version matrix coverage and publish test reports.
- **Plugin packaging.** Build the Codex plugin package in CI and attach it to
  GitHub Releases.

## Later

- Additional source/target object types (synthetics, log pipelines) beyond assessment.
- Optional stronger approval signing (keychain or external approval service), as noted in
  `docs/security/SECURITY-PRIVACY.md`.
- Terraform apply and Git publishing remain deliberately out of scope; import-only
  Terraform generation is supported.

## Proposing roadmap items

Open a *Feature request* issue describing the problem and the expected outcome.
