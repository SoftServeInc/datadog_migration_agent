# Security policy

## Reporting a vulnerability

Please **do not report security vulnerabilities through public GitHub issues, discussions,
or pull requests.**

Report them privately through GitHub's private vulnerability reporting:
open the repository's **Security** tab and choose **Report a vulnerability**.

Please include:

- a description of the issue and its impact,
- the affected component (demo deployment scripts, migration skill, MCP server, plugin),
- steps to reproduce or a proof of concept,
- the commit or release you tested.

Never include real API keys, tokens, or customer configuration in a report.

### What to expect

- Acknowledgement within **5 working days**.
- An initial assessment and planned next steps within **10 working days**.
- We will keep you informed of progress, agree a disclosure date with you, and credit you
  in the release notes unless you prefer otherwise.

## Supported versions

This project is maintained on a best-effort basis. Security fixes are made on the `main`
branch and included in the next release. Only the latest release is supported.

| Version | Supported |
|---|---|
| latest release / `main` | yes |
| older releases | no |

## Security model and scope

The security design is documented in:

- [docs/security/SECURITY-PRIVACY.md](docs/security/SECURITY-PRIVACY.md) - data
  classification, credential handling, approvals, network and filesystem controls,
  prompt-injection controls.
- [docs/security/cisco-innovation-threat-model.md](docs/security/cisco-innovation-threat-model.md) -
  assets, trust boundaries, attacker model, abuse paths.

Key points for users:

- Credentials are read only from your local `.env` / environment. They are never written
  to reports, state, audit logs, or Git.
- Discovery against Datadog is read-only. Writes to Splunk Observability Cloud require a
  separate, hash-bound, short-lived approval and are limited to creating disabled,
  notification-free detectors, one SLO profile, and dashboards.
- The demo deployment (`run.sh`) installs third-party tools and the upstream
  OpenTelemetry Demo into a local or disposable cluster. It is a demo, not a hardened
  production deployment.

## Dependencies and vulnerability management

- The Python code uses **only the Python standard library**; there are no third-party
  Python packages to track.
- The demo deploys the upstream `opentelemetry-demo` Helm chart at the version pinned in
  [versions.env](versions.env). Container images come from that upstream project; their
  vulnerabilities are handled upstream, and we bump the pinned chart version to pick up
  fixes.
- Command-line tools (`kubectl`, `helm`, `minikube`, `kind`, `podman`) are installed from
  their official sources by `scripts/install-tools.sh`.
- CI runs a Trivy filesystem scan (known vulnerabilities and leaked secrets) on every
  pull request, and Dependabot keeps GitHub Actions up to date. Accepted exceptions, if
  any, are recorded in this file.

Known accepted exceptions: none.
