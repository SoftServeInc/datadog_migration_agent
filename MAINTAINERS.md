# Maintainers

## Owner

This project is owned and maintained by **SoftServe**.

| Role | Name | Contact |
|---|---|---|
| Lead maintainer | Dmytro Budko (SoftServe) | GitHub Issues; private matters: `CONTACT_EMAIL_TO_BE_ADDED` |
| SoftServe sponsor | to be confirmed | - |

Security reports go through GitHub private vulnerability reporting, see
[SECURITY.md](SECURITY.md).

## Responsibilities

| Area | Responsible | Expectation |
|---|---|---|
| Issue triage | Lead maintainer | New issues labelled within 10 working days |
| Pull request review | Maintainers | At least one maintainer approval before merge |
| Releases | Lead maintainer | Tagged releases with notes in [CHANGELOG.md](CHANGELOG.md) |
| Dependency updates | Lead maintainer | Review Dependabot PRs; bump `versions.env` deliberately |
| Vulnerability handling | Lead maintainer | Follow the timelines in [SECURITY.md](SECURITY.md) |

## Releases and published artifacts

- Releases are created as Git tags (`vMAJOR.MINOR.PATCH`) with GitHub Releases.
- The Codex plugin package is built from `plugins/observability-migration/` and,
  when distributed, attached to the GitHub Release by the lead maintainer. Release
  artifacts are not committed to the repository (`dist/` is ignored).
- No container images, package-registry packages, or hosted demos are published by this
  project, so there are no publishing accounts or operating costs to maintain.

## Recommended repository settings

- `main` is protected: pull requests required, at least 1 approving review, CI
  (`ci.yml`) must pass, no force-pushes or deletions.
- Squash-merge only; DCO sign-off expected on commits.
- GitHub secret scanning, push protection, private vulnerability reporting, and
  Dependabot alerts enabled.
- GitHub Actions default token permission: read-only. Workflows from forks run without
  secrets (the CI workflow uses `pull_request`, never `pull_request_target`).

## If maintenance ends

If SoftServe stops maintaining the project, the maintainers will:

1. state this at the top of the README and in a pinned issue,
2. try to hand the project over to an interested maintainer or organization, and
3. otherwise archive the repository (read-only) so it stays available under its license.
