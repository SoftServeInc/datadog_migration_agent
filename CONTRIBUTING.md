# Contributing to cisco-innovation

Thanks for your interest in improving this project. This guide explains how to report
problems, propose changes, and get a pull request merged.

## Ways to contribute

- **Report a bug.** Open an issue using the *Bug report* template. Include what you ran,
  what you expected, what happened, and your environment (OS, cluster type, container
  engine, chart version from `versions.env`). Never paste API keys, tokens, or raw
  customer configuration into an issue.
- **Suggest an improvement.** Open an issue using the *Feature request* template and
  describe the problem before the solution.
- **Report a security vulnerability.** Do **not** open a public issue. Follow
  [SECURITY.md](SECURITY.md).
- **Submit a pull request.** For anything larger than a small fix, open an issue first so
  the approach can be agreed before you invest time.

## Development setup

Requirements are listed in the README ([Requirements](README.md#requirements)). For code
changes you only need:

- `python3` 3.10 or newer (the Python code uses the standard library only)
- `bash` and, ideally, [`shellcheck`](https://www.shellcheck.net/)
- `make` (optional; every target wraps a plain script)

```bash
git clone <repository-url> && cd cisco-innovation
cp .env.example .env        # only needed to deploy the demo or run live migrations
make test                   # Python test suite
make check                  # bash syntax check + shellcheck
diff -rq -x __pycache__ -x '*.pyc' .agents/skills plugins/observability-migration/skills   # plugin copy matches
```

You do not need any Datadog or Splunk credentials to run the tests; they use synthetic
fixtures and local emulators.

## Repository layout and conventions

- `.agents/skills/` is the **source of truth** for the migration skills.
  `plugins/observability-migration/skills/` is a distribution copy. After changing a skill,
  apply the same change to the plugin copy and commit both trees; CI fails if they differ.
- Python: standard library only, type hints, small pure functions in the `*_core`
  packages, deterministic output (sorted keys, stable hashes). Do not add third-party
  dependencies without discussing it in an issue first.
- Shell: `set -euo pipefail`, bash 3.2 compatible (macOS default), quote every expansion,
  keep `shellcheck -x -S warning` clean. Shared helpers live in `scripts/lib.sh`.
- Never commit `.env`, tokens, raw provider inventories, migration session folders
  (`.migration-work/`, `.observability-migration*/`), or build output (`dist/`). The
  `.gitignore` covers these; please don't force-add them.
- Architecture decisions are recorded as ADRs in `docs/architecture/`. Add a new ADR for
  changes to the safety model (approvals, mutation scope, credential handling).

## Required checks

Every pull request must pass the CI workflow (`.github/workflows/ci.yml`):

1. Python tests: `python3 -m unittest discover -s tests`
2. Shell lint: `bash -n` and `shellcheck -x -S warning` on `run.sh` and `scripts/*.sh`
3. Plugin copy in sync: `diff -rq -x __pycache__ -x '*.pyc' .agents/skills plugins/observability-migration/skills` prints nothing

Please run them locally before pushing. Add or update tests for any behaviour change.

## Pull request process

1. Fork the repository (external contributors) or create a branch (maintainers).
2. Keep pull requests focused; one logical change per PR.
3. Fill in the pull request template, link the related issue, and describe how you tested.
4. At least one maintainer review is required. Maintainers aim to respond within
   10 working days.
5. Changes are merged with squash-merge once CI is green and review comments are resolved.

## Commit messages

Use short, imperative subject lines (`Fix SLO window parsing`). Conventional-commit
prefixes (`feat:`, `fix:`, `docs:`) are welcome but not required.

## AI-assisted contributions

Parts of this project were written with AI coding assistants (OpenAI Codex, Claude Code),
and the repository ships configuration for them (`.codex/`, `.claude/`).
AI-assisted contributions are welcome, provided that you review and understand every line
you submit, you have the right to submit it under the project license, and it does not
reproduce third-party code with incompatible licensing.

## Licensing of contributions

This project is licensed under the [Apache License 2.0](LICENSE). By submitting a
contribution you agree that it is licensed under the same terms (Apache-2.0, section 5).

We use the [Developer Certificate of Origin (DCO)](https://developercertificate.org/)
instead of a CLA. Sign off each commit to certify that you wrote the change or otherwise
have the right to submit it:

```bash
git commit -s -m "Fix SLO window parsing"
```

This adds a `Signed-off-by: Your Name <you@example.com>` line to the commit message.

## Code of conduct

Participation in this project is governed by our [Code of Conduct](CODE_OF_CONDUCT.md).

## Questions

Open an issue with the *question* label, or see [MAINTAINERS.md](MAINTAINERS.md) for who
maintains the project.
