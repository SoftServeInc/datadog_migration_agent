# Operation guide

This is an internal adapter command reference. Run `prepare-preview` during compilation without
target writes. After migration-wide apply authorization, the orchestrator runs
`execute --confirm-execution`, API validation, and browser validation automatically.

The preview is private. Command output contains only counts, hashes, and local paths.

Execution uses the universal chart and dashboard APIs, not `/dashboard/simple`, because the
simple endpoint can be unavailable when the dashboard-views entitlement is enabled.

The adapter writes `dashboard-apply-checkpoint.local.json` after every group, chart, and dashboard
mutation. It preserves the original `created` or `updated` disposition across resume, captures the
before-state of updates, and refuses blind retries for unresolved create intents. Exact-name
dashboards are updated only when their private source marker proves migration ownership.
