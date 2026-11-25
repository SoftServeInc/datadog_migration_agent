# Observability migration verification checklist

The plugin uses one lightweight checklist widget backed by the persisted assessment checkpoint.
Every visible action must be derived from authoritative `availableActions`.

- [ ] Discovery creates a valid `DISCOVERY` checkpoint.
- [ ] Discovery completion transitions only to `PLAN_REVIEW`.
- [ ] Plan review exposes only the plan-review action.
- [ ] Plan approval persists and verifies approval before entering `MIGRATING`.
- [ ] Migration never exposes approval actions while execution is active.
- [ ] Validation transitions to `REVIEW_READY` and then `WAITING_FINAL_APPROVAL`.
- [ ] Final approval transitions to `COMPLETED`.
- [ ] A failure records `error_code`, `error_message`, `actual_state`, and a safe recovery target.
- [ ] Failed execution exposes `retry` only when a retry target is persisted.
- [ ] Failed execution exposes `rollback` only when session-owned mutations exist.
- [ ] Recovery uses the same session and approved bundle; discovery is not restarted.
- [ ] Rollback failure remains recoverable through the persisted rollback path.
- [ ] Stale or repeated actions return the authoritative state and never invent actions.
- [ ] Legacy checkpoint schemas are rejected with no fabricated recovery action.
- [ ] Checklist resource loads through `resources/list` and `resources/read`.
- [ ] Checklist renders only valid actions and shows diagnostics on failure.
- [ ] Transport errors do not fabricate a workflow state or action.
- [ ] Python compilation, shell syntax, backend tests, and repository audit pass.
