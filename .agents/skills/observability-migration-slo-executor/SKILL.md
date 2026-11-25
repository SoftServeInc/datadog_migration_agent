---
name: observability-migration-slo-executor
description: Internal SLO adapter for the observability migration orchestrator. Classify Datadog SLOs, translate supported profiles into the shared execution bundle, and apply, resume, validate, or roll back without SLO-specific customer prompts.
---

# Observability Migration SLO Executor

This is an internal adapter, not a separate customer workflow. The current implementation creates
hash-bound Splunk Observability Cloud SLOs from a strict automatic profile.
Do not route ordinary detector waves, dashboards, event alerts, or unsupported SLO forms
through this skill.

## Default sequence

1. Classify every planned SLO; the strict profile may be `SUPPORTED`, while all other shapes remain
   explicit `PARTIAL`, `UNSUPPORTED`, or `BLOCKED` results without stopping other object types.
2. Rebuild and compare private IR, compile supported payloads, and run non-mutating target validation.
3. Contribute operations, source refs, semantic differences, assertions, and rollback intent to the
   shared execution bundle. Do not ask for a separate SLO confirmation.
4. After apply authorization, execute and validate automatically through the orchestrator. Resume when exact
   name and source-marker reconciliation is safe; record owned creates in the shared ledger.

## Automatic profile

- One Datadog metric SLO with one 30-day target and a warning threshold above the target.
- Good events are `A - B`; total events are `(A - B) + C`.
- Every term is a wildcard-scoped grouped `sum:metric{*} by {...}.as_count()` expression,
  and all terms use identical grouping.
- Exactly two burn-rate monitors reference that SLO: fast `1h/5m > 14.4` and slow
  `6h/30m > 6`, both over the same 30-day period.
- The target is a request-based rolling-window SLO. Its migrated burn-rate rule
  and Splunk-required breach rule are created disabled and notification-free.
- Datadog's warning display state has no direct target field in this profile and is
  recorded as an explicit difference. Automatic assurance never claims semantic
  equivalence or human review.
- Future SLO payloads preserve the validated source SLO name and include `[AI-Created]`
  plus the deterministic migration marker in the writable description.

All other SLO types, periods, formulas, scopes, alert windows, and thresholds fail closed.

## Safety invariants

- The live adapter exposes only organization GET, exact-name SLO search POST,
  non-mutating SLO validation POST, SLO create POST, and SLO GET.
- Updates, alert enablement, notifications, Terraform, browser mutation, and Git operations are absent.
  Owned cleanup is orchestrator-controlled and requires an explicit destructive request.
- Internal authorization binds the confirmed plan, immutable bundle, source refs, exact origin and
  organization hash, and operations. It is not an additional customer interaction.
- Session-wide and per-wave locks plus final cross-wave claim checks prevent local races.
- Search results are accepted only when the deterministic exact name and sealed payload
  match. Ambiguous create outcomes retain a pending intent and never trigger blind retry.
- Keep manifests, authorizations, checkpoints, payloads, SignalFlow, source IDs, and
  target IDs in the ignored private session directory and out of chat, Git, and audits.

Read [references/operation-guide.md](references/operation-guide.md) when operating a live
SLO wave. The entry point is:

```bash
python3 .agents/skills/observability-migration-slo-executor/scripts/slo_execution.py --help
```
