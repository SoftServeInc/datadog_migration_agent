---
name: datadog-configuration-discovery
description: Internal read-only Datadog discovery adapter. Collect complete paginated configuration evidence under the run's audit authorization; do not add a customer approval, assess targets, or mutate Datadog.
---

# Datadog Configuration Discovery

Collect source evidence through the trusted standard-library adapter. Discovery is read-only and requires a current authorization registered in the same session checkpoint.

## Workflow

1. Require the automatically generated `authorization.local.json` containing `DATADOG_DISCOVERY`,
   exact Datadog origin binding, and an unexpired read-only run authorization.
2. Use a private temporary output directory and run:

   ```bash
   python3 .agents/skills/observability-migration-assessment/scripts/collect_datadog_configuration.py \
     --env-file .env \
     --authorization-file .migration-work/<session-id>/authorization.local.json \
     --output-dir <private-output-directory>
   ```

3. Record endpoint permission gaps without treating the whole discovery as successful or complete.
4. Keep `datadog-estate.local.json` local. It may contain raw IDs, names, expressions, ownership data, and PII.
5. Allow only `codex-context.json` or later pseudonymous IR/report artifacts into model context.

## Invariants

- Use GET only, the built-in Datadog host allowlist, no redirects, bounded retries/timeouts, response limits, and the 5,000-request hard ceiling.
- Do not print response bodies, headers, credentials, notification addresses, or raw errors.
- Cost endpoints stay disabled unless both authorization and invocation explicitly enable them.
- Duplicate and ownerless findings are review candidates, never deletion instructions.
- Never claim active telemetry usage from configuration presence alone.

Return counts, access coverage, safe limitations, artifact paths, and confirmation that zero mutations occurred.
