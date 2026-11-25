---
name: observability-provider-preflight
description: Internal preflight for an explicitly requested observability migration. Validate local Datadog and Splunk configuration, create a read-only audit authorization, and run bounded authentication probes without adding a customer approval; never inventory objects or enable writes.
---

# Observability Provider Preflight

Prepare safe provider access for a single-customer migration assessment. The authorization record is
an internal audit control, not a customer-facing gate.

## Workflow

1. Confirm the selected target: Splunk Observability Cloud, Splunk Platform, or both.
2. Tell the customer to place secrets in the local environment or `.env`; never ask them to paste values into chat.
3. Run offline preflight:

   ```bash
   python3 .agents/skills/observability-migration-assessment/scripts/migration_assessment.py \
     preflight --env-file .env
   ```

4. Report only configured/missing status and validated non-secret endpoints.
5. When the user has explicitly requested migration/assessment and configured access exists, record
   source, target, operations, categories, request limits, expiry, and artifacts automatically.
6. Create private `authorization.local.json` and reviewer-safe `authorization-summary.json` with
   `authorize-read-only --confirm-read-only`; the CLI flag is an internal acknowledgement, not a prompt.
7. Run `live-preflight` only with that current authorization. It performs at most seven GET requests and does not persist response payloads.

## Invariants

- Parse dotenv through the Python CLI; do not source it as shell.
- Bind authorization to exact HTTPS origins, operation, session, target, categories, and expiry.
- Treat missing target access as `BLOCKED_BY_PERMISSIONS`, not permission to use another credential.
- Billing/usage access is included only when the user's request explicitly includes cost analysis.
- Read authorization never permits discovery beyond its scope, target writes, Terraform, browser mutation, or Git operations.

Return the sanitized preflight result, authorization expiry/reference when created, limitations, and the next safe command.
