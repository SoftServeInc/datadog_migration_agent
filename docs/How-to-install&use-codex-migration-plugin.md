# How to install and use the Codex migration plugin

## Purpose

`observability-migration` is a local Codex plugin that discovers Datadog observability
configuration, prepares a governed migration to Splunk Observability Cloud, applies the approved
bundle, and validates the result through APIs and browser inspection.

The customer-facing entry point is `$observability-migration-orchestrator`. Detector, SLO,
dashboard, and assessment skills are internal adapters and should not be invoked as separate phases.

## Requirements

- Codex desktop app with plugin and native MCP tool confirmations.
- Python 3.
- Network access to the configured Datadog and Splunk endpoints.
- A customer project containing a local `.env` file.
- A signed-in Splunk browser session when visual dashboard validation is required.

Keep credentials outside the plugin. Never add `.env`, API keys, tokens, raw inventories, or
`.migration-work/` to the plugin archive or source control.

## Verify the local installation

The plugin is installed correctly when this command reports `installed, enabled`:

```bash
codex plugin list
```

After installation or an update, restart Codex and use a new chat so the updated skills are loaded.

## Transfer to another computer

Distribute the repository through your approved Git host, or create a marketplace bundle from the
repository root. The bundle must contain both the plugin and its marketplace descriptor:

```bash
tar -czf observability-migration-marketplace.tgz \
  .agents/plugins/marketplace.json \
  plugins/observability-migration
```

Transfer the archive through an approved private channel. On the destination computer, extract it
to a dedicated directory:

```bash
mkdir -p "$HOME/cisco-innovation-plugin"
tar -xzf observability-migration-marketplace.tgz \
  -C "$HOME/cisco-innovation-plugin"
```

Register that local marketplace, install the plugin, and verify it:

```bash
codex plugin marketplace add "$HOME/cisco-innovation-plugin"
codex plugin add observability-migration@cisco-innovation
codex plugin list
```

For a Git checkout, pass the repository root to `codex plugin marketplace add` and use the same
plugin-add command. Keep `.env` in each customer's workspace; never place credentials in the bundle.
Restart Codex and open a new task after installation or an update.

## Configure customer access

Create `.env` in the customer project. A standard Datadog-to-Splunk configuration uses:

```dotenv
DD_API_KEY="..."
DD_APP_KEY="..."
DD_SITE="datadoghq.eu"

SPLUNK_O11Y_REALM="eu1"
SPLUNK_O11Y_ACCESS_TOKEN="..."
# Optional exact organization pin:
SPLUNK_O11Y_ORG_ID="..."
```

The project may instead use the complete
`SPLUNK_O11Y_INNOVATIONLAB_TOKEN` and `SPLUNK_O11Y_INNOVATIONLAB_REALM` pair. Do not configure a
partial credential pair. The plugin parses `.env` as data and must never source it as shell code.

## Start a migration

Open the customer project in Codex, create a new chat, and send:

```text
Use $observability-migration-orchestrator.

Analyze all accessible observability objects in Datadog, prepare their migration to Splunk
Observability Cloud, apply the migration after the required customer confirmation, and validate
the result through both APIs and the browser. Use credentials from this project's .env file.
```

The orchestrator automatically handles discovery, compatibility analysis, naming, compilation,
dependency ordering, internal batching, retries, checkpoints, API read-back, dashboard browser
inspection, and final reporting. Internal phases and waves are not customer commands.

Selecting `Observability Migration` from the plugin picker is also sufficient. With a valid `.env`
in the workspace root, the plugin defaults to Datadog as source, Splunk Observability Cloud as
target, full accessible scope, and the organization returned by authenticated Splunk access. It
starts read-only discovery immediately instead of displaying a setup questionnaire.

The plugin opens one compact checklist widget for Discovery, Plan review, Migration, and Results.
It renders only authoritative actions from MCP tool results.

```text
Discovery ⏳ · Plan ○ · Migration ○ · Results ○
```

Detailed inventories, hashes, mappings, and evidence stay in report artifacts rather than filling the chat.

The plugin provides starter choices for **Full migration**, **Supported subset**, and
**Assessment only**. Select a scenario instead of typing internal strategy values. Decisions are
returned through MCP tool results and native confirmation controls. The customer is never expected
to enter `full`, `safe_staged`, phase names, wave IDs, or executor commands.

After the report, the orchestrator calls the local `apply_migration_bundle` action. Tool results provide:

- totals and compatibility counts;
- **Full migration** and **Supported subset** choices with selected/deferred impact;
- **Approve plan** and **Reject** actions.

Scope approval transactionally persists the plan, compiles the exact bundle, and starts the approved
migration. The final result shows API validation and optional browser validation, then exposes
**Approve migration** or **Rollback** through native Codex tool confirmations.

## Expected behavior

- Datadog remains read-only.
- Dashboard names preserve compatible source names.
- Target resources receive `AI-Created` provenance without adding it to dashboard names.
- Detectors remain disabled and notification-free unless the approved plan explicitly says otherwise.
- Unsupported or partial translations remain visible in the report instead of being silently skipped.
- Rollback and cleanup affect only resources proven owned by the migration session.

## Remove migration-created resources

In the same customer project, send:

```text
Use $observability-migration-orchestrator. Delete all resources created by this migration and
marked AI-Created. Preserve every unrelated Splunk resource and verify absence through the API.
```

The cleanup must use the session ownership ledger, verify target provenance, delete in dependency
order, and report zero remaining session-owned resources.

## Troubleshooting

### The skill is not available

1. Run `codex plugin list`.
2. Confirm `observability-migration@cisco-innovation` is `installed, enabled`.
3. Restart Codex.
4. Start a new chat.

### Credentials are rejected

- Confirm both Datadog keys and the correct Datadog site are configured.
- Confirm the Splunk realm matches the access token's organization.
- Remove incomplete alternative credential pairs.
- Never paste token values into chat or logs.

### Dashboards exist through the API but look incorrect

Keep the migration session open and request browser validation of every dashboard. The final report
should distinguish API persistence from visual correctness, compactness, and semantic fidelity.

### A run is interrupted

Ask the orchestrator to resume the existing session. Do not start object-specific waves manually;
the immutable bundle, checkpoint, and ownership ledger determine safe continuation.

### The summary says `zero external mutations`

Nothing has been created yet. Continue only through the compact migration review. If a stale chat
asks you to type an approval phrase, restart Codex and start a new chat so it loads the updated
plugin. Do not continue with that stale task.
