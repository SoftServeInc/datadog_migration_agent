# Agent environment: MCP servers and APIs

This is the read/write path the migration skills run on. It is separate from the
demo itself: the collector fans telemetry *out* to Datadog and Splunk, while the
connections described here let an agent reach *into* both to inventory what
exists and build the equivalent on the other side.

```
                   ┌── datadog MCP ───────────► dashboards, monitors, SLOs, metrics
  migration skill ─┼── splunk-o11y MCP ───────► APM, metrics, detectors, SignalFlow
                   └── splunk-platform MCP ───► SPL search, saved searches, KOs
```

Three MCP servers, configured entirely through environment variables so nothing
secret is ever committed. Two clients are supported and share one set of
credentials:

| Client | Config | Maintained by |
|---|---|---|
| Claude Code | [`.mcp.json`](../.mcp.json) | committed as-is; interpolates `${VAR}` at read time |
| Codex CLI / IDE | [`.codex/config.toml`](../.codex/config.toml) | `scripts/render-codex-mcp.sh` |

**Check your setup at any point:**

```bash
scripts/verify-mcp.sh
```

This is client-agnostic — it tests the endpoints and credentials both clients
sit on. Every check reports `ok`, `·` (skipped, not configured) or `fail`. An
empty `.env` is a clean run with everything skipped; you only have to configure
the backends you actually have.

---

## The one thing that catches everyone

Both clients expand variables from the **shell environment**, not from `.env`.
Sourcing `.env` inside `run.sh` is not enough. Export them before launching:

```bash
set -a; source .env; set +a; claude
set -a; source .env; set +a; codex
```

Without this, every server that needs a token silently fails to connect and the
skills fall back to guessing.

---

## Codex

Codex stores MCP servers in `config.toml`: `~/.codex/config.toml` globally, or a
project-scoped `.codex/config.toml` for trusted projects. The CLI and the IDE
extension share it, so this is a one-time setup for both.

```bash
scripts/render-codex-mcp.sh              # write .codex/config.toml (project-scoped)
scripts/render-codex-mcp.sh --install    # merge into ~/.codex/config.toml instead
scripts/render-codex-mcp.sh --dry-run    # show what --install would change
scripts/render-codex-mcp.sh --print      # print the block, touch nothing

set -a; source .env; set +a
codex mcp login datadog                  # once
codex mcp list                           # confirm all three are present
```

`--install` writes only between managed markers and keeps a `.bak`, so your own
Codex settings survive. Re-running replaces the block rather than appending.
Inside the Codex TUI, `/mcp` shows the active servers.

### Why there's a render step at all

TOML has no `${VAR}` interpolation. Claude Code resolves `${DD_MCP_HOST}` when
it reads `.mcp.json`; Codex cannot, so every site-specific value — Datadog host,
o11y realm, gateway region, Splunk endpoint — has to be written out literally.
The script is what keeps those in step with `.env`. Edit `.env` and re-run
rather than hand-editing the TOML.

Credentials are the exception and are never rendered. Codex resolves those at
connect time:

| Field | Meaning |
|---|---|
| `bearer_token_env_var = "FOO"` | Read `$FOO` at connect, send as `Authorization: Bearer` |
| `env_http_headers = { "X-SF-TOKEN" = "FOO" }` | Header value read from `$FOO` |
| `http_headers = { "X-SF-REALM" = "eu1" }` | Static value, safe to commit |

Note the `env_` variants take variable **names**, not values.

### Three differences from the Claude Code setup

**Datadog toolsets travel in a header, not the query string.** Every other
client appends `?toolsets=core,dashboards,alerting` to the URL; Codex uses
`X-Datadog-MCP-Toolsets`. Datadog documents this exception explicitly. If you
change `DD_MCP_TOOLSETS`, re-run the render script so both stay aligned.

**Splunk platform connects natively, with no Node.** `.mcp.json` bridges it
through the `mcp-remote` npm package because that is what Splunk's docs show.
Codex speaks streamable HTTP directly, and `bearer_token_env_var` keeps the
encrypted token in the environment — a `--header "Authorization: Bearer ..."`
argument would have forced it into the config file in plaintext. So on Codex
this server needs no `npx` at all.

**Unconfigured servers are disabled rather than broken.** Codex has an
`enabled` flag, so a blank `SPLUNK_MCP_PLATFORM_URL` renders as
`enabled = false` instead of a server that fails on every startup. Claude Code
has no equivalent, which is why an unconfigured server shows as failed there.

---

## 1. Datadog — the migration source

The [Datadog MCP Server](https://docs.datadoghq.com/mcp_server/) is remote and
hosted by Datadog; there is nothing to install.

### Authentication

**OAuth is the default and needs no credentials in `.env`.** Start Claude Code,
use any Datadog tool, and a browser opens for login. This is the recommended
path for local work and demos.

Use header-based auth only when the browser flow is unavailable — CI, a headless
EC2 box. Add the keys to `.env` and the headers to your `.mcp.json` entry:

```json
"headers": {
  "DD_API_KEY": "${DD_API_KEY}",
  "DD_APPLICATION_KEY": "${DD_APP_KEY}"
}
```

A [Personal or Service Access Token](https://docs.datadoghq.com/account_management/personal-access-tokens/)
passed as `Authorization: Bearer <token>` is preferred over key pairs when you
have the choice — it scopes better and rotates independently.

### Permissions

| Permission | Needed for |
|---|---|
| `mcp_read` | Every read tool — this is the gate, and it is easy to miss |
| Dashboards Read, Monitors Read | The resources the inventory skill actually walks |
| `mcp_write` | Only if a skill creates or mutates Datadog resources |

The Datadog Standard Role already has both MCP permissions. Custom roles need
them added under **Organization Settings → Roles → Edit Role**.

### Site and endpoint

`DD_MCP_HOST` must mirror `DD_SITE`. US1 uses `mcp.datadoghq.com`, EU uses
`mcp.datadoghq.eu`, and so on. A mismatch reads as an authentication failure
rather than a routing error, so `verify-mcp.sh` checks the key against the site
directly to disambiguate.

Datadog MCP is **not available on GovCloud** (`ddog-gov.com`).

### Toolsets

Every tool definition costs context window. `DD_MCP_TOOLSETS` controls what
loads; the default `core,dashboards,alerting` is chosen for this migration:

| Toolset | Gives you |
|---|---|
| `core` | Logs, metrics, traces, dashboards, monitors, incidents, hosts, services |
| `dashboards` | Full dashboard CRUD plus widget schema reference and validation |
| `alerting` | Monitor validation and creation, monitor coverage analysis, SLO search |
| `ddsql` | SQL over Datadog data — useful for bulk inventory extraction |
| `kubernetes`, `cost`, `rum`, `synthetics`, `profiling` | Available if scope grows |

`toolsets=all` works but loads everything. `omit_tools=` drops individual tools
from whatever the toolsets selected — worth using to strip write tools during
the read-only inventory phase.

### Rate limits

50 requests per 10 seconds, 50,000 tool calls per month. A dashboard-by-dashboard
inventory of a large org can approach the burst limit; batch where possible.

---

## 2. Splunk Observability Cloud — via the SCS MCP Gateway

This one is already wired in this repo and is the "o11y tools only" path
(Scenario 3 in Splunk's docs): you pass observability tokens to the gateway and
no Splunk platform credentials at all.

### Token

An Observability Cloud **API access token** — Settings → Access Tokens. This is
*not* the ingest token used by the collector, and swapping the two is the most
common failure here. The token alone selects the org, so it is one token per
org. `verify-mcp.sh` calls `/v2/organization` specifically because an ingest
token fails that call cleanly.

### Region must match realm

The gateway is region-pinned and the region has to correspond to your o11y
realm. Get this wrong and the error looks like a bad token.

| Realm | Region | Gateway URL |
|---|---|---|
| eu0 | dub10 | `https://region-dub10.api.scs.splunk.com/system/mcp-gateway/v1/` |
| **eu1** | **fra10** | `https://region-fra10.api.scs.splunk.com/system/mcp-gateway/v1/` |
| eu2 | lon10 | `https://region-lon10.api.scs.splunk.com/system/mcp-gateway/v1/` |
| us0 | iad10 | `https://region-iad10.api.scs.splunk.com/system/mcp-gateway/v1/` |
| us1 / us2 / us3 | pdx10 | `https://region-pdx10.api.scs.splunk.com/system/mcp-gateway/v1/` |
| jp0 | tyo10 | `https://region-tyo10.api.scs.splunk.com/system/mcp-gateway/v1/` |
| au0 | syd10 | `https://region-syd10.api.scs.splunk.com/system/mcp-gateway/v1/` |
| sg0 | sin10 | `https://region-sin10.api.scs.splunk.com/system/mcp-gateway/v1/` |

The repo defaults to `eu1` / `fra10`, matching the innovationlab org
(`HP5zPsfCgCs`) this demo reports into. `verify-mcp.sh` asserts the pairing.

The gateway is only available to Splunk Cloud customers in the regions above.

---

## 3. Splunk Enterprise / Cloud Platform — SPL and knowledge objects

This is the only connection with a server-side install step. Without it the
agent can write metrics and traces into Splunk Observability but cannot see or
create anything in the platform: saved searches, lookups, SPL.

### Setup

1. **Install** the [Splunk MCP Server app](https://splunkbase.splunk.com/app/7931)
   (Splunkbase 7931) on your search head or search head cluster. Splunk Cloud
   Platform additionally needs REST API access enabled for the stack.
2. **Enable token authentication** on the instance if it is not already on.
3. **Grant `mcp_tool_execute`** to the roles that need agent access.
   `mcp_tool_admin` is separate and only required to manage tools or mint
   tokens for other users.
4. **Generate an encrypted token** inside the MCP Server app. It is shown once.
5. **Copy the endpoint** from the app into `SPLUNK_MCP_PLATFORM_URL`.

Optionally install **Splunk AI Assistant** to add the `saia_`-prefixed tools:
`generate_spl`, `explain_spl`, `optimize_spl`, `ask_splunk_question`. For a
Datadog-to-SPL migration these are worth having — `generate_spl` maps neatly
onto translating a Datadog query.

### About the encrypted token

Encrypted tokens are MCP-only by design: they cannot be replayed against the
Splunk REST API. That is good security and slightly awkward for verification,
so `verify-mcp.sh` confirms only that a token is present and tests reachability
separately. If you want a real credential check, set the optional
`SPLUNK_PLATFORM_API_URL` and `SPLUNK_PLATFORM_API_TOKEN` (a normal Splunk API
token, Settings → Tokens) and the script will call `/services/server/info`.

Invalidating keys in the app settings kills **every** encrypted token at once —
a single keypair backs all of them.

### Transport

The MCP Server app speaks streamable HTTP, bridged to stdio by the `mcp-remote`
npm package, which is why `node` and `npx` appear in the tooling check. Pin the
bridge with the pinned `MCP_REMOTE_VERSION` value after validating a new release.

### Combining Splunk platform and o11y in one server

If you have both and know your Splunk tenant name, the two Splunk entries can
collapse into a single gateway connection (Scenario 2) carrying four headers:

```
Authorization: Bearer <encrypted Splunk token>
splunk_tenant: <tenant name>
X-SF-TOKEN:    <SignalFx access token>
X-SF-REALM:    <o11y realm>
```

Same gateway URL as the table above. This repo keeps them separate so that each
backend can be configured, tested and demoed independently — a broken Splunk
platform install should not take the observability tools down with it.

---

## Troubleshooting

| Symptom | Cause |
|---|---|
| Server shows as failed on Claude Code startup | Variable not exported. Run `set -a; source .env; set +a` first. |
| Codex shows no servers in `/mcp` | Project-scoped config only applies to trusted projects — use `--install` for the global path. |
| Codex ignores a change you made to `.env` | The TOML is rendered, not interpolated. Re-run `scripts/render-codex-mcp.sh`. |
| Codex Datadog returns every tool regardless of `DD_MCP_TOOLSETS` | Toolsets were put in the URL query string; Codex needs the `X-Datadog-MCP-Toolsets` header. |
| Datadog tools return 403 | `mcp_read` missing from the role, or resource-level read permission missing. |
| Datadog auth fails with a key you know is right | `DD_SITE` and `DD_MCP_HOST` disagree; the key is valid on a different site. |
| Splunk o11y returns 401 with a valid-looking token | Ingest token used instead of an API access token, or gateway region does not match the realm. |
| `splunk-platform` returns 404 | MCP Server app not installed on that search head, or the endpoint was copied from the wrong instance. |
| `splunk-platform` fails to start at all | `node`/`npx` missing, so the `mcp-remote` bridge cannot run. |
| Everything skipped in `verify-mcp.sh` | No `.env` and nothing exported. Expected on a fresh clone. |
| Datadog calls start failing mid-inventory | Burst limit: 50 requests / 10 seconds. |

Self-signed certificates on a Splunk instance: set
`SPLUNK_HEC_INSECURE_SKIP_VERIFY="true"` and `verify-mcp.sh` will pass
`--insecure` to the Splunk checks. For the MCP bridge itself, `mcp-remote` needs
`NODE_TLS_REJECT_UNAUTHORIZED=0` in the server's `env` block. Non-production
only.

---

## References

- [Datadog MCP Server](https://docs.datadoghq.com/mcp_server/) · [setup](https://docs.datadoghq.com/mcp_server/setup/) · [tools](https://docs.datadoghq.com/mcp_server/tools/)
- [MCP Server for Splunk Platform](https://help.splunk.com/en/splunk-cloud-platform/mcp-server-for-splunk-platform) · [configure](https://help.splunk.com/en/splunk-cloud-platform/mcp-server-for-splunk-platform/1.1/configure-the-splunk-mcp-server) · [connecting](https://help.splunk.com/en/splunk-cloud-platform/mcp-server-for-splunk-platform/1.1/connecting-to-the-mcp-server-and-settings)
- [Splunk Observability tools via the MCP Gateway](https://help.splunk.com/en/splunk-cloud-platform/mcp-server-for-splunk-platform/1.1/configure-splunk-observability-tools-with-splunk-mcp-server)
- [Splunk MCP Server app on Splunkbase](https://splunkbase.splunk.com/app/7931)
- [Codex — Model Context Protocol](https://developers.openai.com/codex/mcp) · [config reference](https://developers.openai.com/codex/config-reference)
