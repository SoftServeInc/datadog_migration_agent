# cisco-innovation

One command turns a laptop or an EC2 box into a running
[OpenTelemetry Demo](https://github.com/open-telemetry/opentelemetry-demo) on Kubernetes,
instrumented end to end by an OpenTelemetry Collector that fans the same telemetry
out to **Datadog**, **Splunk Observability Cloud**, **Splunk Enterprise** and
**Splunk Agent Observability** — with load and random error injection already running.

```bash
git clone https://github.com/GH-25091/cisco-innovation && cd cisco-innovation
cp .env.example .env      # fill in the destinations you have credentials for
./run.sh
```

The demo deployment uses upstream, officially maintained charts. The repository also
contains local Codex skills and deterministic Python cores for discovering, previewing,
executing, and validating governed Datadog-to-Splunk migrations.

| Piece | Source | Pinned in |
|---|---|---|
| Astronomy Shop + collector | `open-telemetry/opentelemetry-demo` Helm chart | [versions.env](versions.env) |

One Helm release, one collector, every backend. No vendor agents.

---

## Project status and support

**Status:** active development, maintained by SoftServe on a best-effort basis. The demo
deployment is stable; the observability migration skills are an MVP and every write to
Splunk requires explicit, hash-bound approval.

**Support:** community support through GitHub Issues; there is no SLA. Maintainers aim to
triage new issues within 10 working days. Security issues: see [SECURITY.md](SECURITY.md).
Who maintains what: [MAINTAINERS.md](MAINTAINERS.md).

## What you get

- **A cluster.** minikube by default; `kind` and "use my current context" also work.
- **The full OpenTelemetry Demo (app v3.0.0)** — ~20 microservices in Go, Java, .NET,
  Node, Python, Rust, PHP, Ruby, C++, plus Kafka, Valkey and Postgres.
- **Cluster instrumentation.** The demo's collector runs as a DaemonSet with the
  `hostMetrics`, `kubeletMetrics`, `clusterMetrics`, `kubernetesAttributes` and
  `logsCollection` presets on, plus a `k8sobjects` receiver for Kubernetes events — so
  node metrics, pod metrics, events and container logs travel the same pipelines as
  app telemetry.
- **Continuous load.** The upstream k6 load generator at its default 5 virtual users,
  running both an HTTP and a headless-browser scenario.
- **Random error injection.** flagd flags that make the cart and payment services fail
  a percentage of requests, plus latency and cache-failure flags. Three profiles ship
  in [config/flagd/](config/flagd/); you can also flip flags live.
- **GenAI traffic.** The demo's LangGraph agent is exercised on a loop, producing
  `gen_ai.*` spans. It replays recorded LLM responses by default, so this costs
  nothing and needs no model credentials.

## Observability migration assessment

Eleven composable repository skills expose one customer-facing orchestrator and internal adapters
for preflight, Datadog discovery, normalization, compatibility, planning, detectors, SLOs,
dashboards/charts, and security review. Customer decisions are consolidated into review of the
complete migration report and authorization of the immutable execution bundle.

Compilation, object-type adapters, batches, retries, API validation, browser validation, and final
reporting run automatically. `full` scope represents every discovered object, including explicit
partial, unsupported, blocked, and deferred outcomes. Dashboards preserve source names and source
geometry; detector names normalize source-only placeholders into readable Splunk names.
`AI-Created` is stored as metadata rather than injected into visible names.

The repository executes a shared bundle through one dependency-aware scheduler, checkpoint, apply
approval, and ownership/rollback ledger. Existing detector, SLO, and dashboard engines run through
internal bridges, so legacy waves no longer leak into the customer flow. After final approval, the
control center can generate import-only Terraform configuration for migration-managed resources.
Terraform apply and Git publishing remain deliberately unimplemented.

- [MVP architecture and local development](docs/architecture/OBSERVABILITY-MIGRATION-MVP.md)
- [Architecture decision](docs/architecture/ADR-001-local-deterministic-migration-core.md)
- [Detector executor decision](docs/architecture/ADR-002-create-only-detector-executor.md)
- [Detector executor operation guide](.agents/skills/observability-migration-executor/references/operation-guide.md)
- [SLO executor decision](docs/architecture/ADR-003-create-only-slo-executor.md)
- [SLO executor operation guide](.agents/skills/observability-migration-slo-executor/references/operation-guide.md)
- [Dashboard executor operation guide](.agents/skills/observability-migration-dashboard-executor/references/operation-guide.md)
- [Orchestrator flow](.agents/skills/observability-migration-orchestrator/references/migration-flow.md)
- [Install and use the Codex migration plugin](docs/How-to-install&use-codex-migration-plugin.md)
- [Verification checklist](docs/OBSERVABILITY-MIGRATION-VERIFICATION-CHECKLIST.md)
- [Object adapter contract](.agents/skills/observability-migration-orchestrator/references/object-adapter-contract.md)
- [Migration postmortem](docs/architecture/OBSERVABILITY-MIGRATION-POSTMORTEM.md)
- [Unified execution bundle decision](docs/architecture/ADR-004-unified-execution-bundle.md)
- [Security and privacy guide](docs/security/SECURITY-PRIVACY.md)
- [Repository threat model](docs/security/cisco-innovation-threat-model.md)

## What goes where

The demo's own OpenTelemetry Collector is the single fan-out point. One receive path,
four independent export paths — a backend being down or misconfigured does not affect
the others.

```
  ~20 instrumented services ─┐
  k6 load generator ─────────┤
  AI agent / chatbot / MCP ──┼──► OTel Collector (DaemonSet) ──┬──► Datadog
  kubelet / host / cluster ──┤      • k8sattributes            ├──► Splunk Observability Cloud
  container logs, k8s events ┘      • gen_ai_normalizer        ├──► Splunk Enterprise (HEC)
                                    • span-name sanitizing     └──► Splunk Agent Observability
                                    • deployment.environment        (GenAI spans only)
```

| | traces | metrics | logs | GenAI spans |
|---|---|---|---|---|
| Datadog | `datadog` exporter + APM stats connector | ✔ | ✔ | (in APM traces) |
| Splunk Observability Cloud | `otlphttp` → `/v2/trace/otlp` | `signalfx` | via Log Observer Connect | (in APM traces) |
| Splunk Enterprise | `splunk_hec` | `splunk_hec` | `splunk_hec` | (in HEC traces) |
| Splunk Agent Observability | — | — | — | `otlphttp` → `/otel/v1/traces` |

Details and the reasoning behind each choice: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Requirements

`run.sh` starts with a preflight check and **offers to install whatever is missing**:

```
Preflight
  ok kubectl  /usr/local/bin/kubectl
  ok python3  /usr/bin/python3

Missing tools
  · helm       brew
  · minikube   brew

Install helm minikube now? [y/N]
```

Homebrew is used when it is present; otherwise the official release binaries are
downloaded from `dl.k8s.io`, `get.helm.sh`, `storage.googleapis.com/minikube` and
`kind.sigs.k8s.io` into `/usr/local/bin` (or `~/.local/bin` when that is not writable).

| | |
|---|---|
| `kubectl`, `helm` (3 or 4) | installed for you |
| `minikube` (default) or `kind` | installed for you |
| `podman` | installed for you (Homebrew, or apt/dnf/zypper/pacman) |
| `python3` | ships with macOS and every mainstream Linux |

Control it with `AUTO_INSTALL_TOOLS` in `.env` (`ask` / `always` / `never`), or per run:

```bash
./run.sh --yes          # install without prompting — use this on a fresh EC2 box
./run.sh --no-install   # fail instead of installing
```

### Container engine

**Podman is the default** — no daemon, no licence question, rootless by design.
`CONTAINER_ENGINE="docker"` in `.env` switches back to Docker, which is then the one
tool you install yourself (preflight prints the options for your platform).

On macOS and Windows podman runs inside a VM it calls a *machine*. `run.sh` handles it:

- creates one if there isn't one, sized from `CLUSTER_CPUS` / `CLUSTER_MEMORY_MB` plus
  2 GiB of headroom, and rootful;
- starts it if it's stopped;
- offers to **grow** an existing machine that's too small, and to switch a rootless one
  to rootful. It never shrinks a machine and never touches one without asking.

On Linux podman is native — no machine, nothing to size.

```bash
CONTAINER_ENGINE="podman"              # default
PODMAN_MACHINE_NAME="podman-machine-default"
```

> minikube's podman driver is still marked **experimental** upstream, and needs a rootful
> machine (`run.sh` arranges that). If it misbehaves, `./run.sh --cluster kind` is the
> better-travelled podman path — kind is pinned to your engine via
> `KIND_EXPERIMENTAL_PROVIDER`.

To skip container engines altogether and give minikube its own VM:

```bash
MINIKUBE_DRIVER="vfkit"   # macOS, Apple silicon (also: qemu2)
MINIKUBE_DRIVER="kvm2"    # Linux, needs libvirt
```

Beyond tooling you need **~4 vCPU and ~10 GiB of RAM** available to the cluster;
on EC2, `t3.xlarge` or better.

## Configuration

All of it is in `.env` (see [.env.example](.env.example) for the annotated version).
Every destination is independent — **leave a credential blank and that destination is
simply never wired up**. You can start with zero destinations to smoke-test the cluster,
then add them one at a time.

```bash
# Datadog
DD_API_KEY="..."            DD_SITE="datadoghq.com"

# Splunk Observability Cloud
SPLUNK_O11Y_REALM="us1"     SPLUNK_O11Y_ACCESS_TOKEN="..."

# Splunk Enterprise / Splunk Cloud Platform
SPLUNK_HEC_ENDPOINT="https://splunk.example.com:8088/services/collector/event"
SPLUNK_HEC_TOKEN="..."

# Splunk Agent Observability (AI agent observability)
SPLUNK_AO_API_KEY="..."     SPLUNK_AO_PROJECT="otel-demo"
```

`.env` is yours — nothing in this repo ever writes to it or deletes it. If you want
several configs side by side, keep them as separate files and point at one per run:

```bash
./run.sh --env-file .env.datadog      # or: ENV_FILE=.env.splunk ./run.sh
```

`.gitignore` covers `.env` and `.env.*`, so none of them can be committed by accident.

To see exactly what your `.env` will produce, without touching a cluster:

```bash
./run.sh --render-only && cat .render/demo-values.yaml
```

That file is plain Helm values. Read it, diff it, hand it to a colleague — there is no
hidden templating.

### Costs

The repository itself is free. Running it can create costs in services you own:

- **Datadog / Splunk ingestion.** Every configured backend receives the full demo
  telemetry (~20 services, continuous load, container logs, Kubernetes metrics). This is
  billed under your own Datadog/Splunk plans (hosts, APM, custom metrics, log volume).
  Leave a destination's key empty to skip it, lower `LOAD_GENERATOR_VUS`, or run
  `scripts/teardown.sh` when you are done.
- **Compute.** The default local cluster uses 4 CPUs and 10 GB RAM
  (`CLUSTER_CPUS`, `CLUSTER_MEMORY_MB`). For EC2 the settings below use 8 vCPUs and
  24 GB, roughly an `m6i.2xlarge`-class instance, billed by AWS while it runs.
- **GenAI traffic** replays recorded LLM responses by default, so no model API costs.
- **Migration skills** make bounded read-only API calls during assessment; created
  Splunk objects (disabled detectors, SLOs, dashboards) count toward your Splunk limits.

## Error injection

`ERROR_INJECTION_PROFILE` in `.env` picks the starting state; three profiles ship:

| Profile | What it does |
|---|---|
| `off` | Upstream defaults — a clean, healthy baseline |
| `steady` *(default)* | Cart and payment fail ~10% of requests at random; product-catalog fails for one product |
| `chaos` | 25% failure rates, plus slow image loads and international-shipping latency |

Live control, no redeploy:

```bash
scripts/chaos.sh show                  # what's currently on
scripts/chaos.sh apply chaos           # switch profile
scripts/chaos.sh set cartFailure 50%   # one flag
scripts/chaos.sh randomize 300         # re-roll a random flag every 5 minutes
```

Or use the flagd UI at <http://localhost:8080/feature>.

## URLs

`./run.sh` ends by port-forwarding everything behind one port:

| | |
|---|---|
| <http://localhost:8080/> | Astronomy Shop storefront |
| <http://localhost:8080/chatbot> | AI assistant (generates GenAI spans on demand) |
| <http://localhost:8080/feature> | flagd UI |
| <http://localhost:8080/jaeger/ui> | Jaeger — only when `KEEP_LOCAL_BACKENDS=true` |
| <http://localhost:8080/grafana> | Grafana — only when `KEEP_LOCAL_BACKENDS=true` |

If the forward drops, `scripts/forward.sh` brings it back.

## Day-to-day

```bash
./run.sh                        # create/update everything (safe to re-run)
./run.sh --yes                  # ...and install missing tools without asking
./run.sh --no-install           # ...and never install anything
./run.sh --skip-cluster         # cluster already exists
./run.sh --render-only          # just generate .render/*.yaml
./run.sh --cluster kind         # override CLUSTER_TYPE for one run
./run.sh --env-file .env.foo    # use a different config file

scripts/status.sh               # pods, export errors, active flags
scripts/verify-mcp.sh           # agent environment: MCP endpoints + API credentials
scripts/render-codex-mcp.sh     # regenerate the Codex MCP config from .env
scripts/forward.sh              # re-open localhost:8080
scripts/teardown.sh             # remove releases, keep the cluster
scripts/teardown.sh --cluster   # remove everything
```

### Tests and checks

```bash
make test        # python3 -m unittest discover -s tests (standard library only, no credentials)
make check       # bash -n + shellcheck on run.sh and scripts/*.sh
diff -rq -x __pycache__ -x '*.pyc' .agents/skills plugins/observability-migration/skills   # plugin copy matches
```

The same checks run in CI on every pull request (`.github/workflows/ci.yml`).

### Re-running after an `.env` change

`run.sh` is idempotent — it converges the cluster on whatever `.env` currently says
rather than rebuilding. Re-running is the normal way to change a backend. Nothing is
torn down, and only the workloads whose spec actually changed restart.

| Change in `.env` | What re-running does |
|---|---|
| Added/changed a token or API key | Secret updated, **collector pod rolls** (see below). Seconds. |
| Changed realm / site / HEC endpoint | Collector config changes → config checksum changes → collector rolls. Seconds. |
| Enabled a new destination | Exporter and pipeline added, collector rolls. Other backends unaffected. |
| Removed a destination | Its exporter disappears from the pipelines; nothing else changes. |
| `KEEP_LOCAL_BACKENDS` true → false | Jaeger/Prometheus/Grafana/OpenSearch removed by Helm. |
| `LOAD_GENERATOR_VUS`, `AI_LOAD_*` | Only the load generator restarts. |
| `ERROR_INJECTION_PROFILE` | flagd ConfigMap rewritten, flagd restarts. Or use `scripts/chaos.sh`, no redeploy. |
| `CLUSTER_CPUS` / `CLUSTER_MEMORY_MB` | **Ignored for an existing cluster.** See below. |

Credentials reach the collector as `secretKeyRef` environment variables, which Kubernetes
resolves once when the container starts. Updating the Secret alone would leave the running
collector on the old token — a silent no-op. So the rendered values carry a truncated,
one-way digest of your credentials as a pod annotation, which makes Helm roll the collector
whenever any of them change. Same token, same digest, no pointless restart.

**Cluster sizing is the one thing that is not idempotent.** minikube fixes CPU and memory
when the profile is created and cannot resize in place, so `run.sh` reuses the existing
cluster as-is. To apply new sizing:

```bash
scripts/teardown.sh --cluster && ./run.sh
```

To skip the cluster and cluster-engine steps entirely when you only touched credentials:

```bash
./run.sh --skip-cluster
```

## Running on EC2

Same commands. Two things to change:

```bash
CLUSTER_CPUS="8"
CLUSTER_MEMORY_MB="24576"
```

`./run.sh --yes` is the unattended form — it installs kubectl, helm, minikube and podman
on a bare instance without prompting. On Linux podman is native, so there is no VM to
size and nothing else to set up.

Reach the UI over SSH rather than opening a port:

```bash
ssh -L 8080:localhost:8080 ec2-user@<host>
# then on the instance:
./run.sh
```

## One collector, not one per vendor

There is a single OpenTelemetry Collector. Every backend is an exporter on it, so
each one receives identical spans with identical resource attributes — which is the
only way a side-by-side comparison means anything.

That includes the vendor-specific content you might expect to need a vendor agent for.
Splunk's Kubernetes navigator and APM→infrastructure correlation work here because the
collector's `k8s_cluster` and `kubeletstats` receivers are configured the way Splunk's
own distribution configures them, including `metadata_exporters: [signalfx]`, which is
what publishes Kubernetes object metadata as dimension properties. Details in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

The one thing this cannot reproduce is Datadog's live-container and process views,
which depend on the Datadog agent's own collection path.

## Docs

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — why the pipelines look the way they do
- [docs/MCP-SETUP.md](docs/MCP-SETUP.md) — the agent environment: MCP servers, tokens, permissions
- [docs/SPLUNK-AGENT-OBSERVABILITY.md](docs/SPLUNK-AGENT-OBSERVABILITY.md) — the GenAI branch in detail
- [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) — "no data in X"
- [docs/THIRD-PARTY-NOTICES.md](docs/THIRD-PARTY-NOTICES.md) — third-party components and licenses
- [docs/ROADMAP.md](docs/ROADMAP.md) — planned work

## Contributing

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) for setup, conventions,
required checks and the DCO sign-off, and follow the [Code of Conduct](CODE_OF_CONDUCT.md).
Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

### AI-assisted development

Parts of this project were developed with AI coding assistants (OpenAI Codex and Claude
Code), and the repository includes their project configuration (`.codex/`, `.claude/`). All code was reviewed by the maintainers and is covered by the project
license.

## License

Apache 2.0, matching the upstream projects this repo orchestrates. See [LICENSE](LICENSE) and
[NOTICE](NOTICE).
