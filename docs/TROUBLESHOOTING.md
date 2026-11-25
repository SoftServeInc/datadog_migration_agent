# Troubleshooting

Start here:

```bash
scripts/status.sh
```

It prints pod state, the last 200 collector log lines filtered for export failures, the
active error-injection flags, and which destinations are wired up.

---

## I changed a token in .env and nothing happened

Re-run `./run.sh --skip-cluster`. A credential digest is stamped on the collector pod, so
changing a token forces a rollout; if you edited the Secret by hand instead, restart the
collector yourself:

```bash
kubectl rollout restart daemonset/otel-collector-agent -n otel-demo
```

Confirm the new value is live:

```bash
scripts/status.sh          # "Collector exports" should stop reporting 401/403
```

## Preflight says a tool is missing and I don't want it installed automatically

```bash
./run.sh --no-install
```

...then install by hand. Or set `AUTO_INSTALL_TOOLS="never"` in `.env` to make that the
default. The reverse, for unattended provisioning, is `./run.sh --yes`.

If the installer wrote binaries to `~/.local/bin`, they work for that run only — it
prints the `export PATH=...` line to add to your shell rc.

## "podman info failed" / the podman machine won't cooperate

On macOS and Windows podman needs a running machine:

```bash
podman machine list                      # is there one, and is it up?
podman machine start podman-machine-default
```

`run.sh` starts it for you, and offers to create, grow, or make it rootful. If you'd
rather do it by hand:

```bash
podman machine init podman-machine-default \
  --cpus 4 --memory 12288 --disk-size 60 --rootful --now
```

**"Resize the machine…" keeps appearing.** The machine is smaller than
`CLUSTER_MEMORY_MB` + 2 GiB. Accept the prompt, or resize yourself — `podman machine set`
requires the machine to be stopped:

```bash
podman machine stop  podman-machine-default
podman machine set   podman-machine-default --cpus 4 --memory 12288
podman machine start podman-machine-default
```

**Rootful.** minikube's podman driver requires it, and kind is much less fiddly with it.
`run.sh` offers to switch; the manual form is `podman machine set --rootful` on a stopped
machine.

**minikube's podman driver is experimental.** If `minikube start` fails in ways that look
like the driver rather than resources, switch to kind — same engine, better-trodden path:

```bash
./run.sh --cluster kind
```

Or drop the container engine entirely:

```bash
MINIKUBE_DRIVER="vfkit"   # macOS, Apple silicon
MINIKUBE_DRIVER="kvm2"    # Linux with libvirt
```

## "The docker CLI is present but the daemon is not responding"

Only relevant with `CONTAINER_ENGINE="docker"`.

- **Docker Desktop:** `open -a Docker`, wait for the whale icon to settle.
- **Colima:** `colima start --cpu 4 --memory 12`
- **Linux:** `sudo systemctl start docker`, and confirm you are in the `docker` group
  (`groups | grep docker`); if you were just added, log out and back in.

## Nothing starts / pods stuck in `Pending`

Almost always memory. The demo needs ~4 vCPU and ~10 GiB.

```bash
kubectl top nodes
kubectl describe pod -n otel-demo <pod> | tail -20
```

- **macOS with podman:** the machine is the ceiling —
  `podman machine set --cpus 4 --memory 12288` on a stopped machine.
- **macOS with Docker Desktop:** Settings → Resources. The default 8 GiB is not enough
  with the bundled backends on.
- Set `KEEP_LOCAL_BACKENDS="false"` in `.env` to free ~3 GiB.
- Raise `CLUSTER_CPUS` / `CLUSTER_MEMORY_MB`, then recreate the cluster
  (`scripts/teardown.sh --cluster && ./run.sh`) — minikube only applies sizing at
  creation time.

## Collector `CrashLoopBackOff`

Get the actual config error:

```bash
kubectl logs -n otel-demo -l app.kubernetes.io/name=opentelemetry-collector --tail=50
```

- `references exporter "x" which is not configured` — a pipeline names an exporter that
  the render did not emit. Re-run `./run.sh --render-only` and inspect
  `.render/demo-values.yaml`.
- `cannot unmarshal` on an exporter — usually a chart bump changing an exporter's schema.
  Compare against the pinned version in [versions.env](../versions.env).
- OOMKilled — raise `opentelemetry-collector.resources.limits.memory` in
  `scripts/render.sh`.

## No data in Datadog

1. `scripts/status.sh` — a bad key shows as `403` / `invalid api key`.
2. Check `DD_SITE`. `datadoghq.eu` keys do not work against `datadoghq.com`, and the
   error is a silent drop, not an auth failure.
3. Traces arrive but **APM Services is empty** → the `datadog/connector` is missing.
   It is added automatically when `DD_API_KEY` is set; confirm it appears under
   `connectors:` in `.render/demo-values.yaml`.
4. Filter on `env:otel-demo` (or your `DEPLOYMENT_ENVIRONMENT`) — the default view may
   be scoped elsewhere.

## No data in Splunk Observability Cloud

1. Check the realm. `us0`, `us1`, `eu0`… it is in your Splunk URL. A wrong realm gives a
   DNS or connection error in the collector logs, not a 401.
2. A `401` on `otlphttp/splunk_o11y` means the **org access token** is wrong — an API
   token or a user token will not work for ingest.
3. APM → set the environment selector to your `DEPLOYMENT_ENVIRONMENT`.
4. Metrics land in Infrastructure Monitoring via the `signalfx` exporter, traces in APM
   via `otlphttp`. One can work while the other does not; check both exporter names in
   the logs.

## No data in Splunk Enterprise

1. `SPLUNK_HEC_ENDPOINT` must be the full URL ending in `/services/collector/event`.
2. HEC must be enabled and the token must allow the indexes in `.env`
   (`main`, `otel_metrics`, `otel_traces` by default). **Metrics indexes must be created
   as metrics-type indexes**, not event indexes — otherwise the collector gets a 400.
3. Self-signed certificate → `SPLUNK_HEC_INSECURE_SKIP_VERIFY="true"`.
4. From inside the cluster:
   ```bash
   kubectl run -n otel-demo hectest --rm -it --image=curlimages/curl --restart=Never -- \
     curl -k -v "$SPLUNK_HEC_ENDPOINT" -H "Authorization: Splunk $SPLUNK_HEC_TOKEN" \
     -d '{"event":"hello"}'
   ```
   A minikube cluster cannot reach a Splunk instance on your host at `localhost` — use
   `host.minikube.internal`.

## No data in Splunk Agent Observability

See [SPLUNK-AGENT-OBSERVABILITY.md](SPLUNK-AGENT-OBSERVABILITY.md#verifying).
The short version: confirm `ai-load-generator` is logging `status=200`, then grep the
collector logs for `splunk_ao`.

## Errors are not showing up

```bash
scripts/chaos.sh show
```

Flags marked `*` are active. If everything reads `off`, the profile did not apply —
re-run `scripts/chaos.sh apply steady`. Note that `cartFailure` and `paymentFailure` are
*percentages*: at `10%` you need a few dozen requests before failures are visible.

Some flags only take effect on the next poll by the affected service; give it a minute.

## The load generator is idle

```bash
kubectl logs -n otel-demo deploy/load-generator --tail=30
```

The k6 browser scenario needs a fair amount of memory. If it is being OOMKilled, drop
`LOAD_GENERATOR_VUS` to `2` in `.env` and re-run `./run.sh`.

`loadGeneratorTraffic` is itself a flagd flag — if it got set to `off`, no load runs:

```bash
scripts/chaos.sh set loadGeneratorTraffic on
```

## `helm upgrade` fails with "another operation in progress"

A previous run was interrupted.

```bash
helm rollback otel-demo -n otel-demo   # or:
helm uninstall otel-demo -n otel-demo && ./run.sh --skip-cluster
```

## Starting completely clean

```bash
scripts/teardown.sh --cluster
rm -rf .render
./run.sh
```
