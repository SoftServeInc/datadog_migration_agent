# Third-party components

This repository contains only original code, documentation, and configuration. No
third-party source code, datasets, or binaries are vendored. The Python code uses the
Python standard library only.

The following third-party software is **downloaded or deployed at run time** from its
official source. It is not redistributed by this repository; each component remains under
its own license.

| Component | How it is used | Source | License |
|---|---|---|---|
| OpenTelemetry Demo (Helm chart `opentelemetry-demo`, version in `versions.env`) and its container images | Deployed by `run.sh` / `scripts/deploy.sh` | open-telemetry.github.io/opentelemetry-helm-charts | Apache-2.0 |
| OpenTelemetry Collector (contrib distribution, via the demo chart) | Telemetry pipeline | github.com/open-telemetry/opentelemetry-collector-contrib | Apache-2.0 |
| flagd | Feature flags / error injection (via the demo chart) | flagd.dev | Apache-2.0 |
| k6 | Load generation (via the demo chart) | github.com/grafana/k6 | AGPL-3.0 (run as a separate, unmodified container) |
| curl container image (`curlimages/curl`, tag in `manifests/ai-load-generator.yaml`) | Drives the GenAI agent loop | hub.docker.com/r/curlimages/curl | curl license (MIT-style) |
| kubectl | Installed by `scripts/install-tools.sh` if missing | dl.k8s.io | Apache-2.0 |
| Helm | Installed if missing | get.helm.sh | Apache-2.0 |
| minikube | Installed if missing | storage.googleapis.com/minikube | Apache-2.0 |
| kind | Installed if missing | kind.sigs.k8s.io | Apache-2.0 |
| Podman | Installed if missing (Homebrew or OS package manager) | podman.io | Apache-2.0 |

External services (Datadog, Splunk Observability Cloud, Splunk Enterprise / Cloud
Platform, Splunk Agent Observability) are used through their public APIs under the
user's own accounts and terms of service. JSON Schema meta-schema URLs referenced in
`schemas/` are identifiers only.

When a component is added, update this table in the same pull request.
