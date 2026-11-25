#!/usr/bin/env bash
# Shared helpers. Sourced by every script in scripts/.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC2034  # used by the scripts that source this file
RENDER_DIR="${REPO_ROOT}/.render"

if [[ -t 1 ]] && [[ -z "${NO_COLOR:-}" ]]; then
  C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'; C_DIM=$'\033[2m'
  C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_BLUE=$'\033[34m'
else
  C_RESET=""; C_BOLD=""; C_DIM=""; C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""
fi

log()   { printf '%s==>%s %s\n' "${C_BLUE}${C_BOLD}" "${C_RESET}" "$*"; }
ok()    { printf '%s  ok%s %s\n' "${C_GREEN}" "${C_RESET}" "$*"; }
warn()  { printf '%swarn%s %s\n' "${C_YELLOW}" "${C_RESET}" "$*" >&2; }
die()   { printf '%sfail%s %s\n' "${C_RED}${C_BOLD}" "${C_RESET}" "$*" >&2; exit 1; }
step()  { printf '\n%s%s%s\n' "${C_BOLD}" "$*" "${C_RESET}"; }
dim()   { printf '%s%s%s\n' "${C_DIM}" "$*" "${C_RESET}"; }

have() { command -v "$1" >/dev/null 2>&1; }

# Load versions.env then .env, without clobbering anything already exported.
load_env() {
  # shellcheck source=/dev/null
  source "${REPO_ROOT}/versions.env"

  # ENV_FILE lets you keep several configs side by side (.env.datadog,
  # .env.splunk, ...) and lets tests run without going near your real .env.
  # Nothing in this repo ever writes to or deletes the env file.
  local envfile="${ENV_FILE:-${REPO_ROOT}/.env}"
  if [[ ! -f "${envfile}" ]]; then
    die "${envfile} not found. Run:  cp .env.example .env  then edit it."
  fi
  set -a
  # shellcheck source=/dev/null
  source "${envfile}"
  set +a

  # Defaults for anything the user deleted from their .env.
  : "${CLUSTER_TYPE:=minikube}"
  : "${CLUSTER_NAME:=otel-demo}"
  : "${NAMESPACE:=otel-demo}"
  : "${CLUSTER_CPUS:=4}"
  : "${CLUSTER_MEMORY_MB:=10240}"
  : "${CONTAINER_ENGINE:=podman}"
  : "${MINIKUBE_DRIVER:=}"
  : "${PODMAN_MACHINE_NAME:=podman-machine-default}"
  : "${AUTO_INSTALL_TOOLS:=ask}"
  : "${KUBELET_INSECURE_SKIP_VERIFY:=}"
  : "${DEMO_INSTANCE:=}"
  : "${DEPLOYMENT_ENVIRONMENT:=}"
  : "${KEEP_LOCAL_BACKENDS:=false}"
  : "${LOAD_GENERATOR_VUS:=5}"
  : "${AI_LOAD_ENABLED:=true}"
  : "${AI_LOAD_INTERVAL_SECONDS:=20}"
  : "${ERROR_INJECTION_PROFILE:=steady}"
  : "${DD_API_KEY:=}"
  : "${DD_SITE:=datadoghq.com}"
  : "${SPLUNK_O11Y_REALM:=us1}"
  : "${SPLUNK_O11Y_ACCESS_TOKEN:=}"
  : "${SPLUNK_HEC_ENDPOINT:=}"
  : "${SPLUNK_HEC_TOKEN:=}"
  : "${SPLUNK_HEC_INDEX_LOGS:=main}"
  : "${SPLUNK_HEC_INDEX_METRICS:=otel_metrics}"
  : "${SPLUNK_HEC_INDEX_TRACES:=otel_traces}"
  : "${SPLUNK_HEC_INSECURE_SKIP_VERIFY:=false}"
  : "${SPLUNK_AO_API_KEY:=}"
  : "${SPLUNK_AO_API_URL:=https://api.splunk-ao.splunk.com}"
  : "${SPLUNK_AO_PROJECT:=otel-demo}"
  : "${SPLUNK_AO_AGENT_STREAM:=astronomy-shop}"
  : "${COLLECTOR_DEBUG_EXPORTER:=false}"

  # ---------------------------------------------------------------------------
  # Instance identity.
  #
  # Several engineers point this demo at the same Datadog org or Splunk realm.
  # Without a per-run identity every copy reports the same service names, the
  # same environment and the same cluster, and the backends merge them into one
  # unreadable pile. DEMO_INSTANCE is the tag that keeps them apart.
  # ---------------------------------------------------------------------------
  if [[ -z "${DEMO_INSTANCE}" ]]; then
    local host
    host="$(hostname -s 2>/dev/null || uname -n)"
    DEMO_INSTANCE="$(slugify "${USER:-${LOGNAME:-unknown}}-${host%%.*}")"
  else
    DEMO_INSTANCE="$(slugify "${DEMO_INSTANCE}")"
  fi
  [[ -n "${DEMO_INSTANCE}" ]] || DEMO_INSTANCE="unknown"

  # Empty means "derive"; an explicit value is respected verbatim.
  [[ -n "${DEPLOYMENT_ENVIRONMENT}" ]] || DEPLOYMENT_ENVIRONMENT="otel-demo-${DEMO_INSTANCE}"

  # The name the backends see. CLUSTER_NAME stays the local minikube/kind
  # profile name, which only has to be unique on this machine.
  : "${TELEMETRY_CLUSTER_NAME:=${CLUSTER_NAME}-${DEMO_INSTANCE}}"
  export DEMO_INSTANCE DEPLOYMENT_ENVIRONMENT TELEMETRY_CLUSTER_NAME

  case "${CONTAINER_ENGINE}" in
    podman|docker) ;;
    *) die "CONTAINER_ENGINE must be podman or docker (got '${CONTAINER_ENGINE}')" ;;
  esac

  # An empty MINIKUBE_DRIVER means "use the container engine". Setting it to
  # vfkit/qemu2/kvm2/none runs minikube in its own VM with no engine at all.
  EFFECTIVE_MINIKUBE_DRIVER="${MINIKUBE_DRIVER:-${CONTAINER_ENGINE}}"
  # MINIKUBE_DRIVER is also a variable minikube itself reads. load_env exports
  # everything in .env, and an exported empty value shows up in minikube's
  # startup banner and can override its config, so drop it once it is consumed.
  unset MINIKUBE_DRIVER

  NEEDS_CONTAINER_ENGINE=false
  case "${CLUSTER_TYPE}" in
    kind)     NEEDS_CONTAINER_ENGINE=true ;;
    minikube) [[ "${EFFECTIVE_MINIKUBE_DRIVER}" == "podman" || "${EFFECTIVE_MINIKUBE_DRIVER}" == "docker" ]] \
                && NEEDS_CONTAINER_ENGINE=true ;;
  esac
  export EFFECTIVE_MINIKUBE_DRIVER NEEDS_CONTAINER_ENGINE

  # minikube and kind give the kubelet a self-signed serving certificate with no
  # IP SANs, so scraping https://<node-ip>:10250/stats/summary fails TLS
  # verification and every pod and container metric is lost. Managed clusters
  # (EKS/GKE/AKS) issue a proper cert, so verification stays on there.
  if [[ -z "${KUBELET_INSECURE_SKIP_VERIFY}" ]]; then
    case "${CLUSTER_TYPE}" in
      minikube|kind) KUBELET_INSECURE_SKIP_VERIFY=true ;;
      *)             KUBELET_INSECURE_SKIP_VERIFY=false ;;
    esac
  fi
  export KUBELET_INSECURE_SKIP_VERIFY

  # Derived: which destinations are actually wired up.
  DEST_DATADOG=false;      [[ -n "${DD_API_KEY}" ]] && DEST_DATADOG=true
  DEST_SPLUNK_O11Y=false;  [[ -n "${SPLUNK_O11Y_ACCESS_TOKEN}" ]] && DEST_SPLUNK_O11Y=true
  DEST_SPLUNK_HEC=false;   [[ -n "${SPLUNK_HEC_TOKEN}" && -n "${SPLUNK_HEC_ENDPOINT}" ]] && DEST_SPLUNK_HEC=true
  DEST_SPLUNK_AO=false;    [[ -n "${SPLUNK_AO_API_KEY}" ]] && DEST_SPLUNK_AO=true
  export DEST_DATADOG DEST_SPLUNK_O11Y DEST_SPLUNK_HEC DEST_SPLUNK_AO

  # With no SaaS destination and no local backends, telemetry would go nowhere.
  if [[ "${DEST_DATADOG}${DEST_SPLUNK_O11Y}${DEST_SPLUNK_HEC}${DEST_SPLUNK_AO}" == "falsefalsefalsefalse" \
     && "${KEEP_LOCAL_BACKENDS}" != "true" ]]; then
    warn "No destinations configured — enabling the bundled Jaeger/Grafana so telemetry lands somewhere."
    KEEP_LOCAL_BACKENDS="true"
  fi

  SPLUNK_O11Y_INGEST_URL="https://ingest.${SPLUNK_O11Y_REALM}.observability.splunkcloud.com"
  SPLUNK_O11Y_API_URL="https://api.${SPLUNK_O11Y_REALM}.observability.splunkcloud.com"
  export SPLUNK_O11Y_INGEST_URL SPLUNK_O11Y_API_URL
}

# Print a "yes/no" summary line.
destline() {
  local enabled="$1" name="$2" detail="$3"
  if [[ "${enabled}" == "true" ]]; then
    printf '  %s✔%s %-32s %s\n' "${C_GREEN}" "${C_RESET}" "${name}" "${C_DIM}${detail}${C_RESET}"
  else
    printf '  %s·%s %-32s %s\n' "${C_DIM}" "${C_RESET}" "${name}" "${C_DIM}(not configured)${C_RESET}"
  fi
}

kube() { kubectl --namespace "${NAMESPACE}" "$@"; }

# Lowercase, keep [a-z0-9-], collapse and trim separators, cap the length.
# Produces something safe for a Kubernetes label, a Datadog tag and a Splunk
# dimension all at once.
slugify() {
  printf '%s' "$1" \
    | tr '[:upper:]' '[:lower:]' \
    | sed -e 's/[^a-z0-9]\{1,\}/-/g' -e 's/^-*//' -e 's/-*$//' \
    | cut -c1-40
}

# Short, non-reversible digest. Used to force a pod rollout when credentials
# change: env vars sourced from a Secret are resolved at container start, so
# updating the Secret alone leaves the running collector on the old value.
hash_string() {
  if have sha256sum; then
    printf '%s' "$1" | sha256sum | cut -c1-16
  else
    printf '%s' "$1" | shasum -a 256 | cut -c1-16
  fi
}
