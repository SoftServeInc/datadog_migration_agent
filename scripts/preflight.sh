#!/usr/bin/env bash
# Verifies the local toolchain before anything is created, and offers to install
# whatever is missing (see scripts/install-tools.sh).
#
# Written for bash 3.2 — the version macOS still ships. No mapfile, no
# associative arrays, no bare expansion of possibly-empty arrays.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
source "$(dirname "${BASH_SOURCE[0]}")/install-tools.sh"

# Tools this run needs, given CLUSTER_TYPE / MINIKUBE_DRIVER.
required_tools() {
  local tools="kubectl helm python3"
  case "${CLUSTER_TYPE}" in
    minikube) tools="${tools} minikube" ;;
    kind)     tools="${tools} kind" ;;
    current)  ;;
    *) die "CLUSTER_TYPE must be one of: minikube, kind, current (got '${CLUSTER_TYPE}')" ;;
  esac
  [[ "${NEEDS_CONTAINER_ENGINE}" == "true" ]] && tools="${tools} ${CONTAINER_ENGINE}"
  echo "${tools}"
}

# Echoes the space-separated list of tools that are not on PATH. The "found"
# lines go to stderr so that stdout carries only the list.
find_missing_tools() {
  local missing="" tool
  for tool in $(required_tools); do
    if have "${tool}"; then
      ok "${tool}  $(command -v "${tool}")" >&2
    else
      missing="${missing}${missing:+ }${tool}"
    fi
  done
  echo "${missing}"
}

preflight() {
  step "Preflight"
  [[ "${CLUSTER_TYPE}" == "current" ]] && \
    ok "using current kubectl context: $(kubectl config current-context 2>/dev/null || echo '<none>')"

  local missing still
  missing="$(find_missing_tools)"

  if [[ -n "${missing}" ]]; then
    if maybe_install_tools ${missing}; then
      step "Re-checking"
      still="$(find_missing_tools)"
      [[ -z "${still}" ]] || die "Still missing after install: ${still}"
    else
      die "Missing: ${missing}. Install them and re-run, or use ./run.sh --yes."
    fi
  fi

  # Helm 3 or 4.
  local hv; hv="$(helm version --short 2>/dev/null || true)"
  case "${hv}" in
    v3*|v4*) ok "helm ${hv}" ;;
    *)       die "Helm 3 or 4 required (found: ${hv:-unknown})" ;;
  esac

  # Whether the engine is actually *usable* (podman machine running, docker
  # daemon up) is checked by scripts/engine.sh, just before the cluster is made.

  if [[ "${DEST_SPLUNK_AO}" == "true" && "${SPLUNK_AO_API_URL}" != http* ]]; then
    die "SPLUNK_AO_API_URL must start with http:// or https://"
  fi
  if [[ -n "${SPLUNK_HEC_ENDPOINT}" && "${SPLUNK_HEC_ENDPOINT}" != */services/collector/event ]]; then
    warn "SPLUNK_HEC_ENDPOINT does not end in /services/collector/event — field extraction may be wrong."
  fi

  step "This run's identity"
  dim "  demo.instance            ${DEMO_INSTANCE}"
  dim "  deployment.environment   ${DEPLOYMENT_ENVIRONMENT}"
  dim "  k8s.cluster.name         ${TELEMETRY_CLUSTER_NAME}"
  dim "  (set DEMO_INSTANCE in your env file to override)"

  step "Destinations"
  destline "${DEST_DATADOG}"     "Datadog"                     "site=${DD_SITE}"
  destline "${DEST_SPLUNK_O11Y}" "Splunk Observability Cloud"  "realm=${SPLUNK_O11Y_REALM}"
  destline "${DEST_SPLUNK_HEC}"  "Splunk Enterprise (HEC)"     "${SPLUNK_HEC_ENDPOINT}"
  destline "${DEST_SPLUNK_AO}"   "Splunk Agent Observability"  "project=${SPLUNK_AO_PROJECT}"
  destline "${KEEP_LOCAL_BACKENDS}" "Local Jaeger/Grafana"     "bundled with the demo"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  load_env
  preflight
fi
