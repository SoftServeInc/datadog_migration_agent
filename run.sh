#!/usr/bin/env bash
# =============================================================================
# One command: cluster -> OpenTelemetry Demo -> collector fan-out -> your
# observability backends, with load and random error injection already running.
#
#   cp .env.example .env   # fill in the destinations you have
#   ./run.sh
#
# Flags:
#   --env-file PATH    read config from PATH instead of ./.env
#   --yes, -y          install any missing tools without asking
#   --no-install       never install tools; fail if something is missing
#   --skip-cluster     assume the cluster already exists
#   --skip-forward     don't port-forward at the end
#   --render-only      generate .render/*.yaml and stop (nothing is deployed)
#   --cluster TYPE     override CLUSTER_TYPE (minikube|kind|current)
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/scripts/lib.sh"
source "${SCRIPT_DIR}/scripts/preflight.sh"
source "${SCRIPT_DIR}/scripts/engine.sh"
source "${SCRIPT_DIR}/scripts/cluster.sh"
source "${SCRIPT_DIR}/scripts/render.sh"
source "${SCRIPT_DIR}/scripts/deploy.sh"

SKIP_CLUSTER=false
SKIP_FORWARD=false
RENDER_ONLY=false
CLUSTER_OVERRIDE=""
INSTALL_OVERRIDE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --env-file)     export ENV_FILE="${2:?--env-file needs a path}"; shift 2 ;;
    -y|--yes)       INSTALL_OVERRIDE="always"; shift ;;
    --no-install)   INSTALL_OVERRIDE="never"; shift ;;
    --skip-cluster) SKIP_CLUSTER=true; shift ;;
    --skip-forward) SKIP_FORWARD=true; shift ;;
    --render-only)  RENDER_ONLY=true; shift ;;
    --cluster)      CLUSTER_OVERRIDE="${2:?--cluster needs a value}"; shift 2 ;;
    -h|--help)      sed -n '3,16p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *)              die "unknown flag: $1 (try --help)" ;;
  esac
done

summary() {
  step "Ready"
  cat <<'URLS'
  Storefront      http://localhost:8080/
  AI assistant    http://localhost:8080/chatbot
  Feature flags   http://localhost:8080/feature
URLS
  if [[ "${KEEP_LOCAL_BACKENDS}" == "true" ]]; then
    cat <<'LOCALURLS'
  Jaeger          http://localhost:8080/jaeger/ui
  Grafana         http://localhost:8080/grafana
LOCALURLS
  fi
  echo
  dim "  Filter every backend by  deployment.environment = ${DEPLOYMENT_ENVIRONMENT}"
  echo
  [[ "${DEST_DATADOG}"     == "true" ]] && dim "  Datadog APM        https://app.${DD_SITE}/apm/services   (env:${DEPLOYMENT_ENVIRONMENT})"
  [[ "${DEST_SPLUNK_O11Y}" == "true" ]] && dim "  Splunk APM         https://app.${SPLUNK_O11Y_REALM}.signalfx.com/#/apm   (environment ${DEPLOYMENT_ENVIRONMENT})"
  [[ "${DEST_SPLUNK_HEC}"  == "true" ]] && dim "  Splunk Enterprise  search index=${SPLUNK_HEC_INDEX_LOGS} OR index=${SPLUNK_HEC_INDEX_TRACES}"
  [[ "${DEST_SPLUNK_AO}"   == "true" ]] && dim "  Splunk Agent Obs.  project '${SPLUNK_AO_PROJECT}', agent stream '${SPLUNK_AO_AGENT_STREAM}'"
  cat <<'NEXT'

  Next:
    scripts/status.sh                  health + export errors
    scripts/chaos.sh show              current failure flags
    scripts/chaos.sh apply chaos       turn the failure rate up
    scripts/chaos.sh randomize 300     keep re-rolling failures every 5 min
    scripts/teardown.sh --cluster      remove everything

  Telemetry takes 1-3 minutes to show up in a SaaS backend after first start.
NEXT
}

main() {
  load_env
  [[ -n "${CLUSTER_OVERRIDE}" ]] && CLUSTER_TYPE="${CLUSTER_OVERRIDE}"
  [[ -n "${INSTALL_OVERRIDE}" ]] && AUTO_INSTALL_TOOLS="${INSTALL_OVERRIDE}"

  # --render-only touches nothing, so it does not need helm or a cluster tool.
  if [[ "${RENDER_ONLY}" == "true" ]]; then
    render_values
    step "Render only"
    dim "  inspect: ${RENDER_DIR#"${REPO_ROOT}/"}/"
    exit 0
  fi

  preflight

  [[ "${SKIP_CLUSTER}" == "true" ]] || ensure_cluster
  render_values
  deploy_all
  summary

  if [[ "${SKIP_FORWARD}" != "true" ]]; then
    step "Port-forward"
    exec "${SCRIPT_DIR}/scripts/forward.sh"
  fi
}

main
