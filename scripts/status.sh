#!/usr/bin/env bash
# Quick health check: are pods up, and is the collector actually exporting?
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

status() {
  step "Helm releases"
  helm list --namespace "${NAMESPACE}" 2>/dev/null || true

  step "Pods"
  kube get pods -o wide 2>/dev/null || true

  step "Pods not ready"
  local notready
  notready="$(kube get pods --no-headers 2>/dev/null | awk '$3 != "Running" && $3 != "Completed"')"
  if [[ -z "${notready}" ]]; then ok "none"; else echo "${notready}"; fi

  step "Collector exports"
  local logs
  logs="$(kube logs -l app.kubernetes.io/name=opentelemetry-collector --tail=2000 2>/dev/null || true)"
  if [[ -z "${logs}" ]]; then
    warn "no collector logs yet"
  else
    printf '%s\n' "${logs}" | python3 "${REPO_ROOT}/scripts/summarize-exports.py"
    if printf '%s\n' "${logs}" | grep -qE '401|403|Unauthenticated|invalid api key'; then
      warn "Authentication failure above — check the token, and that the realm/site matches it."
    fi
  fi

  step "Error injection"
  "${REPO_ROOT}/scripts/chaos.sh" show 2>/dev/null || warn "flagd not reachable"

  step "Destinations"
  destline "${DEST_DATADOG}"     "Datadog"                     "https://app.${DD_SITE}/apm/services"
  destline "${DEST_SPLUNK_O11Y}" "Splunk Observability Cloud"  "https://app.${SPLUNK_O11Y_REALM}.signalfx.com/#/apm"
  destline "${DEST_SPLUNK_HEC}"  "Splunk Enterprise (HEC)"     "index=${SPLUNK_HEC_INDEX_LOGS} / ${SPLUNK_HEC_INDEX_TRACES}"
  destline "${DEST_SPLUNK_AO}"   "Splunk Agent Observability"  "project=${SPLUNK_AO_PROJECT} stream=${SPLUNK_AO_AGENT_STREAM}"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  load_env
  status
fi
