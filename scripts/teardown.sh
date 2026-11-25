#!/usr/bin/env bash
# Removes the releases, and optionally the whole cluster.
#
#   scripts/teardown.sh            uninstall releases, keep the cluster
#   scripts/teardown.sh --cluster  also delete the minikube/kind cluster
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

teardown() {
  local drop_cluster="${1:-false}"

  step "Uninstalling releases from namespace ${NAMESPACE}"
  # splunk-otel-collector / datadog-agent are legacy: older versions of this
  # repo deployed them. Listed so an upgraded clone still cleans up fully.
  for release in otel-demo splunk-otel-collector datadog-agent; do
    if helm status "${release}" --namespace "${NAMESPACE}" >/dev/null 2>&1; then
      helm uninstall "${release}" --namespace "${NAMESPACE}" >/dev/null && ok "uninstalled ${release}"
    fi
  done
  kubectl delete deployment ai-load-generator --namespace "${NAMESPACE}" --ignore-not-found >/dev/null 2>&1 || true
  kubectl delete secret otel-demo-destinations --namespace "${NAMESPACE}" --ignore-not-found >/dev/null 2>&1 || true
  kubectl delete namespace "${NAMESPACE}" --ignore-not-found >/dev/null 2>&1 || true
  ok "namespace ${NAMESPACE} removed"

  if [[ "${drop_cluster}" == "true" ]]; then
    step "Deleting cluster"
    case "${CLUSTER_TYPE}" in
      minikube) minikube delete -p "${CLUSTER_NAME}" ;;
      kind)     KIND_EXPERIMENTAL_PROVIDER="${CONTAINER_ENGINE}" kind delete cluster --name "${CLUSTER_NAME}" ;;
      current)  warn "CLUSTER_TYPE=current — refusing to delete a cluster this script did not create." ;;
    esac
  fi
  rm -rf "${RENDER_DIR}"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  load_env
  drop=false
  [[ "${1:-}" == "--cluster" ]] && drop=true
  teardown "${drop}"
fi
