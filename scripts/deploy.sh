#!/usr/bin/env bash
# Installs / upgrades every Helm release and the extra manifests.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
source "$(dirname "${BASH_SOURCE[0]}")/chaos.sh"

add_repos() {
  step "Helm repositories"
  helm repo add open-telemetry "${OTEL_HELM_REPO}" >/dev/null 2>&1 || true
  helm repo update >/dev/null
  ok "repositories up to date"
}

create_secret() {
  step "Credentials"
  # One Secret holds every destination credential. Empty values are fine; the
  # rendered collector config only references the keys it actually needs.
  # 'api-key' is the key name the Datadog chart expects for apiKeyExistingSecret.
  kubectl create secret generic otel-demo-destinations \
    --namespace "${NAMESPACE}" \
    --from-literal=api-key="${DD_API_KEY}" \
    --from-literal=datadog-api-key="${DD_API_KEY}" \
    --from-literal=splunk-o11y-access-token="${SPLUNK_O11Y_ACCESS_TOKEN}" \
    --from-literal=splunk-hec-token="${SPLUNK_HEC_TOKEN}" \
    --from-literal=splunk-ao-api-key="${SPLUNK_AO_API_KEY}" \
    --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  ok "secret/otel-demo-destinations"
}

# One-time repair. Earlier versions of this repo wrote the demo chart's own
# flagd-config ConfigMap with `kubectl apply`, which gives field ownership of
# .data to kubectl-client-side-apply. Helm 4 applies server-side and refuses to
# reclaim those fields, so every subsequent upgrade fails with:
#   conflict with "kubectl-client-side-apply" using v1: .data.demo.flagd.json
# Flags now live in a ConfigMap this repo owns, so the chart's copy can simply be
# dropped; Helm recreates it cleanly on the next upgrade.
migrate_flagd_ownership() {
  kube get configmap flagd-config >/dev/null 2>&1 || return 0
  kube get configmap flagd-config --show-managed-fields -o json 2>/dev/null \
    | grep -q 'kubectl-client-side-apply' || return 0
  log "clearing stale field ownership on the chart's flagd-config ConfigMap"
  kube delete configmap flagd-config >/dev/null
  ok "flagd-config removed; Helm will recreate it"
}

# flagd mounts this, so it has to exist before the chart is installed.
FLAGD_FLAGS_CHANGED=false
ensure_flagd_flags() {
  step "Error injection (${ERROR_INJECTION_PROFILE})"
  local src="${REPO_ROOT}/config/flagd/${ERROR_INJECTION_PROFILE}.flagd.json"
  [[ -f "${src}" ]] || die "No such profile '${ERROR_INJECTION_PROFILE}'. Available: $(cd "${REPO_ROOT}/config/flagd" && ls ./*.flagd.json | sed 's|.*/||; s|\.flagd\.json||' | tr '\n' ' ')"

  local current desired
  current="$(current_json 2>/dev/null || true)"
  desired="$(cat "${src}")"
  if [[ "${current}" == "${desired}" ]]; then
    ok "flags already match profile '${ERROR_INJECTION_PROFILE}'"
    return 0
  fi
  write_flag_configmap "${src}"
  FLAGD_FLAGS_CHANGED=true
  ok "configmap/${FLAG_CONFIGMAP} written from profile '${ERROR_INJECTION_PROFILE}'"
}

# The flags ConfigMap is outside the chart, so Helm will not roll flagd for us.
finalize_flagd() {
  if [[ "${FLAGD_FLAGS_CHANGED}" == "true" ]] && kube get deployment flagd >/dev/null 2>&1; then
    restart_flagd
  fi
  show_flags 2>/dev/null || true
}

install_demo() {
  step "OpenTelemetry Demo (chart ${OTEL_DEMO_CHART_VERSION})"
  helm upgrade --install otel-demo open-telemetry/opentelemetry-demo \
    --version "${OTEL_DEMO_CHART_VERSION}" \
    --namespace "${NAMESPACE}" \
    --values "${RENDER_DIR}/demo-values.yaml" \
    --timeout 20m
  ok "release otel-demo"
}

# Earlier versions of this repo could deploy the splunk-otel-collector and
# datadog Helm charts alongside the demo for vendor-native infrastructure views.
# That is gone: one OpenTelemetry Collector now serves every backend, including
# Splunk's Kubernetes navigator (see docs/ARCHITECTURE.md). Any release left
# over from an older run is removed here so clusters converge on the new shape.
remove_legacy_vendor_agents() {
  local release
  for release in splunk-otel-collector datadog-agent; do
    if helm status "${release}" --namespace "${NAMESPACE}" >/dev/null 2>&1; then
      log "removing ${release} (no longer part of this stack)"
      helm uninstall "${release}" --namespace "${NAMESPACE}" >/dev/null
      ok "uninstalled ${release}"
    fi
  done
}

install_ai_load() {
  step "AI agent load"
  if [[ "${AI_LOAD_ENABLED}" != "true" ]]; then
    kube delete deployment ai-load-generator --ignore-not-found >/dev/null 2>&1 || true
    dim "  disabled (AI_LOAD_ENABLED=false)"
    return 0
  fi
  mkdir -p "${RENDER_DIR}"
  sed "s|__AI_LOAD_INTERVAL__|${AI_LOAD_INTERVAL_SECONDS}|" \
    "${REPO_ROOT}/manifests/ai-load-generator.yaml" > "${RENDER_DIR}/ai-load-generator.yaml"
  kubectl apply --namespace "${NAMESPACE}" -f "${RENDER_DIR}/ai-load-generator.yaml" >/dev/null
  ok "deployment/ai-load-generator (every ${AI_LOAD_INTERVAL_SECONDS}s)"
}

wait_for_rollout() {
  step "Waiting for workloads"
  local deadline=$(( SECONDS + 900 ))
  local pending
  while (( SECONDS < deadline )); do
    pending="$(kube get deployments -o json 2>/dev/null \
      | python3 -c '
import json, sys
d = json.load(sys.stdin)
bad = [i["metadata"]["name"] for i in d["items"]
       if i["status"].get("readyReplicas", 0) < (i["spec"].get("replicas") or 0)]
print(" ".join(sorted(bad)))')"
    if [[ -z "${pending}" ]]; then
      ok "all deployments ready"
      return 0
    fi
    printf '\r%s  waiting on: %-70.70s%s' "${C_DIM}" "${pending}" "${C_RESET}"
    sleep 10
  done
  printf '\n'
  warn "Timed out waiting for: ${pending}"
  warn "Run 'scripts/status.sh' — on a small cluster this is usually memory pressure."
}

deploy_all() {
  add_repos
  create_secret
  migrate_flagd_ownership
  ensure_flagd_flags
  install_demo
  remove_legacy_vendor_agents
  install_ai_load
  wait_for_rollout
  finalize_flagd
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  load_env
  deploy_all
fi
