#!/usr/bin/env bash
# Port-forwards the storefront. Everything the demo exposes is behind this one
# port via frontend-proxy:
#
#   http://localhost:8080/           Astronomy Shop storefront
#   http://localhost:8080/chatbot    AI assistant (drives GenAI spans on demand)
#   http://localhost:8080/feature    flagd UI — toggle failures by hand
#   http://localhost:8080/jaeger/ui  Jaeger      (KEEP_LOCAL_BACKENDS=true only)
#   http://localhost:8080/grafana    Grafana     (KEEP_LOCAL_BACKENDS=true only)
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  load_env
  log "forwarding http://localhost:8080 -> frontend-proxy (Ctrl-C to stop)"
  exec kubectl port-forward --namespace "${NAMESPACE}" svc/frontend-proxy 8080:8080
fi
