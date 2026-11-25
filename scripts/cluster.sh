#!/usr/bin/env bash
# Creates (or reuses) the local Kubernetes cluster.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
source "$(dirname "${BASH_SOURCE[0]}")/engine.sh"

ensure_cluster() {
  ensure_container_engine

  step "Cluster (${CLUSTER_TYPE})"

  case "${CLUSTER_TYPE}" in
    minikube) ensure_minikube ;;
    kind)     ensure_kind ;;
    current)  ok "reusing context $(kubectl config current-context)" ;;
  esac

  kubectl cluster-info >/dev/null 2>&1 \
    || die "Cannot reach the cluster. Check 'kubectl config current-context'."

  local nodes; nodes="$(kubectl get nodes --no-headers 2>/dev/null | wc -l | tr -d ' ')"
  ok "cluster reachable, ${nodes} node(s)"
  if (( nodes > 1 )); then
    warn "Multi-node cluster detected. The collector runs as a DaemonSet and collects"
    warn "Kubernetes events with a k8sobjects receiver that has no leader election, so"
    warn "events will be duplicated per node. See docs/ARCHITECTURE.md."
  fi

  kubectl get namespace "${NAMESPACE}" >/dev/null 2>&1 \
    || kubectl create namespace "${NAMESPACE}" >/dev/null
  ok "namespace ${NAMESPACE}"
}

ensure_minikube() {
  if minikube status -p "${CLUSTER_NAME}" >/dev/null 2>&1; then
    ok "minikube profile '${CLUSTER_NAME}' already running"
  else
    local -a extra=()
    if [[ "${EFFECTIVE_MINIKUBE_DRIVER}" == "podman" ]]; then
      # minikube's podman driver pairs with CRI-O; the docker runtime is not
      # available inside a podman-provisioned node. Upstream still labels this
      # driver experimental — if it misbehaves, ./run.sh --cluster kind is the
      # better-trodden podman path.
      extra+=(--container-runtime=cri-o)
    fi
    log "starting minikube (${CLUSTER_CPUS} cpu / ${CLUSTER_MEMORY_MB} MiB / driver=${EFFECTIVE_MINIKUBE_DRIVER})"
    minikube start \
      -p "${CLUSTER_NAME}" \
      --driver="${EFFECTIVE_MINIKUBE_DRIVER}" \
      --cpus="${CLUSTER_CPUS}" \
      --memory="${CLUSTER_MEMORY_MB}" \
      --addons=metrics-server \
      ${extra[@]+"${extra[@]}"}
  fi
  kubectl config use-context "${CLUSTER_NAME}" >/dev/null
}

ensure_kind() {
  # kind auto-detects an engine; pin it so a stray docker install cannot win.
  export KIND_EXPERIMENTAL_PROVIDER="${CONTAINER_ENGINE}"
  if kind get clusters 2>/dev/null | grep -qx "${CLUSTER_NAME}"; then
    ok "kind cluster '${CLUSTER_NAME}' already exists"
  else
    log "creating kind cluster '${CLUSTER_NAME}'"
    # kind inherits the Docker VM's resources; there is nothing to size here.
    # extraPortMappings gives the storefront a stable localhost port without
    # a long-lived kubectl port-forward.
    kind create cluster --name "${CLUSTER_NAME}" --config=- <<'KINDEOF'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    extraPortMappings:
      - containerPort: 30080
        hostPort: 8080
        protocol: TCP
KINDEOF
  fi
  kubectl config use-context "kind-${CLUSTER_NAME}" >/dev/null
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  load_env
  ensure_cluster
fi
