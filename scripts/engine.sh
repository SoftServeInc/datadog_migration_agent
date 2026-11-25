#!/usr/bin/env bash
# Container engine readiness.
#
# Podman is the default. On macOS and Windows podman runs inside a VM it calls a
# "machine", which has to exist, be sized for the demo, and be running before
# minikube or kind can use it. On Linux podman is native and there is no machine.
#
# minikube's podman driver is still marked experimental upstream and requires a
# ROOTFUL machine. kind works with either, but rootful avoids a pile of cgroup
# and port-binding caveats, so this script standardises on rootful.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

# The podman machine needs headroom above what we hand to the cluster, otherwise
# minikube refuses to start ("requested memory exceeds available").
PODMAN_MACHINE_HEADROOM_MB=2048

machine_needed() {
  [[ "${CONTAINER_ENGINE}" == "podman" && "$(uname -s)" != "Linux" ]]
}

podman_machine_field() {
  podman machine inspect "${PODMAN_MACHINE_NAME}" --format "{{$1}}" 2>/dev/null || true
}

podman_machine_exists() {
  podman machine inspect "${PODMAN_MACHINE_NAME}" >/dev/null 2>&1
}

# Ask, unless AUTO_INSTALL_TOOLS says otherwise. Reused for both machine
# creation and the rootful switch.
confirm() {
  local prompt="$1"
  case "${AUTO_INSTALL_TOOLS:-ask}" in
    always) return 0 ;;
    never)  return 1 ;;
  esac
  [[ -t 0 ]] || { warn "Not an interactive terminal; re-run with --yes to allow this."; return 1; }
  local reply
  read -r -p "${prompt} [y/N] " reply
  [[ "${reply}" =~ ^[Yy] ]]
}

create_podman_machine() {
  local cpus="${CLUSTER_CPUS}"
  local mem=$(( CLUSTER_MEMORY_MB + PODMAN_MACHINE_HEADROOM_MB ))
  log "creating podman machine '${PODMAN_MACHINE_NAME}' (${cpus} cpu / ${mem} MiB / 60 GiB, rootful)"
  podman machine init "${PODMAN_MACHINE_NAME}" \
    --cpus "${cpus}" \
    --memory "${mem}" \
    --disk-size 60 \
    --rootful \
    --now
  ok "podman machine ready"
}

make_machine_rootful() {
  warn "podman machine '${PODMAN_MACHINE_NAME}' is rootless."
  warn "minikube's podman driver requires rootful, and kind is far less fiddly with it."
  if ! confirm "Stop the machine, switch it to rootful, and start it again?"; then
    die "Rootful podman machine required. Run manually:
    podman machine stop  ${PODMAN_MACHINE_NAME}
    podman machine set   ${PODMAN_MACHINE_NAME} --rootful
    podman machine start ${PODMAN_MACHINE_NAME}"
  fi
  podman machine stop "${PODMAN_MACHINE_NAME}" >/dev/null 2>&1 || true
  podman machine set "${PODMAN_MACHINE_NAME}" --rootful
  podman machine start "${PODMAN_MACHINE_NAME}"
  ok "machine is now rootful"
}

host_memory_mib() {
  case "$(uname -s)" in
    Darwin) sysctl -n hw.memsize 2>/dev/null | awk '{printf "%d", $1/1024/1024}' ;;
    Linux)  awk '/^MemTotal:/ {printf "%d", $2/1024}' /proc/meminfo 2>/dev/null ;;
  esac
}

# minikube refuses to start when the podman machine is smaller than the cluster
# it was asked for ("Podman has only NMB memory but you specified MMB"), so an
# undersized machine is a hard stop, not something to warn about and continue.
ensure_machine_size() {
  local want_mem=$(( CLUSTER_MEMORY_MB + PODMAN_MACHINE_HEADROOM_MB ))
  local cpus mem
  cpus="$(podman_machine_field '.Resources.CPUs')"
  mem="$(podman_machine_field '.Resources.Memory')"
  mem="$(printf '%s' "${mem}" | tr -cd '0-9')"

  [[ "${cpus}" =~ ^[0-9]+$ && "${mem}" =~ ^[0-9]+$ ]] || return 0   # unknown format, don't guess
  (( cpus >= CLUSTER_CPUS && mem >= want_mem )) && return 0

  # Only ever grow the machine. Someone who gave podman 7 CPUs does not want
  # this script handing them back 4.
  local target_cpus="${cpus}" target_mem="${mem}"
  (( target_cpus < CLUSTER_CPUS )) && target_cpus="${CLUSTER_CPUS}"
  (( target_mem  < want_mem     )) && target_mem="${want_mem}"

  local fix="    podman machine stop  ${PODMAN_MACHINE_NAME}
    podman machine set   ${PODMAN_MACHINE_NAME} --cpus ${target_cpus} --memory ${target_mem}
    podman machine start ${PODMAN_MACHINE_NAME}"

  warn "podman machine '${PODMAN_MACHINE_NAME}' has ${cpus} cpu / ${mem} MiB."
  warn "The cluster asks for ${CLUSTER_CPUS} cpu / ${CLUSTER_MEMORY_MB} MiB, so the machine"
  warn "needs at least ${want_mem} MiB. minikube will refuse to start otherwise."

  # Sanity-check the target against physical RAM before suggesting it.
  local host; host="$(host_memory_mib)"
  if [[ "${host}" =~ ^[0-9]+$ ]] && (( target_mem > host * 3 / 4 )); then
    warn "Careful: that is more than 75% of this machine's ${host} MiB of RAM."
    warn "Consider lowering CLUSTER_MEMORY_MB in your env file instead."
  fi

  if confirm "Grow the podman machine to ${target_cpus} cpu / ${target_mem} MiB? (stops and restarts it)"; then
    podman machine stop "${PODMAN_MACHINE_NAME}" >/dev/null 2>&1 || true
    podman machine set "${PODMAN_MACHINE_NAME}" --cpus "${target_cpus}" --memory "${target_mem}"
    podman machine start "${PODMAN_MACHINE_NAME}"
    ok "machine resized to ${target_cpus} cpu / ${target_mem} MiB"
    return 0
  fi

  # Only float "shrink the cluster instead" when the machine could actually
  # host something usable. The demo needs ~6 GiB even with the bundled
  # backends off; suggesting a 1.7 GiB cluster would just waste someone's time.
  local fits=$(( mem - PODMAN_MACHINE_HEADROOM_MB ))
  local alt=""
  if (( fits >= 6144 )); then
    alt="

  Or keep the machine as it is and ask for a smaller cluster in your env file:

    CLUSTER_MEMORY_MB=\"${fits}\"
    KEEP_LOCAL_BACKENDS=\"false\"   # already the default; frees ~3 GiB"
  fi

  die "podman machine too small for a ${CLUSTER_MEMORY_MB} MiB cluster.

  Grow the machine:

${fix}${alt}"
}

ensure_podman_machine() {
  if ! podman_machine_exists; then
    if ! confirm "No podman machine '${PODMAN_MACHINE_NAME}'. Create one for this demo?"; then
      die "A podman machine is required on $(uname -s). Create one with:
    podman machine init ${PODMAN_MACHINE_NAME} --cpus ${CLUSTER_CPUS} --memory $(( CLUSTER_MEMORY_MB + PODMAN_MACHINE_HEADROOM_MB )) --disk-size 60 --rootful --now"
    fi
    create_podman_machine
    return 0
  fi

  local state; state="$(podman_machine_field '.State')"
  if [[ "${state}" != "running" ]]; then
    log "starting podman machine '${PODMAN_MACHINE_NAME}' (state: ${state:-unknown})"
    podman machine start "${PODMAN_MACHINE_NAME}"
  fi
  ok "podman machine '${PODMAN_MACHINE_NAME}' running"

  [[ "$(podman_machine_field '.Rootful')" == "true" ]] || make_machine_rootful
  ensure_machine_size
}

ensure_container_engine() {
  [[ "${NEEDS_CONTAINER_ENGINE}" == "true" ]] || return 0
  step "Container engine (${CONTAINER_ENGINE})"

  if [[ "${CONTAINER_ENGINE}" == "podman" ]] && machine_needed; then
    ensure_podman_machine
  fi

  if ! "${CONTAINER_ENGINE}" info >/dev/null 2>&1; then
    warn "'${CONTAINER_ENGINE} info' failed — the engine is installed but not usable."
    case "${CONTAINER_ENGINE}" in
      podman)
        if machine_needed; then
          warn "Try: podman machine start ${PODMAN_MACHINE_NAME}"
        else
          warn "On Linux, check 'systemctl --user status podman.socket' and that your user can run podman."
        fi
        ;;
      docker)
        case "$(uname -s)" in
          Darwin) warn "Start Docker Desktop ('open -a Docker') or Colima ('colima start')." ;;
          *)      warn "Try 'sudo systemctl start docker', and confirm you are in the 'docker' group." ;;
        esac
        ;;
    esac
    die "${CONTAINER_ENGINE} is not usable."
  fi
  ok "${CONTAINER_ENGINE} $(${CONTAINER_ENGINE} version --format '{{.Client.Version}}' 2>/dev/null || echo '') responding"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  load_env
  ensure_container_engine
fi
