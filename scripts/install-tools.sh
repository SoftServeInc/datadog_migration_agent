#!/usr/bin/env bash
# Installs the tools preflight found missing.
#
# Homebrew is used when it is available (macOS, or Linuxbrew). Otherwise the
# official release binaries are downloaded straight from the upstream projects:
#
#   kubectl   dl.k8s.io                       (Kubernetes)
#   helm      get.helm.sh                     (Helm)
#   minikube  storage.googleapis.com/minikube (minikube)
#   kind      kind.sigs.k8s.io/dl             (kind)
#
# Podman is installed via Homebrew or the system package manager. Docker is
# never installed silently — it needs a daemon or a VM, a one-time launch, and
# on macOS a licence decision that is not this script's to make.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

# --- platform ----------------------------------------------------------------

os_name() {
  case "$(uname -s)" in
    Darwin) echo darwin ;;
    Linux)  echo linux ;;
    *)      die "Unsupported OS: $(uname -s). Install the tools manually." ;;
  esac
}

arch_name() {
  case "$(uname -m)" in
    arm64|aarch64) echo arm64 ;;
    x86_64|amd64)  echo amd64 ;;
    *)             die "Unsupported architecture: $(uname -m). Install the tools manually." ;;
  esac
}

# Where downloaded binaries go when Homebrew is not in play.
# Override with TOOLS_INSTALL_DIR. Never uses sudo without asking.
SUDO=""
resolve_install_dir() {
  if [[ -n "${TOOLS_INSTALL_DIR:-}" ]]; then
    mkdir -p "${TOOLS_INSTALL_DIR}"
    echo "${TOOLS_INSTALL_DIR}"; return
  fi
  if [[ -w /usr/local/bin ]]; then
    echo /usr/local/bin; return
  fi
  if [[ "$(id -u)" == "0" ]]; then
    echo /usr/local/bin; return
  fi
  if have sudo && sudo -n true 2>/dev/null; then
    SUDO="sudo"; echo /usr/local/bin; return
  fi
  mkdir -p "${HOME}/.local/bin"
  echo "${HOME}/.local/bin"
}

# --- fetch helpers -----------------------------------------------------------

# fetch_binary <url> <destination-name>
fetch_binary() {
  local url="$1" name="$2" dir tmp
  dir="$(resolve_install_dir)"
  tmp="$(mktemp -d)"
  curl -fsSL "${url}" -o "${tmp}/${name}" || { rm -rf "${tmp}"; die "download failed: ${url}"; }
  chmod +x "${tmp}/${name}"
  ${SUDO} mv "${tmp}/${name}" "${dir}/${name}" || { rm -rf "${tmp}"; die "could not write to ${dir}"; }
  rm -rf "${tmp}"
  ensure_on_path "${dir}"
  ok "${name} -> ${dir}/${name}"
}

# Makes the directory usable for the rest of this run, and tells the user how
# to make it stick.
PATH_HINT_SHOWN=false
ensure_on_path() {
  local dir="$1"
  case ":${PATH}:" in
    *":${dir}:"*) return 0 ;;
  esac
  export PATH="${dir}:${PATH}"
  if [[ "${PATH_HINT_SHOWN}" == "false" ]]; then
    warn "${dir} is not on your PATH. Added for this run only. To make it permanent:"
    warn "    echo 'export PATH=\"${dir}:\$PATH\"' >> ~/.$(basename "${SHELL:-bash}")rc"
    PATH_HINT_SHOWN=true
  fi
}

latest_github_tag() {
  local repo="$1" tag
  tag="$(curl -fsSL "https://api.github.com/repos/${repo}/releases/latest" 2>/dev/null \
        | grep -m1 '"tag_name"' | cut -d'"' -f4)"
  [[ -n "${tag}" ]] || die "Could not determine the latest ${repo} release (GitHub API rate limit?). Install it manually."
  echo "${tag}"
}

# --- per-tool installers -----------------------------------------------------

install_kubectl() {
  if have brew; then brew install kubernetes-cli && return; fi
  local ver; ver="$(curl -fsSL https://dl.k8s.io/release/stable.txt)"
  [[ -n "${ver}" ]] || die "Could not reach dl.k8s.io to resolve the kubectl version."
  fetch_binary "https://dl.k8s.io/release/${ver}/bin/$(os_name)/$(arch_name)/kubectl" kubectl
}

install_helm() {
  if have brew; then brew install helm && return; fi
  local ver os arch dir tmp
  ver="$(latest_github_tag helm/helm)"
  os="$(os_name)"; arch="$(arch_name)"
  dir="$(resolve_install_dir)"
  tmp="$(mktemp -d)"
  curl -fsSL "https://get.helm.sh/helm-${ver}-${os}-${arch}.tar.gz" -o "${tmp}/helm.tgz" \
    || { rm -rf "${tmp}"; die "helm download failed"; }
  tar -xzf "${tmp}/helm.tgz" -C "${tmp}"
  chmod +x "${tmp}/${os}-${arch}/helm"
  ${SUDO} mv "${tmp}/${os}-${arch}/helm" "${dir}/helm" || { rm -rf "${tmp}"; die "could not write to ${dir}"; }
  rm -rf "${tmp}"
  ensure_on_path "${dir}"
  ok "helm ${ver} -> ${dir}/helm"
}

install_minikube() {
  if have brew; then brew install minikube && return; fi
  fetch_binary "https://storage.googleapis.com/minikube/releases/latest/minikube-$(os_name)-$(arch_name)" minikube
}

install_kind() {
  if have brew; then brew install kind && return; fi
  local ver; ver="$(latest_github_tag kubernetes-sigs/kind)"
  fetch_binary "https://kind.sigs.k8s.io/dl/${ver}/kind-$(os_name)-$(arch_name)" kind
}

install_podman() {
  if have brew; then brew install podman && return; fi
  case "$(os_name)" in
    linux)
      local pm=""
      have apt-get && pm="apt-get"
      [[ -z "${pm}" ]] && have dnf && pm="dnf"
      [[ -z "${pm}" ]] && have yum && pm="yum"
      [[ -z "${pm}" ]] && have zypper && pm="zypper"
      [[ -z "${pm}" ]] && have pacman && pm="pacman"
      if [[ -z "${pm}" ]]; then
        warn "No supported package manager found. Install podman from https://podman.io/docs/installation"
        return 1
      fi
      local sudo_cmd=""
      [[ "$(id -u)" == "0" ]] || sudo_cmd="sudo"
      if [[ -n "${sudo_cmd}" ]] && ! have sudo; then
        warn "podman needs root to install and sudo is unavailable. Install it manually."
        return 1
      fi
      log "installing podman with ${pm} (you may be prompted for your password)"
      case "${pm}" in
        apt-get) ${sudo_cmd} apt-get update -qq && ${sudo_cmd} apt-get install -y podman ;;
        dnf|yum) ${sudo_cmd} "${pm}" install -y podman ;;
        zypper)  ${sudo_cmd} zypper --non-interactive install podman ;;
        pacman)  ${sudo_cmd} pacman -Sy --noconfirm podman ;;
      esac
      ;;
    darwin)
      warn "Homebrew is not installed, and podman on macOS needs its helper binaries."
      echo
      cat <<'PODMANMAC'
  Install Homebrew first, then re-run:

    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    brew install podman

  Or grab the macOS installer package from:

    https://github.com/containers/podman/releases
PODMANMAC
      echo
      return 1
      ;;
  esac
}

# Deliberately guidance-only. See the header comment.
install_docker() {
  warn "Docker is not installed, and this script will not install it for you."
  echo
  case "$(os_name)" in
    darwin)
      cat <<'DOCKERMAC'
  On macOS, pick one:

    Docker Desktop (GUI, check your organisation's licence terms)
      brew install --cask docker
      open -a Docker            # launch once, then raise memory in
                                # Settings > Resources to at least 10 GiB

    Colima (CLI only, no licence question)
      brew install colima docker
      colima start --cpu 4 --memory 12

  Or use podman instead — this repo's default — by removing
  CONTAINER_ENGINE="docker" from .env.

  Or skip container engines entirely and let minikube use a native VM:

    MINIKUBE_DRIVER="vfkit"     # in .env  (Apple silicon; also: qemu2)
DOCKERMAC
      ;;
    linux)
      cat <<'DOCKERLINUX'
  On Linux:

    curl -fsSL https://get.docker.com | sh
    sudo usermod -aG docker "$USER"    # then log out and back in

  Amazon Linux 2023:

    sudo dnf install -y docker && sudo systemctl enable --now docker
    sudo usermod -aG docker "$USER"

  Or use podman instead — this repo's default — by removing
  CONTAINER_ENGINE="docker" from .env.

  Or skip container engines entirely and let minikube use a native VM:

    MINIKUBE_DRIVER="kvm2"      # in .env  (needs libvirt)
DOCKERLINUX
      ;;
  esac
  echo
  return 1
}

install_python3() {
  warn "python3 is missing. It ships with macOS and every mainstream Linux, so this"
  warn "is unusual — install it with your system package manager rather than here."
  return 1
}

# --- driver ------------------------------------------------------------------

install_one() {
  case "$1" in
    kubectl)  install_kubectl ;;
    podman)   install_podman ;;
    helm)     install_helm ;;
    minikube) install_minikube ;;
    kind)     install_kind ;;
    docker)   install_docker ;;
    python3)  install_python3 ;;
    *)        warn "no installer for '$1'"; return 1 ;;
  esac
}

# maybe_install_tools <tool>...
# Honours AUTO_INSTALL_TOOLS: ask (default) | always | never
# Returns 0 if everything is now present, 1 otherwise.
maybe_install_tools() {
  local wanted="$*"
  [[ -n "${wanted}" ]] || return 0

  local t auto="" manual=""
  for t in ${wanted}; do
    case "${t}" in
      docker|python3) manual="${manual}${manual:+ }${t}" ;;
      *)              auto="${auto}${auto:+ }${t}" ;;
    esac
  done

  step "Missing tools"
  for t in ${auto};   do printf '  %s·%s %-10s %s\n' "${C_DIM}" "${C_RESET}" "${t}" "${C_DIM}$(installer_label)${C_RESET}"; done
  for t in ${manual}; do printf '  %s·%s %-10s %s\n' "${C_DIM}" "${C_RESET}" "${t}" "${C_DIM}manual — see below${C_RESET}"; done
  echo

  # Guidance for the tools this script will not install is always useful, so
  # print it regardless of the install policy.
  for t in ${manual}; do install_one "${t}" || true; done

  if [[ -z "${auto}" ]]; then
    return 1   # nothing installable; the manual tools still block the run
  fi

  local policy="${AUTO_INSTALL_TOOLS:-ask}"
  case "${policy}" in
    never)
      warn "AUTO_INSTALL_TOOLS=never — not installing anything."
      return 1
      ;;
    always) ;;
    ask)
      if [[ ! -t 0 ]]; then
        warn "Not an interactive terminal. Re-run with --yes, or set AUTO_INSTALL_TOOLS=always in .env."
        return 1
      fi
      local reply
      read -r -p "Install ${auto} now? [y/N] " reply
      [[ "${reply}" =~ ^[Yy] ]] || { warn "Skipped. Install them yourself and re-run."; return 1; }
      ;;
    *)
      die "AUTO_INSTALL_TOOLS must be ask, always or never (got '${policy}')"
      ;;
  esac

  step "Installing"
  local failed=0
  for t in ${auto}; do
    log "installing ${t}"
    install_one "${t}" || failed=1
  done

  hash -r 2>/dev/null || true

  # A manual tool that is still missing blocks the run even if the
  # auto-installs succeeded.
  for t in ${manual}; do have "${t}" || failed=1; done
  return "${failed}"
}

installer_label() {
  if have brew; then echo "brew"; else echo "official release binary"; fi
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  load_env
  maybe_install_tools "$@"
fi
