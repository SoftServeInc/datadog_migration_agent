#!/usr/bin/env bash
# Error injection control for the running demo.
#
#   scripts/chaos.sh show                 current flag values
#   scripts/chaos.sh apply steady         load a profile from config/flagd/
#   scripts/chaos.sh set cartFailure 50%  flip one flag
#   scripts/chaos.sh randomize [seconds]  keep re-rolling flags forever
#
# All of these rewrite the chart's flagd-config ConfigMap and restart flagd,
# which is the same file the flagd UI edits at http://localhost:8080/feature.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

FLAG_FILE_KEY="demo.flagd.json"
# Owned by this repo, not by the demo chart. See scripts/render.sh.
FLAG_CONFIGMAP="otel-demo-flagd-flags"

current_json() {
  kube get configmap "${FLAG_CONFIGMAP}" -o "jsonpath={.data['demo\\.flagd\\.json']}"
}

write_flag_configmap() {
  local src="$1"
  kubectl create configmap "${FLAG_CONFIGMAP}" \
    --namespace "${NAMESPACE}" \
    --from-file="${FLAG_FILE_KEY}=${src}" \
    --dry-run=client -o yaml | kubectl apply -f - >/dev/null
}

restart_flagd() {
  kube rollout restart deployment/flagd >/dev/null
  kube rollout status deployment/flagd --timeout=120s >/dev/null
}

apply_profile() {
  local profile="${1:?profile name required}"
  local src="${REPO_ROOT}/config/flagd/${profile}.flagd.json"
  [[ -f "${src}" ]] || die "No such profile '${profile}'. Available: $(cd "${REPO_ROOT}/config/flagd" && ls *.flagd.json | sed 's/\.flagd\.json//' | tr '\n' ' ')"

  write_flag_configmap "${src}"
  restart_flagd
  ok "error injection profile '${profile}' applied"
  show_flags
}

set_flag() {
  local flag="${1:?flag name required}" variant="${2:?variant required}"
  local updated
  updated="$(current_json | python3 -c '
import json, sys
flag, variant = sys.argv[1], sys.argv[2]
d = json.load(sys.stdin)
if flag not in d["flags"]:
    sys.exit(f"unknown flag: {flag}")
variants = d["flags"][flag]["variants"]
if variant not in variants:
    sys.exit(f"unknown variant {variant!r} for {flag}; valid: {list(variants)}")
d["flags"][flag]["defaultVariant"] = variant
json.dump(d, sys.stdout, indent=2)
' "${flag}" "${variant}")" || die "flag update failed"

  printf '%s' "${updated}" > "${RENDER_DIR}/flagd-current.json"
  write_flag_configmap "${RENDER_DIR}/flagd-current.json"
  restart_flagd
  ok "${flag} = ${variant}"
}

show_flags() {
  current_json | python3 -c '
import json, sys
d = json.load(sys.stdin)
width = max(len(k) for k in d["flags"])
for name, flag in sorted(d["flags"].items()):
    default = flag["defaultVariant"]
    mark = " " if default in ("off", "0") else "*"
    print(f"  {mark} {name:<{width}}  {default}")
print("\n  * = active (non-default) setting")
'
}

# Re-rolls a handful of failure/latency flags at random. Useful for an
# unattended demo where you want the graphs to keep changing shape.
randomize_loop() {
  local interval="${1:-300}"
  local -a knobs=(
    "cartFailure:off,off,10%,25%,50%"
    "paymentFailure:off,off,10%,25%,50%"
    "recommendationCacheFailure:off,off,on"
    "imageSlowLoad:off,off,5sec,10sec"
    "intlShippingSlowdown:off,off,5sec"
    "adFailure:off,off,off,on"
  )
  log "randomizing error injection every ${interval}s (Ctrl-C to stop)"
  while true; do
    local knob="${knobs[RANDOM % ${#knobs[@]}]}"
    local flag="${knob%%:*}"
    local opts="${knob#*:}"
    IFS=',' read -r -a choices <<< "${opts}"
    set_flag "${flag}" "${choices[RANDOM % ${#choices[@]}]}"
    sleep "${interval}"
  done
}

chaos_main() {
  load_env
  mkdir -p "${RENDER_DIR}"
  case "${1:-show}" in
    show)      show_flags ;;
    apply)     apply_profile "${2:-}" ;;
    set)       set_flag "${2:-}" "${3:-}" ;;
    randomize) randomize_loop "${2:-300}" ;;
    *)         die "usage: $0 {show|apply <profile>|set <flag> <variant>|randomize [seconds]}" ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then chaos_main "$@"; fi
