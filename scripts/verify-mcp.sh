#!/usr/bin/env bash
# Verifies the agent-facing environment: the credentials and endpoints that
# .mcp.json and the migration skills depend on.
#
# This checks the READ path an agent uses (Datadog inventory in, Splunk out).
# It does not touch the cluster, the collector, or any deployed telemetry —
# scripts/status.sh is the one that does that.
#
# Every check reports one of three outcomes:
#   ok    credentials present and the endpoint answered
#   ·     not configured, skipped on purpose
#   fail  configured but the endpoint rejected it or was unreachable
#
# Exit code is 0 unless something actually failed. A completely empty .env is
# a clean run with everything skipped.
#
# Written for bash 3.2 — the version macOS still ships.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

CHECK_FAILED=0
CHECK_PASSED=0
CHECK_SKIPPED=0

# Unlike load_env, this tolerates a missing .env: the agent variables are
# often exported into the shell directly rather than written to a file.
load_env_soft() {
  # shellcheck source=/dev/null
  [[ -f "${REPO_ROOT}/versions.env" ]] && source "${REPO_ROOT}/versions.env"

  local envfile="${ENV_FILE:-${REPO_ROOT}/.env}"
  if [[ -f "${envfile}" ]]; then
    set -a
    # shellcheck source=/dev/null
    source "${envfile}"
    set +a
    ENV_FILE_STATUS="${envfile}"
  else
    ENV_FILE_STATUS="none (using shell environment only)"
  fi

  : "${DD_API_KEY:=}"
  : "${DD_APP_KEY:=}"
  : "${DD_SITE:=datadoghq.com}"
  : "${DD_MCP_HOST:=mcp.datadoghq.com}"
  : "${DD_MCP_TOOLSETS:=core,dashboards,alerting}"
  : "${SPLUNK_O11Y_INNOVATIONLAB_TOKEN:=}"
  : "${SPLUNK_O11Y_INNOVATIONLAB_REALM:=eu1}"
  : "${SPLUNK_MCP_GATEWAY_URL:=}"
  : "${SPLUNK_MCP_PLATFORM_URL:=}"
  : "${SPLUNK_MCP_PLATFORM_TOKEN:=}"
  : "${SPLUNK_PLATFORM_API_URL:=}"
  : "${SPLUNK_PLATFORM_API_TOKEN:=}"
  : "${SPLUNK_HEC_ENDPOINT:=}"
  : "${SPLUNK_HEC_TOKEN:=}"
  : "${SPLUNK_HEC_INSECURE_SKIP_VERIFY:=false}"
  : "${MCP_REMOTE_VERSION:=0.1.49}"
}

# The SCS MCP Gateway is region-pinned and the region must match the o11y
# realm. Getting this wrong produces an authentication error that looks like a
# bad token, so it is worth catching here.
gateway_region_for_realm() {
  case "$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')" in
    eu0) echo "dub10" ;;
    eu1) echo "fra10" ;;
    eu2) echo "lon10" ;;
    us0) echo "iad10" ;;
    us1|us2|us3) echo "pdx10" ;;
    jp0) echo "tyo10" ;;
    au0) echo "syd10" ;;
    sg0) echo "sin10" ;;
    *)   echo "" ;;
  esac
}

pass()  { CHECK_PASSED=$((CHECK_PASSED + 1));   printf '  %sok%s   %-30s %s\n' "${C_GREEN}" "${C_RESET}" "$1" "${C_DIM}${2:-}${C_RESET}"; }
omit()  { CHECK_SKIPPED=$((CHECK_SKIPPED + 1)); printf '  %s·%s    %-30s %s\n' "${C_DIM}" "${C_RESET}" "$1" "${C_DIM}${2:-not configured}${C_RESET}"; }
bad()   { CHECK_FAILED=$((CHECK_FAILED + 1));   printf '  %sfail%s %-30s %s\n' "${C_RED}${C_BOLD}" "${C_RESET}" "$1" "$2"; }

# Echo the HTTP status of a request, or 000 when the host could not be reached.
# Never propagates a non-zero exit — callers decide what a code means.
#
# curl already writes 000 through --write-out when the transfer fails, so the
# exit status is swallowed rather than turned into a second value; appending
# one would produce "000000", which matches no case branch and would be read as
# a successful response.
http_code() {
  local url="$1" out; shift
  out="$(curl --silent --output /dev/null --write-out '%{http_code}' \
              --max-time "${VERIFY_TIMEOUT:-15}" --location "$@" "${url}" 2>/dev/null)" || true
  printf '%s' "${out:-000}"
}

# Describe an HTTP status in the terms this script cares about.
explain_code() {
  case "$1" in
    000) echo "unreachable (DNS, TLS, proxy or timeout)" ;;
    401) echo "HTTP 401 — credentials rejected" ;;
    403) echo "HTTP 403 — authenticated but not permitted" ;;
    404) echo "HTTP 404 — wrong URL for this deployment" ;;
    *)   echo "HTTP $1" ;;
  esac
}

check_tooling() {
  step "Tooling"
  if have curl; then pass "curl" "$(command -v curl)"; else bad "curl" "required by this script"; fi

  if have node && have npx; then
    pass "node / npx" "$(node --version 2>/dev/null)"
  elif [[ -n "${SPLUNK_MCP_PLATFORM_URL}" ]]; then
    bad "node / npx" "needed for the splunk-platform MCP server (mcp-remote bridge)"
  else
    omit "node / npx" "only needed for splunk-platform"
  fi

  if have jq; then pass "jq" "optional, used by the skills"; else omit "jq" "optional"; fi
}

check_datadog() {
  step "Datadog — migration source"

  # The MCP server itself authenticates over OAuth, so it is reachable and
  # useful without any key in .env. An unauthenticated request should be
  # refused, not dropped: that refusal is the proof the endpoint is live.
  local mcp_url code
  mcp_url="https://${DD_MCP_HOST}/api/unstable/mcp-server/mcp"
  code="$(http_code "${mcp_url}" --header 'Accept: text/event-stream')"
  case "${code}" in
    000) bad  "MCP endpoint" "${mcp_url} unreachable" ;;
    5*)  bad  "MCP endpoint" "$(explain_code "${code}") from ${DD_MCP_HOST}" ;;
    *)   pass "MCP endpoint" "${DD_MCP_HOST} reachable (${code}), toolsets=${DD_MCP_TOOLSETS}" ;;
  esac

  if [[ -z "${DD_API_KEY}" ]]; then
    omit "API key" "blank — MCP will use OAuth, which is fine"
  else
    code="$(http_code "https://api.${DD_SITE}/api/v1/validate" --header "DD-API-KEY: ${DD_API_KEY}")"
    if [[ "${code}" == "200" ]]; then
      pass "API key" "valid for site ${DD_SITE}"
    else
      bad "API key" "$(explain_code "${code}") — check DD_API_KEY matches DD_SITE=${DD_SITE}"
    fi
  fi

  # The application key is what actually authorises reading dashboards and
  # monitors, which is the whole input to the inventory skill.
  if [[ -z "${DD_APP_KEY}" ]]; then
    omit "application key" "blank — only needed for headless/CI or direct API reads"
  elif [[ -z "${DD_API_KEY}" ]]; then
    bad "application key" "DD_APP_KEY is set but DD_API_KEY is blank; the API needs both"
  else
    code="$(http_code "https://api.${DD_SITE}/api/v1/dashboard" \
              --header "DD-API-KEY: ${DD_API_KEY}" \
              --header "DD-APPLICATION-KEY: ${DD_APP_KEY}")"
    if [[ "${code}" == "200" ]]; then
      pass "application key" "can read dashboards + monitors"
    else
      bad "application key" "$(explain_code "${code}") — needs mcp_read plus Dashboards/Monitors read"
    fi
  fi
}

check_splunk_o11y() {
  step "Splunk Observability Cloud — migration target (metrics, APM)"

  local realm expected gateway code
  realm="${SPLUNK_O11Y_INNOVATIONLAB_REALM}"
  expected="$(gateway_region_for_realm "${realm}")"
  gateway="${SPLUNK_MCP_GATEWAY_URL:-https://region-fra10.api.scs.splunk.com/system/mcp-gateway/v1/}"

  if [[ -z "${expected}" ]]; then
    bad "gateway region" "no SCS region known for realm '${realm}'"
  elif [[ "${gateway}" != *"region-${expected}."* ]]; then
    bad "gateway region" "realm ${realm} needs region-${expected}, but the gateway URL is ${gateway}"
  else
    pass "gateway region" "realm ${realm} -> region-${expected}"
  fi

  code="$(http_code "${gateway}" --header 'Accept: text/event-stream')"
  case "${code}" in
    000) bad  "MCP gateway" "${gateway} unreachable" ;;
    5*)  bad  "MCP gateway" "$(explain_code "${code}")" ;;
    *)   pass "MCP gateway" "reachable (${code})" ;;
  esac

  if [[ -z "${SPLUNK_O11Y_INNOVATIONLAB_TOKEN}" ]]; then
    omit "API access token"
    return
  fi

  # An org read is the cheapest call that proves the token is an API access
  # token for this realm, and not an ingest token pasted by mistake.
  code="$(http_code "https://api.${realm}.signalfx.com/v2/organization" \
            --header "X-SF-Token: ${SPLUNK_O11Y_INNOVATIONLAB_TOKEN}")"
  if [[ "${code}" == "200" ]]; then
    pass "API access token" "valid in realm ${realm}"
  else
    bad "API access token" "$(explain_code "${code}") — must be an API access token, not an ingest token"
  fi
}

check_splunk_platform() {
  step "Splunk Enterprise / Cloud Platform — migration target (logs, SPL)"

  local code insecure=()
  [[ "${SPLUNK_HEC_INSECURE_SKIP_VERIFY}" == "true" ]] && insecure=(--insecure)

  if [[ -z "${SPLUNK_MCP_PLATFORM_URL}" ]]; then
    omit "MCP endpoint" "SPLUNK_MCP_PLATFORM_URL blank — server disabled"
  else
    code="$(http_code "${SPLUNK_MCP_PLATFORM_URL}" "${insecure[@]+"${insecure[@]}"}")"
    case "${code}" in
      000) bad  "MCP endpoint" "${SPLUNK_MCP_PLATFORM_URL} unreachable" ;;
      404) bad  "MCP endpoint" "HTTP 404 — is the Splunk MCP Server app installed on this search head?" ;;
      5*)  bad  "MCP endpoint" "$(explain_code "${code}")" ;;
      *)   pass "MCP endpoint" "reachable (${code})" ;;
    esac
  fi

  # The encrypted MCP token is deliberately unusable against the REST API, so
  # it can only be proven by an actual MCP handshake. All we can assert here is
  # that one was supplied.
  if [[ -z "${SPLUNK_MCP_PLATFORM_TOKEN}" ]]; then
    omit "MCP encrypted token"
  else
    pass "MCP encrypted token" "present (only testable through an MCP client)"
  fi

  if [[ -z "${SPLUNK_PLATFORM_API_URL}" || -z "${SPLUNK_PLATFORM_API_TOKEN}" ]]; then
    omit "platform REST API" "optional cross-check"
  else
    code="$(http_code "${SPLUNK_PLATFORM_API_URL%/}/services/server/info?output_mode=json" \
              --header "Authorization: Bearer ${SPLUNK_PLATFORM_API_TOKEN}" "${insecure[@]+"${insecure[@]}"}")"
    if [[ "${code}" == "200" ]]; then
      pass "platform REST API" "search head reachable and token accepted"
    else
      bad "platform REST API" "$(explain_code "${code}") — is token auth enabled on the search head?"
    fi
  fi

  if [[ -z "${SPLUNK_HEC_ENDPOINT}" || -z "${SPLUNK_HEC_TOKEN}" ]]; then
    omit "HEC ingest" "not configured"
  else
    code="$(http_code "${SPLUNK_HEC_ENDPOINT%/event}/health" "${insecure[@]+"${insecure[@]}"}")"
    if [[ "${code}" == "200" ]]; then
      pass "HEC ingest" "collector healthy"
    else
      bad "HEC ingest" "$(explain_code "${code}") at ${SPLUNK_HEC_ENDPOINT%/event}/health"
    fi
  fi
}

summarise() {
  # Both clients are driven by the same credentials; only the config format
  # differs. .mcp.json interpolates at read time, Codex needs the site-specific
  # values rendered in, which is what scripts/render-codex-mcp.sh does.
  step "MCP servers your clients will start"
  dim "  datadog                    OAuth on first use; no secret on disk"
  if [[ -n "${SPLUNK_O11Y_INNOVATIONLAB_TOKEN}" ]]; then
    dim "  splunk o11y                realm ${SPLUNK_O11Y_INNOVATIONLAB_REALM}"
  else
    dim "  splunk o11y                no token — Claude Code fails to connect, Codex sends an empty header"
  fi
  if [[ -n "${SPLUNK_MCP_PLATFORM_URL}" ]]; then
    dim "  splunk platform            Claude Code via mcp-remote@${MCP_REMOTE_VERSION}; Codex natively"
  else
    dim "  splunk platform            no endpoint — Claude Code fails to connect, Codex leaves it disabled"
  fi

  step "Result"
  dim "  env file: ${ENV_FILE_STATUS}"
  printf '  %d ok, %d skipped, %d failed\n' "${CHECK_PASSED}" "${CHECK_SKIPPED}" "${CHECK_FAILED}"

  if [[ "${CHECK_FAILED}" -gt 0 ]]; then
    warn "Fix the failures above, then re-run. See docs/MCP-SETUP.md."
    return 1
  fi

  if [[ "${CHECK_PASSED}" -eq 0 ]]; then
    warn "Nothing was verified — no credentials found. See docs/MCP-SETUP.md."
    return 0
  fi

  ok "Agent environment looks good."
  dim "  Both clients read the SHELL environment, not .env:"
  dim "      set -a; source .env; set +a; claude"
  dim "      set -a; source .env; set +a; codex     (after scripts/render-codex-mcp.sh)"
  return 0
}

verify_mcp() {
  load_env_soft
  check_tooling
  check_datadog
  check_splunk_o11y
  check_splunk_platform
  summarise
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  verify_mcp
fi
