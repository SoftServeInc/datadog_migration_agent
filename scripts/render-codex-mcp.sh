#!/usr/bin/env bash
# Renders the Codex MCP server definitions from .env.
#
# Codex configuration is TOML and TOML has no variable interpolation, so unlike
# .mcp.json the site-specific values — Datadog host, o11y realm and its gateway
# region, the Splunk search head URL — have to be written out literally. This
# script is what keeps them in step with .env.
#
#   scripts/render-codex-mcp.sh              write .codex/config.toml (project-scoped)
#   scripts/render-codex-mcp.sh --print      print the block, change nothing
#   scripts/render-codex-mcp.sh --install    merge into ~/.codex/config.toml (global)
#   scripts/render-codex-mcp.sh --dry-run    show what --install would change
#
# Credentials are never rendered. Codex resolves them at connect time from the
# environment through bearer_token_env_var and env_http_headers.
#
# Written for bash 3.2 — the version macOS still ships.

# verify-mcp.sh only runs its checks when executed directly, so sourcing it is
# safe and gives us lib.sh, load_env_soft and the realm/region mapping without
# a second copy of either.
source "$(dirname "${BASH_SOURCE[0]}")/verify-mcp.sh"

# Everything this script manages in a shared file lives between these markers,
# so a re-run replaces its own output and leaves the user's config untouched.
MARK_START="# >>> cisco-innovation MCP servers — managed by scripts/render-codex-mcp.sh >>>"
MARK_END="# <<< cisco-innovation MCP servers <<<"

CODEX_CONFIG_HOME="${CODEX_HOME:-${HOME}/.codex}"
PROJECT_CONFIG="${REPO_ROOT}/.codex/config.toml"

usage() {
  sed -n '2,18p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

# The Splunk endpoint is the one org-specific value with no safe default, so an
# unset one disables the server rather than leaving a broken entry that fails on
# every Codex start.
render_toml() {
  local region platform_enabled="false" platform_url="${SPLUNK_MCP_PLATFORM_URL}"
  region="$(gateway_region_for_realm "${SPLUNK_O11Y_INNOVATIONLAB_REALM}")"
  [[ -n "${region}" ]] || die "No SCS gateway region known for o11y realm '${SPLUNK_O11Y_INNOVATIONLAB_REALM}'"

  local gateway="${SPLUNK_MCP_GATEWAY_URL:-https://region-${region}.api.scs.splunk.com/system/mcp-gateway/v1/}"
  [[ -n "${platform_url}" ]] && platform_enabled="true"

  cat <<TOML
${MARK_START}
# Generated from .env — edit .env and re-run, do not hand-edit this block.
# Secrets stay in the environment: see bearer_token_env_var / env_http_headers.

[mcp_servers.datadog]
url = "https://${DD_MCP_HOST}/api/unstable/mcp-server/mcp"
http_headers = { "X-Datadog-MCP-Toolsets" = "${DD_MCP_TOOLSETS}" }
startup_timeout_sec = 30
# Authenticate with:  codex mcp login datadog
# Headless instead? Uncomment (these are env var NAMES, not values):
# env_http_headers = { "DD_API_KEY" = "DD_API_KEY", "DD_APPLICATION_KEY" = "DD_APP_KEY" }

[mcp_servers.splunk_o11y]
url = "${gateway}"
http_headers = { "X-SF-REALM" = "${SPLUNK_O11Y_INNOVATIONLAB_REALM}" }
env_http_headers = { "X-SF-TOKEN" = "SPLUNK_O11Y_INNOVATIONLAB_TOKEN" }
startup_timeout_sec = 20

[mcp_servers.splunk_platform]
url = "${platform_url}"
bearer_token_env_var = "SPLUNK_MCP_PLATFORM_TOKEN"
enabled = ${platform_enabled}
startup_timeout_sec = 20
${MARK_END}
TOML
}

# Replace an existing managed block in place, or append one. Pure text, so it
# works without a TOML parser — macOS ships Python 3.9, which has no tomllib.
merge_into() {
  local target="$1" rendered="$2" tmp
  tmp="$(mktemp)"

  if [[ -f "${target}" ]] && grep -qF "${MARK_START}" "${target}"; then
    awk -v start="${MARK_START}" -v end="${MARK_END}" -v block="${rendered}" '
      index($0, start) == 1 { printf "%s\n", block; skipping = 1; next }
      index($0, end)   == 1 { skipping = 0; next }
      !skipping           { print }
    ' "${target}" > "${tmp}"
  else
    [[ -f "${target}" ]] && cat "${target}" > "${tmp}"
    [[ -s "${tmp}" ]] && printf '\n' >> "${tmp}"
    printf '%s\n' "${rendered}" >> "${tmp}"
  fi

  printf '%s' "${tmp}"
}

summarise_render() {
  step "Rendered from"
  dim "  env file            ${ENV_FILE_STATUS}"
  dim "  Datadog host        ${DD_MCP_HOST}  (must match DD_SITE=${DD_SITE})"
  dim "  Datadog toolsets    ${DD_MCP_TOOLSETS}"
  dim "  o11y realm          ${SPLUNK_O11Y_INNOVATIONLAB_REALM} -> region-$(gateway_region_for_realm "${SPLUNK_O11Y_INNOVATIONLAB_REALM}")"
  if [[ -n "${SPLUNK_MCP_PLATFORM_URL}" ]]; then
    dim "  Splunk platform     ${SPLUNK_MCP_PLATFORM_URL}"
  else
    dim "  Splunk platform     disabled (SPLUNK_MCP_PLATFORM_URL is blank)"
  fi
}

render_codex_mcp() {
  local mode="project"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --print)       mode="print" ;;
      --install)     mode="install" ;;
      --dry-run)     mode="dry-run" ;;
      -h|--help)     usage 0 ;;
      *)             warn "Unknown option: $1"; usage 1 ;;
    esac
    shift
  done

  load_env_soft

  local rendered
  rendered="$(render_toml)"

  case "${mode}" in
    print)
      printf '%s\n' "${rendered}"
      return 0
      ;;

    project)
      mkdir -p "$(dirname "${PROJECT_CONFIG}")"
      local tmp; tmp="$(merge_into "${PROJECT_CONFIG}" "${rendered}")"
      cat "${tmp}" > "${PROJECT_CONFIG}"
      rm -f "${tmp}"
      summarise_render
      step "Wrote"
      ok "${PROJECT_CONFIG}"
      dim "  Project-scoped config applies to trusted projects only."
      dim "  For a global install instead:  scripts/render-codex-mcp.sh --install"
      ;;

    install|dry-run)
      local target="${CODEX_CONFIG_HOME}/config.toml"
      local tmp; tmp="$(merge_into "${target}" "${rendered}")"

      if [[ "${mode}" == "dry-run" ]]; then
        summarise_render
        step "Diff against ${target}"
        if [[ -f "${target}" ]]; then
          diff -u "${target}" "${tmp}" || true
        else
          dim "  (file does not exist yet — it would be created)"
          printf '%s\n' "${rendered}"
        fi
        rm -f "${tmp}"
        warn "Dry run — nothing was written."
        return 0
      fi

      mkdir -p "${CODEX_CONFIG_HOME}"
      # Codex config can hold unrelated settings, so keep one step back.
      if [[ -f "${target}" ]]; then
        cp "${target}" "${target}.bak"
      fi
      cat "${tmp}" > "${target}"
      rm -f "${tmp}"

      summarise_render
      step "Wrote"
      ok "${target}"
      [[ -f "${target}.bak" ]] && dim "  previous version kept at ${target}.bak"
      ;;
  esac

  step "Next"
  dim "  export the credentials, then start Codex:"
  dim "      set -a; source .env; set +a"
  dim "      codex mcp login datadog      # once, unless using header auth"
  dim "      codex mcp list               # confirm all three are present"
  dim "  verify the endpoints behind them:  scripts/verify-mcp.sh"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  render_codex_mcp "$@"
fi
