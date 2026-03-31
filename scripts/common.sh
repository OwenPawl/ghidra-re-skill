#!/usr/bin/env bash

set -euo pipefail

GHIDRA_RE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GHIDRA_RE_DEFAULT_USER_CONFIG="$HOME/.config/ghidra-re/config.env"
GHIDRA_RE_USER_CONFIG="${GHIDRA_RE_USER_CONFIG:-$GHIDRA_RE_DEFAULT_USER_CONFIG}"
GHIDRA_RE_SKILL_CONFIG="${GHIDRA_RE_SKILL_CONFIG:-$GHIDRA_RE_ROOT/local.env}"

if [[ -f "$GHIDRA_RE_USER_CONFIG" ]]; then
  # shellcheck disable=SC1090
  source "$GHIDRA_RE_USER_CONFIG"
fi
if [[ -f "$GHIDRA_RE_SKILL_CONFIG" ]]; then
  # shellcheck disable=SC1090
  source "$GHIDRA_RE_SKILL_CONFIG"
fi

GHIDRA_INSTALL_DIR="${GHIDRA_INSTALL_DIR:-/Applications/Ghidra}"
GHIDRA_JDK="${GHIDRA_JDK:-/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home}"
GHIDRA_WORKSPACE="${GHIDRA_WORKSPACE:-$HOME/ghidra-projects}"
GHIDRA_PROJECTS_DIR="${GHIDRA_PROJECTS_DIR:-$GHIDRA_WORKSPACE/projects}"
GHIDRA_EXPORTS_DIR="${GHIDRA_EXPORTS_DIR:-$GHIDRA_WORKSPACE/exports}"
GHIDRA_LOGS_DIR="${GHIDRA_LOGS_DIR:-$GHIDRA_WORKSPACE/logs}"
GHIDRA_CUSTOM_SCRIPTS_DIR="${GHIDRA_CUSTOM_SCRIPTS_DIR:-$GHIDRA_RE_ROOT/scripts/ghidra_scripts}"
GHIDRA_TEMPLATES_DIR="${GHIDRA_TEMPLATES_DIR:-$GHIDRA_RE_ROOT/templates}"
GHIDRA_RE_BUG_HUNT_MANIFEST="${GHIDRA_RE_BUG_HUNT_MANIFEST:-$GHIDRA_RE_ROOT/references/bug-hunt-patterns.json}"
GHIDRA_RE_BRIDGE_EXTENSION_DIR="${GHIDRA_RE_BRIDGE_EXTENSION_DIR:-$GHIDRA_RE_ROOT/bridge-extension/CodexGhidraBridge}"
GHIDRA_RE_BRIDGE_DIST_DIR="${GHIDRA_RE_BRIDGE_DIST_DIR:-$GHIDRA_RE_BRIDGE_EXTENSION_DIR/dist}"
GHIDRA_RE_BRIDGE_CONFIG_DIR="${GHIDRA_RE_BRIDGE_CONFIG_DIR:-$HOME/.config/ghidra-re}"
GHIDRA_RE_BRIDGE_SESSION_FILE="${GHIDRA_RE_BRIDGE_SESSION_FILE:-$GHIDRA_RE_BRIDGE_CONFIG_DIR/bridge-session.json}"
GHIDRA_RE_BRIDGE_CONTROL_FILE="${GHIDRA_RE_BRIDGE_CONTROL_FILE:-$GHIDRA_RE_BRIDGE_CONFIG_DIR/bridge-control.json}"

GHIDRA_DEFAULT_SCRIPT_DIRS=(
  "$GHIDRA_CUSTOM_SCRIPTS_DIR"
  "$GHIDRA_INSTALL_DIR/Ghidra/Features/Base/ghidra_scripts"
  "$GHIDRA_INSTALL_DIR/Ghidra/Features/Decompiler/ghidra_scripts"
  "$GHIDRA_INSTALL_DIR/Ghidra/Features/PyGhidra/ghidra_scripts"
  "$GHIDRA_INSTALL_DIR/Ghidra/Features/SwiftDemangler/ghidra_scripts"
  "$GHIDRA_INSTALL_DIR/Ghidra/Features/Jython/ghidra_scripts"
)

ghidra_re_die() {
  printf 'ghidra-re: %s\n' "$*" >&2
  exit 1
}

ghidra_re_valid_ghidra_dir() {
  local dir="${1:-}"
  [[ -n "$dir" && -x "$dir/support/analyzeHeadless" && -x "$dir/ghidraRun" ]]
}

ghidra_re_valid_jdk_dir() {
  local dir="${1:-}"
  [[ -n "$dir" && -x "$dir/bin/java" ]]
}

ghidra_re_require_tools() {
  ghidra_re_valid_ghidra_dir "$GHIDRA_INSTALL_DIR" || ghidra_re_die "missing Ghidra install at $GHIDRA_INSTALL_DIR"
  ghidra_re_valid_jdk_dir "$GHIDRA_JDK" || ghidra_re_die "missing JDK at $GHIDRA_JDK"
}

ghidra_re_export_env() {
  export JAVA_HOME="$GHIDRA_JDK"
  export PATH="$JAVA_HOME/bin:$PATH"
  export GHIDRA_INSTALL_DIR
}

ghidra_re_detect_ghidra_dir() {
  local -a candidates=()
  local candidate
  if ghidra_re_valid_ghidra_dir "${GHIDRA_INSTALL_DIR:-}"; then
    printf '%s\n' "$GHIDRA_INSTALL_DIR"
    return 0
  fi
  candidates+=(
    /Applications/Ghidra
    "$HOME/Applications/Ghidra"
  )
  shopt -s nullglob
  candidates+=(
    /Applications/ghidra_*
    /Applications/Ghidra_*
    "$HOME"/Applications/ghidra_*
    "$HOME"/Applications/Ghidra_*
    "$HOME"/Downloads/ghidra_*
    "$HOME"/Downloads/Ghidra_*
  )
  shopt -u nullglob
  for candidate in "${candidates[@]}"; do
    if ghidra_re_valid_ghidra_dir "$candidate"; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

ghidra_re_detect_jdk_dir() {
  local candidate=""
  if ghidra_re_valid_jdk_dir "${GHIDRA_JDK:-}"; then
    printf '%s\n' "$GHIDRA_JDK"
    return 0
  fi
  for candidate in \
    /opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home \
    /usr/local/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home
  do
    if ghidra_re_valid_jdk_dir "$candidate"; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  if [[ -x /usr/libexec/java_home ]]; then
    candidate="$(/usr/libexec/java_home -v 21 2>/dev/null || true)"
    if ghidra_re_valid_jdk_dir "$candidate"; then
      printf '%s\n' "$candidate"
      return 0
    fi
  fi
  return 1
}

ghidra_re_ensure_workspace() {
  mkdir -p "$GHIDRA_PROJECTS_DIR" "$GHIDRA_EXPORTS_DIR" "$GHIDRA_LOGS_DIR"
}

ghidra_re_timestamp() {
  date '+%Y%m%d-%H%M%S'
}

ghidra_re_sanitize_name() {
  local raw="$1"
  raw="${raw##*/}"
  raw="${raw%.*}"
  raw="$(printf '%s' "$raw" | tr '[:space:]/:' '_' | tr -cd '[:alnum:]_.-')"
  if [[ -z "$raw" ]]; then
    raw="ghidra_project"
  fi
  printf '%s' "$raw"
}

ghidra_re_project_location() {
  printf '%s/%s' "$GHIDRA_PROJECTS_DIR" "$1"
}

ghidra_re_project_file() {
  printf '%s/%s/%s.gpr' "$GHIDRA_PROJECTS_DIR" "$1" "$1"
}

ghidra_re_log_dir() {
  printf '%s/%s' "$GHIDRA_LOGS_DIR" "$1"
}

ghidra_re_export_dir() {
  printf '%s/%s/%s' "$GHIDRA_EXPORTS_DIR" "$1" "$2"
}

ghidra_re_bug_hunt_dir() {
  printf '%s/%s/%s/bug-hunt' "$GHIDRA_EXPORTS_DIR" "$1" "$2"
}

ghidra_re_dossiers_dir() {
  printf '%s/%s/%s/dossiers' "$GHIDRA_EXPORTS_DIR" "$1" "$2"
}

ghidra_re_findings_dir() {
  printf '%s/%s/%s/findings' "$GHIDRA_EXPORTS_DIR" "$1" "$2"
}

ghidra_re_program_name_from_binary() {
  basename "$1"
}

ghidra_re_bug_hunt_manifest() {
  [[ -f "$GHIDRA_RE_BUG_HUNT_MANIFEST" ]] || \
    ghidra_re_die "bug-hunt manifest not found at $GHIDRA_RE_BUG_HUNT_MANIFEST"
  printf '%s' "$GHIDRA_RE_BUG_HUNT_MANIFEST"
}

ghidra_re_join_script_paths() {
  local joined=""
  local path
  for path in "$@"; do
    [[ -z "$path" ]] && continue
    if [[ -z "$joined" ]]; then
      joined="$path"
    else
      joined="${joined};${path}"
    fi
  done
  printf '%s' "$joined"
}

ghidra_re_script_path() {
  local dirs=("${GHIDRA_DEFAULT_SCRIPT_DIRS[@]}")
  local extra
  for extra in "$@"; do
    [[ -z "$extra" ]] && continue
    dirs+=("$extra")
  done
  ghidra_re_join_script_paths "${dirs[@]}"
}

ghidra_re_optional_headless_args() {
  local args=()
  if [[ -n "${GHIDRA_ANALYSIS_TIMEOUT_PER_FILE:-}" ]]; then
    args+=("-analysisTimeoutPerFile" "$GHIDRA_ANALYSIS_TIMEOUT_PER_FILE")
  fi
  if [[ -n "${GHIDRA_MAX_CPU:-}" ]]; then
    args+=("-max-cpu" "$GHIDRA_MAX_CPU")
  fi
  if [[ ${#args[@]} -eq 0 ]]; then
    return 0
  fi
  printf '%s\0' "${args[@]}"
}

ghidra_re_normalize_script_args() {
  local normalized=()
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --*=*)
        normalized+=("${1#--}")
        shift
        ;;
      --*)
        [[ $# -ge 2 ]] || ghidra_re_die "missing value for script argument $1"
        normalized+=("${1#--}=$2")
        shift 2
        ;;
      *)
        normalized+=("$1")
        shift
        ;;
    esac
  done
  if [[ ${#normalized[@]} -eq 0 ]]; then
    return 0
  fi
  printf '%s\0' "${normalized[@]}"
}

ghidra_re_flag_enabled() {
  local value="${1:-}"
  case "$value" in
    1|true|yes|on|"")
      return 0
      ;;
    0|false|no|off)
      return 1
      ;;
    *)
      ghidra_re_die "unsupported boolean flag value: $value"
      ;;
  esac
}

ghidra_re_require_project() {
  local project_name="$1"
  [[ -f "$(ghidra_re_project_file "$project_name")" ]] || ghidra_re_die "project $project_name not found at $(ghidra_re_project_file "$project_name")"
}

ghidra_re_detect_ghidra_version() {
  local properties_file="$GHIDRA_INSTALL_DIR/Ghidra/application.properties"
  [[ -f "$properties_file" ]] || return 1
  awk -F= '/^application.version=/{print $2; exit}' "$properties_file"
}

ghidra_re_bridge_settings_dir() {
  if [[ -n "${GHIDRA_RE_GHIDRA_SETTINGS_DIR:-}" ]]; then
    printf '%s' "$GHIDRA_RE_GHIDRA_SETTINGS_DIR"
    return 0
  fi
  local root="$HOME/Library/Ghidra"
  local detected=""
  if [[ -d "$root" ]]; then
    detected="$(find "$root" -maxdepth 1 -type d -name 'ghidra_*_PUBLIC' | sort | tail -n 1)"
    if [[ -n "$detected" ]]; then
      printf '%s' "$detected"
      return 0
    fi
  fi
  local version=""
  version="$(ghidra_re_detect_ghidra_version || true)"
  if [[ -n "$version" ]]; then
    printf '%s/Library/Ghidra/ghidra_%s_PUBLIC' "$HOME" "$version"
    return 0
  fi
  return 1
}

ghidra_re_bridge_extensions_dir() {
  printf '%s/Ghidra/Extensions' "$GHIDRA_INSTALL_DIR"
}

ghidra_re_bridge_installed_dir() {
  printf '%s/CodexGhidraBridge' "$(ghidra_re_bridge_extensions_dir)"
}

ghidra_re_bridge_tools_dir() {
  printf '%s/tools' "$(ghidra_re_bridge_settings_dir)"
}

ghidra_re_bridge_dist_zip() {
  local latest=""
  latest="$(find "$GHIDRA_RE_BRIDGE_DIST_DIR" -maxdepth 1 -type f -name 'ghidra_*_CodexGhidraBridge.zip' | sort | tail -n 1)"
  [[ -n "$latest" ]] || ghidra_re_die "bridge zip not found in $GHIDRA_RE_BRIDGE_DIST_DIR"
  printf '%s' "$latest"
}

ghidra_re_bridge_require_session() {
  [[ -f "$GHIDRA_RE_BRIDGE_SESSION_FILE" ]] || ghidra_re_die "bridge session not found at $GHIDRA_RE_BRIDGE_SESSION_FILE"
}

ghidra_re_bridge_read_session_value() {
  local key="$1"
  ghidra_re_bridge_require_session
  /usr/bin/plutil -extract "$key" raw -o - "$GHIDRA_RE_BRIDGE_SESSION_FILE" 2>/dev/null || true
}

ghidra_re_bridge_wait_for_session() {
  local timeout_seconds="${1:-30}"
  local require_program="${2:-0}"
  local expected_program="${3:-}"
  local started
  started="$(date +%s)"
  while true; do
    if ghidra_re_bridge_session_healthy; then
      if [[ "$require_program" != "1" ]]; then
        return 0
      fi
      local program_path=""
      program_path="$(ghidra_re_bridge_read_session_value program_path)"
      if [[ -n "$program_path" ]]; then
        if [[ -z "$expected_program" || "$program_path" == "$expected_program" || "$program_path" == */"$expected_program" ]]; then
          return 0
        fi
      fi
    fi
    if (( "$(date +%s)" - started >= timeout_seconds )); then
      return 1
    fi
    sleep 1
  done
}

ghidra_re_bridge_wait_for_disarm() {
  local timeout_seconds="${1:-15}"
  local started
  started="$(date +%s)"
  while true; do
    [[ ! -f "$GHIDRA_RE_BRIDGE_SESSION_FILE" ]] && return 0
    if (( "$(date +%s)" - started >= timeout_seconds )); then
      return 1
    fi
    sleep 1
  done
}

ghidra_re_ghidra_running() {
  pgrep -f 'ghidra\.GhidraRun|/Applications/Ghidra/ghidraRun|/Applications/Ghidra/support/launch\.sh' >/dev/null 2>&1
}

ghidra_re_bridge_clear_state_files() {
  rm -f "$GHIDRA_RE_BRIDGE_SESSION_FILE" "$GHIDRA_RE_BRIDGE_CONTROL_FILE"
}

ghidra_re_bridge_session_pid_alive() {
  local pid=""
  [[ -f "$GHIDRA_RE_BRIDGE_SESSION_FILE" ]] || return 1
  pid="$(ghidra_re_bridge_read_session_value pid)"
  [[ -n "$pid" ]] || return 1
  kill -0 "$pid" >/dev/null 2>&1
}

ghidra_re_bridge_prune_stale_session() {
  [[ -f "$GHIDRA_RE_BRIDGE_SESSION_FILE" ]] || return 0
  if ghidra_re_bridge_session_pid_alive; then
    return 0
  fi
  rm -f "$GHIDRA_RE_BRIDGE_SESSION_FILE"
}

ghidra_re_bridge_session_healthy() {
  ghidra_re_bridge_prune_stale_session
  if [[ ! -f "$GHIDRA_RE_BRIDGE_SESSION_FILE" ]]; then
    return 1
  fi
  local url=""
  local token=""
  local response=""
  local ok=""
  if ! ghidra_re_bridge_session_pid_alive; then
    return 1
  fi
  url="$(ghidra_re_bridge_read_session_value bridge_url)"
  token="$(ghidra_re_bridge_read_session_value token)"
  [[ -n "$url" && -n "$token" ]] || return 1
  response="$(curl -fsS --max-time 2 \
    -X POST \
    -H "Authorization: Bearer $token" \
    -H 'Content-Type: application/json' \
    --data '{}' \
    "$url/health" 2>/dev/null || true)"
  [[ -n "$response" ]] || return 1
  ok="$(printf '%s' "$response" | /usr/bin/ruby -rjson -e '
payload = JSON.parse(STDIN.read) rescue nil
STDOUT.write(payload.is_a?(Hash) && payload["ok"] ? "true" : "false")
')"
  [[ "$ok" == "true" ]]
}

ghidra_re_bridge_require_healthy_session() {
  ghidra_re_bridge_prune_stale_session
  ghidra_re_bridge_require_session
  ghidra_re_bridge_session_healthy || \
    ghidra_re_die "bridge session at $GHIDRA_RE_BRIDGE_SESSION_FILE is stale or unreachable; arm the bridge again"
}

ghidra_re_bridge_session_matches_program() {
  local requested_program="${1:-}"
  local program_path=""
  [[ -z "$requested_program" ]] && return 0
  program_path="$(ghidra_re_bridge_read_session_value program_path)"
  [[ -n "$program_path" ]] || return 1
  [[ "$program_path" == "$requested_program" || "$program_path" == */"$requested_program" ]]
}

ghidra_re_bridge_session_matches_project() {
  local requested_project="${1:-}"
  local project_path=""
  [[ -z "$requested_project" ]] && return 0
  project_path="$(ghidra_re_bridge_read_session_value project_path)"
  [[ -n "$project_path" ]] || return 1
  [[ "$project_path" == "$(ghidra_re_project_file "$requested_project")" || "$project_path" == */"$requested_project.gpr" ]]
}

ghidra_re_gui_app_path() {
  local -a candidates=(
    /Applications/Ghidra.app
    "$HOME/Applications/Ghidra.app"
  )
  local candidate=""
  for candidate in "${candidates[@]}"; do
    if [[ -d "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

ghidra_re_bridge_launch_label() {
  local project_name="$1"
  printf 'com.codex.ghidra-re.%s.%s.%s' \
    "$(ghidra_re_sanitize_name "$project_name")" \
    "$(date +%s)" \
    "$RANDOM"
}

ghidra_re_launch_gui_project() {
  local project_file="$1"
  local launch_mode="${2:-default}"
  local project_name=""
  project_name="$(basename "$project_file" .gpr)"
  if [[ "$(uname -s)" == "Darwin" ]] && command -v screen >/dev/null 2>&1; then
    local screen_name=""
    local log_dir=""
    local log_file=""
    local launch_cmd=""
    local quoted_java_home=""
    local quoted_ghidra_run=""
    local quoted_project_file=""
    local quoted_log_file=""
    screen_name="codex-ghidra-$(ghidra_re_sanitize_name "$project_name")-$(date +%s)-$RANDOM"
    log_dir="$(ghidra_re_log_dir "$project_name")/bridge-launch"
    mkdir -p "$log_dir"
    log_file="$log_dir/launch-$(ghidra_re_timestamp)-${launch_mode}.log"
    printf -v quoted_java_home '%q' "$GHIDRA_JDK"
    printf -v quoted_ghidra_run '%q' "$GHIDRA_INSTALL_DIR/ghidraRun"
    printf -v quoted_project_file '%q' "$project_file"
    printf -v quoted_log_file '%q' "$log_file"
    launch_cmd="export JAVA_HOME=$quoted_java_home; export PATH=\"\$JAVA_HOME/bin:\$PATH\"; $quoted_ghidra_run $quoted_project_file >>$quoted_log_file 2>&1; while ps ax -o command= | grep -F 'ghidra.GhidraRun' | grep -F $quoted_project_file >/dev/null 2>&1; do sleep 5; done"
    screen -dmS "$screen_name" /bin/sh -lc "$launch_cmd"
    return 0
  fi
  if [[ "$(uname -s)" == "Darwin" ]] && command -v launchctl >/dev/null 2>&1; then
    local label=""
    local log_dir=""
    local log_file=""
    label="$(ghidra_re_bridge_launch_label "$project_name")"
    log_dir="$(ghidra_re_log_dir "$project_name")/bridge-launch"
    mkdir -p "$log_dir"
    log_file="$log_dir/launch-$(ghidra_re_timestamp)-${launch_mode}.log"
    launchctl submit \
      -l "$label" \
      -o "$log_file" \
      -e "$log_file" \
      -- /bin/sh -c 'export JAVA_HOME="$1"; export PATH="$JAVA_HOME/bin:$PATH"; exec "$2" "$3"' \
      sh \
      "$GHIDRA_JDK" \
      "$GHIDRA_INSTALL_DIR/ghidraRun" \
      "$project_file"
    return 0
  fi
  nohup "$GHIDRA_INSTALL_DIR/ghidraRun" "$project_file" </dev/null >/dev/null 2>&1 &
}

ghidra_re_bridge_write_control_file() {
  local command="$1"
  local project_name="${2:-}"
  local program_name="${3:-}"
  local tmp_file=""
  mkdir -p "$GHIDRA_RE_BRIDGE_CONFIG_DIR"
  tmp_file="$(mktemp "$GHIDRA_RE_BRIDGE_CONFIG_DIR/bridge-control.XXXXXX.tmp")"
  /usr/bin/ruby -rjson -rtime -e '
payload = {
  "command" => ARGV[0],
  "project_name" => ARGV[1],
  "program_name" => ARGV[2],
  "requested_at" => Time.now.utc.iso8601
}
STDOUT.write(JSON.pretty_generate(payload))
' "$command" "$project_name" "$program_name" >"$tmp_file"
  mv "$tmp_file" "$GHIDRA_RE_BRIDGE_CONTROL_FILE"
}

ghidra_re_bridge_json_from_kv() {
  /usr/bin/ruby -rjson -e '
payload = {}
ARGV.each do |arg|
  key, value = arg.split("=", 2)
  next if key.nil? || key.empty?
  if value.nil?
    payload[key] = true
  elsif value.start_with?("json:")
    payload[key] = JSON.parse(value[5..-1])
  elsif value == "true"
    payload[key] = true
  elsif value == "false"
    payload[key] = false
  elsif value.match?(/\A-?\d+\z/)
    payload[key] = value.to_i
  else
    payload[key] = value
  end
end
STDOUT.write(JSON.generate(payload))
' "$@"
}
