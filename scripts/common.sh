#!/usr/bin/env bash

set -euo pipefail

case "$(uname -s)" in
  Darwin)
    GHIDRA_RE_PLATFORM_DEFAULT="macos"
    GHIDRA_RE_CONFIG_HOME_DEFAULT="$HOME/.config/ghidra-re"
    GHIDRA_INSTALL_DIR_DEFAULT="/Applications/Ghidra"
    GHIDRA_JDK_DEFAULT="/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home"
    ;;
  MINGW*|MSYS*|CYGWIN*)
    GHIDRA_RE_PLATFORM_DEFAULT="windows"
    if [[ -n "${APPDATA:-}" ]]; then
      GHIDRA_RE_CONFIG_HOME_DEFAULT="$APPDATA/ghidra-re"
    else
      GHIDRA_RE_CONFIG_HOME_DEFAULT="$HOME/AppData/Roaming/ghidra-re"
    fi
    GHIDRA_INSTALL_DIR_DEFAULT="/c/Program Files/Ghidra"
    GHIDRA_JDK_DEFAULT="/c/Program Files/Eclipse Adoptium/jdk-21"
    ;;
  *)
    GHIDRA_RE_PLATFORM_DEFAULT="linux"
    GHIDRA_RE_CONFIG_HOME_DEFAULT="$HOME/.config/ghidra-re"
    GHIDRA_INSTALL_DIR_DEFAULT="/opt/ghidra"
    GHIDRA_JDK_DEFAULT="${JAVA_HOME:-/usr/lib/jvm/default-java}"
    ;;
esac

GHIDRA_RE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GHIDRA_RE_PLATFORM="${GHIDRA_RE_PLATFORM:-$GHIDRA_RE_PLATFORM_DEFAULT}"
GHIDRA_RE_CONFIG_HOME="${GHIDRA_RE_CONFIG_HOME:-$GHIDRA_RE_CONFIG_HOME_DEFAULT}"
GHIDRA_RE_DEFAULT_USER_CONFIG="$GHIDRA_RE_CONFIG_HOME/config.env"
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

GHIDRA_INSTALL_DIR="${GHIDRA_INSTALL_DIR:-$GHIDRA_INSTALL_DIR_DEFAULT}"
GHIDRA_JDK="${GHIDRA_JDK:-$GHIDRA_JDK_DEFAULT}"
GHIDRA_WORKSPACE="${GHIDRA_WORKSPACE:-$HOME/ghidra-projects}"
GHIDRA_PROJECTS_DIR="${GHIDRA_PROJECTS_DIR:-$GHIDRA_WORKSPACE/projects}"
GHIDRA_EXPORTS_DIR="${GHIDRA_EXPORTS_DIR:-$GHIDRA_WORKSPACE/exports}"
GHIDRA_LOGS_DIR="${GHIDRA_LOGS_DIR:-$GHIDRA_WORKSPACE/logs}"
GHIDRA_INVESTIGATIONS_DIR="${GHIDRA_INVESTIGATIONS_DIR:-$GHIDRA_WORKSPACE/investigations}"
GHIDRA_SOURCES_CACHE_DIR="${GHIDRA_SOURCES_CACHE_DIR:-$GHIDRA_WORKSPACE/sources}"
GHIDRA_CUSTOM_SCRIPTS_DIR="${GHIDRA_CUSTOM_SCRIPTS_DIR:-$GHIDRA_RE_ROOT/scripts/ghidra_scripts}"
GHIDRA_TEMPLATES_DIR="${GHIDRA_TEMPLATES_DIR:-$GHIDRA_RE_ROOT/templates}"
GHIDRA_RE_BUG_HUNT_MANIFEST="${GHIDRA_RE_BUG_HUNT_MANIFEST:-$GHIDRA_RE_ROOT/references/bug-hunt-patterns.json}"
GHIDRA_RE_BRIDGE_EXTENSION_DIR="${GHIDRA_RE_BRIDGE_EXTENSION_DIR:-$GHIDRA_RE_ROOT/bridge-extension/CodexGhidraBridge}"
GHIDRA_RE_BRIDGE_DIST_DIR="${GHIDRA_RE_BRIDGE_DIST_DIR:-$GHIDRA_RE_BRIDGE_EXTENSION_DIR/dist}"
GHIDRA_RE_BRIDGE_CONFIG_DIR="${GHIDRA_RE_BRIDGE_CONFIG_DIR:-$GHIDRA_RE_CONFIG_HOME}"
GHIDRA_RE_BRIDGE_SESSIONS_DIR="${GHIDRA_RE_BRIDGE_SESSIONS_DIR:-$GHIDRA_RE_BRIDGE_CONFIG_DIR/bridge-sessions}"
GHIDRA_RE_BRIDGE_REQUESTS_DIR="${GHIDRA_RE_BRIDGE_REQUESTS_DIR:-$GHIDRA_RE_BRIDGE_CONFIG_DIR/bridge-requests}"
GHIDRA_RE_BRIDGE_CURRENT_FILE="${GHIDRA_RE_BRIDGE_CURRENT_FILE:-$GHIDRA_RE_BRIDGE_CONFIG_DIR/bridge-current.json}"
GHIDRA_RE_BRIDGE_LEGACY_SESSION_FILE="${GHIDRA_RE_BRIDGE_LEGACY_SESSION_FILE:-$GHIDRA_RE_BRIDGE_CONFIG_DIR/bridge-session.json}"
GHIDRA_RE_BRIDGE_LEGACY_CONTROL_FILE="${GHIDRA_RE_BRIDGE_LEGACY_CONTROL_FILE:-$GHIDRA_RE_BRIDGE_CONFIG_DIR/bridge-control.json}"
GHIDRA_RE_BRIDGE_SESSION_FILE="${GHIDRA_RE_BRIDGE_SESSION_FILE:-$GHIDRA_RE_BRIDGE_CURRENT_FILE}"
GHIDRA_RE_BRIDGE_CONTROL_FILE="${GHIDRA_RE_BRIDGE_CONTROL_FILE:-$GHIDRA_RE_BRIDGE_LEGACY_CONTROL_FILE}"
GHIDRA_RE_SOURCE_REGISTRY_FILE="${GHIDRA_RE_SOURCE_REGISTRY_FILE:-$GHIDRA_RE_CONFIG_HOME/sources.json}"

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

ghidra_re_python() {
  if command -v python3 >/dev/null 2>&1; then
    printf '%s\n' python3
    return 0
  fi
  if command -v python >/dev/null 2>&1; then
    printf '%s\n' python
    return 0
  fi
  return 1
}

ghidra_re_platform_is_windows() {
  [[ "$GHIDRA_RE_PLATFORM" == "windows" ]]
}

ghidra_re_platform_is_macos() {
  [[ "$GHIDRA_RE_PLATFORM" == "macos" ]]
}

ghidra_re_ghidra_run_path() {
  local dir="${1:-$GHIDRA_INSTALL_DIR}"
  local candidate=""
  for candidate in "$dir/ghidraRun" "$dir/ghidraRun.bat"; do
    [[ -f "$candidate" ]] && {
      printf '%s\n' "$candidate"
      return 0
    }
  done
  return 1
}

ghidra_re_analyze_headless_path() {
  local dir="${1:-$GHIDRA_INSTALL_DIR}"
  local candidate=""
  for candidate in "$dir/support/analyzeHeadless" "$dir/support/analyzeHeadless.bat"; do
    [[ -f "$candidate" ]] && {
      printf '%s\n' "$candidate"
      return 0
    }
  done
  return 1
}

ghidra_re_gradle_wrapper_path() {
  local dir="${1:-$GHIDRA_INSTALL_DIR}"
  local candidate=""
  for candidate in "$dir/support/gradle/gradlew" "$dir/support/gradle/gradlew.bat"; do
    [[ -f "$candidate" ]] && {
      printf '%s\n' "$candidate"
      return 0
    }
  done
  return 1
}

ghidra_re_valid_ghidra_dir() {
  local dir="${1:-}"
  [[ -n "$dir" ]] || return 1
  [[ -n "$(ghidra_re_analyze_headless_path "$dir" || true)" && -n "$(ghidra_re_ghidra_run_path "$dir" || true)" ]]
}

ghidra_re_valid_jdk_dir() {
  local dir="${1:-}"
  [[ -n "$dir" && ( -f "$dir/bin/java" || -f "$dir/bin/java.exe" ) ]]
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
  if ghidra_re_platform_is_windows; then
    candidates+=(
      "/c/Program Files/Ghidra"
      "/c/Tools/Ghidra"
      "$HOME/AppData/Local/Programs/Ghidra"
    )
    shopt -s nullglob
    candidates+=(
      /c/Program\ Files/ghidra_*
      /c/Program\ Files/Ghidra_*
      /c/Tools/ghidra_*
      /c/Tools/Ghidra_*
      "$HOME"/Downloads/ghidra_*
      "$HOME"/Downloads/Ghidra_*
    )
    shopt -u nullglob
  else
    candidates+=(
      /Applications/Ghidra
      "$HOME/Applications/Ghidra"
      /opt/ghidra
    )
    shopt -s nullglob
    candidates+=(
      /Applications/ghidra_*
      /Applications/Ghidra_*
      "$HOME"/Applications/ghidra_*
      "$HOME"/Applications/Ghidra_*
      "$HOME"/Downloads/ghidra_*
      "$HOME"/Downloads/Ghidra_*
      /opt/ghidra_*
    )
    shopt -u nullglob
  fi
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
  if ghidra_re_valid_jdk_dir "${JAVA_HOME:-}"; then
    printf '%s\n' "$JAVA_HOME"
    return 0
  fi
  local -a candidates=()
  if ghidra_re_platform_is_windows; then
    shopt -s nullglob
    candidates+=(
      /c/Program\ Files/Eclipse\ Adoptium/jdk-21*
      /c/Program\ Files/Java/jdk-21*
      "$HOME"/AppData/Local/Programs/Eclipse\ Adoptium/jdk-21*
    )
    shopt -u nullglob
  else
    candidates+=(
      /opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home
      /usr/local/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home
      /usr/lib/jvm/java-21-openjdk
      /usr/lib/jvm/jdk-21
    )
  fi
  for candidate in "${candidates[@]}"; do
    if ghidra_re_valid_jdk_dir "$candidate"; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  if ghidra_re_platform_is_macos && [[ -x /usr/libexec/java_home ]]; then
    candidate="$(/usr/libexec/java_home -v 21 2>/dev/null || true)"
    if ghidra_re_valid_jdk_dir "$candidate"; then
      printf '%s\n' "$candidate"
      return 0
    fi
  fi
  return 1
}

ghidra_re_ensure_workspace() {
  mkdir -p "$GHIDRA_PROJECTS_DIR" "$GHIDRA_EXPORTS_DIR" "$GHIDRA_LOGS_DIR" "$GHIDRA_INVESTIGATIONS_DIR" "$GHIDRA_SOURCES_CACHE_DIR"
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

ghidra_re_investigation_dir() {
  printf '%s/%s' "$GHIDRA_INVESTIGATIONS_DIR" "$(ghidra_re_sanitize_name "$1")"
}

ghidra_re_mission_backend() {
  printf '%s/scripts/ghidra_mission_backend.py' "$GHIDRA_RE_ROOT"
}

ghidra_re_target_key() {
  printf '%s:%s' "$1" "$2"
}

ghidra_re_source_registry_init() {
  local python_cmd=""
  python_cmd="$(ghidra_re_python)" || ghidra_re_die "python is required for source registry support"
  mkdir -p "$(dirname "$GHIDRA_RE_SOURCE_REGISTRY_FILE")"
  if [[ ! -f "$GHIDRA_RE_SOURCE_REGISTRY_FILE" ]]; then
    "$python_cmd" - "$GHIDRA_RE_SOURCE_REGISTRY_FILE" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
path.write_text(json.dumps({"version": 1, "sources": []}, indent=2), encoding="utf-8")
PY
  fi
}

ghidra_re_source_lookup() {
  local source_name="$1"
  local python_cmd=""
  python_cmd="$(ghidra_re_python)" || ghidra_re_die "python is required for source registry support"
  ghidra_re_source_registry_init
  "$python_cmd" - "$GHIDRA_RE_SOURCE_REGISTRY_FILE" "$source_name" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
name = sys.argv[2]
payload = json.loads(path.read_text(encoding="utf-8"))
for item in payload.get("sources", []):
    if item.get("name") == name:
        print(json.dumps(item))
        raise SystemExit(0)
raise SystemExit(1)
PY
}

ghidra_re_source_resolve_path() {
  local source_name="$1"
  local source_relative_path="$2"
  local copy_mode="${3:-cache}"
  local python_cmd=""
  local source_json=""
  python_cmd="$(ghidra_re_python)" || ghidra_re_die "python is required for source registry support"
  source_json="$(ghidra_re_source_lookup "$source_name")" || ghidra_re_die "source not found: $source_name"
  "$python_cmd" - "$source_json" "$source_relative_path" "$copy_mode" "$GHIDRA_SOURCES_CACHE_DIR" <<'PY'
import json, pathlib, shutil, sys
source = json.loads(sys.argv[1])
relative = sys.argv[2]
copy_mode = sys.argv[3]
cache_root = pathlib.Path(sys.argv[4])
root = pathlib.Path(source.get("root", ""))
if not root.exists():
    raise SystemExit(f"source root not found: {root}")
relative_path = pathlib.PurePosixPath(relative)
parts = [part for part in relative_path.parts if part not in ("", "/")]
resolved = root.joinpath(*parts)
if not resolved.exists():
    raise SystemExit(f"target not found in source {source.get('name')}: {resolved}")
if copy_mode == "direct":
    print(str(resolved))
    raise SystemExit(0)
cache_path = cache_root / source.get("name", "source") / pathlib.Path(*parts)
cache_path.parent.mkdir(parents=True, exist_ok=True)
if resolved.is_file():
    shutil.copy2(resolved, cache_path)
else:
    if cache_path.exists():
      shutil.rmtree(cache_path)
    shutil.copytree(resolved, cache_path)
print(str(cache_path))
PY
}

ghidra_re_resolve_binary_spec() {
  local spec="$1"
  local copy_mode="${2:-cache}"
  if [[ -f "$spec" ]]; then
    printf '%s\n' "$spec"
    return 0
  fi
  if [[ "$spec" == source:*:* ]]; then
    local source_name="${spec#source:}"
    source_name="${source_name%%:*}"
    local source_path="${spec#source:${source_name}:}"
    ghidra_re_source_resolve_path "$source_name" "$source_path" "$copy_mode"
    return 0
  fi
  return 1
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
    if ghidra_re_platform_is_windows && command -v cygpath >/dev/null 2>&1; then
      case "$path" in
        /*|.*|~*)
          path="$(cygpath -aw "$path" 2>/dev/null || printf '%s' "$path")"
          ;;
      esac
    fi
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
  local -a roots=()
  local detected=""
  if ghidra_re_platform_is_macos; then
    roots+=("$HOME/Library/Ghidra")
  elif ghidra_re_platform_is_windows; then
    if [[ -n "${APPDATA:-}" ]]; then
      roots+=("$APPDATA/Ghidra" "$APPDATA/ghidra")
    fi
    roots+=("$HOME/AppData/Roaming/Ghidra" "$HOME/AppData/Roaming/ghidra" "$HOME/.ghidra")
  else
    roots+=("$HOME/.ghidra" "$HOME/.config/ghidra")
  fi
  local root=""
  for root in "${roots[@]}"; do
    [[ -d "$root" ]] || continue
    detected="$(find "$root" -maxdepth 1 -type d \( -name 'ghidra_*_PUBLIC' -o -name '.ghidra_*_PUBLIC' \) | sort | tail -n 1)"
    if [[ -n "$detected" ]]; then
      printf '%s' "$detected"
      return 0
    fi
  done
  local version=""
  version="$(ghidra_re_detect_ghidra_version || true)"
  if [[ -n "$version" ]]; then
    if ghidra_re_platform_is_macos; then
      printf '%s/Library/Ghidra/ghidra_%s_PUBLIC' "$HOME" "$version"
    elif ghidra_re_platform_is_windows; then
      if [[ -n "${APPDATA:-}" ]]; then
        printf '%s/Ghidra/ghidra_%s_PUBLIC' "$APPDATA" "$version"
      else
        printf '%s/AppData/Roaming/Ghidra/ghidra_%s_PUBLIC' "$HOME" "$version"
      fi
    else
      printf '%s/.ghidra/.ghidra_%s_PUBLIC' "$HOME" "$version"
    fi
    return 0
  fi
  return 1
}

ghidra_re_bridge_extensions_dir() {
  printf '%s/Extensions/Ghidra' "$(ghidra_re_bridge_settings_dir)"
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

ghidra_re_bridge_ensure_dirs() {
  mkdir -p "$GHIDRA_RE_BRIDGE_CONFIG_DIR" "$GHIDRA_RE_BRIDGE_SESSIONS_DIR" "$GHIDRA_RE_BRIDGE_REQUESTS_DIR"
}

ghidra_re_bridge_session_files() {
  ghidra_re_bridge_ensure_dirs
  find "$GHIDRA_RE_BRIDGE_SESSIONS_DIR" -maxdepth 1 -type f -name '*.json' | sort
}

ghidra_re_bridge_read_value_from_file() {
  local path="$1"
  local key="$2"
  local python_cmd=""
  [[ -f "$path" ]] || return 1
  python_cmd="$(ghidra_re_python)" || return 1
  "$python_cmd" - "$path" "$key" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
key = sys.argv[2]
payload = json.loads(path.read_text(encoding="utf-8"))
value = payload.get(key, "")
if isinstance(value, bool):
    print("true" if value else "false")
elif value is None:
    print("")
else:
    print(value)
PY
}

ghidra_re_bridge_session_pid_alive_file() {
  local session_file="$1"
  local pid=""
  [[ -f "$session_file" ]] || return 1
  pid="$(ghidra_re_bridge_read_value_from_file "$session_file" pid)"
  [[ -n "$pid" ]] || return 1
  kill -0 "$pid" >/dev/null 2>&1
}

ghidra_re_bridge_session_healthy_file() {
  local session_file="$1"
  local url=""
  local token=""
  local response=""
  local ok=""
  [[ -f "$session_file" ]] || return 1
  if ! ghidra_re_bridge_session_pid_alive_file "$session_file"; then
    return 1
  fi
  url="$(ghidra_re_bridge_read_value_from_file "$session_file" bridge_url)"
  token="$(ghidra_re_bridge_read_value_from_file "$session_file" token)"
  [[ -n "$url" && -n "$token" ]] || return 1
  response="$(curl -fsS --max-time 2 \
    -X POST \
    -H "Authorization: Bearer $token" \
    -H 'Content-Type: application/json' \
    --data '{}' \
    "$url/health" 2>/dev/null || true)"
  [[ -n "$response" ]] || return 1
  ok="$(printf '%s' "$response" | "$(ghidra_re_python)" -c 'import json, sys
try:
    payload = json.loads(sys.stdin.read())
except Exception:
    payload = {}
print("true" if payload.get("ok") else "false")'
)"
  [[ "$ok" == "true" ]]
}

ghidra_re_bridge_remove_current_if_matches() {
  local session_file="$1"
  local current_file=""
  current_file="$(ghidra_re_bridge_read_value_from_file "$GHIDRA_RE_BRIDGE_CURRENT_FILE" session_file || true)"
  if [[ -n "$current_file" && "$current_file" == "$session_file" ]]; then
    rm -f "$GHIDRA_RE_BRIDGE_CURRENT_FILE"
  fi
}

ghidra_re_bridge_prune_stale_sessions() {
  local session_file=""
  ghidra_re_bridge_ensure_dirs
  while IFS= read -r session_file; do
    [[ -z "$session_file" ]] && continue
    if ! ghidra_re_bridge_session_healthy_file "$session_file"; then
      ghidra_re_bridge_remove_current_if_matches "$session_file"
      rm -f "$session_file"
    fi
  done < <(ghidra_re_bridge_session_files)
  if [[ -f "$GHIDRA_RE_BRIDGE_CURRENT_FILE" ]]; then
    local current_session_file=""
    current_session_file="$(ghidra_re_bridge_read_value_from_file "$GHIDRA_RE_BRIDGE_CURRENT_FILE" session_file || true)"
    if [[ -z "$current_session_file" || ! -f "$current_session_file" ]]; then
      rm -f "$GHIDRA_RE_BRIDGE_CURRENT_FILE"
    fi
  fi
}

ghidra_re_bridge_latest_session_file() {
  ghidra_re_bridge_prune_stale_sessions
  find "$GHIDRA_RE_BRIDGE_SESSIONS_DIR" -maxdepth 1 -type f -name '*.json' -print0 2>/dev/null | \
    xargs -0 ls -1t 2>/dev/null | head -n 1
}

ghidra_re_bridge_write_current_from_session_file() {
  local session_file="$1"
  local tmp_file=""
  local session_id=""
  [[ -f "$session_file" ]] || ghidra_re_die "session file not found: $session_file"
  ghidra_re_bridge_ensure_dirs
  session_id="$(ghidra_re_bridge_read_value_from_file "$session_file" session_id)"
  [[ -n "$session_id" ]] || ghidra_re_die "session file is missing session_id: $session_file"
  tmp_file="$(mktemp "$GHIDRA_RE_BRIDGE_CONFIG_DIR/bridge-current.XXXXXX.tmp")"
  "$(ghidra_re_python)" - "$session_id" "$session_file" >"$tmp_file" <<'PY'
import json, sys
from datetime import datetime, timezone
payload = {
    "version": 1,
    "session_id": sys.argv[1],
    "session_file": sys.argv[2],
    "selected_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
}
print(json.dumps(payload, indent=2))
PY
  mv "$tmp_file" "$GHIDRA_RE_BRIDGE_CURRENT_FILE"
}

ghidra_re_bridge_current_session_file() {
  ghidra_re_bridge_prune_stale_sessions
  if [[ -f "$GHIDRA_RE_BRIDGE_CURRENT_FILE" ]]; then
    local current_session_file=""
    current_session_file="$(ghidra_re_bridge_read_value_from_file "$GHIDRA_RE_BRIDGE_CURRENT_FILE" session_file || true)"
    if [[ -n "$current_session_file" && -f "$current_session_file" ]]; then
      printf '%s\n' "$current_session_file"
      return 0
    fi
  fi
  local latest=""
  latest="$(ghidra_re_bridge_latest_session_file || true)"
  if [[ -n "$latest" && -f "$latest" ]]; then
    ghidra_re_bridge_write_current_from_session_file "$latest"
    printf '%s\n' "$latest"
    return 0
  fi
  return 1
}

ghidra_re_bridge_require_session() {
  local session_file=""
  session_file="$(ghidra_re_bridge_current_session_file || true)"
  [[ -n "$session_file" && -f "$session_file" ]] || ghidra_re_die "bridge session not found; arm or select a bridge session first"
}

ghidra_re_bridge_read_session_value() {
  local key="$1"
  local session_file=""
  ghidra_re_bridge_require_session
  session_file="$(ghidra_re_bridge_current_session_file)"
  ghidra_re_bridge_read_value_from_file "$session_file" "$key"
}

ghidra_re_bridge_current_session_id() {
  ghidra_re_bridge_read_session_value session_id
}

ghidra_re_bridge_session_matches_file() {
  local session_file="$1"
  local requested_session="${2:-}"
  local requested_project="${3:-}"
  local requested_program="${4:-}"
  local session_id=""
  local project_name=""
  local project_path=""
  local program_name=""
  local program_path=""
  [[ -f "$session_file" ]] || return 1
  if [[ -n "$requested_session" ]]; then
    session_id="$(ghidra_re_bridge_read_value_from_file "$session_file" session_id)"
    [[ -n "$session_id" ]] || return 1
    [[ "$session_id" == "$requested_session" || "$session_id" == "$requested_session"* ]] || return 1
  fi
  if [[ -n "$requested_project" ]]; then
    project_name="$(ghidra_re_bridge_read_value_from_file "$session_file" project_name)"
    project_path="$(ghidra_re_bridge_read_value_from_file "$session_file" project_path)"
    [[ "$project_name" == "$requested_project" || "$project_path" == "$(ghidra_re_project_file "$requested_project")" || "$project_path" == */"$requested_project.gpr" ]] || return 1
  fi
  if [[ -n "$requested_program" ]]; then
    program_name="$(ghidra_re_bridge_read_value_from_file "$session_file" program_name)"
    program_path="$(ghidra_re_bridge_read_value_from_file "$session_file" program_path)"
    [[ "$program_name" == "$requested_program" || "$program_path" == "$requested_program" || "$program_path" == */"$requested_program" ]] || return 1
  fi
  return 0
}

ghidra_re_bridge_find_matching_sessions() {
  local requested_session="${1:-}"
  local requested_project="${2:-}"
  local requested_program="${3:-}"
  local session_file=""
  ghidra_re_bridge_prune_stale_sessions
  while IFS= read -r session_file; do
    [[ -z "$session_file" ]] && continue
    if ghidra_re_bridge_session_matches_file "$session_file" "$requested_session" "$requested_project" "$requested_program"; then
      printf '%s\n' "$session_file"
    fi
  done < <(ghidra_re_bridge_session_files)
}

ghidra_re_bridge_resolve_session_file() {
  local requested_session="${1:-}"
  local requested_project="${2:-}"
  local requested_program="${3:-}"
  local current_file=""
  local matches=()
  local match=""
  if [[ -z "$requested_session" && -z "$requested_project" && -z "$requested_program" ]]; then
    ghidra_re_bridge_current_session_file
    return 0
  fi
  while IFS= read -r match; do
    [[ -z "$match" ]] && continue
    matches+=("$match")
  done < <(ghidra_re_bridge_find_matching_sessions "$requested_session" "$requested_project" "$requested_program")
  if [[ ${#matches[@]} -eq 0 ]]; then
    return 1
  fi
  if [[ ${#matches[@]} -eq 1 ]]; then
    printf '%s\n' "${matches[0]}"
    return 0
  fi
  current_file="$(ghidra_re_bridge_current_session_file || true)"
  if [[ -n "$current_file" ]]; then
    for match in "${matches[@]}"; do
      if [[ "$match" == "$current_file" ]]; then
        printf '%s\n' "$match"
        return 0
      fi
    done
  fi
  ghidra_re_die "multiple matching bridge sessions found; use session=<id> to disambiguate"
}

ghidra_re_bridge_require_healthy_session() {
  local session_file=""
  session_file="$(ghidra_re_bridge_current_session_file || true)"
  [[ -n "$session_file" ]] || ghidra_re_die "bridge session not found; arm or select a bridge session first"
  ghidra_re_bridge_session_healthy_file "$session_file" || \
    ghidra_re_die "bridge session at $session_file is stale or unreachable; arm the bridge again"
}

ghidra_re_bridge_session_matches_program() {
  local requested_program="${1:-}"
  local session_file=""
  session_file="$(ghidra_re_bridge_current_session_file || true)"
  [[ -n "$session_file" ]] || return 1
  ghidra_re_bridge_session_matches_file "$session_file" "" "" "$requested_program"
}

ghidra_re_bridge_session_matches_project() {
  local requested_project="${1:-}"
  local session_file=""
  session_file="$(ghidra_re_bridge_current_session_file || true)"
  [[ -n "$session_file" ]] || return 1
  ghidra_re_bridge_session_matches_file "$session_file" "" "$requested_project" ""
}

ghidra_re_bridge_wait_for_session() {
  local timeout_seconds="${1:-30}"
  local expected_project="${2:-}"
  local expected_program="${3:-}"
  local started=""
  local session_file=""
  started="$(date +%s)"
  while true; do
    session_file="$(ghidra_re_bridge_resolve_session_file "" "$expected_project" "$expected_program" 2>/dev/null || true)"
    if [[ -n "$session_file" ]] && ghidra_re_bridge_session_healthy_file "$session_file"; then
      printf '%s\n' "$session_file"
      return 0
    fi
    if (( "$(date +%s)" - started >= timeout_seconds )); then
      return 1
    fi
    sleep 1
  done
}

ghidra_re_bridge_wait_for_disarm() {
  local timeout_seconds="${1:-15}"
  local requested_session="${2:-}"
  local requested_project="${3:-}"
  local requested_program="${4:-}"
  local started=""
  started="$(date +%s)"
  while true; do
    ghidra_re_bridge_prune_stale_sessions
    if ! ghidra_re_bridge_find_matching_sessions "$requested_session" "$requested_project" "$requested_program" | grep -q .; then
      return 0
    fi
    if (( "$(date +%s)" - started >= timeout_seconds )); then
      return 1
    fi
    sleep 1
  done
}

ghidra_re_ghidra_running() {
  pgrep -f 'java.*ghidra\.GhidraRun' >/dev/null 2>&1
}

ghidra_re_bridge_clear_state_files() {
  rm -f "$GHIDRA_RE_BRIDGE_CURRENT_FILE" "$GHIDRA_RE_BRIDGE_LEGACY_CONTROL_FILE" "$GHIDRA_RE_BRIDGE_LEGACY_SESSION_FILE"
  if [[ -d "$GHIDRA_RE_BRIDGE_REQUESTS_DIR" ]]; then
    find "$GHIDRA_RE_BRIDGE_REQUESTS_DIR" -maxdepth 1 -type f -name '*.json' -delete
  fi
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
  local ghidra_run=""
  project_name="$(basename "$project_file" .gpr)"
  ghidra_run="$(ghidra_re_ghidra_run_path)"
  if ghidra_re_platform_is_windows; then
    if command -v cygpath >/dev/null 2>&1 && command -v cmd.exe >/dev/null 2>&1; then
      cmd.exe //c start "" "$(cygpath -aw "$ghidra_run")" "$(cygpath -aw "$project_file")" >/dev/null 2>&1
      return 0
    fi
    nohup "$ghidra_run" "$project_file" </dev/null >/dev/null 2>&1 &
    return 0
  fi
  if ghidra_re_platform_is_macos && command -v screen >/dev/null 2>&1; then
    local screen_name=""
    local log_dir=""
    local log_file=""
    local launch_cmd=""
    local quoted_java_home=""
    local quoted_project_file=""
    local quoted_log_file=""
    screen_name="codex-ghidra-$(ghidra_re_sanitize_name "$project_name")-$(date +%s)-$RANDOM"
    log_dir="$(ghidra_re_log_dir "$project_name")/bridge-launch"
    mkdir -p "$log_dir"
    log_file="$log_dir/launch-$(ghidra_re_timestamp)-${launch_mode}.log"
    printf -v quoted_java_home '%q' "$GHIDRA_JDK"
    local quoted_ghidra_run=""
    printf -v quoted_ghidra_run '%q' "$ghidra_run"
    printf -v quoted_project_file '%q' "$project_file"
    printf -v quoted_log_file '%q' "$log_file"
    launch_cmd="export JAVA_HOME=$quoted_java_home; export PATH=\"\$JAVA_HOME/bin:\$PATH\"; $quoted_ghidra_run $quoted_project_file >>$quoted_log_file 2>&1; while ps ax -o command= | grep -F 'ghidra.GhidraRun' | grep -F $quoted_project_file >/dev/null 2>&1; do sleep 5; done"
    screen -dmS "$screen_name" /bin/sh -lc "$launch_cmd"
    return 0
  fi
  if ghidra_re_platform_is_macos && command -v launchctl >/dev/null 2>&1; then
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
      "$ghidra_run" \
      "$project_file"
    return 0
  fi
  nohup "$ghidra_run" "$project_file" </dev/null >/dev/null 2>&1 &
}

ghidra_re_bridge_write_request_file() {
  local command="$1"
  local requested_session="${2:-}"
  local project_name="${3:-}"
  local program_name="${4:-}"
  local request_id=""
  local tmp_file=""
  local request_file=""
  ghidra_re_bridge_ensure_dirs
  request_id="$(uuidgen 2>/dev/null | tr '[:upper:]' '[:lower:]' || true)"
  if [[ -z "$request_id" ]]; then
    request_id="request-$(date +%s)-$RANDOM"
  fi
  tmp_file="$(mktemp "$GHIDRA_RE_BRIDGE_REQUESTS_DIR/request.XXXXXX.tmp")"
  request_file="$GHIDRA_RE_BRIDGE_REQUESTS_DIR/${request_id}.json"
  "$(ghidra_re_python)" - "$request_id" "$command" "$requested_session" "$project_name" "$program_name" >"$tmp_file" <<'PY'
import json, sys
from datetime import datetime, timezone
payload = {
    "version": 1,
    "request_id": sys.argv[1],
    "command": sys.argv[2],
    "session_id": sys.argv[3],
    "project_name": sys.argv[4],
    "program_name": sys.argv[5],
    "requested_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
}
print(json.dumps(payload, indent=2))
PY
  mv "$tmp_file" "$request_file"
  printf '%s\n' "$request_file"
}

ghidra_re_bridge_select_session() {
  local requested_session="${1:-}"
  local requested_project="${2:-}"
  local requested_program="${3:-}"
  local session_file=""
  session_file="$(ghidra_re_bridge_resolve_session_file "$requested_session" "$requested_project" "$requested_program")" || return 1
  ghidra_re_bridge_write_current_from_session_file "$session_file"
  printf '%s\n' "$session_file"
}

ghidra_re_bridge_extract_selectors_from_json() {
  local body="${1:-{}}"
  printf '%s' "$body" | "$(ghidra_re_python)" -c 'import json, sys
try:
    payload = json.loads(sys.stdin.read())
except Exception:
    payload = {}
selectors = [
    payload.get("session") or payload.get("session_id") or "",
    payload.get("project") or payload.get("project_name") or "",
    payload.get("program") or payload.get("program_name") or "",
]
print("\t".join(selectors))'
}

ghidra_re_bridge_json_from_kv() {
  "$(ghidra_re_python)" - "$@" <<'PY'
import json, sys
payload = {}
for arg in sys.argv[1:]:
    if "=" in arg:
        key, value = arg.split("=", 1)
    else:
        key, value = arg, None
    if not key:
        continue
    if value is None:
        payload[key] = True
    elif value.startswith("json:"):
        payload[key] = json.loads(value[5:])
    elif value == "true":
        payload[key] = True
    elif value == "false":
        payload[key] = False
    elif value.lstrip("-").isdigit():
        payload[key] = int(value)
    else:
        payload[key] = value
print(json.dumps(payload))
PY
}
