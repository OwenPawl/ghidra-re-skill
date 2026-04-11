#!/usr/bin/env bash
#
# skill_host.sh
#
# Unified "skill host" resolution layer for ghidra-re.
#
# ghidra-re is designed to be installable under multiple AI tool hosts
# that follow the same on-disk "skills" convention:
#
#   - OpenAI Codex              ~/.codex/skills/<skill>/SKILL.md
#   - Anthropic Claude Code     ~/.claude/skills/<skill>/SKILL.md
#
# Both hosts load a skill from a directory containing SKILL.md with YAML
# frontmatter (name, description). The rest of the skill layout —
# scripts/, references/, templates/, bridge-extension/ — is host-agnostic
# and is reused verbatim across hosts.
#
# This file is the single source of truth for:
#
#   - the list of known hosts
#   - how to locate a host's skill directory
#   - how to resolve install targets from a user-provided "--host" choice
#   - how to detect which hosts look "installed" on the current machine
#
# Source it with:
#
#   source "$(dirname "${BASH_SOURCE[0]}")/lib/skill_host.sh"
#
# or, from common.sh and friends:
#
#   source "$GHIDRA_RE_ROOT/scripts/lib/skill_host.sh"

# Skill name used under <host>/skills/<name>. Override via env for tests.
GHIDRA_RE_SKILL_NAME="${GHIDRA_RE_SKILL_NAME:-ghidra-re}"

# Space-separated list of known host identifiers.
GHIDRA_RE_KNOWN_HOSTS="${GHIDRA_RE_KNOWN_HOSTS:-codex claude}"

# Echo the base directory for a given host id.
#   codex  -> $CODEX_HOME  or ~/.codex
#   claude -> $CLAUDE_HOME or ~/.claude
ghidra_re_host_base() {
  local host="$1"
  case "$host" in
    codex)
      printf '%s\n' "${CODEX_HOME:-$HOME/.codex}"
      ;;
    claude)
      printf '%s\n' "${CLAUDE_HOME:-$HOME/.claude}"
      ;;
    *)
      return 1
      ;;
  esac
}

# Echo <base>/skills for a given host id.
ghidra_re_host_skills_dir() {
  local host="$1"
  local base
  base="$(ghidra_re_host_base "$host")" || return 1
  printf '%s\n' "$base/skills"
}

# Echo <base>/skills/<skill-name> for a given host id.
ghidra_re_host_skill_dir() {
  local host="$1"
  local base
  base="$(ghidra_re_host_base "$host")" || return 1
  printf '%s\n' "$base/skills/$GHIDRA_RE_SKILL_NAME"
}

# Echo every known host id (one per line).
ghidra_re_host_list_all() {
  local host
  for host in $GHIDRA_RE_KNOWN_HOSTS; do
    printf '%s\n' "$host"
  done
}

# Echo every known host whose base directory already exists on disk,
# which is our heuristic for "this user has that tool installed".
ghidra_re_host_detect_installed() {
  local host base
  for host in $GHIDRA_RE_KNOWN_HOSTS; do
    base="$(ghidra_re_host_base "$host")" || continue
    if [[ -d "$base" ]]; then
      printf '%s\n' "$host"
    fi
  done
}

# Resolve a user-supplied host choice into a list of host ids (one per line).
#
# Accepts:
#   "" | auto   -> detected hosts; falls back to "codex" when nothing detected
#   all | both  -> every known host
#   codex       -> codex
#   claude      -> claude
#   "codex,claude" | "codex claude" -> both
#
# Returns non-zero on an unknown host.
ghidra_re_host_resolve_choice() {
  local choice="${1:-auto}"
  local normalized
  normalized="$(printf '%s' "$choice" | tr '[:upper:],' '[:lower:] ')"

  case "$normalized" in
    ""|auto)
      local detected
      detected="$(ghidra_re_host_detect_installed)"
      if [[ -z "$detected" ]]; then
        printf 'codex\n'
      else
        printf '%s\n' "$detected"
      fi
      return 0
      ;;
    all|both|"*")
      ghidra_re_host_list_all
      return 0
      ;;
  esac

  local host seen_any=0
  for host in $normalized; do
    case "$host" in
      codex|claude)
        printf '%s\n' "$host"
        seen_any=1
        ;;
      *)
        printf 'skill_host: unknown host "%s"\n' "$host" >&2
        return 2
        ;;
    esac
  done

  if [[ "$seen_any" -eq 0 ]]; then
    printf 'skill_host: no hosts resolved from choice "%s"\n' "$choice" >&2
    return 2
  fi
}

# Resolve a user-supplied host choice into install directories (one per line).
ghidra_re_host_resolve_install_targets() {
  local choice="${1:-auto}"
  local hosts host
  hosts="$(ghidra_re_host_resolve_choice "$choice")" || return $?
  while IFS= read -r host; do
    [[ -z "$host" ]] && continue
    ghidra_re_host_skill_dir "$host"
  done <<<"$hosts"
}

# Given a currently-running SKILL.md path (or the skill root), guess which
# host it was loaded under. Echoes the host id or empty if it can't tell.
ghidra_re_host_identify_root() {
  local root="${1:-}"
  [[ -z "$root" ]] && return 1
  local host base skills_dir
  for host in $GHIDRA_RE_KNOWN_HOSTS; do
    base="$(ghidra_re_host_base "$host")" || continue
    skills_dir="$base/skills"
    case "$root" in
      "$skills_dir"/*)
        printf '%s\n' "$host"
        return 0
        ;;
    esac
  done
  # Detect Claude Code's plugin-system install path.
  # Pattern: .../Claude/local-agent-mode-sessions/skills-plugin/<uuid>/<uuid>/skills/<skill-name>
  # This path is used when the skill is loaded as a plugin rather than installed
  # into ~/.claude/skills/ via install_skill. We still call it "claude" because
  # it is the same host — just loaded from a different directory.
  case "$root" in
    */Claude/local-agent-mode-sessions/skills-plugin/*/skills/"$GHIDRA_RE_SKILL_NAME" | \
    */Claude/local-agent-mode-sessions/skills-plugin/*/skills/"$GHIDRA_RE_SKILL_NAME"/*)
      printf 'claude\n'
      return 0
      ;;
  esac
  return 1
}

# Echo the best available skill root for the given host on this machine.
# Prefers the standard install path; falls back to plugin-system discovery.
ghidra_re_host_find_root() {
  local host="${1:-}"
  [[ -z "$host" ]] && return 1

  # Check standard install location first.
  local std_dir
  std_dir="$(ghidra_re_host_skill_dir "$host")" || return 1
  if [[ -f "$std_dir/SKILL.md" ]]; then
    printf '%s\n' "$std_dir"
    return 0
  fi

  # For claude, also search the plugin-system directory.
  if [[ "$host" == "claude" ]]; then
    local app_support
    app_support="$(dirname "$(ghidra_re_host_base claude)")/Application Support/Claude"
    if [[ ! -d "$app_support" ]]; then
      # Try the macOS default if CLAUDE_HOME wasn't set
      app_support="$HOME/Library/Application Support/Claude"
    fi
    local found
    found="$(find "$app_support/local-agent-mode-sessions/skills-plugin" \
      -maxdepth 5 -name 'SKILL.md' \
      -path "*/$GHIDRA_RE_SKILL_NAME/SKILL.md" 2>/dev/null \
      | head -1)"
    if [[ -n "$found" ]]; then
      printf '%s\n' "$(dirname "$found")"
      return 0
    fi
  fi

  return 1
}
