#!/usr/bin/env bash
#
# Top-level convenience wrapper around scripts/install_skill.
#
# This exists so that a user who has just cloned the repo can do:
#
#   ./install.sh                 # auto-detect host(s)
#   ./install.sh --host codex    # force OpenAI Codex only
#   ./install.sh --host claude   # force Anthropic Claude Code only
#   ./install.sh --host both     # install under every known host
#
# without having to remember the script path. All flags are forwarded to
# scripts/install_skill unchanged.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
exec "$ROOT/scripts/install_skill" --source "$ROOT" "$@"
