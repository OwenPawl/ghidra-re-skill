#!/usr/bin/env bash

set -euo pipefail

REPO_NAME="${1:-ghidra-re-skill}"
VISIBILITY="${2:-public}"

case "$VISIBILITY" in
  public|private)
    ;;
  *)
    printf 'usage: %s [repo-name] [public|private]\n' "$0" >&2
    exit 1
    ;;
esac

if ! command -v gh >/dev/null 2>&1; then
  printf 'GitHub CLI is required. Install it with: brew install gh\n' >&2
  exit 1
fi

if ! gh auth status >/dev/null 2>&1; then
  printf 'GitHub CLI is not authenticated yet. Run: gh auth login\n' >&2
  exit 1
fi

if git remote get-url origin >/dev/null 2>&1; then
  printf 'origin already exists: %s\n' "$(git remote get-url origin)"
  exit 1
fi

branch="$(git branch --show-current || true)"
if [[ -z "$branch" ]]; then
  branch="main"
  git branch -M "$branch"
fi

gh repo create "$REPO_NAME" \
  "--$VISIBILITY" \
  --source=. \
  --remote=origin \
  --push

printf 'Created and pushed %s (%s)\n' "$REPO_NAME" "$VISIBILITY"
