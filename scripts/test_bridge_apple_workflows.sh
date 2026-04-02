#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/common.sh"

BSR_PROJECT="${GHIDRA_RE_TEST_BSR_PROJECT:-bsr_smoke}"
BSR_PROGRAM="${GHIDRA_RE_TEST_BSR_PROGRAM:-BackgroundShortcutRunner}"
WORKFLOW_PROJECT="${GHIDRA_RE_TEST_WORKFLOW_PROJECT:-workflowkit_bug_smoke}"
WORKFLOW_PROGRAM="${GHIDRA_RE_TEST_WORKFLOW_PROGRAM:-WorkflowKit}"
WORKFLOW_METHOD="${GHIDRA_RE_TEST_WORKFLOW_METHOD:--[WFRemoteExecutionCoordinator handleRunRequest:service:account:fromID:context:]}"

assert_python() {
  local script="$1"
  shift
  python3 - "$@" <<PY
import json, pathlib, sys
${script}
PY
}

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/ghidra-re-test.XXXXXX")"
cleanup() {
  "$SCRIPT_DIR/ghidra_bridge_close_all" all=true >/dev/null 2>&1 || true
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

echo "== install bridge =="
"$SCRIPT_DIR/ghidra_bridge_install" >/dev/null

echo "== clean live sessions =="
"$SCRIPT_DIR/ghidra_bridge_close_all" all=true >/dev/null 2>&1 || true

echo "== open primary live session =="
"$SCRIPT_DIR/ghidra_bridge_open" "$BSR_PROJECT" "$BSR_PROGRAM" >/dev/null

sessions_json="$("$SCRIPT_DIR/ghidra_bridge_sessions")"
assert_python '
payload = json.loads(sys.argv[1])
assert payload and payload[0]["project_name"], "expected at least one live session"
caps = set(payload[0].get("capabilities", []))
for endpoint in ("/data/get", "/strings/search", "/symbols/get", "/symbols/xrefs", "/memory/range"):
    assert endpoint in caps, f"missing capability: {endpoint}"
' "$sessions_json"

echo "== raw selector string search + exact-address references =="
strings_json="$("$SCRIPT_DIR/ghidra_bridge_strings_search" "allowVariableInjection" "project=$BSR_PROJECT" "program=$BSR_PROGRAM" "limit=1")"
selector_address="$(python3 - "$strings_json" <<'PY'
import json, sys
payload = json.loads(sys.argv[1])
matches = payload.get("result", {}).get("matches", [])
assert matches, "expected selector string match"
print(matches[0]["address"])
PY
)"
references_json="$("$SCRIPT_DIR/ghidra_bridge_call" /references "$(ghidra_re_bridge_json_from_kv "project=$BSR_PROJECT" "program=$BSR_PROGRAM" "address=$selector_address")")"
assert_python '
payload = json.loads(sys.argv[1])
result = payload.get("result", {})
assert result.get("address") == sys.argv[2], "address mismatch"
assert "function_ref" not in result, "raw address references should not silently resolve to function"
assert result.get("references_to"), "expected references_to entries"
' "$references_json" "$selector_address"

echo "== live GUI + readonly headless coexistence =="
readonly_output="$tmp_dir/decompile.c"
GHIDRA_RUN_SCRIPT_MODE=readonly "$SCRIPT_DIR/ghidra_run_script" \
  "$BSR_PROJECT" "$BSR_PROGRAM" DecompileFunction.java \
  "address=100081906" "output=$readonly_output" >/dev/null
[[ -f "$readonly_output" ]] || ghidra_re_die "readonly follow-up script did not produce output"

echo "== second live session + deterministic current session =="
"$SCRIPT_DIR/ghidra_bridge_open" "$WORKFLOW_PROJECT" "$WORKFLOW_PROGRAM" >/dev/null
"$SCRIPT_DIR/ghidra_bridge_select" "project=$WORKFLOW_PROJECT" >/dev/null
current_before="$("$SCRIPT_DIR/ghidra_bridge_sessions")"
"$SCRIPT_DIR/ghidra_bridge_strings_search" "allowVariableInjection" "project=$BSR_PROJECT" "program=$BSR_PROGRAM" "limit=1" >/dev/null
current_after="$("$SCRIPT_DIR/ghidra_bridge_sessions")"
assert_python '
before = json.loads(sys.argv[1])
after = json.loads(sys.argv[2])
def current_project(items):
    for item in items:
        if item.get("current"):
            return item.get("project_name")
    return ""
assert current_project(before) == sys.argv[3], "expected workflow project selected before explicit cross-target read"
assert current_project(after) == sys.argv[3], "read-only explicit target call rewrote current session"
' "$current_before" "$current_after" "$WORKFLOW_PROJECT"

echo "== ObjC method dossier resolution =="
"$SCRIPT_DIR/ghidra_function_dossier" "$WORKFLOW_PROJECT" "$WORKFLOW_PROGRAM" "$WORKFLOW_METHOD" >/dev/null

echo "== export bundle smoke =="
"$SCRIPT_DIR/ghidra_export_apple_bundle" "$BSR_PROJECT" "$BSR_PROGRAM" >/dev/null
[[ -f "$(ghidra_re_export_dir "$BSR_PROJECT" "$BSR_PROGRAM")/swift_metadata.json" ]] || \
  ghidra_re_die "swift_metadata.json missing from export bundle"

echo "Apple workflow bridge tests passed"
