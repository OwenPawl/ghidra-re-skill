#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/common.sh"

BSR_PROJECT="${GHIDRA_RE_TEST_BSR_PROJECT:-bsr_smoke}"
BSR_PROGRAM="${GHIDRA_RE_TEST_BSR_PROGRAM:-BackgroundShortcutRunner}"
WORKFLOW_PROJECT="${GHIDRA_RE_TEST_WORKFLOW_PROJECT:-workflowkit_bug_smoke}"
WORKFLOW_PROGRAM="${GHIDRA_RE_TEST_WORKFLOW_PROGRAM:-WorkflowKit}"
OBJC_PROJECT="${GHIDRA_RE_TEST_OBJC_PROJECT:-workflowkit_full_dyld_extract}"
OBJC_PROGRAM="${GHIDRA_RE_TEST_OBJC_PROGRAM:-WorkflowKit}"
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

echo "== enriched bridge snapshot =="
snapshot_json="$("$SCRIPT_DIR/ghidra_bridge_snapshot")"
assert_python '
payload = json.loads(sys.argv[1])
assert "enriched_context" in payload, "missing enriched_context"
enriched = payload["enriched_context"]
assert "nearby_strings" in enriched, "missing nearby_strings"
assert "nearby_selectors" in enriched, "missing nearby_selectors"
assert "imported_symbols" in enriched, "missing imported_symbols"
' "$snapshot_json"

echo "== ObjC method dossier resolution =="
"$SCRIPT_DIR/ghidra_function_dossier" "$WORKFLOW_PROJECT" "$WORKFLOW_PROGRAM" "$WORKFLOW_METHOD" >/dev/null

echo "== ObjC surface helpers =="
objc_surface_json="$(GHIDRA_RE_DISABLE_LIVE_BRIDGE=1 "$SCRIPT_DIR/ghidra_objc_surface_report" "$OBJC_PROJECT" "$OBJC_PROGRAM")"
assert_python '
payload = json.loads(sys.argv[1])
assert payload.get("class_count", 0) > 0, "expected ObjC classes"
assert payload.get("protocol_count", 0) > 0, "expected ObjC protocols"
assert payload.get("top_classes"), "expected top ObjC classes"
' "$objc_surface_json"

objc_class_json="$(GHIDRA_RE_DISABLE_LIVE_BRIDGE=1 "$SCRIPT_DIR/ghidra_describe_objc_class" "$OBJC_PROJECT" "$OBJC_PROGRAM" "WFRemoteExecutionCoordinator")"
assert_python '
payload = json.loads(sys.argv[1])
assert payload.get("declared"), "expected WFRemoteExecutionCoordinator declared"
assert payload.get("method_count", 0) > 0, "expected merged ObjC methods"
assert payload.get("selectors"), "expected class selectors"
' "$objc_class_json"

objc_protocol_json="$(GHIDRA_RE_DISABLE_LIVE_BRIDGE=1 "$SCRIPT_DIR/ghidra_describe_objc_protocol" "$OBJC_PROJECT" "$OBJC_PROGRAM" "IndexedEntity")"
assert_python '
payload = json.loads(sys.argv[1])
assert payload.get("explicit_declared") or payload.get("recovered_declared"), "expected protocol declaration"
assert payload.get("recovered_hits") or payload.get("symbol_hits") or payload.get("swift_hits"), "expected protocol evidence"
' "$objc_protocol_json"

selector_report_json="$(GHIDRA_RE_DISABLE_LIVE_BRIDGE=1 "$SCRIPT_DIR/ghidra_describe_selector" "$OBJC_PROJECT" "$OBJC_PROGRAM" "handleRunRequest:service:account:fromID:context:")"
assert_python '
payload = json.loads(sys.argv[1])
assert payload.get("implementation_count", 0) > 0, "expected selector implementations"
assert "WFRemoteExecutionCoordinator" in payload.get("candidate_classes", []), "expected coordinator implementation"
' "$selector_report_json"

classref_report_json="$(GHIDRA_RE_DISABLE_LIVE_BRIDGE=1 "$SCRIPT_DIR/ghidra_trace_classref" "$OBJC_PROJECT" "$OBJC_PROGRAM" "WFRemoteExecutionCoordinator")"
assert_python '
payload = json.loads(sys.argv[1])
assert payload.get("symbol_hits"), "expected class symbol hits"
' "$classref_report_json"

message_flow_json="$(GHIDRA_RE_DISABLE_LIVE_BRIDGE=1 "$SCRIPT_DIR/ghidra_objc_message_flow" "$OBJC_PROJECT" "$OBJC_PROGRAM" "handleRunRequest:service:account:fromID:context:" class=WFRemoteExecutionCoordinator)"
assert_python '
payload = json.loads(sys.argv[1])
assert payload.get("implementation_count", 0) > 0, "expected message-flow implementation"
assert "WFRemoteExecutionCoordinator" in payload.get("receiver_classes", []), "expected receiver class"
assert payload.get("receiver_class_summaries"), "expected receiver class summaries"
assert payload["receiver_class_summaries"][0].get("top_selectors"), "expected top selectors"
' "$message_flow_json"

echo "== export bundle smoke =="
"$SCRIPT_DIR/ghidra_export_apple_bundle" "$BSR_PROJECT" "$BSR_PROGRAM" >/dev/null
[[ -f "$(ghidra_re_export_dir "$BSR_PROJECT" "$BSR_PROGRAM")/swift_metadata.json" ]] || \
  ghidra_re_die "swift_metadata.json missing from export bundle"
python3 - "$(ghidra_re_export_dir "$BSR_PROJECT" "$BSR_PROGRAM")/objc_metadata.json" <<'PY'
import json, pathlib, sys
payload = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
assert "interface_classes" in payload, "missing interface_classes bucket"
assert payload.get("class_source_preference") == "interface_classes", "unexpected class source preference"
assert "recovered_protocols" in payload, "missing recovered_protocols"
PY

echo "Apple workflow bridge tests passed"
