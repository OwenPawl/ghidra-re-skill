# Output Files

The default Apple bundle writes to:

`~/ghidra-projects/exports/<project_name>/<program_name>/`

Expected files:

- `program_summary.json`
  - program-level metadata, image base, memory blocks, symbol counts, total function count, and `function_inventory_count` for comparison with the inventory file
- `objc_metadata.json`
  - Objective-C classes, interface-quality class buckets, recovered protocols, categories, selectors, parsed method names, class refs, selector refs, protocol refs, and selector/classname string artifacts
- `function_inventory.json`
  - in-program functions with addresses, signatures, parameter details, and xref counts
- `symbols.json`
  - symbols plus import/export categorization
- `strings.json`
  - defined strings with block names and sampled xrefs

Structure export scripts create additional files under the same program export directory:

- `macho_structure.json`
  - Mach-O binary metadata: `arch`, `filetype`, `flags`, `uuid`, `build_version` (platform/minos/sdk),
    `source_version`, `encryption` (offset/size/id), `segments` (name/vm_addr/vm_size/file_off/file_size/
    max_prot/init_prot + nested `sections` array), `dylibs` (ordinal/name/compatibility_version/
    current_version/kind), `rpaths`, `sub_framework`, `code_signature_offset`, `code_signature_size`,
    `memory_blocks`, `dylibs_from_ext_manager`, and optionally `entitlements_plist`.
    Produced by `ghidra-re export macho-structure <project> <program>`.

Targeted scripts create additional files such as:

- `decompile_<function>.c`
- `xrefs_<target>.json`
- `bug-hunt/entrypoints.json`
- `bug-hunt/sinks.json`
- `bug-hunt/candidate_paths.json`
- `dossiers/<slug>/context.json`
- `findings/<slug>/finding_result.json`

Logs live under:

`~/ghidra-projects/logs/<project_name>/`

Bridge-specific files:

- `~/.config/ghidra-re/bridge-sessions/<session_id>.json`
  - one live session record per armed CodeBrowser, including project/program identity, bridge URL, token, heartbeat, and repository write state
- `~/.config/ghidra-re/bridge-current.json`
  - compatibility pointer for whichever session is currently selected by default
- `~/.config/ghidra-re/bridge-requests/<request_id>.json`
  - arm/disarm requests consumed by the GUI helper and the live bridge service
- `~/ghidra-projects/logs/<project_name>/bridge-ops/<timestamp>-<op>.json`
  - destructive bridge operation logs including request body, before-state, after-state summary, target refs, and inverse hints for single-op rollback
- `~/.config/ghidra-re/sources.json`
  - registered external source roots such as mounted or extracted macOS images for Windows or Linux hosts
- `~/ghidra-projects/sources/<source_name>/...`
  - cached copies of files resolved from a registered source when `copy=cache` is used

Mission-specific files:

- `~/ghidra-projects/investigations/<mission_name>/mission.json`
  - mission goal, configured targets, configured seeds, mode, and timestamps
- `~/ghidra-projects/investigations/<mission_name>/graph.sqlite`
  - persistent investigation graph with targets, sessions, nodes, edges, artifacts, notes, and runs
- `~/ghidra-projects/investigations/<mission_name>/reports/latest.json`
  - machine-readable mission summary including current hypothesis, targets visited, evidence used, cross-target links, and recommended next hops
- `~/ghidra-projects/investigations/<mission_name>/reports/latest.md`
  - human-readable mission report
- `~/ghidra-projects/investigations/<mission_name>/exports/`
  - raw machine-readable selector traces, analysis payloads, and target manifests captured during the mission

Bridge snapshot payloads also now carry export-backed context such as nearby strings, selector-like strings, nearby ObjC class names, and imported symbols when an export bundle already exists for the active target.

ObjC helper outputs are intentionally composable:

- `ghidra_objc_surface_report`
  - grouped class, protocol, selector, and subsystem summaries for ObjC-heavy targets
- `ghidra_describe_objc_class`
  - merged class report using both `objc_metadata.json` and `symbols.json`
- `ghidra_describe_selector`
  - selector implementations, string hits, and optional live selector trace data
- `ghidra_describe_objc_protocol`
  - explicit/recovered protocol evidence and Swift-side protocol hits when available
- `ghidra_trace_classref`
  - classref- and symbol-oriented view of a class name
- `ghidra_objc_message_flow`
  - receiver-class summaries, implementation grouping, and live sender hints for a selector

Use the log and script log when a script fails or a built-in behaves differently in headless mode.
