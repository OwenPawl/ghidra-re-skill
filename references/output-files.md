# Output Files

The default Apple bundle writes to:

`~/ghidra-projects/exports/<project_name>/<program_name>/`

Expected files:

- `program_summary.json`
  - program-level metadata, image base, memory blocks, symbol counts, total function count, and `function_inventory_count` for comparison with the inventory file
- `objc_metadata.json`
  - Objective-C classes, protocols, categories, selectors, and parsed method names
- `function_inventory.json`
  - in-program functions with addresses, signatures, parameter details, and xref counts
- `symbols.json`
  - symbols plus import/export categorization
- `strings.json`
  - defined strings with block names and sampled xrefs

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

Use the log and script log when a script fails or a built-in behaves differently in headless mode.
