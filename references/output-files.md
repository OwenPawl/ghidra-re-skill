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

- `~/.config/ghidra-re/bridge-session.json`
  - active localhost bridge URL, bearer token, current tool/program info, and repository write state
- `~/.config/ghidra-re/bridge-control.json`
  - best-effort arm/disarm request file consumed by the GUI plugin
- `~/ghidra-projects/logs/<project_name>/bridge-ops/<timestamp>-<op>.json`
  - destructive bridge operation logs including request body, before-state, after-state summary, target refs, and inverse hints for single-op rollback

Use the log and script log when a script fails or a built-in behaves differently in headless mode.
