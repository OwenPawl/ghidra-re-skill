---
name: ghidra-re
description: Use for Ghidra-based reverse engineering on this machine, especially Apple Mach-O and dyld-extracted binaries. Trigger when the user wants headless Ghidra import/analysis, to run Ghidra scripts, inspect decompilation, or export structured reversing artifacts such as functions, strings, symbols, Objective-C metadata, or xrefs. Prefer this skill over ad hoc shell commands when the task should create or reuse a Ghidra project under ~/ghidra-projects.
---

# Ghidra RE

Use this skill for repeatable, headless-first Ghidra work on macOS or Windows. It assumes:

- Ghidra install:
  - macOS: `/Applications/Ghidra`
  - Windows: `/c/Program Files/Ghidra`
- JDK:
  - macOS: `/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home`
  - Windows: `/c/Program Files/Eclipse Adoptium/jdk-21`
- Workspace root: `~/ghidra-projects`
- Skill root: `~/.codex/skills/ghidra-re`

V1 is optimized for Apple Mach-O reversing and dyld-extracted binaries. It now includes a localhost GUI bridge extension for live inspection, annotation, and controlled program surgery inside open Ghidra sessions, plus mission workspaces for multi-target investigation across frameworks, daemons, and helpers.

The custom automation scripts ship as Java Ghidra scripts because that is the most reliable headless path on this machine.
On Windows, the public repo now also ships a native PowerShell wrapper layer in `powershell/` for people who want first-class PowerShell commands instead of starting in Git Bash.

## Quick Start

1. On a fresh machine, run `scripts/bootstrap` once.
2. If bootstrap cannot find Ghidra or Java 21, run `scripts/doctor`.
3. On Windows, if the targets live in a mounted or extracted macOS image, register that source first:
   - `scripts/ghidra_source_add mac-image root=/d/macos-root platform=macos-image copy=cache`
4. Start a multi-target mission when the task spans more than one framework, daemon, or helper:
   - `scripts/ghidra_mission_start <mission_name> goal=... target=... [target=...] [seed=...]`
5. Extend the mission with a seed-driven trace:
   - `scripts/ghidra_mission_trace <mission_name> seed=<kind:value>`
6. For a more autonomous pass, let the mission keep driving its own next hops:
   - `scripts/ghidra_mission_autopilot <mission_name> [rounds=3]`
7. Read the mission report:
   - `scripts/ghidra_mission_report <mission_name>`
   - `scripts/ghidra_mission_report <mission_name> format=casefile`
8. Finish the mission and close its live Ghidra sessions unless you explicitly keep them open:
   - `scripts/ghidra_mission_finish <mission_name>`
9. For a single target, import and analyze into a dedicated project:
   - `scripts/ghidra_import_analyze <binary|source:name:/path/in/image> [project_name]`
10. Export the default Apple-focused bundle:
   - `scripts/ghidra_export_apple_bundle <project_name> <program_name>`
11. For Swift-heavy Apple targets, generate a surface-level report before you start chasing individual mangled symbols:
   - `scripts/ghidra_swift_surface_report <project_name> <program_name> [query] [format=json|markdown]`
   - `scripts/ghidra_describe_swift_type <project_name> <program_name> <TypeName>`
12. Export the bug-hunt bundle only when the task is explicitly bug hunting or boundary triage:
   - `scripts/ghidra_export_bug_hunt_bundle <project_name> <program_name>`
13. Generate a function dossier for a top candidate:
   - `scripts/ghidra_function_dossier <project_name> <program_name> <function_or_address>`
14. Apply a finding back into the project when you confirm something interesting:
   - `scripts/ghidra_apply_finding <project_name> <program_name> function=... title=... comment=...`
15. Run an extra script when needed:
   - `scripts/ghidra_run_script <project_name> <program_name> <script_name> [script args...]`
16. Record any friction or missing-feature notes through the shared notes flow before you wrap up the session:
   - `scripts/ghidra_notes_add title=... body=... category=workflow`
   - `scripts/ghidra_notes_status`
   - `scripts/ghidra_notes_open_shared`
17. Open the project in the GUI:
   - `scripts/ghidra_open_gui <project_name> [program_name]`
18. Arm or reuse the live bridge when you want an interactive RE loop:
   - `scripts/ghidra_bridge_open <project_name> [program_name]`
19. Use the live bridge wrappers for inspection or edits:
   - `scripts/ghidra_bridge_current_context`
   - `scripts/ghidra_bridge_snapshot`
   - `scripts/ghidra_bridge_analyze_target <query>`
   - `scripts/ghidra_bridge_decompile_current`
   - `scripts/ghidra_bridge_functions_search <query>`
   - `scripts/ghidra_bridge_selector_trace <selector>`
   - `scripts/ghidra_bridge_swift_search <type_or_method>`
   - `scripts/ghidra_bridge_swift_type <TypeName>`
   - `scripts/ghidra_bridge_xrefs`
   - `scripts/ghidra_bridge_rename ...`
   - `scripts/ghidra_bridge_comment ...`
   - `scripts/ghidra_bridge_patch_bytes ...`
   - `scripts/ghidra_bridge_patch_instruction ...`
20. Use the dyld-aware macOS import helper when a framework path comes from a live system image or extracted source root:
   - `scripts/ghidra_import_macos_framework </System/.../Framework.framework/Framework> [project_name] [copy=cache|direct] [source=<name>]`
21. Build a one-file macOS share bundle when you want to hand the skill and Ghidra to another desktop:
   - `scripts/build_mac_desktop_share_package [output_zip]`
22. Build a one-file Windows share bundle when you want easy installation on a Windows machine:
   - `scripts/build_windows_desktop_share_package [output_zip] [--ghidra-zip /path/to/ghidra.zip]`
23. On Windows, optionally import the native module after install:
   - `Import-Module GhidraRe`
   - `Get-GhidraReBridgeSessions`
   - `Start-GhidraReMission -Name win_trace -Goal 'Trace a subsystem' -Target 'source:mac-image:/System/.../WorkflowKit'`
24. Run the explicit polish pass before serious testing or publishing:
   - `scripts/ghidra_polish_release [mode=quick|release]`

## Default Workflow

### 1) Import into the dedicated workspace
- First-use bootstrap writes machine-local config to `~/.config/ghidra-re/config.env`.
- Projects live under `~/ghidra-projects/projects/<project_name>/`.
- Exports live under `~/ghidra-projects/exports/<project_name>/<program_name>/`.
- Logs live under `~/ghidra-projects/logs/<project_name>/`.
- Multi-target investigation workspaces live under `~/ghidra-projects/investigations/<mission_name>/`.
- Source-backed imports are cached under `~/ghidra-projects/sources/<source_name>/` by default when you use `source:name:/path`.
- Prefer explicit project names for reusable work. If omitted, the import wrapper derives one from the binary basename.
- On Windows, the PowerShell module resolves the installed skill root automatically from `CODEX_HOME` or `~/.codex/skills/ghidra-re`, then forwards to the same script surface.

### 2) Use missions for cross-target work
- Prefer `scripts/ghidra_mission_start` whenever the question spans multiple frameworks, daemons, or XPC helpers.
- Mission workspaces keep:
  - `mission.json`
  - `graph.sqlite`
  - `exports/`
  - `reports/latest.md`
  - `reports/latest.json`
- Mission runs are notes-only by default. They do not rename symbols, comment programs, or patch bytes unless you explicitly call the existing write wrappers outside the mission flow.
- `scripts/ghidra_mission_trace` uses the investigation graph first, then live bridge helpers like `functions/search`, `analyze/target`, and `selector-trace`.
- `scripts/ghidra_mission_autopilot` extends that loop by choosing the next seed from configured seeds, graph-derived suggestions, and recent analysis notes, then capturing a live bridge snapshot back into the mission artifacts.
- Autopilot seed ranking now prefers higher-signal graph functions, configured seeds, current-hypothesis targets, and preferred targets that have not been explored yet.
- `scripts/ghidra_mission_finish` is the default closeout path. It renders the report, records the closeout in the mission metadata, and closes the mission's bridge-managed Ghidra sessions unless `keep_sessions_open=true`.
- `scripts/ghidra_mission_finish` can also forward a discovered workflow-friction note into the shared GitHub-backed notes backlog with `shared_note_title=...` and `shared_note_body=...`.
- Finished missions now also emit `reports/casefile.md` and `reports/casefile.json` as a cleaner analyst closeout bundle.

### 3) Use the Apple export bundle first
- Run `scripts/ghidra_export_apple_bundle` after import unless the user only wants a narrow script run.
- The bundle runs `DemangleAllScript.java` and then exports:
  - `program_summary.json`
  - `objc_metadata.json`
  - `swift_metadata.json`
  - `function_inventory.json`
  - `symbols.json`
  - `strings.json`
- `swift_metadata.json` now includes:
  - demangled/raw Swift symbol pairs
  - a stable alias map
  - metadata-section summaries for `__swift5_*` blocks
  - async-like entries, metadata accessors, protocol conformance hints, and dispatch-thunk tagging
- Set `GHIDRA_EXPORT_DEMANGLE=0` when you want a faster or quieter export pass without the blanket demangle step.
- For Swift-heavy frameworks, prefer `scripts/ghidra_swift_surface_report` before ad hoc `functions/search` calls so you start from grouped types/methods instead of raw mangled names.

### 4) Use targeted scripts for follow-up
- Run `scripts/ghidra_export_bug_hunt_bundle` when the task is bug hunting, boundary analysis, or userland trust-boundary triage.
- Use `scripts/ghidra_function_dossier` on the top-ranked candidate paths before decompiling functions ad hoc.
- Use `scripts/ghidra_apply_finding` only when you want to write comments, bookmarks, or renames back into the project.
- Use `scripts/ghidra_notes_add` whenever the workflow exposes missing features, confusing outputs, or repetitive manual steps. The GitHub-backed shared issue is now the canonical community backlog; `references/use-case-driven-notes.md` is legacy/reference-only.
- `DecompileFunction.java` for on-demand decompilation
- `ExportXrefs.java` for targeted xref tracing
- `ExportAppleBundle.java` when you want the full structured export outside the convenience wrapper

### 5) Use the live bridge for iterative GUI sessions
- Prefer the live bridge whenever the target is already open or the task will involve repeated `search -> navigate -> decompile -> refs` loops.
- Prefer headless exports for wide scans, batch bundles, or cold-start project setup; switch to the bridge once you want a tighter interactive loop.
- `scripts/bootstrap` installs the bridge extension into the user's Ghidra settings when possible.
- If Ghidra was already running before the install, restart it once or run `EnableCodexBridge.java` from the GUI Script Manager.
- The bridge now keeps a real multi-session registry under `~/.config/ghidra-re/bridge-sessions/` and a compatibility pointer at `~/.config/ghidra-re/bridge-current.json`.
- `scripts/ghidra_bridge_open` and `scripts/ghidra_bridge_arm` write per-request files under `~/.config/ghidra-re/bridge-requests/`, first give an already-running Ghidra session a chance to consume them, and only then launch a detached GUI session if needed.
- Use `scripts/ghidra_bridge_sessions` to list live sessions and `scripts/ghidra_bridge_select` to change the default target.
- On macOS, detached launches use a hidden `screen` keeper session so Ghidra survives after the launcher command exits and the bridge remains usable across the rest of the Codex session.
- Cross-project arms are supported: a running `bsr_smoke` session can ignore a `workflowkit_bug_smoke` request while a newly launched WorkflowKit instance consumes the same request file and becomes another live session.
- `scripts/ghidra_bridge_call` is the raw HTTP wrapper; prefer the convenience wrappers for common tasks.
- `scripts/ghidra_bridge_open` now waits until both `/health` and `/session` succeed before it returns, so a reported armed bridge is immediately queryable.
- `scripts/ghidra_bridge_snapshot` captures the current live session, function, decompile, references, and variables in one machine-readable artifact for later ingestion or notes.
- Bridge snapshots now try to resolve the containing function from the current address, so mid-function cursor positions still produce a useful decompile/references bundle.
- Most live bridge wrappers accept optional `session=<id>`, `project=<name>`, or `program=<name>` selectors.
- Prefer `project=` or `session=` when duplicate live targets share the same `program_name`.
- `scripts/ghidra_bridge_swift_search` combines the live bridge session with the latest export bundle so type or method queries can resolve through stable aliases and thunk/canonical addresses.
- `scripts/ghidra_bridge_swift_type` aggregates grouped Swift type context, related strings, ObjC bridge names, metadata accessors, and the best live-analysis target when one is available.
- Mutating bridge calls require `write=true`; destructive bridge calls also require `destructive=true`.
- The PowerShell module mirrors the most common source, mission, and bridge commands with `Verb-GhidraRe*` functions for Windows-first usage.

## Command Surface

Run these wrappers from the skill directory:

- `scripts/ghidra_import_analyze <binary> [project_name]`
- `scripts/ghidra_import_macos_framework </System/.../Framework.framework[/Framework]> [project_name] [copy=cache|direct] [source=<name>]`
- `scripts/ghidra_run_script <project_name> <program_name> <script_name> [script args...]`
- `scripts/ghidra_export_apple_bundle <project_name> <program_name>`
- `scripts/ghidra_swift_surface_report <project_name> <program_name> [query] [format=json|markdown]`
- `scripts/ghidra_describe_swift_type <project_name> <program_name> <type_query>`
- `scripts/ghidra_export_bug_hunt_bundle <project_name> <program_name>`
- `scripts/ghidra_function_dossier <project_name> <program_name> <function_or_address>`
- `scripts/ghidra_apply_finding <project_name> <program_name> <key=value args...>`
- `scripts/ghidra_open_gui <project_name> [program_name]`
- `scripts/ghidra_bridge_build`
- `scripts/ghidra_bridge_install`
- `scripts/ghidra_bridge_arm <project_name> [program_name]`
- `scripts/ghidra_bridge_open <project_name> [program_name]`
- `scripts/ghidra_bridge_close [session=<id>|project=<name>|program=<name>]`
- `scripts/ghidra_bridge_close_all [mission=<name>] [all=true]`
- `scripts/ghidra_bridge_disarm`
- `scripts/ghidra_bridge_sessions`
- `scripts/ghidra_bridge_select session=<id>|project=<name>|program=<name>`
- `scripts/ghidra_bridge_status`
- `scripts/ghidra_bridge_call <endpoint> [json_body]`
- `scripts/ghidra_bridge_current_context`
- `scripts/ghidra_bridge_snapshot [key=value ...]`
- `scripts/ghidra_bridge_analyze_target <query> [key=value ...]`
- `scripts/ghidra_bridge_decompile_current [key=value ...]`
- `scripts/ghidra_bridge_functions_search <query> [key=value ...]`
- `scripts/ghidra_bridge_swift_search <type_or_method> [key=value ...]`
- `scripts/ghidra_bridge_swift_type <TypeName> [key=value ...]`
- `scripts/ghidra_bridge_selector_trace <selector> [key=value ...]`
- `scripts/ghidra_bridge_xrefs [key=value ...]`
- `scripts/ghidra_bridge_rename key=value ...`
- `scripts/ghidra_bridge_comment key=value ...`
- `scripts/ghidra_bridge_apply_signature key=value ...`
- `scripts/ghidra_bridge_apply_type key=value ...`
- `scripts/ghidra_bridge_patch_bytes <address> <hex_bytes>`
- `scripts/ghidra_bridge_patch_instruction <address> <assembly>`
- `scripts/ghidra_bridge_clear_listing <start> [end] [mode]`
- `scripts/ghidra_bridge_disassemble <start> [end]`
- `scripts/ghidra_bridge_create_function <entry> [name] [end]`
- `scripts/ghidra_bridge_delete_function <function_or_address>`
- `scripts/ghidra_bridge_create_data <address> <datatype>`
- `scripts/ghidra_bridge_delete_data <address> [end]`
- `scripts/ghidra_source_add <name> root=<path> [platform=macos-image] [copy=cache|direct]`
- `scripts/ghidra_source_list`
- `scripts/ghidra_source_resolve <name> </path/in/image> [copy=cache|direct]`
- `scripts/ghidra_mission_start <mission_name> goal=... target=... [target=...] [seed=...]`
- `scripts/ghidra_mission_status <mission_name>`
- `scripts/ghidra_mission_trace <mission_name> seed=<kind:value> [target=project:program]`
- `scripts/ghidra_mission_report <mission_name> [format=markdown|json|path]`
- `scripts/ghidra_mission_report <mission_name> [format=markdown|json|path|casefile|casefile-path]`
- `scripts/ghidra_mission_autopilot <mission_name> [rounds=3] [seed=<kind:value>] [target=project:program]`
- `scripts/ghidra_mission_finish <mission_name> [all=true] [keep_sessions_open=true]`
- `scripts/ghidra_notes_add title=... body=... [category=workflow] [target=...]`
- `scripts/ghidra_notes_sync`
- `scripts/ghidra_notes_pull`
- `scripts/ghidra_notes_status`
- `scripts/ghidra_notes_remediate fingerprint=... [summary=...]`
- `scripts/ghidra_notes_open_shared [browse=true]`
- `scripts/bootstrap [--skip-smoke-test]`
- `scripts/doctor`
- `scripts/ghidra_polish_release [mode=quick|release]`
- `scripts/build_share_package [output_zip]`
- `scripts/build_mac_desktop_share_package [output_zip] [--without-ghidra-payload]`
- `scripts/build_windows_desktop_share_package [output_zip] [--ghidra-zip /path/to/ghidra.zip]`
- `powershell/GhidraRe.psd1` and `powershell/GhidraRe.psm1` for native Windows PowerShell wrappers
- `scripts/ghidra_polish_release` for the explicit pre-test release/polish pass

### Script argument style
- Prefer `key=value` arguments because they are robust under `analyzeHeadless`.
- The wrapper also accepts `--key value` and rewrites it to `key=value`.
- Set `GHIDRA_IMPORT_DEMANGLE=0` to skip the default import-time demangle pass.
- Examples:
  - `scripts/ghidra_run_script bsr_smoke BackgroundShortcutRunner DecompileFunction.java function=-[WFBackgroundShortcutRunner runWorkflowWithDescriptor:request:inEnvironment:runningContext:completion:] output=/tmp/wf_runner.c`
  - `scripts/ghidra_run_script bsr_smoke BackgroundShortcutRunner ExportXrefs.java --symbol _objc_msgSend --output /tmp/objc_msgsend_xrefs.json`

## Built-ins Vs Custom Scripts

- Prefer the custom scripts in `scripts/ghidra_scripts/` for structured exports and repeatable output.
- The main custom scripts are:
  - `ExportAppleBundle.java`
  - `ExportEntrypoints.java`
  - `ExportSinks.java`
  - `TriageBugPaths.java`
  - `ExportFunctionDossier.java`
  - `ApplyFinding.java`
  - `DecompileFunction.java`
  - `ExportXrefs.java`
- Prefer built-in scripts only when they already solve the job cleanly.
- Safe default built-in:
  - `DemangleAllScript.java`
- Built-ins that are often useful but context-sensitive:
  - `SwiftDemanglerScript.java`
  - `MachO_Script.java`
- Built-ins that are less suited to headless automation because they prompt or assume a GUI cursor:
  - `ExportFunctionInfoScript.java`

Use `scripts/ghidra_run_script` for both built-ins and custom scripts. It adds the custom script directory and the common built-in Ghidra script directories to `-scriptPath`.

## References

Read only what you need:

- Apple Mach-O notes and common targets: `references/apple-macho-notes.md`
- Output files and schemas: `references/output-files.md`
- Bridge session and operation-log notes: `references/output-files.md`
- Bug-hunt output bundle details: `references/bug-hunt-outputs.md`
- Bug-hunt heuristics and categories: `references/bug-hunt-patterns.json`
- Built-in script caveats: `references/builtins.md`
- Use-case-driven skill improvement notes: shared via the GitHub-backed notes commands above; `references/use-case-driven-notes.md` is legacy/reference history inside the repo
