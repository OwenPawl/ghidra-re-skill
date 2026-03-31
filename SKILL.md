---
name: ghidra-re
description: Use for Ghidra-based reverse engineering on this machine, especially Apple Mach-O and dyld-extracted binaries. Trigger when the user wants headless Ghidra import/analysis, to run Ghidra scripts, inspect decompilation, or export structured reversing artifacts such as functions, strings, symbols, Objective-C metadata, or xrefs. Prefer this skill over ad hoc shell commands when the task should create or reuse a Ghidra project under ~/ghidra-projects.
---

# Ghidra RE

Use this skill for repeatable, headless-first Ghidra work on macOS. It assumes:

- Ghidra install: `/Applications/Ghidra`
- JDK: `/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home`
- Workspace root: `~/ghidra-projects`
- Skill root: `~/.codex/skills/ghidra-re`

V1 is optimized for Apple Mach-O reversing and dyld-extracted binaries. It now includes a localhost GUI bridge extension for live inspection, annotation, and controlled program surgery inside an open Ghidra session.

The custom automation scripts ship as Java Ghidra scripts because that is the most reliable headless path on this machine.

## Quick Start

1. On a fresh machine, run `scripts/bootstrap` once.
2. If bootstrap cannot find Ghidra or Java 21, run `scripts/doctor`.
3. Import and analyze a target into a dedicated project:
   - `scripts/ghidra_import_analyze <binary> [project_name]`
4. Export the default Apple-focused bundle:
   - `scripts/ghidra_export_apple_bundle <project_name> <program_name>`
5. Export the bug-hunt bundle when you want entrypoint-to-sink triage:
   - `scripts/ghidra_export_bug_hunt_bundle <project_name> <program_name>`
6. Generate a function dossier for a top candidate:
   - `scripts/ghidra_function_dossier <project_name> <program_name> <function_or_address>`
7. Apply a finding back into the project when you confirm something interesting:
   - `scripts/ghidra_apply_finding <project_name> <program_name> function=... title=... comment=...`
8. Run an extra script when needed:
   - `scripts/ghidra_run_script <project_name> <program_name> <script_name> [script args...]`
9. Append any friction or missing-feature notes to `references/use-case-driven-notes.md` before you wrap up the session.
10. Open the project in the GUI:
   - `scripts/ghidra_open_gui <project_name> [program_name]`
11. Arm the live bridge when you want an interactive RE loop:
   - `scripts/ghidra_bridge_arm <project_name> [program_name]`
12. Use the live bridge wrappers for inspection or edits:
   - `scripts/ghidra_bridge_current_context`
   - `scripts/ghidra_bridge_analyze_target <query>`
   - `scripts/ghidra_bridge_decompile_current`
   - `scripts/ghidra_bridge_functions_search <query>`
   - `scripts/ghidra_bridge_selector_trace <selector>`
   - `scripts/ghidra_bridge_xrefs`
   - `scripts/ghidra_bridge_rename ...`
   - `scripts/ghidra_bridge_comment ...`
   - `scripts/ghidra_bridge_patch_bytes ...`
   - `scripts/ghidra_bridge_patch_instruction ...`
13. Build a one-file macOS share bundle when you want to hand the skill and Ghidra to another desktop:
   - `scripts/build_mac_desktop_share_package [output_zip]`

## Default Workflow

### 1) Import into the dedicated workspace
- First-use bootstrap writes machine-local config to `~/.config/ghidra-re/config.env`.
- Projects live under `~/ghidra-projects/projects/<project_name>/`.
- Exports live under `~/ghidra-projects/exports/<project_name>/<program_name>/`.
- Logs live under `~/ghidra-projects/logs/<project_name>/`.
- Prefer explicit project names for reusable work. If omitted, the import wrapper derives one from the binary basename.

### 2) Use the Apple export bundle first
- Run `scripts/ghidra_export_apple_bundle` after import unless the user only wants a narrow script run.
- The bundle runs `DemangleAllScript.java` and then exports:
  - `program_summary.json`
  - `objc_metadata.json`
  - `function_inventory.json`
  - `symbols.json`
  - `strings.json`
- Set `GHIDRA_EXPORT_DEMANGLE=0` when you want a faster or quieter export pass without the blanket demangle step.

### 3) Use targeted scripts for follow-up
- Run `scripts/ghidra_export_bug_hunt_bundle` when the task is bug hunting, boundary analysis, or userland trust-boundary triage.
- Use `scripts/ghidra_function_dossier` on the top-ranked candidate paths before decompiling functions ad hoc.
- Use `scripts/ghidra_apply_finding` only when you want to write comments, bookmarks, or renames back into the project.
- Append dated notes to `references/use-case-driven-notes.md` whenever the workflow exposes missing features, confusing outputs, or repetitive manual steps.
- `DecompileFunction.java` for on-demand decompilation
- `ExportXrefs.java` for targeted xref tracing
- `ExportAppleBundle.java` when you want the full structured export outside the convenience wrapper

### 4) Use the live bridge for iterative GUI sessions
- Prefer the live bridge whenever the target is already open or the task will involve repeated `search -> navigate -> decompile -> refs` loops.
- Prefer headless exports for wide scans, batch bundles, or cold-start project setup; switch to the bridge once you want a tighter interactive loop.
- `scripts/bootstrap` installs the bridge extension into the user's Ghidra settings when possible.
- If Ghidra was already running before the install, restart it once or run `EnableCodexBridge.java` from the GUI Script Manager.
- `scripts/ghidra_bridge_arm` writes `~/.config/ghidra-re/bridge-control.json`, first gives an already-running Ghidra session a chance to consume it, and only then launches a detached GUI session if needed.
- On macOS, detached launches use a hidden `screen` keeper session so Ghidra survives after the launcher command exits and the bridge remains usable across the rest of the Codex session.
- Cross-project arms are supported: a running `bsr_smoke` session can ignore a `workflowkit_bug_smoke` arm request while a newly launched WorkflowKit instance consumes the same control file and becomes the active bridge session.
- `scripts/ghidra_bridge_call` is the raw HTTP wrapper; prefer the convenience wrappers for common tasks.
- Mutating bridge calls require `write=true`; destructive bridge calls also require `destructive=true`.

## Command Surface

Run these wrappers from the skill directory:

- `scripts/ghidra_import_analyze <binary> [project_name]`
- `scripts/ghidra_run_script <project_name> <program_name> <script_name> [script args...]`
- `scripts/ghidra_export_apple_bundle <project_name> <program_name>`
- `scripts/ghidra_export_bug_hunt_bundle <project_name> <program_name>`
- `scripts/ghidra_function_dossier <project_name> <program_name> <function_or_address>`
- `scripts/ghidra_apply_finding <project_name> <program_name> <key=value args...>`
- `scripts/ghidra_open_gui <project_name> [program_name]`
- `scripts/ghidra_bridge_build`
- `scripts/ghidra_bridge_install`
- `scripts/ghidra_bridge_arm <project_name> [program_name]`
- `scripts/ghidra_bridge_disarm`
- `scripts/ghidra_bridge_status`
- `scripts/ghidra_bridge_call <endpoint> [json_body]`
- `scripts/ghidra_bridge_current_context`
- `scripts/ghidra_bridge_analyze_target <query> [key=value ...]`
- `scripts/ghidra_bridge_decompile_current [key=value ...]`
- `scripts/ghidra_bridge_functions_search <query> [key=value ...]`
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
- `scripts/bootstrap [--skip-smoke-test]`
- `scripts/doctor`
- `scripts/build_share_package [output_zip]`
- `scripts/build_mac_desktop_share_package [output_zip] [--without-ghidra-payload]`

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
- Use-case-driven skill improvement notes: `references/use-case-driven-notes.md`
