# ghidra-re

`ghidra-re` is a local Codex skill for Ghidra-based reverse engineering on macOS, with a workflow tuned for Apple Mach-O binaries, dyld-extracted frameworks, multi-target investigation missions, and a live Ghidra bridge for iterative RE sessions.

## What it includes

- Headless import and analysis helpers
- Structured exports for functions, strings, symbols, Objective-C metadata, and xrefs
- A multi-session live Ghidra bridge registry for several open targets at once
- Mission workspaces with a persistent SQLite investigation graph, notes, and reports
- Function dossiers, write-back helpers, and optional bug-hunt overlays
- A live Ghidra bridge extension for navigation, decompilation, comments, renames, and controlled program surgery
- Share-package builders for handing the skill to another Mac

## Layout

- [SKILL.md](./SKILL.md): skill entrypoint and workflow instructions
- [scripts](./scripts): shell wrappers and builders
- [bridge-extension](./bridge-extension): Ghidra bridge source and prebuilt extension zips
- [references](./references): notes, schemas, and heuristics
- [agents/openai.yaml](./agents/openai.yaml): skill metadata for Codex discovery

## Quick install

If you already use Codex locally:

```bash
mkdir -p ~/.codex/skills
cp -R ghidra-re ~/.codex/skills/ghidra-re
~/.codex/skills/ghidra-re/scripts/bootstrap
```

If you want a one-file Mac installer bundle:

```bash
./scripts/build_mac_desktop_share_package
```

That creates a zip that can install the skill, Ghidra, the launcher app, and Java 21 on another Mac.

## Publish to GitHub

If `gh` is installed and authenticated:

```bash
./publish-to-github.sh
```

Defaults:

- repo name: `ghidra-re-skill`
- visibility: `public`

You can override both:

```bash
./publish-to-github.sh my-repo-name private
```

## Requirements

- macOS or Windows
- Ghidra 12.0.4
- Java 21
- Codex with local skill support

On Windows, the scripts are intended to run from Git Bash.

The default local assumptions are:

- Ghidra install:
  - macOS: `/Applications/Ghidra`
  - Windows: `/c/Program Files/Ghidra`
- Launcher app:
  - macOS: `/Applications/Ghidra.app`
  - Windows: `ghidraRun.bat`
- JDK:
  - macOS: `/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home`
  - Windows: `/c/Program Files/Eclipse Adoptium/jdk-21`
- Workspace: `~/ghidra-projects`

## Windows Apple-target flow

When a Windows machine needs Apple binaries, register a mounted or extracted macOS root as a source:

```bash
./scripts/ghidra_source_add mac-image root=/d/macos-root platform=macos-image copy=cache
./scripts/ghidra_source_list
./scripts/ghidra_import_analyze source:mac-image:/System/Library/PrivateFrameworks/VoiceShortcuts.framework/Versions/A/VoiceShortcuts
```

Mission targets can use the same source form:

```bash
./scripts/ghidra_mission_start win_trace \
  goal='Trace a subsystem across Apple userland targets' \
  target=source:mac-image:/System/Library/PrivateFrameworks/WorkflowKit.framework/Versions/A/WorkflowKit
```

## Typical workflow

```bash
./scripts/bootstrap
./scripts/ghidra_mission_start my_mission \
  goal='Trace a subsystem across related targets' \
  target=/absolute/path/to/binary \
  target=existing_project:FrameworkName
./scripts/ghidra_mission_trace my_mission seed=selector:initWithCoder:
./scripts/ghidra_mission_report my_mission
```

For a focused single-target session, the fastest interactive loop is usually:

```bash
./scripts/ghidra_import_analyze /path/to/binary my_project
./scripts/ghidra_export_apple_bundle my_project BinaryName
./scripts/ghidra_bridge_open my_project BinaryName
./scripts/ghidra_bridge_functions_search 'SomeFunctionName'
./scripts/ghidra_bridge_analyze_target 'SomeFunctionName'
./scripts/ghidra_bridge_selector_trace 'someSelector:'
```

For a live multi-target session, start with the registry:

```bash
./scripts/ghidra_bridge_sessions
./scripts/ghidra_bridge_select project=workflowkit_bug_smoke
```

Prefer `project=` or `session=` when two live targets share the same program name.

The optional bug-hunt layer is still there when you want it:

```bash
./scripts/ghidra_export_bug_hunt_bundle my_project BinaryName
./scripts/ghidra_function_dossier my_project BinaryName 100012340
```

## Notes

- Real workflow friction and wishlist items are tracked in [use-case-driven-notes.md](./references/use-case-driven-notes.md).
- Mission workspaces live under `~/ghidra-projects/investigations/<mission_name>/`.
- The live bridge keeps one compatibility pointer in `bridge-current.json`, but the real session registry lives under `~/.config/ghidra-re/bridge-sessions/`.
- The skill prefers the live bridge when an iterative GUI session is more useful than another headless export pass, and now supports selecting among multiple live targets.
