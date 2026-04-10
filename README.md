# ghidra-re

`ghidra-re` is a local Codex skill for Ghidra-based reverse engineering on macOS and Windows, with a workflow tuned for Apple Mach-O binaries, dyld-extracted frameworks, multi-target investigation missions, and a live Ghidra bridge for iterative RE sessions.

## What it includes

- Headless import and analysis helpers
- Structured exports for functions, strings, symbols, Objective-C metadata, and xrefs
- Richer Swift exports with demangled alias maps, metadata-section recovery, and surface-level type reports
- A multi-session live Ghidra bridge registry for several open targets at once
- Bridge snapshots, mission finish/cleanup, and an autonomous multi-round mission driver
- Mission workspaces with a persistent SQLite investigation graph, notes, and reports
- Smarter autopilot seed ranking, richer live snapshots, and mission case files for closeout
- Function dossiers, write-back helpers, and optional bug-hunt overlays
- A live Ghidra bridge extension for navigation, decompilation, comments, renames, and controlled program surgery
- Dyld-aware import helpers for macOS frameworks and cache-backed Apple binaries
- Share-package builders for handing the skill to another Mac

## Layout

- [SKILL.md](./SKILL.md): skill entrypoint and workflow instructions
- [scripts](./scripts): shell wrappers and builders
- [powershell](./powershell): native PowerShell module for Windows-first usage
- [bridge-extension](./bridge-extension): Ghidra bridge source and prebuilt extension zips
- [references](./references): notes, schemas, and heuristics
- [agents/openai.yaml](./agents/openai.yaml): skill metadata for Codex discovery

## Shared notes

`ghidra-re` now has a GitHub-backed global use-case notes system.

- Canonical public backlog: one GitHub issue in `OwenPawl/ghidra-re-skill`
- Local resilience layer: `~/.config/ghidra-re/shared-notes/`
- Write path: structured local queue first, then sync to GitHub when `gh` is authenticated

The main commands are:

```bash
./scripts/ghidra_notes_status
./scripts/ghidra_notes_add title='Missing live-export ingest' body='Baseline export still requires close/reopen for an already-open target.' category=workflow target=workflowkit_bug_smoke:WorkflowKit
./scripts/ghidra_notes_sync
./scripts/ghidra_notes_pull
./scripts/ghidra_notes_open_shared
```

The old [use-case-driven-notes.md](./references/use-case-driven-notes.md) file is now legacy/reference-only and no longer the canonical live backlog.

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

If you want a one-file Windows installer bundle:

```bash
./scripts/build_windows_desktop_share_package
```

That creates a zip with a PowerShell installer that can:
- install the skill into `%USERPROFILE%\.codex\skills\ghidra-re`
- install a user-scoped `GhidraRe` PowerShell module
- install Git for Windows when Git Bash is missing
- install Java 21 when needed
- reuse an existing Ghidra install or unpack a `ghidra_*.zip` placed next to the installer

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

On Windows, you can now use either Git Bash or the native `GhidraRe` PowerShell module.

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

Shared-notes defaults:

- Repo: `OwenPawl/ghidra-re-skill`
- Auto-sync: on when `gh` is authenticated
- Local queue/cache: `~/.config/ghidra-re/shared-notes/`

## Windows Apple-target flow

The Windows installer now installs a PowerShell module named `GhidraRe`. After install:

```powershell
Import-Module GhidraRe
Get-GhidraReBridgeSessions
Start-GhidraReMission -Name win_trace -Goal 'Trace a subsystem' -Target 'source:mac-image:/System/Library/PrivateFrameworks/WorkflowKit.framework/Versions/A/WorkflowKit'
```

The module is a native PowerShell-facing layer over the same `ghidra-re` scripts, so it feels normal in PowerShell while still reusing the skill's battle-tested Bash workflow underneath.

The shared-notes flow is also available from PowerShell:

```powershell
Get-GhidraReNotesStatus
Add-GhidraReNote -Title 'Missing feature' -Body 'Describe the friction here.'
Sync-GhidraReNotes
Receive-GhidraReNotes
Open-GhidraReSharedNotes
```

If you prefer Bash directly, the source-backed Apple flow is still:

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

If you are preparing a Windows share package on another machine and already have a Windows Ghidra zip, you can embed it:

```bash
./scripts/build_windows_desktop_share_package out.zip --ghidra-zip /path/to/ghidra_*.zip
```

## Typical workflow

```bash
./scripts/bootstrap
./scripts/ghidra_mission_start my_mission \
  goal='Trace a subsystem across related targets' \
  target=/absolute/path/to/binary \
  target=existing_project:FrameworkName
./scripts/ghidra_mission_trace my_mission seed=selector:initWithCoder:
./scripts/ghidra_mission_autopilot my_mission rounds=2
./scripts/ghidra_mission_report my_mission
./scripts/ghidra_mission_report my_mission format=casefile
./scripts/ghidra_mission_finish my_mission shared_note_title='Autopilot friction' shared_note_body='Need a better ObjC sender ranking view in live snapshots.'
```

For a focused single-target session, the fastest interactive loop is usually:

```bash
./scripts/ghidra_import_analyze /path/to/binary my_project
./scripts/ghidra_export_apple_bundle my_project BinaryName
./scripts/ghidra_bridge_open my_project BinaryName
./scripts/ghidra_bridge_functions_search 'SomeFunctionName'
./scripts/ghidra_bridge_analyze_target 'SomeFunctionName'
./scripts/ghidra_bridge_selector_trace 'someSelector:'
./scripts/ghidra_bridge_snapshot
```

`ghidra_bridge_snapshot` now resolves the containing function from the current address when possible, so bridge snapshots stay useful even when the UI is parked mid-function instead of at a clean entry point.

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

For Swift-heavy Apple frameworks, the higher-signal flow is now:

```bash
./scripts/ghidra_import_macos_framework /System/Library/PrivateFrameworks/VoiceShortcuts.framework/VoiceShortcuts
./scripts/ghidra_export_apple_bundle VoiceShortcuts_<hash> VoiceShortcuts
./scripts/ghidra_swift_surface_report VoiceShortcuts_<hash> VoiceShortcuts query=VoiceShortcuts. format=markdown
./scripts/ghidra_describe_swift_type VoiceShortcuts_<hash> VoiceShortcuts VoiceShortcuts.SpotlightIndexingCoordinator
./scripts/ghidra_bridge_open VoiceShortcuts_<hash> VoiceShortcuts
./scripts/ghidra_bridge_swift_search 'VoiceShortcuts.EventNode'
./scripts/ghidra_bridge_swift_type VoiceShortcuts.SpotlightIndexingCoordinator
```

`ghidra_bridge_open` now waits until both `/health` and `/session` succeed before it returns, so “bridge armed” also means “bridge is queryable.”

For ObjC-heavy Apple frameworks or mixed Swift/ObjC subsystems, prefer:

```bash
./scripts/ghidra_export_apple_bundle workflowkit_full_dyld_extract WorkflowKit
./scripts/ghidra_objc_surface_report workflowkit_full_dyld_extract WorkflowKit markdown
./scripts/ghidra_describe_objc_class workflowkit_full_dyld_extract WorkflowKit WFRemoteExecutionCoordinator
./scripts/ghidra_describe_objc_protocol workflowkit_full_dyld_extract WorkflowKit IndexedEntity
./scripts/ghidra_describe_selector workflowkit_full_dyld_extract WorkflowKit 'handleRunRequest:service:account:fromID:context:'
./scripts/ghidra_trace_classref workflowkit_full_dyld_extract WorkflowKit WFRemoteExecutionCoordinator
./scripts/ghidra_objc_message_flow workflowkit_full_dyld_extract WorkflowKit 'handleRunRequest:service:account:fromID:context:' class=WFRemoteExecutionCoordinator
```

Those helpers merge the richer `symbols.json` ObjC method surface with `objc_metadata.json`, so imported-style methods like `-[WFRemoteExecutionCoordinator_handleRunRequest:...]` still show up even when the flatter metadata method bucket is incomplete. `ghidra_objc_message_flow` builds on top of that by grouping receiver classes, sibling selectors, and live sender hints when a bridge session is available.

## Notes

- Real workflow friction and wishlist items now live in the shared GitHub-backed notes flow. Use `./scripts/ghidra_notes_add` for new items and `./scripts/ghidra_notes_open_shared` for the canonical public backlog.
- [use-case-driven-notes.md](./references/use-case-driven-notes.md) remains in the repo as legacy/reference history, not the canonical day-to-day write target.
- Mission workspaces live under `~/ghidra-projects/investigations/<mission_name>/`.
- Finished missions now also emit `reports/casefile.md` and `reports/casefile.json` for analyst-friendly closeout.
- The live bridge keeps one compatibility pointer in `bridge-current.json`, but the real session registry lives under `~/.config/ghidra-re/bridge-sessions/`.
- The skill prefers the live bridge when an iterative GUI session is more useful than another headless export pass, and now supports selecting among multiple live targets.
- `ExportAppleBundle.java` now emits richer `swift_metadata.json` content, including demangled/raw names, stable aliases, metadata-section summaries, async-like entries, protocol witness hints, and dispatch-thunk tagging.
- The Windows desktop installer also installs a user PowerShell module so day-to-day Windows use does not have to start in Git Bash.
- `ghidra_mission_finish` closes the mission's live Ghidra sessions by default, and `ghidra_bridge_close_all all=true` is the emergency cleanup button when you want every bridge-managed Ghidra window gone.
- `ghidra_polish_release` is the explicit pre-testing pass for syntax, builders, bridge buildability, and packaging.
