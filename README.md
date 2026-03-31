# ghidra-re

`ghidra-re` is a local Codex skill for Ghidra-based reverse engineering on macOS, with a workflow tuned for Apple Mach-O binaries, dyld-extracted frameworks, bug-hunting triage, and a live Ghidra bridge for iterative RE sessions.

## What it includes

- Headless import and analysis helpers
- Structured exports for functions, strings, symbols, Objective-C metadata, and xrefs
- Bug-hunt bundle generation for entrypoint-to-sink triage
- Function dossiers and project write-back helpers
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

- macOS
- Ghidra 12.0.4
- Java 21
- Codex with local skill support

The default local assumptions are:

- Ghidra install: `/Applications/Ghidra`
- Launcher app: `/Applications/Ghidra.app`
- JDK: `/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home`
- Workspace: `~/ghidra-projects`

## Typical workflow

```bash
./scripts/bootstrap
./scripts/ghidra_import_analyze /path/to/binary my_project
./scripts/ghidra_export_apple_bundle my_project BinaryName
./scripts/ghidra_export_bug_hunt_bundle my_project BinaryName
./scripts/ghidra_open_gui my_project BinaryName
./scripts/ghidra_bridge_arm my_project BinaryName
```

Once the bridge is armed, the fastest interactive loop is usually:

```bash
./scripts/ghidra_bridge_functions_search 'SomeFunctionName'
./scripts/ghidra_bridge_analyze_target 'SomeFunctionName'
./scripts/ghidra_bridge_selector_trace 'someSelector:'
```

## Notes

- Real workflow friction and wishlist items are tracked in [use-case-driven-notes.md](./references/use-case-driven-notes.md).
- The skill prefers the live bridge when an iterative GUI session is more useful than another headless export pass.
