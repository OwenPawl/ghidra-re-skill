# Use-Case Driven Notes

This file captures friction, missing features, and quality-of-life improvements discovered while using `ghidra-re` on real targets. Add short dated notes here during or immediately after a workflow so future skill work stays grounded in actual reverse-engineering use.

## 2026-03-30 - WorkflowKit

- The default demangle pass is too noisy on a large Swift/ObjC framework like WorkflowKit. Thousands of "Unable to demangle" lines make the logs hard to scan. The skill needs a quieter default mode or a summarized demangle report.
- The bug-hunt bundle schema is not obvious enough from memory alone. Add a lightweight helper that prints "top N candidates", "top entrypoints", and "top sinks" without having to inspect JSON structure manually.
- Large-framework triage needs a faster subsystem summary. Add a command that groups top candidates by class, namespace, or prefix so huge outputs feel navigable sooner.
- Turning a candidate path into a dossier still requires manual function/address selection. Add a wrapper that accepts a ranked candidate index and generates the dossier directly.
- The live bridge install is still awkward when Ghidra was already running. Improve the first-run flow so the plugin is easier to load without a restart or manual script execution.
- Entrypoint ranking on a huge framework still overweights generic helpers and weak evidence like `MACH_HEADER`, `_block_copy_helper`, or broad UI/action strings. Add better filtering for runtime helpers, block stubs, and low-signal exported symbols.
- Sink ranking on Swift-heavy code still misclassifies some concurrency/task scaffolding as interesting sinks. Add better suppression for generic `swift_task_*`-style helpers unless they co-occur with stronger parser, filesystem, process, or authorization evidence.
- The bug-hunt outputs need clearer count semantics. In this WorkflowKit run, `entrypoints.json` contained 14,380 raw matches while `summary.md` reported 40 entrypoints considered. Add explicit fields and documentation for raw matches vs deduplicated/triaged candidates.
- Function dossiers for parser/response handlers should surface object-field writes and retained outputs. In the ACE response parser, the important result is not just the callee list; it is that the function populates `_originatingRequestIdentifier`, `_aceCommandResponseDictionary`, and `_error`.
- WorkflowKit's remote-execution subsystem benefits immediately from the live loop. The sequence "arm bridge -> decompile exact handler -> fetch references -> compare sibling handlers" surfaced the coordinator flow much faster than exporting another dossier each time. Keep that as the default bridge pattern when adding higher-level helpers.
- Objective-C-heavy code needs a better bridge-side "message flow" view than plain callers/callees. On WorkflowKit's remote-execution methods, `references` often showed zero callers because dispatch goes through `objc_msgSend`, even though the functions are clearly part of an active message path.
- The first selector trace is useful, but it is still heuristic. Searching implementations plus selector-string references is enough to surface likely senders, but a stronger ObjC message-flow model should eventually understand selector-bearing callsites and message-send patterns more directly.

## 2026-03-31 - BackgroundShortcutRunner

- The bug-hunt bundle is weaker on stripped Swift host binaries like `BackgroundShortcutRunner` than on framework targets. Too many high-ranked entrypoints and sinks still collapse to `None` or `FUN_*`, which makes the first pass harder to trust. Add a fallback that prefers nearby Objective-C namespace names, selector-bearing wrapper names, or known helper-function identities when direct symbol names are missing.
- The headless dossier workflow should detect and serialize same-project runs instead of letting parallel invocations fail with `Unable to lock project!`. This came up immediately when I asked for multiple `BackgroundShortcutRunner` dossiers at once.
- The current macOS cold-launch backend uses a detached `screen` keeper session so Ghidra survives after the launcher command exits. That works well in Codex, but it is still a workaround. A cleaner long-term launcher helper for GUI ownership on macOS would be nicer than relying on `screen`.
- Multi-target missions are now viable, but the first raw-binary import can still dominate startup time even with demangling disabled by default. A future "fast import now, enrich later" mode would make the pilot feel more autonomous on fresh targets.
- Multi-session selection works well by `project=` or `session=`, but `program=` becomes ambiguous fast when two live targets share the same binary name. Add a helper that shows compact disambiguation choices or prefers exact `project:program` refs in more wrappers.
- When a mission needs its first baseline export for a target that is already open live, the current flow closes and reopens that target because Ghidra project locks are exclusive. A future live-export ingest path would avoid that churn.
- The new Windows installer path is much better, but the skill still fundamentally expects Git Bash for day-to-day use. A future native PowerShell wrapper layer would make Windows feel first-class instead of "well-supported through Bash."
