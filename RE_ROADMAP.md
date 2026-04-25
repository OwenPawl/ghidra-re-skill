# Ghidra RE Skill — Implementation Roadmap

> Living document. Update status inline as work progresses.
> Last updated: 2026-04-24

---

## North Star

Close the full RE circle: **discover → understand → observe → interpret → act**

The skill currently covers discover + understand well, observe partially (LLDB call chain only), and interpret/act almost not at all. Each phase below moves one step closer to a complete loop where static analysis, dynamic observation, and data-level understanding reinforce each other automatically.

---

## Phase 0 — Stabilise existing dynamic infra (prerequisite)
*Must be solid before building on top of it.*

| # | Item | Status | Notes |
|---|------|--------|-------|
| 0.1 | Fix `capture_objc_class` in `ghidra_lldb_trace` — isa memory read | ✅ Built, ❌ Not validated | Handler rewrote, never got clean run. Next shortcut trace should confirm. |
| 0.2 | Validate `capture_objc_class` gives correct class names on BSR | ⬜ Pending | Run "Shift Coverage", confirm hits include `objc_isa` field |
| 0.3 | Document `attach_name` + shortcut-trigger timing recipe in SKILL.md | ✅ Built | SKILL.md now warns that timeout starts before `--waitfor` attach completes; start trace first and trigger quickly. |

---

## Phase 1 — Argument content / object introspection
*What data is actually flowing through the call chain.*

**Gap:** LLDB trace captures `x0=0x8528c8600` — a heap pointer with no content. We see *that* `WFAction runWithInput:` fired, not *what* input was, *which* WFAction subclass `self` is, or *what* was returned.

### 1.1 — ObjC class name from isa (Phase 0.1 dependency)
- Approach: memory read isa pointer at x0, mask PAC bits (`& 0x0000007fffffffff`), resolve against `ghidra_build_isa_map` output
- Needed first: `ghidra_build_isa_map` (Phase 1.2)
- Status: ✅ Implemented in `ghidra_lldb_trace`; live validation still pending via Phase 0.2

### 1.2 — `ghidra_build_isa_map`
- **New script** (shell + Python)
- Reads `objc_metadata.json` from export bundle
- Extracts ObjC class object addresses (Ghidra's `__objc_classrefs` / class list)
- Outputs `isa_map.json`: `{ "0x28a1234": "WFCalculateExpressionAction", ... }`
- LLDB isa captures can then be resolved in post without any live process
- Implementation: parse `objc_metadata.json` → extract `class_address` for each class entry

### 1.3 — `capture_objc_args=true` in `ghidra_lldb_trace`
- Extends existing trace handler
- When `capture_objc_args=true`: follows x0 pointer, reads isa, resolves class name via isa_map if provided
- Also captures x1 (selector string pointer → read cstring) for ObjC calls
- Optional: read `-description` output via `object_getClassName` (already attempted — use memory read path instead)
- Outputs per-hit: `{ "self_class": "WFCalculateExpressionAction", "selector": "runWithInput:error:", ... }`
- Status: ✅ Implemented; waiting on a real ObjC trace to confirm hit quality

### 1.4 — Object field dumper (stretch)
- For known WFAction subclasses, read ivar offsets from ObjC runtime layout in binary
- Dump key ivars (action identifier, parameters dict address) at each hit
- High complexity, do only if 1.1–1.3 prove insufficient

---

## Phase 2 — Static-to-dynamic bridge (`ghidra_lldb_enrich`)
*Map runtime observations back into the static model automatically.*

**Gap:** Every LLDB trace produces a JSON of PCs and registers that lives in isolation. There's no connection to the Ghidra function inventory, decompiled output, or xref graph.

### 2.1 — Address slide computation
- Input: `lldb_trace_*.json` + `function_inventory.json` + `lldb_symbols.json`
- Method: find any named hit whose symbol appears in `lldb_symbols.json` → `slide = runtime_pc - static_addr`
- Fallback: ask user to provide one known-good mapping
- Output: `{ "slide": 0x168017e0, "confidence": "high" }`
- Status: ✅ Implemented in `ghidra_lldb_enrich`; validated on WorkflowKit trace with high-confidence slide

### 2.2 — PC → Ghidra address mapping
- Apply slide to all hit PCs: `ghidra_addr = runtime_pc - slide`
- Look up each ghidra_addr in `function_inventory.json` by address
- Annotate each hit with: function name, address, size, caller count, category tags
- Status: ✅ Implemented and validated on WorkflowKit trace (`5/5` hits mapped)

### 2.3 — Per-hit decompile pull
- For each unique hit function, run `DecompileFunction.java` headlessly
- Attach decompiled pseudocode to the enriched hit record
- Cache by ghidra_addr so repeated runs don't re-decompile
- Status: ⬜ Pending; blocked locally until the configured OpenJDK stops crashing under headless validation

### 2.4 — Xref context
- For each hit function, pull callers and callees from `function_inventory.json`
- Attach top-5 callers / callees to hit record
- Status: ✅ Implemented from function inventory caller/callee counts and sampled references

### 2.5 — Output + auto-apply
- Writes `lldb_trace_<timestamp>_enriched.json`
- Optionally calls `ghidra_apply_finding` for each hit (comment = "Observed at runtime, N hits, concrete class: X")
- Shell + Python only, no new Java
- Status: ✅ Enriched JSON output implemented; ⬜ auto-apply still pending

---

## Phase 3 — Small function classification (`ghidra_classify_small_functions`)
*Reduce unnamed FUN_* noise from 9,760 to near zero.*

**Gap:** 9,760 unnamed functions remain; 5,826 are ≤64 bytes. These are classifiable in bulk without decompiling.

### 3.1 — Classifier design (heuristics)
```
zero callers + single ret/b → dead_stub
calls only swift_retain/release + short → arc_helper → mark inline
single BL + ret → callwrap (embed callee name)
single branch to auth stub → authstub_alias
calls objc_msgSend + no other callers → objc_trampoline
4 instructions, no calls, reads/writes one global → loadglobal
```

### 3.2 — New Java script: `ClassifySmallFunctions.java`
- Iterates all `FUN_*` functions ≤ N bytes (configurable, default 64)
- Applies heuristics using Ghidra's instruction/reference APIs
- Renames to `classified$<category>$<address>` or inlines where appropriate
- Outputs classification report JSON
- Operates as pass after `ResolveSwiftOutlined.java` (complements it, doesn't replace)
- Status: ⬜ Pending; blocked until the Java/headless Ghidra runtime is fixed and validated

### 3.3 — Shell wrapper: `ghidra_classify_small_functions`
```bash
scripts/ghidra_classify_small_functions <project_name> <program_name> \
  [max_bytes=64] [dry_run=true] [categories=arc_helper,callwrap,...]
```

---

## Phase 4 — XPC topology mapper
*Make the inter-process architecture visible.*

**Gap:** We discovered BSR only by watching CPU. The full IPC topology — which processes talk to which, over which XPC interfaces, exchanging which message types — is completely invisible.

### 4.1 — Static XPC surface extractor
- New Java script: `ExportXPCSurface.java`
- Finds: `NSXPCInterface interfaceWithProtocol:`, `NSXPCConnection alloc/init`, service name strings in `__cstring`
- Exports: XPC endpoint names, protocol names, connection setup functions
- Correlates with ObjC protocol list to find the actual method signatures
- Status: ✅ Python-first extractor implemented and validated from existing `objc_metadata.json`, `strings.json`, and `symbols.json`; emits `xpc_surface.json` and `xpc_surface.md`. ⬜ Java instruction-level correlation remains pending.

### 4.2 — Shell wrapper + live trace
- `ghidra_xpc_surface <project_name> <program_name>` — static pass
- `ghidra_xpc_trace` — LLDB trace targeting `NSXPCConnection` init + `invokeSelector:withArguments:` for live message capture
- Status: ✅ `ghidra_xpc_surface` wrapper implemented and validated. ⬜ `ghidra_xpc_trace` live message capture pending.

### 4.3 — IPC graph
- Combine outputs across multiple analyzed binaries (shortcutsd, SVS, BSR, siriactionsd)
- Render as adjacency map: `{ "BackgroundShortcutRunner": { "connects_to": ["shortcutsd"], "receives_from": ["ShortcutsViewService"] } }`
- Status: ✅ Initial graph merger implemented and validated on WorkflowKit + BackgroundShortcutRunner. It auto-builds missing `xpc_surface.json` reports and infers service ownership edges, including WorkflowKit → BackgroundShortcutRunner via `com.apple.shortcuts.background-shortcut-runner`. ⬜ Richer multi-target adjacency and message-type mapping remain pending.

---

## Phase 5 — Differential binary analysis
*Find what changed between versions.*

**Gap:** No way to compare two binary versions. Critical for patch analysis and finding regression vulns.

### 5.1 — Function fingerprinting
- Hash each function by: instruction mnemonic sequence (no operands) — captures structure without ASLR sensitivity
- Store in `function_fingerprints.json` alongside normal export
- Status: ⬜ Pending; requires a Java export pass once local headless Ghidra/JDK validation is usable

### 5.2 — `ghidra_diff <project_a> <program_a> <project_b> <program_b>`
- Aligns functions by name (exact match), then by fingerprint similarity
- Outputs: added, removed, modified functions with before/after decompile for modified ones
- Highlights functions whose xref graph changed (new callers/callees)
- Status: ✅ Structural diff implemented and validated from existing `function_inventory.json` exports; duplicate function names are preserved and disambiguated by entry or structural metadata. ⬜ Fingerprint similarity and before/after decompile attachment remain pending.

### 5.3 — Patch analysis report
- Classify diffs: security-relevant (new validation, removed check, new sanitizer) vs structural (refactor, rename)
- Heuristics: removed bounds check → flag, added error return path → flag, new ObjC method on existing class → flag
- Status: ✅ Basic patch-relevance scoring implemented for name terms, body-size deltas, callee-count changes, and interface changes. ⬜ Full semantic patch classification remains pending.

---

## Phase 6 — Frida integration
*Higher-capability dynamic analysis for SIP-protected processes and production binaries.*

**Gap:** LLDB requires `ptrace` and works only on processes with `get-task-allow`. Frida's gadget/injection model sidesteps this for system frameworks and can read argument values with full ObjC runtime context.

### 6.1 — `ghidra_frida_trace`
- Analogous interface to `ghidra_lldb_trace`
- Generates a Frida script from symbols list
- Uses `ObjC.classes[className][selector].implementation` interception
- Reads argument values as ObjC objects with `.toString()` — actual content, not heap pointers
- Outputs same `lldb_trace_*.json` schema for compatibility with `ghidra_lldb_enrich`

### 6.2 — Heap enumeration
- `ghidra_frida_heap_scan <class_name>` — find all live instances of a class
- Useful for finding WFAction subclass instances during shortcut execution

### 6.3 — Return value modification
- `capture_returns=true` option in frida trace
- Enable fuzzing of specific arguments by intercepting and swapping values

---

## Phase 7 — Harness generation
*Synthesis: turn observations into testable code.*

**Gap:** We find the call chain, observe the arguments, understand the types — but there's no step that produces runnable code exercising the target.

### 7.1 — `ghidra_generate_harness`
- Input: function name or address + enriched trace JSON
- Output: Swift/ObjC `.swift` or `.m` file that:
  - Imports the right framework
  - Allocates the observed input types
  - Calls the target function with fuzzable stubs for arguments
  - Logs outputs to a known location
- Status: ✅ Implemented and validated from enriched WorkflowKit trace. Generates compilable Objective-C and Swift harness skeletons, preserves observed register pointers, loads the target framework, and leaves the actual call commented until valid domain objects are supplied.

### 7.2 — XPC harness variant
- For XPC-exposed surfaces: generate an `NSXPCConnection` client that calls the discovered interface methods
- Uses XPC surface map from Phase 4
- Status: ⬜ Pending; depends on Phase 4 XPC surface map

---

## Phase 8 — Bridge hardening and next-roadmap handoff
*Final stage of this roadmap: fix the Java-dependent block, validate the bridges, then create the next roadmap as a direct continuation of this one.*

**Gap:** The current roadmap reaches static/dynamic connection and harness generation, but the bridge layer still needs hardening before it can become the foundation for the next development cycle. The next roadmap should not be treated as a separate project; it should be the second-stage continuation of this roadmap after the initial bridge foundation is validated.

### 8.1 — Fix the Java/headless Ghidra block
- Resolve the current Java-dependent blocker where local OpenJDK 21 crashes with SIGBUS even on `java -version`
- Make sure the Java block is fixed before treating this roadmap as complete
- Re-test every Java-backed pass that is currently blocked, pending, or only partially validated:
  - `DecompileFunction.java`
  - `ClassifySmallFunctions.java`
  - `ExportXPCSurface.java`
  - Java-backed function fingerprint exports for `ghidra_diff`
  - Any other headless Ghidra export/decompile scripts used by the skill
- Confirm Java/headless validation works on at least one small known-good binary before re-running it against WorkflowKit-scale targets
- Status: ⬜ Pending; required final gate for Java-dependent phases

### 8.2 — Extensive live bridge use-case testing
- Extensively test the live bridge before creating the next roadmap
- Validate LLDB and Frida trace flows against realistic RE workflows, not only narrow success cases
- Test live bridge behavior across:
  - ObjC method tracing
  - Swift/ObjC mixed call chains
  - XPC connection setup
  - argument capture
  - return capture
  - process attach timing
  - timeout/failure handling
  - repeated traces across the same target
- Confirm live bridge output is stable enough to feed directly into enrichment, harness generation, and future automation
- Status: ⬜ Pending

### 8.3 — Extensive headless bridge use-case testing
- Extensively test the headless bridge before creating the next roadmap
- Validate Ghidra headless scripts, exports, enrichment, decompile pulling, classification, XPC surface extraction, and diff-related exports across realistic targets
- Test headless bridge behavior across:
  - small test binaries
  - WorkflowKit-scale binaries
  - ObjC-heavy binaries
  - Swift-heavy binaries
  - framework binaries
  - app/executable binaries
  - partial or malformed export bundles
  - repeated runs over the same project
- Confirm headless outputs are consistent, cacheable, debuggable, and compatible with the live bridge output schema
- Status: ⬜ Pending

### 8.4 — Bridge consistency check
- Compare live bridge and headless bridge outputs for the same target and workflow
- Confirm that runtime PCs, static addresses, slide computation, symbol names, class names, selectors, xrefs, and decompiled context line up correctly
- Add regression fixtures for known-good traces and exports so future changes do not silently break the bridge
- Status: ⬜ Pending

### 8.5 — Create the next development roadmap
- Create a second development roadmap only after the live bridge and headless bridge have been use-case tested extensively
- Make it explicit that the second roadmap is part of this roadmap’s continuation, not a separate or unrelated plan
- The next roadmap should start from the validated end state of this roadmap:
  - live bridge tested
  - headless bridge tested
  - Java/headless block fixed
  - harness generation validated
  - unresolved items carried forward intentionally
- The next roadmap should define the next layer of development: deeper automation, higher-level RE workflows, improved patch analysis, fuzzing/harness iteration, and analyst-facing UX
- Status: ⬜ Pending; depends on Phase 8.1–8.4

### 8.6 — Continue development on the new roadmap
- After creating the next roadmap, continue implementation work on that new roadmap
- Carry forward deferred work, unresolved blockers, bridge test findings, and stretch goals from this roadmap
- Keep the same living-document style: update status inline as development progresses
- Status: ⬜ Pending; begins after Phase 8.5

---

## Implementation Order

```
Phase 0  →  Phase 1.2 (isa_map)  →  Phase 1.1 + 1.3  →  Phase 2  →  Phase 3
                                                                          ↓
                                                               Phase 4  →  Phase 5
                                                                          ↓
                                                               Phase 6  →  Phase 7
                                                                          ↓
                                                               Phase 8  →  Next roadmap
                                                                          ↓
                                                        Continue development on next roadmap
```

Phases 4–7 are independent of 2–3 and can be interleaved based on user need.

Phase 8 is the final gate for this roadmap. It must happen before the next roadmap is created. In particular, the live bridge and headless bridge should be use-case tested extensively before creating the next roadmap, and the next roadmap should be explicitly treated as the continuation of this roadmap. If you were told to finish this roadmap, that includes creating AND completing this continuation.

---

## File inventory (scripts to create/modify)

| Script | Action | Phase |
|--------|--------|-------|
| `ghidra_lldb_trace` | ✅ Built for `capture_objc_class` + `capture_objc_args`; ⬜ live validation pending; needs broader live bridge use-case testing | 0, 1, 8.2 |
| `ghidra_build_isa_map` | ✅ Built, ⬜ Runtime-consumer integration pending | 1.2 |
| `ghidra_lldb_enrich` | ✅ Built and validated for slide + hit enrichment; ⬜ decompile/auto-apply pending; needs bridge consistency testing | 2, 8.4 |
| `ghidra_scripts/DecompileFunction.java` | Existing Java dependency; ⬜ must be re-tested after Java/headless block is fixed | 2.3, 8.1 |
| `ghidra_scripts/ClassifySmallFunctions.java` | **New** Java; ⬜ blocked until Java/headless validation works | 3.2, 8.1 |
| `ghidra_classify_small_functions` | **New** shell wrapper | 3.3 |
| `ghidra_scripts/ExportXPCSurface.java` | **New** Java; ⬜ blocked until Java/headless validation works | 4.1, 8.1 |
| `ghidra_xpc_surface` | ✅ Built and validated for Python-first XPC surface reports from existing exports; ⬜ Java correlation pending | 4.2 |
| `ghidra_xpc_graph` | ✅ Built and validated for coarse service ownership edges across XPC surface reports; ⬜ richer IPC graph semantics pending | 4.3 |
| `ghidra_xpc_trace` | **New** shell + LLDB; ⬜ needs live bridge use-case testing | 4.2, 8.2 |
| `ghidra_diff` | ✅ Built and validated for structural function-inventory diffing; ⬜ mnemonic fingerprints/decompile comparison pending | 5.2 |
| Java-backed function fingerprint export | **New/modify export pass**; ⬜ blocked until Java/headless validation works | 5.1, 8.1 |
| `ghidra_frida_trace` | **New** shell + JS; ⬜ needs live bridge use-case testing | 6.1, 8.2 |
| `ghidra_frida_heap_scan` | **New** shell + JS; ⬜ needs live bridge use-case testing | 6.2, 8.2 |
| `ghidra_generate_harness` | ✅ Built and validated for Swift/Objective-C skeleton generation from enriched traces; ⬜ XPC variant pending | 7.1 |
| Bridge regression fixtures | **New** trace/export fixtures for live/headless consistency checks | 8.4 |
| Next development roadmap | **New** living roadmap document; must be created as the continuation of this roadmap | 8.5 |

---

## Current status

- **Active:** Phase 4.3 coarse IPC graph milestone; Phase 2 decompile/auto-apply and Phase 0 live ObjC validation remain open
- **Next:** Add live XPC tracing and richer message-type mapping; fix the Java/headless Ghidra block before the final Phase 8 gate
- **Final roadmap gate:** The next development roadmap should only be created after extensive live bridge and headless bridge use-case testing. That next roadmap is part of this roadmap’s continuation, not a separate effort.
- **Blocked:** Headless Ghidra validation is currently blocked by local OpenJDK 21 crashing with SIGBUS even on `java -version`

---

## Decisions log

| Date | Decision | Reason |
|------|----------|--------|
| 2026-04-12 | Use memory-read for isa resolution, not `EvaluateExpression` | EvaluateExpression in BP handlers causes LLDB re-entry issues |
| 2026-04-12 | `ghidra_lldb_enrich` before `classify_small_functions` | Enrich closes the dynamic/static gap which informs what small functions are actually interesting |
| 2026-04-12 | Phase 4 (XPC) before Phase 5 (diff) | XPC discovery is architectural — more sessions will need it; diff is more situational |
| 2026-04-12 | Frida deferred to Phase 6 | LLDB is working for BSR (get-task-allow present); Frida setup cost only justified when SIP blocks LLDB |
| 2026-04-24 | Prefer function-inventory slide candidates when they map more hits than LLDB symbol candidates | Existing WorkflowKit artifacts have LLDB symbol and Ghidra inventory address bases that differ; scoring by mapped hit count produces the usable slide. |
| 2026-04-24 | Implement Phase 5 diffing over existing function inventories before adding Java fingerprints | Local Java crashes block new headless Ghidra export passes, but existing JSON exports are sufficient for a useful structural diff milestone. |
| 2026-04-24 | Generate safe harness skeletons rather than auto-invoking private APIs | Enriched traces preserve observed pointers, but valid object construction is target-specific; generated calls stay commented until the analyst supplies safe fixtures. |
| 2026-04-24 | Add Phase 8 as the bridge-hardening and next-roadmap handoff stage | The current roadmap should end by fixing the Java block, extensively testing live/headless bridge use cases, then creating the next roadmap as a direct continuation of this one. |
| 2026-04-24 | Add a Python-first XPC surface pass before the planned Java extractor | Existing ObjC/string/symbol exports already expose useful XPC classes, services, protocols, and listener methods while Java headless validation remains blocked. |
| 2026-04-24 | Require full program-token matches for inferred XPC service ownership | Partial token matches over-link generic Shortcuts services; full-token matching correctly maps `com.apple.shortcuts.background-shortcut-runner` to BackgroundShortcutRunner without assigning unrelated services. |
