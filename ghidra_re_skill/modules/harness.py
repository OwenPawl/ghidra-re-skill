"""Generate source harnesses from enriched runtime traces."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


def generate_harness(
    trace_path: str | Path,
    target: str | None = None,
    language: str = "auto",
    output: str | Path | None = None,
    framework: str | None = None,
    bundle_path: str | None = None,
) -> dict[str, Any]:
    """Generate a Swift or Objective-C harness from an enriched LLDB trace."""
    trace_file = Path(trace_path)
    trace = _load_required_json(trace_file, "enriched trace")
    hits = trace.get("hits", [])
    if not isinstance(hits, list) or not hits:
        raise RuntimeError(f"trace has no hits: {trace_file}")

    selected = _select_hit(hits, target)
    symbol = _target_symbol(selected)
    objc = _parse_objc_symbol(symbol)
    project = str(trace.get("project") or trace.get("enrichment", {}).get("project") or "")
    program = str(trace.get("program") or trace.get("enrichment", {}).get("program") or "")
    framework_name = framework or program or _framework_from_symbol(symbol) or "TargetFramework"
    resolved_bundle = bundle_path or f"/System/Library/PrivateFrameworks/{framework_name}.framework"
    selected_language = _select_language(language, objc)
    out_path = Path(output) if output else trace_file.with_name(f"{trace_file.stem}_harness.{_extension(selected_language)}")

    if selected_language == "objc":
        source = _render_objc_harness(
            project=project,
            program=program,
            framework=framework_name,
            bundle_path=resolved_bundle,
            hit=selected,
            symbol=symbol,
            objc=objc,
        )
    else:
        source = _render_swift_harness(
            project=project,
            program=program,
            framework=framework_name,
            bundle_path=resolved_bundle,
            hit=selected,
            symbol=symbol,
            objc=objc,
        )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(source, encoding="utf-8")
    return {
        "ok": True,
        "output": str(out_path),
        "language": selected_language,
        "target": symbol,
        "project": project or None,
        "program": program or None,
        "framework": framework_name,
        "bundle_path": resolved_bundle,
        "ghidra_addr": selected.get("ghidra_addr"),
        "runtime_pc": selected.get("runtime_pc") or selected.get("pc"),
    }


def _select_hit(hits: list[Any], target: str | None) -> dict[str, Any]:
    dict_hits = [hit for hit in hits if isinstance(hit, dict)]
    if not dict_hits:
        raise RuntimeError("trace hits must contain objects")
    if not target:
        return next((hit for hit in dict_hits if hit.get("ghidra_function")), dict_hits[0])

    target_norm = target.lower()
    for hit in dict_hits:
        candidates = [
            hit.get("symbol"),
            hit.get("pc"),
            hit.get("runtime_pc"),
            hit.get("ghidra_addr"),
            (hit.get("ghidra_function") or {}).get("name") if isinstance(hit.get("ghidra_function"), dict) else None,
            (hit.get("ghidra_function") or {}).get("entry") if isinstance(hit.get("ghidra_function"), dict) else None,
        ]
        for candidate in candidates:
            if candidate is None:
                continue
            if target_norm in str(candidate).lower():
                return hit
    raise RuntimeError(f"target not found in trace hits: {target}")


def _select_language(language: str, objc: dict[str, Any] | None) -> str:
    lowered = language.lower()
    if lowered == "auto":
        return "objc" if objc else "swift"
    if lowered not in {"objc", "swift"}:
        raise RuntimeError("language must be one of: auto, objc, swift")
    return lowered


def _extension(language: str) -> str:
    return "m" if language == "objc" else "swift"


def _target_symbol(hit: dict[str, Any]) -> str:
    symbol = hit.get("symbol")
    if symbol:
        return str(symbol)
    func = hit.get("ghidra_function")
    if isinstance(func, dict) and func.get("name"):
        return str(func["name"])
    return str(hit.get("ghidra_addr") or hit.get("runtime_pc") or hit.get("pc") or "unknown_target")


def _parse_objc_symbol(symbol: str) -> dict[str, Any] | None:
    match = re.match(r"^([+-])\[([^ \]]+)[ _]([^\]]+)\]$", symbol)
    if not match:
        return None
    kind, class_name, selector = match.groups()
    return {
        "kind": kind,
        "class": class_name,
        "selector": selector,
        "is_class_method": kind == "+",
        "argument_count": selector.count(":"),
    }


def _framework_from_symbol(symbol: str) -> str | None:
    objc = _parse_objc_symbol(symbol)
    if objc:
        class_name = str(objc["class"])
        if class_name.startswith("WF"):
            return "WorkflowKit"
    return None


def _render_objc_harness(
    project: str,
    program: str,
    framework: str,
    bundle_path: str,
    hit: dict[str, Any],
    symbol: str,
    objc: dict[str, Any] | None,
) -> str:
    args = _argument_map(hit)
    target_class = str(objc["class"]) if objc else "TargetClass"
    selector = str(objc["selector"]) if objc else symbol
    arg_count = int(objc["argument_count"]) if objc else 0
    is_class_method = bool(objc and objc["is_class_method"])
    is_class_method_objc = "YES" if is_class_method else "NO"
    params = [_objc_param_name(i) for i in range(arg_count)]
    msgsend_args = ", ".join(["receiver", "selector", *params])
    typedef_args = ", ".join(["id", "SEL", *(["id"] * arg_count)])
    observed_lines = _objc_observed_lines(args)
    placeholder_lines = "\n".join(
        f'        id {name} = GhidraMakeFuzzableObject(@"{name}", {_objc_string(args.get(f"x{index + 2}"))});'
        for index, name in enumerate(params)
    )
    call_line = (
        f"        ((GhidraMsgSendFn)objc_msgSend)({msgsend_args});"
        if arg_count <= 6
        else "        // TODO: extend the objc_msgSend typedef for stack-passed arguments before calling."
    )

    return f"""// Generated by ghidra-re from an enriched LLDB trace.
// Project: {_comment_value(project)}
// Program: {_comment_value(program)}
// Target: {_comment_value(symbol)}
// Ghidra address: {_comment_value(hit.get("ghidra_addr"))}
// Runtime PC: {_comment_value(hit.get("runtime_pc") or hit.get("pc"))}

#import <Foundation/Foundation.h>
#import <objc/message.h>
#import <objc/runtime.h>

static id GhidraMakeFuzzableObject(NSString *label, NSString *observedPointer) {{
    NSLog(@"%@ observed pointer: %@", label, observedPointer ?: @"<none>");
    // Replace this placeholder with a concrete object, fixture, or fuzz case.
    return nil;
}}

int main(int argc, const char * argv[]) {{
    @autoreleasepool {{
        NSString *frameworkPath = @"{_objc_escape(bundle_path)}";
        NSBundle *bundle = [NSBundle bundleWithPath:frameworkPath];
        if (!bundle) {{
            NSLog(@"Framework bundle not found at %@", frameworkPath);
            return 2;
        }}
        if (bundle && !bundle.loaded && ![bundle load]) {{
            NSLog(@"Failed to load framework at %@", frameworkPath);
            return 2;
        }}

        Class targetClass = NSClassFromString(@"{_objc_escape(target_class)}");
        SEL selector = NSSelectorFromString(@"{_objc_escape(selector)}");
        BOOL isClassMethod = {is_class_method_objc};
        NSLog(@"Harness target: %@", @"{_objc_escape(symbol)}");
{observed_lines}

        id receiver = GhidraMakeFuzzableObject(@"receiver/self", {_objc_string(args.get("x0"))});
        if (!receiver && targetClass && !isClassMethod) {{
            // Many private-framework classes need domain-specific initialization.
            // Uncomment only when default init is safe for this target.
            // receiver = [[targetClass alloc] init];
        }}
        if (isClassMethod && targetClass) {{
            receiver = targetClass;
        }}
{placeholder_lines if placeholder_lines else "        // No ObjC selector arguments were inferred from the target symbol."}

        typedef void (*GhidraMsgSendFn)({typedef_args});
        // Safety default: the observed call is not invoked until placeholders above are replaced.
        // Uncomment after constructing valid receiver and argument objects:
        // {call_line.strip()}
    }}
    return 0;
}}
"""


def _render_swift_harness(
    project: str,
    program: str,
    framework: str,
    bundle_path: str,
    hit: dict[str, Any],
    symbol: str,
    objc: dict[str, Any] | None,
) -> str:
    args = _argument_map(hit)
    observed = "\n".join(
        f'print("{_swift_escape(register)} observed pointer: {_swift_escape(str(value))}")'
        for register, value in sorted(args.items())
    )
    if not observed:
        observed = 'print("No argument register snapshot was present in the trace.")'

    objc_block = ""
    if objc:
        objc_block = f"""
let targetClassName = "{_swift_escape(str(objc["class"]))}"
let selectorName = "{_swift_escape(str(objc["selector"]))}"
print("ObjC target: \\(targetClassName) \\(selectorName)")
// For multi-argument ObjC calls, prefer the generated Objective-C harness
// so objc_msgSend can be typed explicitly before enabling the call.
"""

    return f"""// Generated by ghidra-re from an enriched LLDB trace.
// Project: {_comment_value(project)}
// Program: {_comment_value(program)}
// Target: {_comment_value(symbol)}
// Ghidra address: {_comment_value(hit.get("ghidra_addr"))}
// Runtime PC: {_comment_value(hit.get("runtime_pc") or hit.get("pc"))}

import Darwin
import Foundation

let frameworkPath = "{_swift_escape(bundle_path)}"
guard let bundle = Bundle(path: frameworkPath) else {{
    print("Framework bundle not found at \\(frameworkPath)")
    exit(2)
}}
if !bundle.isLoaded && !bundle.load() {{
    print("Failed to load framework at \\(frameworkPath)")
    exit(2)
}}

let symbol = "{_swift_escape(symbol)}"
print("Harness target: \\(symbol)")
print("Framework: {_swift_escape(framework)}")
{observed}
{objc_block}
// TODO: bind the target to a concrete Swift/C function signature or switch to
// the Objective-C harness for selector-based invocation.
"""


def _argument_map(hit: dict[str, Any]) -> dict[str, str]:
    args = hit.get("args")
    if not isinstance(args, dict):
        args = hit.get("registers")
    if not isinstance(args, dict):
        return {}
    return {str(key): str(value) for key, value in args.items() if str(key).startswith("x")}


def _objc_observed_lines(args: dict[str, str]) -> str:
    if not args:
        return '        NSLog(@"No argument register snapshot was present in the trace.");'
    return "\n".join(
        f'        NSLog(@"{_objc_escape(register)} observed pointer: %@", {_objc_string(value)});'
        for register, value in sorted(args.items())
    )


def _objc_param_name(index: int) -> str:
    return f"arg{index}"


def _objc_string(value: str | None) -> str:
    if value is None:
        return "nil"
    return f'@"{_objc_escape(value)}"'


def _objc_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _swift_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _comment_value(value: Any) -> str:
    if value is None or value == "":
        return "<unknown>"
    return str(value)


def _load_required_json(path: Path, label: str) -> dict[str, Any]:
    if not path.exists():
        raise RuntimeError(f"missing {label}: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RuntimeError(f"failed to parse JSON at {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise RuntimeError(f"{label} must be a JSON object: {path}")
    return data
