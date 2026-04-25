"""Enrich LLDB runtime traces with static Ghidra export context."""

from __future__ import annotations

import bisect
import json
from collections import Counter
from pathlib import Path
from typing import Any

from ghidra_re_skill.core.config import cfg


def enrich_lldb_trace(
    project: str,
    program: str,
    trace_path: str | Path,
    function_inventory_path: str | Path | None = None,
    lldb_symbols_path: str | Path | None = None,
    output: str | Path | None = None,
    known_runtime_pc: str | None = None,
    known_static_addr: str | None = None,
) -> dict[str, Any]:
    """Annotate an LLDB trace with Ghidra addresses and function metadata."""
    export_dir = cfg.export_dir(project, program)
    trace_file = Path(trace_path)
    inv_path = (
        Path(function_inventory_path)
        if function_inventory_path
        else export_dir / "function_inventory.json"
    )
    symbols_path = (
        Path(lldb_symbols_path)
        if lldb_symbols_path
        else export_dir / "lldb_symbols.json"
    )
    out_path = Path(output) if output else trace_file.with_name(f"{trace_file.stem}_enriched.json")

    trace = _load_required_json(trace_file, "LLDB trace")
    inventory = _load_required_json(inv_path, "function inventory")
    lldb_symbols = _load_json(symbols_path)

    hits = trace.get("hits", [])
    if not isinstance(hits, list):
        raise RuntimeError(f"trace hits must be a list: {trace_file}")

    functions = _normalise_functions(inventory.get("functions", []))
    function_index = _FunctionIndex(functions)
    symbol_index = _build_symbol_index(lldb_symbols)
    function_symbol_index = _build_function_symbol_index(functions)

    slide_info = _compute_slide(
        hits=hits,
        symbol_index=symbol_index,
        function_symbol_index=function_symbol_index,
        function_index=function_index,
        known_runtime_pc=known_runtime_pc,
        known_static_addr=known_static_addr,
    )
    slide = slide_info.get("slide")

    enriched_hits = []
    matched_functions = 0
    for hit in hits:
        enriched = dict(hit)
        runtime_pc = _parse_int(hit.get("pc"))
        if runtime_pc is not None:
            enriched["runtime_pc"] = _hex(runtime_pc)
        if runtime_pc is not None and isinstance(slide, int):
            ghidra_addr = runtime_pc - slide
            enriched["ghidra_addr"] = _hex(ghidra_addr)
            func = function_index.find(ghidra_addr)
            if func:
                matched_functions += 1
                enriched["ghidra_function"] = _function_summary(func)
                enriched["xref_context"] = _xref_context(func)
        enriched_hits.append(enriched)

    result = dict(trace)
    result.update(
        {
            "enriched": True,
            "enrichment": {
                "project": project,
                "program": program,
                "trace": str(trace_file),
                "function_inventory": str(inv_path),
                "lldb_symbols": str(symbols_path) if symbols_path.exists() else None,
                "slide": _hex(slide) if isinstance(slide, int) else None,
                "slide_confidence": slide_info.get("confidence", "none"),
                "slide_evidence": slide_info.get("evidence", []),
                "hit_count": len(hits),
                "matched_function_count": matched_functions,
            },
            "hits": enriched_hits,
        }
    )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    return {
        "ok": True,
        "output": str(out_path),
        "hit_count": len(hits),
        "matched_function_count": matched_functions,
        "slide": _hex(slide) if isinstance(slide, int) else None,
        "slide_confidence": slide_info.get("confidence", "none"),
    }


class _FunctionIndex:
    def __init__(self, functions: list[dict[str, Any]]) -> None:
        self.functions = sorted(functions, key=lambda f: f["_entry_int"])
        self.entries = [f["_entry_int"] for f in self.functions]

    def find(self, addr: int) -> dict[str, Any] | None:
        idx = bisect.bisect_right(self.entries, addr) - 1
        if idx < 0:
            return None
        func = self.functions[idx]
        entry = func["_entry_int"]
        size = max(int(func.get("body_size") or 0), 1)
        if entry <= addr < entry + size:
            return func
        if addr == entry:
            return func
        return None


def _compute_slide(
    hits: list[dict[str, Any]],
    symbol_index: dict[str, list[dict[str, Any]]],
    function_symbol_index: dict[str, list[dict[str, Any]]],
    function_index: _FunctionIndex,
    known_runtime_pc: str | None,
    known_static_addr: str | None,
) -> dict[str, Any]:
    if known_runtime_pc and known_static_addr:
        runtime = _parse_int(known_runtime_pc)
        static = _parse_int(known_static_addr)
        if runtime is None or static is None:
            raise RuntimeError("known runtime/static addresses must be hex or decimal integers")
        return {
            "slide": runtime - static,
            "confidence": "manual",
            "evidence": [{"runtime_pc": _hex(runtime), "static_addr": _hex(static), "source": "manual"}],
        }

    candidates: list[tuple[int, dict[str, Any]]] = []
    for hit in hits:
        runtime_pc = _parse_int(hit.get("pc"))
        symbol = hit.get("symbol")
        if runtime_pc is None or not symbol:
            continue
        for entry in symbol_index.get(str(symbol), []):
            static_addr = _parse_int(entry.get("address"))
            if static_addr is None:
                continue
            candidates.append(
                (
                    runtime_pc - static_addr,
                    {
                        "symbol": symbol,
                        "runtime_pc": _hex(runtime_pc),
                        "static_addr": _hex(static_addr),
                        "source": "lldb_symbols",
                    },
                )
            )
        for key in _name_keys(str(symbol)):
            for entry in function_symbol_index.get(key, []):
                static_addr = _parse_int(entry.get("entry") or entry.get("address"))
                if static_addr is None:
                    continue
                candidates.append(
                    (
                        runtime_pc - static_addr,
                        {
                            "symbol": symbol,
                            "runtime_pc": _hex(runtime_pc),
                            "static_addr": _hex(static_addr),
                            "source": "function_inventory",
                        },
                    )
                )

    if not candidates:
        return {"slide": None, "confidence": "none", "evidence": []}

    counts = Counter(slide for slide, _ in candidates)
    slide_scores = []
    runtime_pcs = [_parse_int(hit.get("pc")) for hit in hits]
    runtime_pcs = [pc for pc in runtime_pcs if pc is not None]
    for candidate_slide, count in counts.items():
        mapped = sum(
            1 for pc in runtime_pcs
            if function_index.find(pc - candidate_slide) is not None
        )
        slide_scores.append((mapped, count, candidate_slide))
    mapped_count, count, slide = max(slide_scores)
    evidence = [item for candidate_slide, item in candidates if candidate_slide == slide][:10]
    confidence = "high" if mapped_count >= 2 else "medium" if count >= 1 else "low"
    return {
        "slide": slide,
        "confidence": confidence,
        "evidence": evidence,
        "mapped_hit_count": mapped_count,
    }


def _build_symbol_index(payload: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    index: dict[str, list[dict[str, Any]]] = {}
    for bucket in (
        "objc_methods",
        "trampolines",
        "outlined",
        "swift",
        "other_code",
        "data",
        "objc_classes",
    ):
        for item in payload.get(bucket, []) if isinstance(payload.get(bucket), list) else []:
            name = item.get("name")
            if name:
                index.setdefault(str(name), []).append(item)
    return index


def _build_function_symbol_index(functions: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    index: dict[str, list[dict[str, Any]]] = {}
    for func in functions:
        for key in _name_keys(str(func.get("name") or "")):
            index.setdefault(key, []).append(func)
    return index


def _name_keys(name: str) -> set[str]:
    keys = {name}
    if name.startswith(("-[", "+[")) and " " in name:
        prefix, rest = name.split(" ", 1)
        keys.add(f"{prefix}_{rest}")
    if name.startswith(("-[", "+[")) and "_" in name and " " not in name:
        marker = name.find("_")
        if marker > 0:
            keys.add(name[:marker] + " " + name[marker + 1:])
    return {key for key in keys if key}


def _normalise_functions(functions: Any) -> list[dict[str, Any]]:
    normalised = []
    if not isinstance(functions, list):
        return normalised
    for func in functions:
        if not isinstance(func, dict):
            continue
        entry = _parse_int(func.get("entry") or func.get("address"))
        if entry is None:
            continue
        item = dict(func)
        item["_entry_int"] = entry
        normalised.append(item)
    return normalised


def _function_summary(func: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "name",
        "entry",
        "namespace",
        "signature",
        "body_size",
        "caller_count",
        "callee_count",
        "artifact_type",
        "block",
        "is_thunk",
        "is_external",
        "is_inline",
    )
    return {key: func.get(key) for key in keys if key in func}


def _xref_context(func: dict[str, Any]) -> dict[str, Any]:
    refs = func.get("sample_xrefs", [])
    if not isinstance(refs, list):
        refs = []
    callers = []
    references = []
    for ref in refs[:20]:
        if not isinstance(ref, dict):
            continue
        ref_summary = {
            "from_address": ref.get("from_address"),
            "from_function": ref.get("from_function"),
            "ref_type": ref.get("ref_type"),
        }
        references.append(ref_summary)
        if ref.get("from_function"):
            callers.append(ref_summary)
    return {
        "caller_count": func.get("caller_count", 0),
        "callee_count": func.get("callee_count", 0),
        "sample_callers": callers[:5],
        "sample_references": references[:5],
    }


def _load_required_json(path: Path, label: str) -> dict[str, Any]:
    if not path.exists():
        raise RuntimeError(f"missing {label}: {path}")
    return _load_json(path)


def _load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RuntimeError(f"failed to parse JSON at {path}: {exc}") from exc


def _parse_int(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if not text:
        return None
    if text.startswith("0x") or text.startswith("0X"):
        try:
            return int(text, 16)
        except ValueError:
            return None
    try:
        return int(text, 16)
    except ValueError:
        try:
            return int(text, 10)
        except ValueError:
            return None


def _hex(value: int | None) -> str | None:
    return None if value is None else f"0x{value:x}"
