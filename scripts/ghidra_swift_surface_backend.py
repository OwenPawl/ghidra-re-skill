#!/usr/bin/env python3

import json
import pathlib
import sys
from typing import Any, Dict, List, Optional


def load_json(path: str) -> Dict[str, Any]:
    file_path = pathlib.Path(path)
    if not file_path.is_file():
        return {}
    return json.loads(file_path.read_text(encoding="utf-8"))


def short_type_name(type_name: str) -> str:
    if not type_name:
        return ""
    return type_name.split(".")[-1]


def normalize(value: str) -> str:
    return "".join(ch for ch in value.lower() if ch.isalnum())


def unique_by_key(items: List[Dict[str, Any]], key: str) -> List[Dict[str, Any]]:
    seen = set()
    result = []
    for item in items:
        marker = (
            item.get(key)
            or item.get("canonical_address")
            or item.get("candidate_address")
            or item.get("address")
            or item.get("associated_type")
            or item.get("conforming_type")
            or json.dumps(item, sort_keys=True)
        )
        if marker in seen:
            continue
        seen.add(marker)
        result.append(item)
    return result


def valid_surface_type_name(type_name: str) -> bool:
    if not type_name:
        return False
    if any(token in type_name for token in ("-[", "+[", "block_invoke", "___", "swift_async_")):
        return False
    if any(ch in type_name for ch in (" ", "(", ")")):
        return False
    return True


def correlate_objc_classes(type_name: str, objc: Dict[str, Any]) -> List[str]:
    short_name = short_type_name(type_name)
    candidates = []
    for value in objc.get("classes", []):
        lowered = value.lower()
        if value == type_name or value == short_name or value == f"Swift{short_name}":
            candidates.append(value)
            continue
        if short_name and short_name.lower() in lowered:
            candidates.append(value)
    return sorted(dict.fromkeys(candidates), key=str.lower)


def related_strings(type_name: str, strings_doc: Dict[str, Any], limit: int = 20) -> List[Dict[str, Any]]:
    short_name = short_type_name(type_name)
    query_terms = [term for term in [type_name, short_name] if term]
    matches: List[Dict[str, Any]] = []
    for item in strings_doc.get("strings", []):
        value = item.get("value", "")
        if any(term.lower() in value.lower() for term in query_terms):
            matches.append(
                {
                    "address": item.get("address", ""),
                    "value": value,
                    "artifact_type": item.get("artifact_type", ""),
                    "metadata_group": item.get("metadata_group", ""),
                    "xref_count": item.get("xref_count", 0),
                }
            )
        if len(matches) >= limit:
            break
    return matches


def related_symbols(type_name: str, symbols_doc: Dict[str, Any], limit: int = 20) -> List[Dict[str, Any]]:
    short_name = short_type_name(type_name)
    query_terms = [term for term in [type_name, short_name] if term]
    matches: List[Dict[str, Any]] = []
    for item in symbols_doc.get("symbols", []):
        name = item.get("name", "")
        demangled = item.get("demangled", "")
        if any(term.lower() in name.lower() or term.lower() in demangled.lower() for term in query_terms):
            matches.append(
                {
                    "name": name,
                    "demangled": demangled,
                    "address": item.get("address", ""),
                    "artifact_type": item.get("artifact_type", ""),
                    "xref_count": item.get("xref_count", 0),
                }
            )
        if len(matches) >= limit:
            break
    return matches


def build_surface_types(swift: Dict[str, Any], objc: Dict[str, Any], symbols_doc: Dict[str, Any],
                        strings_doc: Dict[str, Any]) -> List[Dict[str, Any]]:
    grouped: Dict[str, Dict[str, Any]] = {}
    for type_name in swift.get("types", []):
        if not valid_surface_type_name(type_name):
            continue
        grouped.setdefault(
            type_name,
            {
                "type_name": type_name,
                "short_name": short_type_name(type_name),
                "methods": [],
                "properties": [],
                "async_methods": [],
                "dispatch_thunks": [],
                "metadata_accessors": [],
                "metadata_methods": [],
                "protocol_witnesses": [],
                "protocol_requirements": [],
                "associated_types": [],
                "associated_conformances": [],
                "code_candidates": [],
                "async_helpers": [],
                "init_methods": [],
                "deinit_methods": [],
                "start_methods": [],
                "raw_symbols": [],
                "protocol_conformances": [],
            },
        )
    for symbol in swift.get("symbols", []):
        type_name = symbol.get("type_name", "") or ""
        if not valid_surface_type_name(type_name):
            continue
        surface = grouped.setdefault(
            type_name,
            {
                "type_name": type_name,
                "short_name": short_type_name(type_name),
                "methods": [],
                "properties": [],
                "async_methods": [],
                "dispatch_thunks": [],
                "metadata_accessors": [],
                "metadata_methods": [],
                "protocol_witnesses": [],
                "protocol_requirements": [],
                "associated_types": [],
                "associated_conformances": [],
                "code_candidates": [],
                "async_helpers": [],
                "init_methods": [],
                "deinit_methods": [],
                "start_methods": [],
                "raw_symbols": [],
                "protocol_conformances": [],
            },
        )
        entry = {
            "name": symbol.get("name", ""),
            "demangled": symbol.get("demangled", ""),
            "display_name": symbol.get("display_name", ""),
            "address": symbol.get("address", ""),
            "canonical_address": symbol.get("canonical_address", symbol.get("thunk_target_address", symbol.get("address", ""))),
            "source": symbol.get("source", ""),
            "stable_alias": symbol.get("stable_alias", ""),
            "member_name": symbol.get("member_name", ""),
            "symbol_kind": symbol.get("symbol_kind", ""),
            "thunk": bool(symbol.get("thunk", False)),
            "thunk_target_name": symbol.get("thunk_target_name", ""),
            "thunk_target_address": symbol.get("thunk_target_address", ""),
        }
        surface["raw_symbols"].append(entry)
        kind = entry["symbol_kind"]
        member_name = entry["member_name"]
        if kind == "property_accessor":
            surface["properties"].append(entry)
        elif kind == "metadata_accessor":
            surface["metadata_accessors"].append(entry)
        elif kind == "protocol_witness":
            surface["protocol_witnesses"].append(entry)
        elif kind == "dispatch_thunk":
            surface["dispatch_thunks"].append(entry)
            surface["methods"].append(entry)
        else:
            surface["methods"].append(entry)
        if symbol.get("async_like"):
            surface["async_methods"].append(entry)
        if member_name.startswith("init(") or member_name.startswith("__allocating_init("):
            surface["init_methods"].append(entry)
        if member_name.startswith("deinit"):
            surface["deinit_methods"].append(entry)
        if member_name.startswith("start(") or member_name.startswith("start()"):
            surface["start_methods"].append(entry)

    for entry in swift.get("metadata_methods", []):
        type_name = entry.get("type_name", "") or ""
        if not valid_surface_type_name(type_name):
            continue
        surface = grouped.setdefault(
            type_name,
            {
                "type_name": type_name,
                "short_name": short_type_name(type_name),
                "methods": [],
                "properties": [],
                "async_methods": [],
                "dispatch_thunks": [],
                "metadata_accessors": [],
                "metadata_methods": [],
                "protocol_witnesses": [],
                "protocol_requirements": [],
                "associated_types": [],
                "associated_conformances": [],
                "code_candidates": [],
                "async_helpers": [],
                "init_methods": [],
                "deinit_methods": [],
                "start_methods": [],
                "raw_symbols": [],
                "protocol_conformances": [],
            },
        )
        record = {
            "name": entry.get("name", ""),
            "demangled": entry.get("demangled", ""),
            "display_name": entry.get("display_name", ""),
            "address": entry.get("address", ""),
            "canonical_address": entry.get("canonical_address", entry.get("address", "")),
            "source": entry.get("source", ""),
            "stable_alias": entry.get("stable_alias", ""),
            "member_name": entry.get("member_name", ""),
            "symbol_kind": entry.get("symbol_kind", ""),
            "artifact_role": entry.get("artifact_role", "metadata_method"),
            "implementation_chain": entry.get("implementation_chain", []),
        }
        surface["metadata_methods"].append(record)
        surface["methods"].append(record)
        member_name = record["member_name"]
        if member_name.startswith("init(") or member_name.startswith("__allocating_init("):
            surface["init_methods"].append(record)
        if member_name.startswith("deinit"):
            surface["deinit_methods"].append(record)
        if member_name.startswith("start(") or member_name.startswith("start()"):
            surface["start_methods"].append(record)

    for entry in swift.get("protocol_requirements", []):
        type_name = entry.get("type_name") or entry.get("protocol_name") or ""
        if not valid_surface_type_name(type_name):
            continue
        surface = grouped.setdefault(
            type_name,
            {
                "type_name": type_name,
                "short_name": short_type_name(type_name),
                "methods": [],
                "properties": [],
                "async_methods": [],
                "dispatch_thunks": [],
                "metadata_accessors": [],
                "metadata_methods": [],
                "protocol_witnesses": [],
                "protocol_requirements": [],
                "associated_types": [],
                "associated_conformances": [],
                "code_candidates": [],
                "async_helpers": [],
                "init_methods": [],
                "deinit_methods": [],
                "start_methods": [],
                "raw_symbols": [],
                "protocol_conformances": [],
            },
        )
        surface["protocol_requirements"].append(entry)
        if entry.get("kind") == "associated_type":
            surface["associated_types"].append(entry)

    for entry in swift.get("associated_conformances", []):
        type_name = entry.get("type_name") or entry.get("protocol_name") or ""
        if not valid_surface_type_name(type_name):
            continue
        surface = grouped.setdefault(
            type_name,
            {
                "type_name": type_name,
                "short_name": short_type_name(type_name),
                "methods": [],
                "properties": [],
                "async_methods": [],
                "dispatch_thunks": [],
                "metadata_accessors": [],
                "metadata_methods": [],
                "protocol_witnesses": [],
                "protocol_requirements": [],
                "associated_types": [],
                "associated_conformances": [],
                "code_candidates": [],
                "async_helpers": [],
                "init_methods": [],
                "deinit_methods": [],
                "start_methods": [],
                "raw_symbols": [],
                "protocol_conformances": [],
            },
        )
        surface["associated_conformances"].append(entry)

    for entry in swift.get("code_candidates", []):
        type_name = entry.get("type_name", "") or ""
        if not valid_surface_type_name(type_name):
            continue
        surface = grouped.setdefault(
            type_name,
            {
                "type_name": type_name,
                "short_name": short_type_name(type_name),
                "methods": [],
                "properties": [],
                "async_methods": [],
                "dispatch_thunks": [],
                "metadata_accessors": [],
                "metadata_methods": [],
                "protocol_witnesses": [],
                "protocol_requirements": [],
                "associated_types": [],
                "associated_conformances": [],
                "code_candidates": [],
                "async_helpers": [],
                "init_methods": [],
                "deinit_methods": [],
                "start_methods": [],
                "raw_symbols": [],
                "protocol_conformances": [],
            },
        )
        surface["code_candidates"].append(entry)
        for candidate in surface["code_candidates"]:
            if candidate.get("candidate_address") and not candidate.get("canonical_address"):
                candidate["canonical_address"] = candidate.get("candidate_address", "")
            if candidate.get("candidate_address") and not candidate.get("address"):
                candidate["address"] = candidate.get("candidate_address", "")

    for entry in swift.get("async_relationships", []):
        type_name = entry.get("type_name", "") or ""
        if not valid_surface_type_name(type_name):
            continue
        surface = grouped.setdefault(
            type_name,
            {
                "type_name": type_name,
                "short_name": short_type_name(type_name),
                "methods": [],
                "properties": [],
                "async_methods": [],
                "dispatch_thunks": [],
                "metadata_accessors": [],
                "metadata_methods": [],
                "protocol_witnesses": [],
                "protocol_requirements": [],
                "associated_types": [],
                "associated_conformances": [],
                "code_candidates": [],
                "async_helpers": [],
                "init_methods": [],
                "deinit_methods": [],
                "start_methods": [],
                "raw_symbols": [],
                "protocol_conformances": [],
            },
        )
        surface["async_helpers"].append(entry)

    conformance_hits = swift.get("protocol_conformances", [])
    for surface in grouped.values():
        type_name = surface["type_name"]
        surface["protocol_conformances"] = [
            value for value in conformance_hits if type_name in value or short_type_name(type_name) in value
        ]
        surface["objc_bridge_names"] = correlate_objc_classes(type_name, objc)
        surface["related_strings"] = related_strings(type_name, strings_doc)
        surface["related_symbols"] = related_symbols(type_name, symbols_doc)
        for key in [
            "methods",
            "properties",
            "async_methods",
            "dispatch_thunks",
            "metadata_accessors",
            "metadata_methods",
            "protocol_witnesses",
            "protocol_requirements",
            "associated_types",
            "associated_conformances",
            "code_candidates",
            "async_helpers",
            "init_methods",
            "deinit_methods",
            "start_methods",
            "raw_symbols",
        ]:
            surface[key] = unique_by_key(surface[key], "stable_alias")
        surface["summary"] = {
            "method_count": len(surface["methods"]),
            "property_count": len(surface["properties"]),
            "async_method_count": len(surface["async_methods"]),
            "dispatch_thunk_count": len(surface["dispatch_thunks"]),
            "metadata_method_count": len(surface["metadata_methods"]),
            "protocol_witness_count": len(surface["protocol_witnesses"]),
            "protocol_requirement_count": len(surface["protocol_requirements"]),
            "associated_type_count": len(surface["associated_types"]),
            "associated_conformance_count": len(surface["associated_conformances"]),
            "code_candidate_count": len(surface["code_candidates"]),
            "objc_bridge_count": len(surface["objc_bridge_names"]),
        }

    return sorted(grouped.values(), key=lambda item: item["type_name"].lower())


def find_surface(surfaces: List[Dict[str, Any]], query: str) -> Optional[Dict[str, Any]]:
    if not query:
        return None
    lowered = query.lower()
    exact = [surface for surface in surfaces if surface["type_name"].lower() == lowered or surface["short_name"].lower() == lowered]
    if exact:
        return exact[0]
    contains = [
        surface
        for surface in surfaces
        if lowered in surface["type_name"].lower()
        or lowered in surface["short_name"].lower()
        or any(lowered in candidate.lower() for candidate in surface.get("objc_bridge_names", []))
    ]
    return contains[0] if contains else None


def search_swift_surface(surfaces: List[Dict[str, Any]], query: str) -> Dict[str, Any]:
    lowered = query.lower()
    candidates: List[Dict[str, Any]] = []
    for surface in surfaces:
        type_name = surface["type_name"]
        short_name = surface["short_name"]
        type_score = 0
        if lowered == type_name.lower() or lowered == short_name.lower():
            type_score = 120
        elif lowered in type_name.lower() or lowered in short_name.lower():
            type_score = 70

        if type_score:
            candidates.append(
                {
                    "score": type_score,
                    "kind": "type",
                    "type_name": type_name,
                    "label": type_name,
                    "address": "",
                    "canonical_address": "",
                    "symbol": None,
                }
            )

        for bucket_name in [
            "methods",
            "properties",
            "async_methods",
            "dispatch_thunks",
            "metadata_accessors",
            "metadata_methods",
            "protocol_witnesses",
            "protocol_requirements",
            "associated_conformances",
            "code_candidates",
            "init_methods",
            "deinit_methods",
            "start_methods",
        ]:
            for entry in surface.get(bucket_name, []):
                labels = [
                    entry.get("stable_alias", ""),
                    entry.get("display_name", ""),
                    entry.get("demangled", ""),
                    entry.get("name", ""),
                    entry.get("associated_type", ""),
                    entry.get("conforming_type", ""),
                    entry.get("concrete_type", ""),
                    f"{type_name}.{entry.get('member_name', '')}",
                    f"{short_name}.{entry.get('member_name', '')}",
                ]
                labels = [label for label in labels if label]
                score = 0
                for label in labels:
                    label_lower = label.lower()
                    if lowered == label_lower:
                        score = max(score, 200)
                    elif label_lower.endswith("." + lowered):
                        score = max(score, 180)
                    elif lowered in label_lower:
                        score = max(score, 120)
                if score == 0:
                    continue
                if bucket_name == "dispatch_thunks" and entry.get("thunk_target_address"):
                    score += 10
                if bucket_name == "start_methods":
                    score += 15
                if bucket_name == "async_methods":
                    score += 8
                candidates.append(
                    {
                        "score": score,
                        "kind": bucket_name,
                        "type_name": type_name,
                        "label": entry.get("stable_alias") or entry.get("display_name") or entry.get("name") or entry.get("associated_type") or entry.get("conforming_type"),
                        "address": entry.get("address", entry.get("candidate_address", "")),
                        "canonical_address": entry.get("canonical_address", entry.get("candidate_address", entry.get("address", ""))),
                        "symbol": entry,
                    }
                )

    candidates.sort(
        key=lambda item: (
            -item["score"],
            item["type_name"].lower(),
            item["label"].lower(),
            item["canonical_address"],
        )
    )
    return {"query": query, "match_count": len(candidates), "matches": candidates[:50]}


def choose_live_entry(surface: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    for bucket in [
        "start_methods",
        "async_methods",
        "init_methods",
        "methods",
        "metadata_methods",
        "metadata_accessors",
        "dispatch_thunks",
        "code_candidates",
        "protocol_requirements",
        "associated_conformances",
        "associated_types",
        "related_symbols",
    ]:
        entries = surface.get(bucket, [])
        if entries:
            if bucket == "code_candidates":
                entries = sorted(
                    entries,
                    key=lambda entry: (
                        0 if entry.get("function_address") or entry.get("instruction_address") or entry.get("candidate_executable") else 1,
                        0 if entry.get("canonical_address") else 1,
                        entry.get("canonical_address", entry.get("candidate_address", entry.get("address", ""))),
                    ),
                )
            return entries[0]
    return None


def render_markdown(payload: Dict[str, Any]) -> str:
    lines = []
    query = payload.get("query", "")
    if query:
        lines.append(f"# Swift Surface Report: {query}")
    else:
        lines.append("# Swift Surface Report")
    for surface in payload.get("types", []):
        lines.append("")
        lines.append(f"## {surface['type_name']}")
        summary = surface.get("summary", {})
        lines.append(
            f"- methods: {summary.get('method_count', 0)}"
            f", properties: {summary.get('property_count', 0)}"
            f", async: {summary.get('async_method_count', 0)}"
            f", thunks: {summary.get('dispatch_thunk_count', 0)}"
            f", requirements: {summary.get('protocol_requirement_count', 0)}"
        )
        if surface.get("objc_bridge_names"):
            lines.append("- objc bridges: " + ", ".join(surface["objc_bridge_names"]))
        if surface.get("protocol_conformances"):
            lines.append("- conformances: " + ", ".join(surface["protocol_conformances"][:10]))
        if surface.get("associated_types"):
            lines.append("- associated types: " + ", ".join(
                entry.get("associated_type", "") for entry in surface["associated_types"][:10]
                if entry.get("associated_type", "")
            ))
        if surface.get("associated_conformances"):
            labels = []
            for entry in surface["associated_conformances"][:8]:
                conforming = entry.get("conforming_type", "")
                assoc = entry.get("associated_type", "")
                concrete = entry.get("concrete_type", "")
                parts = [part for part in [conforming, assoc, concrete] if part]
                if parts:
                    labels.append(" -> ".join(parts))
            if labels:
                lines.append("- associated conformances: " + ", ".join(labels))
        for bucket_name, title in [
            ("start_methods", "start"),
            ("async_methods", "async"),
            ("methods", "methods"),
            ("metadata_methods", "metadata methods"),
            ("properties", "properties"),
            ("dispatch_thunks", "dispatch thunks"),
            ("protocol_witnesses", "protocol witnesses"),
            ("protocol_requirements", "protocol requirements"),
            ("code_candidates", "code candidates"),
        ]:
            entries = surface.get(bucket_name, [])
            if not entries:
                continue
            lines.append(f"- {title}:")
            for entry in entries[:8]:
                label = (
                    entry.get("stable_alias")
                    or entry.get("display_name")
                    or entry.get("name")
                    or entry.get("associated_type")
                    or entry.get("conforming_type")
                )
                address = (
                    entry.get("canonical_address")
                    or entry.get("candidate_address")
                    or entry.get("address", "")
                )
                lines.append(f"  - {label} @ {address}")
    return "\n".join(lines).strip() + "\n"


def main() -> int:
    if len(sys.argv) < 7:
        print(
            "Usage: ghidra_swift_surface_backend.py <mode> <swift_json> <objc_json> <symbols_json> <strings_json> <query> [format]",
            file=sys.stderr,
        )
        return 1

    mode = sys.argv[1]
    swift = load_json(sys.argv[2])
    objc = load_json(sys.argv[3])
    symbols_doc = load_json(sys.argv[4])
    strings_doc = load_json(sys.argv[5])
    query = sys.argv[6]
    output_format = sys.argv[7] if len(sys.argv) > 7 else "json"

    surfaces = build_surface_types(swift, objc, symbols_doc, strings_doc)

    if mode == "report":
        types = surfaces if not query else [
            surface for surface in surfaces
            if query.lower() in surface["type_name"].lower()
            or query.lower() in surface["short_name"].lower()
            or any(query.lower() in value.lower() for value in surface.get("objc_bridge_names", []))
        ]
        payload = {
            "query": query,
            "type_count": len(types),
            "types": types,
            "alias_map": swift.get("alias_map", {}),
            "metadata_sections": swift.get("metadata_sections", {}),
        }
        if output_format == "markdown":
            print(render_markdown(payload))
        else:
            print(json.dumps(payload, indent=2))
        return 0

    if mode == "type":
        surface = find_surface(surfaces, query)
        payload = {
            "query": query,
            "type": surface,
            "selected_entry": choose_live_entry(surface) if surface else None,
        }
        print(json.dumps(payload, indent=2))
        return 0

    if mode == "search":
        payload = search_swift_surface(surfaces, query)
        print(json.dumps(payload, indent=2))
        return 0

    print(f"unsupported mode: {mode}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
