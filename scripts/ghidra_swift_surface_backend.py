#!/usr/bin/env python3

import json
import pathlib
import re
import sys
from typing import Any, Dict, List, Optional, Set

OBJC_METHOD_RE = re.compile(r"^([+-])\[(.+?) ([^\]]+)\]$")
OBJC_METHOD_BODY_RE = re.compile(r"^([+-])\[(.+)\]$")
CANONICAL_SWIFT_TYPE_RE = re.compile(
    r"(?:__C\.)?[A-Z][A-Za-z0-9_]*(?:\.[A-Z][A-Za-z0-9_]*)+"
)
PROPERTY_DESCRIPTOR_RE = re.compile(
    r"property_descriptor_for_(?:\(extension_in_[^)]+\):)?"
    r"(?P<type>(?:__C\.)?[A-Z][A-Za-z0-9_]*(?:\.[A-Z][A-Za-z0-9_]*)+)"
    r"\.(?P<property>[a-zA-Z_][A-Za-z0-9_]*)_"
)
CAMEL_CASE_TOKEN_RE = re.compile(
    r"[A-Z]+(?=[A-Z][a-z]|[0-9]|$)|[A-Z]?[a-z]+|[0-9]+"
)
GENERIC_SWIFT_TYPE_TOKENS = {
    "action",
    "cell",
    "configuration",
    "context",
    "controller",
    "coordinator",
    "delegate",
    "helper",
    "item",
    "manager",
    "model",
    "presenter",
    "provider",
    "service",
    "state",
    "style",
    "type",
    "view",
    "viewmodel",
}
PATH_LIKE_NAMESPACE_SEGMENTS = {
    "applications",
    "coreservices",
    "desktop",
    "library",
    "mobile",
    "privateframeworks",
    "system",
    "tmp",
    "users",
    "var",
}


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


def camel_case_tokens(value: str) -> List[str]:
    if not value:
        return []
    return [token.lower() for token in CAMEL_CASE_TOKEN_RE.findall(value) if token]


def empty_surface(type_name: str) -> Dict[str, Any]:
    return {
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
        "objc_bridge_methods": [],
        "objc_runtime_artifacts": [],
        "property_hints": [],
        "objc_bridge_names": [],
    }


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
    if type_name.startswith("_") and not type_name.startswith("__C."):
        return False
    if ".." in type_name:
        return False
    return True


def type_name_noise_penalty(type_name: str) -> int:
    penalty = 0
    segments = [segment for segment in type_name.split(".") if segment]
    if not segments:
        return 100
    short_segments = 0
    for segment in segments:
        if segment.startswith("_") and segment != "__C":
            penalty += 35
        if not re.match(r"^[A-Za-z][A-Za-z0-9_]*$", segment):
            penalty += 30
        if len(segment) <= 2:
            short_segments += 1
        if re.search(r"[0-9]_[0-9]|_[0-9]|[0-9]$", segment):
            penalty += 12
        if segment.lower() in PATH_LIKE_NAMESPACE_SEGMENTS:
            penalty += 25
    if short_segments >= 2:
        penalty += 20
    if len(type_name) < 3:
        penalty += 25
    if len(segments) >= 3 and sum(1 for segment in segments[:-1] if segment.lower() in PATH_LIKE_NAMESPACE_SEGMENTS) >= 1:
        penalty += 35
    return penalty


def parse_length_encoded_path(value: str, start: int = 0) -> str:
    parts: List[str] = []
    index = start
    while index < len(value) and value[index].isdigit():
        end = index
        while end < len(value) and value[end].isdigit():
            end += 1
        try:
            declared_length = int(value[index:end])
        except ValueError:
            break
        if declared_length <= 0 or end + declared_length > len(value):
            break
        part = value[end:end + declared_length]
        if not part or not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", part):
            break
        parts.append(part)
        index = end + declared_length
    if len(parts) >= 2:
        return ".".join(parts)
    return ""


def extract_type_candidates_from_text(text: str) -> List[str]:
    if not text:
        return []
    candidates = set()
    text = text.strip()
    for match in CANONICAL_SWIFT_TYPE_RE.finditer(text.replace("/", ".")):
        value = match.group(0).strip(".")
        if valid_surface_type_name(value):
            candidates.add(value)
    normalized = text.replace("_symbolic_", " ").replace("_symbolic ", " ").replace("/", ".")
    for index, ch in enumerate(normalized):
        if not ch.isdigit():
            continue
        value = parse_length_encoded_path(normalized, index)
        if valid_surface_type_name(value):
            candidates.add(value)
    return sorted(candidates, key=str.lower)


def parse_objc_method_name(name: str, known_classes=None) -> Optional[Dict[str, Any]]:
    if not name:
        return None
    match = OBJC_METHOD_RE.match(name)
    if not match:
        body_match = OBJC_METHOD_BODY_RE.match(name)
        if not body_match:
            return None
        kind, body = body_match.groups()
        class_name = ""
        selector = ""
        for candidate in sorted(known_classes or [], key=len, reverse=True):
            for separator in (" ", "_"):
                prefix = candidate + separator
                if body.startswith(prefix):
                    class_name = candidate
                    selector = body[len(prefix):]
                    break
            if class_name:
                break
        if not class_name and "_" in body:
            class_name, selector = body.split("_", 1)
        if not class_name or not selector:
            return None
    else:
        kind, class_name, selector = match.groups()
    return {
        "kind": kind,
        "class_name": class_name,
        "selector": selector,
    }


def recovered_type_candidates(*values: str) -> List[str]:
    candidates: List[str] = []
    seen: Set[str] = set()
    for value in values:
        for candidate in extract_type_candidates_from_text(value):
            if candidate in seen:
                continue
            seen.add(candidate)
            candidates.append(candidate)
    return candidates


def recovered_type_score(type_name: str) -> int:
    score = len(type_name)
    segments = [segment for segment in type_name.split(".") if segment]
    score += len(segments) * 10
    if type_name.startswith("__C."):
        score += 15
    score -= type_name_noise_penalty(type_name)
    return score


def recover_surface_type_name(entry: Dict[str, Any], fallback_type_name: str = "") -> str:
    existing = (entry.get("type_name", "") or fallback_type_name or "").strip()
    candidates = recovered_type_candidates(
        existing,
        entry.get("stable_alias", ""),
        entry.get("member_name", ""),
        entry.get("display_name", ""),
        entry.get("demangled", ""),
        entry.get("name", ""),
    )
    if existing and candidates:
        if not valid_surface_type_name(existing) or type_name_noise_penalty(existing) >= 35:
            return max(candidates, key=recovered_type_score)
        for candidate in candidates:
            if candidate == existing:
                return existing
            if candidate.endswith("." + existing) or candidate.endswith(".__C." + existing):
                return candidate
            if candidate.startswith(existing + ".") or candidate.startswith("__C." + existing + "."):
                return candidate
    if valid_surface_type_name(existing):
        return existing
    if candidates:
        return max(candidates, key=recovered_type_score)
    return existing


def significant_type_tokens(type_name: str) -> List[str]:
    tokens: List[str] = []
    segments = [segment for segment in type_name.replace("__C.", "").split(".") if segment]
    if len(segments) >= 2:
        segments = segments[1:]
    for segment in segments:
        for token in camel_case_tokens(segment):
            if len(token) < 3:
                continue
            if token in GENERIC_SWIFT_TYPE_TOKENS:
                continue
            tokens.append(token)
    return list(dict.fromkeys(tokens))


def correlate_objc_classes(type_name: str, objc: Dict[str, Any]) -> List[str]:
    short_name = short_type_name(type_name)
    candidates = []
    significant_tokens = significant_type_tokens(type_name)
    significant_signature = "".join(significant_tokens)
    short_name_generic = normalize(short_name) in GENERIC_SWIFT_TYPE_TOKENS
    for value in objc.get("classes", []):
        lowered = value.lower()
        normalized_value = normalize(value)
        normalized_short = normalize(short_name)
        normalized_type = normalize(type_name)
        if value == type_name or value == short_name or value == f"Swift{short_name}":
            candidates.append(value)
            continue
        if (
            significant_signature
            and len(significant_signature) >= 8
            and significant_signature in normalized_value
        ):
            candidates.append(value)
            continue
        if (
            significant_tokens
            and sum(1 for token in significant_tokens if token in normalized_value) >= min(2, len(significant_tokens))
        ):
            candidates.append(value)
            continue
        if (
            normalized_short
            and not short_name_generic
            and len(normalized_short) >= 6
            and normalized_short in normalized_value
        ):
            candidates.append(value)
            continue
        if normalized_type and normalized_type in normalized_value:
            candidates.append(value)
    return sorted(dict.fromkeys(candidates), key=str.lower)


def bridge_name_matches_surface(type_name: str, bridge_name: str) -> bool:
    if not bridge_name:
        return False
    short_name = short_type_name(type_name)
    normalized_bridge = normalize(bridge_name.replace("_OBJC_CLASS_$", "").replace("_OBJC_METACLASS_$", ""))
    normalized_type = normalize(type_name)
    normalized_short = normalize(short_name)
    significant_tokens = significant_type_tokens(type_name)
    significant_signature = "".join(significant_tokens)
    short_name_generic = normalized_short in GENERIC_SWIFT_TYPE_TOKENS
    if normalized_type and normalized_type in normalized_bridge:
        return True
    if (
        normalized_short
        and not short_name_generic
        and len(normalized_short) >= 6
        and normalized_short in normalized_bridge
    ):
        return True
    if (
        significant_signature
        and len(significant_signature) >= 8
        and significant_signature in normalized_bridge
    ):
        return True
    if significant_tokens and sum(1 for token in significant_tokens if token in normalized_bridge) >= min(2, len(significant_tokens)):
        return True
    return False


def associated_conformance_label(entry: Dict[str, Any]) -> str:
    leading = entry.get("conforming_type", "") or entry.get("type_name", "")
    middle = entry.get("associated_type", "") or entry.get("protocol_name", "")
    trailing = entry.get("concrete_type", "")
    if middle and normalize(middle) == normalize(leading):
        middle = ""
    if trailing and normalize(trailing) == normalize(middle or leading):
        trailing = ""
    parts = [part for part in [leading, middle, trailing] if part]
    return " -> ".join(parts)


def related_strings(type_name: str, strings_doc: Dict[str, Any], extra_terms=None,
                    limit: int = 20) -> List[Dict[str, Any]]:
    short_name = short_type_name(type_name)
    query_terms = [term for term in [type_name, short_name] + list(extra_terms or []) if term]
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


def related_symbols(type_name: str, symbols_doc: Dict[str, Any], extra_terms=None,
                    limit: int = 20,
                    symbol_indexes: Optional[Dict[str, Dict[str, List[Dict[str, Any]]]]] = None
                    ) -> List[Dict[str, Any]]:
    short_name = short_type_name(type_name)
    query_terms = [term for term in [type_name, short_name] + list(extra_terms or []) if term]
    matches: List[Dict[str, Any]] = []
    if symbol_indexes:
        items = []
        seen_items = set()
        for term in query_terms:
            for item in symbol_indexes.get("symbols_by_candidate", {}).get(term, []):
                marker = item.get("name", "") + "|" + item.get("address", "")
                if marker in seen_items:
                    continue
                seen_items.add(marker)
                items.append(item)
    else:
        items = symbols_doc.get("symbols", [])
    for item in items:
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


def build_symbol_indexes(objc: Dict[str, Any],
                         symbols_doc: Dict[str, Any]) -> Dict[str, Dict[str, List[Dict[str, Any]]]]:
    known_classes = set(objc.get("interface_classes", []) or [])
    known_classes.update(objc.get("classes", []))
    known_classes.update(objc.get("metaclasses", []))
    objc_methods_by_class: Dict[str, List[Dict[str, Any]]] = {}
    symbols_by_candidate: Dict[str, List[Dict[str, Any]]] = {}
    for item in symbols_doc.get("objc_related", []) + symbols_doc.get("symbols", []):
        text = " ".join(str(item.get(key, "")) for key in ["name", "demangled", "display_name"])
        for candidate in extract_type_candidates_from_text(text):
            symbols_by_candidate.setdefault(candidate, []).append(item)
            symbols_by_candidate.setdefault(short_type_name(candidate), []).append(item)
        parsed = parse_objc_method_name(item.get("name", ""), known_classes)
        if parsed:
            objc_methods_by_class.setdefault(parsed["class_name"], []).append(item)
    return {
        "objc_methods_by_class": objc_methods_by_class,
        "symbols_by_candidate": symbols_by_candidate,
    }


def inferred_surface_types(swift: Dict[str, Any], symbols_doc: Dict[str, Any],
                           strings_doc: Dict[str, Any]) -> List[str]:
    candidates = set()
    for type_name in swift.get("types", []):
        if valid_surface_type_name(type_name):
            candidates.add(type_name)
    for entry in swift.get("protocol_requirements", []):
        for value in [entry.get("type_name", ""), entry.get("protocol_name", "")]:
            if valid_surface_type_name(value):
                candidates.add(value)
    for entry in swift.get("associated_conformances", []):
        for value in [
            entry.get("type_name", ""),
            entry.get("protocol_name", ""),
            entry.get("conforming_type", ""),
            entry.get("concrete_type", ""),
        ]:
            if valid_surface_type_name(value):
                candidates.add(value)
    for entry in swift.get("symbols", []):
        for value in [entry.get("type_name", ""), entry.get("display_name", ""), entry.get("name", "")]:
            for candidate in extract_type_candidates_from_text(value):
                candidates.add(candidate)
    for collection in [symbols_doc.get("symbols", []), symbols_doc.get("objc_related", [])]:
        for entry in collection:
            for value in [entry.get("name", ""), entry.get("demangled", ""), entry.get("display_name", "")]:
                for candidate in extract_type_candidates_from_text(value):
                    candidates.add(candidate)
    for entry in strings_doc.get("strings", []):
        value = entry.get("value", "") or entry.get("string_value", "")
        for candidate in extract_type_candidates_from_text(value):
            candidates.add(candidate)
    for meta in swift.get("metadata_sections", {}).values():
        for key in ["demangled_strings", "strings"]:
            for value in meta.get(key, []):
                for candidate in extract_type_candidates_from_text(value):
                    candidates.add(candidate)
    return sorted(candidates, key=str.lower)


def objc_runtime_artifacts_for_type(type_name: str, objc: Dict[str, Any],
                                    symbols_doc: Dict[str, Any],
                                    bridge_names: List[str],
                                    symbol_indexes: Optional[Dict[str, Dict[str, List[Dict[str, Any]]]]] = None
                                    ) -> List[Dict[str, Any]]:
    short_name = short_type_name(type_name)
    matches = []
    candidates = [type_name, short_name] + list(bridge_names)
    seen_names = set()
    indexed_items: List[Dict[str, Any]] = []
    if symbol_indexes:
        for candidate in candidates:
            if not candidate:
                continue
            for item in symbol_indexes.get("symbols_by_candidate", {}).get(candidate, []):
                marker = item.get("name", "") + "|" + item.get("address", "")
                if marker in seen_names:
                    continue
                seen_names.add(marker)
                indexed_items.append(item)
    else:
        indexed_items = symbols_doc.get("objc_related", []) + symbols_doc.get("symbols", [])
    for item in indexed_items:
        name = item.get("name", "")
        matches.append(
            {
                "name": name,
                "demangled": item.get("demangled", ""),
                "address": item.get("address", ""),
                "artifact_type": item.get("artifact_type", ""),
                "xref_count": item.get("xref_count", 0),
            }
        )
    return unique_by_key(matches, "name")


def bridge_names_for_surface(type_name: str, objc: Dict[str, Any],
                             surface: Dict[str, Any]) -> List[str]:
    candidates: Set[str] = set(correlate_objc_classes(type_name, objc))
    for bucket_name in ["raw_symbols", "properties", "objc_runtime_artifacts", "metadata_methods"]:
        for entry in surface.get(bucket_name, []):
            bridge_name = entry.get("objc_bridge_name", "")
            if bridge_name and bridge_name_matches_surface(type_name, bridge_name):
                candidates.add(bridge_name)
    for artifact in surface.get("objc_runtime_artifacts", []):
        name = artifact.get("name", "")
        if name.startswith("_OBJC_CLASS_$__Tt") or name.startswith("_OBJC_METACLASS_$__Tt"):
            candidate = name.split("$", 1)[-1]
            if bridge_name_matches_surface(type_name, candidate):
                candidates.add(candidate)
    return sorted(candidates, key=str.lower)


def preferred_namespaces(program_name: str) -> List[str]:
    if not program_name:
        return []
    candidates = [program_name]
    if program_name.endswith("Core") and len(program_name) > 4:
        candidates.append(program_name[:-4])
    if program_name.endswith("UI") and len(program_name) > 2:
        candidates.append(program_name[:-2])
    return [value for value in dict.fromkeys(candidates) if value]


def candidate_type_priority(type_name: str, program_name: str) -> int:
    short_name = short_type_name(type_name)
    score = 0
    namespaces = preferred_namespaces(program_name)
    if "." in type_name:
        namespace = type_name.split(".", 1)[0]
        if namespace in namespaces:
            score += 120
        elif namespace in {"SwiftUI", "Foundation", "Combine", "AppKit", "CoreGraphics"}:
            score -= 25
    else:
        if short_name.startswith(("WF", "AK", "CK", "TK", "IN")):
            score += 40
        elif len(short_name) <= 2:
            score -= 25
    if short_name.startswith(program_name):
        score += 35
    if "Workflow" in type_name or "Shortcut" in type_name or "ToolKit" in type_name:
        score += 12
    score -= type_name_noise_penalty(type_name)
    return score


def select_candidate_types(type_names: List[str], program_name: str,
                           focus_query: str) -> List[str]:
    if focus_query:
        return type_names
    ranked = sorted(
        type_names,
        key=lambda value: (-candidate_type_priority(value, program_name), value.lower()),
    )
    return ranked[:40]


def score_surface(surface: Dict[str, Any], program_name: str) -> int:
    type_name = surface["type_name"]
    short_name = surface["short_name"]
    summary = surface.get("summary", {})
    score = 0
    if "." in type_name:
        namespace = type_name.split(".", 1)[0]
        if namespace in preferred_namespaces(program_name):
            score += 120
        elif namespace in {"SwiftUI", "Foundation", "Combine", "AppKit"}:
            score -= 20
    elif short_name.startswith(("WF", "CK", "AK", "TK", "IN")):
        score += 35
    if any(name.startswith("_Tt") or name.startswith("__Tt") for name in surface.get("objc_bridge_names", [])):
        score += 40
    if any(name.startswith("WF") for name in surface.get("objc_bridge_names", [])):
        score += 25
    score += summary.get("method_count", 0) * 4
    score += summary.get("property_count", 0) * 3
    score += summary.get("async_method_count", 0) * 5
    score += summary.get("metadata_method_count", 0) * 4
    score += summary.get("objc_runtime_artifact_count", 0) * 2
    score += summary.get("objc_bridge_method_count", 0) * 4
    score += summary.get("associated_conformance_count", 0) * 2
    score += min(20, len(surface.get("related_strings", [])))
    score -= type_name_noise_penalty(type_name)
    return score


def rank_surfaces(surfaces: List[Dict[str, Any]], program_name: str) -> List[Dict[str, Any]]:
    for surface in surfaces:
        surface["surface_score"] = score_surface(surface, program_name)
    return sorted(
        surfaces,
        key=lambda item: (
            -item.get("surface_score", 0),
            -item.get("summary", {}).get("method_count", 0),
            -item.get("summary", {}).get("objc_runtime_artifact_count", 0),
            item["type_name"].lower(),
        ),
    )


def surface_identity_key(surface: Dict[str, Any]) -> str:
    for bucket_name in ["objc_bridge_methods", "methods", "objc_runtime_artifacts", "metadata_methods"]:
        for entry in surface.get(bucket_name, []):
            address = (
                entry.get("canonical_address")
                or entry.get("candidate_address")
                or entry.get("address", "")
            )
            if address:
                return "addr:" + address
    bridge_names = sorted(surface.get("objc_bridge_names", []))
    if bridge_names:
        return "bridge:" + "|".join(bridge_names)
    return "type:" + surface.get("type_name", "")


def dedupe_ranked_surfaces(surfaces: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen: Set[str] = set()
    result: List[Dict[str, Any]] = []
    for surface in surfaces:
        marker = surface_identity_key(surface)
        if marker in seen:
            continue
        seen.add(marker)
        result.append(surface)
    return result


def property_hints_from_strings(type_name: str, strings_doc: Dict[str, Any],
                                extra_terms=None) -> List[Dict[str, Any]]:
    hints = []
    for entry in related_strings(type_name, strings_doc, extra_terms=extra_terms, limit=200):
        value = entry.get("value", "")
        candidates = []
        if re.match(r"^[a-z][A-Za-z0-9_]{2,}$", value):
            candidates.append(value)
        for match in re.finditer(r"V_([A-Za-z_][A-Za-z0-9_]*)", value):
            candidates.append(match.group(1))
        if re.match(r"^_[a-z][A-Za-z0-9_]*$", value):
            candidates.append(value[1:])
        for candidate in candidates:
            if candidate.lower() == short_type_name(type_name).lower():
                continue
            hints.append(
                {
                    "name": candidate,
                    "address": entry.get("address", ""),
                    "artifact_type": entry.get("artifact_type", ""),
                    "xref_count": entry.get("xref_count", 0),
                }
            )
    return unique_by_key(hints, "name")


def properties_from_runtime_artifacts(type_name: str,
                                      runtime_artifacts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    properties: List[Dict[str, Any]] = []
    for artifact in runtime_artifacts:
        labels = [
            artifact.get("stable_alias", ""),
            artifact.get("demangled", ""),
            artifact.get("name", ""),
        ]
        for label in labels:
            match = PROPERTY_DESCRIPTOR_RE.search(label)
            if not match:
                continue
            descriptor_type = match.group("type")
            descriptor_property = match.group("property")
            if not descriptor_property:
                continue
            if descriptor_type != type_name and short_type_name(descriptor_type) != short_type_name(type_name):
                continue
            properties.append(
                {
                    "name": artifact.get("name", ""),
                    "display_name": artifact.get("demangled", "") or artifact.get("name", ""),
                    "demangled": artifact.get("demangled", "") or artifact.get("name", ""),
                    "address": artifact.get("address", ""),
                    "canonical_address": artifact.get("canonical_address", artifact.get("address", "")),
                    "source": "runtime_property_descriptor",
                    "stable_alias": f"{type_name}.{descriptor_property}",
                    "member_name": descriptor_property,
                    "symbol_kind": "runtime_property_descriptor",
                    "objc_bridge_name": artifact.get("objc_bridge_name", ""),
                    "xref_count": artifact.get("xref_count", 0),
                }
            )
            break
    return unique_by_key(properties, "stable_alias")


def objc_bridge_methods_for_type(type_name: str, objc: Dict[str, Any],
                                 symbols_doc: Dict[str, Any],
                                 bridge_names: List[str],
                                 symbol_indexes: Optional[Dict[str, Dict[str, List[Dict[str, Any]]]]] = None
                                 ) -> List[Dict[str, Any]]:
    known_classes = set(objc.get("interface_classes", []) or [])
    known_classes.update(objc.get("classes", []))
    known_classes.update(objc.get("metaclasses", []))
    allowed = set(bridge_names)
    methods = []
    if symbol_indexes:
        method_items = []
        seen_items = set()
        for class_name in allowed:
            for item in symbol_indexes.get("objc_methods_by_class", {}).get(class_name, []):
                marker = item.get("name", "") + "|" + item.get("address", "")
                if marker in seen_items:
                    continue
                seen_items.add(marker)
                method_items.append(item)
    else:
        method_items = symbols_doc.get("objc_related", [])
    for item in method_items:
        parsed = parse_objc_method_name(item.get("name", ""), known_classes)
        if not parsed:
            continue
        if parsed["class_name"] not in allowed:
            continue
        selector = parsed["selector"]
        record = {
            "name": item.get("name", ""),
            "display_name": item.get("name", ""),
            "demangled": item.get("name", ""),
            "address": item.get("address", ""),
            "canonical_address": item.get("address", ""),
            "source": "objc_bridge",
            "stable_alias": f"{type_name}.{selector}",
            "member_name": selector,
            "symbol_kind": "objc_bridge_method",
            "objc_class_name": parsed["class_name"],
            "xref_count": item.get("xref_count", 0),
        }
        methods.append(record)
    return unique_by_key(methods, "stable_alias")


def build_surface_types(swift: Dict[str, Any], objc: Dict[str, Any], symbols_doc: Dict[str, Any],
                        strings_doc: Dict[str, Any], focus_query: str = "") -> List[Dict[str, Any]]:
    grouped: Dict[str, Dict[str, Any]] = {}
    symbol_indexes = build_symbol_indexes(objc, symbols_doc)
    inferred_types = inferred_surface_types(swift, symbols_doc, strings_doc)
    if focus_query:
        lowered = focus_query.lower()
        focused = [
            type_name
            for type_name in inferred_types
            if lowered == type_name.lower()
            or lowered == short_type_name(type_name).lower()
            or lowered in type_name.lower()
            or lowered in short_type_name(type_name).lower()
        ]
        for candidate in extract_type_candidates_from_text(focus_query):
            if candidate not in focused:
                focused.append(candidate)
        if valid_surface_type_name(focus_query) and focus_query not in focused:
            focused.append(focus_query)
        inferred_types = focused
    inferred_types = select_candidate_types(
        inferred_types, swift.get("program_name", ""), focus_query
    )
    allowed_type_names = set(inferred_types)
    for type_name in inferred_types:
        if not valid_surface_type_name(type_name):
            continue
        grouped.setdefault(type_name, empty_surface(type_name))
    for symbol in swift.get("symbols", []):
        type_name = recover_surface_type_name(symbol)
        if not valid_surface_type_name(type_name):
            continue
        if allowed_type_names is not None and type_name not in allowed_type_names:
            continue
        surface = grouped.setdefault(type_name, empty_surface(type_name))
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
        type_name = recover_surface_type_name(entry)
        if not valid_surface_type_name(type_name):
            continue
        if allowed_type_names is not None and type_name not in allowed_type_names:
            continue
        surface = grouped.setdefault(type_name, empty_surface(type_name))
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

    for entry in swift.get("property_records", []):
        type_name = recover_surface_type_name(entry)
        if not valid_surface_type_name(type_name):
            continue
        if allowed_type_names is not None and type_name not in allowed_type_names:
            continue
        surface = grouped.setdefault(type_name, empty_surface(type_name))
        record = {
            "name": entry.get("name", ""),
            "demangled": entry.get("demangled", ""),
            "display_name": entry.get("display_name", ""),
            "address": entry.get("address", ""),
            "canonical_address": entry.get("canonical_address", entry.get("address", "")),
            "source": entry.get("source", ""),
            "stable_alias": entry.get("stable_alias", ""),
            "member_name": entry.get("member_name", ""),
            "symbol_kind": entry.get("symbol_kind", "property_record"),
            "objc_bridge_name": entry.get("objc_bridge_name", ""),
            "readonly": bool(entry.get("readonly", False)),
        }
        surface["properties"].append(record)

    for entry in swift.get("protocol_requirements", []):
        type_name = recover_surface_type_name(
            entry, entry.get("type_name") or entry.get("protocol_name") or ""
        )
        if not valid_surface_type_name(type_name):
            continue
        if allowed_type_names is not None and type_name not in allowed_type_names:
            continue
        surface = grouped.setdefault(type_name, empty_surface(type_name))
        surface["protocol_requirements"].append(entry)
        if entry.get("kind") == "associated_type":
            surface["associated_types"].append(entry)

    for entry in swift.get("associated_conformances", []):
        type_name = recover_surface_type_name(
            entry, entry.get("type_name") or entry.get("protocol_name") or ""
        )
        if not valid_surface_type_name(type_name):
            continue
        if allowed_type_names is not None and type_name not in allowed_type_names:
            continue
        surface = grouped.setdefault(type_name, empty_surface(type_name))
        record = dict(entry)
        if not record.get("stable_alias"):
            record["stable_alias"] = associated_conformance_label(record)
        surface["associated_conformances"].append(record)

    for entry in swift.get("code_candidates", []):
        type_name = recover_surface_type_name(entry)
        if not valid_surface_type_name(type_name):
            continue
        if allowed_type_names is not None and type_name not in allowed_type_names:
            continue
        surface = grouped.setdefault(type_name, empty_surface(type_name))
        surface["code_candidates"].append(entry)
        for candidate in surface["code_candidates"]:
            if candidate.get("candidate_address") and not candidate.get("canonical_address"):
                candidate["canonical_address"] = candidate.get("candidate_address", "")
            if candidate.get("candidate_address") and not candidate.get("address"):
                candidate["address"] = candidate.get("candidate_address", "")

    for entry in swift.get("runtime_artifacts", []):
        type_name = recover_surface_type_name(entry)
        if not valid_surface_type_name(type_name):
            continue
        if allowed_type_names is not None and type_name not in allowed_type_names:
            continue
        surface = grouped.setdefault(type_name, empty_surface(type_name))
        surface["objc_runtime_artifacts"].append(
            {
                "name": entry.get("name", ""),
                "demangled": entry.get("demangled", ""),
                "address": entry.get("address", ""),
                "artifact_type": entry.get("symbol_kind", ""),
                "xref_count": entry.get("xref_count", 0),
                "objc_bridge_name": entry.get("objc_bridge_name", ""),
                "stable_alias": entry.get("stable_alias", ""),
            }
        )

    for entry in swift.get("async_relationships", []):
        type_name = recover_surface_type_name(entry)
        if not valid_surface_type_name(type_name):
            continue
        if allowed_type_names is not None and type_name not in allowed_type_names:
            continue
        surface = grouped.setdefault(type_name, empty_surface(type_name))
        surface["async_helpers"].append(entry)

    conformance_hits = swift.get("protocol_conformances", [])
    for surface in grouped.values():
        type_name = surface["type_name"]
        surface["protocol_conformances"] = list(dict.fromkeys([
            value for value in conformance_hits if type_name in value or short_type_name(type_name) in value
        ]))
        surface["objc_bridge_names"] = bridge_names_for_surface(type_name, objc, surface)
        bridge_names = surface["objc_bridge_names"]
        surface["related_strings"] = related_strings(type_name, strings_doc, extra_terms=bridge_names)
        surface["related_symbols"] = related_symbols(
            type_name, symbols_doc, extra_terms=bridge_names, symbol_indexes=symbol_indexes
        )
        surface["objc_runtime_artifacts"].extend(
            objc_runtime_artifacts_for_type(
                type_name, objc, symbols_doc, bridge_names, symbol_indexes=symbol_indexes
            )
        )
        surface["properties"].extend(
            properties_from_runtime_artifacts(type_name, surface["objc_runtime_artifacts"])
        )
        surface["property_hints"] = property_hints_from_strings(
            type_name, strings_doc, extra_terms=bridge_names
        )
        surface["objc_bridge_methods"] = objc_bridge_methods_for_type(
            type_name, objc, symbols_doc, bridge_names, symbol_indexes=symbol_indexes
        )
        surface["methods"].extend(surface["objc_bridge_methods"])
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
            "objc_bridge_methods",
            "objc_runtime_artifacts",
            "property_hints",
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
            "objc_bridge_method_count": len(surface["objc_bridge_methods"]),
            "objc_runtime_artifact_count": len(surface["objc_runtime_artifacts"]),
            "property_hint_count": len(surface["property_hints"]),
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
            type_score = 260
        elif lowered in type_name.lower() or lowered in short_name.lower():
            type_score = 180

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
            "objc_bridge_methods",
            "objc_runtime_artifacts",
            "property_hints",
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
                if bucket_name in {"methods", "metadata_methods", "objc_bridge_methods"}:
                    score += 40
                elif bucket_name == "objc_runtime_artifacts":
                    score += 15
                elif bucket_name in {"associated_conformances", "property_hints"}:
                    score -= 60
                elif bucket_name in {"protocol_requirements", "protocol_witnesses"}:
                    score -= 15
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
        "objc_bridge_methods",
        "objc_runtime_artifacts",
        "property_hints",
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
            if bucket == "objc_runtime_artifacts":
                entries = sorted(
                    entries,
                    key=lambda entry: (
                        0 if "__INSTANCE_METHODS_" in entry.get("name", "") else
                        1 if "__PROPERTIES_" in entry.get("name", "") else
                        2 if "__IVARS_" in entry.get("name", "") else
                        3 if "_OBJC_CLASS_" in entry.get("name", "") else
                        4,
                        entry.get("name", ""),
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
        candidate_count = payload.get("candidate_type_count", 0)
        returned_count = payload.get("returned_type_count", len(payload.get("types", [])))
        if candidate_count:
            lines.append(
                f"Showing top {returned_count} of {candidate_count} inferred surfaces"
            )
        namespaces = payload.get("preferred_namespaces", [])
        if namespaces:
            lines.append("Preferred namespaces: " + ", ".join(namespaces))
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
        if "surface_score" in surface:
            lines.append(f"- score: {surface['surface_score']}")
        if surface.get("objc_bridge_names"):
            lines.append("- objc bridges: " + ", ".join(surface["objc_bridge_names"]))
        if surface.get("property_hints"):
            lines.append("- property hints: " + ", ".join(
                entry.get("name", "") for entry in surface["property_hints"][:10] if entry.get("name")
            ))
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
                label = associated_conformance_label(entry)
                if label:
                    labels.append(label)
            if labels:
                lines.append("- associated conformances: " + ", ".join(dict.fromkeys(labels)))
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
            ("objc_bridge_methods", "objc bridge methods"),
            ("objc_runtime_artifacts", "objc runtime artifacts"),
            ("property_hints", "property hints"),
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

    focus_query = query if mode in {"type", "search"} or (mode == "report" and query) else ""
    surfaces = build_surface_types(swift, objc, symbols_doc, strings_doc, focus_query=focus_query)

    if mode == "report":
        if query:
            types = [
            surface for surface in surfaces
            if query.lower() in surface["type_name"].lower()
            or query.lower() in surface["short_name"].lower()
            or any(query.lower() in value.lower() for value in surface.get("objc_bridge_names", []))
            ]
            types = rank_surfaces(types, swift.get("program_name", ""))
            types = dedupe_ranked_surfaces(types)
            if types:
                min_score = max(120, types[0].get("surface_score", 0) - 100)
                types = [surface for surface in types if surface.get("surface_score", 0) >= min_score]
            types = types[:10]
        else:
            ranked = rank_surfaces(surfaces, swift.get("program_name", ""))
            types = ranked[:25]
        payload = {
            "query": query,
            "type_count": len(types),
            "candidate_type_count": len(surfaces),
            "returned_type_count": len(types),
            "preferred_namespaces": preferred_namespaces(swift.get("program_name", "")),
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
