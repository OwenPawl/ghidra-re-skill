"""Recover XPC surface hints from existing export bundles."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ghidra_re_skill.core.config import cfg


XPC_TERMS = (
    "xpc",
    "listener",
    "listenerendpoint",
    "interfacewithprotocol",
    "machservicename",
    "servicename",
    "remoteobjectproxy",
    "exportedinterface",
    "exportedobject",
)


def build_xpc_surface(
    project: str,
    program: str,
    objc_metadata_path: str | Path | None = None,
    strings_path: str | Path | None = None,
    symbols_path: str | Path | None = None,
    output: str | Path | None = None,
    markdown_output: str | Path | None = None,
) -> dict[str, Any]:
    """Build an XPC surface report from already-exported JSON artifacts."""
    export_dir = cfg.export_dir(project, program)
    objc_path = Path(objc_metadata_path) if objc_metadata_path else export_dir / "objc_metadata.json"
    str_path = Path(strings_path) if strings_path else export_dir / "strings.json"
    sym_path = Path(symbols_path) if symbols_path else export_dir / "symbols.json"
    out_path = Path(output) if output else export_dir / "xpc_surface.json"
    md_path = Path(markdown_output) if markdown_output else export_dir / "xpc_surface.md"

    objc = _load_json(objc_path)
    strings = _load_json(str_path)
    symbols = _load_json(sym_path)

    xpc_classes = _name_hits(_objc_names(objc, "classes") + _objc_names(objc, "interface_classes"))
    xpc_protocols = _protocol_hits(objc)
    xpc_selectors = _name_hits(_objc_names(objc, "selectors"))
    xpc_ivars = _name_hits(_objc_names(objc, "ivars"))
    xpc_symbols = _symbol_hits(symbols)
    service_names = _service_name_hits(strings)
    method_hints = _method_hints(xpc_symbols, xpc_selectors)

    report = {
        "ok": True,
        "project": project,
        "program": program,
        "inputs": {
            "objc_metadata": str(objc_path),
            "strings": str(str_path),
            "symbols": str(sym_path),
        },
        "summary": {
            "xpc_class_count": len(xpc_classes),
            "xpc_protocol_count": len(xpc_protocols),
            "xpc_selector_count": len(xpc_selectors),
            "xpc_ivar_count": len(xpc_ivars),
            "xpc_symbol_count": len(xpc_symbols),
            "service_name_count": len(service_names),
            "listener_method_count": len(method_hints["listener_methods"]),
            "connection_method_count": len(method_hints["connection_methods"]),
        },
        "xpc_classes": xpc_classes,
        "xpc_protocols": xpc_protocols,
        "xpc_selectors": xpc_selectors[:500],
        "xpc_ivars": xpc_ivars[:500],
        "service_names": service_names[:500],
        "method_hints": method_hints,
        "xpc_symbols": xpc_symbols[:1000],
        "topology_hints": _topology_hints(service_names, method_hints, xpc_protocols),
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    md_path.write_text(_render_markdown(report), encoding="utf-8")
    return {
        "ok": True,
        "output": str(out_path),
        "markdown_output": str(md_path),
        **report["summary"],
    }


def _objc_names(payload: dict[str, Any], key: str) -> list[str]:
    values = payload.get(key, [])
    names = []
    if not isinstance(values, list):
        return names
    for item in values:
        if isinstance(item, str):
            names.append(item)
        elif isinstance(item, dict):
            for candidate_key in ("name", "raw_name", "selector"):
                candidate = item.get(candidate_key)
                if candidate:
                    names.append(str(candidate))
                    break
    return names


def _name_hits(names: list[str]) -> list[str]:
    seen = set()
    hits = []
    for name in names:
        lowered = _normalise(name)
        if lowered in seen:
            continue
        if _is_xpc_related(name):
            seen.add(lowered)
            hits.append(name)
    return sorted(hits, key=str.lower)


def _protocol_hits(objc: dict[str, Any]) -> list[dict[str, Any]]:
    protocols = []
    for source_key in ("protocols", "recovered_protocols", "protocol_refs"):
        values = objc.get(source_key, [])
        if not isinstance(values, list):
            continue
        for item in values:
            if isinstance(item, str):
                raw = item
                name = _clean_protocol_name(item)
            elif isinstance(item, dict):
                raw_value = str(item.get("raw_name") or item.get("name") or "")
                name = _clean_protocol_name(str(item.get("name") or raw_value))
                raw = str(item.get("raw_name") or item.get("name") or "")
            else:
                continue
            if not name or "xpc" not in name.lower() and "xpc" not in raw.lower():
                continue
            protocols.append({"name": name, "raw_name": raw, "source": source_key})
    return _dedupe_dicts(protocols, ("name", "source"))


def _symbol_hits(symbols: dict[str, Any]) -> list[dict[str, Any]]:
    hits = []
    for source_key in ("symbols", "imports", "exports"):
        values = symbols.get(source_key, [])
        if not isinstance(values, list):
            continue
        for item in values:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "")
            if not name or not _is_xpc_related(name):
                continue
            hits.append(
                {
                    "name": name,
                    "address": item.get("address"),
                    "source": source_key,
                    "symbol_type": item.get("symbol_type"),
                    "xref_count": item.get("xref_count"),
                    "sample_xrefs": item.get("sample_xrefs", [])[:5]
                    if isinstance(item.get("sample_xrefs"), list)
                    else [],
                }
            )
    return _dedupe_dicts(hits, ("name", "address", "source"))


def _service_name_hits(strings: dict[str, Any]) -> list[dict[str, Any]]:
    hits = []
    values = strings.get("strings", [])
    if not isinstance(values, list):
        return hits
    for item in values:
        if not isinstance(item, dict):
            continue
        value = str(item.get("value") or "")
        if not _looks_like_service_name(value):
            continue
        xrefs = item.get("xrefs", [])
        hits.append(
            {
                "value": value,
                "address": item.get("address"),
                "xref_count": item.get("xref_count"),
                "referenced_from": _referenced_from(xrefs),
            }
        )
    return _dedupe_dicts(sorted(hits, key=lambda item: str(item["value"]).lower()), ("value", "address"))


def _method_hints(symbols: list[dict[str, Any]], selectors: list[str]) -> dict[str, list[dict[str, Any]]]:
    names = [{"name": selector, "source": "selector"} for selector in selectors]
    names.extend({"name": str(symbol.get("name")), "source": str(symbol.get("source"))} for symbol in symbols)
    listener = []
    connection = []
    interface = []
    for item in names:
        name = item["name"]
        lowered = name.lower()
        entry = {"name": name, "source": item["source"]}
        if "listener" in lowered or "shouldacceptnewconnection" in lowered:
            listener.append(entry)
        if "xpcconnection" in lowered or "machservicename" in lowered or "servicename" in lowered:
            connection.append(entry)
        if "interfacewithprotocol" in lowered or "xpcinterface" in lowered or "exportedinterface" in lowered:
            interface.append(entry)
    return {
        "listener_methods": _dedupe_dicts(listener, ("name", "source"))[:500],
        "connection_methods": _dedupe_dicts(connection, ("name", "source"))[:500],
        "interface_methods": _dedupe_dicts(interface, ("name", "source"))[:500],
    }


def _topology_hints(
    service_names: list[dict[str, Any]],
    method_hints: dict[str, list[dict[str, Any]]],
    protocols: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "probable_services": service_names[:100],
        "probable_listeners": method_hints["listener_methods"][:100],
        "probable_clients": method_hints["connection_methods"][:100],
        "probable_interfaces": protocols[:100] + method_hints["interface_methods"][:100],
    }


def _referenced_from(xrefs: Any) -> list[dict[str, Any]]:
    if not isinstance(xrefs, list):
        return []
    refs = []
    for ref in xrefs[:10]:
        if not isinstance(ref, dict):
            continue
        refs.append(
            {
                "from_address": ref.get("from_address"),
                "from_function": ref.get("from_function"),
                "ref_type": ref.get("ref_type"),
            }
        )
    return refs


def _looks_like_service_name(value: str) -> bool:
    lowered = value.lower()
    if len(value) > 240 or len(value) < 4:
        return False
    if " " in value or "\n" in value or "\t" in value:
        return False
    if ":" in value:
        return False
    if "$" in value:
        return False
    if value.startswith("_") and "machservicename" not in lowered:
        return False
    if "machservicename" in lowered:
        return True
    if lowered.endswith(".xpc") or ".xpc." in lowered:
        return True
    if not lowered.startswith(("com.apple.", "com.owen.", "org.", "net.")):
        return False
    if "xpc" in lowered or ".service" in lowered or "-service" in lowered:
        return True
    if lowered.startswith("com.apple.shortcuts.") and any(
        term in lowered for term in ("background-shortcut-runner", ".automationd", "shortcutsautomationd", "view-service", "poster-service")
    ):
        return True
    return False


def _is_xpc_related(name: str) -> bool:
    lowered = _normalise(name)
    return any(term in lowered for term in XPC_TERMS)


def _normalise(value: str) -> str:
    return value.lower().replace("_", "").replace(":", "").replace("-", "")


def _clean_protocol_name(value: str) -> str:
    name = value
    for prefix in (
        "__OBJC_$_PROTOCOL_INSTANCE_METHODS_OPT_",
        "__OBJC_$_PROTOCOL_INSTANCE_METHODS_",
        "__OBJC_$_PROTOCOL_CLASS_METHODS_",
        "__OBJC_$_PROTOCOL_METHOD_TYPES_",
        "__OBJC_$_PROTOCOL_REFS_",
        "__OBJC_LABEL_PROTOCOL_$_",
        "__OBJC_PROTOCOL_REFERENCE_$_",
        "__OBJC_PROTOCOL_$_",
        "__OBJC_CLASS_PROTOCOLS_$_",
    ):
        if name.startswith(prefix):
            return name[len(prefix) :]
    return name


def _dedupe_dicts(items: list[dict[str, Any]], keys: tuple[str, ...]) -> list[dict[str, Any]]:
    seen = set()
    result = []
    for item in items:
        marker = tuple(str(item.get(key)) for key in keys)
        if marker in seen:
            continue
        seen.add(marker)
        result.append(item)
    return result


def _render_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        f"# XPC Surface: {report['project']} / {report['program']}",
        "",
        "## Summary",
        "",
    ]
    for key, value in summary.items():
        lines.append(f"- `{key}`: {value}")
    lines.extend(["", "## Probable Services", ""])
    for item in report["topology_hints"]["probable_services"][:25]:
        refs = item.get("referenced_from") or []
        ref_text = ""
        if refs:
            ref = refs[0]
            ref_text = f" from `{ref.get('from_function') or ref.get('from_address')}`"
        lines.append(f"- `{item['value']}` at `{item.get('address')}`{ref_text}")
    lines.extend(["", "## Probable Listeners", ""])
    for item in report["topology_hints"]["probable_listeners"][:25]:
        lines.append(f"- `{item['name']}` ({item['source']})")
    lines.extend(["", "## Probable Interfaces", ""])
    for item in report["topology_hints"]["probable_interfaces"][:25]:
        name = item.get("name") if isinstance(item, dict) else str(item)
        source = item.get("source") if isinstance(item, dict) else "unknown"
        lines.append(f"- `{name}` ({source})")
    lines.append("")
    return "\n".join(lines)


def _load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RuntimeError(f"failed to parse JSON at {path}: {exc}") from exc
    return data if isinstance(data, dict) else {}
