"""Merge per-binary XPC surface reports into a coarse IPC graph."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from ghidra_re_skill.core.config import cfg
from ghidra_re_skill.modules.xpc_surface import build_xpc_surface


def build_xpc_graph(
    targets: list[str],
    output: str | Path | None = None,
    markdown_output: str | Path | None = None,
) -> dict[str, Any]:
    """Merge XPC surface reports for targets formatted as project:program."""
    parsed_targets = [_parse_target(target) for target in targets]
    if len(parsed_targets) < 1:
        raise RuntimeError("at least one target is required")

    surfaces = [_load_or_build_surface(project, program) for project, program in parsed_targets]
    nodes = [_node_from_surface(surface) for surface in surfaces]
    edges = _infer_edges(nodes)

    out_path = Path(output) if output else cfg.exports_dir / "xpc_graph.json"
    md_path = Path(markdown_output) if markdown_output else cfg.exports_dir / "xpc_graph.md"
    report = {
        "ok": True,
        "targets": [{"project": project, "program": program} for project, program in parsed_targets],
        "summary": {
            "node_count": len(nodes),
            "edge_count": len(edges),
            "service_count": sum(len(node["services"]) for node in nodes),
        },
        "nodes": nodes,
        "edges": edges,
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


def _parse_target(target: str) -> tuple[str, str]:
    if ":" not in target:
        raise RuntimeError(f"target must be formatted as project:program: {target}")
    project, program = target.split(":", 1)
    if not project or not program:
        raise RuntimeError(f"target must include both project and program: {target}")
    return project, program


def _load_or_build_surface(project: str, program: str) -> dict[str, Any]:
    surface_path = cfg.export_dir(project, program) / "xpc_surface.json"
    if surface_path.exists():
        data = _load_json(surface_path)
        if data.get("ok"):
            return data
    build_xpc_surface(project, program)
    return _load_json(surface_path)


def _node_from_surface(surface: dict[str, Any]) -> dict[str, Any]:
    project = str(surface.get("project") or "")
    program = str(surface.get("program") or "")
    topology = surface.get("topology_hints") if isinstance(surface.get("topology_hints"), dict) else {}
    services = _service_values(topology.get("probable_services", []))
    return {
        "id": f"{project}:{program}",
        "project": project,
        "program": program,
        "services": services,
        "classes": surface.get("xpc_classes", [])[:100] if isinstance(surface.get("xpc_classes"), list) else [],
        "protocols": _names(topology.get("probable_interfaces", []))[:100],
        "listeners": _names(topology.get("probable_listeners", []))[:100],
        "clients": _names(topology.get("probable_clients", []))[:100],
    }


def _service_values(items: Any) -> list[dict[str, Any]]:
    if not isinstance(items, list):
        return []
    services = []
    for item in items:
        if not isinstance(item, dict):
            continue
        value = item.get("value")
        if not value:
            continue
        services.append(
            {
                "value": str(value),
                "address": item.get("address"),
                "referenced_from": item.get("referenced_from", []),
            }
        )
    return services


def _names(items: Any) -> list[str]:
    if not isinstance(items, list):
        return []
    names = []
    for item in items:
        if isinstance(item, str):
            names.append(item)
        elif isinstance(item, dict):
            name = item.get("name") or item.get("value")
            if name:
                names.append(str(name))
    return sorted(set(names), key=str.lower)


def _infer_edges(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    edges = []
    for source in nodes:
        for service in source["services"]:
            owner = _best_owner(service["value"], nodes)
            if owner is None:
                continue
            relation = "provides_service" if owner["id"] == source["id"] else "references_service"
            edges.append(
                {
                    "from": source["id"],
                    "to": owner["id"],
                    "relation": relation,
                    "service": service["value"],
                    "evidence": {
                        "service_address": service.get("address"),
                        "referenced_from": service.get("referenced_from", []),
                    },
                }
            )
    return _dedupe_edges(edges)


def _best_owner(service: str, nodes: list[dict[str, Any]]) -> dict[str, Any] | None:
    scored = []
    for node in nodes:
        score = _owner_score(service, node["program"])
        if score:
            scored.append((score, node))
    if not scored:
        return None
    scored.sort(key=lambda item: (-item[0], item[1]["id"]))
    return scored[0][1]


def _owner_score(service: str, program: str) -> int:
    service_norm = _normalise(service)
    program_norm = _normalise(program)
    if program_norm and program_norm in service_norm:
        return 100
    tokens = [token for token in _tokens(program) if len(token) >= 4]
    if not tokens:
        return 0
    hits = sum(1 for token in tokens if token in service_norm)
    if hits == len(tokens):
        return 80 + hits
    return 0


def _tokens(value: str) -> list[str]:
    split = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", value)
    return [_normalise(part) for part in re.split(r"[^A-Za-z0-9]+", split) if part]


def _normalise(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def _dedupe_edges(edges: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    result = []
    for edge in edges:
        marker = (edge["from"], edge["to"], edge["relation"], edge["service"])
        if marker in seen:
            continue
        seen.add(marker)
        result.append(edge)
    return sorted(result, key=lambda edge: (edge["from"], edge["to"], edge["service"]))


def _render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# XPC Graph",
        "",
        "## Summary",
        "",
    ]
    for key, value in report["summary"].items():
        lines.append(f"- `{key}`: {value}")
    lines.extend(["", "## Edges", ""])
    if not report["edges"]:
        lines.append("- No cross-target service ownership edges inferred.")
    for edge in report["edges"]:
        lines.append(
            f"- `{edge['from']}` -> `{edge['to']}` via `{edge['service']}` ({edge['relation']})"
        )
    lines.extend(["", "## Nodes", ""])
    for node in report["nodes"]:
        lines.append(
            f"- `{node['id']}`: {len(node['services'])} services, "
            f"{len(node['listeners'])} listeners, {len(node['protocols'])} interfaces"
        )
    lines.append("")
    return "\n".join(lines)


def _load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise RuntimeError(f"missing XPC surface report: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RuntimeError(f"failed to parse JSON at {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise RuntimeError(f"XPC surface report must be a JSON object: {path}")
    return data
