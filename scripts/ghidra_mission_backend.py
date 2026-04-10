#!/usr/bin/env python3

import argparse
import datetime as dt
import hashlib
import json
import re
import sqlite3
import sys
from pathlib import Path


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_json(path: Path):
    return json.loads(path.read_text())


def write_json(path: Path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2))


def slug(value: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in value.strip())
    cleaned = cleaned.strip("._-")
    return cleaned or "mission"


def mission_paths(mission_dir: Path):
    return {
        "mission_dir": mission_dir,
        "mission_file": mission_dir / "mission.json",
        "graph_db": mission_dir / "graph.sqlite",
        "exports_dir": mission_dir / "exports",
        "reports_dir": mission_dir / "reports",
        "latest_json": mission_dir / "reports" / "latest.json",
        "latest_md": mission_dir / "reports" / "latest.md",
    }


def connect_db(path: Path):
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    ensure_schema(conn)
    return conn


def ensure_schema(conn: sqlite3.Connection):
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS targets (
            target_key TEXT PRIMARY KEY,
            project_name TEXT,
            program_name TEXT,
            binary_path TEXT,
            program_path TEXT,
            export_dir TEXT,
            metadata_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            target_key TEXT,
            session_file TEXT,
            bridge_url TEXT,
            project_name TEXT,
            program_name TEXT,
            program_path TEXT,
            last_heartbeat TEXT,
            metadata_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS nodes (
            node_key TEXT PRIMARY KEY,
            kind TEXT NOT NULL,
            label TEXT NOT NULL,
            target_key TEXT NOT NULL,
            metadata_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_nodes_kind_label ON nodes(kind, label);
        CREATE INDEX IF NOT EXISTS idx_nodes_target ON nodes(target_key);

        CREATE TABLE IF NOT EXISTS edges (
            edge_id INTEGER PRIMARY KEY AUTOINCREMENT,
            kind TEXT NOT NULL,
            source_key TEXT NOT NULL,
            dest_key TEXT NOT NULL,
            evidence_json TEXT NOT NULL,
            confidence REAL NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(kind, source_key, dest_key)
        );

        CREATE INDEX IF NOT EXISTS idx_edges_kind ON edges(kind);
        CREATE INDEX IF NOT EXISTS idx_edges_source ON edges(source_key);
        CREATE INDEX IF NOT EXISTS idx_edges_dest ON edges(dest_key);

        CREATE TABLE IF NOT EXISTS artifacts (
            path TEXT PRIMARY KEY,
            target_key TEXT NOT NULL,
            kind TEXT NOT NULL,
            metadata_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS notes (
            note_id INTEGER PRIMARY KEY AUTOINCREMENT,
            kind TEXT NOT NULL,
            title TEXT NOT NULL,
            body TEXT NOT NULL,
            metadata_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS runs (
            run_id TEXT PRIMARY KEY,
            run_kind TEXT NOT NULL,
            status TEXT NOT NULL,
            started_at TEXT NOT NULL,
            finished_at TEXT NOT NULL,
            metadata_json TEXT NOT NULL
        );
        """
    )
    conn.commit()


def upsert_target(conn, target_key, project_name="", program_name="", binary_path="", program_path="", export_dir="", metadata=None):
    now = utc_now()
    payload = json.dumps(metadata or {}, sort_keys=True)
    conn.execute(
        """
        INSERT INTO targets(target_key, project_name, program_name, binary_path, program_path, export_dir, metadata_json, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(target_key) DO UPDATE SET
            project_name=excluded.project_name,
            program_name=excluded.program_name,
            binary_path=excluded.binary_path,
            program_path=excluded.program_path,
            export_dir=excluded.export_dir,
            metadata_json=excluded.metadata_json,
            updated_at=excluded.updated_at
        """,
        (target_key, project_name, program_name, binary_path, program_path, export_dir, payload, now, now),
    )


def upsert_session(conn, session):
    now = utc_now()
    target_key = target_key_for(
        session.get("project_name", ""),
        session.get("program_name", ""),
        session.get("program_path", ""),
    )
    conn.execute(
        """
        INSERT INTO sessions(session_id, target_key, session_file, bridge_url, project_name, program_name, program_path, last_heartbeat, metadata_json, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(session_id) DO UPDATE SET
            target_key=excluded.target_key,
            session_file=excluded.session_file,
            bridge_url=excluded.bridge_url,
            project_name=excluded.project_name,
            program_name=excluded.program_name,
            program_path=excluded.program_path,
            last_heartbeat=excluded.last_heartbeat,
            metadata_json=excluded.metadata_json,
            updated_at=excluded.updated_at
        """,
        (
            session.get("session_id", ""),
            target_key,
            session.get("session_file", ""),
            session.get("bridge_url", ""),
            session.get("project_name", ""),
            session.get("program_name", ""),
            session.get("program_path", ""),
            session.get("last_heartbeat", ""),
            json.dumps(session, sort_keys=True),
            now,
            now,
        ),
    )


def upsert_node(conn, kind, node_key, label, target_key, metadata=None):
    now = utc_now()
    conn.execute(
        """
        INSERT INTO nodes(node_key, kind, label, target_key, metadata_json, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(node_key) DO UPDATE SET
            kind=excluded.kind,
            label=excluded.label,
            target_key=excluded.target_key,
            metadata_json=excluded.metadata_json,
            updated_at=excluded.updated_at
        """,
        (node_key, kind, label, target_key, json.dumps(metadata or {}, sort_keys=True), now, now),
    )


def upsert_edge(conn, kind, source_key, dest_key, evidence=None, confidence=0.5):
    now = utc_now()
    conn.execute(
        """
        INSERT INTO edges(kind, source_key, dest_key, evidence_json, confidence, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(kind, source_key, dest_key) DO UPDATE SET
            evidence_json=excluded.evidence_json,
            confidence=excluded.confidence,
            updated_at=excluded.updated_at
        """,
        (kind, source_key, dest_key, json.dumps(evidence or {}, sort_keys=True), float(confidence), now, now),
    )


def add_artifact(conn, target_key, kind, path, metadata=None):
    now = utc_now()
    conn.execute(
        """
        INSERT INTO artifacts(path, target_key, kind, metadata_json, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(path) DO UPDATE SET
            target_key=excluded.target_key,
            kind=excluded.kind,
            metadata_json=excluded.metadata_json,
            updated_at=excluded.updated_at
        """,
        (str(path), target_key, kind, json.dumps(metadata or {}, sort_keys=True), now, now),
    )


def add_note(conn, kind, title, body, metadata=None):
    conn.execute(
        "INSERT INTO notes(kind, title, body, metadata_json, created_at) VALUES (?, ?, ?, ?, ?)",
        (kind, title, body, json.dumps(metadata or {}, sort_keys=True), utc_now()),
    )


def add_run(conn, run_kind, status, metadata=None):
    run_id = f"{slug(run_kind)}-{utc_now()}"
    conn.execute(
        "INSERT INTO runs(run_id, run_kind, status, started_at, finished_at, metadata_json) VALUES (?, ?, ?, ?, ?, ?)",
        (run_id, run_kind, status, utc_now(), utc_now(), json.dumps(metadata or {}, sort_keys=True)),
    )


def target_key_for(project_name, program_name, program_path=""):
    if project_name and program_name:
        return f"{project_name}:{program_name}"
    if program_path:
        return program_path
    return program_name or project_name or "unknown-target"


def function_node_key(target_key, entry):
    return f"{target_key}:function:{entry}"


def framework_node_key(target_key):
    return f"{target_key}:framework"


def class_node_key(target_key, class_name):
    return f"{target_key}:class:{class_name}"


def local_string_node_key(target_key, address):
    return f"{target_key}:string:{address}"


def global_string_key(value):
    digest = hashlib.sha1(value.encode("utf-8")).hexdigest()
    return f"string:{digest}"


def global_selector_key(value):
    return f"selector:{value}"


def global_symbol_key(value):
    return f"symbol:{value}"


def global_service_key(value):
    return f"service:{value}"


def unwrap_payload(payload):
    if isinstance(payload, dict) and "result" in payload:
        return payload["result"]
    return payload


def load_mission(paths):
    if paths["mission_file"].exists():
        return load_json(paths["mission_file"])
    return {}


def save_mission(paths, mission):
    mission["updated_at"] = utc_now()
    write_json(paths["mission_file"], mission)


def touch_mission(paths):
    mission = load_mission(paths)
    if not mission:
        return
    save_mission(paths, mission)


def maybe_service_name(value: str) -> bool:
    return value.startswith("com.apple.") or value.startswith("group.") or value.endswith(".xpc") or value.startswith("is.workflow.")


def is_low_signal_symbol(value: str) -> bool:
    prefixes = (
        "__",
        "_objc_",
        "_swift_",
        "swift_",
        "_dispatch_",
        "_os_",
        "_Block_",
        "_NSConcrete",
        "$$associated_type_descriptor",
        "$$base_conformance_descriptor",
    )
    exact = {
        "_objc_msgSend",
        "_objc_retain",
        "_objc_release",
        "_objc_autoreleaseReturnValue",
        "_objc_retainAutoreleasedReturnValue",
        "_swift_allocObject",
        "_swift_release",
        "_swift_retain",
        "___stack_chk_fail",
        "_NSLog",
        "_NSLocalizedDescriptionKey",
        "_NSStringFromClass",
        "_coderRequiresSecureCoding",
        "_verifyAllowedClassesByPropertyKey",
    }
    return value in exact or value.startswith(prefixes)


def is_low_signal_function_name(value: str) -> bool:
    value = (value or "").strip()
    if not value:
        return True
    exact = {
        "None",
        "entry",
        "thunk",
        "__stub_helper",
        "___stack_chk_fail",
    }
    prefixes = (
        "FUN_",
        "SUB_",
        "sub_",
        "thunk ",
        "thunk_",
        "partial apply",
        "closure #",
        "outlined ",
        "__swift",
        "__copy_helper_block_",
        "__destroy_helper_block_",
        "block_copy_helper",
        "block_destroy_helper",
        "$$",
        "$$associated_type_descriptor",
        "$$base_conformance_descriptor",
        "$s",
    )
    return value in exact or value.startswith(prefixes)


def is_low_signal_selector(value: str) -> bool:
    value = (value or "").strip()
    if not value:
        return True
    exact = {
        ".cxx_destruct",
        "copyWithZone:",
        "dealloc",
        "debugDescription",
        "description",
        "hash",
        "init",
        "isEqual:",
        "supportsSecureCoding",
    }
    return value in exact


def preferred_function_label(metadata, fallback_entry="") -> str:
    metadata = metadata or {}
    name = (metadata.get("name") or "").strip()
    signature = (metadata.get("signature") or "").strip()
    class_name = (metadata.get("class_name") or "").strip()
    selector = (metadata.get("selector") or "").strip()
    namespace = (metadata.get("namespace") or "").strip()
    match_value = (metadata.get("match_value") or "").strip()
    match_kind = (metadata.get("match_kind") or "").strip()

    for candidate in (name, signature, match_value):
        if candidate.startswith("-[") or candidate.startswith("+["):
            return candidate

    if class_name and selector:
        return f"-[{class_name} {selector}]"

    if not is_low_signal_function_name(name):
        return name

    if namespace and not is_low_signal_function_name(namespace):
        if selector:
            return f"{namespace}::{selector}"
        if name:
            return f"{namespace}::{name}"

    objc_match = re.search(r"([+-]\[[^\]]+\])", signature)
    if objc_match:
        return objc_match.group(1)

    if match_kind and match_value and not is_low_signal_function_name(match_value):
        return match_value

    if signature and not is_low_signal_function_name(signature):
        return signature

    return name or fallback_entry or metadata.get("entry", "") or "unknown-function"


OBJC_METHOD_RE = re.compile(r"^([+-])\[(.+?) ([^\]]+)\]$")
OBJC_METHOD_BODY_RE = re.compile(r"^([+-])\[(.+)\]$")


def parse_objc_method_name(name: str, address: str = "", source: str = "symbol", known_classes=None):
    name = (name or "").strip()
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
        "name": name,
        "kind": kind,
        "class_name": class_name,
        "selector": selector,
        "entry": address,
        "source": source,
    }


def merged_objc_methods(objc, symbols):
    methods = []
    seen = set()
    known_classes = set(objc.get("interface_classes") or [])
    known_classes.update(objc.get("classes") or [])
    known_classes.update(objc.get("metaclasses") or [])
    for method in objc.get("methods", []):
        if not method.get("selector"):
            continue
        item = dict(method)
        if not item.get("entry"):
            item["entry"] = item.get("address", "")
        key = (
            item.get("entry", ""),
            item.get("name", ""),
            item.get("class_name", ""),
            item.get("selector", ""),
        )
        if key in seen:
            continue
        seen.add(key)
        methods.append(item)
    for symbol in symbols.get("objc_related", []):
        parsed = parse_objc_method_name(
            symbol.get("name", ""),
            symbol.get("address", ""),
            symbol.get("source", "symbols"),
            known_classes,
        )
        if not parsed:
            continue
        parsed["artifact_type"] = symbol.get("artifact_type", "")
        parsed["xref_count"] = symbol.get("xref_count", 0)
        parsed["sample_xrefs"] = symbol.get("sample_xrefs", [])
        key = (
            parsed.get("entry", ""),
            parsed.get("name", ""),
            parsed.get("class_name", ""),
            parsed.get("selector", ""),
        )
        if key in seen:
            continue
        seen.add(key)
        methods.append(parsed)
    return methods


def seed_value_for_label(label: str, metadata=None):
    metadata = metadata or {}
    label = (label or "").strip()
    if not label:
        return None
    if label.startswith("-[") or label.startswith("+["):
        return f"function:{label}"
    selector = (metadata.get("selector") or "").strip()
    if selector:
        return f"selector:{selector}"
    if label.startswith("_"):
        return f"symbol:{label}"
    if ":" in label and " " not in label and "::" not in label:
        return f"selector:{label}"
    return f"function:{label}"


def seed_quality_penalty(kind: str, value: str) -> float:
    value = (value or "").strip()
    if kind == "symbol" and is_low_signal_symbol(value):
        return 100.0
    if kind == "function" and is_low_signal_function_name(value):
        return 30.0
    if kind == "function" and value.startswith("-[") and (" init" in value or value.endswith("init]")):
        return -4.0
    if kind == "selector" and value in {"description", "copyWithZone:", "init", "dealloc", ".cxx_destruct"}:
        return 20.0
    return 0.0


def infer_seed(raw_value: str):
    value = (raw_value or "").strip()
    if not value:
        return None
    if ":" in value:
        kind, remainder = value.split(":", 1)
        if kind in {"selector", "symbol", "function", "string", "class", "service"} and remainder:
            return {"seed": value, "kind": kind, "value": remainder}
    if value.startswith("-[") or value.startswith("+["):
        return {"seed": f"function:{value}", "kind": "function", "value": value}
    if maybe_service_name(value):
        return {"seed": f"service:{value}", "kind": "service", "value": value}
    if value.startswith("_"):
        return {"seed": f"symbol:{value}", "kind": "symbol", "value": value}
    if ":" in value:
        return {"seed": f"selector:{value}", "kind": "selector", "value": value}
    return {"seed": f"function:{value}", "kind": "function", "value": value}


def suggest_seeds(conn, mission):
    suggestions = {}

    def push(seed, reason, score, preferred_targets=None, evidence=None):
        inferred = infer_seed(seed)
        if not inferred:
            return
        penalty = seed_quality_penalty(inferred["kind"], inferred["value"])
        if penalty >= 100.0:
            return
        key = inferred["seed"]
        adjusted_score = float(score) - penalty
        entry = suggestions.get(key)
        if entry is None:
            entry = {
                "seed": key,
                "kind": inferred["kind"],
                "value": inferred["value"],
                "score": adjusted_score,
                "reasons": [],
                "preferred_targets": [],
                "evidence": [],
                "signal_penalty": penalty,
            }
            suggestions[key] = entry
        else:
            entry["score"] = max(entry["score"], adjusted_score)
            entry["signal_penalty"] = min(entry.get("signal_penalty", penalty), penalty)
        if reason and reason not in entry["reasons"]:
            entry["reasons"].append(reason)
        for item in preferred_targets or []:
            if item and item not in entry["preferred_targets"]:
                entry["preferred_targets"].append(item)
        if evidence:
            entry["evidence"].append(evidence)

    for seed in mission.get("seeds", []):
        push(seed, "configured seed", 100.0)

    current_hypothesis = mission.get("current_hypothesis", "")
    for candidate in re.findall(r"([+-]\[[^\]]+\])", current_hypothesis):
        push(f"function:{candidate}", "current hypothesis target", 96.0)

    note_rows = conn.execute(
        "SELECT kind, title, metadata_json FROM notes ORDER BY note_id DESC LIMIT 30"
    ).fetchall()
    for row in note_rows:
        metadata = json.loads(row["metadata_json"])
        note_targets = []
        target_key = metadata.get("target_key", "")
        if target_key:
            note_targets.append(target_key)
        function_name = metadata.get("function_name", "")
        if function_name:
            push(f"function:{function_name}", f"recent {row['kind']} focus", 88.0, note_targets)
        for item in metadata.get("next_hops", []):
            push(item, f"next hop from recent {row['kind']} note", 90.0, note_targets)
        for item in metadata.get("interesting_next_hops", []):
            push(item, f"interesting next hop from {row['kind']} note", 92.0, note_targets)

    selector_rows = conn.execute(
        """
        SELECT selector.label AS selector_label,
               COUNT(DISTINCT fn.target_key) AS target_count,
               COUNT(*) AS implementation_count
        FROM edges e
        JOIN nodes selector ON selector.node_key = e.dest_key
        JOIN nodes fn ON fn.node_key = e.source_key
        WHERE e.kind = 'implements'
          AND selector.kind = 'selector'
          AND fn.target_key != '*'
        GROUP BY selector.node_key, selector.label
        ORDER BY target_count DESC, implementation_count DESC, selector.label
        LIMIT 20
        """
    ).fetchall()
    for row in selector_rows:
        if row["selector_label"] in {"description", "copyWithZone:", "init", "dealloc", ".cxx_destruct"}:
            continue
        push(
            f"selector:{row['selector_label']}",
            f"implemented across {row['target_count']} target(s)",
            70.0 + min(row["target_count"] * 2.0, 10.0),
            evidence={"kind": "selector-implementation-spread", "target_count": row["target_count"], "implementation_count": row["implementation_count"]},
        )

    symbol_rows = conn.execute(
        """
        SELECT symbol.label AS symbol_label,
               COUNT(DISTINCT framework.target_key) AS target_count
        FROM edges e
        JOIN nodes symbol ON symbol.node_key = e.dest_key
        JOIN nodes framework ON framework.node_key = e.source_key
        WHERE e.kind = 'imports'
          AND symbol.kind = 'symbol'
          AND framework.kind = 'framework'
        GROUP BY symbol.node_key, symbol.label
        ORDER BY target_count DESC, symbol.label
        LIMIT 30
        """
    ).fetchall()
    for row in symbol_rows:
        symbol_label = row["symbol_label"]
        if is_low_signal_symbol(symbol_label):
            continue
        push(
            f"symbol:{symbol_label}",
            f"imported by {row['target_count']} target(s)",
            60.0 + min(row["target_count"] * 1.5, 8.0),
            evidence={"kind": "symbol-import-spread", "target_count": row["target_count"]},
        )

    service_rows = conn.execute(
        """
        SELECT service.label AS service_label,
               COUNT(DISTINCT framework.target_key) AS target_count
        FROM edges e
        JOIN nodes framework ON framework.node_key = e.source_key
        JOIN nodes service ON service.node_key = e.dest_key
        WHERE e.kind = 'derived-from'
          AND framework.kind = 'framework'
          AND service.kind = 'service'
        GROUP BY service.node_key, service.label
        ORDER BY target_count DESC, service.label
        LIMIT 20
        """
    ).fetchall()
    for row in service_rows:
        push(
            f"service:{row['service_label']}",
            f"service string seen in {row['target_count']} target(s)",
            55.0 + min(row["target_count"], 6.0),
            evidence={"kind": "service-string-spread", "target_count": row["target_count"]},
        )

    function_rows = conn.execute(
        """
        SELECT n.label,
               n.target_key,
               json_extract(n.metadata_json, '$.entry') AS entry,
               (
                 SELECT COUNT(*)
                 FROM edges incoming
                 WHERE incoming.dest_key = n.node_key
                   AND incoming.kind = 'calls'
               ) AS caller_count,
               (
                 SELECT COUNT(*)
                 FROM edges outgoing
                 WHERE outgoing.source_key = n.node_key
                   AND outgoing.kind = 'calls'
               ) AS callee_count,
               (
                 SELECT COUNT(*)
                 FROM edges implements
                 WHERE implements.source_key = n.node_key
                   AND implements.kind = 'implements'
               ) AS selector_count
        FROM nodes n
        WHERE n.kind = 'function'
          AND n.target_key != '*'
        ORDER BY selector_count DESC, caller_count DESC, callee_count DESC
        LIMIT 80
        """
    ).fetchall()
    for row in function_rows:
        label = row["label"]
        if is_low_signal_function_name(label):
            continue
        total_degree = int(row["caller_count"] or 0) + int(row["callee_count"] or 0)
        score = 52.0 + min(total_degree * 1.2, 16.0) + min(int(row["selector_count"] or 0) * 6.0, 12.0)
        push(
            f"function:{label}",
            f"high-traffic function in {row['target_key']}",
            score,
            preferred_targets=[row["target_key"]],
            evidence={
                "kind": "graph-function-degree",
                "caller_count": int(row["caller_count"] or 0),
                "callee_count": int(row["callee_count"] or 0),
                "selector_count": int(row["selector_count"] or 0),
            },
        )

    return sorted(
        suggestions.values(),
        key=lambda item: (-item["score"], item.get("signal_penalty", 0.0), item["kind"], item["value"]),
    )


def register_framework_node(conn, target_key, summary):
    label = summary.get("program_name", target_key)
    key = framework_node_key(target_key)
    upsert_node(conn, "framework", key, label, target_key, summary)
    return key


def ingest_export_bundle(conn, target_key, export_dir: Path):
    summary = load_json(export_dir / "program_summary.json")
    objc = load_json(export_dir / "objc_metadata.json")
    swift = load_json(export_dir / "swift_metadata.json") if (export_dir / "swift_metadata.json").is_file() else {}
    functions = load_json(export_dir / "function_inventory.json")
    symbols = load_json(export_dir / "symbols.json")
    strings = load_json(export_dir / "strings.json")

    framework_key = register_framework_node(conn, target_key, summary)

    for kind, filename in [
        ("program-summary", "program_summary.json"),
        ("objc-metadata", "objc_metadata.json"),
        ("swift-metadata", "swift_metadata.json"),
        ("function-inventory", "function_inventory.json"),
        ("symbols", "symbols.json"),
        ("strings", "strings.json"),
    ]:
        artifact_path = export_dir / filename
        if artifact_path.is_file():
            add_artifact(conn, target_key, kind, artifact_path)

    for item in functions.get("functions", []):
        node_key = function_node_key(target_key, item.get("entry", ""))
        item = dict(item)
        item["display_label"] = preferred_function_label(item, item.get("entry", ""))
        upsert_node(conn, "function", node_key, item["display_label"], target_key, item)
        upsert_edge(conn, "derived-from", node_key, framework_key, {"source": "function_inventory"}, 0.9)

    objc_class_bucket = objc.get("interface_classes") or objc.get("classes", [])
    for class_name in objc_class_bucket:
        class_key = class_node_key(target_key, class_name)
        upsert_node(conn, "class", class_key, class_name, target_key, {"source": "objc_metadata"})
        upsert_edge(conn, "derived-from", class_key, framework_key, {"source": "objc_metadata"}, 0.8)

    seen_protocols = set()
    for protocol_name in objc.get("protocols", []):
        if not protocol_name or protocol_name in seen_protocols:
            continue
        seen_protocols.add(protocol_name)
        protocol_key = f"protocol::{target_key}::{protocol_name}"
        upsert_node(conn, "protocol", protocol_key, protocol_name, target_key, {"source": "objc_metadata"})
        upsert_edge(conn, "derived-from", protocol_key, framework_key, {"source": "objc_metadata"}, 0.7)
    for protocol_item in objc.get("recovered_protocols", []):
        protocol_name = protocol_item.get("name", "")
        if not protocol_name or protocol_name in seen_protocols:
            continue
        seen_protocols.add(protocol_name)
        protocol_key = f"protocol::{target_key}::{protocol_name}"
        upsert_node(conn, "protocol", protocol_key, protocol_name, target_key, protocol_item)
        upsert_edge(conn, "derived-from", protocol_key, framework_key, {"source": "objc_metadata"}, 0.65)

    for selector in objc.get("selectors", []):
        selector_key = global_selector_key(selector)
        upsert_node(conn, "selector", selector_key, selector, "*", {"source": "objc_metadata"})

    for method in merged_objc_methods(objc, symbols):
        selector = method.get("selector", "")
        entry = method.get("entry", "") or method.get("address", "")
        class_name = method.get("class_name", "")
        if not selector or not entry:
            continue
        function_key = function_node_key(target_key, entry)
        selector_key = global_selector_key(selector)
        upsert_node(conn, "selector", selector_key, selector, "*", {"source": "objc_metadata"})
        method = dict(method)
        method["display_label"] = preferred_function_label(method, entry)
        upsert_node(conn, "function", function_key, method["display_label"], target_key, method)
        source_name = method.get("source", "objc_metadata")
        confidence = 0.95 if source_name == "objc_metadata" else 0.8
        upsert_edge(conn, "implements", function_key, selector_key, {"source": source_name, "method": method.get("name", "")}, confidence)
        if class_name:
            class_key = class_node_key(target_key, class_name)
            upsert_node(conn, "class", class_key, class_name, target_key, {"source": source_name})
            upsert_edge(conn, "derived-from", function_key, class_key, {"source": source_name}, 0.85 if source_name == "objc_metadata" else 0.7)

    for item in symbols.get("imports", []):
        symbol_name = item.get("name", "")
        if not symbol_name:
            continue
        symbol_key = global_symbol_key(symbol_name)
        upsert_node(conn, "symbol", symbol_key, symbol_name, "*", item)
        upsert_edge(conn, "imports", framework_key, symbol_key, {"source": "symbols", "address": item.get("address", "")}, 0.9)

    for item in strings.get("strings", []):
        value = item.get("value", "")
        address = item.get("address", "")
        if not value or not address:
            continue
        local_key = local_string_node_key(target_key, address)
        upsert_node(conn, "string", local_key, value, target_key, item)
        upsert_edge(conn, "derived-from", local_key, framework_key, {"source": "strings", "address": address}, 0.5)
        global_key = global_string_key(value)
        upsert_node(conn, "string", global_key, value, "*", {"source": "strings"})
        upsert_edge(conn, "derived-from", local_key, global_key, {"source": "strings"}, 0.6)
        if maybe_service_name(value):
            service_key = global_service_key(value)
            upsert_node(conn, "service", service_key, value, "*", {"source": "strings"})
            upsert_edge(conn, "derived-from", framework_key, service_key, {"source": "strings", "address": address}, 0.55)

    for item in swift.get("symbols", []):
        name = item.get("name", "")
        if not name:
            continue
        symbol_key = global_symbol_key(name)
        upsert_node(conn, "symbol", symbol_key, name, target_key, item)
        upsert_edge(conn, "derived-from", symbol_key, framework_key, {"source": "swift_metadata"}, 0.7)

    for type_name in swift.get("types", []):
        if not type_name:
            continue
        type_key = f"{target_key}:type:{type_name}"
        upsert_node(conn, "type", type_key, type_name, target_key, {"source": "swift_metadata"})
        upsert_edge(conn, "derived-from", type_key, framework_key, {"source": "swift_metadata"}, 0.7)

    for protocol_name in swift.get("protocol_conformances", []):
        if not protocol_name:
            continue
        protocol_key = f"{target_key}:protocol:{protocol_name}"
        upsert_node(conn, "protocol", protocol_key, protocol_name, target_key, {"source": "swift_metadata"})
        upsert_edge(conn, "derived-from", protocol_key, framework_key, {"source": "swift_metadata"}, 0.65)

    refresh_same_subsystem_links(conn, target_key)


def refresh_same_subsystem_links(conn, focus_target_key):
    framework_key = framework_node_key(focus_target_key)
    target_rows = conn.execute(
        "SELECT target_key FROM targets WHERE target_key != ? ORDER BY target_key",
        (focus_target_key,),
    ).fetchall()
    for row in target_rows:
        other_target_key = row["target_key"]
        other_framework_key = framework_node_key(other_target_key)
        shared_selectors = conn.execute(
            """
            SELECT COUNT(DISTINCT e1.dest_key) AS count
            FROM edges e1
            JOIN nodes n1 ON n1.node_key = e1.source_key
            JOIN edges e2 ON e2.dest_key = e1.dest_key AND e2.kind = e1.kind
            JOIN nodes n2 ON n2.node_key = e2.source_key
            WHERE e1.kind = 'implements'
              AND n1.target_key = ?
              AND n2.target_key = ?
            """,
            (focus_target_key, other_target_key),
        ).fetchone()["count"]
        shared_imports = conn.execute(
            """
            SELECT COUNT(DISTINCT e1.dest_key) AS count
            FROM edges e1
            JOIN edges e2 ON e2.dest_key = e1.dest_key AND e2.kind = e1.kind
            WHERE e1.kind = 'imports'
              AND e1.source_key = ?
              AND e2.source_key = ?
            """,
            (framework_key, other_framework_key),
        ).fetchone()["count"]
        if not shared_selectors and not shared_imports:
            continue
        confidence = min(1.0, (shared_selectors * 0.1) + (shared_imports * 0.05))
        evidence = {
            "shared_selectors": shared_selectors,
            "shared_imports": shared_imports,
        }
        upsert_edge(conn, "same-subsystem", framework_key, other_framework_key, evidence, confidence)
        upsert_edge(conn, "same-subsystem", other_framework_key, framework_key, evidence, confidence)


def ingest_selector_trace(conn, target_key, selector, trace_payload, analysis_payload=None):
    payload = unwrap_payload(trace_payload)
    selector_key = global_selector_key(selector)
    framework_key = framework_node_key(target_key)
    upsert_node(conn, "selector", selector_key, selector, "*", {"source": "selector-trace"})
    implementations = payload.get("implementations", [])
    sender_functions = payload.get("sender_functions", [])
    sender_callsites = payload.get("sender_callsites", [])
    for item in implementations:
        entry = item.get("entry", "")
        name = item.get("name", "")
        if not entry:
            continue
        fn_key = function_node_key(target_key, entry)
        item = dict(item)
        item["display_label"] = preferred_function_label(item, entry)
        upsert_node(conn, "function", fn_key, item["display_label"], target_key, item)
        upsert_edge(conn, "implements", fn_key, selector_key, {"source": "selector-trace", "match_kind": item.get("match_kind", "")}, 0.98)
        upsert_edge(conn, "derived-from", fn_key, framework_key, {"source": "selector-trace"}, 0.85)
    for item in sender_functions:
        entry = item.get("entry", "")
        name = item.get("name", "")
        if not entry:
            continue
        fn_key = function_node_key(target_key, entry)
        item = dict(item)
        item["display_label"] = preferred_function_label(item, entry)
        upsert_node(conn, "function", fn_key, item["display_label"], target_key, item)
        upsert_edge(conn, "references", fn_key, selector_key, {"source": "selector-trace"}, 0.8)
    if analysis_payload:
        ingest_analyze_target(conn, target_key, "selector", selector, analysis_payload)
    next_hops = [preferred_function_label(item, item.get("entry", "")) for item in implementations[:3]] + [
        preferred_function_label(item, item.get("entry", "")) for item in sender_functions[:2]
    ]
    next_hops = [item for item in next_hops if item]
    add_note(
        conn,
        "trace",
        f"Selector trace: {selector}",
        f"{selector} matched {len(implementations)} implementations and {len(sender_functions)} sender functions in {target_key}.",
        {
            "target_key": target_key,
            "selector": selector,
            "sender_callsites": len(sender_callsites),
            "next_hops": next_hops[:5],
        },
    )


def ingest_analyze_target(conn, target_key, seed_kind, seed_value, analysis_payload):
    payload = unwrap_payload(analysis_payload)
    function = payload.get("function", {})
    if not function:
        return
    entry = function.get("entry") or function.get("function_ref", {}).get("entry", "")
    if not entry:
        return
    framework_key = framework_node_key(target_key)
    source_key = function_node_key(target_key, entry)
    function = dict(function)
    function["display_label"] = preferred_function_label(function, entry)
    upsert_node(conn, "function", source_key, function["display_label"], target_key, function)
    upsert_edge(conn, "derived-from", source_key, framework_key, {"source": "analyze-target"}, 0.9)
    references = payload.get("references", {})
    for caller in references.get("callers", []):
        caller_entry = caller.get("entry", "")
        if not caller_entry:
            continue
        caller_key = function_node_key(target_key, caller_entry)
        caller = dict(caller)
        caller["display_label"] = preferred_function_label(caller, caller_entry)
        upsert_node(conn, "function", caller_key, caller["display_label"], target_key, caller)
        upsert_edge(conn, "calls", caller_key, source_key, {"source": "analyze-target", "relation": "caller"}, 0.85)
    for callee in references.get("callees", []):
        callee_entry = callee.get("entry", "")
        if not callee_entry:
            continue
        callee_key = function_node_key(target_key, callee_entry)
        callee = dict(callee)
        callee["display_label"] = preferred_function_label(callee, callee_entry)
        upsert_node(conn, "function", callee_key, callee["display_label"], target_key, callee)
        upsert_edge(conn, "calls", source_key, callee_key, {"source": "analyze-target", "relation": "callee"}, 0.85)
    next_hops = [
        preferred_function_label(callee, callee.get("entry", ""))
        for callee in references.get("callees", [])[:5]
        if preferred_function_label(callee, callee.get("entry", ""))
    ]
    add_note(
        conn,
        "analysis",
        f"Analyze target: {seed_kind}:{seed_value}",
        f"{target_key} resolved {seed_kind}:{seed_value} to {function['display_label']}.",
        {
            "target_key": target_key,
            "seed_kind": seed_kind,
            "seed_value": seed_value,
            "function_entry": entry,
            "function_name": function["display_label"],
            "next_hops": next_hops,
        },
    )


def top_target_signals(conn, target_key, limit=6):
    class_rows = conn.execute(
        """
        SELECT class.label, COUNT(*) AS method_hits
        FROM nodes class
        JOIN edges e ON e.dest_key = class.node_key AND e.kind = 'derived-from'
        JOIN nodes fn ON fn.node_key = e.source_key
        WHERE class.target_key = ?
          AND class.kind = 'class'
          AND fn.target_key = ?
          AND fn.kind = 'function'
        GROUP BY class.node_key, class.label
        ORDER BY method_hits DESC, class.label
        LIMIT ?
        """,
        (target_key, target_key, limit * 8),
    ).fetchall()
    classes = []
    for row in class_rows:
        label = row["label"]
        if label and label not in classes:
            classes.append(label)
    if not classes:
        fallback_class_rows = conn.execute(
            """
            SELECT label
            FROM nodes
            WHERE target_key = ?
              AND kind = 'class'
            ORDER BY label
            LIMIT ?
            """,
            (target_key, limit * 8),
        ).fetchall()
        for row in fallback_class_rows:
            label = row["label"]
            if label and label not in classes:
                classes.append(label)

    rows = conn.execute(
        """
        SELECT kind, label, metadata_json
        FROM nodes
        WHERE target_key = ?
          AND kind = 'function'
        ORDER BY
          label
        LIMIT 200
        """,
        (target_key,),
    ).fetchall()
    functions = []
    for row in rows:
        label = row["label"]
        if is_low_signal_function_name(label):
            continue
        if label not in functions:
            functions.append(label)
    selector_rows = conn.execute(
        """
        SELECT selector.label, COUNT(*) AS hits
        FROM edges e
        JOIN nodes selector ON selector.node_key = e.dest_key
        JOIN nodes source ON source.node_key = e.source_key
        WHERE source.target_key = ?
          AND e.kind = 'implements'
          AND selector.kind = 'selector'
        GROUP BY selector.node_key, selector.label
        ORDER BY hits DESC, selector.label
        LIMIT ?
        """,
        (target_key, limit * 8),
    ).fetchall()
    selectors = [row["label"] for row in selector_rows if not is_low_signal_selector(row["label"])]
    return {
        "top_classes": classes[:limit],
        "top_functions": functions[:limit],
        "top_selectors": selectors[:limit],
    }


def derive_unresolved_questions(payload):
    questions = []
    if not payload["cross_target_links_found"]:
        questions.append("Which imports, selectors, or services best connect the current targets into one subsystem?")
    if any(target["has_live_session"] is False for target in payload["targets_visited"]):
        questions.append("Which headless-only targets should be opened live next for tighter follow-up navigation?")
    for seed in payload.get("suggested_seeds", [])[:6]:
        reason = "; ".join(seed.get("reasons", [])[:2])
        questions.append(f"What does {seed['seed']} reveal if followed next? {reason}".strip())
    deduped = []
    for item in questions:
        if item not in deduped:
            deduped.append(item)
    return deduped[:8]


def confidence_ledger(payload):
    if not payload["cross_target_links_found"]:
        return {"high": 0, "medium": 0, "low": 1}
    ledger = {"high": 0, "medium": 0, "low": 0}
    for link in payload["cross_target_links_found"]:
        confidence = float(link.get("confidence", 0.0))
        if confidence >= 0.8:
            ledger["high"] += 1
        elif confidence >= 0.5:
            ledger["medium"] += 1
        else:
            ledger["low"] += 1
    return ledger


def query_seed(conn, kind, value):
    value_like = f"%{value.lower()}%"
    matches = [
        dict(row)
        for row in conn.execute(
            """
            SELECT node_key, kind, label, target_key
            FROM nodes
            WHERE lower(kind) = lower(?) AND lower(label) LIKE ?
            ORDER BY target_key, label
            LIMIT 100
            """,
            (kind, value_like),
        ).fetchall()
    ]
    target_candidates = []
    if kind.lower() == "selector":
        selector_keys = [row["node_key"] for row in matches]
        if selector_keys:
            placeholders = ",".join("?" for _ in selector_keys)
            rows = conn.execute(
                f"""
                SELECT n.target_key, COUNT(*) AS hit_count
                FROM edges e
                JOIN nodes n ON n.node_key = e.source_key
                WHERE e.dest_key IN ({placeholders})
                  AND n.target_key != '*'
                GROUP BY n.target_key
                ORDER BY hit_count DESC, n.target_key
                """,
                selector_keys,
            ).fetchall()
            target_candidates = [dict(row) for row in rows]
    elif kind.lower() == "symbol":
        symbol_keys = [row["node_key"] for row in matches]
        if symbol_keys:
            placeholders = ",".join("?" for _ in symbol_keys)
            rows = conn.execute(
                f"""
                SELECT t.target_key, COUNT(*) AS hit_count
                FROM edges e
                JOIN targets t ON t.target_key = substr(e.source_key, 1, instr(e.source_key, ':framework') - 1)
                WHERE e.kind = 'imports' AND e.dest_key IN ({placeholders})
                GROUP BY t.target_key
                ORDER BY hit_count DESC, t.target_key
                """,
                symbol_keys,
            ).fetchall()
            target_candidates = [dict(row) for row in rows]
    else:
        counts = {}
        for row in matches:
            target_key = row["target_key"]
            if target_key == "*":
                continue
            counts[target_key] = counts.get(target_key, 0) + 1
        target_candidates = [
            {"target_key": key, "hit_count": value}
            for key, value in sorted(counts.items(), key=lambda item: (-item[1], item[0]))
        ]
    return {"seed_kind": kind, "seed_value": value, "matches": matches, "target_candidates": target_candidates}


def report_payload(conn, mission):
    targets = [dict(row) for row in conn.execute("SELECT * FROM targets ORDER BY target_key").fetchall()]
    sessions = [dict(row) for row in conn.execute("SELECT * FROM sessions ORDER BY updated_at DESC").fetchall()]
    links = []
    for row in conn.execute(
        """
        SELECT source_key, dest_key, evidence_json, confidence
        FROM edges
        WHERE kind = 'same-subsystem'
        ORDER BY confidence DESC, source_key, dest_key
        LIMIT 20
        """
    ).fetchall():
        links.append(
            {
                "from": row["source_key"],
                "to": row["dest_key"],
                "evidence": json.loads(row["evidence_json"]),
                "confidence": row["confidence"],
            }
        )
    notes = [
        {
            "kind": row["kind"],
            "title": row["title"],
            "body": row["body"],
            "metadata": json.loads(row["metadata_json"]),
            "created_at": row["created_at"],
        }
        for row in conn.execute(
            "SELECT kind, title, body, metadata_json, created_at FROM notes ORDER BY note_id DESC LIMIT 10"
        ).fetchall()
    ]
    evidence_used = []
    for row in conn.execute(
        "SELECT kind, target_key, path FROM artifacts ORDER BY updated_at DESC LIMIT 20"
    ).fetchall():
        evidence_used.append(
            {"kind": row["kind"], "target_key": row["target_key"], "path": row["path"]}
        )
    current_hypothesis = mission.get("current_hypothesis") or mission.get("goal") or "No hypothesis recorded yet."
    recommended_next_hops = []
    for note in notes:
        for item in note["metadata"].get("next_hops", []):
            inferred = infer_seed(item)
            if inferred and inferred["kind"] == "symbol" and is_low_signal_symbol(inferred["value"]):
                continue
            if item and item not in recommended_next_hops:
                recommended_next_hops.append(item)
    if not recommended_next_hops:
        for link in links[:5]:
            recommended_next_hops.append(
                f"Compare {link['from']} with {link['to']} via shared selectors/imports."
            )
    target_summaries = []
    for target in targets:
        target_summaries.append(
            {
                "target_key": target["target_key"],
                "project_name": target["project_name"],
                "program_name": target["program_name"],
                "signals": top_target_signals(conn, target["target_key"]),
            }
        )
    unresolved_questions = derive_unresolved_questions(
        {
            "targets_visited": [
                {
                    "target_key": target["target_key"],
                    "has_live_session": any(session["target_key"] == target["target_key"] for session in sessions),
                }
                for target in targets
            ],
            "cross_target_links_found": links,
            "suggested_seeds": suggest_seeds(conn, mission)[:12],
        }
    )
    ledger = confidence_ledger({"cross_target_links_found": links})
    return {
        "mission_name": mission.get("mission_name", ""),
        "mission_slug": mission.get("mission_slug", ""),
        "goal": mission.get("goal", ""),
        "mode": mission.get("mode", "trace"),
        "configured_targets": mission.get("targets", []),
        "configured_seeds": mission.get("seeds", []),
        "created_at": mission.get("created_at", ""),
        "updated_at": mission.get("updated_at", ""),
        "finished_at": mission.get("finished_at", ""),
        "current_hypothesis": current_hypothesis,
        "targets_visited": [
            {
                "target_key": target["target_key"],
                "project_name": target["project_name"],
                "program_name": target["program_name"],
                "program_path": target["program_path"],
                "has_live_session": any(session["target_key"] == target["target_key"] for session in sessions),
            }
            for target in targets
        ],
        "evidence_used": evidence_used,
        "cross_target_links_found": links,
        "recommended_next_hops": recommended_next_hops[:8],
        "suggested_seeds": suggest_seeds(conn, mission)[:12],
        "target_summaries": target_summaries,
        "unresolved_questions": unresolved_questions,
        "confidence_ledger": ledger,
        "notes": notes,
    }


def render_report(paths, conn, mission):
    payload = report_payload(conn, mission)
    lines = [
        f"# {payload['mission_name']}",
        "",
        f"Goal: {payload['goal']}",
        f"Mode: {payload['mode']}",
    ]
    if payload["finished_at"]:
        lines.append(f"Finished at: {payload['finished_at']}")
    lines.extend([
        "",
        "## Current hypothesis",
        payload["current_hypothesis"],
        "",
        "## Targets visited",
    ])
    for target in payload["targets_visited"]:
        session_state = "live" if target["has_live_session"] else "headless-only"
        lines.append(f"- {target['target_key']} ({session_state})")
    lines.extend(["", "## Target summaries"])
    for summary in payload["target_summaries"]:
        lines.append(f"- {summary['target_key']}")
        signals = summary["signals"]
        if signals["top_classes"]:
            lines.append(f"  classes: {', '.join(signals['top_classes'][:4])}")
        if signals["top_selectors"]:
            lines.append(f"  selectors: {', '.join(signals['top_selectors'][:4])}")
        if signals["top_functions"]:
            lines.append(f"  functions: {', '.join(signals['top_functions'][:4])}")
    lines.extend(["", "## Cross-target links found"])
    if payload["cross_target_links_found"]:
        for link in payload["cross_target_links_found"][:10]:
            evidence = link["evidence"]
            lines.append(
                f"- {link['from']} -> {link['to']} "
                f"(selectors={evidence.get('shared_selectors', 0)}, imports={evidence.get('shared_imports', 0)}, confidence={link['confidence']:.2f})"
            )
    else:
        lines.append("- No cross-target links recorded yet.")
    lines.extend(["", "## Recommended next hops"])
    for item in payload["recommended_next_hops"] or ["No next hops recorded yet."]:
        lines.append(f"- {item}")
    lines.extend(["", "## Suggested seeds"])
    for item in payload["suggested_seeds"][:8]:
        lines.append(
            f"- {item['seed']} (score={item['score']:.1f}; reasons={'; '.join(item['reasons'])})"
        )
    lines.extend(["", "## Confidence ledger"])
    lines.append(
        f"- high={payload['confidence_ledger']['high']}, medium={payload['confidence_ledger']['medium']}, low={payload['confidence_ledger']['low']}"
    )
    lines.extend(["", "## Unresolved questions"])
    for item in payload["unresolved_questions"] or ["No unresolved questions recorded yet."]:
        lines.append(f"- {item}")
    lines.extend(["", "## Recent notes"])
    for note in payload["notes"][:5]:
        lines.append(f"- [{note['kind']}] {note['title']}: {note['body']}")
    write_json(paths["latest_json"], payload)
    paths["latest_md"].write_text("\n".join(lines) + "\n")
    if payload["finished_at"]:
        casefile = {
            "mission_name": payload["mission_name"],
            "finished_at": payload["finished_at"],
            "current_hypothesis": payload["current_hypothesis"],
            "targets_visited": payload["targets_visited"],
            "target_summaries": payload["target_summaries"],
            "cross_target_links_found": payload["cross_target_links_found"],
            "evidence_used": payload["evidence_used"][:12],
            "recommended_next_hops": payload["recommended_next_hops"],
            "unresolved_questions": payload["unresolved_questions"],
            "confidence_ledger": payload["confidence_ledger"],
        }
        write_json(paths["reports_dir"] / "casefile.json", casefile)
        case_lines = [
            f"# {payload['mission_name']} case file",
            "",
            f"Finished at: {payload['finished_at']}",
            "",
            "## Current hypothesis",
            payload["current_hypothesis"],
            "",
            "## Target summaries",
        ]
        for summary in payload["target_summaries"]:
            case_lines.append(f"- {summary['target_key']}")
            signals = summary["signals"]
            if signals["top_functions"]:
                case_lines.append(f"  top functions: {', '.join(signals['top_functions'][:5])}")
            if signals["top_selectors"]:
                case_lines.append(f"  top selectors: {', '.join(signals['top_selectors'][:5])}")
        case_lines.extend(["", "## Unresolved questions"])
        for item in payload["unresolved_questions"]:
            case_lines.append(f"- {item}")
        (paths["reports_dir"] / "casefile.md").write_text("\n".join(case_lines) + "\n")
    return payload


def cmd_init(args):
    mission_dir = Path(args.mission_dir)
    paths = mission_paths(mission_dir)
    is_new = not paths["mission_file"].exists()
    mission_dir.mkdir(parents=True, exist_ok=True)
    paths["exports_dir"].mkdir(parents=True, exist_ok=True)
    paths["reports_dir"].mkdir(parents=True, exist_ok=True)
    conn = connect_db(paths["graph_db"])
    mission = load_mission(paths)
    previous_goal = mission.get("goal")
    previous_mode = mission.get("mode")
    configured_targets = json.loads(args.targets_json) if args.targets_json else mission.get("targets", [])
    configured_seeds = json.loads(args.seeds_json) if args.seeds_json else mission.get("seeds", [])
    mission.update(
        {
            "mission_name": args.mission_name,
            "mission_slug": slug(args.mission_name),
            "goal": args.goal,
            "mode": args.mode,
            "targets": configured_targets,
            "seeds": configured_seeds,
            "created_at": mission.get("created_at", utc_now()),
            "updated_at": utc_now(),
            "current_hypothesis": mission.get("current_hypothesis", args.goal),
        }
    )
    save_mission(paths, mission)
    if is_new or previous_goal != args.goal or previous_mode != args.mode:
        add_note(conn, "mission", "Mission started", args.goal, {"mode": args.mode})
    add_run(conn, "mission-start", "success", {"goal": args.goal, "mode": args.mode})
    conn.commit()
    render_report(paths, conn, mission)
    print(json.dumps({"ok": True, "mission_dir": str(mission_dir)}, indent=2))


def cmd_register_target(args):
    paths = mission_paths(Path(args.mission_dir))
    conn = connect_db(paths["graph_db"])
    metadata = json.loads(args.metadata_json) if args.metadata_json else {"target_ref": args.target_key}
    upsert_target(
        conn,
        args.target_key,
        project_name=args.project_name,
        program_name=args.program_name,
        binary_path=args.binary_path,
        program_path=args.program_path,
        export_dir=args.export_dir,
        metadata=metadata,
    )
    conn.commit()
    touch_mission(paths)
    print(json.dumps({"ok": True, "target_key": args.target_key}, indent=2))


def cmd_register_session(args):
    paths = mission_paths(Path(args.mission_dir))
    conn = connect_db(paths["graph_db"])
    session_file = Path(args.session_file)
    session = load_json(session_file)
    session["session_file"] = str(session_file)
    upsert_session(conn, session)
    conn.commit()
    touch_mission(paths)
    print(json.dumps({"ok": True, "session_id": session.get("session_id", "")}, indent=2))


def cmd_ingest_export(args):
    paths = mission_paths(Path(args.mission_dir))
    conn = connect_db(paths["graph_db"])
    export_dir = Path(args.export_dir)
    ingest_export_bundle(conn, args.target_key, export_dir)
    conn.commit()
    touch_mission(paths)
    print(json.dumps({"ok": True, "target_key": args.target_key, "export_dir": str(export_dir)}, indent=2))


def cmd_query_seed(args):
    paths = mission_paths(Path(args.mission_dir))
    conn = connect_db(paths["graph_db"])
    result = query_seed(conn, args.seed_kind, args.seed_value)
    print(json.dumps(result, indent=2))


def cmd_ingest_selector_trace(args):
    paths = mission_paths(Path(args.mission_dir))
    conn = connect_db(paths["graph_db"])
    trace_payload = load_json(Path(args.trace_file))
    analysis_payload = load_json(Path(args.analysis_file)) if args.analysis_file else None
    ingest_selector_trace(conn, args.target_key, args.selector, trace_payload, analysis_payload)
    conn.commit()
    touch_mission(paths)
    print(json.dumps({"ok": True, "target_key": args.target_key, "selector": args.selector}, indent=2))


def cmd_ingest_analyze_target(args):
    paths = mission_paths(Path(args.mission_dir))
    conn = connect_db(paths["graph_db"])
    payload = load_json(Path(args.analysis_file))
    ingest_analyze_target(conn, args.target_key, args.seed_kind, args.seed_value, payload)
    conn.commit()
    touch_mission(paths)
    print(json.dumps({"ok": True, "target_key": args.target_key, "seed": f"{args.seed_kind}:{args.seed_value}"}, indent=2))


def cmd_render_report(args):
    paths = mission_paths(Path(args.mission_dir))
    conn = connect_db(paths["graph_db"])
    mission = load_mission(paths)
    payload = render_report(paths, conn, mission)
    print(json.dumps(payload, indent=2))


def cmd_status(args):
    paths = mission_paths(Path(args.mission_dir))
    conn = connect_db(paths["graph_db"])
    mission = load_mission(paths)
    payload = report_payload(conn, mission)
    payload["graph_db"] = str(paths["graph_db"])
    print(json.dumps(payload, indent=2))


def cmd_add_note(args):
    paths = mission_paths(Path(args.mission_dir))
    conn = connect_db(paths["graph_db"])
    metadata = json.loads(args.metadata_json) if args.metadata_json else {}
    add_note(conn, args.kind, args.title, args.body, metadata)
    add_run(conn, "mission-note", "success", {"kind": args.kind, "title": args.title})
    conn.commit()
    touch_mission(paths)
    print(json.dumps({"ok": True, "kind": args.kind, "title": args.title}, indent=2))


def cmd_add_artifact(args):
    paths = mission_paths(Path(args.mission_dir))
    conn = connect_db(paths["graph_db"])
    metadata = json.loads(args.metadata_json) if args.metadata_json else {}
    add_artifact(conn, args.target_key, args.kind, Path(args.path), metadata)
    conn.commit()
    touch_mission(paths)
    print(json.dumps({"ok": True, "kind": args.kind, "path": args.path}, indent=2))


def cmd_set_hypothesis(args):
    paths = mission_paths(Path(args.mission_dir))
    mission = load_mission(paths)
    mission["current_hypothesis"] = args.value
    save_mission(paths, mission)
    print(json.dumps({"ok": True, "current_hypothesis": args.value}, indent=2))


def cmd_suggest_seeds(args):
    paths = mission_paths(Path(args.mission_dir))
    conn = connect_db(paths["graph_db"])
    mission = load_mission(paths)
    print(json.dumps({"suggestions": suggest_seeds(conn, mission)}, indent=2))


def cmd_finish(args):
    paths = mission_paths(Path(args.mission_dir))
    conn = connect_db(paths["graph_db"])
    mission = load_mission(paths)
    metadata = json.loads(args.metadata_json) if args.metadata_json else {}
    finished_at = utc_now()
    mission["finished_at"] = finished_at
    if args.report_path:
        mission["last_report_path"] = args.report_path
    if args.summary:
        add_note(conn, "finish", "Mission finished", args.summary, metadata)
    add_run(conn, "mission-finish", args.status, metadata)
    save_mission(paths, mission)
    conn.commit()
    payload = render_report(paths, conn, mission)
    print(
        json.dumps(
            {
                "ok": True,
                "finished_at": finished_at,
                "report_path": args.report_path,
                "summary": args.summary,
                "status": args.status,
                "report": payload,
            },
            indent=2,
        )
    )


def build_parser():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init")
    init_parser.add_argument("--mission-dir", required=True)
    init_parser.add_argument("--mission-name", required=True)
    init_parser.add_argument("--goal", required=True)
    init_parser.add_argument("--mode", default="trace")
    init_parser.add_argument("--targets-json", default="[]")
    init_parser.add_argument("--seeds-json", default="[]")
    init_parser.set_defaults(func=cmd_init)

    target_parser = subparsers.add_parser("register-target")
    target_parser.add_argument("--mission-dir", required=True)
    target_parser.add_argument("--target-key", required=True)
    target_parser.add_argument("--project-name", default="")
    target_parser.add_argument("--program-name", default="")
    target_parser.add_argument("--binary-path", default="")
    target_parser.add_argument("--program-path", default="")
    target_parser.add_argument("--export-dir", default="")
    target_parser.add_argument("--metadata-json", default="")
    target_parser.set_defaults(func=cmd_register_target)

    session_parser = subparsers.add_parser("register-session")
    session_parser.add_argument("--mission-dir", required=True)
    session_parser.add_argument("--session-file", required=True)
    session_parser.set_defaults(func=cmd_register_session)

    export_parser = subparsers.add_parser("ingest-export")
    export_parser.add_argument("--mission-dir", required=True)
    export_parser.add_argument("--target-key", required=True)
    export_parser.add_argument("--export-dir", required=True)
    export_parser.set_defaults(func=cmd_ingest_export)

    query_parser = subparsers.add_parser("query-seed")
    query_parser.add_argument("--mission-dir", required=True)
    query_parser.add_argument("--seed-kind", required=True)
    query_parser.add_argument("--seed-value", required=True)
    query_parser.set_defaults(func=cmd_query_seed)

    selector_trace_parser = subparsers.add_parser("ingest-selector-trace")
    selector_trace_parser.add_argument("--mission-dir", required=True)
    selector_trace_parser.add_argument("--target-key", required=True)
    selector_trace_parser.add_argument("--selector", required=True)
    selector_trace_parser.add_argument("--trace-file", required=True)
    selector_trace_parser.add_argument("--analysis-file", default="")
    selector_trace_parser.set_defaults(func=cmd_ingest_selector_trace)

    analyze_parser = subparsers.add_parser("ingest-analyze-target")
    analyze_parser.add_argument("--mission-dir", required=True)
    analyze_parser.add_argument("--target-key", required=True)
    analyze_parser.add_argument("--seed-kind", required=True)
    analyze_parser.add_argument("--seed-value", required=True)
    analyze_parser.add_argument("--analysis-file", required=True)
    analyze_parser.set_defaults(func=cmd_ingest_analyze_target)

    render_parser = subparsers.add_parser("render-report")
    render_parser.add_argument("--mission-dir", required=True)
    render_parser.set_defaults(func=cmd_render_report)

    status_parser = subparsers.add_parser("status")
    status_parser.add_argument("--mission-dir", required=True)
    status_parser.set_defaults(func=cmd_status)

    note_parser = subparsers.add_parser("add-note")
    note_parser.add_argument("--mission-dir", required=True)
    note_parser.add_argument("--kind", required=True)
    note_parser.add_argument("--title", required=True)
    note_parser.add_argument("--body", required=True)
    note_parser.add_argument("--metadata-json", default="{}")
    note_parser.set_defaults(func=cmd_add_note)

    artifact_parser = subparsers.add_parser("add-artifact")
    artifact_parser.add_argument("--mission-dir", required=True)
    artifact_parser.add_argument("--target-key", required=True)
    artifact_parser.add_argument("--kind", required=True)
    artifact_parser.add_argument("--path", required=True)
    artifact_parser.add_argument("--metadata-json", default="{}")
    artifact_parser.set_defaults(func=cmd_add_artifact)

    hypothesis_parser = subparsers.add_parser("set-hypothesis")
    hypothesis_parser.add_argument("--mission-dir", required=True)
    hypothesis_parser.add_argument("--value", required=True)
    hypothesis_parser.set_defaults(func=cmd_set_hypothesis)

    suggest_parser = subparsers.add_parser("suggest-seeds")
    suggest_parser.add_argument("--mission-dir", required=True)
    suggest_parser.set_defaults(func=cmd_suggest_seeds)

    finish_parser = subparsers.add_parser("finish")
    finish_parser.add_argument("--mission-dir", required=True)
    finish_parser.add_argument("--status", default="success")
    finish_parser.add_argument("--summary", default="")
    finish_parser.add_argument("--report-path", default="")
    finish_parser.add_argument("--metadata-json", default="{}")
    finish_parser.set_defaults(func=cmd_finish)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
