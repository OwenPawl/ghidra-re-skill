#!/usr/bin/env python3

import argparse
import datetime as dt
import hashlib
import json
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


def register_framework_node(conn, target_key, summary):
    label = summary.get("program_name", target_key)
    key = framework_node_key(target_key)
    upsert_node(conn, "framework", key, label, target_key, summary)
    return key


def ingest_export_bundle(conn, target_key, export_dir: Path):
    summary = load_json(export_dir / "program_summary.json")
    objc = load_json(export_dir / "objc_metadata.json")
    functions = load_json(export_dir / "function_inventory.json")
    symbols = load_json(export_dir / "symbols.json")
    strings = load_json(export_dir / "strings.json")

    framework_key = register_framework_node(conn, target_key, summary)

    for kind, filename in [
        ("program-summary", "program_summary.json"),
        ("objc-metadata", "objc_metadata.json"),
        ("function-inventory", "function_inventory.json"),
        ("symbols", "symbols.json"),
        ("strings", "strings.json"),
    ]:
        add_artifact(conn, target_key, kind, export_dir / filename)

    for item in functions.get("functions", []):
        node_key = function_node_key(target_key, item.get("entry", ""))
        upsert_node(conn, "function", node_key, item.get("name", ""), target_key, item)
        upsert_edge(conn, "derived-from", node_key, framework_key, {"source": "function_inventory"}, 0.9)

    for class_name in objc.get("classes", []):
        class_key = class_node_key(target_key, class_name)
        upsert_node(conn, "class", class_key, class_name, target_key, {"source": "objc_metadata"})
        upsert_edge(conn, "derived-from", class_key, framework_key, {"source": "objc_metadata"}, 0.8)

    for selector in objc.get("selectors", []):
        selector_key = global_selector_key(selector)
        upsert_node(conn, "selector", selector_key, selector, "*", {"source": "objc_metadata"})

    for method in objc.get("methods", []):
        selector = method.get("selector", "")
        entry = method.get("entry", "")
        class_name = method.get("class_name", "")
        if not selector or not entry:
            continue
        function_key = function_node_key(target_key, entry)
        selector_key = global_selector_key(selector)
        upsert_node(conn, "selector", selector_key, selector, "*", {"source": "objc_metadata"})
        upsert_edge(conn, "implements", function_key, selector_key, {"source": "objc_metadata", "method": method.get("name", "")}, 0.95)
        if class_name:
            class_key = class_node_key(target_key, class_name)
            upsert_node(conn, "class", class_key, class_name, target_key, {"source": "objc_metadata"})
            upsert_edge(conn, "derived-from", function_key, class_key, {"source": "objc_metadata"}, 0.85)

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
        upsert_node(conn, "function", fn_key, name or entry, target_key, item)
        upsert_edge(conn, "implements", fn_key, selector_key, {"source": "selector-trace", "match_kind": item.get("match_kind", "")}, 0.98)
        upsert_edge(conn, "derived-from", fn_key, framework_key, {"source": "selector-trace"}, 0.85)
    for item in sender_functions:
        entry = item.get("entry", "")
        name = item.get("name", "")
        if not entry:
            continue
        fn_key = function_node_key(target_key, entry)
        upsert_node(conn, "function", fn_key, name or entry, target_key, item)
        upsert_edge(conn, "references", fn_key, selector_key, {"source": "selector-trace"}, 0.8)
    if analysis_payload:
        ingest_analyze_target(conn, target_key, "selector", selector, analysis_payload)
    next_hops = [item.get("name", "") for item in implementations[:3]] + [item.get("name", "") for item in sender_functions[:2]]
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
    upsert_node(conn, "function", source_key, function.get("name", entry), target_key, function)
    upsert_edge(conn, "derived-from", source_key, framework_key, {"source": "analyze-target"}, 0.9)
    references = payload.get("references", {})
    for caller in references.get("callers", []):
        caller_entry = caller.get("entry", "")
        if not caller_entry:
            continue
        caller_key = function_node_key(target_key, caller_entry)
        upsert_node(conn, "function", caller_key, caller.get("name", caller_entry), target_key, caller)
        upsert_edge(conn, "calls", caller_key, source_key, {"source": "analyze-target", "relation": "caller"}, 0.85)
    for callee in references.get("callees", []):
        callee_entry = callee.get("entry", "")
        if not callee_entry:
            continue
        callee_key = function_node_key(target_key, callee_entry)
        upsert_node(conn, "function", callee_key, callee.get("name", callee_entry), target_key, callee)
        upsert_edge(conn, "calls", source_key, callee_key, {"source": "analyze-target", "relation": "callee"}, 0.85)
    next_hops = [callee.get("name", "") for callee in references.get("callees", [])[:5] if callee.get("name")]
    add_note(
        conn,
        "analysis",
        f"Analyze target: {seed_kind}:{seed_value}",
        f"{target_key} resolved {seed_kind}:{seed_value} to {function.get('name', entry)}.",
        {
            "target_key": target_key,
            "seed_kind": seed_kind,
            "seed_value": seed_value,
            "function_entry": entry,
            "next_hops": next_hops,
        },
    )


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
            if item and item not in recommended_next_hops:
                recommended_next_hops.append(item)
    if not recommended_next_hops:
        for link in links[:5]:
            recommended_next_hops.append(
                f"Compare {link['from']} with {link['to']} via shared selectors/imports."
            )
    return {
        "mission_name": mission.get("mission_name", ""),
        "mission_slug": mission.get("mission_slug", ""),
        "goal": mission.get("goal", ""),
        "mode": mission.get("mode", "trace"),
        "configured_targets": mission.get("targets", []),
        "configured_seeds": mission.get("seeds", []),
        "created_at": mission.get("created_at", ""),
        "updated_at": mission.get("updated_at", ""),
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
        "notes": notes,
    }


def render_report(paths, conn, mission):
    payload = report_payload(conn, mission)
    lines = [
        f"# {payload['mission_name']}",
        "",
        f"Goal: {payload['goal']}",
        f"Mode: {payload['mode']}",
        "",
        "## Current hypothesis",
        payload["current_hypothesis"],
        "",
        "## Targets visited",
    ]
    for target in payload["targets_visited"]:
        session_state = "live" if target["has_live_session"] else "headless-only"
        lines.append(f"- {target['target_key']} ({session_state})")
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
    lines.extend(["", "## Recent notes"])
    for note in payload["notes"][:5]:
        lines.append(f"- [{note['kind']}] {note['title']}: {note['body']}")
    write_json(paths["latest_json"], payload)
    paths["latest_md"].write_text("\n".join(lines) + "\n")
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
    upsert_target(
        conn,
        args.target_key,
        project_name=args.project_name,
        program_name=args.program_name,
        binary_path=args.binary_path,
        program_path=args.program_path,
        export_dir=args.export_dir,
        metadata={"target_ref": args.target_key},
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

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
