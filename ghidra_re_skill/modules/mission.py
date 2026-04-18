"""Mission management: start, status, finish, autopilot, report, trace."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from ghidra_re_skill.core.config import cfg
from ghidra_re_skill.core.subprocess_utils import find_python, run
from ghidra_re_skill.core.utils import sanitize_name


def _python() -> str:
    return find_python()


def _backend() -> Path:
    return cfg.mission_backend()


def start(
    mission_name: str,
    goal: str,
    targets: list[str],
    seeds: list[str] | None = None,
    mode: str = "trace",
) -> dict:
    """Start a mission: init, resolve targets, export bundles, register sessions."""
    if not goal:
        raise ValueError("goal is required")
    if not targets:
        raise ValueError("at least one target is required")

    seeds = seeds or []
    mission_dir = cfg.investigation_dir(mission_name)
    mission_dir.mkdir(parents=True, exist_ok=True)

    py = _python()
    backend = _backend()

    result = run(
        [
            py, str(backend), "init",
            "--mission-dir", str(mission_dir),
            "--mission-name", mission_name,
            "--goal", goal,
            "--mode", mode,
            "--targets-json", json.dumps(targets),
            "--seeds-json", json.dumps(seeds),
        ],
        capture_output=True,
        check=True,
    )

    return {
        "ok": True,
        "mission_name": mission_name,
        "mission_dir": str(mission_dir),
        "targets": targets,
    }


def status(mission_name: str) -> dict:
    """Return the status of a mission."""
    mission_dir = cfg.investigation_dir(mission_name)
    if not mission_dir.exists():
        raise RuntimeError(f"mission {mission_name!r} not found at {mission_dir}")
    py = _python()
    result = run(
        [py, str(_backend()), "status", "--mission-dir", str(mission_dir)],
        capture_output=True,
        check=True,
    )
    return json.loads(result.stdout.decode())


def finish(mission_name: str) -> dict:
    """Finish a mission."""
    mission_dir = cfg.investigation_dir(mission_name)
    if not mission_dir.exists():
        raise RuntimeError(f"mission {mission_name!r} not found at {mission_dir}")
    py = _python()
    result = run(
        [py, str(_backend()), "finish", "--mission-dir", str(mission_dir)],
        capture_output=True,
        check=True,
    )
    try:
        return json.loads(result.stdout.decode())
    except Exception:
        return {"ok": True, "message": result.stdout.decode().strip()}


def report(mission_name: str) -> dict:
    """Render the mission report."""
    mission_dir = cfg.investigation_dir(mission_name)
    if not mission_dir.exists():
        raise RuntimeError(f"mission {mission_name!r} not found at {mission_dir}")
    py = _python()
    result = run(
        [py, str(_backend()), "render-report", "--mission-dir", str(mission_dir)],
        capture_output=True,
        check=True,
    )
    report_file = mission_dir / "reports" / "latest.md"
    return {
        "ok": True,
        "report_file": str(report_file),
        "exists": report_file.exists(),
    }


def trace(mission_name: str, seed: str, extra_args: list[str] | None = None) -> dict:
    """Trace a seed in a mission."""
    mission_dir = cfg.investigation_dir(mission_name)
    if not mission_dir.exists():
        raise RuntimeError(f"mission {mission_name!r} not found at {mission_dir}")
    py = _python()
    cmd = [
        py, str(_backend()), "trace",
        "--mission-dir", str(mission_dir),
        "--seed", seed,
    ]
    if extra_args:
        cmd.extend(extra_args)
    result = run(cmd, capture_output=True, check=True)
    try:
        return json.loads(result.stdout.decode())
    except Exception:
        return {"ok": True, "output": result.stdout.decode().strip()}


def autopilot(mission_name: str) -> dict:
    """Run mission autopilot."""
    mission_dir = cfg.investigation_dir(mission_name)
    if not mission_dir.exists():
        raise RuntimeError(f"mission {mission_name!r} not found at {mission_dir}")
    py = _python()
    result = run(
        [py, str(_backend()), "autopilot", "--mission-dir", str(mission_dir)],
        capture_output=True,
        check=True,
    )
    try:
        return json.loads(result.stdout.decode())
    except Exception:
        return {"ok": True, "output": result.stdout.decode().strip()}
