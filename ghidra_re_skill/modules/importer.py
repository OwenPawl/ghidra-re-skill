"""Import and analysis: import_analyze, import_macos_framework, run_script."""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from typing import Any

from ghidra_re_skill.core.config import cfg
from ghidra_re_skill.core.ghidra_locator import analyze_headless_path
from ghidra_re_skill.core.subprocess_utils import find_python, run
from ghidra_re_skill.core.utils import flag_enabled, sanitize_name, timestamp


def _python() -> str:
    return find_python()


def _headless() -> Path:
    auto_configure()
    headless = analyze_headless_path(cfg.ghidra_install_dir)
    if not headless:
        raise RuntimeError(f"analyzeHeadless not found in {cfg.ghidra_install_dir}")
    return headless


def auto_configure() -> None:
    from ghidra_re_skill.modules.bridge import auto_configure as _ac
    _ac()


def _optional_headless_args() -> list[str]:
    args = []
    if cfg.analysis_timeout_per_file:
        args += ["-analysisTimeoutPerFile", cfg.analysis_timeout_per_file]
    if cfg.max_cpu:
        args += ["-max-cpu", cfg.max_cpu]
    return args


def import_analyze(binary_path: str | Path, project_name: str | None = None) -> dict:
    """Import and analyze a binary with Ghidra analyzeHeadless.

    Returns a dict with project/program/log info.
    """
    from ghidra_re_skill.modules.bridge import ensure_workspace, export_env, require_tools

    binary = Path(binary_path)
    if not binary.exists():
        raise RuntimeError(f"binary not found: {binary}")

    if project_name is None:
        project_name = sanitize_name(binary.stem)

    program_name = binary.name
    project_location = cfg.project_location(project_name)
    log_dir = cfg.log_dir(project_name)
    ts = timestamp()
    log_file = log_dir / f"import-{ts}.log"
    script_log = log_dir / f"import-{ts}.script.log"
    script_path = cfg.script_path_str()

    require_tools()
    env = export_env()
    ensure_workspace()
    project_location.mkdir(parents=True, exist_ok=True)
    log_dir.mkdir(parents=True, exist_ok=True)

    headless = _headless()
    cmd: list[str] = [
        str(headless),
        str(project_location),
        project_name,
        "-import", str(binary),
        "-overwrite",
        "-scriptPath", script_path,
    ]
    if flag_enabled(cfg.import_demangle):
        cmd += ["-postScript", "DemangleAllScript.java"]
    cmd += _optional_headless_args()
    cmd += ["-log", str(log_file), "-scriptlog", str(script_log)]

    run(cmd, env=env, check=True)

    summary = _summarize_import_log(log_file, script_log)

    return {
        "ok": True,
        "binary": str(binary),
        "project_name": project_name,
        "program_name": program_name,
        "project_file": str(cfg.project_file(project_name)),
        "log": str(log_file),
        "script_log": str(script_log),
        "warnings": summary,
    }


def _summarize_import_log(log_file: Path, script_log: Path) -> dict:
    unresolved_count = 0
    system = private = swift_rt = other = 0
    symbol_length_failures = 0
    demangle_failures = 0

    if log_file.exists():
        text = log_file.read_text(encoding="utf-8", errors="replace")
        for line in text.splitlines():
            if "-> not found in project" in line:
                unresolved_count += 1
                m = re.search(r"\[(.+?)\]", line)
                path = m.group(1) if m else ""
                if path.startswith("/usr/lib/swift/"):
                    swift_rt += 1
                elif path.startswith("/System/Library/PrivateFrameworks/"):
                    private += 1
                elif path.startswith("/System/Library/Frameworks/") or path.startswith("/usr/lib/"):
                    system += 1
                else:
                    other += 1
            if "Symbol name exceeds maximum length" in line:
                symbol_length_failures += 1

    if script_log.exists():
        with script_log.open(encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if "Unable to demangle:" in line:
                    demangle_failures += 1

    return {
        "unresolved_count": unresolved_count,
        "unresolved_system": system,
        "unresolved_private": private,
        "unresolved_swift_runtime": swift_rt,
        "unresolved_other": other,
        "symbol_length_failures": symbol_length_failures,
        "demangle_failures": demangle_failures,
    }


def import_macos_framework(
    framework_path: str | Path,
    project_name: str | None = None,
) -> dict:
    """Import a macOS framework using the macOS import backend."""
    from ghidra_re_skill.modules.bridge import require_tools, export_env

    framework = Path(framework_path)
    if not framework.exists():
        raise RuntimeError(f"framework not found: {framework}")

    backend = cfg.skill_root / "scripts" / "ghidra_macos_import_backend.py"
    if not backend.exists():
        raise RuntimeError(f"macOS import backend not found at {backend}")

    cmd = [_python(), str(backend)]
    if project_name:
        cmd += ["--project-name", project_name]
    cmd += [str(framework)]

    require_tools()
    env = export_env()
    result = run(cmd, env=env, capture_output=True, check=True)
    try:
        return json.loads(result.stdout.decode())
    except Exception:
        return {"ok": True, "output": result.stdout.decode().strip()}


def run_script(
    script_name: str,
    project_name: str,
    program_name: str | None = None,
    script_args: list[str] | None = None,
    extra_script_paths: list[Path] | None = None,
) -> dict:
    """Run a Ghidra headless script against an existing project/program."""
    from ghidra_re_skill.modules.bridge import ensure_workspace, export_env, require_tools

    project_file = cfg.project_file(project_name)
    if not project_file.exists():
        raise RuntimeError(f"project {project_name!r} not found at {project_file}")

    project_location = cfg.project_location(project_name)
    log_dir = cfg.log_dir(project_name)
    ts = timestamp()
    log_file = log_dir / f"script-{ts}.log"
    script_log = log_dir / f"script-{ts}.script.log"
    script_path = cfg.script_path_str(extra_script_paths)

    require_tools()
    env = export_env()
    log_dir.mkdir(parents=True, exist_ok=True)

    headless = _headless()
    cmd: list[str] = [
        str(headless),
        str(project_location),
        project_name,
        "-readOnly",
        "-scriptPath", script_path,
        "-postScript", script_name,
    ]
    if script_args:
        cmd += script_args
    if program_name:
        cmd += ["-process", program_name]
    cmd += _optional_headless_args()
    cmd += ["-log", str(log_file), "-scriptlog", str(script_log)]

    run(cmd, env=env, check=True)

    return {
        "ok": True,
        "project_name": project_name,
        "script_name": script_name,
        "log": str(log_file),
        "script_log": str(script_log),
    }
