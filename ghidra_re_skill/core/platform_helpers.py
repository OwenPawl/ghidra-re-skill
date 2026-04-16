"""Cross-platform helpers: OS detection, path resolution, config dirs."""

from __future__ import annotations

import os
import platform
from pathlib import Path


def get_platform() -> str:
    """Return 'macos', 'windows', or 'linux'."""
    s = platform.system()
    if s == "Darwin":
        return "macos"
    if s == "Windows":
        return "windows"
    return "linux"


def get_config_home() -> Path:
    """Return the user-specific config directory for ghidra-re."""
    p = get_platform()
    if p == "macos":
        return Path.home() / ".config" / "ghidra-re"
    if p == "windows":
        appdata = os.environ.get("APPDATA")
        if appdata:
            return Path(appdata) / "ghidra-re"
        return Path.home() / "AppData" / "Roaming" / "ghidra-re"
    return Path.home() / ".config" / "ghidra-re"


def get_skill_root() -> Path:
    """Return the root directory of this skill installation."""
    return Path(__file__).parent.parent


def get_workspace_root() -> Path:
    """Return the default workspace root (GHIDRA_WORKSPACE env or ~/ghidra-projects)."""
    env = os.environ.get("GHIDRA_WORKSPACE")
    if env:
        return Path(env)
    return Path.home() / "ghidra-projects"


def is_windows() -> bool:
    return get_platform() == "windows"


def is_macos() -> bool:
    return get_platform() == "macos"


def is_linux() -> bool:
    return get_platform() == "linux"
