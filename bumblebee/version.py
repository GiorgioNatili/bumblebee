"""
Version string resolution.

Reads the version from the bundled version.txt, with optional override
via the BUMBLEBEE_VERSION environment variable (matching the Go build
-ldflags pattern).
"""

import importlib.resources
import os
import platform
import subprocess
from pathlib import Path


def _read_version_file() -> str:
    """Read version from the bundled version.txt."""
    try:
        return importlib.resources.read_text("bumblebee", "version.txt").strip()
    except Exception:
        return "0.1.1"


_FALLBACK_VERSION = _read_version_file()


def current_version() -> str:
    """Return the resolved version string.

    Precedence:
    1. BUMBLEBEE_VERSION env var (settable via ``BUMBLEBEE_VERSION=...``)
    2. The compiled-in version.txt default (``0.1.1``)
    """
    env_ver = os.environ.get("BUMBLEBEE_VERSION", "").strip()
    if env_ver:
        return env_ver
    return _FALLBACK_VERSION


def _git_revision() -> tuple[str, str]:
    """Attempt to read VCS revision and build time via git.

    Returns (revision, build_time) or ("unknown", "unknown").
    """
    try:
        rev = subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            stderr=subprocess.DEVNULL, text=True,
        ).strip()
    except Exception:
        rev = "unknown"

    try:
        built = subprocess.check_output(
            ["git", "log", "-1", "--format=%cI"],
            stderr=subprocess.DEVNULL, text=True,
        ).strip()
    except Exception:
        built = "unknown"

    # Check for dirty working tree
    if rev != "unknown":
        try:
            status = subprocess.check_output(
                ["git", "status", "--porcelain"],
                stderr=subprocess.DEVNULL, text=True,
            ).strip()
            if status:
                rev += "-dirty"
        except Exception:
            pass

    return rev, built


def version_string() -> str:
    """Return the multi-line version output for ``bumblebee version``."""
    rev, built = _git_revision()
    return (
        f"bumblebee {current_version()}\n"
        f"commit: {rev}\n"
        f"built:  {built}\n"
        f"python: {platform.python_version()}"
    )
