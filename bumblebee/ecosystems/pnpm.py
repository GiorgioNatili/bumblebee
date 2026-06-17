"""
pnpm lockfile and store package.json scanner.
"""

import json
import os
import re
from typing import Optional

from bumblebee.ecosystems.base import BaseScanner
from bumblebee.model import ECOSYSTEM_NPM, Record
from bumblebee import normalize

ECOSYSTEM = ECOSYSTEM_NPM


def is_lockfile(base: str) -> bool:
    return base == "pnpm-lock.yaml" or base == "pnpm-lock.yml"


def is_pnpm_store_package_json(path: str) -> tuple[bool, str, str, str]:
    """Check if path is a pnpm store package.json.

    Returns (True, projectPath, name, version).
    Pattern: .../pnpm-store/<hash>/<name>/<version>/package.json
    """
    if os.path.basename(path) != "package.json":
        return False, "", "", ""
    parts = path.replace("\\", "/").split("/")
    # Look for pnpm-store in path
    for i, p in enumerate(parts):
        if "pnpm-store" in p or ".pnpm-store" in p:
            # The structure is pnpm-store/<hash>/<name>/<version>/package.json
            # or pnpm-store/v3/files/<hash>/package.json
            tail = parts[i + 1:]
            if len(tail) >= 3:
                # <name>/<version>/package.json
                name = tail[-3]
                version = tail[-2]
                project_path = "/".join(parts[:i])
                return True, project_path, name, version
    return False, "", "", ""


class Scanner(BaseScanner):

    def scan_lockfile(self, path: str, base: Record):
        data = self.read_bounded(path)
        if data is None:
            return
        project_path = os.path.dirname(path)
        text = data.decode("utf-8", errors="replace")
        packages = _parse_pnpm_lock_yaml(text)
        for name, version in packages:
            if not name or not version:
                continue
            r = Record(
                ecosystem=ECOSYSTEM,
                package_name=name,
                normalized_name=normalize.npm(name),
                version=version,
                project_path=project_path,
                package_manager="pnpm",
                source_type="pnpm-lockfile",
                source_file=path,
                confidence="high",
            )
            self._apply_base(r, base)
            self.emit(r)

    def scan_store_package_json(self, path: str, project_path: str,
                                name: str, version: str, base: Record):
        """Scan a pnpm store package.json for additional metadata."""
        data = self.read_bounded(path)
        if data is None:
            # Still emit with the info from the path
            pass
        r = Record(
            ecosystem=ECOSYSTEM,
            package_name=name,
            normalized_name=normalize.npm(name),
            version=version,
            project_path=project_path,
            package_manager="pnpm",
            source_type="pnpm-store",
            source_file=path,
            confidence="medium",
        )
        if data:
            try:
                pj = json.loads(data)
                if pj.get("scripts"):
                    scripts = _lifecycle_script_keys(pj["scripts"])
                    r.has_lifecycle_scripts = bool(scripts)
                    r.lifecycle_scripts = scripts
            except json.JSONDecodeError:
                pass
        self._apply_base(r, base)
        self.emit(r)

    def _apply_base(self, r: Record, base: Record):
        for attr in ("record_type", "schema_version", "scanner_name",
                     "scanner_version", "run_id", "scan_time", "endpoint",
                     "profile", "root_kind"):
            val = getattr(base, attr)
            if val:
                setattr(r, attr, val)


def _parse_pnpm_lock_yaml(text: str) -> list[tuple[str, str]]:
    """Simple YAML parser for pnpm-lock.yaml's packages section.

    Returns list of (name, version) tuples.
    """
    packages = []
    in_packages = False
    current_name = ""
    for line in text.splitlines():
        stripped = line.rstrip()
        if stripped == "packages:":
            in_packages = True
            continue
        if in_packages:
            # Top-level key under packages: starts with whitespace + "/"
            m = re.match(r"^\s{2}(['\"]?)(/.+?)\1:", stripped)
            if m:
                current_name = m.group(2).strip("/")
                continue
            # Nested keys like versions/...
            m = re.match(r"^\s{4,}(['\"]?)(\S+?)\1:", stripped)
            if m:
                key = m.group(2)
                if key == "version":
                    # Version line: "  version: 1.2.3"
                    val_m = re.search(r":\s*(.+)$", stripped)
                    if val_m and current_name:
                        packages.append((current_name, val_m.group(1).strip().strip("'\"")))
            # Detect end of packages section
            if stripped and not stripped.startswith(" ") and ":" in stripped:
                if stripped != "packages:":
                    in_packages = False
    return packages


def _lifecycle_script_keys(scripts: dict) -> list[str]:
    lifecycle = {"preinstall", "install", "postinstall", "prepare",
                 "preprepare", "postprepare"}
    return sorted(k for k in lifecycle if scripts.get(k, "").strip())
