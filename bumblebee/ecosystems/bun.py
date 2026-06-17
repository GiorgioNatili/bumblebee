"""
Bun lockfile scanner: bun.lock (text format) and bun.lockb (binary, noted only).
"""

import json
import os
import re
from typing import Optional

from bumblebee.ecosystems.base import BaseScanner
from bumblebee.model import ECOSYSTEM_NPM, Record
from bumblebee import normalize

ECOSYSTEM = ECOSYSTEM_NPM
# Bun uses npm ecosystem; package_manager is set to "bun"


def is_text_lockfile(base: str) -> bool:
    return base == "bun.lock"


def is_binary_lockfile(base: str) -> bool:
    return base == "bun.lockb"


class Scanner(BaseScanner):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._binary_lockfiles = set()

    def note_binary_lockfile(self, path: str):
        """Record a binary lockfile path. No parsing is done."""
        self._binary_lockfiles.add(path)

    def scan_text_lockfile(self, path: str, base: Record):
        data = self.read_bounded(path)
        if data is None:
            return
        project_path = os.path.dirname(path)
        try:
            doc = json.loads(data)
        except json.JSONDecodeError:
            # Bun's bun.lock is sometimes a JSON-like format.
            # Try TOML-like or fallback to line parsing.
            _parse_bun_lock_text(data, path, project_path, base, self)
            return

        # Bun JSON lockfile format
        _parse_bun_lock_json(doc, path, project_path, base, self)

    def _apply_base(self, r: Record, base: Record):
        for attr in ("record_type", "schema_version", "scanner_name",
                     "scanner_version", "run_id", "scan_time", "endpoint",
                     "profile", "root_kind"):
            val = getattr(base, attr)
            if val:
                setattr(r, attr, val)


def _parse_bun_lock_json(doc: dict, path: str, project_path: str,
                          base: Record, scanner: Scanner):
    """Parse Bun's JSON lockfile format."""
    # Bun lockfiles can have "packages" or "lockfileVersion"
    packages = doc
    if "packages" in doc:
        packages = doc["packages"]
    if isinstance(packages, dict):
        for key, entry in packages.items():
            if not isinstance(entry, dict):
                continue
            name = entry.get("name", "")
            version = entry.get("version", "")
            if not name:
                # Derive name from key
                if "/" in key:
                    parts = key.split("/")
                    if key.startswith("@"):
                        name = f"{parts[0]}/{parts[1]}" if len(parts) > 1 else key
                    else:
                        name = parts[-1]
                else:
                    name = key
            if not name or not version:
                continue
            r = Record(
                ecosystem=ECOSYSTEM,
                package_name=name,
                normalized_name=normalize.npm(name),
                version=version,
                project_path=project_path,
                package_manager="bun",
                source_type="bun-lock",
                source_file=path,
                confidence="high",
            )
            scanner._apply_base(r, base)
            scanner.emit(r)


def _parse_bun_lock_text(data: bytes, path: str, project_path: str,
                          base: Record, scanner: Scanner):
    """Fallback text-based parsing for bun.lock."""
    text = data.decode("utf-8", errors="replace")
    for line in text.splitlines():
        # Look for lines like: name@version or name = "version"
        m = re.match(r'^\s*([\w@./-]+)@(\S+)', line)
        if m:
            name, version = m.group(1), m.group(2)
            r = Record(
                ecosystem=ECOSYSTEM,
                package_name=name.strip(),
                normalized_name=normalize.npm(name.strip()),
                version=version.strip(),
                project_path=project_path,
                package_manager="bun",
                source_type="bun-lock",
                source_file=path,
                confidence="high",
            )
            scanner._apply_base(r, base)
            scanner.emit(r)
