"""
Yarn lockfile scanner: yarn.lock (Classic + Berry).
"""

import os
import re
from typing import Optional

from bumblebee_py.ecosystems.base import BaseScanner
from bumblebee_py.model import ECOSYSTEM_NPM, Record
from bumblebee_py import normalize

ECOSYSTEM = ECOSYSTEM_NPM


def is_lockfile(base: str) -> bool:
    return base == "yarn.lock"


class Scanner(BaseScanner):

    def scan_lockfile(self, path: str, base: Record):
        data = self.read_bounded(path)
        if data is None:
            return
        project_path = os.path.dirname(path)
        packages = _parse_yarn_lock(data)
        for name, version in packages:
            if not name or not version:
                continue
            r = Record(
                ecosystem=ECOSYSTEM,
                package_name=name,
                normalized_name=normalize.npm(name),
                version=version,
                project_path=project_path,
                package_manager="yarn",
                source_type="yarn-lock",
                source_file=path,
                confidence="high",
            )
            self._apply_base(r, base)
            self.emit(r)

    def _apply_base(self, r: Record, base: Record):
        for attr in ("record_type", "schema_version", "scanner_name",
                     "scanner_version", "run_id", "scan_time", "endpoint",
                     "profile", "root_kind"):
            val = getattr(base, attr)
            if val:
                setattr(r, attr, val)


def _parse_yarn_lock(data: bytes) -> list[tuple[str, str]]:
    """Parse yarn.lock entries. Returns list of (name, version).

    Handles both Yarn Classic (v1) and Yarn Berry (v2+) formats.
    """
    packages = []
    text = data.decode("utf-8", errors="replace")
    lines = text.splitlines()

    # Yarn Berry uses "# yarn lockfile v1" header too but has different format.
    # Try Berry format first (entries under "packages:" key). Then fallback to Classic.
    in_berry_packages = False
    berry_mode = False
    current_name = ""
    current_version = ""
    in_block = False

    for line in lines:
        stripped = line.rstrip()

        # Detect Berry format
        if stripped == "__metadata:":
            berry_mode = True
            continue
        if berry_mode and stripped == "packages:":
            in_berry_packages = True
            continue
        if berry_mode and in_berry_packages:
            if stripped and not stripped.startswith(" "):
                in_berry_packages = False
                continue
            # Berry entry: "  name@version:" or "  @scope/name@version:"
            m = re.match(r"^\s{2}(.+?):$", stripped)
            if m and "@" in m.group(1):
                if current_name and current_version:
                    packages.append((current_name, current_version))
                entry = m.group(1)
                # Split on last @
                at_idx = entry.rindex("@")
                current_name = entry[:at_idx]
                current_version = entry[at_idx + 1:]
                continue
            # Version specifier inside entry: "  version: 1.2.3"
            if not current_name:
                continue
            continue
        else:
            # Classic yarn.lock
            if stripped.startswith('"') and stripped.endswith(':'):
                # Entry header: '"name@version, name@version...":'
                if current_name and current_version:
                    packages.append((current_name, current_version))
                header = stripped.strip('":')
                # Take the first spec before comma
                first_spec = header.split(",")[0].strip()
                if first_spec.startswith("@"):
                    # Scoped: @scope/name@version
                    m = re.match(r'(@[^@]+@)(.+)$', first_spec)
                else:
                    m = re.match(r'([^@]+)@(.+)$', first_spec)
                if m:
                    current_name = m.group(1).rstrip("@")
                    current_version = m.group(2)
                else:
                    current_name = first_spec
                    current_version = ""
                in_block = True
                continue
            if in_block:
                # Version line: "  version "1.2.3""
                m = re.match(r'^\s{2}version\s+"([^"]+)"', stripped)
                if m:
                    current_version = m.group(1)

    # Last entry
    if current_name and current_version:
        packages.append((current_name, current_version))

    return packages
