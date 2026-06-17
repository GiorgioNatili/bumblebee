"""
RubyGems scanner: Gemfile.lock and installed gemspec files.
"""

import json
import os
import re
from typing import Optional

from bumblebee_py.ecosystems.base import BaseScanner
from bumblebee_py.model import ECOSYSTEM_RUBYGEMS, Record

ECOSYSTEM = ECOSYSTEM_RUBYGEMS


def is_gemfile_lock(base: str) -> bool:
    return base == "Gemfile.lock"


def is_gemspec(base: str) -> bool:
    return base.endswith(".gemspec")


def is_installed_gemspec(path: str) -> tuple[bool, str]:
    """Return (True, gemsDir) if path is an installed gemspec under specifications/."""
    if not path.endswith(".gemspec"):
        return False, ""
    parts = path.replace("\\", "/").split("/")
    for i, p in enumerate(parts):
        if p == "specifications":
            gems_dir = "/".join(parts[:i])
            return True, gems_dir
    return False, ""


class Scanner(BaseScanner):

    def scan_gemfile_lock(self, path: str, base: Record):
        data = self.read_bounded(path)
        if data is None:
            return
        project_path = os.path.dirname(path)
        gems = _parse_gemfile_lock(data)
        for name, version, source in gems:
            if not name or not version:
                continue
            r = Record(
                ecosystem=ECOSYSTEM,
                package_name=name,
                normalized_name=name.lower(),
                version=version,
                project_path=project_path,
                package_manager="bundler",
                source_type="gemfile-lock",
                source_file=path,
                confidence="high",
            )
            self._apply_base(r, base)
            self.emit(r)

    def scan_gemspec(self, path: str, gems_dir: str, base: Record):
        data = self.read_bounded(path)
        if data is None:
            return
        name, version = _parse_gemspec(data)
        if not name or not version:
            return
        r = Record(
            ecosystem=ECOSYSTEM,
            package_name=name,
            normalized_name=name.lower(),
            version=version,
            project_path=gems_dir,
            package_manager="gem",
            source_type="gemspec",
            source_file=path,
            confidence="medium",
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


def _parse_gemfile_lock(data: bytes) -> list[tuple[str, str, str]]:
    """Parse 'GEM' section of Bundler's Gemfile.lock to extract (name, version, source)."""
    gems = []
    text = data.decode("utf-8", errors="replace")
    in_gem_section = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == "GEM":
            in_gem_section = True
            continue
        if in_gem_section:
            if stripped.startswith("remote:"):
                continue
            if stripped.startswith("specs:"):
                continue
            if stripped == "" or stripped.startswith("PLATFORMS") or stripped.startswith("DEPENDENCIES"):
                in_gem_section = False
                continue
            # Parse "name (version)" or "name (version)" with indentation
            m = re.match(r'\s{4}(\S+)\s+\(([^)]+)\)', line)
            if m:
                gems.append((m.group(1), m.group(2), ""))
    return gems


def _parse_gemspec(data: bytes) -> tuple[str, str]:
    """Heuristically parse name and version from a .gemspec file."""
    name = ""
    version = ""
    text = data.decode("utf-8", errors="replace")
    for line in text.splitlines():
        stripped = line.strip()
        # Ruby: s.name = "foo" or s.name = 'foo'
        m = re.search(r'\.name\s*=\s*["\']([^"\']+)["\']', stripped)
        if m and not name:
            name = m.group(1)
        m = re.search(r'\.version\s*=\s*["\']([^"\']+)["\']', stripped)
        if m and not version:
            version = m.group(1)
        if name and version:
            break
    return name, version
