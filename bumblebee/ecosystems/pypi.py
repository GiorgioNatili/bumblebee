"""
PyPI ecosystem scanner: *.dist-info/METADATA (PEP 566),
*.egg-info/PKG-INFO, plus adjacent INSTALLER and direct_url.json.
"""

import json
import os
from typing import Optional

from bumblebee.ecosystems.base import BaseScanner
from bumblebee.model import ECOSYSTEM_PYPI, Record
from bumblebee import normalize

ECOSYSTEM = ECOSYSTEM_PYPI


def is_dist_info_metadata(path: str) -> tuple[bool, str]:
    """Return (True, distInfoDir) if path is a *.dist-info/METADATA."""
    if os.path.basename(path) != "METADATA":
        return False, ""
    d = os.path.dirname(path)
    if d.endswith(".dist-info"):
        return True, d
    return False, ""


def is_egg_info_pkg_info(path: str) -> tuple[bool, str]:
    """Return (True, eggInfoDir) for legacy *.egg-info/PKG-INFO."""
    if os.path.basename(path) != "PKG-INFO":
        return False, ""
    d = os.path.dirname(path)
    if d.endswith(".egg-info"):
        return True, d
    return False, ""


class Scanner(BaseScanner):

    def scan_dist_info(self, metadata_path: str, dist_info_dir: str, base: Record):
        data = self.read_bounded(metadata_path)
        if data is None:
            return
        name, version = _parse_rfc822_name_version(data)
        if not name or not version:
            if self.diag:
                self.diag("warn", metadata_path,
                          "skipping: METADATA missing Name and/or Version header")
            return
        r = Record(
            ecosystem=ECOSYSTEM,
            package_name=name,
            normalized_name=normalize.pypi(name),
            version=version,
            project_path=_site_packages_project_path(dist_info_dir),
            source_type="pypi-dist-info",
            source_file=metadata_path,
            confidence="high",
        )
        # Adjacent INSTALLER
        installer = self.read_optional(os.path.join(dist_info_dir, "INSTALLER"))
        if installer:
            v = installer.decode("utf-8", errors="replace").strip()
            if v:
                r.package_manager = v
        # Adjacent direct_url.json
        du = self.read_optional(os.path.join(dist_info_dir, "direct_url.json"))
        if du:
            try:
                du_data = json.loads(du)
                if du_data.get("url"):
                    r.direct_dependency = True
            except json.JSONDecodeError:
                pass
        self._apply_base(r, base)
        self.emit(r)

    def scan_egg_info(self, pkg_info_path: str, egg_info_dir: str, base: Record):
        data = self.read_bounded(pkg_info_path)
        if data is None:
            return
        name, version = _parse_rfc822_name_version(data)
        if not name or not version:
            if self.diag:
                self.diag("warn", pkg_info_path,
                          "skipping: PKG-INFO missing Name and/or Version header")
            return
        r = Record(
            ecosystem=ECOSYSTEM,
            package_name=name,
            normalized_name=normalize.pypi(name),
            version=version,
            project_path=_site_packages_project_path(egg_info_dir),
            source_type="pypi-egg-info",
            source_file=pkg_info_path,
            confidence="medium",
        )
        installer = self.read_optional(os.path.join(egg_info_dir, "INSTALLER"))
        if installer:
            v = installer.decode("utf-8", errors="replace").strip()
            if v:
                r.package_manager = v
        self._apply_base(r, base)
        self.emit(r)

    def _apply_base(self, r: Record, base: Record):
        for attr in ("record_type", "schema_version", "scanner_name",
                     "scanner_version", "run_id", "scan_time", "endpoint",
                     "profile", "root_kind"):
            val = getattr(base, attr)
            if val:
                setattr(r, attr, val)


def _parse_rfc822_name_version(data: bytes) -> tuple[str, str]:
    """Parse Name and Version from an RFC 822-style METADATA/PKG-INFO header block."""
    name = ""
    version = ""
    text = data.decode("utf-8", errors="replace")
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            break
        # Continuation lines start with whitespace — skip
        if line[0] in (" ", "\t"):
            continue
        if ":" in stripped:
            idx = stripped.index(":")
            key = stripped[:idx].strip().lower()
            val = stripped[idx + 1:].strip()
            if key == "name" and not name:
                name = val
            elif key == "version" and not version:
                version = val
        if name and version:
            break
    return name, version


def _site_packages_project_path(meta_dir: str) -> str:
    return os.path.dirname(meta_dir)
