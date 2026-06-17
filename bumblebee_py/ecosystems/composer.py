"""
Composer (Packagist) scanner: composer.lock and installed.json.
"""

import json
import os
from typing import Optional

from bumblebee_py.ecosystems.base import BaseScanner
from bumblebee_py.model import ECOSYSTEM_PACKAGIST, Record

ECOSYSTEM = ECOSYSTEM_PACKAGIST


def is_composer_lock(base: str) -> bool:
    return base == "composer.lock"


def is_installed_json(path: str) -> bool:
    """Check if path is a composer installed.json under a vendor/composer/ dir."""
    parts = path.replace("\\", "/").split("/")
    return "vendor" in parts and "composer" in parts and path.endswith("installed.json")


class Scanner(BaseScanner):

    def scan_composer_lock(self, path: str, base: Record):
        data = self.read_bounded(path)
        if data is None:
            return
        try:
            doc = json.loads(data)
        except json.JSONDecodeError as e:
            if self.diag:
                self.diag("warn", path, f"parse: {e}")
            return
        project_path = os.path.dirname(path)
        for entry in doc.get("packages", []):
            name = entry.get("name", "")
            version = entry.get("version", "")
            if not name or not version:
                continue
            # Strip leading "v" or "V" from version
            version = version.lstrip("vV")
            r = Record(
                ecosystem=ECOSYSTEM,
                package_name=name,
                normalized_name=name.lower(),
                version=version,
                project_path=project_path,
                package_manager="composer",
                source_type="composer-lock",
                source_file=path,
                confidence="high",
            )
            self._apply_base(r, base)
            self.emit(r)

    def scan_installed_json(self, path: str, base: Record):
        data = self.read_bounded(path)
        if data is None:
            return
        try:
            doc = json.loads(data)
        except json.JSONDecodeError as e:
            if self.diag:
                self.diag("warn", path, f"parse: {e}")
            return
        # Can be an object with "installed" key or a flat array
        entries = doc if isinstance(doc, list) else doc.get("installed", doc.get("packages", []))
        for entry in entries:
            name = ""
            version = ""
            if isinstance(entry, dict):
                name = entry.get("name", "")
                version = entry.get("version", "")
                if not version:
                    version = entry.get("version_normalized", "")
            elif isinstance(entry, str):
                continue
            if not name or not version:
                continue
            version = version.lstrip("vV")
            r = Record(
                ecosystem=ECOSYSTEM,
                package_name=name,
                normalized_name=name.lower(),
                version=version,
                package_manager="composer",
                source_type="composer-installed",
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
