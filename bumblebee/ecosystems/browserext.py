"""
Browser extension scanner: Chromium-family manifests and Firefox extensions.json.
"""

import json
import os
import re

from bumblebee.ecosystems.base import BaseScanner
from bumblebee.model import ECOSYSTEM_BROWSER_EXTENSION, Record

ECOSYSTEM = ECOSYSTEM_BROWSER_EXTENSION


def is_chromium_extension_manifest(path: str) -> tuple[bool, str, str, str]:
    """Check if path is a Chromium-family extension manifest.json.

    Returns (True, extID, verDir, profileDir).
    Profile: .../<profile>/Extensions/<extID>/<version>/manifest.json
    """
    if os.path.basename(path) != "manifest.json":
        return False, "", "", ""
    parts = path.replace("\\", "/").split("/")
    # Find "Extensions" in the path
    for i, p in enumerate(parts):
        if p == "Extensions" and i + 3 < len(parts):
            ext_id = parts[i + 1]
            ver_dir = parts[i + 2]
            profile_dir = "/".join(parts[:i])
            return True, ext_id, ver_dir, profile_dir
    return False, "", "", ""


def is_firefox_extensions_json(path: str) -> bool:
    """Check if path is Firefox's extensions.json under a profile."""
    if os.path.basename(path) != "extensions.json":
        return False
    parts = path.replace("\\", "/").split("/")
    return any(p in ("Profiles", "firefox", "librewolf", "waterfox") for p in parts)


class Scanner(BaseScanner):

    def scan_chromium_extension(self, path: str, ext_id: str, ver_dir: str,
                                profile_dir: str, base: Record):
        data = self.read_bounded(path)
        if data is None:
            return
        try:
            manifest = json.loads(data)
        except json.JSONDecodeError as e:
            if self.diag:
                self.diag("warn", path, f"parse: {e}")
            return

        name = manifest.get("name", ext_id)
        version = manifest.get("version", ver_dir)
        if not name or not version:
            return

        r = Record(
            ecosystem=ECOSYSTEM,
            package_name=name,
            normalized_name=name.lower(),
            version=version,
            project_path=profile_dir,
            source_type="chromium-extension",
            source_file=path,
            confidence="high",
        )
        self._apply_base(r, base)
        self.emit(r)

    def scan_firefox_extensions(self, path: str, base: Record):
        data = self.read_bounded(path)
        if data is None:
            return
        try:
            doc = json.loads(data)
        except json.JSONDecodeError as e:
            if self.diag:
                self.diag("warn", path, f"parse: {e}")
            return

        # Firefox extensions.json has an "addons" array
        addons = doc.get("addons", []) if isinstance(doc, dict) else doc
        if isinstance(addons, list):
            for addon in addons:
                if not isinstance(addon, dict):
                    continue
                _id = addon.get("id", "")
                default_locale = addon.get("defaultLocale", {})
                name = ""
                if isinstance(default_locale, dict):
                    name = default_locale.get("name", "")
                if not name:
                    name = addon.get("name", _id)
                version = addon.get("version", "")
                if not _id or not version:
                    continue

                r = Record(
                    ecosystem=ECOSYSTEM,
                    package_name=name,
                    normalized_name=name.lower(),
                    version=version,
                    source_type="firefox-extension",
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
