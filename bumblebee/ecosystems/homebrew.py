"""
Homebrew scanner: formula INSTALL_RECEIPT.json and cask metadata.
"""

import json
import os

from bumblebee.ecosystems.base import BaseScanner
from bumblebee.model import ECOSYSTEM_HOMEBREW, Record

ECOSYSTEM = ECOSYSTEM_HOMEBREW


def is_formula_receipt(path: str) -> tuple[bool, str, str, str]:
    """Check if path is a Homebrew formula INSTALL_RECEIPT.json.

    Returns (True, name, version, cellarDir).
    Path pattern: .../Cellar/<name>/<version>/INSTALL_RECEIPT.json
    """
    if os.path.basename(path) != "INSTALL_RECEIPT.json":
        return False, "", "", ""
    parts = path.replace("\\", "/").split("/")
    for i, p in enumerate(parts):
        if p == "Cellar" and i + 2 < len(parts):
            name = parts[i + 1]
            version = parts[i + 2]
            cellar_dir = "/".join(parts[:i + 1])
            return True, name, version, cellar_dir
    return False, "", "", ""


def looks_like_cask_metadata_marker(path: str) -> bool:
    """Check if path looks like a cask metadata marker."""
    base = os.path.basename(path)
    return base.endswith(".json") and not base.startswith(".")


def is_cask_metadata_marker(path: str) -> tuple[bool, str, str, str]:
    """Check if path is a Homebrew cask metadata file.

    Returns (True, token, version, caskroomDir).
    Path pattern: .../Caskroom/<token>/<version>/.metadata.json or similar.
    """
    parts = path.replace("\\", "/").split("/")
    for i, p in enumerate(parts):
        if p == "Caskroom" and i + 2 < len(parts):
            token = parts[i + 1]
            version = parts[i + 2]
            caskroom_dir = "/".join(parts[:i + 1])
            return True, token, version, caskroom_dir
    return False, "", "", ""


class Scanner(BaseScanner):

    def scan_formula_receipt(self, path: str, name: str, version: str,
                             cellar_dir: str, base: Record):
        data = self.read_bounded(path)
        if data is None:
            return
        try:
            receipt = json.loads(data)
        except json.JSONDecodeError as e:
            if self.diag:
                self.diag("warn", path, f"parse: {e}")
            return

        # Check for installed_on_dependency (keg-only formula pulled as dep)
        source = receipt.get("source", {})
        tap = source.get("tap", "") if isinstance(source, dict) else ""
        r = Record(
            ecosystem=ECOSYSTEM,
            package_name=name,
            normalized_name=name.lower(),
            version=version,
            project_path=cellar_dir,
            package_manager="homebrew",
            source_type="homebrew-formula",
            source_file=path,
            confidence="high",
        )
        self._apply_base(r, base)
        self.emit(r)

    def scan_cask_metadata(self, path: str, token: str, version: str,
                           caskroom_dir: str, base: Record):
        r = Record(
            ecosystem=ECOSYSTEM,
            package_name=token,
            normalized_name=token.lower(),
            version=version,
            project_path=caskroom_dir,
            package_manager="homebrew",
            source_type="homebrew-cask",
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
