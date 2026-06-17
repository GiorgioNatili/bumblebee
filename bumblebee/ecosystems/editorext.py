"""
Editor extension scanner: VS Code, Cursor, Windsurf, VSCodium extensions.
"""

import json
import os

from bumblebee.ecosystems.base import BaseScanner
from bumblebee.model import ECOSYSTEM_EDITOR_EXTENSION, Record

ECOSYSTEM = ECOSYSTEM_EDITOR_EXTENSION


def is_extension_package_json(path: str) -> tuple[bool, str, str]:
    """Check if path is an editor extension package.json.

    Returns (True, extRoot, extDir) if it matches
    <extensions-dir>/<publisher>.<name>/package.json pattern.
    """
    if os.path.basename(path) != "package.json":
        return False, "", ""
    parts = path.replace("\\", "/").split("/")
    # Find the extensions directory marker
    for i, p in enumerate(parts):
        if p in (".vscode", ".vscode-insiders", ".vscode-server",
                 ".cursor", ".cursor-server", ".windsurf",
                 ".windsurf-server", ".vscodium"):
            # Check if next part is "extensions"
            if i + 1 < len(parts) and parts[i + 1] == "extensions":
                tail = parts[i + 2:]
                if len(tail) >= 2:
                    ext_dir = tail[-2]
                    ext_root = "/".join(parts[:i + 2])
                    return True, ext_root, "/".join(tail[:-1])
    return False, "", ""


class Scanner(BaseScanner):

    def scan_extension(self, path: str, ext_root: str, ext_dir: str, base: Record):
        data = self.read_bounded(path)
        if data is None:
            return
        try:
            pj = json.loads(data)
        except json.JSONDecodeError as e:
            if self.diag:
                self.diag("warn", path, f"parse: {e}")
            return
        name = pj.get("name", "")
        version = pj.get("version", "")
        publisher = pj.get("publisher", "")
        if not name or not version:
            return
        display_name = pj.get("displayName", "")
        pkg_name = f"{publisher}.{name}" if publisher else name

        r = Record(
            ecosystem=ECOSYSTEM,
            package_name=pkg_name,
            normalized_name=pkg_name.lower(),
            version=version,
            source_type="editor-extension",
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
