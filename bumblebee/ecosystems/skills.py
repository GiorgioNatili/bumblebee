"""
Agent skills scanner: skill lockfiles (.skill-lock.json).
"""

import json
import os

from bumblebee.ecosystems.base import BaseScanner
from bumblebee.model import ECOSYSTEM_AGENT_SKILL, Record

ECOSYSTEM = ECOSYSTEM_AGENT_SKILL


def is_known_lock_file(base: str) -> bool:
    return base == ".skill-lock.json"


class Scanner(BaseScanner):

    def scan_lock_file(self, path: str, base: Record):
        data = self.read_bounded(path)
        if data is None:
            return
        try:
            doc = json.loads(data)
        except json.JSONDecodeError as e:
            if self.diag:
                self.diag("warn", path, f"parse: {e}")
            return

        entries = doc
        if isinstance(doc, dict):
            # Format: {"skills": [ ... ]} or {"packages": [ ... ]} or flat map
            entries = doc.get("skills", doc.get("packages", doc))

        if isinstance(entries, list):
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                name = entry.get("name", entry.get("package", ""))
                version = entry.get("version", "")
                source = entry.get("source", entry.get("from", ""))
                local_name = entry.get("local_name", entry.get("id", ""))
                if not name:
                    continue
                r = Record(
                    ecosystem=ECOSYSTEM,
                    package_name=name,
                    normalized_name=name.lower(),
                    version=version,
                    source_type="skill-lock",
                    source_file=path,
                    package_manager="agents",
                    confidence="high",
                )
                if local_name:
                    r.server_name = local_name
                if source:
                    r.requested_spec = source
                self._apply_base(r, base)
                self.emit(r)
        elif isinstance(entries, dict):
            for key, entry in entries.items():
                if not isinstance(entry, dict):
                    continue
                name = entry.get("name", entry.get("package", key))
                version = entry.get("version", "")
                r = Record(
                    ecosystem=ECOSYSTEM,
                    package_name=name,
                    normalized_name=name.lower(),
                    version=version,
                    source_type="skill-lock",
                    source_file=path,
                    package_manager="agents",
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
