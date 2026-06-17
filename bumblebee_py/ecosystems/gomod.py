"""
Go module scanner: go.sum and go.mod files.
"""

import os
from typing import Optional

from bumblebee_py.ecosystems.base import BaseScanner
from bumblebee_py.model import ECOSYSTEM_GO, Record

ECOSYSTEM = ECOSYSTEM_GO


def is_go_sum(base: str) -> bool:
    return base == "go.sum"


def is_go_mod(base: str) -> bool:
    return base == "go.mod"


class Scanner(BaseScanner):

    def scan_go_sum(self, path: str, base: Record):
        data = self.read_bounded(path)
        if data is None:
            return
        project_path = os.path.dirname(path)
        seen = set()
        text = data.decode("utf-8", errors="replace")
        for line in text.splitlines():
            fields = line.split()
            if len(fields) < 3:
                continue
            module = fields[0]
            version = fields[1]
            if version.endswith("/go.mod"):
                continue
            key = f"{module}\x00{version}"
            if key in seen:
                continue
            seen.add(key)
            r = Record(
                ecosystem=ECOSYSTEM,
                package_name=module,
                normalized_name=module.lower(),
                version=version,
                project_path=project_path,
                package_manager="go",
                source_type="go-sum",
                source_file=path,
                confidence="high",
            )
            self._apply_base(r, base)
            self.emit(r)

    def scan_go_mod(self, path: str, base: Record):
        data = self.read_bounded(path)
        if data is None:
            return
        project_path = os.path.dirname(path)
        reqs = _parse_go_mod_requires(data)
        for req in reqs:
            if not req["module"] or not req["version"]:
                continue
            r = Record(
                ecosystem=ECOSYSTEM,
                package_name=req["module"],
                normalized_name=req["module"].lower(),
                version=req["version"],
                project_path=project_path,
                package_manager="go",
                source_type="go-mod",
                source_file=path,
                confidence="medium",
            )
            if req["indirect"]:
                r.install_scope = "indirect"
                r.direct_dependency = False
            else:
                r.direct_dependency = True
            self._apply_base(r, base)
            self.emit(r)

    def _apply_base(self, r: Record, base: Record):
        for attr in ("record_type", "schema_version", "scanner_name",
                     "scanner_version", "run_id", "scan_time", "endpoint",
                     "profile", "root_kind"):
            val = getattr(base, attr)
            if val:
                setattr(r, attr, val)


def _parse_go_mod_requires(data: bytes) -> list[dict]:
    """Parse Go module require directives."""
    out = []
    text = data.decode("utf-8", errors="replace")
    in_block = False
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("//"):
            continue
        comment = ""
        if "//" in line:
            ci = line.index("//")
            comment = line[ci + 2:].strip()
            line = line[:ci].strip()
        if not in_block:
            if line == "require (":
                in_block = True
                continue
            if line.startswith("require "):
                rest = line[len("require"):].strip()
                r = _parse_require_line(rest, comment)
                if r:
                    out.append(r)
                continue
            continue
        if line == ")":
            in_block = False
            continue
        r = _parse_require_line(line, comment)
        if r:
            out.append(r)
    return out


def _parse_require_line(line: str, comment: str) -> Optional[dict]:
    fields = line.split()
    if len(fields) < 2:
        return None
    return {
        "module": fields[0],
        "version": fields[1],
        "indirect": "indirect" in comment,
    }
