"""
npm ecosystem scanner: package-lock.json, npm-shrinkwrap.json,
node_modules/<pkg>/package.json, and .package-lock.json.
"""

import json
import os
from typing import Optional

from bumblebee_py.ecosystems.base import BaseScanner
from bumblebee_py.model import ECOSYSTEM_NPM, Record
from bumblebee_py import normalize


ECOSYSTEM = ECOSYSTEM_NPM


def is_lockfile(base: str) -> bool:
    return base in ("package-lock.json", "npm-shrinkwrap.json", ".package-lock.json")


def is_node_modules_package_json(path: str) -> tuple[bool, str]:
    """Return (True, projectPath) if path is a node_modules/<pkg>/package.json."""
    if os.path.basename(path) != "package.json":
        return False, ""
    parts = path.replace("\\", "/").split("/")
    # Need at least: node_modules/<pkg>/package.json
    if len(parts) < 3:
        return False, ""
    # Find the LAST node_modules
    nm_idx = -1
    for i in range(len(parts) - 1, -1, -1):
        if parts[i] == "node_modules":
            nm_idx = i
            break
    if nm_idx < 0:
        return False, ""
    tail = parts[nm_idx + 1:]
    if len(tail) == 2:
        if tail[0].startswith("@"):
            return False, ""
    elif len(tail) == 3:
        if not tail[0].startswith("@"):
            return False, ""
    else:
        return False, ""
    project_path = "/".join(parts[:nm_idx]) or "."
    return True, project_path


class Scanner(BaseScanner):
    """npm lockfile and node_modules scanner."""

    def scan_lockfile(self, path: str, base: Record):
        data = self.read_bounded(path)
        if data is None:
            return
        try:
            lf = json.loads(data)
        except json.JSONDecodeError as e:
            if self.diag:
                self.diag("warn", path, f"parse: {e}")
            return

        project_path = os.path.dirname(path)
        pm = "npm"
        packages = lf.get("packages", {})
        dependencies = lf.get("dependencies", {})

        if packages:
            for key in sorted(packages.keys()):
                if key == "":
                    continue
                entry = packages[key]
                if entry.get("link"):
                    continue
                name = _name_from_packages_key(key, entry.get("name", ""))
                version = entry.get("version", "")
                if not name or not version:
                    continue
                direct = key.count("node_modules/") == 1
                scripts = _lifecycle_script_keys(entry.get("scripts", {}))
                r = Record(
                    ecosystem=ECOSYSTEM,
                    package_name=name,
                    normalized_name=normalize.npm(name),
                    version=version,
                    project_path=project_path,
                    package_manager=pm,
                    source_type="npm-lockfile",
                    source_file=path,
                    direct_dependency=direct,
                    has_lifecycle_scripts=bool(scripts),
                    lifecycle_scripts=scripts,
                    install_scope="dev" if entry.get("dev") else "prod",
                    confidence="high",
                )
                self._apply_base(r, base)
                self.emit(r)
        elif dependencies:
            self._emit_deps_v1(dependencies, path, project_path, pm, True, base)

    def _emit_deps_v1(self, deps: dict, path: str, project_path: str,
                      pm: str, direct: bool, base: Record):
        for name in sorted(deps.keys()):
            dep = deps[name]
            version = dep.get("version", "")
            if not name or not version:
                continue
            r = Record(
                ecosystem=ECOSYSTEM,
                package_name=name,
                normalized_name=normalize.npm(name),
                version=version,
                project_path=project_path,
                package_manager=pm,
                source_type="npm-lockfile",
                source_file=path,
                direct_dependency=direct,
                install_scope="dev" if dep.get("dev") else "prod",
                confidence="high",
            )
            self._apply_base(r, base)
            self.emit(r)
            sub_deps = dep.get("dependencies", {})
            if sub_deps:
                self._emit_deps_v1(sub_deps, path, project_path, pm, False, base)

    def scan_node_modules_package_json(self, path: str, project_path: str, base: Record):
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
        if not name or not version:
            return
        scripts = _lifecycle_script_keys(pj.get("scripts", {}))
        r = Record(
            ecosystem=ECOSYSTEM,
            package_name=name,
            normalized_name=normalize.npm(name),
            version=version,
            project_path=project_path,
            package_manager="npm",
            source_type="npm-node_modules",
            source_file=path,
            has_lifecycle_scripts=bool(scripts),
            lifecycle_scripts=scripts,
            confidence="medium",
        )
        self._apply_base(r, base)
        self.emit(r)

    def _apply_base(self, r: Record, base: Record):
        """Copy base record fields onto r."""
        for attr in ("record_type", "schema_version", "scanner_name",
                     "scanner_version", "run_id", "scan_time", "endpoint",
                     "profile", "root_kind"):
            val = getattr(base, attr)
            if val:
                setattr(r, attr, val)


def _name_from_packages_key(key: str, explicit: str) -> str:
    if explicit:
        return explicit
    parts = key.split("node_modules/")
    if len(parts) < 2:
        return ""
    tail = parts[-1].rstrip("/")
    if tail.startswith("@"):
        segs = tail.split("/", 2)
        if len(segs) < 2:
            return ""
        return f"{segs[0]}/{segs[1]}"
    if "/" in tail:
        return tail[: tail.index("/")]
    return tail


def _lifecycle_script_keys(scripts: dict) -> list[str]:
    lifecycle = {"preinstall", "install", "postinstall", "prepare",
                 "preprepare", "postprepare"}
    return sorted(k for k in lifecycle if scripts.get(k, "").strip())
