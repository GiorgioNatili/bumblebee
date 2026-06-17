"""
MCP (Model Context Protocol) server configuration scanner.
"""

import json
import os
import re
from typing import Optional

from bumblebee.ecosystems.base import BaseScanner
from bumblebee.model import ECOSYSTEM_MCP, Record

ECOSYSTEM = ECOSYSTEM_MCP


def is_known_mcp_config(base: str) -> bool:
    return base in (
        "mcp.json", "claude_desktop_config.json", "mcp_config.json",
        "mcp_settings.json", "cline_mcp_settings.json", ".mcp.json",
    )


def is_gemini_settings_json(path: str) -> bool:
    return (os.path.basename(path) == "settings.json" and
            os.path.basename(os.path.dirname(path)) == ".gemini")


def is_claude_config_json(path: str) -> bool:
    return os.path.basename(path) == ".claude.json"


class Scanner(BaseScanner):

    def scan_config(self, path: str, base: Record):
        data = self.read_bounded(path)
        if data is None:
            return
        try:
            doc = json.loads(data)
        except json.JSONDecodeError as e:
            if self.diag:
                self.diag("warn", path, f"parse MCP config: {e}")
            return

        servers = {}
        # Try envelope { mcpServers: {...} } first, then { servers: {...} }, then flat
        if isinstance(doc, dict):
            if "mcpServers" in doc and isinstance(doc["mcpServers"], dict):
                servers.update(doc["mcpServers"])
            if "servers" in doc and isinstance(doc["servers"], dict):
                for k, v in doc["servers"].items():
                    servers.setdefault(k, v)
            if not servers:
                # Try flat map — accept entries that look like MCP servers
                for k, v in doc.items():
                    if isinstance(v, dict) and (
                        v.get("command") or v.get("url") or
                        v.get("serverUrl") or v.get("httpUrl") or
                        v.get("args") or v.get("type")
                    ):
                        servers[k] = v

        if not servers:
            return

        self._emit_servers(servers, base, path, os.path.dirname(path))

    def scan_claude_config(self, path: str, base: Record):
        data = self.read_bounded(path)
        if data is None:
            return
        try:
            doc = json.loads(data)
        except json.JSONDecodeError as e:
            if self.diag:
                self.diag("warn", path, f"parse Claude config: {e}")
            return

        if isinstance(doc, dict):
            mcp_servers = doc.get("mcpServers", {})
            if isinstance(mcp_servers, dict):
                self._emit_servers(mcp_servers, base, path, os.path.dirname(path))

            projects = doc.get("projects", {})
            if isinstance(projects, dict):
                for proj_dir in sorted(projects.keys()):
                    proj = projects[proj_dir]
                    if isinstance(proj, dict):
                        ps = proj.get("mcpServers", {})
                        if isinstance(ps, dict):
                            self._emit_servers(ps, base, path, proj_dir)

    def _emit_servers(self, servers: dict, base: Record,
                      source_path: str, project_path: str):
        for sid in sorted(servers.keys()):
            srv = servers[sid]
            if not isinstance(srv, dict):
                continue

            r = Record(
                ecosystem=ECOSYSTEM,
                package_manager="mcp",
                source_type="mcp-config",
                source_file=source_path,
                project_path=project_path,
                root_kind="mcp_config_root",
                server_name=sid,
                confidence="low",
            )

            # Remote URL entry
            command = srv.get("command", "") or ""
            if not command:
                url = srv.get("url") or srv.get("serverUrl") or srv.get("httpUrl") or ""
                sanitized = _sanitize_remote_url(url)
                if sanitized:
                    r.package_name = sid
                    r.normalized_name = sid.lower()
                    r.package_manager = "mcp-remote"
                    r.requested_spec = sanitized
                    self._apply_base(r, base)
                    self.emit(r)
                continue

            args = srv.get("args", []) or []
            spec, launcher = _infer_package_from_args(command, args)
            name, selector, version = "", "", ""

            if launcher == "docker":
                name, version = _split_docker_image_ref(spec)
            else:
                name, selector = _split_spec(spec)

            if _looks_unresolved_shell_var(name):
                name, spec, selector = "", "", ""

            if launcher != "docker" and not _looks_like_package_spec(spec):
                name, spec, selector = "", "", ""

            if not name:
                name = sid

            r.package_name = name
            r.normalized_name = name.lower()
            if launcher:
                r.package_manager = launcher
            if version:
                r.version = version
            if selector:
                r.requested_spec = spec
            if launcher == "docker" and (version or "@sha256:" in name):
                r.confidence = "medium"

            self._apply_base(r, base)
            self.emit(r)

    def _apply_base(self, r: Record, base: Record):
        for attr in ("record_type", "schema_version", "scanner_name",
                     "scanner_version", "run_id", "scan_time", "endpoint",
                     "profile", "root_kind"):
            val = getattr(base, attr)
            if val:
                setattr(r, attr, val)


def _sanitize_remote_url(u: str) -> str:
    """Reduce URL to scheme://host only, stripping credentials and path."""
    if not u:
        return ""
    from urllib.parse import urlparse
    try:
        parsed = urlparse(u)
    except Exception:
        return ""
    host = parsed.hostname
    if not host:
        return ""
    if parsed.scheme:
        return f"{parsed.scheme}://{host}"
    if u.startswith("//"):
        return f"//{host}"
    return ""


def _infer_package_from_args(command: str, args: list[str]) -> tuple[str, str]:
    """Try to extract a package spec from command/args.

    Returns (spec, launcher) where launcher is '', 'docker', 'uv', 'pipx', etc.
    """
    cmd = os.path.basename(command) if command else ""
    cmd_lower = cmd.lower()

    if cmd_lower in ("npx", "pnpx", "yarn", "yarnpkg", "bunx", "bun"):
        # npx [--package=X] or npx [subcommand] <pkg>
        explicit = _scan_explicit_package(args)
        if explicit:
            return explicit, ""
        return _first_non_flag(args, {"dlx", "exec", "x", "run"}, _NPM_VALUE_TAKING_FLAGS), ""

    if cmd_lower in ("uvx",):
        return _first_non_flag(args, set(), None), "uv"

    if cmd_lower == "uv":
        has_tool = "tool" in args
        for i, a in enumerate(args):
            if a == "--from" and i + 1 < len(args):
                return args[i + 1], "uv"
        if not has_tool:
            return "", "uv"
        return _first_non_flag(args, {"tool", "run"}, None), "uv"

    if cmd_lower == "pipx":
        for i, a in enumerate(args):
            if a == "--spec" and i + 1 < len(args):
                return args[i + 1], "pipx"
        return _first_non_flag(args, {"run"}, None), "pipx"

    if cmd_lower in ("docker", "podman"):
        value_taking = {
            "-e", "--env", "--env-file", "-v", "--volume", "--mount",
            "-p", "--publish", "--name", "--network", "--user", "-u",
            "--workdir", "-w", "--entrypoint", "--label", "-l",
            "--add-host", "--platform",
        }
        started = False
        for i, a in enumerate(args):
            if not started:
                if a in ("run", "container"):
                    started = True
                    continue
                started = True
            if a.startswith("-"):
                if "=" in a:
                    continue
                if a in value_taking and i + 1 < len(args):
                    i += 1  # skip value (loop variable won't update)
                continue
            return a, "docker"
        return "", "docker"

    if cmd_lower in ("python", "python3"):
        for i, a in enumerate(args):
            if a == "-m" and i + 1 < len(args):
                return f"python:{args[i + 1]}", ""

    return "", ""


def _scan_explicit_package(args: list[str], skip: set = None) -> str:
    skip = skip or {"dlx", "exec", "x", "run"}
    for i, a in enumerate(args):
        if a == "--":
            return ""
        if a.startswith("--package="):
            return a[len("--package="):]
        if a == "--package" and i + 1 < len(args):
            return args[i + 1]
        if a.startswith("-"):
            if "=" in a:
                continue
            if a in _NPM_VALUE_TAKING_FLAGS and i + 1 < len(args):
                i += 1
            continue
        if a in skip:
            continue
        return ""
    return ""


def _first_non_flag(args: list[str], skip: set, value_taking: set) -> str:
    if skip is None:
        skip = set()
    if value_taking is None:
        value_taking = set()
    i = 0
    while i < len(args):
        a = args[i]
        if a.startswith("-"):
            if "=" in a:
                i += 1
                continue
            if a in value_taking and i + 1 < len(args):
                i += 1
            i += 1
            continue
        if a in skip:
            i += 1
            continue
        return a
    return ""


_NPM_VALUE_TAKING_FLAGS = {
    "--registry", "--reg", "--cache", "--prefix", "--userconfig",
    "--globalconfig", "--node-options", "--node-version", "--workspace",
    "-w", "--filter", "--otp", "--access", "--auth-type", "--tag",
    "--call", "-c", "--package", "--shell", "--script-shell",
    "--cwd", "--loglevel", "--store", "--store-dir", "--virtual-store-dir",
    "--lockfile-dir", "--config", "--config-file",
}


def _looks_unresolved_shell_var(s: str) -> bool:
    if not s:
        return False
    if "${" in s:
        return True
    for i, ch in enumerate(s):
        if ch == '$' and i + 1 < len(s):
            n = s[i + 1]
            if n == '_' or n.isalnum():
                return True
    if '%' in s:
        first = s.index('%')
        if first >= 0:
            rest = s[first + 1:]
            if '%' in rest:
                between = rest[:rest.index('%')]
                if between and all(c == '_' or c.isalnum() for c in between):
                    return True
    return False


def _looks_like_package_spec(s: str) -> bool:
    if not s:
        return False
    if s.startswith("python:"):
        return True
    if s.startswith("/"):
        return False
    if len(s) >= 3 and s[1] == ':' and s[2] in ('\\', '/'):
        if s[0].isalpha():
            return False
    if s.startswith("./") or s.startswith("../"):
        return False
    if "\\" in s:
        return False
    lower = s.lower()
    for prefix in ("http://", "https://", "ftp://", "ftps://", "ssh://",
                   "git://", "git+", "svn://", "svn+", "file://", "file:",
                   "github:", "gitlab:", "bitbucket:", "gist:", "npm:"):
        if lower.startswith(prefix):
            return False
    for suffix in (".tgz", ".tar.gz", ".tar.bz2", ".tar", ".zip"):
        if lower.endswith(suffix):
            return False
    at = s.find("@")
    if at > 0:
        if s[at:].startswith("@npm:"):
            target = s[at + len("@npm:"):]
            if not target:
                return False
            return _looks_like_package_spec(target)
        if "/" in s[at:]:
            return False
    return True


def _split_spec(spec: str) -> tuple[str, str]:
    """Split an npm-style package spec into (name, selector)."""
    if not spec:
        return "", ""
    if spec.startswith("python:"):
        return spec, ""
    start = 0
    if spec.startswith("@"):
        start = 1
    # npm alias: "pkg@npm:other@version"
    i = spec[start:].find("@npm:")
    if i >= 0:
        cut = start + i
        return spec[:cut], spec[cut:]
    # Last @ that's not the scope marker
    idx = spec[start:].rfind("@")
    if idx <= 0:
        return spec, ""
    cut = start + idx
    return spec[:cut], spec[cut:]


def _split_docker_image_ref(ref: str) -> tuple[str, str]:
    """Split Docker image ref into (name, tag)."""
    if not ref:
        return "", ""
    # Handle digest refs: "image@sha256:..."
    at = ref.find("@")
    if at >= 0:
        head = ref[:at]
        digest = ref[at:]
        last_slash = head.rfind("/")
        tail = head[last_slash + 1:] if last_slash >= 0 else head
        colon = tail.rfind(":")
        if colon >= 0:
            cut = colon
            if last_slash >= 0:
                cut = last_slash + 1 + colon
            return head[:cut] + digest, head[cut + 1:]
        return ref, ""
    last_slash = ref.rfind("/")
    tail = ref[last_slash + 1:] if last_slash >= 0 else ref
    colon = tail.rfind(":")
    if colon < 0:
        return ref, ""
    cut = colon
    if last_slash >= 0:
        cut = last_slash + 1 + colon
    return ref[:cut], ref[cut + 1:]
