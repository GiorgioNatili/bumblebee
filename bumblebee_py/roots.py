"""
Profile-aware scan root resolution.

Each profile selects a different population of roots:
  - baseline  — bounded known package/tool roots only
  - project   — configured developer/project roots
  - deep      — incident-response exposure scan
"""

import glob
import os
import platform
from dataclasses import dataclass, field
from typing import Optional

from bumblebee_py.model import (
    PROFILE_BASELINE, PROFILE_PROJECT, PROFILE_DEEP,
    ROOT_KIND_GLOBAL_PACKAGE, ROOT_KIND_USER_PACKAGE,
    ROOT_KIND_PROJECT, ROOT_KIND_EDITOR_EXTENSION,
    ROOT_KIND_BROWSER_EXTENSION, ROOT_KIND_MCP_CONFIG,
    ROOT_KIND_AGENT_SKILL, ROOT_KIND_HOMEBREW,
    ROOT_KIND_DEEP_HOME, ROOT_KIND_UNKNOWN,
)
from bumblebee_py.scanner import Root


@dataclass
class RootsOpts:
    all_users: bool = False


def resolve_roots(profile: str, explicit: list[str],
                  opts: RootsOpts) -> tuple[list[Root], list[str], Optional[str]]:
    """Resolve scan roots for the given profile.

    Returns (roots, notes, error).
    """
    if profile not in (PROFILE_BASELINE, PROFILE_PROJECT, PROFILE_DEEP):
        return [], [], f"--profile is required (one of: baseline, project, deep)"

    if opts.all_users and profile == PROFILE_DEEP:
        return [], [], (
            "--all-users is not valid with --profile deep.\n"
            "deep is the incident-response profile and intentionally requires "
            "explicit --root paths.\n"
            "To fan out a deep sweep across users, pass --root /Users/<name> per user."
        )

    if explicit:
        if opts.all_users:
            return [], [], (
                "--all-users cannot be combined with explicit --root entries.\n"
                "--all-users expands the profile's curated defaults across every "
                "user home.\nEither drop --all-users and enumerate roots manually, "
                "or drop --root and let --all-users expand the defaults."
            )
        roots = []
        for p in explicit:
            kind = _classify_root(p, profile)
            if _is_broad_home_root(p) and profile != PROFILE_DEEP:
                return [], [], (
                    f"profile={profile} refuses broad home/filesystem root {p!r}.\n"
                    "baseline and project profiles are source/root-allowlist inventories "
                    "— they do not walk bare home directories.\n"
                    "For an incident-response exposure scan that does walk home roots, "
                    "re-run with --profile deep."
                )
            roots.append(Root(path=p, kind=kind))
        return roots, [], None

    if profile == PROFILE_BASELINE:
        return _baseline_default_roots(opts)
    elif profile == PROFILE_PROJECT:
        return _project_default_roots(opts)
    else:  # deep
        return [], [], (
            "profile=deep requires at least one explicit --root.\n"
            "deep is the incident-response profile and is intentionally not "
            "auto-configured.\nPass the home root(s) you want to scan, "
            'e.g. --root "$HOME" or --root /Users/<name>.'
        )


def _classify_root(path: str, profile: str) -> str:
    """Infer a RootKind for an operator-supplied --root path."""
    p = path.replace("\\", "/").rstrip("/")

    # Editor extensions
    if p.endswith("/extensions") and any(x in p for x in
                                         [".vscode", ".cursor", ".windsurf", ".vscodium"]):
        return ROOT_KIND_EDITOR_EXTENSION

    # Browser extensions
    if (p.endswith("/Extensions") or p.endswith("/extensions")) and any(
        x in p for x in ["Chrome", "Chromium", "Firefox", "BraveSoftware",
                         "Microsoft Edge", "Vivaldi", "Arc", "Comet",
                         "LibreWolf", "Waterfox", ".mozilla"]
    ):
        return ROOT_KIND_BROWSER_EXTENSION
    if p.endswith("/Profiles") and any(x in p for x in ["Firefox", "LibreWolf", "Waterfox"]):
        return ROOT_KIND_BROWSER_EXTENSION

    # MCP configs
    if any(x in p for x in [
        "Library/Application Support/Claude", "/.cursor", "/.codeium/windsurf",
        "/.claude", "/.codex", "/.gemini", "/.config/Claude",
        "/.config/Claude Code", "/.continue",
    ]):
        return ROOT_KIND_MCP_CONFIG

    # Agent skills
    if p.endswith("/.agents") or p.endswith("/.local/state/skills"):
        return ROOT_KIND_AGENT_SKILL

    # Homebrew
    if p in ("/opt/homebrew/lib", "/usr/local/lib") or \
       p.endswith("/Cellar") or p.endswith("/Caskroom") or \
       p.endswith("/Library/Python"):
        return ROOT_KIND_HOMEBREW

    # Broad home root
    if _is_broad_home_root(path):
        return ROOT_KIND_DEEP_HOME

    if profile == PROFILE_BASELINE:
        return ROOT_KIND_USER_PACKAGE
    if profile == PROFILE_PROJECT:
        return ROOT_KIND_PROJECT
    return ROOT_KIND_UNKNOWN


def _is_broad_home_root(path: str) -> bool:
    if not path:
        return False
    abs_path = os.path.abspath(path)
    if abs_path == "/":
        return True
    home = os.path.expanduser("~")
    if home and abs_path == os.path.normpath(home):
        return True
    if abs_path in ("/Users", "/home", "/root"):
        return True
    parent = os.path.dirname(abs_path)
    if parent in ("/Users", "/home"):
        return True
    return False


def _baseline_default_roots(opts: RootsOpts) -> tuple[list[Root], list[str], None]:
    """Return baseline profile default roots."""
    candidates = []
    homes = _homes_for_expansion(opts)
    for home in homes:
        candidates.extend(_baseline_home_candidates(home))
    candidates.extend(_system_roots())

    present, notes = _filter_existing_roots(candidates)
    if opts.all_users:
        if platform.system().lower() == "darwin":
            notes.append(_all_users_expansion_note())
        else:
            notes.append("--all-users expansion: not supported on this OS; "
                         "using current user's default roots")

    if not present:
        return [], notes, "profile=baseline found no default roots on this host. Pass --root explicitly."
    return present, notes, None


def _project_default_roots(opts: RootsOpts) -> tuple[list[Root], list[str], None]:
    """Return project profile default roots."""
    candidates = []
    homes = _homes_for_expansion(opts)
    for home in homes:
        for sub in ("code", "src", "Developer", "Projects", "workspace"):
            candidates.append(Root(
                path=os.path.join(home, sub),
                kind=ROOT_KIND_PROJECT,
            ))

    present, notes = _filter_existing_roots(candidates)
    if opts.all_users:
        if platform.system().lower() == "darwin":
            notes.append(_all_users_expansion_note())
        else:
            notes.append("--all-users expansion: not supported on this OS; "
                         "using current user's default roots")

    if not present:
        return [], notes, "profile=project found no default roots on this host. Pass --root explicitly."
    return present, notes, None


def _baseline_home_candidates(home: str) -> list[Root]:
    """Per-home set of curated baseline root candidates."""
    if not home:
        return []
    out = []

    def add(p, kind):
        out.append(Root(path=p, kind=kind))

    # Language toolchains
    add(os.path.join(home, "go"), ROOT_KIND_USER_PACKAGE)
    add(os.path.join(home, ".cargo"), ROOT_KIND_USER_PACKAGE)
    add(os.path.join(home, ".rbenv"), ROOT_KIND_USER_PACKAGE)
    add(os.path.join(home, ".rvm"), ROOT_KIND_USER_PACKAGE)
    add(os.path.join(home, ".pyenv", "versions"), ROOT_KIND_USER_PACKAGE)
    add(os.path.join(home, ".asdf", "installs"), ROOT_KIND_USER_PACKAGE)
    add(os.path.join(home, ".nvm", "versions"), ROOT_KIND_USER_PACKAGE)
    for p in glob.glob(os.path.join(home, ".local", "lib", "python*")):
        if os.path.isdir(p):
            add(p, ROOT_KIND_USER_PACKAGE)
    add(os.path.join(home, ".local", "share", "pipx", "venvs"), ROOT_KIND_USER_PACKAGE)

    # Editor extension trees
    for seg in ["extensions"]:
        for editor in [".vscode", ".vscode-insiders", ".vscode-server",
                       ".cursor", ".cursor-server", ".windsurf",
                       ".windsurf-server", ".vscodium"]:
            add(os.path.join(home, editor, seg), ROOT_KIND_EDITOR_EXTENSION)

    # MCP config locations
    add(os.path.join(home, ".cursor"), ROOT_KIND_MCP_CONFIG)
    add(os.path.join(home, ".codeium", "windsurf"), ROOT_KIND_MCP_CONFIG)
    add(os.path.join(home, ".claude"), ROOT_KIND_MCP_CONFIG)
    add(os.path.join(home, ".claude.json"), ROOT_KIND_MCP_CONFIG)
    add(os.path.join(home, ".codex"), ROOT_KIND_MCP_CONFIG)
    add(os.path.join(home, ".gemini"), ROOT_KIND_MCP_CONFIG)
    if platform.system().lower() == "darwin":
        add(os.path.join(home, "Library", "Application Support", "Claude"),
            ROOT_KIND_MCP_CONFIG)
    else:
        add(os.path.join(home, ".config", "Claude"), ROOT_KIND_MCP_CONFIG)
        add(os.path.join(home, ".config", "Claude Code"), ROOT_KIND_MCP_CONFIG)
        add(os.path.join(home, ".continue"), ROOT_KIND_MCP_CONFIG)

    # Agent-skill lock locations
    add(os.path.join(home, ".agents"), ROOT_KIND_AGENT_SKILL)
    xdg = os.environ.get("XDG_STATE_HOME", "")
    if xdg:
        add(os.path.join(xdg, "skills"), ROOT_KIND_AGENT_SKILL)

    # Browser extension trees
    for r in _browser_extension_candidate_roots(home):
        add(r, ROOT_KIND_BROWSER_EXTENSION)

    return out


def _system_roots() -> list[Root]:
    """Return OS-specific system/Homebrew install prefixes."""
    out = []
    if platform.system().lower() == "darwin":
        out.extend([
            Root(path="/opt/homebrew/Cellar", kind=ROOT_KIND_HOMEBREW),
            Root(path="/opt/homebrew/Caskroom", kind=ROOT_KIND_HOMEBREW),
            Root(path="/opt/homebrew/lib", kind=ROOT_KIND_HOMEBREW),
            Root(path="/usr/local/Cellar", kind=ROOT_KIND_HOMEBREW),
            Root(path="/usr/local/Caskroom", kind=ROOT_KIND_HOMEBREW),
            Root(path="/usr/local/lib", kind=ROOT_KIND_HOMEBREW),
            Root(path="/Library/Python", kind=ROOT_KIND_HOMEBREW),
        ])
    else:
        out.extend([
            Root(path="/usr/local/lib", kind=ROOT_KIND_GLOBAL_PACKAGE),
            Root(path="/home/linuxbrew/.linuxbrew/Cellar", kind=ROOT_KIND_HOMEBREW),
            Root(path="/home/linuxbrew/.linuxbrew/Caskroom", kind=ROOT_KIND_HOMEBREW),
        ])
        for p in glob.glob("/usr/lib/python*"):
            if os.path.isdir(p):
                out.append(Root(path=p, kind=ROOT_KIND_GLOBAL_PACKAGE))
    return out


def _browser_extension_candidate_roots(home: str) -> list[str]:
    """Return per-profile browser extension directory candidates."""
    roots = []
    chromium_profiles = [f"Profile {i}" for i in range(10)]
    chromium_profiles.insert(0, "Default")

    chromium_bases = {}
    sysname = platform.system().lower()
    if sysname == "darwin":
        app_support = os.path.join(home, "Library", "Application Support")
        chromium_bases["chrome"] = [os.path.join(app_support, "Google", "Chrome")]
        chromium_bases["chromium"] = [os.path.join(app_support, "Chromium")]
        chromium_bases["brave"] = [os.path.join(app_support, "BraveSoftware", "Brave-Browser")]
        chromium_bases["edge"] = [os.path.join(app_support, "Microsoft Edge")]
        chromium_bases["vivaldi"] = [os.path.join(app_support, "Vivaldi")]
        chromium_bases["arc"] = [os.path.join(app_support, "Arc", "User Data")]
        chromium_bases["comet"] = [os.path.join(app_support, "Comet")]
    else:
        cfg = os.path.join(home, ".config")
        chromium_bases["chrome"] = [os.path.join(cfg, "google-chrome")]
        chromium_bases["chromium"] = [
            os.path.join(cfg, "chromium"),
            os.path.join(home, "snap", "chromium", "common", "chromium"),
            os.path.join(home, ".var", "app", "org.chromium.Chromium", "config", "chromium"),
        ]
        chromium_bases["brave"] = [
            os.path.join(cfg, "BraveSoftware", "Brave-Browser"),
            os.path.join(home, ".var", "app", "com.brave.Browser", "config",
                         "BraveSoftware", "Brave-Browser"),
        ]
        chromium_bases["edge"] = [
            os.path.join(cfg, "microsoft-edge"),
            os.path.join(home, ".var", "app", "com.microsoft.Edge", "config", "microsoft-edge"),
        ]
        chromium_bases["vivaldi"] = [os.path.join(cfg, "vivaldi")]

    for bases in chromium_bases.values():
        for b in bases:
            for prof in chromium_profiles:
                roots.append(os.path.join(b, prof, "Extensions"))

    # Firefox
    if sysname == "darwin":
        app_support = os.path.join(home, "Library", "Application Support")
        roots.extend([
            os.path.join(app_support, "Firefox", "Profiles"),
            os.path.join(app_support, "LibreWolf", "Profiles"),
            os.path.join(app_support, "Waterfox", "Profiles"),
        ])
    else:
        roots.extend([
            os.path.join(home, ".mozilla", "firefox"),
            os.path.join(home, "snap", "firefox", "common", ".mozilla", "firefox"),
            os.path.join(home, ".var", "app", "org.mozilla.firefox", ".mozilla", "firefox"),
            os.path.join(home, ".librewolf"),
            os.path.join(home, ".var", "app", "io.gitlab.librewolf-community", ".librewolf"),
            os.path.join(home, ".waterfox"),
        ])

    return roots


def _filter_existing_roots(candidates: list[Root]) -> tuple[list[Root], list[str]]:
    """Return roots that exist, plus a note about skipped ones."""
    present = []
    skipped = 0
    for c in candidates:
        try:
            info = os.stat(c.path)
            if os.path.isdir(c.path) or os.path.isfile(c.path):
                present.append(c)
            else:
                skipped += 1
        except OSError:
            skipped += 1

    notes = []
    if present and skipped > 0:
        notes.append(
            f"default roots: {len(present)} present, {skipped} candidate paths absent"
        )
    return present, notes


def _homes_for_expansion(opts: RootsOpts) -> list[str]:
    """Return home directories for root expansion."""
    if opts.all_users and platform.system().lower() == "darwin":
        homes = _all_users_homes()
        if homes:
            return homes
    home = os.path.expanduser("~")
    if home:
        return [home]
    return []


def _all_users_homes() -> list[str]:
    """Enumerate real user home directories under /Users."""
    users_dir = os.environ.get("BUMBLEBEE_USERS_DIR", "") or "/Users"
    try:
        entries = os.listdir(users_dir)
    except OSError:
        return []
    homes = []
    for name in entries:
        if not _is_likely_user_home_name(name):
            continue
        full = os.path.join(users_dir, name)
        if os.path.isdir(full):
            homes.append(full)
    return homes


def _is_likely_user_home_name(name: str) -> bool:
    if not name or name.startswith("."):
        return False
    if name.lower() in ("shared", "guest", "root", "deleted users"):
        return False
    return True


def _all_users_expansion_note() -> str:
    homes = _all_users_homes()
    users_dir = os.environ.get("BUMBLEBEE_USERS_DIR", "") or "/Users"
    return f"--all-users expansion: {len(homes)} home(s) under {users_dir}"
