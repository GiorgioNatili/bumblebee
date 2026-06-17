"""
Bounded, safety-aware filesystem walker.

The walker visits directories under configured roots, applying:
  - exclude-directory matching by name and suffix path
  - symlink-loop protection via visited-realpath tracking
  - file size limits live in the scanners themselves
"""

import os
import stat


# ── Default excludes ───────────────────────────────────────────────────────

DEFAULT_EXCLUDES = [
    ".git", ".hg", ".svn",
    ".ssh", ".gnupg", ".aws", ".azure",
    ".config/gcloud", ".kube", ".docker",

    # macOS Library — caches, mail/messages, browser profiles, system
    "Library/Caches",
    "Library/Application Support/Google/Chrome",
    "Library/Application Support/Chromium",
    "Library/Application Support/Firefox",
    "Library/Application Support/BraveSoftware",
    "Library/Application Support/Microsoft Edge",
    "Library/Application Support/Vivaldi",
    "Library/Application Support/Arc",
    "Library/Safari",
    "Library/Containers",
    "Library/ContainerManager",
    "Library/Daemon Containers",
    "Library/Group Containers",
    "Library/Mail", "Library/Messages",
    "Library/Suggestions", "Library/Trial", "Library/Weather",
    "Library/Metadata", "Library/Biome",
    "Library/PersonalizationPortrait", "Library/CoreFollowUp",
    "Library/HomeKit", "Library/Mobile Documents", "Library/CloudStorage",
    "Library/com.apple.aiml.instrumentation", "Library/IdentityServices",
    "Library/Keychains", "Library/Cookies", "Library/HTTPStorages",
    "Library/WebKit", "Library/Autosave Information",
    "Library/Saved Application State", "Library/DoNotDisturb",
    "Library/DuetExpertCenter", "Library/IntelligencePlatform",
    "Library/Photos", "Library/Sharing", "Library/Shortcuts",
    "Library/StatusKit", "Library/Accounts", "Library/Assistant",
    "Library/CallServices", "Library/com.apple.icloud.searchpartyd",
    "Library/FaceTime", "Library/Family", "Library/FrontBoard",
    "Library/Reminders", "Library/Springboard", "Library/Sync Services",
    "Library/Voice Trigger",

    # macOS media libraries
    "Movies/TV", "Music/Music",
    "Pictures/Photos Library.photoslibrary",
    "Pictures/Photo Booth Library",

    # Generic caches and high-cost build/dependency cache trees
    ".cache", ".npm/_cacache", ".pnpm-store", ".yarn/cache",
    ".gradle", ".m2", ".ivy2", ".sbt",
    "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    ".tox", ".venv-cache", ".nox", ".terraform",
    "node_modules/.cache",

    # Bazel
    "bazel-cache", "bazel-out", "bazel-bin", "bazel-testlogs",
    ".bazel-cache", ".cache/bazel",

    # Editor remote-server runtime/state/log subtrees
    ".vscode-server/data", ".vscode-server/bin", ".vscode-server/cli",
    ".vscode-server/logs",
    ".vscode-server-insiders/data", ".vscode-server-insiders/bin",
    ".vscode-server-insiders/cli", ".vscode-server-insiders/logs",
    ".cursor-server/data", ".cursor-server/bin", ".cursor-server/cli",
    ".cursor-server/logs",
    ".windsurf-server/data", ".windsurf-server/bin", ".windsurf-server/cli",
    ".windsurf-server/logs",
]


class SkipDir(Exception):
    """Raised by a Visitor to skip a directory subtree."""
    pass


def walk(roots, excludes, on_error, visit):
    """Walk each root, calling ``visit(path, name)`` for every entry.

    *visit* receives ``(full_path, basename)`` for each file or directory.
    Raise ``SkipDir`` to abort the current directory subtree.

    Args:
        roots: List of filesystem paths to walk.
        excludes: List of path patterns to exclude (basename or suffix match).
        on_error: ``callable(path, error)`` called for non-fatal errors.
        visit: ``callable(full_path, basename)`` — return normally, or
               raise SkipDir to skip a directory subtree.
    """
    excludes_normalized = _normalize_excludes(excludes or DEFAULT_EXCLUDES)
    seen_realpaths = set()

    for root in roots:
        root = os.path.normpath(root)
        _walk_one(root, excludes_normalized, seen_realpaths, on_error, visit)


def _walk_one(root, excludes, seen, on_error, visit):
    """Walk a single root directory tree."""
    if not os.path.isdir(root):
        # Non-directory root: visit the file directly
        try:
            visit(root, os.path.basename(root))
        except SkipDir:
            pass
        except Exception as e:
            if on_error:
                on_error(root, e)
        return

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        # Symlink-loop guard
        try:
            rp = os.path.realpath(dirpath)
            if rp in seen:
                dirnames.clear()
                continue
            seen.add(rp)
        except OSError:
            pass

        # Filter directories
        filtered = []
        for d in dirnames:
            full = os.path.join(dirpath, d)
            if _is_excluded(full, d, excludes):
                continue
            try:
                st = os.lstat(full)
                if stat.S_ISLNK(st.st_mode):
                    continue
            except OSError:
                continue
            filtered.append(d)
        dirnames[:] = filtered

        # Visit all entries (dirs + files)
        for name in dirnames + filenames:
            full = os.path.join(dirpath, name)
            try:
                visit(full, name)
            except SkipDir:
                # If it's a directory, prevent os.walk from descending
                if name in dirnames:
                    dirnames.remove(name)
            except Exception as e:
                if on_error:
                    on_error(full, e)


def _normalize_excludes(excludes):
    out = set()
    for x in excludes:
        x = x.strip()
        if x:
            out.add(os.path.normpath(x))
    return out


def _is_excluded(full_path, base, excludes):
    if base in excludes:
        return True
    # Suffix match: "Library/Caches" matches any path ending in /Library/Caches
    for ex in excludes:
        if "/" not in ex and os.sep not in ex:
            continue
        if os.path.normpath(full_path).endswith(os.sep + ex):
            return True
    return False
