"""
Exposure catalog loading and exact-match engine.

The catalog describes packages whose mere presence on an endpoint is the
signal of interest — typically the (ecosystem, name, version) tuples
published by a recent supply-chain compromise advisory.

v0.1 matching is exact: a package record matches a catalog entry when
ecosystem and normalized name are equal and the version equals one of
the entry's listed versions.
"""

import json
import os
import stat
from typing import Optional

from bumblebee_py import normalize
from bumblebee_py.model import SCHEMA_VERSION, Record


class Entry:
    """One exposure catalog entry."""

    def __init__(self, entry_id: str, ecosystem: str, package: str,
                 versions: list[str], name: str = "", severity: str = ""):
        self.id = entry_id
        self.name = name
        self.ecosystem = ecosystem
        self.package = package
        self.versions = versions
        self.severity = severity
        self.normalized = _normalize_name(ecosystem, package)

    @classmethod
    def from_dict(cls, d: dict) -> "Entry":
        entry_id = d.get("id", "")
        return cls(
            entry_id=entry_id,
            ecosystem=d.get("ecosystem", ""),
            package=d.get("package", ""),
            versions=d.get("versions", []),
            name=d.get("name", ""),
            severity=d.get("severity", ""),
        )


class Match:
    """A single (entry, matched-version) pair."""

    def __init__(self, entry: Entry, version: str):
        self.entry = entry
        self.version = version


class Catalog:
    """Parsed exposure catalog with indexed lookup."""

    def __init__(self, schema_version: str = "", entries: list = None,
                 index: dict = None):
        self.schema_version = schema_version
        self.entries: list[Entry] = entries or []
        # index: (ecosystem|normalized_name) -> list of Entry
        self._index: dict[str, list[Entry]] = index or {}

    def match(self, r: Record) -> tuple[Optional[Entry], str]:
        """Return (entry, matched_version) for the first match, or (None, '')."""
        hits = self.match_all(r)
        if not hits:
            return None, ""
        return hits[0].entry, hits[0].version

    def match_all(self, r: Record) -> list[Match]:
        """Return every catalog entry matching *r*."""
        if not self._index:
            return []
        key = f"{r.ecosystem}\x00{r.normalized_name}"
        hits = self._index.get(key)
        if not hits:
            return []
        out = []
        for e in hits:
            for v in e.versions:
                if v == r.version:
                    out.append(Match(entry=e, version=v))
                    break
        return out

    def __len__(self):
        return len(self.entries)


def load(path: str, max_size: int = 64 * 1024 * 1024) -> "Catalog":
    """Load an exposure catalog from *path*.

    If *path* is a directory, all ``*.json`` files directly inside are
    loaded and merged. Subdirectories and non-.json files are ignored.
    """
    info = os.stat(path)
    if not stat.S_ISDIR(info.st_mode):
        return load_file(path, max_size)
    return _load_dir(path, max_size)


def load_file(path: str, max_size: int = 64 * 1024 * 1024) -> "Catalog":
    """Load a single JSON exposure catalog file from disk."""
    info = os.stat(path)
    if not stat.S_ISREG(info.st_mode):
        raise ValueError(f"exposure catalog {path}: not a regular file")
    if max_size > 0 and info.st_size > max_size:
        raise ValueError(
            f"exposure catalog {path} exceeds max size {max_size} bytes "
            f"(file is {info.st_size})"
        )
    with open(path, "rb") as f:
        data = f.read()
    return parse(data)


def _load_dir(path: str, max_size: int) -> "Catalog":
    entries_list = []
    schema_version = ""
    first_source = ""

    # Collect JSON files from this directory and all subdirectories
    json_files = []
    for rootdir, dirs, files in os.walk(path):
        for name in files:
            if name.lower().endswith(".json"):
                json_files.append(os.path.join(rootdir, name))
    json_files.sort()

    for sub in json_files:
        # Resolve symlinks — skip if it's a directory
        try:
            info = os.stat(sub)
        except OSError:
            continue
        if stat.S_ISDIR(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode):
            # Symlink to dir that resolved as non-regular
            if os.path.isdir(sub):
                continue

        c = load_file(sub, max_size)
        if not schema_version:
            schema_version = c.schema_version
            first_source = sub
        elif c.schema_version and c.schema_version != schema_version:
            raise ValueError(
                f"exposure catalog {sub} declares schema_version "
                f"{c.schema_version!r} which conflicts with "
                f"{schema_version!r} from {first_source}"
            )
        entries_list.extend(c.entries)

    if not schema_version:
        return Catalog(index={})
    return _build(schema_version, entries_list)


def parse(data: bytes) -> "Catalog":
    """Parse a catalog from raw JSON bytes.

    Accepted shapes:
    - ``{"schema_version": "0.1.0", "entries": [...]}``
    - Empty/whitespace-only (returns empty catalog)
    """
    text = data.decode("utf-8").strip()
    if not text:
        return Catalog(index={})

    parsed = json.loads(text)
    if not isinstance(parsed, dict):
        raise ValueError(
            "parse exposure catalog: root must be a JSON object "
            "with 'schema_version' and 'entries' keys"
        )

    schema_ver = parsed.get("schema_version", "")
    if not schema_ver:
        raise ValueError(
            "parse exposure catalog: missing required field 'schema_version'"
        )
    raw_entries = parsed.get("entries")
    if raw_entries is None:
        raise ValueError(
            "parse exposure catalog: missing required field 'entries'"
        )
    if not isinstance(raw_entries, list):
        raise ValueError("parse exposure catalog: 'entries' must be an array")

    _validate_schema_version(schema_ver)
    entries = [Entry.from_dict(e) for e in raw_entries]
    return _build(schema_ver, entries)


def _build(schema_version: str, entries: list[Entry]) -> Catalog:
    """Build a Catalog with index from a validated list of Entry."""
    c = Catalog(schema_version=schema_version)
    for i, e in enumerate(entries):
        if not e.id:
            raise ValueError(f"catalog entry {i}: missing id")
        if not e.ecosystem:
            raise ValueError(f"catalog entry {e.id!r}: missing ecosystem")
        if not e.package:
            raise ValueError(f"catalog entry {e.id!r}: missing package")
        if not e.versions:
            raise ValueError(
                f"catalog entry {e.id!r}: at least one version is required"
            )
        c.entries.append(e)

    for e in c.entries:
        key = f"{e.ecosystem}\x00{e.normalized}"
        c._index.setdefault(key, []).append(e)
    return c


def _validate_schema_version(version: str):
    version = version.strip()
    if not version:
        raise ValueError(
            f"exposure catalog schema_version is required "
            f"(supported: {SCHEMA_VERSION!r})"
        )
    if version != SCHEMA_VERSION:
        raise ValueError(
            f"unsupported exposure catalog schema_version {version!r} "
            f"(supported: {SCHEMA_VERSION!r})"
        )


def _normalize_name(ecosystem: str, name: str) -> str:
    """Normalize a package name for the given ecosystem."""
    if ecosystem == "pypi":
        return normalize.pypi(name)
    elif ecosystem == "npm":
        return normalize.npm(name)
    else:
        return name.strip().lower()
