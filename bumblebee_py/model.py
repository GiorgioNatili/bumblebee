"""
Data model definitions for the Bumblebee inventory record schema.

All record types are defined as frozen dataclasses with JSON serialization
matching the v0.1.0 schema. Stable IDs are SHA-256 content-addressed hashes
over the public metadata fields.
"""

import hashlib
from dataclasses import dataclass, field, asdict
from typing import Optional


# ── Constants ──────────────────────────────────────────────────────────────

SCHEMA_VERSION = "0.1.0"
SCANNER_NAME = "bumblebee"

RECORD_TYPE_PACKAGE = "package"
RECORD_TYPE_FINDING = "finding"
RECORD_TYPE_SCAN_SUMMARY = "scan_summary"
RECORD_TYPE_DIAGNOSTIC = "diagnostic"

SCAN_STATUS_COMPLETE = "complete"
SCAN_STATUS_PARTIAL = "partial"
SCAN_STATUS_ERROR = "error"

PROFILE_BASELINE = "baseline"
PROFILE_PROJECT = "project"
PROFILE_DEEP = "deep"

FINDING_TYPE_PACKAGE_EXPOSURE = "package_exposure"

# ── Ecosystem constants ────────────────────────────────────────────────────

ECOSYSTEM_NPM = "npm"
ECOSYSTEM_PYPI = "pypi"
ECOSYSTEM_GO = "go"
ECOSYSTEM_RUBYGEMS = "rubygems"
ECOSYSTEM_PACKAGIST = "packagist"
ECOSYSTEM_MCP = "mcp"
ECOSYSTEM_EDITOR_EXTENSION = "editor-extension"
ECOSYSTEM_BROWSER_EXTENSION = "browser-extension"
ECOSYSTEM_HOMEBREW = "homebrew"
ECOSYSTEM_AGENT_SKILL = "agent-skill"

_SUPPORTED_ECOSYSTEMS = frozenset({
    ECOSYSTEM_NPM,
    ECOSYSTEM_PYPI,
    ECOSYSTEM_GO,
    ECOSYSTEM_RUBYGEMS,
    ECOSYSTEM_PACKAGIST,
    ECOSYSTEM_MCP,
    ECOSYSTEM_EDITOR_EXTENSION,
    ECOSYSTEM_BROWSER_EXTENSION,
    ECOSYSTEM_HOMEBREW,
    ECOSYSTEM_AGENT_SKILL,
})

_SUPPORTED_ECOSYSTEM_ORDER = [
    ECOSYSTEM_NPM,
    ECOSYSTEM_PYPI,
    ECOSYSTEM_GO,
    ECOSYSTEM_RUBYGEMS,
    ECOSYSTEM_PACKAGIST,
    ECOSYSTEM_MCP,
    ECOSYSTEM_EDITOR_EXTENSION,
    ECOSYSTEM_BROWSER_EXTENSION,
    ECOSYSTEM_HOMEBREW,
    ECOSYSTEM_AGENT_SKILL,
]


def supported_ecosystems():
    """Return the list of supported ecosystem values."""
    return list(_SUPPORTED_ECOSYSTEM_ORDER)


def is_supported_ecosystem(ecosystem: str) -> bool:
    """Check whether *ecosystem* is a recognized emitted value."""
    return ecosystem in _SUPPORTED_ECOSYSTEMS


# ── Root kind constants ────────────────────────────────────────────────────

ROOT_KIND_GLOBAL_PACKAGE = "global_package_root"
ROOT_KIND_USER_PACKAGE = "user_package_root"
ROOT_KIND_PROJECT = "project_root"
ROOT_KIND_EDITOR_EXTENSION = "editor_extension_root"
ROOT_KIND_BROWSER_EXTENSION = "browser_extension_root"
ROOT_KIND_MCP_CONFIG = "mcp_config_root"
ROOT_KIND_AGENT_SKILL = "agent_skill_root"
ROOT_KIND_HOMEBREW = "homebrew_root"
ROOT_KIND_DEEP_HOME = "deep_home_root"
ROOT_KIND_UNKNOWN = "unknown"


# ── Helper functions ───────────────────────────────────────────────────────


def _stable_id(record_type: str, parts: list[str]) -> str:
    """Return a SHA-256 content-addressed stable ID.

    The canonical string is ``record_type + '\\x00' + parts joined by '\\x1e'``.
    """
    canonical = record_type + "\x00" + "\x1e".join(parts)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return f"{record_type}:{digest}"


def _bool_ptr(val: Optional[bool]) -> str:
    """Serialize a nullable bool to a string for stable-ID hashing."""
    if val is None:
        return ""
    return "true" if val else "false"


def _join_sorted(values: list[str]) -> str:
    """Join a sorted list with unit separator for hashing."""
    if not values:
        return ""
    return "\x1e".join(sorted(values))


def _canonical_counts(counts: dict[str, int]) -> str:
    """Canonical string representation of a counts dict for hashing."""
    if not counts:
        return ""
    parts = []
    for key in sorted(counts):
        parts.append(f"{key}\x1f{counts[key]}")
    return "\x1e".join(parts)


# ── Data types ─────────────────────────────────────────────────────────────


@dataclass
class Endpoint:
    hostname: str = ""
    os: str = ""
    arch: str = ""
    username: str = ""
    uid: str = ""
    device_id: str = ""


@dataclass
class Record:
    record_type: str = RECORD_TYPE_PACKAGE
    record_id: str = ""
    schema_version: str = SCHEMA_VERSION
    scanner_name: str = SCANNER_NAME
    scanner_version: str = ""
    run_id: str = ""
    scan_time: str = ""
    endpoint: Endpoint = field(default_factory=Endpoint)
    profile: str = ""
    ecosystem: str = ""
    package_name: str = ""
    normalized_name: str = ""
    version: str = ""
    project_path: str = ""
    root_kind: str = ""
    install_scope: str = ""
    package_manager: str = ""
    source_type: str = ""
    source_file: str = ""
    direct_dependency: Optional[bool] = None
    has_lifecycle_scripts: bool = False
    lifecycle_scripts: list[str] = field(default_factory=list)
    confidence: str = ""
    requested_spec: str = ""
    server_name: str = ""

    def dedup_key(self) -> str:
        return self.stable_id()

    def stable_id(self) -> str:
        return _stable_id(RECORD_TYPE_PACKAGE, [
            self.profile,
            self.ecosystem,
            self.normalized_name,
            self.version,
            self.project_path,
            self.root_kind,
            self.install_scope,
            self.package_manager,
            self.source_type,
            self.source_file,
            _bool_ptr(self.direct_dependency),
            "true" if self.has_lifecycle_scripts else "false",
            _join_sorted(self.lifecycle_scripts),
            self.confidence,
            self.requested_spec,
            self.server_name,
        ])

    def to_dict(self) -> dict:
        """Serialize to a JSON-safe dict, omitting empty optional fields."""
        d = asdict(self)
        # Remove empty optional fields
        if not d.get("project_path"):
            del d["project_path"]
        if not d.get("root_kind"):
            del d["root_kind"]
        if not d.get("install_scope"):
            del d["install_scope"]
        if not d.get("package_manager"):
            del d["package_manager"]
        if d.get("direct_dependency") is None:
            del d["direct_dependency"]
        if not d.get("lifecycle_scripts"):
            del d["lifecycle_scripts"]
        if not d.get("requested_spec"):
            del d["requested_spec"]
        if not d.get("server_name"):
            del d["server_name"]
        # Endpoint handling
        ep = dict(d["endpoint"])
        if not ep.get("device_id"):
            del ep["device_id"]
        d["endpoint"] = ep
        # Ensure record_id is set
        if not d.get("record_id"):
            d["record_id"] = self.stable_id()
        return d


@dataclass
class Finding:
    record_type: str = RECORD_TYPE_FINDING
    record_id: str = ""
    schema_version: str = SCHEMA_VERSION
    scanner_name: str = SCANNER_NAME
    scanner_version: str = ""
    run_id: str = ""
    scan_time: str = ""
    endpoint: Endpoint = field(default_factory=Endpoint)
    profile: str = ""
    finding_type: str = ""
    severity: str = ""
    catalog_id: str = ""
    catalog_name: str = ""
    ecosystem: str = ""
    package_name: str = ""
    normalized_name: str = ""
    version: str = ""
    root_kind: str = ""
    project_path: str = ""
    source_type: str = ""
    source_file: str = ""
    confidence: str = ""
    evidence: str = ""

    def stable_id(self) -> str:
        return _stable_id(RECORD_TYPE_FINDING, [
            self.profile,
            self.finding_type,
            self.catalog_id,
            self.ecosystem,
            self.normalized_name,
            self.version,
            self.root_kind,
            self.project_path,
            self.source_type,
            self.source_file,
            self.confidence,
        ])

    def to_dict(self) -> dict:
        d = asdict(self)
        if not d.get("severity"):
            del d["severity"]
        if not d.get("catalog_name"):
            del d["catalog_name"]
        if not d.get("root_kind"):
            del d["root_kind"]
        if not d.get("project_path"):
            del d["project_path"]
        if not d.get("evidence"):
            del d["evidence"]
        if not d.get("record_id"):
            d["record_id"] = self.stable_id()
        return d


@dataclass
class SummaryRoot:
    path: str = ""
    kind: str = ""


@dataclass
class ScanSummary:
    record_type: str = RECORD_TYPE_SCAN_SUMMARY
    record_id: str = ""
    schema_version: str = SCHEMA_VERSION
    scanner_name: str = SCANNER_NAME
    scanner_version: str = ""
    run_id: str = ""
    scan_time: str = ""
    end_time: str = ""
    endpoint: Endpoint = field(default_factory=Endpoint)
    profile: str = ""
    status: str = ""
    roots: list[SummaryRoot] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    package_records_emitted: int = 0
    package_records_suppressed: int = 0
    findings_emitted: int = 0
    duplicates: int = 0
    diagnostics_count: int = 0
    files_considered: int = 0
    timed_out: bool = False
    duration_ms: int = 0
    http_batches_attempted: int = 0
    http_batches_succeeded: int = 0
    http_batches_failed: int = 0
    http_last_status: int = 0
    error: str = ""

    def stable_id(self) -> str:
        root_parts = []
        for root in self.roots:
            root_parts.append(f"{root.path}\x1f{root.kind}")
        return _stable_id(RECORD_TYPE_SCAN_SUMMARY, [
            self.profile,
            self.status,
            self.scan_time,
            self.end_time,
            _join_sorted(root_parts) if root_parts else "",
            _canonical_counts(self.counts),
            str(self.package_records_emitted),
            str(self.package_records_suppressed),
            str(self.findings_emitted),
            str(self.duplicates),
            str(self.diagnostics_count),
            str(self.files_considered),
            "true" if self.timed_out else "false",
            str(self.duration_ms),
            str(self.http_batches_attempted),
            str(self.http_batches_succeeded),
            str(self.http_batches_failed),
            str(self.http_last_status),
            self.error,
        ])

    def to_dict(self) -> dict:
        d = asdict(self)
        if not d.get("roots"):
            del d["roots"]
        if not d.get("counts"):
            del d["counts"]
        if not d.get("error"):
            del d["error"]
        if d.get("package_records_suppressed", 0) == 0:
            del d["package_records_suppressed"]
        if d.get("http_batches_attempted", 0) == 0:
            for k in ("http_batches_attempted", "http_batches_succeeded", "http_batches_failed", "http_last_status"):
                d.pop(k, None)
        if not d.get("record_id"):
            d["record_id"] = self.stable_id()
        return d


@dataclass
class Diagnostic:
    record_type: str = RECORD_TYPE_DIAGNOSTIC
    record_id: str = ""
    run_id: str = ""
    time: str = ""
    level: str = ""
    path: str = ""
    message: str = ""

    def stable_id(self) -> str:
        return _stable_id(RECORD_TYPE_DIAGNOSTIC, [
            self.level,
            self.path,
            self.message,
        ])

    def to_dict(self) -> dict:
        d = asdict(self)
        if not d.get("path"):
            del d["path"]
        if not d.get("record_id"):
            d["record_id"] = self.stable_id()
        return d
