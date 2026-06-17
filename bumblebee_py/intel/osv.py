"""
OSV malicious-package data retrieval and conversion.

Fetches the OpenSSF malicious-packages dataset and converts OSV-format
records to Bumblebee exposure-catalog entries.
"""

import json
import os
import sys
import time
from typing import Optional

if sys.version_info >= (3, 11):
    from urllib.request import urlopen, Request
    from urllib.error import URLError
else:
    from urllib2 import urlopen, Request  # type: ignore  # pragma: no cover
    from urllib2 import URLError  # type: ignore  # pragma: no cover


# Default upstream source for OSV malicious-packages data
DEFAULT_SOURCE = (
    "https://raw.githubusercontent.com/"
    "ossf/malicious-packages/main/"
    "osv-malicious.json"
)

# Ecosystem mapping: OSV ecosystem → Bumblebee ecosystem
ECOSYSTEM_MAP = {
    "npm": "npm",
    "PyPI": "pypi",
    "Go": "go",
    "RubyGems": "rubygems",
    "Packagist": "packagist",
    "Homebrew": "homebrew",
    # Mapped but not scanned by Bumblebee (records will be skipped)
    "Maven": "maven",
    "NuGet": "nuget",
    "Cargo": "cargo",
}

# Ecosystems Bumblebee actually scans
SCANNED_ECOSYSTEMS = {"npm", "pypi", "go", "rubygems", "packagist", "homebrew"}


def fetch_osv_data(source: str, timeout: int = 60) -> list[dict]:
    """Fetch OSV malicious-package data from a URL or local path.

    Args:
        source: URL or local file path.
        timeout: Request timeout in seconds (URL only).

    Returns:
        List of OSV entry dicts.

    Raises:
        ValueError: If the source cannot be read or parsed.
        OSError: If a local file cannot be read.
    """
    if os.path.isfile(source):
        with open(source, "rb") as f:
            raw = f.read()
    else:
        try:
            req = Request(source)
            resp = urlopen(req, timeout=timeout)
            raw = resp.read()
        except URLError as e:
            raise ValueError(f"network error fetching {source}: {e}") from e
        except Exception as e:
            raise ValueError(f"failed to fetch {source}: {e}") from e

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ValueError(f"invalid JSON from {source}: {e}") from e

    # OSV data can be a list of entries or {"entries": [...]}
    entries = data
    if isinstance(data, dict) and "entries" in data:
        entries = data["entries"]

    if not isinstance(entries, list):
        raise ValueError(f"expected a list of OSV entries, got {type(entries).__name__}")

    return entries


def convert_osv_entry(entry: dict) -> Optional[dict]:
    """Convert one OSV entry to a Bumblebee catalog entry.

    Args:
        entry: An OSV malicious-package record dict.

    Returns:
        A catalog entry dict on success, or None if the record should be skipped.
    """
    osv_id = entry.get("id", "")
    if not osv_id:
        return None

    affected = entry.get("affected", [])
    if not affected:
        return None

    first_affected = affected[0]
    pkg_info = first_affected.get("package", {})
    osv_eco = pkg_info.get("ecosystem", "")
    pkg_name = pkg_info.get("name", "")

    if not osv_eco or not pkg_name:
        return None

    # Map to Bumblebee ecosystem
    bb_eco = ECOSYSTEM_MAP.get(osv_eco, "")
    if not bb_eco:
        return None

    # Extract explicit versions only (OSV "versions" list)
    versions = []
    versions_list = first_affected.get("versions", [])
    if versions_list:
        for v in versions_list:
            v = v.strip()
            if v and v not in versions:
                versions.append(v)

    # If no explicit versions, check ranges for "fixed" events
    if not versions:
        ranges = first_affected.get("ranges", [])
        for r in ranges:
            for event in r.get("events", []):
                fixed = event.get("fixed", "")
                if fixed and fixed.strip() and fixed.strip() != "0":
                    v = fixed.strip()
                    if v not in versions:
                        versions.append(v)

    if not versions:
        return None  # Can't produce exact-version entries

    severity = _infer_severity(entry)

    return {
        "id": osv_id,
        "name": f"OSV: {osv_id}",
        "ecosystem": bb_eco,
        "package": pkg_name,
        "versions": versions,
        "severity": severity,
    }


def _infer_severity(entry: dict) -> str:
    """Infer severity from an OSV entry."""
    sev_list = entry.get("severity", [])
    for s in sev_list:
        if isinstance(s, dict):
            sev = s.get("type", "")
            if sev:
                return sev
    db_specific = entry.get("database_specific", {})
    if isinstance(db_specific, dict):
        sev = db_specific.get("severity", "")
        if sev:
            return sev
    return "high"


def convert_all(entries: list[dict]) -> tuple[list[dict], dict]:
    """Convert all OSV entries, collecting results and statistics.

    Args:
        entries: List of OSV entry dicts.

    Returns:
        (catalog_entries, stats) where stats includes records_processed,
        entries_emitted, records_skipped, and skip_reasons.
    """
    catalog_entries = []
    stats = {
        "records_processed": 0,
        "entries_emitted": 0,
        "records_skipped": 0,
        "skip_reasons": {},
    }

    for entry in entries:
        stats["records_processed"] += 1
        result = convert_osv_entry(entry)

        if result is None:
            stats["records_skipped"] += 1
            # Determine skip reason
            osv_id = entry.get("id", "")
            affected = entry.get("affected", [])
            reason = _skip_reason(entry)
            stats["skip_reasons"][reason] = stats["skip_reasons"].get(reason, 0) + 1
            continue

        # Check if this ecosystem is actually scanned by Bumblebee
        if result["ecosystem"] not in SCANNED_ECOSYSTEMS:
            catalog_entries.append(result)
            stats["entries_emitted"] += 1
        else:
            catalog_entries.append(result)
            stats["entries_emitted"] += 1

    return catalog_entries, stats


def _skip_reason(entry: dict) -> str:
    """Determine why an OSV entry was skipped."""
    affected = entry.get("affected", [])
    if not affected:
        return "no_affected_packages"
    first = affected[0]
    pkg_info = first.get("package", {})
    osv_eco = pkg_info.get("ecosystem", "")
    pkg_name = pkg_info.get("name", "")

    if not osv_eco:
        return "no_ecosystem"
    if not pkg_name:
        return "no_package_name"

    mapped = ECOSYSTEM_MAP.get(osv_eco, "")
    if not mapped:
        return f"unsupported_ecosystem:{osv_eco}"

    versions_list = first.get("versions", [])
    ranges = first.get("ranges", [])
    has_versions = bool(versions_list)
    has_fixed_ranges = any(
        event.get("fixed", "")
        for r in ranges
        for event in r.get("events", [])
    )
    if not has_versions and not has_fixed_ranges:
        return "no_explicit_versions"

    return "unknown"
