#!/usr/bin/env python3
"""
OSV malicious-package catalog converter.

Reads the OSV (Open Source Vulnerabilities) malicious-package dataset
and produces Bumblebee exposure catalogs.

Usage: python -m bumblebee.tools.osvcatalog <osv-dump.json> [output-dir]
"""

import json
import os
import sys


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    if len(argv) < 1:
        print(f"Usage: {sys.argv[0]} <osv-dump.json> [output-dir]", file=sys.stderr)
        return 2

    input_path = argv[0]
    output_dir = argv[1] if len(argv) > 1 else "."

    if not os.path.isdir(output_dir):
        os.makedirs(output_dir, exist_ok=True)

    with open(input_path, "r") as f:
        data = json.load(f)

    # OSV data can be a list of entries or a list of {"entries": [...]}
    entries = data
    if isinstance(data, dict) and "entries" in data:
        entries = data["entries"]

    count = 0
    for entry in entries:
        if not isinstance(entry, dict):
            continue

        osv_id = entry.get("id", "")
        if not osv_id:
            continue

        ecosystem = ""
        packages = entry.get("affected", [])
        if not packages:
            continue

        affected = packages[0]
        package = affected.get("package", {})
        ecosystem = package.get("ecosystem", "")
        pkg_name = package.get("name", "")

        if not ecosystem or not pkg_name:
            continue

        # Map OSV ecosystem to Bumblebee ecosystem
        bb_ecosystem = _map_ecosystem(ecosystem)
        if not bb_ecosystem:
            continue

        # Extract versions
        versions = []
        versions_info = affected.get("versions", []) or []
        ranges = affected.get("ranges", []) or []

        # Use versions list directly
        for v in versions_info:
            v = v.strip()
            if v and v not in versions:
                versions.append(v)

        # Fall back to range events
        if not versions:
            for r in ranges:
                for event in r.get("events", []) or []:
                    v = event.get("fixed", event.get("introduced", ""))
                    if v and v != "0":
                        v = v.strip()
                        if v and v not in versions:
                            versions.append(v)

        if not versions:
            continue

        severity = _infer_severity(entry)

        catalog_entry = {
            "id": osv_id,
            "name": f"OSV: {osv_id}",
            "ecosystem": bb_ecosystem,
            "package": pkg_name,
            "versions": versions,
            "severity": severity,
        }

        # Write one catalog per OSV entry
        fname = f"{osv_id}.json"
        fpath = os.path.join(output_dir, fname)
        with open(fpath, "w") as out:
            json.dump({
                "schema_version": "0.1.0",
                "entries": [catalog_entry],
            }, out, indent=2)

        count += 1

    print(f"Wrote {count} catalog file(s) to {output_dir}/", file=sys.stderr)
    return 0


def _map_ecosystem(osv_eco: str) -> str:
    """Map OSV ecosystem names to Bumblebee ecosystem names."""
    mapping = {
        "npm": "npm",
        "PyPI": "pypi",
        "Go": "go",
        "RubyGems": "rubygems",
        "Packagist": "packagist",
        "Homebrew": "homebrew",
        "Maven": "maven",
        "NuGet": "nuget",
        "Cargo": "cargo",
    }
    return mapping.get(osv_eco, "")


def _infer_severity(entry: dict) -> str:
    """Infer a severity label from an OSV entry."""
    severity = entry.get("severity", [])
    for s in severity:
        if isinstance(s, dict):
            return s.get("type", "unknown")
    # Look for database_specific
    db_specific = entry.get("database_specific", {})
    if isinstance(db_specific, dict):
        severity = db_specific.get("severity", "")
        if severity:
            return severity
    return "high"


if __name__ == "__main__":
    sys.exit(main())
