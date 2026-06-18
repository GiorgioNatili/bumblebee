"""
``bumblebee intel refresh`` subcommand.

Fetches OSV malicious-package data and writes a local Bumblebee
exposure catalog.
"""

import argparse
import json
import os
import sys
import time
from typing import Optional

from bumblebee_py.catalogs import osv as _osv
from bumblebee_py.intel import catalog as _catalog


def main(argv: Optional[list[str]] = None) -> int:
    """Entry point for ``bumblebee intel refresh``.

    Returns exit code.
    """
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(
        prog="bumblebee intel refresh",
        description="Fetch OSV malicious-package data and refresh local exposure catalogs.",
    )
    parser.add_argument(
        "--output", "-o", default="",
        help="Output path for the generated catalog file (default: stdout)",
    )
    parser.add_argument(
        "--source", default="",
        help="Source URL, local file path, or 'osv-malicious' for OSSF per-ecosystem "
             f"fetch (default: per-ecosystem fetch from OSSF malicious-packages repo)",
    )
    parser.add_argument(
        "--dry-run", action="store_true", default=False,
        help="Fetch and parse but do not write output",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", default=False,
        help="Print progress information to stderr",
    )

    opts = parser.parse_args(argv)

    # Source aliases: map shorthand names to real source locations
    source = opts.source.lower() if opts.source else ""
    if source in ("openssf", "osv-malicious", ""):
        effective_source = _osv.DEFAULT_SOURCE
    elif source == "ghsa":
        effective_source = "osv-malicious"
    elif source == "cisa-kev":
        effective_source = (
            "https://www.cisa.gov/sites/default/files/feeds/"
            "known_exploited_vulnerabilities.json"
        )
    else:
        effective_source = opts.source

    is_ecosystem = (effective_source == "osv-malicious")
    is_url = not is_ecosystem and not os.path.isfile(effective_source)
    source_label = source if source else "openssf"

    if opts.verbose:
        labels = {"openssf": "OpenSSF malicious-packages",
                  "ghsa": "GitHub Advisory Database",
                  "cisa-kev": "CISA KEV",
                  "osv-malicious": "OSSF malicious-packages"}
        label = labels.get(source_label, source_label)
        print(f"[catalog] source: {label}", file=sys.stderr)
        if is_url:
            print(f"[catalog] fetching from upstream...", file=sys.stderr)

    try:
        entries = _osv.fetch_osv_data(effective_source)
    except (ValueError, OSError) as e:
        print(f"[catalog] error: {e}", file=sys.stderr)
        return 1

    if opts.verbose:
        print(f"[catalog] processing {len(entries)} records...", file=sys.stderr)

    catalog_entries, stats = _osv.convert_all(entries)

    if opts.verbose:
        print(f"[catalog] processed: {stats['records_processed']}, "
              f"emitted: {stats['entries_emitted']}, "
              f"skipped: {stats['records_skipped']}",
              file=sys.stderr)
        if stats["skip_reasons"]:
            print(f"[catalog] skip reasons: {stats['skip_reasons']}", file=sys.stderr)

    if opts.dry_run:
        if opts.verbose:
            print(f"[catalog] dry-run: would write {stats['entries_emitted']} entries",
                  file=sys.stderr)
        return 0

    metadata = {
        "source": source_label,
        "source_url": effective_source if is_url else os.path.abspath(effective_source),
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source_revision": "",
        "records_processed": stats["records_processed"],
        "entries_emitted": stats["entries_emitted"],
        "records_skipped": stats["records_skipped"],
        "skip_reasons": stats["skip_reasons"],
    }

    if not opts.output:
        # Print to stdout
        catalog = {
            "schema_version": _catalog.SCHEMA_VERSION,
            "metadata": metadata,
            "entries": catalog_entries,
        }
        print(json.dumps(catalog, indent=2, ensure_ascii=False))
        if opts.verbose:
            print(f"[intel] wrote {stats['entries_emitted']} entries to stdout",
                  file=sys.stderr)
        return 0

    try:
        _catalog.write_catalog(opts.output, catalog_entries, metadata=metadata)
    except (OSError, ValueError) as e:
        print(f"[intel] write error: {e}", file=sys.stderr)
        return 1

    if opts.verbose:
        print(f"[intel] wrote {stats['entries_emitted']} entries to {opts.output}",
              file=sys.stderr)
    return 0
