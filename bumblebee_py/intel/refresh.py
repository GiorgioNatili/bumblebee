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

from bumblebee_py.intel import osv as _osv
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
        help="Source URL or local file path for OSV data "
             f"(default: {_osv.DEFAULT_SOURCE})",
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

    source = opts.source or _osv.DEFAULT_SOURCE
    is_url = not os.path.isfile(source)

    if opts.verbose:
        print(f"[intel] source: {source}", file=sys.stderr)
        if is_url:
            print(f"[intel] fetching from upstream...", file=sys.stderr)

    try:
        entries = _osv.fetch_osv_data(source)
    except (ValueError, OSError) as e:
        print(f"[intel] error: {e}", file=sys.stderr)
        return 1

    if opts.verbose:
        print(f"[intel] processing {len(entries)} records...", file=sys.stderr)

    catalog_entries, stats = _osv.convert_all(entries)

    if opts.verbose:
        print(f"[intel] processed: {stats['records_processed']}, "
              f"emitted: {stats['entries_emitted']}, "
              f"skipped: {stats['records_skipped']}",
              file=sys.stderr)
        if stats["skip_reasons"]:
            print(f"[intel] skip reasons: {stats['skip_reasons']}", file=sys.stderr)

    if opts.dry_run:
        if opts.verbose:
            print(f"[intel] dry-run: would write {stats['entries_emitted']} entries",
                  file=sys.stderr)
        return 0

    metadata = {
        "source": source if is_url else os.path.abspath(source),
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
