"""
Catalog reading/writing helpers for Bumblebee exposure catalogs.

Supports atomic writes, metadata injection, and schema validation.
"""

import json
import os
import tempfile
from typing import Optional


SCHEMA_VERSION = "0.1.0"


def write_catalog(output_path: str, entries: list[dict],
                  metadata: Optional[dict] = None) -> str:
    """Write a Bumblebee exposure catalog atomically.

    Args:
        output_path: Final output path for the catalog file.
        entries: List of catalog entry dicts (each with id, name,
                 ecosystem, package, versions, severity).
        metadata: Optional dict with source metadata (source,
                  generated_at, source_revision, records_processed,
                  entries_emitted, records_skipped, skip_reasons).

    Returns:
        The output_path on success.

    Raises:
        OSError: If the write fails.
        ValueError: If entries cannot be serialized.
    """
    catalog = {
        "schema_version": SCHEMA_VERSION,
        "entries": entries,
    }
    if metadata:
        catalog["metadata"] = metadata

    content = json.dumps(catalog, indent=2, ensure_ascii=False)

    # Atomic write: write to temp, validate JSON, rename
    fd, tmp_path = tempfile.mkstemp(
        suffix=".json", prefix="bumblebee_catalog_",
        dir=os.path.dirname(output_path) or ".",
    )
    try:
        with os.fdopen(fd, "w") as f:
            f.write(content)
        # Validate the written JSON
        _validate_catalog(tmp_path)
        os.replace(tmp_path, output_path)
    except (OSError, ValueError):
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise

    return output_path


def _validate_catalog(path: str) -> None:
    """Validate that a JSON file is a readable exposure catalog."""
    with open(path) as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("catalog must be a JSON object")
    if data.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(f"unsupported schema_version {data.get('schema_version')!r}")
    if "entries" not in data:
        raise ValueError("catalog missing 'entries'")
    if not isinstance(data["entries"], list):
        raise ValueError("'entries' must be a list")
