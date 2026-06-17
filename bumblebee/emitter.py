"""
NDJSON emitter for inventory records, findings, and diagnostics.

Records are JSON-encoded, one per line. The emitter deduplicates identical
package records within a single run using their stable record_id.
Findings and scan_summary records are not deduplicated at this layer.
"""

import json
import threading
import time
from io import TextIOBase
from typing import Any, Optional

from bumblebee.model import (
    RECORD_TYPE_DIAGNOSTIC,
    Record, Finding, ScanSummary, Diagnostic,
)


class SinkStats:
    """Transport-side counters copied into scan_summary."""

    def __init__(self):
        self.http_batches_attempted = 0
        self.http_batches_succeeded = 0
        self.http_batches_failed = 0
        self.http_last_status = 0


class Emitter:
    """Emits NDJSON records, findings, and diagnostics.

    Thread-safe. Records go to *records_writer*, diagnostics to *diags_writer*.
    """

    def __init__(self, records_writer: TextIOBase, diags_writer: TextIOBase, run_id: str):
        self._records = records_writer
        self._diags = diags_writer
        self._run_id = run_id
        self._lock = threading.Lock()
        self._seen: set[str] = set()

        self.records_emitted = 0
        self.duplicates = 0
        self.diagnostics_count = 0

    def observe_package(self, r: Record) -> tuple[Record, bool]:
        """Reserve the package record's dedup slot.

        Returns (canonicalized_record, is_new).
        """
        with self._lock:
            if r.record_type == "":
                r.record_type = "package"
            if r.record_id == "":
                r.record_id = r.stable_id()
            k = r.dedup_key()
            if k in self._seen:
                self.duplicates += 1
                return r, False
            self._seen.add(k)
            return r, True

    def emit_observed_package(self, r: Record) -> None:
        """Write a package record already canonicalized via observe_package."""
        with self._lock:
            self.records_emitted += 1
            self._write_json(self._records, r.to_dict())

    def emit(self, r: Record) -> tuple[bool, Optional[Exception]]:
        """Emit a package record unless a duplicate.

        Returns (was_written, error).
        """
        r, ok = self.observe_package(r)
        if not ok:
            return False, None
        try:
            self.emit_observed_package(r)
            return True, None
        except Exception as e:
            return True, e

    def emit_finding(self, f: Finding) -> Optional[Exception]:
        """Write one finding record to the records sink."""
        with self._lock:
            if f.record_type == "":
                f.record_type = "finding"
            if f.record_id == "":
                f.record_id = f.stable_id()
            try:
                self._write_json(self._records, f.to_dict())
            except Exception as e:
                return e
            return None

    def emit_summary(self, s: ScanSummary) -> Optional[Exception]:
        """Write a single scan_summary record."""
        with self._lock:
            if s.record_type == "":
                s.record_type = "scan_summary"
            if s.record_id == "":
                s.record_id = s.stable_id()
            try:
                self._write_json(self._records, s.to_dict())
            except Exception as e:
                return e
            return None

    def diag(self, level: str, path: str, msg: str):
        """Emit a diagnostic record to the diagnostics writer."""
        with self._lock:
            self.diagnostics_count += 1
            d = Diagnostic(
                record_type=RECORD_TYPE_DIAGNOSTIC,
                run_id=self._run_id,
                time=time.strftime("%Y-%m-%dT%H:%M:%S.", time.gmtime()) +
                 f"{int(time.time() * 1_000_000) % 1_000_000:06d}Z",
                level=level,
                path=path,
                message=msg,
            )
            d.record_id = d.stable_id()
            self._write_json(self._diags, d.to_dict())

    def close(self) -> Optional[Exception]:
        """Flush the records writer if it supports close."""
        if hasattr(self._records, "close"):
            try:
                self._records.close()
            except Exception as e:
                return e
        return None

    def sink_stats(self) -> SinkStats:
        """Return transport counters if the records writer exposes them."""
        reporter = getattr(self._records, "stats_reporter", None)
        if reporter:
            return reporter()
        return SinkStats()

    @staticmethod
    def _write_json(writer: TextIOBase, obj: dict[str, Any]):
        """Write one JSON line to *writer*."""
        line = json.dumps(obj, separators=(",", ":"), ensure_ascii=False)
        writer.write(line)
        writer.write("\n")
        writer.flush()
