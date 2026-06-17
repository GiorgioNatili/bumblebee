"""Tests for the NDJSON emitter."""
import io

from bumblebee_py.emitter import Emitter
from bumblebee_py.model import Record, Finding, Endpoint


def make_record(**kw):
    defaults = dict(
        ecosystem="npm",
        package_name="test-pkg",
        normalized_name="test-pkg",
        version="1.0.0",
        source_type="npm-lockfile",
        source_file="/path/lock.json",
        confidence="high",
        endpoint=Endpoint(hostname="test-host"),
    )
    defaults.update(kw)
    return Record(**defaults)


class TestEmitter:
    def test_emit_package(self):
        buf = io.StringIO()
        e = Emitter(buf, io.StringIO(), "run-1")
        r = make_record()
        ok, err = e.emit(r)
        assert ok is True
        assert err is None
        assert e.records_emitted == 1
        output = buf.getvalue()
        assert "test-pkg" in output
        assert '"record_type":"package"' in output

    def test_dedup(self):
        buf = io.StringIO()
        e = Emitter(buf, io.StringIO(), "run-2")
        r = make_record()
        ok1, _ = e.emit(r)
        ok2, _ = e.emit(r)  # same record again
        assert ok1 is True
        assert ok2 is False
        assert e.records_emitted == 1
        assert e.duplicates == 1

    def test_emit_finding(self):
        buf = io.StringIO()
        e = Emitter(buf, io.StringIO(), "run-3")
        f = Finding(
            finding_type="package_exposure",
            catalog_id="CVE-2023-0001",
            ecosystem="npm",
            package_name="test-pkg",
            normalized_name="test-pkg",
            version="1.0.0",
            source_type="npm-lockfile",
            source_file="/path/lock.json",
            confidence="high",
        )
        err = e.emit_finding(f)
        assert err is None
        output = buf.getvalue()
        assert '"record_type":"finding"' in output

    def test_diag(self):
        diag_buf = io.StringIO()
        e = Emitter(io.StringIO(), diag_buf, "run-4")
        e.diag("warn", "/path/to/file", "something went wrong")
        assert e.diagnostics_count == 1
        output = diag_buf.getvalue()
        assert "warn" in output
        assert "something went wrong" in output

    def test_emit_summary(self):
        from bumblebee_py.model import ScanSummary
        buf = io.StringIO()
        e = Emitter(buf, io.StringIO(), "run-5")
        s = ScanSummary(profile="baseline", status="complete")
        err = e.emit_summary(s)
        assert err is None
        output = buf.getvalue()
        assert '"record_type":"scan_summary"' in output

    def test_observe_package(self):
        buf = io.StringIO()
        e = Emitter(buf, io.StringIO(), "run-6")
        r = make_record()
        r2, ok = e.observe_package(r)
        assert ok is True
        r3, ok2 = e.observe_package(r)
        assert ok2 is False  # duplicate
        assert e.duplicates == 1

    def test_close_noop_for_stringio(self):
        e = Emitter(io.StringIO(), io.StringIO(), "run-7")
        err = e.close()
        assert err is None
