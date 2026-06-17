"""Tests for the bumblebee_py.intel submodule (OSV refresh + catalog)."""

import json
import os
import tempfile

from bumblebee_py.intel import osv as _osv
from bumblebee_py.intel import catalog as _catalog


FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


def _fixture(name):
    return os.path.join(FIXTURE_DIR, name)


class TestOSVFetch:
    """Tests for osv.fetch_osv_data."""

    def test_fetch_from_local_file(self):
        """Local OSV fixture is loaded correctly."""
        entries = _osv.fetch_osv_data(_fixture("osv-malicious-sample.json"))
        assert isinstance(entries, list)
        assert len(entries) == 10

    def test_fetch_missing_file(self):
        """Missing file raises ValueError."""
        try:
            _osv.fetch_osv_data("/nonexistent/path.json")
            assert False, "expected ValueError"
        except (ValueError, OSError):
            pass

    def test_fetch_wrapped_format(self):
        """OSV data wrapped in {'entries': [...]} is unwrapped."""
        data = {"entries": [{"id": "MAL-TEST-1", "affected": [{"package": {"ecosystem": "npm", "name": "test"}, "versions": ["1.0"]}]}]}
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as f:
            json.dump(data, f)
        try:
            entries = _osv.fetch_osv_data(path)
            assert len(entries) == 1
            assert entries[0]["id"] == "MAL-TEST-1"
        finally:
            os.unlink(path)


class TestOSVConvert:
    """Tests for osv.convert_osv_entry."""

    def _make_entry(self, overrides=None):
        entry = {
            "id": "MAL-TEST",
            "affected": [{
                "package": {"ecosystem": "npm", "name": "test-pkg"},
                "versions": ["1.0.0"],
                "ranges": [],
            }],
            "database_specific": {"severity": "critical"},
        }
        if overrides:
            entry.update(overrides)
        return entry

    def test_valid_npm_entry(self):
        result = _osv.convert_osv_entry(self._make_entry())
        assert result is not None
        assert result["ecosystem"] == "npm"
        assert result["package"] == "test-pkg"
        assert "1.0.0" in result["versions"]
        assert result["severity"] == "critical"

    def test_valid_pypi_entry(self):
        entry = self._make_entry({"affected": [{"package": {"ecosystem": "PyPI", "name": "test"}, "versions": ["1.0"]}]})
        result = _osv.convert_osv_entry(entry)
        assert result is not None
        assert result["ecosystem"] == "pypi"

    def test_no_id_returns_none(self):
        result = _osv.convert_osv_entry({"affected": [{"package": {"ecosystem": "npm", "name": "test"}, "versions": ["1.0"]}]})
        assert result is None

    def test_no_affected_returns_none(self):
        result = _osv.convert_osv_entry({"id": "MAL-TEST"})
        assert result is None

    def test_no_ecosystem_returns_none(self):
        result = _osv.convert_osv_entry(self._make_entry({"affected": [{"package": {"name": "test"}, "versions": ["1.0"]}]}))
        assert result is None

    def test_unsupported_ecosystem_creates_entry(self):
        """Maven maps via ECOSYSTEM_MAP, so convert_osv_entry returns an entry."""
        entry = self._make_entry({"affected": [{"package": {"ecosystem": "Maven", "name": "test"}, "versions": ["1.0"]}]})
        result = _osv.convert_osv_entry(entry)
        assert result is not None
        assert result["ecosystem"] == "maven"

    def test_no_versions_returns_none(self):
        entry = self._make_entry({"affected": [{"package": {"ecosystem": "npm", "name": "test"}, "versions": [], "ranges": []}]})
        result = _osv.convert_osv_entry(entry)
        assert result is None

    def test_fixed_version_from_range(self):
        """Range with 'fixed' event produces a version entry."""
        entry = self._make_entry({
            "affected": [{
                "package": {"ecosystem": "npm", "name": "test"},
                "versions": [],
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.0"}]}],
            }]
        })
        result = _osv.convert_osv_entry(entry)
        assert result is not None
        assert "1.0.0" in result["versions"]

    def test_severity_from_severity_list(self):
        entry = self._make_entry({
            "severity": [{"type": "MEDIUM"}],
            "database_specific": {"severity": "critical"},
        })
        result = _osv.convert_osv_entry(entry)
        assert result["severity"] == "MEDIUM"

    def test_severity_fallback(self):
        entry = self._make_entry({"database_specific": {}})
        result = _osv.convert_osv_entry(entry)
        assert result["severity"] == "high"


class TestOSVConvertAll:
    """Tests for osv.convert_all."""

    def test_convert_all(self):
        entries = _osv.fetch_osv_data(_fixture("osv-malicious-sample.json"))
        catalog_entries, stats = _osv.convert_all(entries)
        assert stats["records_processed"] == 10
        assert stats["entries_emitted"] >= 1
        assert stats["records_skipped"] >= 1
        assert isinstance(catalog_entries, list)

    def test_skip_reasons_present(self):
        entries = _osv.fetch_osv_data(_fixture("osv-malicious-sample.json"))
        _, stats = _osv.convert_all(entries)
        assert isinstance(stats["skip_reasons"], dict)
        # At least one skip reason should be recorded
        assert len(stats["skip_reasons"]) > 0 or stats["records_skipped"] == 0


class TestCatalogWrite:
    """Tests for catalog.write_catalog."""

    def test_write_catalog(self):
        entries = [{"id": "TEST-1", "name": "Test", "ecosystem": "npm", "package": "pkg", "versions": ["1.0"], "severity": "high"}]
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "catalog.json")
            result = _catalog.write_catalog(out, entries)
            assert result == out
            assert os.path.isfile(out)
            with open(out) as f:
                data = json.load(f)
            assert data["schema_version"] == "0.1.0"
            assert len(data["entries"]) == 1

    def test_write_with_metadata(self):
        entries = [{"id": "META-1", "name": "Meta", "ecosystem": "npm", "package": "p", "versions": ["1.0"], "severity": "low"}]
        meta = {"source": "test", "generated_at": "now", "records_processed": 5, "entries_emitted": 1, "records_skipped": 4, "skip_reasons": {}}
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "meta-catalog.json")
            _catalog.write_catalog(out, entries, metadata=meta)
            with open(out) as f:
                data = json.load(f)
            assert "metadata" in data
            assert data["metadata"]["source"] == "test"

    def test_empty_entries(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "empty.json")
            _catalog.write_catalog(out, [])
            with open(out) as f:
                data = json.load(f)
            assert data["entries"] == []


class TestCatalogValidation:
    """Tests for catalog._validate_catalog."""

    def test_valid_catalog(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "valid.json")
            with open(path, "w") as f:
                json.dump({"schema_version": "0.1.0", "entries": []}, f)
            _catalog._validate_catalog(path)  # should not raise

    def test_invalid_schema_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "bad.json")
            with open(path, "w") as f:
                json.dump({"schema_version": "9.9.9", "entries": []}, f)
            try:
                _catalog._validate_catalog(path)
                assert False, "expected ValueError"
            except ValueError:
                pass

    def test_missing_entries(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "noentries.json")
            with open(path, "w") as f:
                json.dump({"schema_version": "0.1.0"}, f)
            try:
                _catalog._validate_catalog(path)
                assert False, "expected ValueError"
            except ValueError:
                pass


class TestRefreshCLI:
    """Smoke tests for the intel refresh CLI via main()."""

    def test_refresh_dry_run(self):
        """--dry-run with local --source processes without writing output."""
        from bumblebee_py.intel.refresh import main
        rc = main(["--source", _fixture("osv-malicious-sample.json"), "--dry-run"])
        assert rc == 0

    def test_refresh_verbose(self):
        """--dry-run --verbose produces output to stderr."""
        import io, sys
        from bumblebee_py.intel.refresh import main
        stderr = io.StringIO()
        old_stderr = sys.stderr
        sys.stderr = stderr
        try:
            rc = main(["--source", _fixture("osv-malicious-sample.json"), "--dry-run", "--verbose"])
            assert rc == 0
            assert "[intel]" in stderr.getvalue()
        finally:
            sys.stderr = old_stderr

    def test_refresh_output_file(self):
        """--output writes a valid catalog file."""
        from bumblebee_py.intel.refresh import main
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            out = f.name
        try:
            rc = main(["--source", _fixture("osv-malicious-sample.json"), "--output", out])
            assert rc == 0
            with open(out) as f:
                data = json.load(f)
            assert "schema_version" in data
            assert "entries" in data
            assert "metadata" in data
        finally:
            os.unlink(out)

    def test_refresh_stdout_output(self):
        """Without --output, prints catalog to stdout."""
        import io, sys
        from bumblebee_py.intel.refresh import main
        stdout = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = stdout
        try:
            rc = main(["--source", _fixture("osv-malicious-sample.json")])
            assert rc == 0
            output = stdout.getvalue()
            assert '"schema_version": "0.1.0"' in output
            assert '"entries"' in output
        finally:
            sys.stdout = old_stdout
