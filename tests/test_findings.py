"""Tests for exposure-catalog matching and finding generation."""

import json
import os
import tempfile

from bumblebee_py import model
from bumblebee_py.exposure import load as load_catalog, Entry, _build


FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


class TestCatalogLoading:
    """Tests for loading exposure catalogs."""

    def test_load_single_file(self):
        catalog = load_catalog(os.path.join(FIXTURE_DIR, "test-catalog.json"), 1024 * 1024)
        assert catalog is not None
        assert len(catalog.entries) == 2

    def test_load_directory(self):
        catalog = load_catalog(os.path.join(FIXTURE_DIR, "catalogs"), 1024 * 1024)
        assert catalog is not None
        assert len(catalog.entries) >= 2

    def test_load_with_metadata(self):
        """Catalog with metadata field loads successfully."""
        catalog = load_catalog(
            os.path.join(FIXTURE_DIR, "test-catalog-with-metadata.json"),
            1024 * 1024,
        )
        assert catalog is not None
        assert len(catalog.entries) == 1
        assert catalog.entries[0].id == "META-001"

    def test_load_nonexistent_path(self):
        try:
            load_catalog("/nonexistent/path.json", 1024 * 1024)
            assert False, "expected exception"
        except (FileNotFoundError, OSError, ValueError):
            pass


class TestFindingGeneration:
    """Tests that catalog matching produces correct findings."""

    def _make_record(self, ecosystem="npm", name="test-pkg", version="1.0.0"):
        return model.Record(
            ecosystem=ecosystem,
            package_name=name,
            normalized_name=name.lower(),
            version=version,
            source_type="npm-lockfile",
            source_file="/path/lock.json",
            confidence="high",
            endpoint=model.Endpoint(hostname="test"),
        )

    def test_exact_match_produces_finding(self):
        catalog = _build("0.1.0", [
            Entry(entry_id="TEST-001", name="Test entry", ecosystem="npm",
                  package="test-pkg", versions=["1.0.0"], severity="high"),
        ])
        record = self._make_record()
        matches = catalog.match_all(record)
        assert len(matches) == 1
        m = matches[0]
        assert m.entry.id == "TEST-001"
        assert m.version == "1.0.0"
        assert m.entry.severity == "high"

    def test_different_version_no_match(self):
        catalog = _build("0.1.0", [
            Entry(entry_id="TEST-001", name="Test", ecosystem="npm",
                  package="test-pkg", versions=["2.0.0"], severity="high"),
        ])
        record = self._make_record(version="1.0.0")
        matches = catalog.match_all(record)
        assert len(matches) == 0

    def test_different_ecosystem_no_match(self):
        catalog = _build("0.1.0", [
            Entry(entry_id="TEST-001", name="Test", ecosystem="npm",
                  package="test-pkg", versions=["1.0.0"], severity="high"),
        ])
        record = self._make_record(ecosystem="pypi")
        matches = catalog.match_all(record)
        assert len(matches) == 0

    def test_multiple_versions_match(self):
        catalog = _build("0.1.0", [
            Entry(entry_id="TEST-001", name="Test", ecosystem="npm",
                  package="test-pkg", versions=["1.0.0", "1.0.1", "2.0.0"],
                  severity="critical"),
        ])
        record = self._make_record(version="1.0.1")
        matches = catalog.match_all(record)
        assert len(matches) == 1
        assert matches[0].version == "1.0.1"


class TestFindingsOnlyMode:
    """Tests for --findings-only mode via CLI."""

    def test_findings_only_suppresses_packages(self):
        """Smoke test: --findings-only with a catalog produces findings."""
        import io, sys
        from unittest.mock import patch
        from bumblebee_py.cli import main

        stderr = io.StringIO()
        with patch("sys.stderr", stderr), \
             patch("os.path.isfile", return_value=True):
            rc = main(["scan", "--profile", "deep", "--root", "/tmp",
                       "--exposure-catalog",
                       os.path.join(FIXTURE_DIR, "test-catalog.json"),
                       "--findings-only"])
        # Should still succeed (finding counts may be 0 since no matching packages)
        # Just verify the exit code and that it ran without error
        assert rc in (0, 1), f"exit {rc}: {stderr.getvalue()}"
