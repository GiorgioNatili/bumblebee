"""Tests for the exposure catalog."""
import json
import tempfile
import os

from bumblebee_py.exposure import (
    Catalog, Entry, Match, load, load_file, parse, _build,
)
from bumblebee_py.model import Record, Endpoint


SAMPLE_CATALOG_JSON = json.dumps({
    "schema_version": "0.1.0",
    "entries": [
        {
            "id": "CVE-2023-0001",
            "name": "Test Advisory",
            "ecosystem": "npm",
            "package": "left-pad",
            "versions": ["1.0.0", "1.0.1"],
            "severity": "critical",
        },
        {
            "id": "CVE-2023-0002",
            "name": "PyPI Advisory",
            "ecosystem": "pypi",
            "package": "Requests",
            "versions": ["2.28.0"],
            "severity": "high",
        },
    ],
})


class TestParse:
    def test_parse_valid(self):
        c = parse(SAMPLE_CATALOG_JSON.encode("utf-8"))
        assert c.schema_version == "0.1.0"
        assert len(c.entries) == 2
        assert c.entries[0].id == "CVE-2023-0001"
        assert c.entries[0].ecosystem == "npm"
        assert c.entries[0].normalized == "left-pad"

    def test_parse_empty(self):
        c = parse(b"")
        assert len(c.entries) == 0

    def test_parse_whitespace(self):
        c = parse(b"   ")
        assert len(c.entries) == 0

    def test_parse_missing_schema_version(self):
        import pytest
        with pytest.raises(ValueError, match="schema_version"):
            parse(b'{"entries": []}')

    def test_parse_missing_entries(self):
        import pytest
        with pytest.raises(ValueError, match="entries"):
            parse(b'{"schema_version": "0.1.0"}')

    def test_parse_wrong_schema_version(self):
        import pytest
        with pytest.raises(ValueError, match="unsupported"):
            parse(b'{"schema_version": "0.2.0", "entries": []}')

    def test_parse_entry_missing_id(self):
        import pytest
        with pytest.raises(ValueError, match="missing id"):
            parse(json.dumps({
                "schema_version": "0.1.0",
                "entries": [{"ecosystem": "npm", "package": "foo", "versions": ["1.0"]}]
            }).encode())


class TestMatch:
    def test_exact_match_npm(self):
        c = parse(SAMPLE_CATALOG_JSON.encode("utf-8"))
        r = Record(ecosystem="npm", normalized_name="left-pad", version="1.0.0")
        entry, version = c.match(r)
        assert entry is not None
        assert entry.id == "CVE-2023-0001"
        assert version == "1.0.0"

    def test_no_match_wrong_version(self):
        c = parse(SAMPLE_CATALOG_JSON.encode("utf-8"))
        r = Record(ecosystem="npm", normalized_name="left-pad", version="9.9.9")
        entry, version = c.match(r)
        assert entry is None

    def test_no_match_wrong_ecosystem(self):
        c = parse(SAMPLE_CATALOG_JSON.encode("utf-8"))
        r = Record(ecosystem="go", normalized_name="left-pad", version="1.0.0")
        entry, version = c.match(r)
        assert entry is None

    def test_match_all_multiple(self):
        # Create catalog with two entries for same package
        data = json.dumps({
            "schema_version": "0.1.0",
            "entries": [
                {"id": "ADV-1", "ecosystem": "npm", "package": "foo", "versions": ["1.0"]},
                {"id": "ADV-2", "ecosystem": "npm", "package": "foo", "versions": ["1.0"]},
            ],
        })
        c = parse(data.encode())
        r = Record(ecosystem="npm", normalized_name="foo", version="1.0")
        hits = c.match_all(r)
        assert len(hits) == 2
        assert hits[0].entry.id == "ADV-1"
        assert hits[1].entry.id == "ADV-2"

    def test_pypi_normalization(self):
        data = json.dumps({
            "schema_version": "0.1.0",
            "entries": [
                {"id": "ADV-3", "ecosystem": "pypi", "package": "Requests", "versions": ["2.28.0"]},
            ],
        })
        c = parse(data.encode())
        # normalized form is "requests"
        r = Record(ecosystem="pypi", normalized_name="requests", version="2.28.0")
        entry, _ = c.match(r)
        assert entry is not None

    def test_npm_normalization(self):
        data = json.dumps({
            "schema_version": "0.1.0",
            "entries": [
                {"id": "ADV-4", "ecosystem": "npm", "package": "@TanStack/Query-Core",
                 "versions": ["1.0.0"]},
            ],
        })
        c = parse(data.encode())
        r = Record(ecosystem="npm", normalized_name="@tanstack/query-core", version="1.0.0")
        entry, _ = c.match(r)
        assert entry is not None


class TestLoadFile:
    def test_load_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write(SAMPLE_CATALOG_JSON)
            f.flush()
            path = f.name
        try:
            c = load_file(path)
            assert len(c.entries) == 2
        finally:
            os.unlink(path)

    def test_load_directory(self):
        with tempfile.TemporaryDirectory() as d:
            # Write two catalog files
            with open(os.path.join(d, "adv1.json"), "w") as f:
                json.dump({
                    "schema_version": "0.1.0",
                    "entries": [{"id": "ADV-1", "ecosystem": "npm",
                                 "package": "foo", "versions": ["1.0"]}],
                }, f)
            with open(os.path.join(d, "adv2.json"), "w") as f:
                json.dump({
                    "schema_version": "0.1.0",
                    "entries": [{"id": "ADV-2", "ecosystem": "npm",
                                 "package": "bar", "versions": ["2.0"]}],
                }, f)
            c = load(d)
            assert len(c.entries) == 2

    def test_load_file_or_directory_path(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write(SAMPLE_CATALOG_JSON)
            path = f.name
        try:
            c = load(path)
            assert len(c.entries) == 2
        finally:
            os.unlink(path)

    def test_load_nonexistent(self):
        import pytest
        with pytest.raises(OSError):
            load_file("/nonexistent/path.json")

    def test_load_oversized_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write(SAMPLE_CATALOG_JSON)
            path = f.name
        try:
            import pytest
            with pytest.raises(ValueError, match="exceeds max size"):
                load_file(path, max_size=1)
        finally:
            os.unlink(path)
