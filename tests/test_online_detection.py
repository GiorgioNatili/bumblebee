"""Online-data detection efficacy test.

Uses a recorded real-world OSV fixture downloaded from the OSSF
malicious-packages repository. An optional live test can refresh
from online data when BUMBLEBEE_RUN_ONLINE_TESTS=1 is set.
"""

import json
import os
import sys

import pytest

from bumblebee_py import model
from bumblebee_py.intel import osv as _osv
from bumblebee_py.exposure import _build, Entry, load as load_catalog


FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "fixtures")
REAL_FIXTURE = os.path.join(FIXTURE_DIR, "real-osv-MAL-2025-49456.json")


class TestRealWorldOSVFixture:
    """Verify a recorded real-world OSV entry can be converted and matched."""

    def test_fixture_loads(self):
        """The recorded fixture is valid OSV JSON."""
        with open(REAL_FIXTURE) as f:
            data = json.load(f)
        assert data["id"] == "MAL-2025-49456"
        assert len(data["affected"]) > 0
        assert "versions" in data["affected"][0]
        assert len(data["affected"][0]["versions"]) > 0

    def test_convert_real_osv_entry(self):
        """The real OSV entry converts to a Bumblebee catalog entry."""
        with open(REAL_FIXTURE) as f:
            data = json.load(f)
        entry = _osv.convert_osv_entry(data)
        assert entry is not None, "real OSV entry should convert successfully"
        assert entry["ecosystem"] == "npm"
        assert entry["package"] == "0e"
        assert len(entry["versions"]) > 0
        assert "severity" in entry

    def test_match_real_exposure(self):
        """A package matching the real entry produces a finding."""
        with open(REAL_FIXTURE) as f:
            data = json.load(f)
        entry = _osv.convert_osv_entry(data)
        assert entry is not None

        # Build a catalog with this entry
        catalog = _build("0.1.0", [
            Entry(
                entry_id=entry["id"],
                ecosystem=entry["ecosystem"],
                package=entry["package"],
                versions=entry["versions"],
                name=entry["name"],
                severity=entry["severity"],
            )
        ])

        # Create a package record matching one of the versions
        versions = entry["versions"]
        pkg = model.Record(
            ecosystem=entry["ecosystem"],
            package_name=entry["package"],
            normalized_name=entry["package"].lower(),
            version=versions[0],
            source_type="npm-lockfile",
            source_file="/tmp/package-lock.json",
            confidence="high",
            endpoint=model.Endpoint(hostname="test-host"),
        )

        matches = catalog.match_all(pkg)
        assert len(matches) == 1, f"expected 1 match, got {len(matches)}"
        m = matches[0]
        assert m.entry.id == entry["id"]
        assert m.entry.severity
        assert m.version == versions[0]


class TestOnlineDetection:
    """Optional live online tests gated by environment variable."""

    @pytest.mark.skipif(
        os.environ.get("BUMBLEBEE_RUN_ONLINE_TESTS") != "1",
        reason="set BUMBLEBEE_RUN_ONLINE_TESTS=1 to run live online tests",
    )
    def test_fetch_real_osv_online(self):
        """Fetch a real OSV entry from the OSSF repo and verify conversion.

        This test fetches from the live GitHub raw content endpoint.
        It may fail if the upstream repo changes or the network is down.
        """
        url = (
            "https://raw.githubusercontent.com/ossf/"
            "malicious-packages/main/osv/malicious/npm/0e/"
            "MAL-2025-49456.json"
        )
        entries = _osv.fetch_osv_data(url, timeout=30)
        assert len(entries) >= 1, "should fetch at least one OSV entry"
        entry = entries[0] if isinstance(entries[0], dict) else entries
        if isinstance(entry, dict):
            assert "id" in entry
            assert "affected" in entry

    @pytest.mark.skipif(
        os.environ.get("BUMBLEBEE_RUN_ONLINE_TESTS") != "1",
        reason="set BUMBLEBEE_RUN_ONLINE_TESTS=1 to run live online tests",
    )
    def test_refresh_cli_dry_run_online(self):
        """intel refresh --dry-run with real online data."""
        from bumblebee_py.intel.refresh import main
        # Use the per-ecosystem default source
        rc = main(["--dry-run"])
        assert rc == 0
