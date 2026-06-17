"""Tests for model module — stable IDs, serialization, constants."""
import json

from bumblebee_py import model
from bumblebee_py.model import (
    Record, Finding, ScanSummary, Diagnostic, Endpoint,
)


class TestConstants:
    def test_supported_ecosystems(self):
        ecosystems = model.supported_ecosystems()
        assert model.ECOSYSTEM_NPM in ecosystems
        assert model.ECOSYSTEM_PYPI in ecosystems
        assert len(ecosystems) == 10

    def test_is_supported_ecosystem(self):
        assert model.is_supported_ecosystem("npm") is True
        assert model.is_supported_ecosystem("bogus") is False

    def test_constants(self):
        assert model.SCHEMA_VERSION == "0.1.0"
        assert model.SCANNER_NAME == "bumblebee"
        assert model.PROFILE_BASELINE == "baseline"
        assert model.PROFILE_PROJECT == "project"
        assert model.PROFILE_DEEP == "deep"


class TestRecordStableID:
    def test_stable_id_deterministic(self):
        r1 = Record(normalized_name="test", version="1.0", ecosystem="npm")
        r2 = Record(normalized_name="test", version="1.0", ecosystem="npm")
        assert r1.stable_id() == r2.stable_id()

    def test_stable_id_different_for_different_fields(self):
        r1 = Record(normalized_name="test", version="1.0", ecosystem="npm")
        r2 = Record(normalized_name="test", version="2.0", ecosystem="npm")
        assert r1.stable_id() != r2.stable_id()

    def test_stable_id_format(self):
        r = Record(normalized_name="test", version="1.0", ecosystem="npm")
        sid = r.stable_id()
        assert sid.startswith("package:")
        assert len(sid.split(":")[1]) == 64  # SHA-256 hex

    def test_dedup_key_matches_stable_id(self):
        r = Record(normalized_name="test", version="1.0", ecosystem="npm")
        assert r.dedup_key() == r.stable_id()


class TestFindingStableID:
    def test_finding_stable_id_deterministic(self):
        f1 = Finding(finding_type="package_exposure", catalog_id="CVE-2023-0001",
                     ecosystem="npm", normalized_name="test", version="1.0")
        f2 = Finding(finding_type="package_exposure", catalog_id="CVE-2023-0001",
                     ecosystem="npm", normalized_name="test", version="1.0")
        assert f1.stable_id() == f2.stable_id()

    def test_finding_stable_id_format(self):
        f = Finding(finding_type="package_exposure", catalog_id="CVE-2023-0001",
                    ecosystem="npm", normalized_name="test", version="1.0")
        sid = f.stable_id()
        assert sid.startswith("finding:")
        assert len(sid.split(":")[1]) == 64


class TestScanSummaryStableID:
    def test_summary_stable_id(self):
        s = ScanSummary(profile="baseline", status="complete",
                        scan_time="2024-01-01T00:00:00Z",
                        end_time="2024-01-01T00:00:01Z")
        sid = s.stable_id()
        assert sid.startswith("scan_summary:")

    def test_summary_with_roots(self):
        from bumblebee_py.model import SummaryRoot
        s = ScanSummary(profile="baseline", status="complete",
                        scan_time="2024-01-01T00:00:00Z",
                        end_time="2024-01-01T00:00:01Z",
                        roots=[SummaryRoot(path="/usr/local", kind="homebrew_root")])
        assert s.stable_id()


class TestDiagnosticStableID:
    def test_diagnostic_stable_id(self):
        d = Diagnostic(level="warn", path="/tmp/test", message="test message")
        sid = d.stable_id()
        assert sid.startswith("diagnostic:")

    def test_diagnostic_deterministic(self):
        d1 = Diagnostic(level="info", path="", message="hello")
        d2 = Diagnostic(level="info", path="", message="hello")
        assert d1.stable_id() == d2.stable_id()


class TestRecordSerialization:
    def test_to_dict_minimal(self):
        r = Record(
            ecosystem="npm",
            package_name="test-pkg",
            normalized_name="test-pkg",
            version="1.0.0",
            source_type="npm-lockfile",
            source_file="/path/lock.json",
            confidence="high",
            endpoint=Endpoint(hostname="test-host", os="darwin", arch="arm64"),
        )
        d = r.to_dict()
        assert d["record_type"] == "package"
        assert d["ecosystem"] == "npm"
        assert d["package_name"] == "test-pkg"
        assert d["normalized_name"] == "test-pkg"
        assert d["version"] == "1.0.0"
        assert d["record_id"] == r.stable_id()
        # Optional fields should be omitted
        assert "project_path" not in d
        assert "root_kind" not in d

    def test_to_dict_with_all_fields(self):
        r = Record(
            ecosystem="npm",
            package_name="test-pkg",
            normalized_name="test-pkg",
            version="1.0.0",
            project_path="/my/project",
            root_kind="project_root",
            package_manager="npm",
            direct_dependency=True,
            has_lifecycle_scripts=True,
            lifecycle_scripts=["postinstall"],
            source_type="npm-lockfile",
            source_file="/path/lock.json",
            confidence="high",
            requested_spec="test-pkg@1.0.0",
            server_name="test-server",
            install_scope="prod",
            endpoint=Endpoint(hostname="h", os="linux", arch="x86_64",
                              username="user", uid="1000"),
        )
        d = r.to_dict()
        assert d["project_path"] == "/my/project"
        assert d["direct_dependency"] is True
        assert d["lifecycle_scripts"] == ["postinstall"]

    def test_to_dict_json_roundtrip(self):
        r = Record(
            ecosystem="npm",
            package_name="test-pkg",
            normalized_name="test-pkg",
            version="1.0.0",
            source_type="npm-lockfile",
            source_file="/path/lock.json",
            confidence="high",
        )
        d = r.to_dict()
        json_str = json.dumps(d, separators=(",", ":"))
        parsed = json.loads(json_str)
        assert parsed["ecosystem"] == "npm"
        assert parsed["version"] == "1.0.0"


class TestNormalize:
    def test_npm_basic(self):
        from bumblebee_py import normalize
        assert normalize.npm("Left-Pad") == "left-pad"
        assert normalize.npm("  LEFT-PAD  ") == "left-pad"

    def test_npm_scoped(self):
        from bumblebee_py import normalize
        assert normalize.npm("@TanStack/Query-Core") == "@tanstack/query-core"

    def test_pypi_basic(self):
        from bumblebee_py import normalize
        assert normalize.pypi("Requests") == "requests"
        assert normalize.pypi("  REQUEST_S  ") == "request-s"

    def test_pypi_pep503(self):
        from bumblebee_py import normalize
        assert normalize.pypi("My.Super_Package") == "my-super-package"
        assert normalize.pypi("---hello---") == "hello"


class TestEndpoint:
    def test_current_returns_endpoint(self):
        from bumblebee_py import endpoint
        ep = endpoint.current()
        assert ep.os in ("darwin", "linux")
        assert ep.arch != ""
        assert ep.hostname != ""

    def test_device_id(self):
        from bumblebee_py import endpoint
        ep = endpoint.current("my-device-id")
        assert ep.device_id == "my-device-id"
