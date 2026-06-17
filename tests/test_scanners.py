"""Integration test for npm and pypi scanners."""
import json
import os
import tempfile

from bumblebee_py.model import Record, Endpoint
from bumblebee_py.ecosystems import npm, pypi


BASE_RECORD = Record(
    schema_version="0.1.0",
    scanner_name="bumblebee",
    scanner_version="0.2.1",
    run_id="test-run",
    scan_time="2024-01-01T00:00:00Z",
    endpoint=Endpoint(hostname="test-host", os="linux", arch="x86_64"),
    profile="baseline",
)


def test_npm_scan_lockfile_v2():
    """Test parsing an npm lockfile v2/v3 (with packages key)."""
    lockfile = {
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "my-project"},
            "node_modules/left-pad": {"version": "1.3.0", "dev": False},
            "node_modules/is-odd": {"version": "3.0.1", "dev": True,
                                    "scripts": {"postinstall": "node post.js"}},
        },
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(lockfile, f)
        path = f.name

    emitted = []

    def emit(r):
        emitted.append(r)

    scanner = npm.Scanner(max_file_size=10*1024*1024, emit=emit, diag=None)
    try:
        scanner.scan_lockfile(path, BASE_RECORD)
    finally:
        os.unlink(path)

    assert len(emitted) == 2
    names = {r.package_name for r in emitted}
    assert "left-pad" in names
    assert "is-odd" in names
    # Check confidence
    for r in emitted:
        assert r.confidence == "high"
        assert r.source_type == "npm-lockfile"
        assert r.package_manager == "npm"
    # Check lifecycle scripts
    odd = [r for r in emitted if r.package_name == "is-odd"][0]
    assert odd.has_lifecycle_scripts is True
    assert odd.lifecycle_scripts == ["postinstall"]
    # Check dev scope
    odd_scope = [r for r in emitted if r.package_name == "is-odd"][0]
    assert odd_scope.install_scope == "dev"


def test_npm_scan_lockfile_v1():
    """Test parsing an npm lockfile v1 (with dependencies key)."""
    lockfile = {
        "lockfileVersion": 1,
        "dependencies": {
            "left-pad": {"version": "1.3.0", "dev": False},
            "is-odd": {"version": "3.0.1", "dev": True},
        },
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(lockfile, f)
        path = f.name

    emitted = []

    def emit(r):
        emitted.append(r)

    scanner = npm.Scanner(max_file_size=10*1024*1024, emit=emit)
    try:
        scanner.scan_lockfile(path, BASE_RECORD)
    finally:
        os.unlink(path)

    assert len(emitted) == 2
    names = {r.package_name for r in emitted}
    assert "left-pad" in names
    assert "is-odd" in names


def test_npm_scan_node_modules_package_json():
    """Test scanning an installed node_modules package.json."""
    pkg = {
        "name": "my-package",
        "version": "2.0.0",
        "scripts": {"postinstall": "make build", "test": "echo test"},
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(pkg, f)
        path = f.name

    emitted = []

    def emit(r):
        emitted.append(r)

    scanner = npm.Scanner(max_file_size=10*1024*1024, emit=emit)
    try:
        scanner.scan_node_modules_package_json(path, "/project", BASE_RECORD)
    finally:
        os.unlink(path)

    assert len(emitted) == 1
    r = emitted[0]
    assert r.package_name == "my-package"
    assert r.version == "2.0.0"
    assert r.project_path == "/project"
    assert r.confidence == "medium"
    assert r.has_lifecycle_scripts is True
    assert r.lifecycle_scripts == ["postinstall"]


def test_npm_is_lockfile():
    assert npm.is_lockfile("package-lock.json") is True
    assert npm.is_lockfile("npm-shrinkwrap.json") is True
    assert npm.is_lockfile(".package-lock.json") is True
    assert npm.is_lockfile("yarn.lock") is False


def test_npm_is_node_modules_package_json():
    ok, proj = npm.is_node_modules_package_json("/project/node_modules/foo/package.json")
    assert ok is True
    assert proj == "/project"

    ok, proj = npm.is_node_modules_package_json(
        "/project/node_modules/@scope/pkg/package.json"
    )
    assert ok is True
    assert proj == "/project"

    ok, _ = npm.is_node_modules_package_json("/plain/package.json")
    assert ok is False


def test_pypi_scan_dist_info():
    """Test parsing a PEP 566 METADATA file."""
    metadata = (
        "Metadata-Version: 2.1\n"
        "Name: Requests\n"
        "Version: 2.28.0\n"
        "Summary: HTTP library\n"
        "\n"
        "Description body here\n"
    )
    with tempfile.TemporaryDirectory() as d:
        dist_dir = os.path.join(d, "requests-2.28.0.dist-info")
        os.makedirs(dist_dir)
        meta_path = os.path.join(dist_dir, "METADATA")
        with open(meta_path, "w") as f:
            f.write(metadata)
        # Add INSTALLER
        with open(os.path.join(dist_dir, "INSTALLER"), "w") as f:
            f.write("pip\n")

        emitted = []

        def emit(r):
            emitted.append(r)

        scanner = pypi.Scanner(max_file_size=10*1024*1024, emit=emit)
        scanner.scan_dist_info(meta_path, dist_dir, BASE_RECORD)

    assert len(emitted) == 1
    r = emitted[0]
    assert r.package_name == "Requests"
    assert r.normalized_name == "requests"
    assert r.version == "2.28.0"
    assert r.confidence == "high"
    assert r.source_type == "pypi-dist-info"
    assert r.package_manager == "pip"


def test_pypi_is_dist_info_metadata():
    ok, dir = pypi.is_dist_info_metadata("/path/foo-1.0.dist-info/METADATA")
    assert ok is True
    assert dir == "/path/foo-1.0.dist-info"

    ok, _ = pypi.is_dist_info_metadata("/path/foo-1.0.dist-info/PKG-INFO")
    assert ok is False


def test_pypi_is_egg_info_pkg_info():
    ok, dir = pypi.is_egg_info_pkg_info("/path/foo-1.0.egg-info/PKG-INFO")
    assert ok is True
    assert dir == "/path/foo-1.0.egg-info"


def test_pypi_scan_egg_info():
    """Test parsing a legacy PKG-INFO file."""
    pkg_info = (
        "Metadata-Version: 1.1\n"
        "Name: MyPackage\n"
        "Version: 0.1.0\n"
        "\n"
        "Description\n"
    )
    with tempfile.TemporaryDirectory() as d:
        egg_dir = os.path.join(d, "mypackage-0.1.0.egg-info")
        os.makedirs(egg_dir)
        pi_path = os.path.join(egg_dir, "PKG-INFO")
        with open(pi_path, "w") as f:
            f.write(pkg_info)

        emitted = []

        def emit(r):
            emitted.append(r)

        scanner = pypi.Scanner(max_file_size=10*1024*1024, emit=emit)
        scanner.scan_egg_info(pi_path, egg_dir, BASE_RECORD)

    assert len(emitted) == 1
    r = emitted[0]
    assert r.package_name == "MyPackage"
    assert r.normalized_name == "mypackage"
    assert r.version == "0.1.0"
    assert r.confidence == "medium"
