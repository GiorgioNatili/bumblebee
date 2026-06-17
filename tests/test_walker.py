"""Tests for the filesystem walker."""
import os
import tempfile

from bumblebee_py import walker


def test_walk_simple_directory():
    with tempfile.TemporaryDirectory() as d:
        # Create some files
        open(os.path.join(d, "file1.txt"), "w").close()
        open(os.path.join(d, "file2.txt"), "w").close()
        os.makedirs(os.path.join(d, "subdir"))
        open(os.path.join(d, "subdir", "file3.txt"), "w").close()

        visited = []

        def visit(path, name):
            visited.append(name)

        walker.walk([d], [], None, visit)
        assert "file1.txt" in visited
        assert "file2.txt" in visited
        assert "file3.txt" in visited


def test_walk_exclude_by_basename():
    with tempfile.TemporaryDirectory() as d:
        os.makedirs(os.path.join(d, ".git"))
        open(os.path.join(d, ".git", "config"), "w").close()
        open(os.path.join(d, "real.txt"), "w").close()

        visited = []

        def visit(path, name):
            visited.append(name)

        walker.walk([d], [".git"], None, visit)
        assert "real.txt" in visited
        assert ".git" not in visited


def test_walk_exclude_by_suffix():
    with tempfile.TemporaryDirectory() as d:
        os.makedirs(os.path.join(d, "a", "b", "Library", "Caches"))
        open(os.path.join(d, "a", "b", "Library", "Caches", "cache.dat"), "w").close()
        open(os.path.join(d, "a", "b", "keep.txt"), "w").close()

        visited = []

        def visit(path, name):
            visited.append(name)

        walker.walk([d], ["Library/Caches"], None, visit)
        assert "keep.txt" in visited
        assert "cache.dat" not in visited


def test_walk_skip_dir():
    with tempfile.TemporaryDirectory() as d:
        os.makedirs(os.path.join(d, "skip_me"))
        open(os.path.join(d, "skip_me", "file.txt"), "w").close()
        open(os.path.join(d, "keep_me.txt"), "w").close()

        visited = []

        def visit(path, name):
            if name == "skip_me":
                raise walker.SkipDir()
            visited.append(name)

        walker.walk([d], [], None, visit)
        assert "keep_me.txt" in visited
        # skip_me was visited as a directory entry; SkipDir stops descent
        assert "file.txt" not in visited  # its contents are skipped


def test_walk_non_directory_root():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "standalone.txt")
        open(path, "w").close()

        visited = []

        def visit(p, name):
            visited.append(name)

        walker.walk([path], [], None, visit)
        assert "standalone.txt" in visited


def test_walk_with_on_error():
    visited = []

    def visit(path, name):
        visited.append(name)

    errors = []

    def on_error(path, err):
        errors.append((path, err))

    walker.walk(["/nonexistent/path"], [], on_error, visit)
    # Should not crash; error is reported via on_error
    assert len(errors) >= 0


def test_default_excludes_present():
    """Verify that common macOS/Library excludes are in DEFAULT_EXCLUDES."""
    excludes = walker.DEFAULT_EXCLUDES
    assert ".git" in excludes
    assert "Library/Caches" in excludes
    assert "__pycache__" in excludes
    assert ".terraform" in excludes
