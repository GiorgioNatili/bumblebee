"""Tests for the CLI --view flag and _open_viewer function."""

import io
import json
import os
import sys
import tempfile
from unittest.mock import patch, MagicMock

from bumblebee_py import cli


class TestOpenViewer:
    """Unit tests for _open_viewer — patches all I/O dependencies."""

    SAMPLE_JSONL = (
        '{"record_type":"package","ecosystem":"npm","package_name":"a","version":"1.0"}\n'
        '{"record_type":"package","ecosystem":"npm","package_name":"b","version":"2.0"}\n'
        '{"record_type":"scan_summary","status":"complete","records_emitted":2}\n'
    )

    SAMPLE_TEMPLATE = (
        '<!DOCTYPE html><html><head>'
        '<meta charset="UTF-8">'
        '<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js"></script>'
        '</head><body>'
        '<script>\n// app code\n</script>'
        '</body></html>'
    )

    # ── template missing ───────────────────────────────────────

    def test_template_missing(self):
        """When scan-viewer.html does not exist, print error to stderr, no browser."""
        browser_opened = []
        stderr = io.StringIO()
        with patch("os.path.isfile", return_value=False), \
             patch("webbrowser.open", lambda u: browser_opened.append(u)), \
             patch("sys.stderr", stderr):
            cli._open_viewer("/some/data.jsonl")
        assert "dashboard template" in stderr.getvalue()
        assert "not found" in stderr.getvalue()
        assert len(browser_opened) == 0

    # ── data file unreadable ───────────────────────────────────

    def test_data_unreadable(self):
        """When the JSONL data file cannot be read, print error, no browser."""
        browser_opened = []
        stderr = io.StringIO()
        with patch("os.path.isfile", return_value=True), \
             patch("builtins.open", MagicMock(side_effect=OSError(2, "No such file"))), \
             patch("webbrowser.open", lambda u: browser_opened.append(u)), \
             patch("sys.stderr", stderr):
            cli._open_viewer("/nonexistent/data.jsonl")
        assert "read scan data" in stderr.getvalue()
        assert "No such file" in stderr.getvalue()
        assert len(browser_opened) == 0

    # ── template unreadable ────────────────────────────────────

    def test_template_unreadable(self):
        """When the template HTML cannot be read, print error, no browser."""
        browser_opened = []
        stderr = io.StringIO()
        # First open call (data) succeeds, second (template) fails
        real_data = io.StringIO(self.SAMPLE_JSONL)
        with patch("os.path.isfile", return_value=True), \
             patch("builtins.open", MagicMock(side_effect=[
                 real_data,
                 OSError(13, "Permission denied"),
             ])), \
             patch("webbrowser.open", lambda u: browser_opened.append(u)), \
             patch("sys.stderr", stderr):
            cli._open_viewer("/some/data.jsonl")
        out = stderr.getvalue()
        assert "read viewer template" in out
        assert "Permission denied" in out
        assert len(browser_opened) == 0

    # ── write failure ──────────────────────────────────────────

    def test_write_failure(self):
        """When tempfile.mkstemp fails, print error, no browser."""
        browser_opened = []
        stderr = io.StringIO()
        data_content = io.StringIO(self.SAMPLE_JSONL)
        template_content = io.StringIO(self.SAMPLE_TEMPLATE)
        with patch("os.path.isfile", return_value=True), \
             patch("builtins.open", MagicMock(side_effect=[
                 data_content, template_content,
             ])), \
             patch("tempfile.mkstemp", MagicMock(side_effect=OSError(28, "No space left"))), \
             patch("webbrowser.open", lambda u: browser_opened.append(u)), \
             patch("sys.stderr", stderr):
            cli._open_viewer("/some/data.jsonl")
        out = stderr.getvalue()
        assert "write viewer" in out
        assert "No space left" in out
        assert len(browser_opened) == 0

    # ── write open failure (os.fdopen) ─────────────────────────

    def test_fdopen_failure(self):
        """When os.fdopen fails, print error, no browser."""
        browser_opened = []
        stderr = io.StringIO()
        data_content = io.StringIO(self.SAMPLE_JSONL)
        template_content = io.StringIO(self.SAMPLE_TEMPLATE)
        with patch("os.path.isfile", return_value=True), \
             patch("builtins.open", MagicMock(side_effect=[
                 data_content, template_content,
             ])), \
             patch("tempfile.mkstemp", return_value=(42, "/tmp/bumblebee_test.html")), \
             patch("os.fdopen", MagicMock(side_effect=OSError(5, "Input/output error"))), \
             patch("webbrowser.open", lambda u: browser_opened.append(u)), \
             patch("sys.stderr", stderr):
            cli._open_viewer("/some/data.jsonl")
        out = stderr.getvalue()
        assert "write viewer" in out or "Input/output error" in out
        assert len(browser_opened) == 0

    # ── success path ───────────────────────────────────────────

    def test_success(self):
        """Happy path: reads data, embeds into HTML, writes output, opens browser."""
        import io as io_module
        browser_opened = []
        stderr = io.StringIO()
        fake_fd = 42
        fake_out_path = "/tmp/bumblebee_test_viewer.html"
        written = []  # capture written content

        class CapturedStringIO(io_module.StringIO):
            """StringIO that saves its content before close()."""
            def close(self):
                written.append(self.getvalue())
                super().close()

        def fake_fdopen(fd, mode="w"):
            return CapturedStringIO()

        with patch("os.path.isfile", return_value=True), \
             patch("builtins.open", MagicMock(side_effect=[
                     io_module.StringIO(self.SAMPLE_JSONL),   # data read
                     io_module.StringIO(self.SAMPLE_TEMPLATE), # template read
             ])), \
             patch("tempfile.mkstemp", return_value=(fake_fd, fake_out_path)), \
             patch("os.fdopen", fake_fdopen), \
             patch("webbrowser.open", lambda u: browser_opened.append(u)), \
             patch("sys.stderr", stderr):
            cli._open_viewer("/some/data.jsonl")

        # 1. Browser was opened with file:// URL
        assert len(browser_opened) == 1, f"expected 1 browser call, got {browser_opened}"
        assert browser_opened[0].startswith("file://"), \
            f"expected file:// URL, got {browser_opened[0]}"
        assert fake_out_path in browser_opened[0]

        # 2. The output HTML contains the embedded JSONL data
        assert len(written) == 1, "output was not written"
        output_html = written[0]
        assert "__BUMBLEBEE_DATA__" in output_html, "missing data in output HTML"

        # 3. The data is properly JSON-encoded inside the script tag
        data_start = output_html.index("__BUMBLEBEE_DATA__ = ") + len("__BUMBLEBEE_DATA__ = ")
        data_end = output_html.index(";", data_start)
        embedded_json = output_html[data_start:data_end]
        parsed = json.loads(embedded_json)
        assert "npm" in parsed

        # 4. Dashboard opened message printed to stderr
        assert "Dashboard opened" in stderr.getvalue()

    # ── data_file is a NamedTemporaryFile object ───────────────

    def test_data_is_tempfile_object(self):
        """When data_file is a NamedTemporaryFile, use .name attribute."""
        import io as io_module
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False)
        f.write(self.SAMPLE_JSONL)
        f.close()

        browser_opened = []
        stderr = io.StringIO()
        written_buf = io_module.StringIO()

        try:
            with patch("os.path.isfile", return_value=True), \
                 patch("builtins.open", MagicMock(side_effect=[
                     io_module.StringIO(self.SAMPLE_JSONL),  # data read (replaces open(f.name))
                     io_module.StringIO(self.SAMPLE_TEMPLATE), # template read
                 ])), \
                 patch("tempfile.mkstemp", return_value=(42, "/tmp/b.html")), \
                 patch("os.fdopen", return_value=written_buf), \
                 patch("webbrowser.open", lambda u: browser_opened.append(u)), \
                 patch("sys.stderr", stderr):
                # Pass the tempfile object, not its .name string
                cli._open_viewer(f)
        finally:
            os.unlink(f.name)

        assert len(browser_opened) == 1, "browser was not opened"
        assert "Dashboard opened" in stderr.getvalue()


class TestScanViewFlag:
    """End-to-end tests for scan --view via main()."""

    def test_view_flag(self):
        """--view with a valid scan opens the browser dashboard."""
        browser_opened = []
        stderr = io.StringIO()

        with patch("os.path.isfile", return_value=True), \
             patch("tempfile.mkstemp", return_value=(42, "/tmp/bumblebee_e2e.html")), \
             patch("os.fdopen", return_value=io.StringIO()), \
             patch("webbrowser.open", lambda u: browser_opened.append(u)), \
             patch("sys.stderr", stderr):
            rc = cli.main(["scan", "--profile", "deep",
                           "--root", "/tmp", "--view"])

        assert rc == 0, f"exit code {rc}, stderr: {stderr.getvalue()}"
        assert len(browser_opened) >= 1, "browser was not opened"
        url = browser_opened[0]
        assert url.startswith("file://"), f"expected file:// URL, got {url}"
        assert "bumblebee" in url

    def test_view_rejected_with_http(self):
        """--view with --output=http should error before scanning."""
        stderr = io.StringIO()
        with patch("sys.stderr", stderr):
            rc = cli.main(["scan", "--profile", "deep",
                           "--root", "/tmp",
                           "--view", "--output=http", "--http-url",
                           "http://localhost:8080"])
        assert rc == 2, f"expected exit 2, got {rc}"
        assert "not compatible" in stderr.getvalue(), stderr.getvalue()
