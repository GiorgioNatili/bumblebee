"""Tests for the CLI --view flag, _generate_report, and _ensure_report_dir."""

import io
import json
import os
import tempfile
from unittest.mock import patch, MagicMock

from bumblebee_py import cli


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


def _mock_file(content: str):
    """Return a mock file-like object whose .read() returns content."""
    m = MagicMock()
    m.read.return_value = content
    m.__enter__.return_value = m
    return m


class TestEnsureReportDir:
    """Tests for _ensure_report_dir."""

    def test_creates_default_dir(self):
        """~/.bumblebee/reports/ is created when it does not exist."""
        with tempfile.TemporaryDirectory() as tmp:
            fake_home = os.path.join(tmp, "home")
            os.makedirs(fake_home)
            with patch("os.path.expanduser", return_value=fake_home):
                result = cli._ensure_report_dir()
            expected = os.path.join(fake_home, ".bumblebee", "reports")
            assert result == expected
            assert os.path.isdir(expected)

    def test_fallback_on_makedirs_error(self):
        """When makedirs fails, falls back to a temp dir."""
        with patch("os.makedirs", side_effect=OSError(13, "Permission denied")):
            result = cli._ensure_report_dir()
        # Falls back to a temp directory that exists
        assert os.path.isdir(result)
        # Clean up
        if result and os.path.isdir(result) and "tmp" in result:
            os.rmdir(result)


class TestGenerateReport:
    """Tests for _generate_report."""

    def _make_jsonl(self, content=None):
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False)
        f.write(content or SAMPLE_JSONL)
        f.close()
        return f.name

    # ── template missing ───────────────────────────────────────

    def test_template_missing(self):
        """When scan-viewer.html does not exist, return None."""
        jsonl = self._make_jsonl()
        stderr = io.StringIO()
        with patch("os.path.isfile", return_value=False), \
             patch("sys.stderr", stderr):
            result = cli._generate_report(jsonl)
        assert result is None
        assert "dashboard template" in stderr.getvalue()
        assert "not found" in stderr.getvalue()
        os.unlink(jsonl)

    # ── data file unreadable ───────────────────────────────────

    def test_data_unreadable(self):
        """When the JSONL data file cannot be read, return None."""
        stderr = io.StringIO()
        with patch("os.path.isfile", return_value=True), \
             patch("builtins.open", MagicMock(side_effect=[
                 OSError(2, "No such file"),   # data read
             ])), \
             patch("sys.stderr", stderr):
            result = cli._generate_report("/nonexistent/data.jsonl")
        assert result is None
        assert "read scan data" in stderr.getvalue()

    # ── template unreadable ────────────────────────────────────

    def test_template_unreadable(self):
        """When the template HTML cannot be read, return None."""
        stderr = io.StringIO()
        with patch("os.path.isfile", return_value=True), \
             patch("builtins.open", MagicMock(side_effect=[
                 _mock_file(SAMPLE_JSONL),        # data read succeeds
                 OSError(13, "Permission denied"), # template read fails
             ])), \
             patch("sys.stderr", stderr):
            result = cli._generate_report("/some/data.jsonl")
        assert result is None
        assert "read viewer template" in stderr.getvalue()
        assert "Permission denied" in stderr.getvalue()

    # ── write failure ──────────────────────────────────────────

    def test_write_failure(self):
        """When the output file cannot be written, return None."""
        stderr = io.StringIO()
        with patch("os.path.isfile", return_value=True), \
             patch("builtins.open", MagicMock(side_effect=[
                 _mock_file(SAMPLE_JSONL),           # data read
                 _mock_file(SAMPLE_TEMPLATE),        # template read
                 OSError(28, "No space left"),        # write fails
             ])), \
             patch("bumblebee_py.cli._ensure_report_dir",
                   return_value="/tmp/bumblebee_reports_test"), \
             patch("sys.stderr", stderr):
            result = cli._generate_report("/some/data.jsonl")
        assert result is None
        assert "write report" in stderr.getvalue()

    # ── success path ───────────────────────────────────────────

    def test_success(self):
        """Happy path: reads data, embeds into HTML, writes to reports dir."""
        jsonl = self._make_jsonl()
        stderr = io.StringIO()

        with tempfile.TemporaryDirectory() as tmp:
            report_dir = os.path.join(tmp, "reports")
            os.makedirs(report_dir)

            with patch("os.path.isfile", return_value=True), \
                 patch("bumblebee_py.cli._ensure_report_dir",
                       return_value=report_dir), \
                 patch("sys.stderr", stderr):
                result = cli._generate_report(jsonl)

            # 1. A path was returned
            assert result is not None, \
                f"expected report path, got None (stderr: {stderr.getvalue()})"
            assert result.startswith(report_dir)
            assert result.endswith(".html")
            assert "bumblebee_" in os.path.basename(result)

            # 2. The file was written and contains the embedded data
            with open(result) as f:
                output_html = f.read()
            assert "__BUMBLEBEE_DATA__" in output_html

            # 3. Simulate what the browser does with the embedded JS string:
            #    Extract the JS string literal, unescape JS escapes,
            #    split by newlines, and parse each line as JSON.
            import re as _re
            m = _re.search(
                r'__BUMBLEBEE_DATA__ = (.+?);</script>',
                output_html, _re.DOTALL
            )
            assert m is not None, "could not find __BUMBLEBEE_DATA__ assignment"
            js_literal = m.group(1)

            # The JS string literal is double-quoted: "content"
            assert js_literal.startswith('"') and js_literal.endswith('"')

            # Verify NO actual newlines inside the JS string literal
            # (actual newlines would be a JS SyntaxError)
            assert '\n' not in js_literal, \
                "actual newline found inside JS string literal - SyntaxError in browser!"

            # Verify that \\n (escaped newline sequences) exist
            assert '\\n' in js_literal, \
                "no escaped newlines (\\n) found - JS won't create line breaks"

            # Simulate JS string unescaping:
            js_content = js_literal[1:-1]          # strip outer quotes
            js_unescaped = (js_content
                .replace('\\"', '"')                # \" → "
                .replace('\\\\', '\\')              # \\ → \
                .replace('\\n', '\n'))              # \n → newline

            # Split by actual newlines and parse each JSON line
            lines = [l for l in js_unescaped.split("\n") if l.strip()]
            records = []
            for line in lines:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError as e:
                    assert False, \
                        f"JSON parse error on {line[:80]!r}: {e}"

            packages = [r for r in records
                        if r.get("record_type") == "package"]
            assert len(packages) == 2, \
                f"expected 2 package records, got {len(packages)}"
            assert packages[0]["ecosystem"] == "npm"
            assert packages[0]["package_name"] == "a"

            # 4. Two <script> tags: injected data + original app
            assert output_html.count("<script>") == 2

        # Clean up
        os.unlink(jsonl)


class TestScanViewFlag:
    """Tests for scan --view via main()."""

    def test_view_opens_browser(self):
        """--view generates the report and opens the browser."""
        browser_opened = []
        stderr = io.StringIO()

        with patch("os.path.isfile", return_value=True), \
             patch("bumblebee_py.cli._generate_report",
                   return_value="/tmp/bumblebee_test_report.html"), \
             patch("bumblebee_py.cli.webbrowser.open",
                   lambda u: browser_opened.append(u)), \
             patch("sys.stderr", stderr):
            rc = cli.main(["scan", "--profile", "deep",
                           "--root", "/tmp", "--view"])

        assert rc == 0, f"exit code {rc}, stderr: {stderr.getvalue()}"
        assert len(browser_opened) == 1, "browser was not opened"
        assert browser_opened[0].startswith("file://")

    def test_without_view_no_browser(self):
        """Without --view, the report is generated but browser is not opened."""
        browser_opened = []
        stderr = io.StringIO()

        with patch("os.path.isfile", return_value=True), \
             patch("bumblebee_py.cli._generate_report",
                   return_value="/tmp/bumblebee_test_report.html"), \
             patch("bumblebee_py.cli.webbrowser.open",
                   lambda u: browser_opened.append(u)), \
             patch("sys.stderr", stderr):
            rc = cli.main(["scan", "--profile", "deep",
                           "--root", "/tmp"])

        assert rc == 0, f"exit code {rc}"
        # Report is generated and path is printed
        assert "Report saved" in stderr.getvalue(), stderr.getvalue()
        # Browser is NOT opened
        assert len(browser_opened) == 0, "browser should not open without --view"
