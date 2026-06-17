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
            assert "bumblebee_data" in output_html

            # 3. Simulate what the browser does with the embedded JS string:
            #    Extract the JS string literal, unescape JS escapes,
            #    split by newlines, and parse each line as JSON.
            import re as _re
            m = _re.search(
                r'bumblebee_data = (.+?);</script>',
                output_html, _re.DOTALL
            )
            assert m is not None, "could not find bumblebee_data assignment"
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


class TestEmbeddedReportRendering:
    """Tests that the generated report renders correctly in a browser.

    Validates the JavaScript structure has no temporal-dead-zone issues
    and the embedded data survives the round-trip.
    """

    def _read_template(self):
        with open(os.path.join(
                os.path.dirname(cli.__file__), "scan-viewer.html")) as f:
            return f.read()

    def test_eco_constants_before_autoload(self):
        """ECO_COLORS and ECO_LABELS must be defined before the auto-load IIFE.
        """
        src = self._read_template()
        pos_colors = src.index("const ECO_COLORS")
        pos_labels = src.index("const ECO_LABELS")
        pos_autoload = src.index("if (window.bumblebee_data)")
        assert pos_colors < pos_autoload, \
            "ECO_COLORS after auto-load — temporal dead zone crash!"
        assert pos_labels < pos_autoload, \
            "ECO_LABELS after auto-load — temporal dead zone crash!"

    def test_template_first_script_is_chartjs(self):
        """First <script> in the template is Chart.js CDN (gets replaced by injection).

        The injection replaces the first <script> tag with the data script.
        Chart.js must be the original first script for the injection to work
        correctly.
        """
        src = self._read_template()
        first_script = src.find("<script")
        assert first_script >= 0
        chart_js_snippet = src[first_script:first_script + 80]
        assert "chart.js" in chart_js_snippet, \
            f"first <script> should be Chart.js CDN, got: {chart_js_snippet[:60]}"

    def test_template_second_script_contains_app_code(self):
        """Second <script> contains the full app code with loadScanData."""
        src = self._read_template()
        first_script = src.find("<script")
        second_script = src.find("<script", first_script + 7)
        assert second_script >= 0
        second_end = src.find("</script>", second_script)
        second_content = src[second_script:second_end]
        assert "loadScanData" in second_content, \
            "second <script> should contain loadScanData (app pipeline)"

    def test_generated_report_round_trip(self):
        """Generate a report and validate the HTML would render in a browser."""
        import tempfile as _tf
        import json as _json

        sample = (
            '{"record_type":"package","ecosystem":"npm",'
            '"package_name":"a","version":"1.0"}\n'
            '{"record_type":"package","ecosystem":"npm",'
            '"package_name":"b","version":"2.0"}\n'
            '{"record_type":"scan_summary","status":"complete"}\n'
        )
        jsonl = _tf.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False)
        jsonl.write(sample)
        jsonl.close()

        try:
            with _tf.TemporaryDirectory() as tmp:
                report_dir = os.path.join(tmp, "reports")
                os.makedirs(report_dir)
                with patch("os.path.isfile", return_value=True), \
                     patch("bumblebee_py.cli._ensure_report_dir",
                           return_value=report_dir):
                    result = cli._generate_report(jsonl.name)

                assert result is not None
                with open(result) as f:
                    html = f.read()

                # bumblebee_data appears 7 times:
                #   1. injected data script (definition)
                #   2. if-check: "if (window.bumblebee_data)"
                #   3. debugLog length: "${window.bumblebee_data.length}"
                #   4. typeof check: "typeof window.bumblebee_data"
                #   5. rawDataText assign: "window.bumblebee_data"
                #   6. stringify: "JSON.stringify(window.bumblebee_data)"
                #   7. parse call: "loadScanData(window.bumblebee_data)"
                data_refs = html.count("bumblebee_data")
                assert data_refs == 7, \
                    f"expected 7 bumblebee_data refs, got {data_refs}"

                # Extract the data string
                import re as _re
                m = _re.search(
                    r'bumblebee_data = (.+?);</script>',
                    html, _re.DOTALL
                )
                assert m, "no bumblebee_data assignment"
                js_literal = m.group(1)

                # Must be a valid JS double-quoted string
                assert js_literal.startswith('"') and js_literal.endswith('"')

                # No actual newlines (would be JS SyntaxError)
                assert '\n' not in js_literal, \
                    "actual newline inside JS string — SyntaxError in browser!"

                # Escaped newlines present
                assert '\\n' in js_literal, \
                    "no \\n escape sequences — split will find no line breaks"

                # Simulate JS unescaping and verify data
                js_val = js_literal[1:-1]
                js_val = (js_val
                    .replace('\\"', '"')
                    .replace('\\\\', '\\')
                    .replace('\\n', '\n'))
                lines = [l for l in js_val.split('\n') if l.strip()]
                records = [_json.loads(l) for l in lines]
                pkgs = [r for r in records
                        if r.get("record_type") == "package"]
                assert len(pkgs) == 2, f"expected 2 packages, got {len(pkgs)}"

                # Chart.js script still present
                assert "chart.js" in html, \
                    "Chart.js script tag missing after injection"

                # App code present
                assert "function loadScanData" in html
                assert "function parseScanData" in html
                assert "function renderDashboard" in html
                assert "const ECO_COLORS" in html
                assert "const ECO_LABELS" in html

                # Debug logging present
                assert "debugLog" in html, "debugLog function missing"

                # Error/fallback CSS present
                assert ".error" in html, "error state CSS missing"

        finally:
            os.unlink(jsonl.name)

    def test_fallback_on_empty_data(self):
        """When embedded data has no package records, show error on drop zone."""
        import tempfile as _tf

        sample = '{"record_type":"scan_summary","status":"complete"}\n'
        jsonl = _tf.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False)
        jsonl.write(sample)
        jsonl.close()

        try:
            with _tf.TemporaryDirectory() as tmp:
                report_dir = os.path.join(tmp, "reports")
                os.makedirs(report_dir)
                with patch("os.path.isfile", return_value=True), \
                     patch("bumblebee_py.cli._ensure_report_dir",
                           return_value=report_dir):
                    result = cli._generate_report(jsonl.name)

                assert result is not None
                with open(result) as f:
                    html = f.read()

                # Check for fallback logic in the JS code
                assert 'packages.length === 0' in html, \
                    "fallback check for empty packages missing"
                assert '⚠' in html, \
                    "warning icon missing for fallback"

                # Verify the data IS still embedded
                assert "bumblebee_data" in html

        finally:
            os.unlink(jsonl.name)

    def test_fallback_on_invalid_json(self):
        """When embedded data is not valid JSONL, show error on drop zone."""
        import tempfile as _tf

        sample = "not valid json at all\nstill not json\n"
        jsonl = _tf.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False)
        jsonl.write(sample)
        jsonl.close()

        try:
            with _tf.TemporaryDirectory() as tmp:
                report_dir = os.path.join(tmp, "reports")
                os.makedirs(report_dir)
                with patch("os.path.isfile", return_value=True), \
                     patch("bumblebee_py.cli._ensure_report_dir",
                           return_value=report_dir):
                    result = cli._generate_report(jsonl.name)

                assert result is not None
                with open(result) as f:
                    html = f.read()

                # The data is embedded, and the JS will try to parse it
                assert "bumblebee_data" in html
                # Fallback triggers when allRecords.length === 0
                assert "allRecords.length === 0" in html or "not be parsed" in html

        finally:
            os.unlink(jsonl.name)
