"""
CLI entry point for Bumblebee.

Subcommands:
  scan       run a scan and emit NDJSON records
  roots      print the resolved scan roots and exit
  selftest   scan embedded fixtures and verify detection
  version    print version and exit
"""

import argparse
import os
import secrets
import signal
import sys
import tempfile
import time
import webbrowser
from typing import Optional

from bumblebee import model
from bumblebee import endpoint
from bumblebee import version as bversion
from bumblebee.emitter import Emitter
from bumblebee.httpsink import HTTPSink, HTTPConfig, HTTPAuth, validate_http_config
from bumblebee.exposure import load as load_catalog
from bumblebee.scanner import Config as ScannerConfig, Root, run as run_scan
from bumblebee.roots import RootsOpts, resolve_roots


def main(argv: Optional[list[str]] = None) -> int:
    """Main CLI entry point. Returns exit code."""
    if argv is None:
        argv = sys.argv[1:]

    if not argv:
        _print_usage(sys.stderr)
        return 2

    subcommand = argv[0]
    rest = argv[1:]

    if subcommand == "scan":
        return _run_scan(rest)
    elif subcommand == "roots":
        return _run_roots(rest)
    elif subcommand in ("version", "--version", "-version"):
        print(bversion.version_string())
        return 0
    elif subcommand in ("-h", "--help", "help"):
        _print_usage(sys.stdout)
        return 0
    else:
        print(f"unknown subcommand {subcommand!r}", file=sys.stderr)
        _print_usage(sys.stderr)
        return 2


def _print_usage(file):
    print(_USAGE, file=file)


_USAGE = """\
bumblebee — endpoint package inventory collector

usage:
  bumblebee scan     [flags]   run a scan and emit NDJSON records
  bumblebee roots    [flags]   print the resolved scan roots and exit
  bumblebee selftest [flags]   scan embedded fixtures and verify detection
  bumblebee version            print version and exit

run "bumblebee scan --help" for scan flags, including --profile.
"""


def _run_scan(args: list[str]) -> int:
    """Execute the scan subcommand."""
    parser = argparse.ArgumentParser(
        prog="bumblebee scan",
        description="Run a package inventory scan and emit NDJSON records.",
    )
    _add_scan_flags(parser)
    opts = parser.parse_args(args)

    # Validate profile
    profile = opts.profile or model.PROFILE_BASELINE
    profile = profile.strip()
    if profile not in (model.PROFILE_BASELINE, model.PROFILE_PROJECT, model.PROFILE_DEEP):
        print(f"unknown --profile {profile!r} (want: baseline, project, deep)",
              file=sys.stderr)
        return 2
    opts.profile = profile

    # Parse ecosystem filter
    ecosystem_filter, parse_err = _parse_ecosystem_filter(opts.ecosystems)
    if parse_err:
        print(parse_err, file=sys.stderr)
        return 2

    # findings-only requires catalog
    if opts.findings_only and not opts.exposure_catalog:
        print("--findings-only requires --exposure-catalog", file=sys.stderr)
        return 2

    # Resolve roots
    roots_opts = RootsOpts(all_users=opts.all_users)
    roots, notes, err = resolve_roots(
        opts.profile, opts.roots or [], roots_opts,
    )
    if err:
        print(err, file=sys.stderr)
        return 2

    # Load catalog
    catalog = None
    if opts.exposure_catalog:
        try:
            catalog = load_catalog(opts.exposure_catalog, opts.max_catalog_size)
        except (ValueError, OSError) as e:
            print(f"exposure catalog: {e}", file=sys.stderr)
            return 2

    # Open sink
    records_w, close_fn, err = _open_sink(
        opts.output, opts.output_file, opts.append,
        opts.http_url, opts.http_auth, opts.http_token_env, opts.http_hmac_key_env,
        opts.http_timeout, opts.http_batch_size, opts.http_allow_insecure,
        opts.http_gzip,
    )
    if err:
        print(err, file=sys.stderr)
        return 2

    # Capture output for --view
    _view_data_file = None
    if opts.view:
        if opts.output == "http":
            print("--view is not compatible with --output=http", file=sys.stderr)
            return 2
        if opts.output == "stdout":
            _view_data_file = tempfile.NamedTemporaryFile(
                mode="w", suffix=".jsonl", delete=False, prefix="bumblebee_")
            records_w = _view_data_file
            close_fn_orig = close_fn
            def _close_view():
                if close_fn_orig:
                    close_fn_orig()
                _view_data_file.close()
            close_fn = _close_view
        else:
            _view_data_file = opts.output_file

    run_id = secrets.token_hex(16)
    emitter = Emitter(records_w, sys.stderr, run_id)

    for note in notes:
        emitter.diag("info", "", note)

    device_id, device_warn = _resolve_device_id(opts.device_id_env)
    if device_warn:
        emitter.diag("warn", "", device_warn)

    ep = endpoint.current(device_id)
    scan_start = time.strftime("%Y-%m-%dT%H:%M:%S.", time.gmtime()) + \
        f"{int(time.time() * 1_000_000) % 1_000_000:06d}Z"

    base_record = model.Record(
        record_type=model.RECORD_TYPE_PACKAGE,
        schema_version=model.SCHEMA_VERSION,
        scanner_name=model.SCANNER_NAME,
        scanner_version=bversion.current_version(),
        run_id=run_id,
        scan_time=scan_start,
        endpoint=ep,
        profile=opts.profile,
    )

    # Handle cancellation
    cancel_requested = [False]

    def handle_signal(signum, frame):
        cancel_requested[0] = True

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    cfg = ScannerConfig(
        profile=opts.profile,
        roots=[Root(path=p, kind=k) for p, k in zip(
            [r.path for r in roots], [r.kind for r in roots]
        )] if roots else [],
        excludes=opts.excludes or [],
        ecosystems=ecosystem_filter,
        max_file_size=opts.max_file_size,
        max_duration=opts.max_duration,
        concurrency=opts.concurrency,
        catalog=catalog,
        findings_only=opts.findings_only,
        base_record=base_record,
        emitter=emitter,
    )

    res, scan_err = run_scan(None, cfg)

    # Determine exit code and scan status
    exit_code = 0
    status = model.SCAN_STATUS_COMPLETE
    err_msg = ""

    if scan_err:
        if res.records_emitted > 0:
            status = model.SCAN_STATUS_PARTIAL
        else:
            status = model.SCAN_STATUS_ERROR
        err_msg = str(scan_err)
        if exit_code == 0:
            exit_code = 1

    # Restore from roots list
    summary_roots = [
        model.SummaryRoot(path=r.path, kind=r.kind)
        for r in roots
    ]

    if opts.emit_summary:
        counts = {
            model.RECORD_TYPE_PACKAGE: res.records_emitted,
            model.RECORD_TYPE_FINDING: res.findings_emitted,
        }
        summary = model.ScanSummary(
            record_type=model.RECORD_TYPE_SCAN_SUMMARY,
            schema_version=model.SCHEMA_VERSION,
            scanner_name=model.SCANNER_NAME,
            scanner_version=bversion.current_version(),
            run_id=run_id,
            scan_time=scan_start,
            end_time=time.strftime("%Y-%m-%dT%H:%M:%S.", time.gmtime()) +
                     f"{int(time.time() * 1_000_000) % 1_000_000:06d}Z",
            endpoint=ep,
            profile=opts.profile,
            status=status,
            roots=summary_roots,
            counts=counts,
            package_records_emitted=res.records_emitted,
            package_records_suppressed=res.package_records_suppressed,
            findings_emitted=res.findings_emitted,
            duplicates=res.duplicates,
            diagnostics_count=res.diagnostics,
            files_considered=res.files_considered,
            timed_out=res.timed_out,
            duration_ms=int(res.duration * 1000),
        )
        err = emitter.emit_summary(summary)
        if err:
            emitter.diag("error", "", f"emit scan_summary: {err}")
            exit_code = 1

    if close_fn:
        try:
            close_fn()
        except Exception as e:
            emitter.diag("error", "", str(e))
            exit_code = 1

    emitter.diag("info", "",
                 f"scan complete: profile={profile} status={status} "
                 f"files_considered={res.files_considered} "
                 f"records={res.records_emitted} "
                 f"findings={res.findings_emitted} "
                 f"suppressed={res.package_records_suppressed} "
                 f"duplicates={res.duplicates} "
                 f"diagnostics={res.diagnostics} "
                 f"timed_out={res.timed_out} "
                 f"duration={res.duration:.2f}s")

    # Open the dashboard viewer in the browser
    if opts.view and _view_data_file:
        _open_viewer(_view_data_file)

    return exit_code


def _open_viewer(data_file):
    """Generate a self-contained HTML dashboard and open it in the browser."""
    import json

    # Locate the viewer template bundled with the package
    viewer_path = os.path.join(os.path.dirname(__file__), "scan-viewer.html")
    if not os.path.isfile(viewer_path):
        print("dashboard template (scan-viewer.html) not found in package",
              file=sys.stderr)
        return

    # Read the JSONL data
    if isinstance(data_file, str):
        data_path = data_file
    else:
        data_path = data_file.name

    try:
        with open(data_path) as f:
            jsonl_data = f.read()
    except OSError as e:
        print(f"read scan data for viewer: {e}", file=sys.stderr)
        return

    # Read the viewer template
    try:
        with open(viewer_path) as f:
            html = f.read()
    except OSError as e:
        print(f"read viewer template: {e}", file=sys.stderr)
        return

    # Embed the JSONL data as a JS string literal (using json.dumps for safe escaping)
    data_script = f"<script>window.__BUMBLEBEE_DATA__ = {json.dumps(jsonl_data)};</script>"

    # Insert the data script right before the first <script> tag (after <head>)
    html = html.replace("<script>", data_script + "\n<script>", 1)

    # Write to a temp HTML file
    try:
        out_fd, out_path = tempfile.mkstemp(suffix=".html", prefix="bumblebee_")
        with os.fdopen(out_fd, "w") as f:
            f.write(html)
    except OSError as e:
        print(f"write viewer: {e}", file=sys.stderr)
        return

    print(f"📊 Dashboard opened: {out_path}", file=sys.stderr)
    webbrowser.open(f"file://{os.path.abspath(out_path)}")


def _run_roots(args: list[str]) -> int:
    """Print resolved roots for a profile."""
    parser = argparse.ArgumentParser(prog="bumblebee roots")
    parser.add_argument("--profile", default=model.PROFILE_BASELINE,
                        choices=[model.PROFILE_BASELINE, model.PROFILE_PROJECT, model.PROFILE_DEEP])
    parser.add_argument("--root", action="append", default=[], dest="roots")
    parser.add_argument("--all-users", action="store_true", default=False)

    opts = parser.parse_args(args)
    roots_opts = RootsOpts(all_users=opts.all_users)
    roots, notes, err = resolve_roots(opts.profile, opts.roots, roots_opts)
    if err:
        print(err, file=sys.stderr)
        return 2
    for note in notes:
        print(note, file=sys.stderr)
    for r in roots:
        print(f"{r.kind}\t{r.path}")
    return 0


def _add_scan_flags(parser: argparse.ArgumentParser):
    """Register scan-specific flags."""
    parser.add_argument("--profile", default=model.PROFILE_BASELINE,
                        help="scan profile: baseline, project, or deep")
    parser.add_argument("--root", "-r", action="append", default=[], dest="roots",
                        help="directory to scan (repeatable)")
    parser.add_argument("--exclude", action="append", default=[], dest="excludes",
                        help="additional directory name or suffix path to exclude")
    parser.add_argument("--ecosystem", action="append", default=[], dest="ecosystems",
                        help="limit scanning to specific ecosystems (repeatable)")
    parser.add_argument("--max-file-size", type=int, default=5 * 1024 * 1024,
                        help="max bytes to read from any single metadata file")
    parser.add_argument("--max-duration", type=float, default=0,
                        help="max wall-clock duration in seconds (0 = unbounded)")
    parser.add_argument("--concurrency", type=int, default=4,
                        help="number of concurrent file parsers")

    parser.add_argument("--exposure-catalog", default="",
                        help="path to a JSON exposure catalog file or directory")
    parser.add_argument("--max-catalog-size", type=int, default=64 * 1024 * 1024,
                        help="max bytes per catalog file")
    parser.add_argument("--findings-only", action="store_true", default=False,
                        help="suppress package records, emit only findings")

    parser.add_argument("--all-users", action="store_true", default=False,
                        help="on macOS, expand per-user defaults across all homes")

    parser.add_argument("--output", default="stdout",
                        choices=["stdout", "file", "http"],
                        help="where to send records")
    parser.add_argument("--output-file", default="",
                        help="path for --output=file")
    parser.add_argument("--append", action="store_true", default=False,
                        help="append to --output-file instead of truncating")
    parser.add_argument("--emit-summary", action="store_true", default=True,
                        help="emit a scan_summary record")
    parser.add_argument("--no-emit-summary", action="store_false", dest="emit_summary",
                        help="suppress the scan_summary record")

    parser.add_argument("--http-url", default="", help="ingest URL for --output=http")
    parser.add_argument("--http-auth", default="none",
                        choices=["none", "bearer", "hmac-sha256"])
    parser.add_argument("--http-token-env", default="",
                        help="env var for bearer token")
    parser.add_argument("--http-hmac-key-env", default="",
                        help="env var for HMAC shared secret")
    parser.add_argument("--http-timeout", type=float, default=30.0,
                        help="per-request timeout in seconds")
    parser.add_argument("--http-batch-size", type=int, default=500,
                        help="records per POST")
    parser.add_argument("--http-allow-insecure", action="store_true", default=False,
                        help="allow plain http:// to non-loopback hosts")
    parser.add_argument("--http-gzip", action="store_true", default=False,
                        help="gzip the POST body")

    parser.add_argument("--device-id-env", default="",
                        help="env var holding a stable device/endpoint id")

    parser.add_argument("--view", action="store_true", default=False,
                        help="open the dashboard in a browser after the scan")


def _parse_ecosystem_filter(values: list[str]) -> tuple[Optional[set[str]], Optional[str]]:
    """Parse --ecosystem values into a set, or None for all.

    Returns (ecosystem_set_or_None, error_string_or_None).
    """
    if not values:
        return None, None
    result = set()
    invalid = []
    for value in values:
        for part in value.split(","):
            part = part.strip()
            if not part:
                continue
            if not model.is_supported_ecosystem(part):
                invalid.append(part)
                continue
            result.add(part)
    if invalid:
        valid = ", ".join(model.supported_ecosystems())
        err = (f"invalid --ecosystem value(s): {', '.join(sorted(invalid))} "
               f"(allowed: {valid})")
        return None, err
    return (result if result else None), None


def _resolve_device_id(env_name: str) -> tuple[str, str]:
    """Read device ID from env var.

    Returns (device_id, warning_message).
    """
    if not env_name:
        return "", ""
    raw = os.environ.get(env_name, "")
    if not raw:
        return "", (f"--device-id-env={env_name!r} is not set in the environment; "
                    "proceeding without endpoint.device_id")
    dev_id = raw.strip()
    if not dev_id:
        return "", (f"--device-id-env={env_name!r} is set but empty/whitespace; "
                    "proceeding without endpoint.device_id")
    return dev_id, ""


def _open_sink(dest: str, file_path: str, append_mode: bool,
               http_url: str, http_auth: str, http_token_env: str,
               http_hmac_key_env: str, http_timeout: float,
               http_batch_size: int, http_allow_insecure: bool,
               http_gzip: bool) -> tuple:
    """Open an output sink.

    Returns (writer, close_fn, error).
    """
    if dest == "" or dest == "stdout":
        return sys.stdout, None, None
    elif dest == "file":
        if not file_path:
            return None, None, "--output=file requires --output-file"
        mode = "a" if append_mode else "w"
        try:
            f = open(file_path, mode)
            return f, f.close, None
        except OSError as e:
            return None, None, f"open output file: {e}"
    elif dest == "http":
        auth = HTTPAuth(mode=http_auth)
        if http_auth == "bearer":
            if not http_token_env:
                return None, None, "--http-auth=bearer requires --http-token-env"
            tok = os.environ.get(http_token_env, "")
            if not tok:
                return None, None, f"env var {http_token_env!r} is empty"
            auth.token = tok
        elif http_auth == "hmac-sha256":
            if not http_hmac_key_env:
                return None, None, "--http-auth=hmac-sha256 requires --http-hmac-key-env"
            key = os.environ.get(http_hmac_key_env, "")
            if not key:
                return None, None, f"env var {http_hmac_key_env!r} is empty"
            auth.hmac_key = key.encode("utf-8")

        hcfg = HTTPConfig(
            url=http_url,
            auth=auth,
            timeout=http_timeout,
            batch_size=http_batch_size,
            user_agent=f"bumblebee/{bversion.current_version()}",
            allow_insecure=http_allow_insecure,
            gzip=http_gzip,
        )
        err = validate_http_config(hcfg)
        if err:
            return None, None, err
        sink = HTTPSink(hcfg)
        return sink, sink.close, None
    else:
        return None, None, f"unknown --output {dest!r} (want stdout|file|http)"


if __name__ == "__main__":
    sys.exit(main())
