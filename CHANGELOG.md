# Changelog

## 0.3.0 (2026-06-17)

### Added

- **`bumblebee intel refresh` subcommand** — Fetches OSV malicious-package
  data and converts it to Bumblebee exposure catalogs. Supports `--source`
  (URL or local file), `--output`, `--dry-run`, and `--verbose` flags.
  Implemented as a package submodule at `bumblebee_py/intel/`.
- **Findings rendering in the HTML viewer** — The dashboard now has a
  dedicated Findings section with severity filters (critical/high/medium/low),
  catalog ID, catalog name, ecosystem, package name, version, evidence, source
  path, and confidence columns.
- **Offline operation** — Removed Chart.js CDN dependency. Ecosystem
  distribution is now rendered with inline CSS bar charts. No network
  required.
- **Findings summary cards** — The summary section now shows potential
  exposure counts (total, critical, high, medium, low) before package counts.
- **Test suite expanded** — 113 tests total (up from 78). New test files:
  `test_intel.py` (OSV refresh, catalog writing, CLI smoke tests),
  `test_findings.py` (catalog loading, finding generation, findings-only mode).
- **Test fixtures** — OSV malicious-package sample data and sample exposure
  catalogs under `tests/fixtures/`.

### Changed

- **CLI usage** — Updated to include `bumblebee intel <command>`.
- **`scan-viewer.html`** — Refactored to use `loadScanData()` →
  `parseScanData()` → `renderDashboard()` pipeline. Added `renderFindings()`,
  `filterFindings()`, and `buildEcoBars()` functions. No external
  dependencies.
- Version bumped to 0.3.0 (minor bump for new CLI subcommand).

## 0.2.6 (2026-06-17)

### Added

- **Browser dashboard section in README** — Full usage instructions for
  `bumblebee scan --profile baseline --view`, data flow documentation,
  dashboard UI description (summary cards, package table, filtering,
  expandable details, raw-data view), manual `.jsonl` loading fallback,
  and troubleshooting guidance.

### Fixed

- **Embedded dashboard rendering** — Refactored the HTML viewer into a
  clean `loadScanData()` → `parseScanData()` → `renderDashboard()`
  pipeline. Each rendering step is wrapped in try-catch so Chart.js
  failures no longer block the table or summary cards.
- **In-page debug panel** — Visible status messages show data type,
  length, record count, package count, render status, and errors.
- **Multi-format input** — `window.bumblebee_data` now supports NDJSON
  string, JSON string, JavaScript array, and JavaScript object formats.
- **Fallback states** — Clear messages for: no embedded data, data could
  not be parsed, data parsed but no packages found, render completed.
- **Variable rename** — `window.__BUMBLEBEE_DATA__` → `window.bumblebee_data`.

## 0.2.5 (2026-06-17)

### Added

- **Debug logging** — The HTML dashboard now logs embedded data size, line
  count, package count, parse errors, and scan summary to the browser
  console (`console.log` with `[bumblebee]` prefix).
- **Fallback state** — If embedded data contains no package records (or is
  completely invalid), the dashboard shows a red-bordered drop-zone with
  an error message instead of a blank dashboard.

## 0.2.4 (2026-06-17)

### Fixed

- **Dashboard HTML rendering was blank** — `json.dumps()` was used to embed
  the JSONL data into the HTML, which escaped newlines as `\n` (backslash-n).
  The JavaScript code does `text.split('\n')` looking for actual newline
  characters (ASCII 10), so it found none and treated the entire dataset as
  one invalid JSON line, silently discarding all records.
  
  **Fix:** Replaced `json.dumps()` with manual JavaScript string escaping
  (`\"` for double quotes, `\\` for backslashes, actual newlines preserved).
  The data is now correctly parsed as multiple JSONL lines in the browser.

## 0.2.3 (2026-06-17)

### Changed

- **HTML report auto-generated on every scan** — The JSONL output is now
  always captured to a temp file and rendered into the dashboard HTML,
  saved to `~/.bumblebee/reports/bumblebee_{hostname}_{timestamp}.html`.
  The path is printed on stderr so you know where to find it.
- **`--view` now means "open in browser"** — The report is always generated;
  `--view` additionally opens it in your default browser.

## 0.2.2 (2026-06-17)

### Changed

- **Package renamed** `bumblebee/` → `bumblebee_py/` to disambiguate from Go
  `cmd/bumblebee/`. Internal imports updated, console script unchanged.
- **`scan-viewer.html` now ships in the wheel** — added `*.html` to
  `[tool.setuptools.package-data]` so pip/pipx installs find the template.

## 0.2.1 (2026-06-17)

### Fixed

- **`--view` flag not found with pipx installs** — `scan-viewer.html` was
  bundled but the template path lookup had a broken fallback that checked
  the same path twice. Removed the duplicate check; the file is now found
  correctly at `bumblebee_py/scan-viewer.html` (always shipped with the package).

## 0.2.0 (2026-06-17)

### Added

- **`--view` flag** — After a scan, opens a self-contained browser dashboard
  showing summary cards, ecosystem donut charts, confidence distribution,
  and a searchable/sortable table. No server or network required.
  ```sh
  bumblebee scan --profile baseline --view
  ```
- **Browser dashboard** (`bumblebee_py/scan-viewer.html`) — A single HTML file that
  renders NDJSON scan output. Can be used standalone (drag-drop a `.jsonl`
  file) or auto-launched via `--view`.

### Fixed

- **Build backend** (`pyproject.toml`): Changed from
  `setuptools.backends._legacy._Backend` (unavailable in some setuptools ≥68
  releases) to `setuptools.build_meta` — the standard backend present in all
  setuptools versions.
- **Homebrew scanning** (`scanner.py`): `is_formula_receipt`,
  `looks_like_cask_metadata_marker`, and `is_cask_metadata_marker` are
  module-level functions but were called as instance methods on the Scanner
  object, causing `AttributeError` for every non-matching file (~359K noisy
  diagnostics) and silently disabling Homebrew + browser extension scanning.
  Fixed by using `homebrew.xxx` / `browserext.xxx` module references.
- **Ecosystem filter parsing** (`cli.py`): `_parse_ecosystem_filter` returned
  `None` for both "no --ecosystem flag given" (valid, meaning all ecosystems)
  and "invalid ecosystem name" (error). The caller treated all `None` returns
  as failures and exited with code 2 without printing an error message.

### Changed

- Version bumped to `0.2.0` (pipx upgrade now works without reinstall).

---

## 0.1.1 (2026-05-15)

Initial Python port of the Go bumblebee inventory collector. Scans npm, PyPI,
Go, RubyGems, Packagist, Homebrew, MCP configs, editor extensions, browser
extensions, and agent-skill locks. All 18 scanners ported with matching stable
IDs and NDJSON output schema.
