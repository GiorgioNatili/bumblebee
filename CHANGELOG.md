# Changelog

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
