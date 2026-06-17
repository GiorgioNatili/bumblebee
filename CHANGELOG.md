# Changelog

## 0.2.0 (2026-06-17)

### Added

- **`--view` flag** — After a scan, opens a self-contained browser dashboard
  showing summary cards, ecosystem donut charts, confidence distribution,
  and a searchable/sortable table. No server or network required.
  ```sh
  bumblebee scan --profile baseline --view
  ```
- **Browser dashboard** (`bumblebee/scan-viewer.html`) — A single HTML file that
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
