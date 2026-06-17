# bumblebee

Bumblebee is a read-only inventory collector for package, extension,
and developer-tool metadata on macOS and Linux developer endpoints.

It answers a narrow supply-chain response question: when an advisory
names a package, extension, or version, which developer machines show
a match in their on-disk metadata right now?

SBOMs help answer what shipped, and EDR helps answer what ran or
touched the network, but supply-chain response often needs a different
view: messy local state across lockfiles, package-manager metadata,
extension manifests, and supported developer-tool configs.

Bumblebee turns that scattered on-disk state into structured NDJSON
component records and, when given an exposure catalog, flags exact
matches for fast, read-only exposure checks when responders already
know what they are looking for.

## Scope

- Single static binary, Go 1.25+, zero non-stdlib dependencies.
- Three scan profiles (`baseline`, `project`, `deep`) for different
  populations and cadences.
- Reads only the lockfiles, package-manager install metadata,
  extension manifests, and supported MCP JSON configs listed in
  [docs/inventory-sources.md](docs/inventory-sources.md). No package
  manager execution (`npm ls`, `pip show`, `go list`, ...) and no
  source-file reads. MCP host configs can carry environment values
  and credentials in their `env` blocks; Bumblebee parses these
  configs for the server inventory it needs but does not emit those
  values in its records.

## Coverage

| Family | Emitted `ecosystem` | Sources |
|---|---|---|
| npm | `npm` | `package-lock.json`, `npm-shrinkwrap.json`, `node_modules/.package-lock.json`, `node_modules/<pkg>/package.json` |
| pnpm | `npm` | `pnpm-lock.yaml`, `.pnpm/.../package.json` |
| Yarn | `npm` | `yarn.lock` (Classic + Berry) |
| Bun | `npm` | `bun.lock`; `bun.lockb` presence as diagnostic |
| PyPI | `pypi` | `*.dist-info/METADATA`, `INSTALLER`, `direct_url.json`, `*.egg-info/PKG-INFO` |
| Go modules | `go` | `go.sum`, `go.mod` |
| RubyGems | `rubygems` | `Gemfile.lock`, installed `*.gemspec` |
| Composer | `packagist` | `composer.lock`, `vendor/composer/installed.json` |
| MCP | `mcp` | JSON host configs: `mcp.json`, `.mcp.json`, `claude_desktop_config.json`, `mcp_config.json`, `mcp_settings.json`, `cline_mcp_settings.json`, plus `~/.gemini/settings.json` (Gemini CLI / Code Assist) and `~/.claude.json` (Claude Code user- and project-scoped `mcpServers`). Non-JSON configs (Codex `config.toml`, Continue YAML) are not parsed in v0.1. |
| Agent skills | `agent-skill` | `skills.sh` / `vercel-labs/skills` lock files: global `~/.agents/.skill-lock.json` (or `$XDG_STATE_HOME/skills/.skill-lock.json`) and project-local `skills-lock.json`. Loose `SKILL.md` directories without a lock file are not enumerated. |
| Editor extensions | `editor-extension` | VS Code, Cursor, Windsurf, VSCodium manifests |
| Browser extensions | `browser-extension` | Chromium-family (`manifest.json`) and Firefox (`extensions.json`) per profile |
| Homebrew | `homebrew` | Formula `INSTALL_RECEIPT.json` files and cask `.metadata` install markers |

Per-ecosystem detail: [docs/inventory-sources.md](docs/inventory-sources.md).

## Install

### Go (original)

Requires Go 1.25+. Zero non-stdlib dependencies.

```sh
# Install the latest tagged release into $GOBIN.
go install github.com/perplexityai/bumblebee/cmd/bumblebee@latest

# Or pin a specific tag.
go install github.com/perplexityai/bumblebee/cmd/bumblebee@v0.1.1
```

To build from a checkout:

```sh
go build -o bumblebee ./cmd/bumblebee
go test ./...
```

Stamp an explicit version at build time:

```sh
go build -ldflags "-X main.Version=v0.1.1" -o bumblebee ./cmd/bumblebee
```

`bumblebee version` prints the version plus the VCS revision, build
time, and Go runtime — so a record emitted in production can be traced
back to a specific build. Version precedence: `-ldflags` override,
module version recorded by `go install`, then the in-tree default
tracked in `VERSION`.

### Python port

A pure Python 3 port lives on the [`python-port`](https://github.com/GiorgioNatili/bumblebee/tree/python-port) branch.
Zero external dependencies — only the standard library.

#### With pip (global install)

```sh
# Switch to the python-port branch.
git checkout python-port

# Install the package.
pip install .

# Run.
bumblebee scan --profile baseline

# Or without installing, via the module directly.
python3 -m bumblebee_py version

# Run the test suite.
python3 -m pytest tests/
```

#### With pipx (isolated environment)

[pipx](https://pipx.pypa.io/) installs Python applications into their own
isolated virtual environments, keeping global site-packages clean — ideal
if you manage Python with Homebrew and don't want to pollute
`$(brew --prefix)/lib/pythonX.Y/site-packages`.

```sh
# Switch to the python-port branch.
git checkout python-port

# Install into an isolated environment.
pipx install .

# Run.
bumblebee scan --profile baseline

# Or install directly from the remote branch (no local clone needed).
pipx install git+https://github.com/GiorgioNatili/bumblebee.git@python-port

# Run once without installing (ephemeral environment).
pipx run git+https://github.com/GiorgioNatili/bumblebee.git@python-port scan --profile baseline

# Upgrade the pipx install.
pipx upgrade bumblebee

# Uninstall.
pipx uninstall bumblebee
```

Since Bumblebee has zero external dependencies, pipx's main benefit here
is **environment isolation**: the app and its metadata live in
`~/.local/pipx/venvs/` rather than in your Homebrew-managed site-packages,
and you can remove it cleanly with `pipx uninstall`.

The Python port implements the same three scan profiles, all 12 ecosystem
scanners, the exposure-catalog matching engine, and the HTTP sink with
bearer / HMAC-SHA256 auth — all ported directly from the Go original
with matching stable IDs and NDJSON output schema.

Key differences from the Go build:
- Requires Python 3.10+ (tested on 3.13).
- No `selftest` subcommand yet (the embedded Go fixtures are not bundled).
- Concurrency uses `ThreadPoolExecutor` instead of goroutines, with
  the same semantics (serial walk, parallel parse).
- Version can be overridden via the `BUMBLEBEE_VERSION` env var.
- `--max-duration` and `--http-timeout` accept **float seconds** (e.g.
  `--max-duration 600` for 10 minutes), not Go's `time.Duration` strings
  like `"10m"`.
- `--root` also accepts the short form `-r`. Comma-separated values
  (e.g. `--root a,b`) are **not** supported — repeat the flag:
  `--root a --root b`.

See [CHANGELOG](CHANGELOG.md) for version history.

### Browser dashboard

Scan results can be viewed in an interactive browser dashboard — a
self-contained HTML file with summary cards, ecosystem and confidence pie
charts, a searchable/filterable package table, expandable detail rows,
and an optional raw-data view.

```sh
# Run a scan and open the dashboard automatically.
bumblebee scan --profile baseline --view
```

#### Data flow

```
scan output
→ NDJSON/JSONL records
→ embedded as window.bumblebee_data in HTML
→ parsed by scan-viewer.html (loadScanData → parseScanData → renderDashboard)
→ rendered as an interactive dashboard
```

The dashboard opens automatically when `--view` is passed. The scan data
is embedded directly into the HTML file — no server, no network, no
additional files needed.

#### Dashboard UI

| Component | Description |
|---|---|
| **Summary cards** | Total packages, largest ecosystem, high/medium/low confidence counts, direct dependencies, packages with lifecycle scripts |
| **Ecosystem chart** | Doughnut chart showing package distribution by ecosystem |
| **Confidence chart** | Doughnut chart showing confidence-level breakdown |
| **Ecosystem tabs** | Filter the package table to a single ecosystem |
| **Search box** | Filter packages by name, version, or source path |
| **Package table** | Sortable columns (ecosystem, package name, version, confidence, source type, path) |
| **Expandable details** | Click ▶ on any row to reveal: record ID, source file, package manager, root kind, install scope, direct dependency flag, lifecycle scripts |
| **Raw data view** | Hidden by default; click "Show" to see the full embedded NDJSON |

#### Manual loading (fallback)

If you saved scan output to a file, you can load it manually:

```sh
# Save scan output to a file.
bumblebee scan --profile baseline > inventory.jsonl

# Open the dashboard (bundled with the package) in your browser,
# then drag inventory.jsonl onto the drop zone.
```

The dashboard is bundled with the package at
[`bumblebee_py/scan-viewer.html`](bumblebee_py/scan-viewer.html).

#### Troubleshooting

| Symptom | Likely cause | What to check |
|---|---|---|
| Dashboard is blank | Embedded data missing or empty | Run with `--view` so data is injected automatically |
| Dashboard shows "could not be parsed" | The embedded data is not valid NDJSON/JSON | Check the debug panel (shown above the dashboard) for parse errors |
| Dashboard shows "no packages found" | Data contains non-package records only | The data may contain only diagnostic or summary records |
| Charts don't render | Chart.js CDN blocked (offline) | Table, tabs, and raw data still work — charts are non-critical |
| Drag-and-drop doesn't load | File is not `.jsonl` / `.ndjson` / `.json` | The file picker accepts these extensions |
| Debug panel shows errors | See browser console for details | Open DevTools (F12) → Console for full error logs |

Self-contained: the dashboard requires no network once the HTML is
generated (Chart.js loads from CDN when first opened, but the table
and summary cards work offline).

### Self-test

After installing, run a built-in end-to-end check against embedded
fixtures:

```sh
bumblebee selftest
# selftest OK (2 findings in 1ms)
```

The fixtures live inside the binary, use deliberately fake package
names (`bumblebee-selftest-evil@0.0.0`), and make no network calls. A
non-zero exit means the local install can no longer detect what it
should — a fast pre-deployment smoke test for fleet rollouts.

## Profiles

Bumblebee is a one-shot scanner: each invocation performs a single scan
and exits. Cadence is the runner's responsibility (cron, launchd, systemd,
MDM, etc.). Each record carries `profile` and a per-root `root_kind` so
receivers can keep populations separate.

| Profile | Scans | Use for |
|---|---|---|
| `baseline` | Common global/user package roots, language toolchains, editor extensions, browser extensions, and MCP configs. | Recurring lightweight inventory via an external runner. |
| `project` | Configured development directories, such as `~/code`, `~/src`, or `~/work`. | Recurring inventory for known project workspaces. |
| `deep` | Explicit `--root` paths, including broad roots like `$HOME`. | On-demand incident or campaign checks, usually with `--ecosystem`, `--exposure-catalog`, and `--findings-only`. |

`baseline` and `project` refuse bare-home roots; only `deep` walks them.

## Quick start

```sh
# Baseline global inventory and open the browser dashboard.
bumblebee scan --profile baseline --view

# Daily project sweep with explicit roots.
bumblebee scan --profile project \
  --root "$HOME/code" \
  --root "$HOME/Developer"

# Limit a run to selected emitted ecosystems.
bumblebee scan --profile baseline \
  --ecosystem npm \
  --ecosystem pypi

# On-demand exposure scan against a published advisory.
bumblebee scan --profile deep \
  --root "$HOME" \
  --exposure-catalog ./catalog.json \
  --max-duration 600
```

Preview the resolved roots without scanning:

```sh
bumblebee roots --profile baseline
# prints "<root_kind>\t<path>" lines
```

`--root` is a filesystem path to scan; repeatable, required for `deep`,
optional for the other profiles. `--ecosystem` is repeatable and
comma-separated. `--exposure-catalog` accepts a JSON file or a directory
of `*.json` catalogs (merged non-recursively, all files must share
`schema_version`). `--findings-only` requires `--exposure-catalog` and
suppresses package records while keeping findings. `--view` runs the
scan, captures the output, embeds it into a self-contained HTML dashboard,
and opens it in your browser. `bumblebee scan --help`
lists every flag.

### Exposure-catalog matching

Scan results can be matched against local threat-intel catalogs to flag
potential exposures. Matching is **exact** (ecosystem + normalized package
name + version) — package-presence evidence, not runtime forensic proof.

```bash
# Baseline scan with catalog matching, saved to file.
bumblebee scan \
  --profile baseline \
  --exposure-catalog ./threat_intel \
  --output file \
  --output-file ~/.bumblebee/snapshots/baseline-$(date +%F).ndjson

# Deep scan, findings only (suppress package records).
bumblebee scan \
  --profile deep \
  --root "$HOME" \
  --exposure-catalog ./threat_intel \
  --findings-only \
  --output file \
  --output-file ~/.bumblebee/snapshots/findings-$(date +%F).ndjson
```

Matching produces `finding` records with severity, catalog metadata, and
evidence text. These records are rendered in the dashboard's **Findings**
section (see [Browser dashboard](#browser-dashboard)).

### Threat-intel refresh

Bumblebee can fetch OSV malicious-package data and convert it to a local
exposure catalog:

```bash
# Fetch from the default OpenSSF source and write a catalog file.
bumblebee intel refresh --output threat_intel/osv-malicious.json

# Dry-run with verbose output (no file written).
bumblebee intel refresh --dry-run --verbose

# Refresh from a local OSV dump (offline).
bumblebee intel refresh --source ./osv-malicious.json --output threat_intel/refresh.json
```

Supported ecosystems: npm, PyPI, Go, RubyGems, Packagist, Homebrew.
Records with only range-based versions (no explicit version list) are
skipped with a recorded skip reason. Unsupported ecosystems are noted in
the output metadata.

```text
~/.bumblebee/
  threat_intel/          # local exposure catalogs
  snapshots/             # daily scan output
    baseline-2026-06-17.ndjson
    findings-2026-06-17.ndjson
```

### Daily snapshots with refreshed threat intelligence

For ongoing monitoring, set up a daily workflow:

```bash
# 1. Refresh threat intel.
bumblebee intel refresh \
  --output ~/.bumblebee/threat_intel/osv-malicious.json \
  --verbose

# 2. Run a daily inventory snapshot with catalog matching.
bumblebee scan \
  --profile baseline \
  --exposure-catalog ~/.bumblebee/threat_intel \
  --output file \
  --output-file ~/.bumblebee/snapshots/baseline-$(date +%F).ndjson

# 3 (optional). Findings-only snapshot.
bumblebee scan \
  --profile baseline \
  --exposure-catalog ~/.bumblebee/threat_intel \
  --findings-only \
  --output file \
  --output-file ~/.bumblebee/snapshots/findings-$(date +%F).ndjson
```

**Cron example (macOS/Linux):**

```cron
# Run daily at 6 AM.
0 6 * * * cd /path/to/bumblebee && \
  bumblebee intel refresh --output ~/.bumblebee/threat_intel/osv-malicious.json && \
  bumblebee scan --profile baseline \
    --exposure-catalog ~/.bumblebee/threat_intel \
    --output file \
    --output-file ~/.bumblebee/snapshots/baseline-$(date +\%F).ndjson
```

## Output

Records are NDJSON, one per line. Diagnostics go to stderr as NDJSON. Each
run ends with a `scan_summary` record; receivers use it to decide whether
to promote a run to current state. See [docs/transport.md](docs/transport.md)
for HTTPS/file output and [docs/state-model.md](docs/state-model.md) for the
receiver-side current-state model.

Package record:

<details>
<summary>Example package record</summary>

```json
{
  "record_type": "package",
  "record_id": "package:...",
  "schema_version": "0.1.0",
  "scanner_name": "bumblebee",
  "scanner_version": "v0.2.0",
  "run_id": "9b1f0c2e4d5a6b7c8d9e0f1a2b3c4d5e",
  "scan_time": "2026-06-17T18:22:01.482Z",
  "endpoint": {
    "hostname": "alex-mbp",
    "os": "darwin",
    "arch": "arm64",
    "username": "alex",
    "uid": "501",
    "device_id": "MDM-7F4A2B"
  },
  "profile": "project",
  "ecosystem": "npm",
  "package_name": "@tanstack/query-core",
  "normalized_name": "@tanstack/query-core",
  "version": "5.59.20",
  "project_path": "/Users/alex/code/web-app",
  "root_kind": "project_root",
  "package_manager": "pnpm",
  "source_type": "pnpm-lockfile",
  "source_file": "/Users/alex/code/web-app/pnpm-lock.yaml",
  "has_lifecycle_scripts": false,
  "confidence": "high"
}
```

</details>

`confidence`:

- `high` — exact identity and version came from canonical metadata.
- `medium` — identity is reliable, but version or source is partial.
- `low` — config/path/spec reference only; not proof of an installed exact version.

Finding record (exposure-catalog match):

<details>
<summary>Example finding record</summary>

```json
{
  "record_type": "finding",
  "record_id": "finding:...",
  "schema_version": "0.1.0",
  "scanner_name": "bumblebee",
  "scanner_version": "v0.2.0",
  "run_id": "3a8c7d1e9f0b2a4c6d8e0f1a2b3c4d5e",
  "scan_time": "2026-06-17T18:22:01.482Z",
  "endpoint": {
    "hostname": "alex-mbp",
    "os": "darwin",
    "arch": "arm64",
    "username": "alex",
    "uid": "501",
    "device_id": "MDM-7F4A2B"
  },
  "profile": "deep",
  "finding_type": "package_exposure",
  "severity": "critical",
  "catalog_id": "advisory-2026-0042",
  "catalog_name": "example-pkg 1.2.3 (compromised release)",
  "ecosystem": "npm",
  "package_name": "example-pkg",
  "normalized_name": "example-pkg",
  "version": "1.2.3",
  "root_kind": "deep_home_root",
  "project_path": "/Users/alex/code/web-app",
  "source_type": "pnpm-lockfile",
  "source_file": "/Users/alex/code/web-app/pnpm-lock.yaml",
  "confidence": "high",
  "evidence": "exact name+version match (version=1.2.3)"
}
```

</details>

`record_id` is a content-addressed hash of a canonical identity tuple per
record type, stable across runs. Per-record-type field lists and dedupe
guidance: [docs/state-model.md](docs/state-model.md#record-identity-record_id).

## Exposure Catalog Format

Minimal JSON, exact `(ecosystem, name, version)` matching only:

```json
{
  "schema_version": "0.1.0",
  "entries": [
    {
      "id": "advisory-2026-0042",
      "name": "example-pkg 1.2.3 (compromised release)",
      "ecosystem": "npm",
      "package": "example-pkg",
      "versions": ["1.2.3"],
      "severity": "critical"
    }
  ]
}
```

The catalog must be a JSON object with `schema_version` and `entries`
keys. Bare top-level arrays are rejected. Unsupported future
`schema_version` values are rejected. Multiple catalog files can be
loaded together by pointing `--exposure-catalog` at a directory; see
the flag description above.

### Sample exposure catalogs

The [`threat_intel/`](threat_intel/) directory holds maintained exposure
catalogs built from public threat-intelligence reporting on recent
supply-chain campaigns, assembled with
[Perplexity Computer](https://www.perplexity.ai/computer) and updated
via PRs as new campaigns are reported. See
[`threat_intel/README.md`](threat_intel/README.md) for the current
catalog list and review guidance.

## License

Apache License 2.0. See [LICENSE](LICENSE).
