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
| **Summary cards** | Total packages, total findings (critical/high/medium/low), largest ecosystem, confidence counts, direct dependencies, lifecycle scripts. Cards show helpful subtext (e.g. "No catalog matches", "Trait — review when paired with exposure") |
| **Explainer panel** | "What am I looking at?" — separates Inventory, Traits, Potential Exposures, and Evidence |
| **Action guide** | "What should I do next?" — adaptive triage steps based on available data |
| **Ecosystem bars** | Inline CSS bar chart showing package distribution by ecosystem (no CDN) |
| **Findings table** | Severity-filterable (critical/high/medium/low/all) with ecosystem, package, version, catalog ID, evidence, source path, and **recommended action** (e.g. "Review immediately", "Check lifecycle scripts") |
| **Threat-intel status** | Shows catalog source, generated timestamp, records processed/emitted/skipped when available |
| **Ecosystem tabs** | Filter the package table to a single ecosystem |
| **Search box** | Filter packages by name, version, or source path |
| **Package table** | Sortable columns (ecosystem, package name, version, confidence, source type, path). Expandable rows show: potential exposure status, severity and catalog info (if matched), traits labeled with "— trait", identity fields, source info |
| **Raw data view** | Hidden by default; click "Show" to see the full embedded NDJSON |
| **Debug details** | Collapsible section (hidden by default), auto-expands on error |

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
| Dashboard shows no findings | No catalog match, or scan was run without `--catalogs (or legacy --exposure-catalog)` | Run with `--catalogs (or legacy --exposure-catalog) ./catalogs` |
| Drag-and-drop doesn't load | File is not `.jsonl` / `.ndjson` / `.json` | The file picker accepts these extensions |
| Debug panel shows errors | See browser console for details | Open DevTools (F12) → Console for full error logs |

The dashboard is fully self-contained. No network access is required.

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
| `deep` | Explicit `--root` paths, including broad roots like `$HOME`. | On-demand incident or campaign checks, usually with `--ecosystem`, `--catalogs (or legacy --exposure-catalog)`, and `--findings-only`. |

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
  --catalogs (or legacy --exposure-catalog) ./catalog.json \
  --max-duration 600
```

Preview the resolved roots without scanning:

```sh
bumblebee roots --profile baseline
# prints "<root_kind>\t<path>" lines
```

`--root` is a filesystem path to scan; repeatable, required for `deep`,
optional for the other profiles. `--ecosystem` is repeatable and
comma-separated. `--catalogs (or legacy --exposure-catalog)` accepts a JSON file or a directory
of `*.json` catalogs (merged non-recursively, all files must share
`schema_version`). `--findings-only` requires `--catalogs (or legacy --exposure-catalog)` and
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
  --catalogs (or legacy --exposure-catalog) ./catalogs \
  --output file \
  --output-file ~/.bumblebee/snapshots/baseline-$(date +%F).ndjson

# Deep scan, findings only (suppress package records).
bumblebee scan \
  --profile deep \
  --root "$HOME" \
  --catalogs (or legacy --exposure-catalog) ./catalogs \
  --findings-only \
  --output file \
  --output-file ~/.bumblebee/snapshots/findings-$(date +%F).ndjson
```

Matching produces `finding` records with severity, catalog metadata, and
evidence text. These records are rendered in the dashboard's **Findings**
section (see [Browser dashboard](#browser-dashboard)).

### Catalog refresh

Bumblebee can fetch OSV malicious-package data and convert it to a local
exposure catalog:

```bash
# Fetch from the default OpenSSF source and write a catalog file.
bumblebee catalog refresh --output catalogs/malicious/openssf.json

# Dry-run with verbose output (no file written).
bumblebee catalog refresh --dry-run --verbose

# Refresh from a local OSV dump (offline).
bumblebee catalog refresh --source ./osv-malicious.json --output catalogs/custom.json
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

### Daily snapshots with refreshed catalogs

For ongoing monitoring, set up a daily workflow:

```bash
# 1. Refresh catalogs.
bumblebee catalog refresh \
  --output ~/.bumblebee/catalogs/malicious/openssf.json \
  --verbose

# 2. Run a daily inventory snapshot with catalog matching.
bumblebee scan \
  --profile baseline \
  --catalogs (or legacy --exposure-catalog) ~/.bumblebee/catalogs \
  --output file \
  --output-file ~/.bumblebee/snapshots/baseline-$(date +%F).ndjson

# 3 (optional). Findings-only snapshot.
bumblebee scan \
  --profile baseline \
  --catalogs (or legacy --exposure-catalog) ~/.bumblebee/catalogs \
  --findings-only \
  --output file \
  --output-file ~/.bumblebee/snapshots/findings-$(date +%F).ndjson
```

**Cron example (macOS/Linux):**

```cron
# Run daily at 6 AM.
0 6 * * * cd /path/to/bumblebee && \
  bumblebee catalog refresh --output ~/.bumblebee/catalogs/malicious/openssf.json && \
  bumblebee scan --profile baseline \
    --catalogs (or legacy --exposure-catalog) ~/.bumblebee/catalogs \
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
loaded together by pointing `--catalogs (or legacy --exposure-catalog)` at a directory; see
the flag description above.

### Sample exposure catalogs

## Package traits

Each `package` record carries traits that help triage potential exposure:

| Trait | Meaning | Why it matters |
|---|---|---|
| `ecosystem` | Package ecosystem (npm, PyPI, Go, RubyGems, Packagist, homebrew, browser-extension, editor-extension, mcp, agent-skill) | Groups exposure by package source |
| `package_name` | Discovered package or extension name | Used for catalog matching |
| `version` | Installed or locked version | Used for exact exposure matching |
| `source_file` | File or metadata source where the package was found | Supports analyst review |
| `source_type` | Type of source (lockfile, dist-info, manifest, receipt, etc.) | Indicates how the package was discovered |
| `package_manager` | Package manager that installed the package (npm, pip, pnpm, homebrew, etc.) | Helps understand install context |
| `confidence` | Confidence in the discovery (`high`, `medium`, `low`) | Helps prioritize review |
| `direct_dependency` | Whether the package appears to be directly declared | Helps distinguish direct from transitive exposure |
| `install_scope` | Global, user, project, extension, or similar scope | Helps determine blast radius |
| `has_lifecycle_scripts` | Whether lifecycle scripts were detected | Useful for supply-chain triage |
| `lifecycle_scripts` | Script names or metadata, if available | Helps review install-time execution risk |
| `requested_spec` | Requested dependency specifier, if available | Helps compare declared vs resolved package |
| `server_name` | MCP or server config name, if available (MCP ecosystem only) | Helps map packages back to configured tools |
| `project_path` | Project root or workspace path where the package was found | Helps locate the package in context |
| `root_kind` | Kind of scan root (user_package_root, project_root, homebrew_root, deep_home_root, etc.) | Identifies the root type that discovered the package |

Some traits are source-specific. For example, `server_name` is only
populated for MCP config discoveries, and `lifecycle_scripts` only
appears when the source metadata includes scripts.

### Inspecting output with jq

```bash
# Select all package records, compact fields.
jq 'select(.record_type == "package") | {ecosystem, package_name, version, confidence, source_file}' snapshot.ndjson

# Trait-rich view.
jq '
  select(.record_type == "package")
  | {
      ecosystem,
      package_name,
      version,
      source_type,
      source_file,
      package_manager,
      confidence,
      direct_dependency,
      install_scope,
      requested_spec,
      has_lifecycle_scripts,
      lifecycle_scripts,
      server_name
    }
' snapshot.ndjson

# Select all finding records.
jq 'select(.record_type == "finding")' snapshot.ndjson

# Findings as a compact table (TSV).
jq -r '
  select(.record_type == "finding")
  | [.severity, .ecosystem, .package_name, .version, .catalog_id, .evidence, .source_file]
  | @tsv
' snapshot.ndjson

# Scan summary (one per run).
jq 'select(.record_type == "scan_summary") | {status, package_records_emitted, findings_emitted, duration_ms}' snapshot.ndjson
```

## Understanding findings

A `finding` record means Bumblebee discovered a package/version that
matches an entry in a local exposure catalog. It is **package-presence
evidence**, not runtime forensic proof.

| Statement | Supported by Bumblebee? |
|---|---|
| "This package/version was found on this machine" | ✅ Yes (exact-match scanning of on-disk metadata) |
| "This package/version matches a known-bad entry in the local catalog" | ✅ Yes (if `--catalogs (or legacy --exposure-catalog)` was used) |
| "This machine is compromised" | ❌ No (Bumblebee does not execute packages or collect runtime evidence) |
| "This finding is a true positive" | ❌ No (catalogs may contain false positives; review each finding) |

What to do with a finding:

1. **Review the evidence** — check `source_file` and `confidence`.
2. **Check install context** — is it a direct dependency (`direct_dependency`)?
   Is it in a project (`install_scope: project`) or globally installed (`install_scope: global`)?
3. **Check lifecycle scripts** — does the package have install-time scripts?
4. **Refresh threat intel** — run `bumblebee catalog refresh` to get the latest
   catalog, then rescan.
5. **Correlate with other tools** — Bumblebee findings are a triage signal,
   not a verdict.

Example finding:

```json
{
  "record_type": "finding",
  "severity": "critical",
  "catalog_id": "local-2026-001",
  "catalog_name": "Example package version present in exposure catalog",
  "ecosystem": "npm",
  "package_name": "example-pkg",
  "version": "1.2.3",
  "evidence": "exact name+version match (version=1.2.3)",
  "source_file": "/path/to/package-lock.json",
  "confidence": "high"
}
```json
```

### Malicious packages vs general vulnerabilities

Bumblebee's exposure matching is catalog-driven. The default catalog
generated by `bumblebee catalog refresh` contains **malicious-package records**
from the OpenSSF dataset — not general CVE advisories.

> ⚠️ Zero findings does not mean zero vulnerabilities. It only means
> Bumblebee did not find exact package/version matches against the loaded
> catalog. The system may still have unpatched CVEs or other risks.

**Verifying detection:**

```bash
# Run offline tests with a recorded real-world OSV fixture.
python -m pytest tests/test_online_detection.py

# Optional live online test (requires network).
BUMBLEBEE_RUN_ONLINE_TESTS=1 python -m pytest tests/test_online_detection.py
```

## Documentation validation

Before updating command examples, verify against the actual CLI:

```bash
# Top-level help.
bumblebee --help

# Scan flags.
bumblebee scan --help

# Threat-intel refresh.
bumblebee catalog refresh --help

# Smoke test all major combinations.
bumblebee scan --profile baseline --catalogs (or legacy --exposure-catalog) ./catalogs --findings-only --max-duration 60
bumblebee scan --profile baseline --catalogs (or legacy --exposure-catalog) ./catalogs --view --max-duration 60
bumblebee catalog refresh --dry-run --verbose
```

The [`threat_intel/`](threat_intel/) directory holds maintained exposure
catalogs built from public threat-intelligence reporting on recent
supply-chain campaigns, assembled with
[Perplexity Computer](https://www.perplexity.ai/computer) and updated
via PRs as new campaigns are reported. See
[`threat_intel/README.md`](threat_intel/README.md) for the current
catalog list and review guidance.

## License

Apache License 2.0. See [LICENSE](LICENSE).
