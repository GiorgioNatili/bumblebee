# Threat-Intel Sources — Decision Matrix

Evaluated vulnerability and exposure data sources for Bumblebee integration.

## Sources

| Source | Coverage | Ecosystems | Severity | Version Matching | Offline Cache | Effort | Recommendation |
|---|---|---|---|---|---|---|---|
| **OSV.dev API** | Malicious + CVE/advisory | npm, PyPI, Go, RubyGems, Packagist, crates.io, Maven, NuGet | CVSS, severity type | Exact version + ranges (with GHSA aliases) | Yes (catalog files) | Medium | **Implement now** |
| **OpenSSF malicious-packages** | Malicious-only | npm, PyPI, Go, RubyGems, Packagist, crates.io, Maven, NuGet, VS Code | Severity inferred from DB-specific fields | Exact versions (MAL- entries list explicit versions) | Yes (Git-based clone or raw files) | Low (already implemented via `intel refresh`) | **Implement now** (done) |
| **GitHub Advisory Database** | CVEs, GHSAs | npm, PyPI, RubyGems, Packagist, Go, Rust, Swift, Maven, NuGet, Erlang | CVSS | Exact version + ranges, aliased to OSV | Yes | Medium | **Implement next** |
| **CISA Known Exploited Vulnerabilities** | Actively exploited CVEs | Cross-ecosystem (CVE-based) | CVE (any severity if actively exploited) | CVE ID matching to published package versions | Yes (JSON catalog) | Low | **Implement next** |
| **NVD/CVE feeds** | Vulnerabilities (all CVEs) | Cross-ecosystem (must be mapped to packages) | CVSS | CVE ID only; no package mapping | Yes (feeds) | High (package mapping required) | **Not recommended** — needs extensive ecosystem mapping; prefer OSV.dev |
| **npm audit** | Vulnerabilities in npm packages | npm only | npm advisory severity | Exact version + semver ranges via package.json | No (requires `npm` CLI or npm API) | Medium | **Optional** — Bumblebee already reads lockfiles; npm audit is redundant for inventory |
| **PyPI advisory / OSV PyPI** | Vulnerabilities in PyPI packages | PyPI only | CVSS via OSV | Exact version + ranges via OSV | Yes (OSV.dev API) | Low | **Covered by OSV.dev** |
| **EPSS** | Exploit prediction scores | Cross-ecosystem (CVE-based) | EPSS score (probability) | CVE ID matching | Yes (daily CSV) | Medium | **Optional** — useful for prioritization but needs CVE-to-package mapping |

## Implementation status

| Source | Status |
|---|---|
| OpenSSF malicious-packages | ✅ Implemented (`bumblebee intel refresh`) |
| OSV.dev API | ✅ Catalog format supported; fetch via `--source` |
| GitHub Advisory Database | ❌ Not yet — covered by OSV aliases for most languages |
| CISA KEV | ❌ Not yet — low effort catalog-only integration |
| NVD/CVE | ❌ Not recommended — high mapping effort |
| EPSS | ❌ Not yet — requires CVE-to-package correlation |

## Next steps

1. **OSV.dev vulnerability support** — Extend `intel refresh` to optionally include non-malicious OSV records (CVE/GHSA advisories), filtered by ecosystem. This gives general vulnerability coverage without requiring a separate source.

2. **CISA KEV integration** — Add a KEV-to-catalog converter that maps KEV CVE IDs to known package versions from OSV.dev, producing a prioritized exposure catalog.

3. **EPSS scoring** — If CVE-based matching lands, EPSS scores can prioritize findings by exploit probability.
