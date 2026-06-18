# Catalog Sources

Supported upstream sources for `bumblebee catalog refresh`.

## OpenSSF malicious-packages

- **Catalog type:** `malicious-package`
- **Source:** [ossf/malicious-packages](https://github.com/ossf/malicious-packages)
- **Covers:** Known malicious package releases across npm, PyPI, Go, RubyGems, Packagist, Homebrew
- **Matching:** Exact ecosystem/package/version
- **CLI:** `bumblebee catalog refresh --source openssf --output catalogs/malicious/openssf.json`

## GitHub Advisory Database (GHSA)

- **Catalog type:** `vulnerability`
- **Source:** [GitHub Advisory Database](https://github.com/github/advisory-database)
- **Covers:** Package vulnerability advisories with CVE/GHSA aliases
- **Matching:** Exact versions from patched entries; range-only advisories preserved as informational
- **CLI:** `bumblebee catalog refresh --source ghsa --output catalogs/vulnerabilities/ghsa.json`
- **Auth:** Set `GITHUB_TOKEN` for higher rate limits (optional)

## CISA Known Exploited Vulnerabilities (KEV)

- **Catalog type:** `overlay`
- **Source:** [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- **Covers:** CVEs actively exploited in the wild — prioritization/enrichment, not package/version proof
- **CLI:** `bumblebee catalog refresh --source cisa-kev --output catalogs/overlays/cisa-kev.json`

## Terminology

| Term | Definition |
|---|---|
| **Source** | Upstream provider (OpenSSF, GHSA, CISA KEV) |
| **Catalog** | Local normalized file generated from a source |
| **Catalog type** | malicious-package, vulnerability, or overlay |
| **Finding** | Package/inventory record matched a catalog entry |
| **Overlay** | Enrichment applied to a finding (e.g., CISA KEV known-exploited status) |

## Caveats

- OpenSSF detects **malicious package exposure** — not general vulnerabilities.
- GHSA detects **vulnerability advisories** but full value requires version-range matching.
- CISA KEV identifies **known exploited CVEs** for prioritization — not new detection.
- **Zero findings does not mean zero vulnerabilities.**
