# Bumblebee Catalogs

Local exposure catalogs generated from upstream vulnerability and threat-intel sources.

## Directory layout

```
catalogs/
  malicious/         # Malicious-package exposure catalogs (OpenSSF)
    openssf.json
  vulnerabilities/   # Vulnerability advisory catalogs (GitHub Advisory Database)
    ghsa.json
  overlays/          # Prioritization overlays (CISA KEV)
    cisa-kev.json
```

## Generating catalogs

```bash
# OpenSSF malicious packages (malicious-package exposure).
bumblebee catalog refresh --source openssf --output catalogs/malicious/openssf.json

# GitHub Advisory Database (vulnerability advisories).
bumblebee catalog refresh --source ghsa --output catalogs/vulnerabilities/ghsa.json

# CISA Known Exploited Vulnerabilities (prioritization overlay).
bumblebee catalog refresh --source cisa-kev --output catalogs/overlays/cisa-kev.json
```

## Scanning with catalogs

```bash
bumblebee scan --catalogs ./catalogs --view
bumblebee scan --catalogs ./catalogs --findings-only
```

## Migration from threat_intel/

Before 0.6.0, Bumblebee used `threat_intel/` and `--exposure-catalog`.
These names remain available as deprecated compatibility aliases.

To migrate:
```bash
mv threat_intel catalogs
```
