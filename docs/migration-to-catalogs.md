# Migration to Catalogs (0.6.0)

Starting in 0.6.0, Bumblebee renamed the local data concept from "threat intel" to **catalogs**.

## What changed

| Before (legacy) | After (0.6.0+) |
|---|---|
| `threat_intel/` directory | `catalogs/` directory |
| `bumblebee intel refresh` | `bumblebee catalog refresh` |
| `bumblebee scan --exposure-catalog` | `bumblebee scan --catalogs` |

## Backward compatibility

Legacy commands continue to work as deprecated aliases:

```bash
# These still work (deprecated):
bumblebee intel refresh --source openssf --output threat_intel/osv-malicious.json
bumblebee scan --exposure-catalog ./threat_intel

# Preferred (0.6.0+):
bumblebee catalog refresh --source openssf --output catalogs/malicious/openssf.json
bumblebee scan --catalogs ./catalogs
```

## Migrating existing data

```bash
# Rename the directory
mv threat_intel catalogs

# Or keep both and regenerate from new location
mkdir -p catalogs/malicious
bumblebee catalog refresh --source openssf --output catalogs/malicious/openssf.json
```

## Directory layout

```
catalogs/
  malicious/
    openssf.json       # OpenSSF malicious-package catalog
  vulnerabilities/
    ghsa.json           # GitHub Advisory Database catalog
  overlays/
    cisa-kev.json       # CISA KEV prioritization overlay
```
