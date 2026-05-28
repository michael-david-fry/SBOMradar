# SBOMradar

SBOMradar is a Python CLI tool for scanning SBOM files and reporting vulnerabilities for the
software components listed in them. It accepts CycloneDX JSON and SPDX JSON SBOMs, normalizes
components, queries ProjectDiscovery `vulnx` for vulnerability intelligence, and writes actionable
JSON, CSV, HTML, and console reports.

This first version is intentionally focused on SBOM parsing, component normalization, `vulnx`
lookup/enrichment, and reporting.

## What It Does Not Do Yet

- No VEX support yet.
- No web UI.
- No live target scanning.
- No Nuclei execution against hosts.
- No exploit code.
- No database or live validation service.

## Installation

```bash
python -m pip install -e ".[dev]"
```

SBOMradar requires Python 3.12 or newer.

## vulnx Dependency

SBOMradar uses ProjectDiscovery `vulnx` as its vulnerability intelligence backend. Install `vulnx`
separately and make sure the `vulnx` command is available on your `PATH`.

If `vulnx` is missing during an interactive scan, SBOMradar asks whether to install it with:

```bash
go install github.com/projectdiscovery/vulnx/v2/cmd/vulnx@latest
```

After installation, SBOMradar adds the Go bin directory to the current process `PATH` and attempts
to persist it to your user PATH. If Go itself is missing, or PATH persistence fails, SBOMradar exits
with scanner error code `2` and prints the directory to add manually.

In `--quiet` mode, SBOMradar does not prompt and exits with scanner error code `2` if `vulnx` is
missing.

## Usage

```bash
bomradar scan sbom.json
```

```bash
bomradar scan sbom.json --format cyclonedx-json --json report.json --csv report.csv --html report.html
```

```bash
bomradar scan sbom.json --output-dir reports
```

```bash
bomradar scan sbom.json --fail-on critical
```

```bash
bomradar explain CVE-2021-44228
```

Exit codes:

- `0`: scan completed and no findings met the fail threshold.
- `1`: scan completed and at least one finding met the fail threshold.
- `2`: scanner error, invalid SBOM, missing dependency, or provider failure.

## Supported SBOM Formats

- CycloneDX JSON: extracts component name, version, purl, CPE, bom-ref, component type, supplier,
  and dependency relationships when available.
- SPDX JSON: extracts package name, package version, externalRefs, purl, CPE, SPDXID, and supplier.

## Report Fields

JSON reports include a `scan_summary`, normalized `findings`, `unscannable_components`, source SBOM,
and timestamp. CSV reports include component identity fields, vulnerability IDs, CVE IDs, severity,
CVSS, EPSS, KEV, public PoC, Nuclei template availability, match confidence, recommendations, and
references. HTML reports include summary counts, severity breakdown, an immediate attention section,
findings, unscannable components, timestamp, and source SBOM filename.

Example JSON summary:

```json
{
  "tool": "bomradar",
  "scan_summary": {
    "component_count": 2,
    "scanned_component_count": 2,
    "unscannable_component_count": 0,
    "finding_count": 1,
    "critical_count": 1,
    "high_count": 0,
    "medium_count": 0,
    "low_count": 0,
    "unknown_count": 0
  }
}
```

## Match Confidence

SBOMradar does not hide uncertainty. Findings are labeled with one of:

- `exact_cpe_match`
- `purl_component_match`
- `name_version_match`
- `name_only_match`
- `manual_review_required`

Components that cannot be looked up are listed in `unscannable_components`.

## Priority Score

The priority score is deterministic and intentionally simple. It increases for critical and high
severity, CISA KEV membership, high EPSS, public PoC availability, Nuclei template availability, and
stronger match confidence. The score is only a triage aid; review weak matches before treating them
as confirmed.

## Known Limitations

- The `vulnx` CLI has changed over time, so SBOMradar prefers JSON output and parses several common
  result shapes. If your installed `vulnx` uses different flags, update `providers/vulnx.py`.
- Unit tests mock `vulnx`; they do not require a live internet connection or a real `vulnx` binary.
- VEX is intentionally excluded from this first version.

## Roadmap

- Add VEX ingestion and filtering.
- Improve ecosystem-specific matching.
- Add richer report templates.
- Add provider conformance tests for pinned `vulnx` versions.
