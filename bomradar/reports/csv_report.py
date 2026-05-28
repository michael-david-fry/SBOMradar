from __future__ import annotations

import csv
from pathlib import Path

from bomradar.models import ScanReport


FIELDS = [
    "component_name",
    "component_version",
    "purl",
    "cpe",
    "vulnerability_id",
    "cve_ids",
    "severity",
    "cvss_score",
    "epss_score",
    "kev",
    "public_poc",
    "nuclei_template",
    "match_confidence",
    "recommendation",
    "references",
]


def write_csv_report(report: ScanReport, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        for finding in report.findings:
            row = finding.model_dump(mode="json")
            row["cve_ids"] = ";".join(finding.cve_ids)
            row["references"] = ";".join(finding.references)
            writer.writerow({field: row.get(field) for field in FIELDS})
