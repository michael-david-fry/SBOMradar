import json
from pathlib import Path

from bomradar.models import Component, ScanReport, ScanSummary, VulnerabilityFinding
from bomradar.reports.csv_report import write_csv_report
from bomradar.reports.html_report import write_html_report
from bomradar.reports.json_report import write_json_report


def _report() -> ScanReport:
    finding = VulnerabilityFinding(
        component_name="lodash",
        component_version="4.17.20",
        purl="pkg:npm/lodash@4.17.20",
        vulnerability_id="CVE-2021-23337",
        cve_ids=["CVE-2021-23337"],
        severity="high",
        match_confidence="purl_component_match",
        references=["https://example.test"],
    )
    return ScanReport(
        scan_summary=ScanSummary(component_count=1, scanned_component_count=1, finding_count=1, high_count=1),
        findings=[finding],
        unscannable_components=[Component(name="unknown", source_format="cyclonedx-json")],
        source_sbom="sbom.json",
    )


OUTPUT_DIR = Path("test-output")


def test_json_report_generation() -> None:
    path = OUTPUT_DIR / "report.json"
    write_json_report(_report(), path)

    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["tool"] == "bomradar"
    assert data["scan_summary"]["finding_count"] == 1


def test_csv_report_generation() -> None:
    path = OUTPUT_DIR / "report.csv"
    write_csv_report(_report(), path)

    text = path.read_text(encoding="utf-8")
    assert "component_name" in text
    assert "CVE-2021-23337" in text


def test_html_report_generation() -> None:
    path = OUTPUT_DIR / "report.html"
    write_html_report(_report(), path)

    text = path.read_text(encoding="utf-8")
    assert "SBOMradar Report" in text
    assert "Immediate Attention" in text
